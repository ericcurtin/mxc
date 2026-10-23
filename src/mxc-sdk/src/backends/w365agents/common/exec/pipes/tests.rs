// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs::File;
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{spawn_reader, spawn_writer, Cancellation};

const CHILD_TEST: &str =
    "backend_modules::w365agents::common::exec::pipes::tests::w365_pipe_probe_child";
const CASE_ENV: &str = "MXC_W365_PIPE_TEST_CASE";
const WATCHDOG: Duration = Duration::from_secs(10);
pub(super) const CANCEL_BUDGET: Duration = Duration::from_secs(2);

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn run_child(case: &str, budget: Duration) -> io::Result<()> {
    let directory = tempfile::tempdir()?;
    let log_path = directory.path().join("probe.log");
    let log = File::create(&log_path)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(CASE_ENV, case)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(windows)]
    if case == "input_console" {
        use std::os::windows::process::CommandExt;
        use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;
        command.creation_flags(CREATE_NEW_CONSOLE.0);
    }
    let mut child = OwnedChild(command.spawn()?);
    let deadline = Instant::now() + budget;
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.0.kill()?;
            child.0.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("W365 pipe probe {case} exceeded its parent watchdog"),
            ));
        }
        thread::sleep(Duration::from_millis(5));
    };
    let mut output = String::new();
    File::open(log_path)?
        .take(64 * 1024)
        .read_to_string(&mut output)?;
    assert!(status.success(), "{case}: {status}\n{output}");
    assert!(
        output.contains(&format!("W365_PIPE_PROBE_OK:{case}")),
        "The child did not execute {case}:\n{output}"
    );
    println!("W365_PIPE_PROBE_OK:{case}");
    Ok(())
}

pub(super) fn cancel_and_join<T>(
    worker: JoinHandle<io::Result<T>>,
    cancellation: &Cancellation,
) -> io::Result<T> {
    let deadline = Instant::now() + CANCEL_BUDGET;
    loop {
        cancellation.cancel()?;
        if worker.is_finished() {
            return worker
                .join()
                .map_err(|_| io::Error::other("W365 pipe worker panicked"))?;
        }
        assert!(
            Instant::now() < deadline,
            "A cancelled worker did not finish; its pipe peer is still open"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn join_finished<T>(worker: JoinHandle<io::Result<T>>) -> io::Result<T> {
    let deadline = Instant::now() + CANCEL_BUDGET;
    while !worker.is_finished() {
        assert!(
            Instant::now() < deadline,
            "A pipe worker did not finish before its join deadline"
        );
        thread::sleep(Duration::from_millis(1));
    }
    worker
        .join()
        .map_err(|_| io::Error::other("W365 pipe worker panicked"))?
}

fn blocked_read() -> io::Result<()> {
    let (reader, writer) = io::pipe()?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let (worker, cancellation) = spawn_reader("w365-test-read", reader, move |mut reader| {
        ready_tx.send(()).map_err(io::Error::other)?;
        let result = reader.read(&mut [0u8; 1]);
        done_tx.send(()).map_err(io::Error::other)?;
        result
    })?;
    ready_rx
        .recv_timeout(CANCEL_BUDGET)
        .map_err(io::Error::other)?;
    assert_eq!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "The empty pipe did not block"
    );
    assert_eq!(cancel_and_join(worker, &cancellation)?, 0);
    drop(writer);
    cancellation.cancel()?;
    Ok(())
}

fn blocked_write() -> io::Result<()> {
    let (reader, writer) = io::pipe()?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let (worker, cancellation) = spawn_writer("w365-test-write", writer, move |mut writer| {
        ready_tx.send(()).map_err(io::Error::other)?;
        let result = writer.write_all(&vec![0xA5; 1024 * 1024]);
        done_tx.send(()).map_err(io::Error::other)?;
        result
    })?;
    ready_rx
        .recv_timeout(CANCEL_BUDGET)
        .map_err(io::Error::other)?;
    assert_eq!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "The unconsumed output pipe did not block"
    );
    let error = cancel_and_join(worker, &cancellation).expect_err("cancelled write must fail");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    drop(reader);
    cancellation.cancel()?;
    Ok(())
}

fn data_eof_and_late_cancel() -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: this is the single selected test in an owned child process.
        // Model an FFI host, without changing the parent or production handlers.
        if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    let bytes = [0, 0xFF, b'\r', b'\n', 0x80, 0];
    let (reader, writer) = io::pipe()?;
    let (input, cancel_input) = spawn_reader("w365-test-binary-read", reader, |mut reader| {
        let mut output = Vec::new();
        reader.read_to_end(&mut output)?;
        Ok(output)
    })?;
    let (output, cancel_output) =
        spawn_writer("w365-test-binary-write", writer, move |mut writer| {
            writer.write_all(&bytes)?;
            writer.flush()
        })?;
    assert_eq!(join_finished(input)?, bytes);
    join_finished(output)?;
    cancel_input.cancel()?;
    cancel_input.cancel()?;
    cancel_output.cancel()?;
    cancel_output.cancel()?;
    Ok(())
}

fn cancel_before_io() -> io::Result<()> {
    let bytes = [0xA5, 0, 0xFF];
    let (reader, mut writer) = io::pipe()?;
    writer.write_all(&bytes)?;
    drop(writer);
    let mut unread = reader.try_clone()?;
    let (read_tx, read_rx) = mpsc::channel();
    let (worker, cancellation) =
        spawn_reader("w365-test-pre-cancel-read", reader, move |mut reader| {
            read_rx.recv().map_err(io::Error::other)?;
            reader.read(&mut [0u8; 3])
        })?;
    cancellation.cancel()?;
    read_tx.send(()).map_err(io::Error::other)?;
    assert_eq!(cancel_and_join(worker, &cancellation)?, 0);
    let mut remaining = Vec::new();
    unread.read_to_end(&mut remaining)?;
    assert_eq!(remaining, bytes, "A cancelled read consumed queued input");

    let (mut reader, writer) = io::pipe()?;
    let (write_tx, write_rx) = mpsc::channel();
    let (worker, cancellation) =
        spawn_writer("w365-test-pre-cancel-write", writer, move |mut writer| {
            write_rx.recv().map_err(io::Error::other)?;
            writer.write_all(&bytes)
        })?;
    cancellation.cancel()?;
    write_tx.send(()).map_err(io::Error::other)?;
    assert_eq!(
        cancel_and_join(worker, &cancellation)
            .expect_err("A cancelled writer must not accept output")
            .kind(),
        io::ErrorKind::ConnectionAborted
    );
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    assert!(output.is_empty(), "A cancelled writer emitted output");
    Ok(())
}

fn broken_output() -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: only this owned probe's signal disposition is changed.
        if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    let (reader, writer) = io::pipe()?;
    drop(reader);
    let (worker, cancellation) = spawn_writer("w365-test-broken-write", writer, |mut writer| {
        writer.write_all(b"must report a broken pipe")
    })?;
    assert_eq!(
        join_finished(worker)
            .expect_err("A disconnected consumer must fail output")
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    cancellation.cancel()?;
    Ok(())
}

fn concurrent_drop_and_cancel() -> io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: only this watchdog-owned probe models a foreign FFI host.
        if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    for _ in 0..256 {
        let (reader, writer) = io::pipe()?;
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let (worker, cancellation) = spawn_reader("w365-test-drop-race", reader, move |reader| {
            release_rx.recv().map_err(io::Error::other)?;
            drop(reader);
            Ok(())
        })?;
        release_tx.send(()).map_err(io::Error::other)?;
        cancellation.cancel()?;
        join_finished(worker)?;
        cancellation.cancel()?;
        drop(writer);
    }
    Ok(())
}

#[test]
fn w365_pipe_workers_cancel_blocked_read() -> io::Result<()> {
    run_child("blocked_read", WATCHDOG)
}

#[test]
fn w365_pipe_workers_cancel_blocked_write() -> io::Result<()> {
    run_child("blocked_write", WATCHDOG)
}

#[test]
fn w365_pipe_watchdog_reaps_stalled_child() {
    let error = run_child("watchdog", Duration::from_millis(500))
        .expect_err("a stalled probe must fail its parent watchdog");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn w365_pipe_workers_preserve_binary_data_eof_and_late_cancel() -> io::Result<()> {
    run_child("data_eof_late_cancel", WATCHDOG)
}

#[test]
fn w365_pipe_workers_do_not_start_io_after_cancel() -> io::Result<()> {
    run_child("cancel_before_io", WATCHDOG)
}

#[test]
fn w365_pipe_workers_report_broken_output_in_foreign_hosts() -> io::Result<()> {
    run_child("broken_output", WATCHDOG)
}

#[test]
fn w365_pipe_workers_survive_concurrent_drop_and_cancel() -> io::Result<()> {
    run_child("drop_cancel_race", WATCHDOG)
}

#[cfg(windows)]
#[test]
fn w365_pipe_retries_cancel_before_kernel_read_issuance() -> io::Result<()> {
    run_child("read_issuance_race", WATCHDOG)
}

#[cfg(windows)]
#[test]
fn w365_pipe_retries_cancel_before_kernel_write_issuance() -> io::Result<()> {
    run_child("write_issuance_race", WATCHDOG)
}

#[cfg(windows)]
#[test]
fn w365_pipe_classifies_windows_relayed_input_without_consuming_it() -> io::Result<()> {
    for case in [
        "input_pipe",
        "input_closed",
        "input_null",
        "input_disk",
        "input_overlapped",
        "input_console",
        "input_unproven_character",
    ] {
        run_child(case, WATCHDOG)?;
    }
    Ok(())
}

#[test]
#[ignore = "executed in an owned child by the parent watchdog tests"]
fn w365_pipe_probe_child() -> io::Result<()> {
    let case = std::env::var(CASE_ENV).map_err(io::Error::other)?;
    match case.as_str() {
        "blocked_read" => blocked_read()?,
        "blocked_write" => blocked_write()?,
        "data_eof_late_cancel" => data_eof_and_late_cancel()?,
        "cancel_before_io" => cancel_before_io()?,
        "broken_output" => broken_output()?,
        "drop_cancel_race" => concurrent_drop_and_cancel()?,
        #[cfg(windows)]
        "read_issuance_race" => super::platform::tests::read_issuance_race()?,
        #[cfg(windows)]
        "write_issuance_race" => super::platform::tests::write_issuance_race()?,
        #[cfg(windows)]
        case if case.starts_with("input_") => super::platform::input::tests::run_case(case)?,
        "watchdog" => loop {
            thread::park();
        },
        _ => return Err(io::Error::other("unknown W365 pipe probe case")),
    }
    println!("W365_PIPE_PROBE_OK:{case}");
    Ok(())
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real end-to-end interop test: the **actual** DesktopControl.Exec host binary
//! (C#) driven by the **actual** MXC client transport + relay (Rust)
//! over the binary frame wire protocol — running real commands.
//!
//! This exercises the direct loopback path (client ⇄ DC.Exec host on
//! `127.0.0.1:{port}`), which is the production app-layer contract; the
//! RemotingInterface relay in between is an opaque byte carrier (reused
//! unchanged) and is not required to validate frame-protocol interop.
//!
//! **Opt-in:** set `DC_EXEC_EXE` to the path of `DesktopControl.Exec.exe`.
//! Without it the test prints a SKIP notice and passes, so normal `cargo test`
//! (and CI) never depends on the cross-repo C# build.
//!
//! Run:
//! ```text
//! $env:DC_EXEC_EXE = "path\to\DesktopControl.Exec.exe"
//! cargo test -p mxc-sdk --features w365_agents --test w365agents_e2e_desktopcontrol -- --nocapture
//! ```

#![cfg(feature = "w365_agents")]

use std::io::{Cursor, Write};

use std::net::TcpStream;

use std::process::{Child, Command, Stdio};

use std::time::{Duration, Instant};

use mxc_sdk::w365agents_common::exec::payload::ExecStartPayload;

use mxc_sdk::w365agents_common::exec::relay::run_relay_session;

use mxc_sdk::w365agents_common::exec::transport::{
    build_upgrade_request, read_upgrade_response, UpgradeTarget,
};

/// Grab an ephemeral loopback port (bind :0, read it back, release it).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Block until the DC.Exec host accepts connections on `port` (or time out).
fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "DC.Exec never listened on {port}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Drive ONE exec over a fresh connection using the real client helpers:
/// TCP → HTTP/1.1 upgrade (101) → `EXEC_START` → relay → `EXIT`.
/// Returns `(exit_code, stdout, stderr)`.
fn run_one(port: u16, command: &str, stdin: &[u8]) -> (i32, String, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect to DC.Exec");

    // The real upgrade request (path/auth headers are ignored by the loopback
    // host — they matter only at the relay). This is `build_upgrade_request`
    // verbatim from the shipping client.
    let target = UpgradeTarget {
        host: "127.0.0.1".to_string(),
        port,
        path: "/computers/e2e/microsoft.mxc-exec".to_string(),
        computer_id: "e2e".to_string(),
        bearer_token: mxc_sdk::w365agents_common::secret::Redacted::new("e2e-token"),
        capability: "microsoft.mxc-exec".to_string(),
    };
    sock.write_all(build_upgrade_request(&target).unwrap().as_bytes())
        .unwrap();
    read_upgrade_response(&mut sock).expect("101 Switching Protocols from DC.Exec");

    // Post-101: switch to the relay poll cadence (mirrors `connect_upgrade`).
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();

    let start = ExecStartPayload {
        command_line: command.to_string(),
        working_directory: String::new(),
        env: vec![],
        timeout_ms: 15_000,
        shell: None, // server defaults to `cmd`
    };

    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_relay_session(sock, start, &mut out, &mut err, Cursor::new(stdin.to_vec()))
        .expect("relay session");
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

/// RAII guard so the spawned host is always killed, even on assertion panic,
/// and its captured console log is dumped for diagnosis.
struct HostGuard {
    child: Child,
    log: std::path::PathBuf,
}
impl Drop for HostGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Ok(text) = std::fs::read_to_string(&self.log) {
            if !text.trim().is_empty() {
                eprintln!("---- DC.Exec server log ----\n{text}\n----------------------------");
            }
        }
        let _ = std::fs::remove_file(&self.log);
    }
}

#[test]
fn real_desktopcontrol_exec_interop() {
    let exe = match std::env::var("DC_EXEC_EXE") {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "SKIP real_desktopcontrol_exec_interop: set DC_EXEC_EXE to the \
                 DesktopControl.Exec.exe path to run the real cross-binary E2E."
            );
            return;
        }
    };

    let port = free_port();
    let log = std::env::temp_dir().join(format!("dc_exec_e2e_{port}.log"));
    let log_file = std::fs::File::create(&log).unwrap();
    let log_err = log_file.try_clone().unwrap();
    let child = Command::new(&exe)
        .args(["--port", &port.to_string()])
        .env("DOTNET_ENVIRONMENT", "Development")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn DC.Exec '{exe}': {e}"));
    let _guard = HostGuard {
        child,
        log: log.clone(),
    };

    wait_for_listen(port);
    eprintln!("[e2e] DC.Exec listening on 127.0.0.1:{port}");

    // 1) echo → stdout + clean exit 0
    let (code, out, err) = run_one(port, "echo hello-e2e", b"");
    eprintln!("[e2e] echo -> code={code} out={out:?} err={err:?}");
    assert_eq!(code, 0, "echo exit code");
    assert!(
        out.contains("hello-e2e"),
        "echo stdout must contain the marker: {out:?}"
    );

    // 2) non-zero exit code round-trips
    let (code, _o, _e) = run_one(port, "exit 7", b"");
    eprintln!("[e2e] exit 7 -> code={code}");
    assert_eq!(code, 7, "non-zero exit code must round-trip");

    // 3) stderr is delivered on the STDERR channel
    let (code, _o, err) = run_one(port, "echo err-e2e 1>&2", b"");
    eprintln!("[e2e] stderr -> code={code} err={err:?}");
    assert_eq!(code, 0, "stderr-echo exit code");
    assert!(
        err.contains("err-e2e"),
        "stderr must contain the marker: {err:?}"
    );

    // 4) stdin is forwarded and echoed back (sort reads stdin, emits, exits 0)
    let (code, out, _e) = run_one(port, "sort", b"ping-e2e\r\n");
    eprintln!("[e2e] stdin -> code={code} out={out:?}");
    assert_eq!(code, 0, "stdin-echo exit code");
    assert!(
        out.contains("ping-e2e"),
        "stdin must be echoed to stdout: {out:?}"
    );

    eprintln!("[e2e] all 4 real client<->server scenarios passed");
}

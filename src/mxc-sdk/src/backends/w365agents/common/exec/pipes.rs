// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

#[cfg(unix)]
#[path = "pipes/unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "pipes/windows.rs"]
mod platform;

pub(super) use platform::Cancellation;
use platform::{Reader, Writer};

type Worker<T> = (JoinHandle<io::Result<T>>, Cancellation);

pub(super) fn spawn_reader<T, F>(name: &str, pipe: io::PipeReader, run: F) -> io::Result<Worker<T>>
where
    T: Send + 'static,
    F: FnOnce(Reader) -> io::Result<T> + Send + 'static,
{
    let (reader, cancellation) = platform::reader(pipe)?;
    spawn_worker(name, reader, cancellation, run)
}

pub(super) fn spawn_writer<T, F>(name: &str, pipe: io::PipeWriter, run: F) -> io::Result<Worker<T>>
where
    T: Send + 'static,
    F: FnOnce(Writer) -> io::Result<T> + Send + 'static,
{
    let (writer, cancellation) = platform::writer(pipe)?;
    spawn_worker(name, writer, cancellation, run)
}

fn spawn_worker<I, T, F>(
    name: &str,
    io: I,
    cancellation: Cancellation,
    run: F,
) -> io::Result<Worker<T>>
where
    I: Send + 'static,
    T: Send + 'static,
    F: FnOnce(I) -> io::Result<T> + Send + 'static,
{
    let (start_tx, start_rx) = mpsc::sync_channel(0);
    let worker = thread::Builder::new().name(name.into()).spawn(move || {
        start_rx
            .recv()
            .map_err(|_| io::Error::other("W365 pipe worker startup was cancelled"))?;
        #[cfg(unix)]
        crate::mxc_common::unix_io::block_sigpipe()?;
        run(io)
    })?;
    #[cfg(windows)]
    let cancellation = match cancellation.bind(&worker) {
        Ok(cancellation) => cancellation,
        Err(error) => {
            drop(start_tx);
            join_unstarted(worker)?;
            return Err(error);
        }
    };
    if start_tx.send(()).is_err() {
        join_unstarted(worker)?;
        return Err(io::Error::other("W365 pipe worker exited before startup"));
    }
    Ok((worker, cancellation))
}

fn join_unstarted<T>(worker: JoinHandle<io::Result<T>>) -> io::Result<()> {
    // Startup failed before the closure could enter I/O.
    while !worker.is_finished() {
        thread::yield_now();
    }
    let outcome = worker
        .join()
        .map_err(|_| io::Error::other("W365 pipe worker panicked during startup"))?;
    match outcome {
        Err(_) => Ok(()),
        Ok(_) => Err(io::Error::other(
            "W365 pipe worker ran after startup was cancelled",
        )),
    }
}

fn cancelled_write() -> io::Error {
    // Interrupted would make Write::write_all retry forever after cancellation.
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "W365 output pipe was cancelled",
    )
}

#[cfg(test)]
mod tests;

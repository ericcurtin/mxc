// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Write};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use super::super::tests::{cancel_and_join, CANCEL_BUDGET};
use super::super::{spawn_reader, spawn_writer};

fn release_after_first_cancel(
    cancellation: &super::Cancellation,
    announced: mpsc::Receiver<()>,
    release: mpsc::SyncSender<()>,
    done: &mpsc::Receiver<()>,
) -> io::Result<()> {
    announced
        .recv_timeout(CANCEL_BUDGET)
        .map_err(io::Error::other)?;
    cancellation.cancel()?;
    release.send(()).map_err(io::Error::other)?;
    assert_eq!(
        done.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "the first cancel must precede the actual kernel I/O"
    );
    Ok(())
}

pub(crate) fn read_issuance_race() -> io::Result<()> {
    let (reader, writer) = io::pipe()?;
    let (announce_tx, announce_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (worker, cancellation) =
        spawn_reader("w365-test-read-issuance", reader, move |mut reader| {
            let gate = Arc::clone(&reader.gate);
            let outcome = gate
                .perform(|| {
                    announce_tx.send(()).map_err(io::Error::other)?;
                    release_rx.recv().map_err(io::Error::other)?;
                    reader.pipe.read(&mut [0; 1])
                })
                .unwrap_or(Ok(0));
            done_tx.send(()).map_err(io::Error::other)?;
            outcome
        })?;
    release_after_first_cancel(&cancellation, announce_rx, release_tx, &done_rx)?;
    assert_eq!(cancel_and_join(worker, &cancellation)?, 0);
    drop(writer);
    Ok(())
}

pub(crate) fn write_issuance_race() -> io::Result<()> {
    let (reader, writer) = io::pipe()?;
    let (announce_tx, announce_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let (worker, cancellation) =
        spawn_writer("w365-test-write-issuance", writer, move |mut writer| {
            let gate = Arc::clone(&writer.gate);
            let outcome = gate
                .perform(|| {
                    announce_tx.send(()).map_err(io::Error::other)?;
                    release_rx.recv().map_err(io::Error::other)?;
                    writer.pipe.write(&vec![0xA5; 1024 * 1024])
                })
                .unwrap_or_else(|| Err(super::super::cancelled_write()));
            done_tx.send(()).map_err(io::Error::other)?;
            outcome
        })?;
    release_after_first_cancel(&cancellation, announce_rx, release_tx, &done_rx)?;
    assert_eq!(
        cancel_and_join(worker, &cancellation)
            .expect_err("a cancelled write must fail")
            .kind(),
        io::ErrorKind::ConnectionAborted
    );
    drop(reader);
    Ok(())
}

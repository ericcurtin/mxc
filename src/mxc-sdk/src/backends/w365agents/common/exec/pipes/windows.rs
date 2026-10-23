// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Write};
use std::os::windows::io::{AsHandle, AsRawHandle, OwnedHandle};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

use windows::Win32::Foundation::{ERROR_NOT_FOUND, HANDLE};
use windows::Win32::System::IO::CancelSynchronousIo;

#[path = "windows/input.rs"]
pub(super) mod input;

#[cfg(test)]
#[path = "windows/tests.rs"]
pub(super) mod tests;

#[derive(Default)]
struct State {
    cancelled: bool,
    active: bool,
}

#[derive(Default)]
struct Gate(Mutex<State>);

impl Gate {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Both fields remain valid if the owning worker panics.
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn begin(self: &Arc<Self>) -> Option<ActiveIo> {
        let mut state = self.lock();
        if state.cancelled {
            return None;
        }
        state.active = true;
        Some(ActiveIo(Arc::clone(self)))
    }

    fn perform<T>(self: &Arc<Self>, run: impl FnOnce() -> io::Result<T>) -> Option<io::Result<T>> {
        let active = self.begin()?;
        let result = run();
        drop(active);
        if self.lock().cancelled {
            None
        } else {
            Some(result)
        }
    }
}

struct ActiveIo(Arc<Gate>);

impl Drop for ActiveIo {
    fn drop(&mut self) {
        self.0.lock().active = false;
    }
}

pub(crate) struct Reader {
    pipe: io::PipeReader,
    gate: Arc<Gate>,
}

pub(crate) struct Writer {
    pipe: io::PipeWriter,
    gate: Arc<Gate>,
}

pub(crate) struct Cancellation {
    gate: Arc<Gate>,
    thread: Option<OwnedHandle>,
}

impl Cancellation {
    pub(super) fn bind<T>(self, worker: &JoinHandle<T>) -> io::Result<Self> {
        Ok(Self {
            thread: Some(worker.as_handle().try_clone_to_owned()?),
            ..self
        })
    }

    /// Request cancellation once per driver turn, retrying an issuance race.
    pub(crate) fn cancel(&self) -> io::Result<()> {
        let mut state = self.gate.lock();
        state.cancelled = true;
        if !state.active {
            return Ok(());
        }
        let thread = self
            .thread
            .as_ref()
            .ok_or_else(|| io::Error::other("W365 pipe worker has no cancellation target"))?;
        // SAFETY: this owned duplicate of JoinHandle retains the worker's thread
        // HANDLE and its THREAD_TERMINATE right. The startup gate prevents I/O
        // before binding; the state gate prevents new I/O after cancellation.
        match unsafe { CancelSynchronousIo(HANDLE(thread.as_raw_handle())) } {
            Ok(()) => Ok(()),
            // The worker may be between Gate::begin and entering the kernel.
            Err(error) if error.code() == ERROR_NOT_FOUND.to_hresult() => Ok(()),
            Err(error) => Err(io::Error::other(error)),
        }
    }
}

pub(super) fn reader(pipe: io::PipeReader) -> io::Result<(Reader, Cancellation)> {
    let gate = Arc::new(Gate::default());
    Ok((
        Reader {
            pipe,
            gate: Arc::clone(&gate),
        },
        Cancellation { gate, thread: None },
    ))
}

pub(super) fn writer(pipe: io::PipeWriter) -> io::Result<(Writer, Cancellation)> {
    let gate = Arc::new(Gate::default());
    Ok((
        Writer {
            pipe,
            gate: Arc::clone(&gate),
        },
        Cancellation { gate, thread: None },
    ))
}

impl Read for Reader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.gate
            .perform(|| self.pipe.read(buffer))
            .unwrap_or(Ok(0))
    }
}

impl Write for Writer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.gate
            .perform(|| self.pipe.write(buffer))
            .unwrap_or_else(|| Err(super::cancelled_write()))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::mxc_common::interruptible_reader::{InterruptibleReader, ReadCanceller};
use crate::mxc_common::sandbox_process::StreamCloser;

pub(crate) struct Reader {
    inner: InterruptibleReader,
    alive: Arc<Mutex<bool>>,
}

impl Read for Reader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        // Serialize destruction with cancellation's wake write. The inner
        // reader (and its wake fd) stays alive until this Drop body returns.
        *self
            .alive
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
    }
}

pub(crate) struct Writer {
    pipe: io::PipeWriter,
    wake: Arc<Wake>,
}

pub(crate) enum Cancellation {
    Reader {
        canceller: ReadCanceller,
        alive: Arc<Mutex<bool>>,
    },
    Writer(Arc<Wake>),
}

pub(crate) struct Wake {
    cancelled: AtomicBool,
    // Both endpoints outlive either owner, so a late cancel cannot raise SIGPIPE.
    reader: io::PipeReader,
    writer: io::PipeWriter,
}

impl Cancellation {
    pub(crate) fn cancel(&self) -> io::Result<()> {
        match self {
            Self::Reader { canceller, alive } => {
                // A late close on the shared reader would otherwise write to
                // a dead wake pipe in an FFI host with SIGPIPE left at default.
                let alive = alive
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if *alive {
                    canceller.close();
                }
                Ok(())
            }
            Self::Writer(wake) => {
                if wake.cancelled.swap(true, Ordering::AcqRel) {
                    return Ok(());
                }
                match (&wake.writer).write(&[0]) {
                    Ok(1) => Ok(()),
                    Ok(_) => Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "W365 pipe cancellation did not write its wake byte",
                    )),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
                    Err(error) => Err(error),
                }
            }
        }
    }
}

pub(super) fn reader(pipe: io::PipeReader) -> io::Result<(Reader, Cancellation)> {
    let inner = InterruptibleReader::new(pipe.into())?;
    let alive = Arc::new(Mutex::new(true));
    let cancellation = Cancellation::Reader {
        canceller: inner.canceller(),
        alive: Arc::clone(&alive),
    };
    Ok((Reader { inner, alive }, cancellation))
}

pub(super) fn writer(pipe: io::PipeWriter) -> io::Result<(Writer, Cancellation)> {
    set_nonblocking(pipe.as_raw_fd())?;
    let (reader, writer) = io::pipe()?;
    set_nonblocking(writer.as_raw_fd())?;
    let wake = Arc::new(Wake {
        cancelled: AtomicBool::new(false),
        reader,
        writer,
    });
    Ok((
        Writer {
            pipe,
            wake: Arc::clone(&wake),
        },
        Cancellation::Writer(wake),
    ))
}

impl Write for Writer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.wake.cancelled.load(Ordering::Acquire) {
                return Err(super::cancelled_write());
            }
            match self.pipe.write(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
            let mut descriptors = [
                libc::pollfd {
                    fd: self.pipe.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake.reader.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: both descriptors stay owned through the call and the
            // two-element pollfd array is writable for its entire length.
            if unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: fd is an owned private endpoint; only its status flags change.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd remains owned, and the existing flags are preserved.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

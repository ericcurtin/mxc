// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Blocking frame relay loop and stdin pump for an upgraded exec duplex.

use std::io::{ErrorKind, Read, Write};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;

use crate::mxc_common::mxc_error::MxcError;

use crate::w365agents_common::exec::frame::{
    encode_frame, FrameAccumulator, FrameType, MAX_FRAME_PAYLOAD,
};
use crate::w365agents_common::exec::payload::{parse_error, parse_exit, ExecStartPayload};

/// Exit code reported by `waiter` when the workload ends abnormally (device
/// `ERROR` frame, or a transport drop before `EXIT`).
pub const SENTINEL_ABNORMAL_EXIT: i32 = -1;

/// Largest stdin chunk sent in a single `STDIN` frame (respects the 64 KiB cap).
const STDIN_CHUNK: usize = MAX_FRAME_PAYLOAD;

/// Spin-guard sleep applied only when a read returns `WouldBlock` (a
/// misconfigured non-blocking socket), so a bad transport degrades to latency
/// rather than a pegged core. The normal path is a blocking read with a finite
/// timeout (`TimedOut`), which paces the loop in the kernel with no extra sleep.
const READ_SPIN_GUARD: Duration = Duration::from_millis(5);

/// Message from the stdin-reader thread to the relay loop.
pub enum StdinMsg {
    Data(Vec<u8>),
    Eof,
}

/// Drive one exec over an already-upgraded duplex. Writes `EXEC_START`, then
/// relays frames: `STDOUT`/`STDERR` → `out`/`err`, queued stdin → `STDIN`
/// frames, terminal `EXIT`/`ERROR` → return.
///
/// **Post-`101` contract:** the workload commit point is the `101`
/// upgrade (performed in the transport before this runs), so **every duplex
/// I/O failure resolves to `Ok(SENTINEL_ABNORMAL_EXIT)`, never a wire `Err`**.
/// A stdin-write failure does NOT abort — it only stops further stdin (the peer
/// may still have a buffered `EXIT`/`ERROR` to read); only a read EOF/error or
/// an `ERROR` frame yields the sentinel. `Err` is reserved for local faults
/// (encoding, or writing to our own `out`/`err`).
pub fn relay_exec<S: Read + Write>(
    stream: &mut S,
    start: &ExecStartPayload,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stdin_rx: Receiver<StdinMsg>,
) -> Result<i32, MxcError> {
    // First duplex write. `encode()` faults are local (`Err`); a *send* failure
    // is already post-`101`, so it is an abnormal close (sentinel), not a wire error.
    // `encode()` already returns a COMPLETE frame — write it RAW. Do NOT pass it
    // through `write_frame` (that would double-wrap EXEC_START: `[0x01][len][0x01…]`).
    let start_frame = start.encode()?;
    if stream
        .write_all(&start_frame)
        .and_then(|()| stream.flush())
        .is_err()
    {
        return Ok(abnormal_exit(out, err));
    }

    let mut acc = FrameAccumulator::new();
    let mut buf = [0u8; 16 * 1024];
    let mut stdin_open = true;
    let mut peer_gone = false;
    loop {
        // 1. Drain queued stdin (non-blocking). A write failure means the peer's
        //    read half is gone — stop sending stdin but KEEP reading, since an
        //    `EXIT`/`ERROR` frame may already be buffered inbound (this is the
        //    normal-exit-with-queued-stdin race).
        if stdin_open && !peer_gone {
            loop {
                match stdin_rx.try_recv() {
                    Ok(StdinMsg::Data(bytes)) => {
                        for chunk in bytes.chunks(STDIN_CHUNK) {
                            if write_frame(stream, FrameType::Stdin, chunk).is_err() {
                                peer_gone = true;
                                break;
                            }
                        }
                        if peer_gone {
                            break;
                        }
                    }
                    Ok(StdinMsg::Eof) => {
                        let _ = write_frame(stream, FrameType::StdinClose, b"");
                        stdin_open = false;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        let _ = write_frame(stream, FrameType::StdinClose, b"");
                        stdin_open = false;
                        break;
                    }
                }
            }
        }

        // 2. Read inbound bytes (bounded by the transport's finite read timeout).
        match stream.read(&mut buf) {
            Ok(0) => return Ok(abnormal_exit(out, err)), // clean EOF before EXIT
            Ok(n) => acc.extend(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::TimedOut => continue, // normal poll tick
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // Misconfigured non-blocking socket: bounded spin-guard.
                thread::sleep(READ_SPIN_GUARD);
                continue;
            }
            // Peer gone (reset / broken pipe / aborted / ...) — abnormal close.
            Err(_) => return Ok(abnormal_exit(out, err)),
        }

        // 3. Process every complete frame now buffered.
        while let Some(frame) = acc.next_frame()? {
            match frame.kind {
                Some(FrameType::Started) => { /* process launched; nothing to emit */ }
                Some(FrameType::Stdout) => {
                    out.write_all(&frame.payload)
                        .and_then(|()| out.flush())
                        .map_err(|e| MxcError::backend_error(format!("write stdout: {e}")))?;
                }
                Some(FrameType::Stderr) => {
                    err.write_all(&frame.payload)
                        .and_then(|()| err.flush())
                        .map_err(|e| MxcError::backend_error(format!("write stderr: {e}")))?;
                }
                Some(FrameType::Exit) => {
                    let exit = parse_exit(&frame.payload)?;
                    let _ = out.flush();
                    let _ = err.flush();
                    return Ok(exit.exit_code);
                }
                Some(FrameType::Error) => {
                    let msg = parse_error(&frame.payload)?.message;
                    let _ = writeln!(err, "exec error: {msg}");
                    let _ = err.flush();
                    return Ok(SENTINEL_ABNORMAL_EXIT);
                }
                // Client→device or reserved/unknown frames are not expected inbound.
                _ => {}
            }
        }
    }
}

/// Flush local streams and return the abnormal-exit sentinel (a post-`101`
/// transport drop is reported through `waiter`, never as a wire error).
fn abnormal_exit(out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let _ = out.flush();
    let _ = err.flush();
    SENTINEL_ABNORMAL_EXIT
}

fn write_frame<S: Write>(stream: &mut S, kind: FrameType, payload: &[u8]) -> Result<(), MxcError> {
    stream
        .write_all(&encode_frame(kind, payload))
        .and_then(|()| stream.flush())
        .map_err(|e| MxcError::backend_error(format!("send {kind:?} frame: {e}")))
}

/// Spawn the stdin-reader thread and run the relay on the current thread.
/// `stdin_source` is read on a dedicated thread and forwarded as `StdinMsg`.
pub fn run_relay_session<S, I>(
    mut stream: S,
    start: ExecStartPayload,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stdin_source: I,
) -> Result<i32, MxcError>
where
    S: Read + Write,
    I: Read + Send + 'static,
{
    let (tx, rx): (Sender<StdinMsg>, Receiver<StdinMsg>) = std::sync::mpsc::channel();
    // Detach the stdin reader: it exits on stdin EOF or when `rx` is dropped
    // (relay finished). We must NOT join it — a blocking read on a real stdin
    // with no input would otherwise hang the whole exec after the child exits.
    let _stdin_thread = thread::spawn(move || pump_stdin(stdin_source, tx));
    relay_exec(&mut stream, &start, out, err, rx)
}

fn pump_stdin<I: Read>(mut source: I, tx: Sender<StdinMsg>) {
    let mut buf = [0u8; STDIN_CHUNK];
    loop {
        match source.read(&mut buf) {
            Ok(0) => {
                let _ = tx.send(StdinMsg::Eof);
                return;
            }
            Ok(n) => {
                if tx.send(StdinMsg::Data(buf[..n].to_vec())).is_err() {
                    return; // relay finished; stop reading stdin
                }
            }
            Err(_) => {
                let _ = tx.send(StdinMsg::Eof);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::mpsc;

    use super::super::frame::{encode_frame, FrameType};
    use super::super::payload::ExecStartPayload;
    use super::super::relay::{relay_exec, StdinMsg, SENTINEL_ABNORMAL_EXIT};

    /// In-memory duplex: `read` drains a scripted inbound buffer; `write`
    /// captures outbound bytes.
    struct MockDuplex {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }
    impl std::io::Read for MockDuplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(b)
        }
    }
    impl std::io::Write for MockDuplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.outbound.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn start() -> ExecStartPayload {
        ExecStartPayload {
            command_line: "cmd".into(),
            working_directory: String::new(),
            env: vec![],
            timeout_ms: 0,
            shell: None,
        }
    }

    fn run(inbound: Vec<u8>, stdin: Vec<StdinMsg>) -> (i32, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut dup = MockDuplex {
            inbound: Cursor::new(inbound),
            outbound: Vec::new(),
        };
        let (tx, rx) = mpsc::channel();
        for m in stdin {
            tx.send(m).unwrap();
        }
        drop(tx);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = relay_exec(&mut dup, &start(), &mut out, &mut err, rx).unwrap();
        (code, out, err, dup.outbound)
    }

    #[test]
    fn writes_exec_start_first() {
        let mut inbound = encode_frame(FrameType::Started, b"");
        inbound.extend(encode_frame(FrameType::Exit, br#"{"code":0}"#));
        let (_c, _o, _e, outbound) = run(inbound, vec![]);
        // The first outbound frame must be a SINGLE EXEC_START whose payload is the
        // raw JSON — regression guard against double-framing (`[0x01][len][0x01…]`,
        // which a real DesktopControl.Exec server rejects as "invalid start of a value").
        let mut acc = super::super::frame::FrameAccumulator::new();
        acc.extend(&outbound);
        let frame = acc.next_frame().unwrap().expect("an EXEC_START frame");
        assert_eq!(frame.kind, Some(FrameType::ExecStart));
        assert_eq!(
            frame.payload.first(),
            Some(&b'{'),
            "EXEC_START payload must be raw JSON, not a nested frame"
        );
        let json: serde_json::Value =
            serde_json::from_slice(&frame.payload).expect("EXEC_START payload is valid JSON");
        assert_eq!(json["command"], "cmd");
    }

    #[test]
    fn streams_stdout_and_returns_exit_code() {
        let mut inbound = encode_frame(FrameType::Started, b"");
        inbound.extend(encode_frame(FrameType::Stdout, b"hello "));
        inbound.extend(encode_frame(FrameType::Stdout, b"world"));
        inbound.extend(encode_frame(FrameType::Exit, br#"{"code":0}"#));
        let (code, out, _e, _ob) = run(inbound, vec![]);
        assert_eq!(code, 0);
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn returns_nonzero_exit_code() {
        let mut inbound = encode_frame(FrameType::Started, b"");
        inbound.extend(encode_frame(FrameType::Exit, br#"{"code":7}"#));
        let (code, _o, _e, _ob) = run(inbound, vec![]);
        assert_eq!(code, 7);
    }

    #[test]
    fn error_frame_writes_stderr_and_returns_sentinel() {
        let inbound = encode_frame(FrameType::Error, br#"{"message":"spawn failed"}"#);
        let (code, _o, err, _ob) = run(inbound, vec![]);
        assert_eq!(code, SENTINEL_ABNORMAL_EXIT);
        assert!(String::from_utf8_lossy(&err).contains("spawn failed"));
    }

    #[test]
    fn transport_drop_before_exit_returns_sentinel() {
        // STARTED then EOF, no EXIT.
        let inbound = encode_frame(FrameType::Started, b"");
        let (code, _o, _e, _ob) = run(inbound, vec![]);
        assert_eq!(code, SENTINEL_ABNORMAL_EXIT);
    }

    #[test]
    fn forwards_stdin_then_close() {
        let mut inbound = encode_frame(FrameType::Started, b"");
        inbound.extend(encode_frame(FrameType::Exit, br#"{"code":0}"#));
        let (_c, _o, _e, outbound) = run(
            inbound,
            vec![StdinMsg::Data(b"ping".to_vec()), StdinMsg::Eof],
        );
        // outbound = EXEC_START, then STDIN("ping"), then STDIN_CLOSE.
        let stdin_frame = encode_frame(FrameType::Stdin, b"ping");
        let close_frame = encode_frame(FrameType::StdinClose, b"");
        let hay = &outbound;
        assert!(hay
            .windows(stdin_frame.len())
            .any(|w| w == stdin_frame.as_slice()));
        assert!(hay
            .windows(close_frame.len())
            .any(|w| w == close_frame.as_slice()));
    }

    /// Duplex that fails writes after `writes_before_fail` successful writes, and
    /// whose reads drain `inbound` then (once exhausted) return `read_err` (or a
    /// clean EOF when `read_err` is `None`). Used to exercise post-`101` abnormal
    /// closes on both directions.
    struct FlakyDuplex {
        inbound: Cursor<Vec<u8>>,
        writes_before_fail: usize,
        write_err: std::io::ErrorKind,
        read_err: Option<std::io::ErrorKind>,
    }
    impl std::io::Read for FlakyDuplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inbound.read(b)?;
            if n == 0 {
                if let Some(kind) = self.read_err {
                    return Err(std::io::Error::from(kind));
                }
            }
            Ok(n)
        }
    }
    impl std::io::Write for FlakyDuplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.writes_before_fail == 0 {
                return Err(std::io::Error::from(self.write_err));
            }
            self.writes_before_fail -= 1;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stdin_write_failure_keeps_reading_buffered_exit() {
        // EXEC_START write succeeds; the first STDIN write fails (peer's read half
        // gone), but the EXIT frame is already buffered inbound → must return Ok(5),
        // NOT a wire error and NOT the sentinel.
        let mut inbound = encode_frame(FrameType::Started, b"");
        inbound.extend(encode_frame(FrameType::Exit, br#"{"code":5}"#));
        let mut dup = FlakyDuplex {
            inbound: Cursor::new(inbound),
            writes_before_fail: 1, // EXEC_START ok; next write (STDIN) fails
            write_err: std::io::ErrorKind::BrokenPipe,
            read_err: None,
        };
        let (tx, rx) = mpsc::channel();
        tx.send(StdinMsg::Data(b"x".to_vec())).unwrap();
        drop(tx);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = relay_exec(&mut dup, &start(), &mut out, &mut err, rx).unwrap();
        assert_eq!(code, 5);
    }

    #[test]
    fn read_error_returns_sentinel_not_wire_error() {
        // A peer-gone read error (e.g. ConnectionReset) after EXEC_START must
        // resolve to Ok(sentinel), never a wire Err (post-101 contract).
        let mut dup = FlakyDuplex {
            inbound: Cursor::new(Vec::new()),
            writes_before_fail: 100,
            write_err: std::io::ErrorKind::BrokenPipe,
            read_err: Some(std::io::ErrorKind::ConnectionReset),
        };
        let (tx, rx) = mpsc::channel::<StdinMsg>();
        drop(tx);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = relay_exec(&mut dup, &start(), &mut out, &mut err, rx).unwrap();
        assert_eq!(code, SENTINEL_ABNORMAL_EXIT);
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(feature = "w365_agents")]

use std::io::{Cursor, Read, Write};

use std::net::{TcpListener, TcpStream};

use std::thread;

use std::time::Duration;

use mxc_sdk::w365agents_common::exec::frame::{encode_frame, FrameAccumulator, FrameType};

use mxc_sdk::w365agents_common::exec::payload::ExecStartPayload;

use mxc_sdk::w365agents_common::exec::relay::{run_relay_session, SENTINEL_ABNORMAL_EXIT};

use mxc_sdk::w365agents_common::exec::transport::read_upgrade_response;

fn start() -> ExecStartPayload {
    ExecStartPayload {
        command_line: "cmd".into(),
        working_directory: String::new(),
        env: vec![],
        timeout_ms: 0,
        shell: None,
    }
}

/// Read the client's HTTP upgrade request line + headers, then reply `101`.
fn accept_and_upgrade(listener: &TcpListener) -> TcpStream {
    let (mut sock, _) = listener.accept().unwrap();
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    loop {
        let n = sock.read(&mut one).unwrap();
        if n == 0 {
            break;
        }
        head.push(one[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    sock.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: microsoft.mxc-exec\r\n\r\n")
        .unwrap();
    sock.flush().unwrap();
    sock
}

/// Client side: connect, send a minimal upgrade request, validate `101`.
fn connect_and_upgrade(addr: std::net::SocketAddr) -> TcpStream {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.write_all(
        b"GET /computers/x/microsoft.mxc-exec HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n\
          Upgrade: microsoft.mxc-exec\r\nAuthorization: ****** x\r\n\r\n",
    )
    .unwrap();
    read_upgrade_response(&mut sock).unwrap();
    // Post-upgrade: poll cadence for the relay (drains stdin between reads).
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    sock
}

/// Orderly server close: block until the client half-closes (EOF), so the OS
/// performs a graceful FIN rather than an abortive RST. On Windows, dropping a
/// socket that still holds the client's unread `EXEC_START`/`STDIN_CLOSE` bytes
/// triggers an RST (RFC 1122 §4.2.2.13) that discards the `EXIT` frame we just
/// sent, which the relay then (correctly, per spec §7) surfaces as the
/// abnormal-exit sentinel — masking the real exit code under test.
fn drain_until_client_closes(sock: &mut TcpStream) {
    let mut sink = [0u8; 256];
    loop {
        match sock.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[test]
fn run_command_streams_stdout_and_exit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut sock = accept_and_upgrade(&listener);
        // Ignore the client's EXEC_START; emit output + exit.
        sock.write_all(&encode_frame(FrameType::Started, b""))
            .unwrap();
        sock.write_all(&encode_frame(FrameType::Stdout, b"done"))
            .unwrap();
        sock.write_all(&encode_frame(FrameType::Exit, br#"{"code":0}"#))
            .unwrap();
        sock.flush().unwrap();
        drain_until_client_closes(&mut sock);
    });

    let sock = connect_and_upgrade(addr);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code =
        run_relay_session(sock, start(), &mut out, &mut err, Cursor::new(Vec::new())).unwrap();
    server.join().unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"done");
}

#[test]
fn nonzero_exit_is_propagated() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut sock = accept_and_upgrade(&listener);
        sock.write_all(&encode_frame(FrameType::Started, b""))
            .unwrap();
        sock.write_all(&encode_frame(FrameType::Exit, br#"{"code":7}"#))
            .unwrap();
        sock.flush().unwrap();
        drain_until_client_closes(&mut sock);
    });
    let sock = connect_and_upgrade(addr);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code =
        run_relay_session(sock, start(), &mut out, &mut err, Cursor::new(Vec::new())).unwrap();
    server.join().unwrap();
    assert_eq!(code, 7);
}

#[test]
fn stdin_is_echoed_through_the_duplex() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut sock = accept_and_upgrade(&listener);
        sock.write_all(&encode_frame(FrameType::Started, b""))
            .unwrap();
        // Read client frames until we see STDIN, echo its payload as STDOUT.
        let mut acc = FrameAccumulator::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = sock.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            acc.extend(&buf[..n]);
            while let Some(f) = acc.next_frame().unwrap() {
                if f.kind == Some(FrameType::Stdin) {
                    sock.write_all(&encode_frame(FrameType::Stdout, &f.payload))
                        .unwrap();
                    sock.write_all(&encode_frame(FrameType::Exit, br#"{"code":0}"#))
                        .unwrap();
                    sock.flush().unwrap();
                    drain_until_client_closes(&mut sock);
                    return;
                }
            }
        }
    });
    let sock = connect_and_upgrade(addr);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_relay_session(
        sock,
        start(),
        &mut out,
        &mut err,
        Cursor::new(b"ping".to_vec()),
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"ping");
}

#[test]
fn transport_close_before_exit_yields_sentinel() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut sock = accept_and_upgrade(&listener);
        sock.write_all(&encode_frame(FrameType::Started, b""))
            .unwrap();
        sock.flush().unwrap();
        // Drop the socket without an EXIT frame → client sees a mid-run close.
        drop(sock);
    });
    let sock = connect_and_upgrade(addr);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code =
        run_relay_session(sock, start(), &mut out, &mut err, Cursor::new(Vec::new())).unwrap();
    server.join().unwrap();
    assert_eq!(code, SENTINEL_ABNORMAL_EXIT);
}

#[test]
fn many_concurrent_execs() {
    let mut handles = Vec::new();
    for i in 0..8 {
        handles.push(thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let mut sock = accept_and_upgrade(&listener);
                sock.write_all(&encode_frame(FrameType::Started, b""))
                    .unwrap();
                let body = format!(r#"{{"code":{i}}}"#);
                sock.write_all(&encode_frame(FrameType::Exit, body.as_bytes()))
                    .unwrap();
                sock.flush().unwrap();
                drain_until_client_closes(&mut sock);
            });
            let sock = connect_and_upgrade(addr);
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code =
                run_relay_session(sock, start(), &mut out, &mut err, Cursor::new(Vec::new()))
                    .unwrap();
            server.join().unwrap();
            assert_eq!(code, i);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

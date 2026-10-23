// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Downstream correlation-header propagation, in an isolated test binary.
//!
//! This lives in its own integration-test file on purpose. The process MS-CV is
//! stashed behind a `Mutex` that [`mxc_sdk::mxc_common::telemetry::current_correlation_vector`]
//! reads with `try_lock` (deliberately, so the panic hook cannot deadlock on a
//! reentrant read). A read that loses that race legitimately observes an empty
//! vector and the header is then omitted — correct production behaviour, but it
//! makes any assertion on the header flaky when sibling tests in the same binary
//! touch the same mutex concurrently. Cargo runs each integration-test file as a
//! separate PROCESS, so keeping the only CV-dependent assertions here removes the
//! contention instead of papering over it with a retry.

#![cfg(feature = "w365_agents")]

use std::io::{Read, Write};

use std::net::{TcpListener, TcpStream};

use std::thread;

use mxc_sdk::w365agents_common::cp::{release_request, SmClient};

use mxc_sdk::w365agents_common::exec::transport::{build_upgrade_request, UpgradeTarget};

use mxc_sdk::w365agents_common::http::send;

use mxc_sdk::w365agents_common::secret::Redacted;

use mxc_sdk::mxc_common::telemetry::{current_correlation_vector, set_process_correlation_vector};

/// A computer/session GUID; `computerId == sessionId` on the pooled path.
const COMPUTER: &str = "538fdbe2-1f9a-40c7-b8dd-f2391d55a24a";
/// A stand-in MS-CV to seed so the outbound correlation header is emitted.
const CORRELATION_VECTOR: &str = "correlationLoopbackCv.0";

/// Accept one connection, capture the request head, and reply with `response`.
fn serve_once(listener: TcpListener, response: &'static str) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut head = Vec::new();
        let mut one = [0u8; 1];
        loop {
            let n = sock.read(&mut one).expect("read request head");
            if n == 0 {
                break;
            }
            head.push(one[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        sock.write_all(response.as_bytes()).expect("write response");
        sock.flush().ok();
        String::from_utf8_lossy(&head).into_owned()
    })
}

/// Assert `wire` carries exactly one `x-ms-correlation-id`, with the seeded value.
fn assert_carries_the_correlation_vector(wire: &str, what: &str) {
    let correlation_lines = wire
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("x-ms-correlation-id:"))
        .count();
    assert_eq!(
        correlation_lines, 1,
        "{what}: expected exactly one correlation header:\n{wire}"
    );
    assert!(
        wire.contains(&format!("x-ms-correlation-id: {CORRELATION_VECTOR}")),
        "{what}: correlation value wrong:\n{wire}"
    );
    // The header must land inside the header block, not after the terminator.
    let head = wire.split("\r\n\r\n").next().unwrap_or_default();
    assert!(
        head.to_ascii_lowercase().contains("x-ms-correlation-id: "),
        "{what}: correlation header escaped the header block:\n{wire}"
    );
}

/// The MS-CV the executor seeds must reach **every** outbound path as
/// `x-ms-correlation-id`, so an operator can pivot from a failed `wxc-exec` to
/// the matching service request. The framework emits the CV into its own
/// telemetry, but only the backend can put it on the outbound wire.
///
/// Deliberately **one** `#[test]`, not one per path. This binary exists so that
/// nothing reads the process CV concurrently: the read uses `try_lock`, so a
/// second `#[test]` running in parallel here could lose the lock race,
/// observe an empty CV, omit the header, and fail the assertion.
#[test]
fn the_seeded_correlation_vector_reaches_every_outbound_request() {
    set_process_correlation_vector(CORRELATION_VECTOR);
    assert_eq!(
        current_correlation_vector(),
        CORRELATION_VECTOR,
        "this binary must own the process correlation vector"
    );

    // 1. SessionManagement release, over a real socket: proves the header
    //    survives `HttpRequest` serialisation onto the wire.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = serve_once(
        listener,
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    );

    let client = SmClient {
        base_host: addr.ip().to_string(),
        port: addr.port(),
        api_version: "2.0".to_string(),
        bearer_token: Redacted::new("SM_TOKEN"),
    };
    let mut sock = TcpStream::connect(addr).unwrap();
    send(&mut sock, &release_request(&client, COMPUTER)).unwrap();

    let sent = server.join().unwrap();
    assert_carries_the_correlation_vector(&sent, "sm release");
    // The credential must not have been logged into the captured head by any
    // diagnostic path; only the wire Authorization header carries it.
    assert!(
        sent.contains("Authorization: "),
        "authorization header missing:\n{sent}"
    );

    // 2. The ARI exec upgrade — the request an operator is most likely pivoting
    //    *from*. It hand-rolls its wire string instead of going through
    //    `HttpRequest`, which is exactly how it was missed the first time.
    let target = UpgradeTarget {
        host: "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9.westus3.ari.example.net".to_string(),
        port: 443,
        path: format!("/computers/{COMPUTER}/microsoft.mxc-exec"),
        computer_id: COMPUTER.to_string(),
        bearer_token: Redacted::new("DP_TOKEN"),
        capability: "microsoft.mxc-exec".to_string(),
    };
    assert_carries_the_correlation_vector(
        &build_upgrade_request(&target).expect("upgrade request must build"),
        "exec upgrade",
    );
}

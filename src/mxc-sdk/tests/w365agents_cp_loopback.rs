// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Control-plane and status-poller wiring over a loopback TCP server.
//!
//! These integration tests drive the pure request builders
//! (`cp::checkout_request`, `cp::release_request`, `dp::status_request`), the
//! HTTP codec (`http::send` -> `build_request` / `read_response`), and the
//! response mappers against a real `TcpListener` on `127.0.0.1`, asserting on
//! the request head the server hand-reads back — the plain-TCP pattern
//! established by `tests/w365agents_loopback.rs`.
//!
//! They call `http::send` directly rather than the higher-level `cp::checkout`
//! / `cp::release` / `dp::poll_until_ready` wrappers: those dial through
//! `http::https_json` -> `http::tls_dial`, which performs a real TLS handshake
//! validated against the Web PKI roots, with no seam to inject a loopback root
//! or a plain-TCP transport. A loopback server cannot complete that handshake,
//! so the `https_json` / `tls_dial` dial and the `poll_until_ready` retry loop
//! stay covered only by the pure unit tests, not here. Each client still sets
//! its `port` to mirror production shape.

#![cfg(feature = "w365_agents")]

use std::io::{Read, Write};

use std::net::{TcpListener, TcpStream};

use std::thread;

use std::time::Duration;

use mxc_sdk::w365agents_common::cp::{
    checkout_request, map_checkout_response, map_release_response, release_request,
    CheckoutOptions, SmClient,
};

use mxc_sdk::w365agents_common::dp::{map_status_response, status_request, DeviceState, DpClient};

use mxc_sdk::w365agents_common::http::send;

use mxc_sdk::w365agents_common::secret::Redacted;

/// A registered pool GUID (checkout route + minted sandbox id).
const POOL: &str = "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9";
/// A computer/session GUID; `computerId == sessionId` on the pooled path.
const COMPUTER: &str = "538fdbe2-1f9a-40c7-b8dd-f2391d55a24a";
/// Ceiling on a single loopback exchange, so a wiring regression fails the test
/// instead of hanging CI. The server always replies promptly, so it is never
/// reached in a healthy run.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept one connection, capture the request head, and reply with `response`.
///
/// Returns the captured head so the caller can assert on the request line and
/// headers after it has read the response.
fn serve_once(listener: TcpListener, response: String) -> thread::JoinHandle<String> {
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

fn sm_client(host: String, port: u16) -> SmClient {
    SmClient {
        base_host: host,
        port,
        api_version: "2.0".to_string(),
        bearer_token: Redacted::new("SM_TOKEN"),
    }
}

/// Connect, send `req` with a read timeout, and return the parsed response.
fn round_trip(
    addr: std::net::SocketAddr,
    req: &mxc_sdk::w365agents_common::http::HttpRequest,
) -> mxc_sdk::w365agents_common::http::HttpResponse {
    let mut sock = TcpStream::connect(addr).expect("connect");
    sock.set_read_timeout(Some(READ_TIMEOUT))
        .expect("set read timeout");
    send(&mut sock, req).expect("send")
}

#[test]
fn checkout_round_trips_over_a_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(
        r#"{{"sessionId":"{COMPUTER}","status":"Succeeded","computerId":"{COMPUTER}","computerUrl":"https://cu"}}"#
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nx-ms-request-id: rid-1\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let server = serve_once(listener, response);

    let client = sm_client(addr.ip().to_string(), addr.port());
    let req = checkout_request(
        &client,
        &CheckoutOptions {
            pool_id: POOL.to_string(),
            agent_user_token: Some(Redacted::new("AUX")),
            user_object_id: Some("11111111-2222-3333-4444-555555555555".to_string()),
            user_type: Some("Agentic".to_string()),
        },
    );
    let resp = round_trip(addr, &req);
    let session = map_checkout_response(&resp).expect("map checkout");

    assert_eq!(session.session_id, COMPUTER);
    assert_eq!(session.computer_id.as_deref(), Some(COMPUTER));
    assert_eq!(resp.request_id.as_deref(), Some("rid-1"));

    let sent = server.join().unwrap();
    assert!(
        sent.starts_with(&format!(
            "POST /api/pools/{POOL}/sessions?api-version=2.0 HTTP/1.1"
        )),
        "unexpected request line:\n{sent}"
    );
    // The bearer scheme + fake token ride on the wire (the redaction is only in
    // `Debug`/logs, never in the bytes the service must authenticate).
    assert!(
        sent.contains("Authorization: Bearer SM_TOKEN"),
        "authorization header missing:\n{sent}"
    );
    assert!(
        sent.contains("x-ms-authorization-auxiliary: AUX"),
        "aux header:\n{sent}"
    );
    assert!(
        sent.contains("user-object-id: 11111111-2222-3333-4444-555555555555"),
        "user-object-id header:\n{sent}"
    );
    assert!(
        sent.contains("user-type: Agentic"),
        "user-type header:\n{sent}"
    );
    assert!(
        sent.contains("Connection: close"),
        "connection header:\n{sent}"
    );
    // The correlation header is asserted in `tests/w365agents_correlation_loopback.rs`,
    // which is a separate test BINARY: the process MS-CV lives behind a mutex
    // read with `try_lock`, so a read racing the other tests in this binary can
    // legitimately observe an empty vector and omit the header.
}

#[test]
fn release_sends_delete_with_the_session_header() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = serve_once(
        listener,
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string(),
    );

    let client = sm_client(addr.ip().to_string(), addr.port());
    let req = release_request(&client, COMPUTER);
    let resp = round_trip(addr, &req);
    map_release_response(&resp).expect("204 must be a successful release");

    let sent = server.join().unwrap();
    assert!(
        sent.starts_with(&format!(
            "DELETE /api/sessions/{COMPUTER}?api-version=2.0 HTTP/1.1"
        )),
        "unexpected request line:\n{sent}"
    );
    assert!(
        sent.contains(&format!("x-ms-sessionId: {COMPUTER}")),
        "locality header missing:\n{sent}"
    );
}

#[test]
fn release_treats_a_404_as_already_released() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = serve_once(
        listener,
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
    );

    let client = sm_client(addr.ip().to_string(), addr.port());
    let req = release_request(&client, COMPUTER);
    let resp = round_trip(addr, &req);
    map_release_response(&resp).expect("404 must be success-equivalent (already released)");
}

#[test]
fn status_request_carries_the_computer_id_and_parses_ready() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = r#"{"status":"Ready","computerUrl":"https://cu","screenshareUrl":"https://su"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let server = serve_once(listener, response);

    let client = DpClient {
        host: addr.ip().to_string(),
        port: addr.port(),
        api_version: "1.0".to_string(),
        computer_id: COMPUTER.to_string(),
        bearer_token: Redacted::new("DP_TOKEN"),
    };
    let req = status_request(&client);
    let resp = round_trip(addr, &req);
    let status = map_status_response(&resp).expect("map status");

    assert_eq!(status.state, DeviceState::Ready);
    assert_eq!(status.computer_url.as_deref(), Some("https://cu"));

    let sent = server.join().unwrap();
    assert!(
        sent.starts_with(&format!(
            "GET /computers/{COMPUTER}/status?api-version=1.0 HTTP/1.1"
        )),
        "unexpected request line:\n{sent}"
    );
    // Required on the partner path: a missing or mismatched value 403s at ARI.
    assert!(
        sent.contains(&format!("x-ms-computerId: {COMPUTER}")),
        "computerId header missing:\n{sent}"
    );
}

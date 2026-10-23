// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TLS connection and HTTP/1.1 WebSocket upgrade handshake for the exec duplex.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rustls::{ClientConnection, StreamOwned};

use crate::mxc_common::mxc_error::MxcError;

use crate::w365agents_common::http::reject_control_chars;
use crate::w365agents_common::secret::Redacted;

/// Poll cadence for the relay's read-timeout (bounds stdin delivery latency).
pub const READ_POLL_TIMEOUT: Duration = Duration::from_millis(50);

/// Generous timeout for the TLS handshake + `101` upgrade, before switching to
/// the tighter [`READ_POLL_TIMEOUT`] for the relay phase.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on the `x-ms-request-id` copied from a failed upgrade response into the
/// error payload. Comfortably above a GUID, so a well-behaved service is never
/// truncated.
const MAX_REQUEST_ID_CHARS: usize = 128;

/// Everything needed to open the exec duplex to one device via the relay.
///
/// `Debug` is derived: the token field is [`Redacted`], which redacts itself,
/// so the guarantee lives on the value rather than on this struct's impl.
#[derive(Debug, Clone)]
pub struct UpgradeTarget {
    pub host: String,
    pub port: u16,
    /// Request path, e.g. `/computers/{computerId}/{capability}`.
    pub path: String,
    pub computer_id: String,
    /// Dataplane bearer token. `Redacted` so the value cannot escape through a
    /// `Debug`, a `Display`, or direct field access.
    pub bearer_token: Redacted,
    /// Reverse-DNS capability name, e.g. `microsoft.mxc-exec`.
    pub capability: String,
}

/// The HTTP/1.1 upgrade request. Presented as a standard WebSocket (RFC-6455)
/// handshake because the ARI ingress only forwards `Upgrade: websocket` — a bare
/// `Upgrade: <capability>` is rejected at the edge with a 403 before it reaches
/// ARI. Both peers still raw-tunnel bytes after `101` (no WebSocket framing), so
/// the handshake is only an edge-traversal formality.
///
/// This builder hand-assembles its wire string rather than going through
/// [`crate::w365agents_common::http::HttpRequest`], so it applies the same control-character
/// chokepoint itself — that divergence is exactly how the correlation header was
/// missed once already.
///
/// # Errors
/// Returns `policy_validation` when the path, host, computer id, or bearer token
/// contains a control character (which would split the request line).
pub fn build_upgrade_request(t: &UpgradeTarget) -> Result<String, MxcError> {
    reject_control_chars("path", &t.path)?;
    reject_control_chars("host", &t.host)?;
    reject_control_chars("computerId", &t.computer_id)?;
    if t.bearer_token.expose().chars().any(char::is_control) {
        return Err(MxcError::policy_validation(
            "w365_agents: the bearer token contains a control character",
        ));
    }
    // Assembled via push_str with the header name, auth scheme, and the config
    // bearer token pushed as SEPARATE pieces (never one combined credential
    // literal) so the real token is always interpolated into the header.
    let header_name = "Authorization";
    let scheme = "Bearer";
    let mut req = String::with_capacity(256);
    req.push_str(&format!("GET {} HTTP/1.1\r\n", t.path));
    req.push_str(&format!("Host: {}\r\n", t.host));
    req.push_str("Connection: Upgrade\r\n");
    // ARI's ingress (Envoy) only forwards `Upgrade: websocket`; a bare
    // `Upgrade: <capability>` is rejected at the edge (403) before reaching ARI.
    // ARI and the device both raw-tunnel after `101` and never validate
    // `Sec-WebSocket-Accept`, so a constant RFC-6455 key satisfies the handshake.
    // The capability still selects the endpoint via the request path (t.path).
    req.push_str("Upgrade: websocket\r\n");
    req.push_str("Sec-WebSocket-Version: 13\r\n");
    req.push_str("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
    req.push_str(header_name);
    req.push_str(": ");
    req.push_str(scheme);
    req.push(' ');
    req.push_str(t.bearer_token.expose());
    req.push_str("\r\n");
    req.push_str(&format!("x-ms-computerId: {}\r\n", t.computer_id));
    // Tag the upgrade with the process MS-CV so a failed `wxc-exec` can be pivoted
    // to the matching ARI request. Omitted when telemetry is off, because a blank
    // header is worse than no header. The value is structurally CR/LF-free (an
    // MS-CV is base64 + dot-separated integers), but it still goes through the
    // chokepoint: the claim above is that the invariant lives *at* the wire, and
    // an unchecked append would make that true only by luck.
    if let Some((name, value)) = crate::w365agents_common::http::correlation_header() {
        reject_control_chars("correlation header name", &name)?;
        reject_control_chars("correlation header value", &value)?;
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    Ok(req)
}

/// Map a pre-`101` HTTP status to a typed error. The relay's taxonomy is
/// deliberate: 503 means "come back shortly", 404 means the capability *name*
/// is wrong, and neither is a dead sandbox. Nothing here may be terminal
/// unless the service actually proved it.
///
/// `request_id` is ARI's `x-ms-request-id`, threaded into `details` when the
/// response carried one. ARI captures the inbound correlation id only *after*
/// authorization, so a 401/403 is not tagged with it service-side and the
/// request id is the only handle an operator has on those two.
fn classify_upgrade_status(status: u16, status_line: &str, request_id: Option<&str>) -> MxcError {
    // A stable, machine-readable `code` rides alongside the free-text message so
    // a consumer can branch without string-matching (matches `cp.rs` / `dp.rs`).
    let details = |code: &str, retryable: bool| {
        let mut d = serde_json::json!({ "httpStatus": status, "code": code });
        if retryable {
            d["retryable"] = serde_json::json!(true);
        }
        if let Some(id) = request_id {
            d["requestId"] = serde_json::json!(id);
        }
        d
    };
    match status {
        // SessionUnavailable / NoWorkersAvailable — the device is not connected
        // right now. Carries Retry-After: 1.
        503 => MxcError::backend_error(format!(
            "exec upgrade failed: device_unavailable ({status_line})"
        ))
        .with_details(details("device_unavailable", true)),
        502 | 504 => MxcError::backend_error(format!(
            "exec upgrade failed: relay_upstream ({status_line})"
        ))
        .with_details(details("relay_upstream", true)),
        // CapabilityNotFound: the path segment is not a valid reverse-DNS
        // capability name — a client config error, not a lifecycle failure.
        404 => MxcError::policy_validation(format!(
            "exec upgrade failed: unknown capability name ({status_line})"
        ))
        .with_details(details("unknown_capability", false)),
        401 => MxcError::backend_error(format!("exec upgrade failed: auth_denied ({status_line})"))
            .with_details(details("auth_denied", false)),
        403 => MxcError::backend_error(format!(
            "exec upgrade failed: pool_authorization_denied ({status_line})"
        ))
        .with_details(details("pool_authorization_denied", false)),
        // HeaderMismatch — the backend derives header and path from the same id,
        // so this is an internal invariant violation.
        400 => MxcError::backend_error(format!("exec upgrade failed: id_mismatch ({status_line})"))
            .with_details(details("id_mismatch", false)),
        413 => MxcError::backend_error(format!(
            "exec upgrade failed: payload_too_large ({status_line})"
        ))
        .with_details(details("payload_too_large", false)),
        _ => MxcError::backend_error(format!(
            "exec upgrade failed: expected 101, got status line '{status_line}'"
        ))
        .with_details(details("unexpected_status", false)),
    }
}

/// Read and validate the upgrade response: consume bytes through the first
/// blank line (`\r\n\r\n`) and require a `101` status. Reads one byte at a time
/// so no post-header duplex bytes are stranded in a buffer.
///
/// # Errors
/// Returns `backend_error` if the connection closes before a response, if the
/// header block exceeds 16 KiB, or on any non-`101` status other than `404`;
/// returns `policy_validation` for a `404` (the capability name is not valid
/// reverse-DNS). Every error carries `details.code`, and retryable causes
/// (`503`, `502`/`504`) additionally set `details.retryable = true`.
pub fn read_upgrade_response<S: Read>(stream: &mut S) -> Result<(), MxcError> {
    let mut head = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    loop {
        let n = stream
            .read(&mut one)
            .map_err(|e| MxcError::backend_error(format!("read upgrade response: {e}")))?;
        if n == 0 {
            return Err(MxcError::backend_error(
                "exec upgrade failed: connection closed before response",
            ));
        }
        head.push(one[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > crate::w365agents_common::http::MAX_HEADER_BYTES {
            return Err(MxcError::backend_error(
                "exec upgrade failed: response header too large",
            ));
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status_line = text.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    if status == 101 {
        return Ok(());
    }
    // ARI stamps every response with `x-ms-request-id`; surface it so a failed
    // upgrade is correlatable even on the 401/403 paths, where the service does
    // not record the inbound correlation id.
    let request_id = text
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("x-ms-request-id"))
        .map(|(_, value)| {
            // Bounded at 16 KiB by the header-block cap above, but a service is
            // only ever going to send a GUID here; truncate so a malformed or
            // hostile response cannot bloat the error payload an operator reads.
            // Sliced on a char boundary: the head is `from_utf8_lossy`d, so a
            // byte-index slice could panic mid-codepoint.
            let v = value.trim();
            v.char_indices()
                .nth(MAX_REQUEST_ID_CHARS)
                .map_or(v, |(i, _)| &v[..i])
        });
    Err(classify_upgrade_status(status, status_line, request_id))
}

/// Connect TCP → TLS handshake → HTTP/1.1 upgrade → `101`, returning the raw
/// duplex (a blocking `Read + Write` TLS stream with a read-timeout applied).
pub fn connect_upgrade(
    t: &UpgradeTarget,
) -> Result<StreamOwned<ClientConnection, TcpStream>, MxcError> {
    // Generous timeout for the TLS handshake + `101`; switched to the poll
    // cadence only *after* the upgrade so `read_upgrade_response` cannot
    // spuriously fail on a slow-but-healthy server.
    let mut tls = crate::w365agents_common::http::tls_dial(&t.host, t.port, HANDSHAKE_TIMEOUT)?;

    let wire = build_upgrade_request(t)?;
    tls.write_all(wire.as_bytes())
        .and_then(|()| tls.flush())
        .map_err(|e| MxcError::backend_error(format!("send upgrade request: {e}")))?;
    read_upgrade_response(&mut tls)?;

    // Post-`101`: switch to the relay poll cadence so the loop wakes to drain
    // queued stdin. `StreamOwned::sock` is the underlying `TcpStream`.
    tls.sock
        .set_read_timeout(Some(READ_POLL_TIMEOUT))
        .map_err(|e| MxcError::backend_error(format!("set read timeout: {e}")))?;
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::super::transport::{build_upgrade_request, read_upgrade_response, UpgradeTarget};
    use super::MAX_REQUEST_ID_CHARS;
    use crate::w365agents_common::secret::Redacted;

    /// Drive `read_upgrade_response` over a canned failure head and return the
    /// `details.requestId` it extracted, if any.
    fn request_id_from(head: &str) -> Option<String> {
        let err = read_upgrade_response(&mut Cursor::new(head.as_bytes().to_vec()))
            .expect_err("a non-101 status must be an error");
        err.details.and_then(|d| {
            d.get("requestId")
                .and_then(|v| v.as_str().map(str::to_owned))
        })
    }

    #[test]
    fn the_request_id_is_lifted_out_of_a_failed_upgrade_response() {
        let id = request_id_from(
            "HTTP/1.1 503 Service Unavailable\r\nx-ms-request-id: 7f1c\r\nRetry-After: 1\r\n\r\n",
        );
        assert_eq!(id.as_deref(), Some("7f1c"));
    }

    #[test]
    fn a_colon_in_the_reason_phrase_is_not_mistaken_for_a_header() {
        // `split_once(':')` sees the status line as a name/value pair; the name
        // must fail the case-insensitive match rather than be adopted.
        let id = request_id_from("HTTP/1.1 403 Forbidden: nope\r\nx-ms-request-id: real\r\n\r\n");
        assert_eq!(id.as_deref(), Some("real"));
    }

    #[test]
    fn the_first_of_several_request_ids_wins_deterministically() {
        // Matches the first-wins rule the cp/dp path already uses, so the two
        // code paths cannot disagree about which id an operator is given.
        let id =
            request_id_from("HTTP/1.1 500 x\r\nx-ms-request-id: a\r\nX-MS-Request-Id: b\r\n\r\n");
        assert_eq!(id.as_deref(), Some("a"));
    }

    #[test]
    fn an_absent_request_id_is_simply_omitted() {
        let err = read_upgrade_response(&mut Cursor::new(
            b"HTTP/1.1 401 Unauthorized\r\n\r\n".to_vec(),
        ))
        .expect_err("401 is an error");
        let details = err.details.expect("details");
        assert_eq!(details["code"], "auth_denied");
        assert!(details.get("requestId").is_none());
    }

    #[test]
    fn an_oversized_request_id_is_truncated_on_a_char_boundary() {
        // Padded with a 3-byte char on purpose: 128 is not a multiple of 3, so
        // byte offset 128 lands mid-codepoint and a naive `&v[..128]` byte slice
        // panics. A 2-byte pad would only mis-count, not panic, leaving the
        // char-boundary claim untested.
        let long = "\u{20AC}".repeat(MAX_REQUEST_ID_CHARS * 2);
        let id = request_id_from(&format!(
            "HTTP/1.1 500 x\r\nx-ms-request-id: {long}\r\n\r\n"
        ))
        .expect("an id was present");
        assert_eq!(id.chars().count(), MAX_REQUEST_ID_CHARS);
    }

    #[test]
    fn an_oversized_upgrade_response_header_is_refused_before_it_can_exhaust_memory() {
        // This read loop is a second copy of `http::read_response`'s header
        // scan. Both must enforce the same cap, and this path is the one a
        // hostile relay reaches first. Without the guard an origin that never
        // sends the blank line grows `head` without bound.
        //
        // The two copies now share `http::MAX_HEADER_BYTES`, so this test also
        // fails if someone re-introduces a divergent literal here.
        let flood = vec![b'x'; crate::w365agents_common::http::MAX_HEADER_BYTES + 1024];
        let err = read_upgrade_response(&mut Cursor::new(flood))
            .expect_err("an unterminated header block must be refused");
        assert!(
            err.message.contains("response header too large"),
            "{}",
            err.message
        );
    }

    fn target() -> UpgradeTarget {
        UpgradeTarget {
            host: "pool123.dp.example.com".into(),
            port: 443,
            path: "/computers/abc-guid/microsoft.mxc-exec".into(),
            computer_id: "abc-guid".into(),
            bearer_token: Redacted::new("TOK"),
            capability: "microsoft.mxc-exec".into(),
        }
    }

    #[test]
    fn builds_a_raw_http11_upgrade_request() {
        let req = build_upgrade_request(&target()).unwrap();
        assert!(req.starts_with("GET /computers/abc-guid/microsoft.mxc-exec HTTP/1.1\r\n"));
        assert!(req.contains("Host: pool123.dp.example.com\r\n"));
        assert!(req.contains("Connection: Upgrade\r\n"));
        assert!(req.contains("Upgrade: websocket\r\n"));
        assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(req.contains("Sec-WebSocket-Key: "));
        assert!(req.contains("Bearer "), "must use the Bearer scheme");
        assert!(
            req.contains(target().bearer_token.expose()),
            "must interpolate the config bearer token"
        );
        assert!(req.contains("x-ms-computerId: abc-guid\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn debug_redacts_the_bearer_token() {
        let mut t = target();
        t.bearer_token = Redacted::new("UPGRADE_SECRET");
        let dbg = format!("{t:?}");
        assert!(
            !dbg.contains("UPGRADE_SECRET"),
            "bearer token leaked: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
    }

    #[test]
    fn accepts_101_switching_protocols() {
        let mut resp = Cursor::new(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: microsoft.mxc-exec\r\n\r\n".to_vec(),
        );
        assert!(read_upgrade_response(&mut resp).is_ok());
    }

    #[test]
    fn rejects_non_101() {
        let mut resp = Cursor::new(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec());
        let err = read_upgrade_response(&mut resp).unwrap_err();
        assert!(err.message.contains("403"));
    }

    fn read_status(raw: &str) -> crate::mxc_common::mxc_error::MxcError {
        let mut resp = Cursor::new(raw.as_bytes().to_vec());
        read_upgrade_response(&mut resp).unwrap_err()
    }

    #[test]
    fn a_503_is_a_retryable_device_unavailable() {
        // ARI writes 503 SessionUnavailable / NoWorkersAvailable with Retry-After: 1
        // for a device that is not currently connected. This must NOT be terminal.
        for reason in ["SessionUnavailable", "NoWorkersAvailable"] {
            let err = read_status(&format!(
                "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n{reason}"
            ));
            let details = err.details.as_ref().expect("details");
            assert_eq!(
                details["code"],
                serde_json::json!("device_unavailable"),
                "{reason}"
            );
            assert_eq!(details["retryable"], serde_json::json!(true), "{reason}");
        }
    }

    #[test]
    fn a_502_or_504_is_a_retryable_relay_upstream_failure() {
        for status in ["502 Bad Gateway", "504 Gateway Timeout"] {
            let err = read_status(&format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n"));
            let details = err.details.as_ref().expect("details");
            assert_eq!(
                details["code"],
                serde_json::json!("relay_upstream"),
                "{status}"
            );
            assert_eq!(details["retryable"], serde_json::json!(true), "{status}");
        }
    }

    #[test]
    fn a_404_is_a_bad_capability_name_not_a_dead_sandbox() {
        // ARI's only 404 on this route is CapabilityNotFound: the route segment
        // is not a valid reverse-DNS capability. That is a config typo.
        let err = read_status("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(err.code.as_str(), "policy_validation");
        assert_eq!(
            err.details.as_ref().expect("details")["code"],
            serde_json::json!("unknown_capability")
        );
    }

    #[test]
    fn auth_statuses_are_distinguished() {
        // 401 and 403 must be distinguishable WITHOUT parsing the message.
        let unauth = read_status("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            unauth.details.as_ref().expect("details")["code"],
            serde_json::json!("auth_denied")
        );

        let forbidden = read_status("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            forbidden.details.as_ref().expect("details")["code"],
            serde_json::json!("pool_authorization_denied")
        );
    }

    #[test]
    fn a_400_is_an_id_mismatch_invariant_violation() {
        let err = read_status("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            err.details.as_ref().expect("details")["code"],
            serde_json::json!("id_mismatch")
        );
    }

    #[test]
    fn a_413_is_reported_as_payload_too_large() {
        let err = read_status("HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            err.details.as_ref().expect("details")["code"],
            serde_json::json!("payload_too_large")
        );
    }

    #[test]
    fn an_unclassified_status_still_reports_the_code() {
        let err = read_status("HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(err.code.as_str(), "backend_error");
        assert_eq!(
            err.details.as_ref().expect("details")["code"],
            serde_json::json!("unexpected_status")
        );
        // The raw status is preserved for diagnosis.
        assert_eq!(
            err.details.as_ref().expect("details")["httpStatus"],
            serde_json::json!(418)
        );
    }
}

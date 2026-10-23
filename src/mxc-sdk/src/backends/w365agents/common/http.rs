// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal HTTP/1.1 client used by the control plane and the status poller.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, StreamOwned};

use crate::mxc_common::mxc_error::MxcError;

use crate::w365agents_common::secret::Redacted;

/// Cap on the response header block, mirroring `exec::transport`.
pub(crate) const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Cap on the response body, so a hostile or buggy origin cannot force an
/// unbounded allocation via `Content-Length` (mirrors `MAX_HEADER_BYTES`).
/// Control-plane responses are a few KiB; 8 MiB is generous headroom.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// One outbound request. `bearer_token` is separate from `headers` so the
/// redacting `Debug` below can never print it.
pub struct HttpRequest {
    pub method: &'static str,
    pub path: String,
    pub host: String,
    pub bearer_token: Redacted,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

// Manual Debug: the bearer token must never reach a log line or an error
// `details` object (spec §8).
/// Header names whose values are credentials and must never be printed.
/// Matched case-insensitively as substrings, so `x-ms-authorization-auxiliary`
/// is covered by `authorization`.
const SENSITIVE_HEADER_MARKERS: [&str; 4] = ["authorization", "token", "secret", "key"];

/// True when a header's value is a credential that must be redacted in `Debug`.
fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADER_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

// Manual Debug: the bearer token must never reach a log line or an error
// `details` object (spec §8). Header VALUES are redacted by name as well —
// the agentic checkout carries a second credential in the
// `x-ms-authorization-auxiliary` header, which is just as sensitive as the
// bearer token and would otherwise print verbatim.
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let shown = if is_sensitive_header(name) {
                    "<redacted>"
                } else {
                    value.as_str()
                };
                (name.as_str(), shown)
            })
            .collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("host", &self.host)
            .field("bearer_token", &"<redacted>")
            .field("headers", &headers)
            .field("body", &self.body.as_ref().map(|_| "<body>"))
            .finish()
    }
}

/// One inbound response. `request_id` carries the service's `x-ms-request-id`
/// into error `details` for cross-service diagnosis (spec §8).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub request_id: Option<String>,
}

/// Reject a value that could break out of its request line or header.
///
/// This is the **chokepoint**: every value that reaches the wire passes through
/// here, so a new caller-supplied field cannot reintroduce request splitting by
/// forgetting a boundary check. CR and LF are the splitting characters; NUL and
/// the other C0 controls are rejected too because they have no legal place in a
/// request line or a header value and their presence means the value did not
/// come from where the caller claimed.
///
/// # Errors
/// Returns `policy_validation` naming `field` when `value` contains a control
/// character.
pub(crate) fn reject_control_chars(field: &str, value: &str) -> Result<(), MxcError> {
    if let Some(bad) = value.chars().find(|c| c.is_control()) {
        return Err(MxcError::policy_validation(format!(
            "w365_agents: '{field}' contains the illegal control character {:?}; \
             a request line or header value may not contain control characters",
            bad
        )));
    }
    Ok(())
}

/// Serialize the request. The `Authorization` header is assembled from separate
/// pieces so no combined credential literal ever exists in the binary.
///
/// Every interpolated value is checked for control characters first, so a
/// caller-supplied path segment, host, or header cannot split the request.
///
/// # Errors
/// Returns `policy_validation` when the method, path, host, or any header name
/// or value contains a control character.
pub fn build_request(req: &HttpRequest) -> Result<String, MxcError> {
    reject_control_chars("path", req.path.as_str())?;
    reject_control_chars("host", &req.host)?;
    for (name, value) in &req.headers {
        reject_control_chars("header name", name)?;
        reject_control_chars(&format!("header '{name}'"), value)?;
    }
    // The bearer token is never checked against `field` names in an error
    // message, so validate it without echoing it: a token with a control
    // character would split the request just as readily as any other value.
    if req.bearer_token.expose().chars().any(char::is_control) {
        return Err(MxcError::policy_validation(
            "w365_agents: the bearer token contains a control character",
        ));
    }
    let mut out = String::with_capacity(512);
    out.push_str(&format!("{} {} HTTP/1.1\r\n", req.method, req.path));
    out.push_str(&format!("Host: {}\r\n", req.host));
    out.push_str("Authorization");
    out.push_str(": ");
    out.push_str("Bearer");
    out.push(' ');
    out.push_str(req.bearer_token.expose());
    out.push_str("\r\n");
    out.push_str("Accept: application/json\r\n");
    // One request per process: closing the connection lets the reader treat EOF
    // as end-of-body when the service omits Content-Length.
    out.push_str("Connection: close\r\n");
    for (name, value) in &req.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = &req.body {
        out.push_str("Content-Type: application/json\r\n");
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
        out.push_str("\r\n");
        out.push_str(body);
    } else {
        out.push_str("\r\n");
    }
    Ok(out)
}

/// The `x-ms-correlation-id` header for this process, when one should be sent.
///
/// The value is this process's MS-CV, seeded and spun by the executor and read
/// back through [`crate::mxc_common::telemetry::current_correlation_vector`]. Returns
/// `None` when telemetry is disabled (the MS-CV is the empty string): a blank
/// correlation header must never be sent, since it is optional at ARI, which
/// distinguishes absent from empty.
///
/// Sending it lets an operator pivot from a failed phase to the matching SM or
/// ARI request. Caveat: ARI records the value as an `Activity` tag only *after*
/// authorization, so 401/403 responses are NOT tagged on ARI's side and
/// correlate solely through the `x-ms-request-id` this crate already captures in
/// each error's `details` (spec §8).
pub(crate) fn correlation_header() -> Option<(String, String)> {
    correlation_header_from(&crate::mxc_common::telemetry::current_correlation_vector())
}

/// Build the correlation header from an explicit MS-CV, or `None` when empty.
///
/// Split out from [`correlation_header`] so the omit-when-blank rule is
/// unit-testable without seeding the process-global correlation vector.
fn correlation_header_from(correlation_vector: &str) -> Option<(String, String)> {
    if correlation_vector.is_empty() {
        return None;
    }
    Some((
        "x-ms-correlation-id".to_string(),
        correlation_vector.to_string(),
    ))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Read a full response: byte-wise through the header terminator, then the body
/// by `Content-Length` when present or to EOF otherwise.
///
/// The caller is responsible for having set a read timeout on `stream`
/// (`tls_dial` does this); without one a silent origin can block indefinitely.
///
/// # Errors
/// Returns `backend_error` if the connection closes before the header
/// terminator, if the header block exceeds 16 KiB, if the status line is
/// malformed, if `Content-Length` is unparsable or exceeds 8 MiB, or if the
/// body cannot be read.
pub fn read_response<S: Read>(stream: &mut S) -> Result<HttpResponse, MxcError> {
    let mut head = Vec::with_capacity(512);
    let mut one = [0u8; 1];
    loop {
        let n = stream
            .read(&mut one)
            .map_err(|e| MxcError::backend_error(format!("read response: {e}")))?;
        if n == 0 {
            return Err(MxcError::backend_error(
                "connection closed before the response headers were complete",
            ));
        }
        head.push(one[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEADER_BYTES {
            return Err(MxcError::backend_error("response header too large"));
        }
    }

    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.lines();
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| {
            MxcError::backend_error(format!("malformed status line: '{status_line}'"))
        })?;

    let headers: Vec<(String, String)> = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    let body = match header_value(&headers, "content-length") {
        Some(len) => {
            let len: usize = len
                .parse()
                .map_err(|e| MxcError::backend_error(format!("bad Content-Length: {e}")))?;
            if len > MAX_BODY_BYTES {
                return Err(MxcError::backend_error(format!(
                    "response body too large: {len} bytes (max {MAX_BODY_BYTES})"
                )));
            }
            let mut buf = vec![0u8; len];
            stream
                .read_exact(&mut buf)
                .map_err(|e| MxcError::backend_error(format!("read body: {e}")))?;
            String::from_utf8_lossy(&buf).into_owned()
        }
        None => {
            let mut buf = Vec::new();
            stream
                .by_ref()
                .take(MAX_BODY_BYTES as u64)
                .read_to_end(&mut buf)
                .map_err(|e| MxcError::backend_error(format!("read body: {e}")))?;
            String::from_utf8_lossy(&buf).into_owned()
        }
    };

    Ok(HttpResponse {
        status,
        body,
        request_id: header_value(&headers, "x-ms-request-id").map(str::to_string),
    })
}

/// Write the request and read the response over any duplex stream. Tests drive
/// this over plain TCP; production drives it over TLS.
///
/// # Errors
/// Returns `policy_validation` when the request contains a control character
/// (see [`build_request`]), `backend_error` if the request cannot be written, or
/// for any of the response failures described on [`read_response`].
pub fn send<S: Read + Write>(stream: &mut S, req: &HttpRequest) -> Result<HttpResponse, MxcError> {
    let wire = build_request(req)?;
    stream
        .write_all(wire.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| MxcError::backend_error(format!("send request: {e}")))?;
    read_response(stream)
}

/// Web PKI roots, shared by every outbound TLS connection in this crate.
fn root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// TCP connect + TLS handshake with a read timeout applied. Shared by the exec
/// upgrade path and the control plane.
///
/// # Security invariant — read before adding a caller-influenced coordinate
/// `host` decides **where a bearer token is sent**. Any value that reaches this
/// argument and can be influenced by the caller MUST be resolved through
/// [`crate::w365agents_common::config::require_host_and_token`], which refuses a caller-supplied
/// host paired with a token from the trusted environment. Without that pairing,
/// a config file can redirect the deployment's token to a machine the caller
/// owns, and TLS will not object: the attacker holds a perfectly valid
/// certificate for their own domain, and the fixed token audience is what makes
/// the captured token replayable against the real service rather than what
/// protects it.
///
/// Today every host here is either co-resolved by that function or built from a
/// GUID-validated [`crate::w365agents_common::id::W365SandboxId`] segment, and no service response
/// field is ever dialled. `port` is exempt — it cannot move a token to a
/// different DNS name, because the TLS `ServerName` is derived from `host` alone.
///
/// # Errors
/// Returns `backend_error` if the host cannot be resolved or connected, if the
/// read timeout cannot be applied, if `host` is not a valid TLS server name, or
/// if the TLS client cannot be initialised.
pub fn tls_dial(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<StreamOwned<ClientConnection, TcpStream>, MxcError> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| MxcError::backend_error(format!("connect {host}:{port}: {e}")))?
        .collect();
    let addr = addrs.first().ok_or_else(|| {
        MxcError::backend_error(format!(
            "connect {host}:{port}: no socket addresses resolved"
        ))
    })?;
    let sock = TcpStream::connect_timeout(addr, timeout)
        .map_err(|e| MxcError::backend_error(format!("connect {host}:{port}: {e}")))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| MxcError::backend_error(format!("set read timeout: {e}")))?;
    sock.set_write_timeout(Some(timeout))
        .map_err(|e| MxcError::backend_error(format!("set write timeout: {e}")))?;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store())
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| MxcError::backend_error(format!("invalid server name '{host}': {e}")))?;
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| MxcError::backend_error(format!("TLS client init: {e}")))?;
    Ok(StreamOwned::new(conn, sock))
}

/// One complete HTTPS request/response. The connection is closed afterwards.
///
/// # Errors
/// Returns `backend_error` for any dial failure described on [`tls_dial`] or
/// any request/response failure described on [`send`].
pub fn https_json(
    port: u16,
    timeout: Duration,
    req: &HttpRequest,
) -> Result<HttpResponse, MxcError> {
    let mut tls = tls_dial(&req.host, port, timeout)?;
    send(&mut tls, req)
}

#[cfg(test)]
mod tests {
    use super::{build_request, read_response, HttpRequest};
    use crate::w365agents_common::secret::Redacted;
    use std::io::Cursor;

    fn req() -> HttpRequest {
        HttpRequest {
            method: "POST",
            path: "/api/pools/p1/sessions?api-version=2.0".to_string(),
            host: "sm.example.net".to_string(),
            bearer_token: Redacted::new("TOKEN123"),
            headers: vec![("x-ms-sessionId".to_string(), "s1".to_string())],
            body: Some("{}".to_string()),
        }
    }

    #[test]
    fn builds_a_request_with_auth_host_and_content_length() {
        let wire = build_request(&req()).unwrap();
        assert!(wire.starts_with("POST /api/pools/p1/sessions?api-version=2.0 HTTP/1.1\r\n"));
        assert!(wire.contains("Authorization: Bearer TOKEN123\r\n"));
        assert!(wire.contains("x-ms-sessionId: s1\r\n"));
        assert!(wire.contains("Content-Type: application/json\r\n"));
        assert!(wire.contains("Content-Length: 2\r\n"));
        assert!(wire.contains("Connection: close\r\n"));
        assert!(wire.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn a_header_value_with_crlf_is_refused_before_the_wire() {
        // The chokepoint. Without it a caller-supplied header value splits the
        // request and injects headers onto a call authenticated with the
        // deployment's token.
        let mut r = req();
        r.headers = vec![("user-object-id".to_string(), "x\r\nInjected: 1".to_string())];
        let err = build_request(&r).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("user-object-id"), "{}", err.message);
    }

    #[test]
    fn a_path_with_crlf_is_refused_before_the_wire() {
        let mut r = req();
        r.path = "/api/x\r\nX-Injected: 1".to_string();
        let err = build_request(&r).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("path"), "{}", err.message);
    }

    #[test]
    fn a_host_with_crlf_is_refused_before_the_wire() {
        let mut r = req();
        r.host = "h\r\nX-Injected: 1".to_string();
        let err = build_request(&r).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("host"), "{}", err.message);
    }

    #[test]
    fn a_bare_newline_is_refused_too() {
        // HTTP/1.1 parsers differ on whether a bare LF terminates a line, so
        // rejecting only the CRLF pair would leave a request-smuggling seam.
        let mut r = req();
        r.headers = vec![("x".to_string(), "a\nInjected: 1".to_string())];
        assert!(build_request(&r).is_err());
    }

    #[test]
    fn debug_redacts_the_bearer_token_and_credential_headers() {
        // The agentic checkout carries a SECOND credential in a header, so
        // redacting only `bearer_token` is not enough (spec §8: no token in a
        // sandbox id, a log line, or an error `details` object).
        let mut r = req();
        r.bearer_token = Redacted::new("BEARER_SECRET");
        r.headers = vec![
            (
                "x-ms-authorization-auxiliary".to_string(),
                "AUX_SECRET".to_string(),
            ),
            ("x-ms-computerId".to_string(), "not-a-secret".to_string()),
        ];
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("BEARER_SECRET"), "bearer token leaked: {dbg}");
        assert!(!dbg.contains("AUX_SECRET"), "auxiliary token leaked: {dbg}");
        // Non-credential headers stay visible — they are what makes the log useful.
        assert!(dbg.contains("not-a-secret"), "benign header hidden: {dbg}");
    }

    #[test]
    fn omits_content_length_when_there_is_no_body() {
        let mut r = req();
        r.method = "DELETE";
        r.body = None;
        let wire = build_request(&r).unwrap();
        assert!(!wire.contains("Content-Length"));
        assert!(!wire.contains("Content-Type"));
        assert!(wire.ends_with("\r\n\r\n"));
    }

    #[test]
    fn reads_a_content_length_body() {
        let raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nx-ms-request-id: abc\r\n\r\n{\"ok\":true}!!";
        let resp = read_response(&mut Cursor::new(raw.as_bytes().to_vec())).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "{\"ok\":true}!!");
        assert_eq!(resp.request_id.as_deref(), Some("abc"));
    }

    #[test]
    fn reads_a_body_that_runs_to_eof_when_no_content_length() {
        let raw = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"a\":1}";
        let resp = read_response(&mut Cursor::new(raw.as_bytes().to_vec())).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "{\"a\":1}");
    }

    #[test]
    fn reads_a_bodyless_204() {
        let raw = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        let resp = read_response(&mut Cursor::new(raw.as_bytes().to_vec())).unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
        assert!(resp.request_id.is_none());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let raw = "HTTP/1.1 500 Server Error\r\nX-MS-Request-Id: XYZ\r\nContent-Length: 0\r\n\r\n";
        let resp = read_response(&mut Cursor::new(raw.as_bytes().to_vec())).unwrap();
        assert_eq!(resp.status, 500);
        assert_eq!(resp.request_id.as_deref(), Some("XYZ"));
    }

    #[test]
    fn rejects_a_malformed_status_line() {
        let raw = "NOT-HTTP\r\n\r\n";
        let err = read_response(&mut Cursor::new(raw.as_bytes().to_vec())).unwrap_err();
        assert_eq!(err.code.as_str(), "backend_error");
    }

    #[test]
    fn rejects_an_oversize_header_block() {
        let mut raw = String::from("HTTP/1.1 200 OK\r\n");
        raw.push_str(&format!("X-Pad: {}\r\n", "a".repeat(64 * 1024)));
        let err = read_response(&mut Cursor::new(raw.into_bytes())).unwrap_err();
        assert!(err.message.contains("header too large"));
    }

    #[test]
    fn rejects_a_content_length_that_would_force_a_huge_allocation() {
        // A hostile or buggy origin must not be able to make us pre-allocate
        // gigabytes: allocation failure aborts the process and is not catchable.
        let raw = "HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n";
        let err = read_response(&mut Cursor::new(raw.as_bytes().to_vec())).unwrap_err();
        assert!(
            err.message.contains("body too large"),
            "expected a size rejection, got: {}",
            err.message
        );
    }

    #[test]
    fn caps_an_unbounded_eof_body() {
        // No Content-Length: the read must stop at the cap rather than stream
        // for as long as the origin keeps sending.
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'x', super::MAX_BODY_BYTES + 4096));
        let resp = read_response(&mut Cursor::new(raw)).unwrap();
        assert_eq!(resp.body.len(), super::MAX_BODY_BYTES);
    }

    #[test]
    fn tls_dial_reports_an_unresolvable_host_as_backend_error() {
        // No network needed: the name cannot resolve, so this exercises the
        // error mapping rather than a real handshake.
        let err = super::tls_dial(
            "no-such-host.invalid",
            443,
            std::time::Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(err.code.as_str(), "backend_error");
        assert!(err.message.contains("connect no-such-host.invalid:443"));
    }

    #[test]
    fn a_present_correlation_vector_produces_exactly_one_header() {
        // An `Option` is 0-or-1 by construction, so a `Some` is "exactly one";
        // assert the header name and value are the untouched MS-CV.
        let header = super::correlation_header_from("AAAAAAAAAAAAAAAAAAAAAA.0");
        assert_eq!(
            header,
            Some((
                "x-ms-correlation-id".to_string(),
                "AAAAAAAAAAAAAAAAAAAAAA.0".to_string()
            ))
        );
    }

    #[test]
    fn an_empty_correlation_vector_produces_no_header() {
        // Telemetry disabled → empty MS-CV → the header is omitted, never blank.
        assert_eq!(super::correlation_header_from(""), None);
    }
}

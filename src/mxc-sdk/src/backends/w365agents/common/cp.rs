// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SessionManagement (control-plane) client: checkout and release.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::mxc_common::mxc_error::MxcError;

use crate::w365agents_common::http::{https_json, HttpRequest, HttpResponse};
use crate::w365agents_common::secret::Redacted;

/// Write one token-free, machine-parseable audit line to stderr.
///
/// The framework already emits per-phase telemetry (name, duration, outcome,
/// MS-CV), but it can only do so for a phase that *returned*. The case this
/// exists for is the one where nothing is returned: a `provision` whose response
/// was lost may have committed a billing VM whose `sessionId` the backend never
/// learned, and with no partner `GetCheckout` to reconcile against, this line is
/// the only record that the checkout was attempted at all.
///
/// The correlation vector is emitted on every line because it is the **only**
/// cross-service handle available when the `sessionId` is exactly what was lost:
/// SM logs its side of the checkout under the same MS-CV, so an offline sweeper
/// can pivot from this line to SM's record, recover the session, and release the
/// VM. Without it an orphan can be *counted* but not *reconciled*.
///
/// Shape is `logfmt`-ish with a fixed `event=` key rather than a free-text event
/// name, so a sweeper can parse it without special-casing the leading token.
/// Fields are limited to non-secret identifiers.
fn audit(event: &str, fields: &[(&str, &str)]) {
    let mut line = format!("w365_agents event={event}");
    for (k, v) in fields {
        line.push_str(&format!(" {k}={v}"));
    }
    let cv = crate::mxc_common::telemetry::current_correlation_vector();
    if !cv.is_empty() {
        line.push_str(&format!(" correlationVector={cv}"));
    }
    eprintln!("{line}");
}

/// SessionManagement coordinates and credential.
#[derive(Debug, Clone)]
pub struct SmClient {
    pub base_host: String,
    pub port: u16,
    pub api_version: String,
    pub bearer_token: Redacted,
}

/// Caller intent for a checkout. The agentic trio is optional; when
/// `agent_user_token` is present `user_object_id` is required (SM infers
/// `AgenticUserSession` and rejects the request without it).
#[derive(Debug, Clone)]
pub struct CheckoutOptions {
    pub pool_id: String,
    pub agent_user_token: Option<Redacted>,
    pub user_object_id: Option<String>,
    pub user_type: Option<String>,
}

/// `SessionResponseV1` as returned by `POST /api/pools/{poolId}/sessions`.
///
/// `Debug` is hand-written rather than derived so it can redact
/// `connectivity_url` (see that field's doc) while printing the rest.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponseV1 {
    pub session_id: String,
    pub status: String,
    pub computer_id: Option<String>,
    pub computer_url: Option<String>,
    /// Returned verbatim from the CDP checkout output via SessionManagement (SM
    /// does not build it locally), so it may embed a connection ticket in its
    /// query string and cannot be proven credential-free. The caller needs the
    /// value, but — like a token — it must never reach a log line or an error
    /// `details` object, so this type's `Debug` renders it as `<redacted>`.
    /// `computer_url`/`screenshare_url` are proven credential-free (a pool or
    /// computer GUID host/path plus an `api-version` query) and print normally.
    pub connectivity_url: Option<String>,
    pub screenshare_url: Option<String>,
}

impl std::fmt::Debug for SessionResponseV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionResponseV1")
            .field("session_id", &self.session_id)
            .field("status", &self.status)
            .field("computer_id", &self.computer_id)
            .field("computer_url", &self.computer_url)
            .field(
                "connectivity_url",
                &self.connectivity_url.as_ref().map(|_| "<redacted>"),
            )
            .field("screenshare_url", &self.screenshare_url)
            .finish()
    }
}

/// Build the checkout request (pure).
pub fn checkout_request(client: &SmClient, opts: &CheckoutOptions) -> HttpRequest {
    let mut headers = Vec::new();
    if let Some(token) = &opts.agent_user_token {
        headers.push((
            "x-ms-authorization-auxiliary".to_string(),
            token.expose().to_string(),
        ));
    }
    if let Some(oid) = &opts.user_object_id {
        headers.push(("user-object-id".to_string(), oid.clone()));
    }
    if let Some(kind) = &opts.user_type {
        headers.push(("user-type".to_string(), kind.clone()));
    }
    // Tag the outbound SM call with the process MS-CV for cross-service
    // correlation; omitted when telemetry is off. See `http::correlation_header`
    // for the omit-when-empty rule and the post-authorization ARI caveat.
    if let Some(header) = crate::w365agents_common::http::correlation_header() {
        headers.push(header);
    }
    HttpRequest {
        method: "POST",
        path: format!(
            "/api/pools/{}/sessions?api-version={}",
            opts.pool_id, client.api_version
        ),
        host: client.base_host.clone(),
        bearer_token: client.bearer_token.clone(),
        headers,
        body: None,
    }
}

/// Map a checkout response to a session or a typed error (pure). Every row here
/// is a row of spec §7's control-plane table.
///
/// # Errors
/// Returns `backend_error` for a `404` (`pool_not_found`), `401`/`403`
/// (`auth_denied`), `500` (`provision_timeout`, flagged `possiblySucceeded` and
/// deliberately never retryable), or any other non-success status
/// (`checkout_failed`); for a body that is not a parseable `SessionResponseV1`;
/// for a session whose status is not `Succeeded` (`provision_failed`); or when
/// `computerId` differs from `sessionId` (`id_mismatch`).
pub fn map_checkout_response(resp: &HttpResponse) -> Result<SessionResponseV1, MxcError> {
    // A stable, machine-readable `code` rides alongside the free-text message so
    // a consumer can branch without string-matching. The outer wire code stays
    // `backend_error`; this is purely additive inside `details`.
    let details = |code: &str| {
        json!({
            "httpStatus": resp.status,
            "requestId": resp.request_id,
            "code": code,
        })
    };
    match resp.status {
        200 | 201 => {}
        404 => {
            return Err(MxcError::backend_error("checkout failed: pool_not_found")
                .with_details(details("pool_not_found")))
        }
        401 | 403 => {
            return Err(MxcError::backend_error("checkout failed: auth_denied")
                .with_details(details("auth_denied")))
        }
        // The server caps checkout at 30 s and surfaces the overrun as a 500.
        // The checkout may still have succeeded, so this is explicitly NOT
        // retryable — a retry strands the prior checkout (spec §4.1).
        500 => {
            return Err(MxcError::backend_error(
                "checkout failed: provision_timeout (the checkout may have succeeded)",
            )
            .with_details(json!({
                "httpStatus": resp.status,
                "requestId": resp.request_id,
                "possiblySucceeded": true,
                "code": "provision_timeout"
            })))
        }
        _ => {
            return Err(MxcError::backend_error("checkout failed: checkout_failed")
                .with_details(details("checkout_failed")))
        }
    }

    // Past this point SM answered 2xx, so it has COMMITTED a billing VM. Any
    // failure from here is an orphan: we hold a live checkout whose id we are
    // about to throw away, and there is no partner GetCheckout to recover it.
    // These carry `possiblySucceeded` for the same reason the 500 does — the
    // caller must not retry, and an operator must be able to count them.
    let orphan = |code: &str| {
        json!({
            "httpStatus": resp.status,
            "requestId": resp.request_id,
            "possiblySucceeded": true,
            "code": code
        })
    };

    let session: SessionResponseV1 = serde_json::from_str(&resp.body).map_err(|e| {
        MxcError::backend_error(format!(
            "checkout failed: unparsable SessionResponseV1: {e}"
        ))
        .with_details(orphan("unparsable_response"))
    })?;

    if !session.status.eq_ignore_ascii_case("Succeeded") {
        // NOT an orphan: SM explicitly reported the checkout did not succeed, so
        // there is no committed VM to reconcile.
        return Err(MxcError::backend_error(format!(
            "checkout failed: provision_failed (status '{}')",
            session.status
        ))
        .with_details(details("provision_failed")));
    }

    // A Succeeded checkout whose ids are not canonical GUIDs would mint a sandbox
    // id that `id::W365SandboxId::parse` later rejects, stranding a live checkout
    // that can never be started or released. Reject it at this boundary, reusing
    // the one canonical GUID check rather than writing a second one.
    if !crate::w365agents_common::id::is_guid(&session.session_id) {
        return Err(MxcError::backend_error(format!(
            "checkout failed: malformed_session_id (sessionId '{}' is not a GUID)",
            session.session_id
        ))
        .with_details(orphan("malformed_session_id")));
    }

    // The pooled-VM path guarantees computerId == sessionId; a future pool type
    // that breaks that assumption must fail loudly rather than route wrongly.
    if let Some(computer_id) = &session.computer_id {
        if !crate::w365agents_common::id::is_guid(computer_id) {
            return Err(MxcError::backend_error(format!(
                "checkout failed: malformed_session_id (computerId '{computer_id}' is not a GUID)"
            ))
            .with_details(orphan("malformed_session_id")));
        }
        if computer_id != &session.session_id {
            return Err(MxcError::backend_error(format!(
                "checkout failed: id_mismatch (computerId '{computer_id}' != sessionId '{}')",
                session.session_id
            ))
            .with_details(orphan("id_mismatch")));
        }
    }

    Ok(session)
}

/// Perform a checkout (IO).
///
/// A failure *after* the request reached the wire cannot prove the checkout did
/// not happen: SM may have committed a billing VM whose `sessionId` we never
/// learned and therefore can never release. Every such failure is tagged
/// `possiblySucceeded` and gets a `checkout_outcome_unknown` audit line, so an
/// orphan is countable and — via the MS-CV on that line — reconcilable against
/// SM's own record. There is no partner `GetCheckout` to reconcile with.
///
/// # Errors
/// Returns `backend_error` for any dial or request/response failure from the
/// HTTP layer, or any mapping failure described on [`map_checkout_response`].
/// Never returns a retryable error: a retry would strand a second billing VM.
pub fn checkout(
    client: &SmClient,
    opts: &CheckoutOptions,
    timeout: Duration,
) -> Result<SessionResponseV1, MxcError> {
    let req = checkout_request(client, opts);
    // Validate the wire serialization before emitting `checkout_issued` or
    // touching the socket, so a local control-character rejection never raises
    // a false `checkout_outcome_unknown` orphan alarm.
    crate::w365agents_common::http::build_request(&req)?;
    audit("checkout_issued", &[("poolId", &opts.pool_id)]);
    let resp = match https_json(client.port, timeout, &req) {
        Ok(resp) => resp,
        Err(e) => {
            // The dial itself failing is unambiguous (nothing was sent), but the
            // transport layer does not distinguish that from a drop after the
            // POST was written. Fail safe: assume the expensive case.
            audit(
                "checkout_outcome_unknown",
                &[("poolId", &opts.pool_id), ("reason", "transport")],
            );
            return Err(e.with_details(json!({
                "code": "checkout_outcome_unknown",
                "possiblySucceeded": true,
                "poolId": opts.pool_id,
            })));
        }
    };
    let session = match map_checkout_response(&resp) {
        Ok(session) => session,
        Err(e) => {
            // SM answered 2xx but we could not turn the body into a usable
            // session: it committed a VM and we are discarding the only id that
            // could release it. `map_checkout_response` marks exactly those
            // cases `possiblySucceeded`, so branch on that rather than guessing.
            if e.details
                .as_ref()
                .and_then(|d| d.get("possiblySucceeded"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                let reason = e
                    .details
                    .as_ref()
                    .and_then(|d| d.get("code"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                audit(
                    "checkout_outcome_unknown",
                    &[("poolId", &opts.pool_id), ("reason", reason)],
                );
            }
            return Err(e);
        }
    };
    audit(
        "checkout_succeeded",
        &[
            ("poolId", &opts.pool_id),
            ("sessionId", &session.session_id),
        ],
    );
    Ok(session)
}

/// Build the release (check-in) request (pure).
pub fn release_request(client: &SmClient, session_id: &str) -> HttpRequest {
    let mut headers = vec![("x-ms-sessionId".to_string(), session_id.to_string())];
    // See `http::correlation_header`: omitted when the process MS-CV is empty.
    if let Some(header) = crate::w365agents_common::http::correlation_header() {
        headers.push(header);
    }
    HttpRequest {
        method: "DELETE",
        path: format!(
            "/api/sessions/{}?api-version={}",
            session_id, client.api_version
        ),
        host: client.base_host.clone(),
        bearer_token: client.bearer_token.clone(),
        headers,
        body: None,
    }
}

/// Map a release response (pure). `404` is success-equivalent: the service
/// already treats a missing session as a completed release.
///
/// # Errors
/// Returns `backend_error` when the caller is unauthorized (401/403 →
/// `auth_denied`), when the synchronous ARI computer-removal failed (500 →
/// `release_failed`, marked retryable), or for any other non-success status.
pub fn map_release_response(resp: &HttpResponse) -> Result<(), MxcError> {
    let details = |code: &str| {
        json!({
            "httpStatus": resp.status,
            "requestId": resp.request_id,
            "code": code,
        })
    };
    match resp.status {
        200 | 202 | 204 | 404 => Ok(()),
        401 | 403 => Err(MxcError::backend_error("release failed: auth_denied")
            .with_details(details("auth_denied"))),
        // The synchronous ARI computer-removal inside check-in throws a 500 on
        // failure; the caller may safely retry the whole release.
        500 => Err(
            MxcError::backend_error("release failed: release_failed").with_details(json!({
                "httpStatus": resp.status,
                "requestId": resp.request_id,
                "retryable": true,
                "code": "release_failed"
            })),
        ),
        _ => Err(MxcError::backend_error("release failed").with_details(details("release_failed"))),
    }
}

/// Perform a release (IO). Used by both `stop` and `deprovision`.
///
/// # Errors
/// Returns `backend_error` for any dial or request/response failure from the
/// HTTP layer, or any mapping failure described on [`map_release_response`].
pub fn release(client: &SmClient, session_id: &str, timeout: Duration) -> Result<(), MxcError> {
    let req = release_request(client, session_id);
    audit("release_issued", &[("sessionId", session_id)]);
    let resp = https_json(client.port, timeout, &req)?;
    let out = map_release_response(&resp);
    if out.is_ok() {
        audit("release_accepted", &[("sessionId", session_id)]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{checkout_request, map_checkout_response, CheckoutOptions, SmClient};
    use crate::w365agents_common::http::HttpResponse;
    use crate::w365agents_common::secret::Redacted;

    #[test]
    fn a_succeeded_checkout_with_bad_ids_is_flagged_as_a_possible_orphan() {
        // SM answered 2xx, so it committed a billing VM; we are about to discard
        // the only id that could release it. These MUST carry possiblySucceeded
        // or the orphan is invisible. `provision_failed` deliberately does not
        // (SM said it did not succeed), which the next test pins.
        let cases = [
            (
                r#"{"sessionId":"not-a-guid","status":"Succeeded"}"#,
                "malformed_session_id",
            ),
            (
                r#"{"sessionId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","computerId":"nope","status":"Succeeded"}"#,
                "malformed_session_id",
            ),
            (
                r#"{"sessionId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","computerId":"11111111-2222-3333-4444-555555555555","status":"Succeeded"}"#,
                "id_mismatch",
            ),
            ("{ this is not json", "unparsable_response"),
        ];
        for (body, code) in cases {
            let resp = HttpResponse {
                status: 200,
                body: body.to_string(),
                request_id: Some("r1".to_string()),
            };
            let err = map_checkout_response(&resp).expect_err("expected an error");
            let details = err.details.expect("details");
            assert_eq!(details["code"], code, "body: {body}");
            assert_eq!(
                details["possiblySucceeded"], true,
                "a post-2xx failure must be flagged a possible orphan: {body}"
            );
            assert!(
                details.get("retryable").is_none(),
                "an orphan must never be retryable: {body}"
            );
        }
    }

    #[test]
    fn an_explicit_non_succeeded_status_is_not_a_possible_orphan() {
        // SM reported the checkout did not succeed, so there is no committed VM
        // to reconcile; flagging it would inflate the orphan count.
        let resp = HttpResponse {
            status: 200,
            body: r#"{"sessionId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","status":"Failed"}"#
                .to_string(),
            request_id: None,
        };
        let err = map_checkout_response(&resp).unwrap_err();
        let details = err.details.expect("details");
        assert_eq!(details["code"], "provision_failed");
        assert!(details.get("possiblySucceeded").is_none());
    }

    fn client() -> SmClient {
        SmClient {
            base_host: "westus3.sessionmanagement.example.net".to_string(),
            port: 443,
            api_version: "2.0".to_string(),
            bearer_token: Redacted::new("SM_TOKEN"),
        }
    }

    fn opts() -> CheckoutOptions {
        CheckoutOptions {
            pool_id: "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9".to_string(),
            agent_user_token: None,
            user_object_id: None,
            user_type: None,
        }
    }

    fn ok_body(session: &str, computer: &str, status: &str) -> String {
        format!(
            r#"{{"sessionId":"{session}","status":"{status}","computerId":"{computer}",
                 "computerUrl":"https://p.example/computers/{computer}?api-version=1.0",
                 "connectivityUrl":"https://c.example","screenshareUrl":"https://s.example"}}"#
        )
    }

    const S: &str = "538fdbe2-1f9a-40c7-b8dd-f2391d55a24a";

    #[test]
    fn builds_the_checkout_request() {
        let req = checkout_request(&client(), &opts());
        assert_eq!(req.method, "POST");
        assert_eq!(
            req.path,
            "/api/pools/6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9/sessions?api-version=2.0"
        );
        assert_eq!(req.host, "westus3.sessionmanagement.example.net");
        // No agentic headers when no aux token is supplied → LocalUserSession.
        assert!(req
            .headers
            .iter()
            .all(|(k, _)| k != "x-ms-authorization-auxiliary"));
    }

    #[test]
    fn agentic_headers_are_sent_when_the_aux_token_is_present() {
        let mut o = opts();
        o.agent_user_token = Some(Redacted::new("AUX"));
        o.user_object_id = Some("11111111-2222-3333-4444-555555555555".to_string());
        o.user_type = Some("Agentic".to_string());
        let req = checkout_request(&client(), &o);
        let names: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"x-ms-authorization-auxiliary"));
        assert!(names.contains(&"user-object-id"));
        assert!(names.contains(&"user-type"));
    }

    #[test]
    fn debug_redacts_both_tokens() {
        let mut o = opts();
        o.agent_user_token = Some(Redacted::new("AUX_SECRET"));
        let dbg = format!("{:?} {:?}", client(), o);
        assert!(!dbg.contains("SM_TOKEN"));
        assert!(!dbg.contains("AUX_SECRET"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn maps_a_succeeded_checkout() {
        let resp = HttpResponse {
            status: 200,
            body: ok_body(S, S, "Succeeded"),
            request_id: Some("rid".to_string()),
        };
        let session = map_checkout_response(&resp).unwrap();
        assert_eq!(session.session_id, S);
        assert_eq!(session.computer_id.as_deref(), Some(S));
    }

    #[test]
    fn maps_a_failed_checkout_to_provision_failed() {
        let resp = HttpResponse {
            status: 200,
            body: ok_body(S, S, "Failed"),
            request_id: None,
        };
        let err = map_checkout_response(&resp).unwrap_err();
        assert_eq!(err.code.as_str(), "backend_error");
        assert!(err.message.contains("provision_failed"));
    }

    #[test]
    fn rejects_a_computer_id_that_differs_from_the_session_id() {
        let resp = HttpResponse {
            status: 200,
            body: ok_body(S, "99999999-9999-9999-9999-999999999999", "Succeeded"),
            request_id: None,
        };
        let err = map_checkout_response(&resp).unwrap_err();
        assert!(err.message.contains("id_mismatch"));
    }

    #[test]
    fn maps_the_http_error_statuses() {
        for (status, expect) in [
            (404u16, "pool_not_found"),
            (401, "auth_denied"),
            (403, "auth_denied"),
            (500, "provision_timeout"),
            (429, "checkout_failed"),
        ] {
            let resp = HttpResponse {
                status,
                body: "{}".to_string(),
                request_id: Some("rid".to_string()),
            };
            let err = map_checkout_response(&resp).unwrap_err();
            assert!(
                err.message.contains(expect),
                "status {status} should map to {expect}, got: {}",
                err.message
            );
        }
    }

    #[test]
    fn a_500_is_flagged_possibly_succeeded_and_never_retryable() {
        let resp = HttpResponse {
            status: 500,
            body: String::new(),
            request_id: None,
        };
        let err = map_checkout_response(&resp).unwrap_err();
        let details = err.details.expect("details");
        assert_eq!(details["possiblySucceeded"], serde_json::json!(true));
        assert!(
            details.get("retryable").is_none(),
            "provision must never advertise retryable"
        );
    }

    #[test]
    fn checkout_error_details_carry_a_stable_code() {
        let resp = HttpResponse {
            status: 404,
            body: "{}".to_string(),
            request_id: Some("rid".to_string()),
        };
        let err = map_checkout_response(&resp).unwrap_err();
        assert_eq!(
            err.details.unwrap()["code"],
            serde_json::json!("pool_not_found")
        );
    }

    #[test]
    fn rejects_a_non_guid_session_id() {
        // A Succeeded checkout with a non-GUID sessionId would strand a live
        // checkout behind a sandbox id that `W365SandboxId::parse` rejects.
        let resp = HttpResponse {
            status: 200,
            body: ok_body("not-a-guid", "not-a-guid", "Succeeded"),
            request_id: None,
        };
        let err = map_checkout_response(&resp).unwrap_err();
        assert_eq!(err.code.as_str(), "backend_error");
        assert!(err.message.contains("malformed_session_id"));
        assert_eq!(
            err.details.unwrap()["code"],
            serde_json::json!("malformed_session_id")
        );
    }

    #[test]
    fn debug_redacts_the_connectivity_url_but_prints_the_clean_urls() {
        // connectivity_url may carry a connection ticket; the proven
        // credential-free URLs stay visible for diagnostics.
        let session = super::SessionResponseV1 {
            session_id: S.to_string(),
            status: "Succeeded".to_string(),
            computer_id: Some(S.to_string()),
            computer_url: Some("https://cu.example/computers/abc?api-version=1.0".to_string()),
            connectivity_url: Some("https://gw.example/connect?token=TICKET_SECRET".to_string()),
            screenshare_url: Some("https://su.example".to_string()),
        };
        let dbg = format!("{session:?}");
        assert!(
            !dbg.contains("TICKET_SECRET"),
            "connectivity_url leaked: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("cu.example"),
            "computer_url must stay visible: {dbg}"
        );
    }

    use super::{map_release_response, release_request};

    #[test]
    fn builds_the_release_request_with_the_locality_header() {
        let req = release_request(&client(), S);
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, format!("/api/sessions/{S}?api-version=2.0"));
        // x-ms-sessionId is the Envoy consistent-hash locality key. SM reads the
        // id from the route, so this is not required for correctness — we send
        // it because the service's own client does.
        assert_eq!(
            req.headers
                .iter()
                .find(|(k, _)| k == "x-ms-sessionId")
                .map(|(_, v)| v.as_str()),
            Some(S)
        );
        assert!(req.body.is_none());
    }

    #[test]
    fn release_treats_204_and_404_as_success() {
        for status in [200u16, 204, 404] {
            let resp = HttpResponse {
                status,
                body: String::new(),
                request_id: None,
            };
            assert!(
                map_release_response(&resp).is_ok(),
                "status {status} should be success-equivalent"
            );
        }
    }

    #[test]
    fn release_maps_500_to_a_retryable_release_failure() {
        let resp = HttpResponse {
            status: 500,
            body: String::new(),
            request_id: Some("rid".to_string()),
        };
        let err = map_release_response(&resp).unwrap_err();
        assert!(err.message.contains("release_failed"));
        assert_eq!(err.details.unwrap()["retryable"], serde_json::json!(true));
    }

    #[test]
    fn release_maps_auth_failures() {
        for status in [401u16, 403] {
            let resp = HttpResponse {
                status,
                body: String::new(),
                request_id: None,
            };
            let err = map_release_response(&resp).unwrap_err();
            assert!(err.message.contains("auth_denied"));
        }
    }
}

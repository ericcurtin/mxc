// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RemotingInterface (data-plane) device-status poller.

use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;

use crate::mxc_common::mxc_error::MxcError;

use crate::w365agents_common::http::{https_json, HttpRequest, HttpResponse};
use crate::w365agents_common::secret::Redacted;

/// Per-poll HTTP read timeout for a single status GET.
///
/// A status read is a few KiB and returns promptly, so this only bounds a
/// stalled connection: it stops one hung poll from consuming the whole
/// `ready_timeout` budget. It is deliberately independent of `poll_interval` —
/// the interval paces the loop, this caps a single request.
const STATUS_POLL_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The device's self-reported state, as defined by the relay protobuf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Waiting,
    Live,
    Ready,
}

/// Data-plane coordinates for one computer.
#[derive(Debug, Clone)]
pub struct DpClient {
    pub host: String,
    pub port: u16,
    pub api_version: String,
    pub computer_id: String,
    pub bearer_token: Redacted,
}

/// Parsed device status.
#[derive(Debug, Clone)]
pub struct DeviceStatus {
    pub state: DeviceState,
    pub computer_url: Option<String>,
    pub screenshare_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatusBody {
    status: String,
    computer_url: Option<String>,
    screenshare_url: Option<String>,
}

/// Build the status request (pure). `x-ms-computerId` must equal the path
/// segment or authorization fails with 403.
pub fn status_request(client: &DpClient) -> HttpRequest {
    let mut headers = vec![("x-ms-computerId".to_string(), client.computer_id.clone())];
    // Tag the outbound ARI call with the process MS-CV; omitted when telemetry
    // is off. ARI captures it as an `Activity` tag but only after authorization,
    // so a 401/403 here is not tagged — see `http::correlation_header`.
    if let Some(header) = crate::w365agents_common::http::correlation_header() {
        headers.push(header);
    }
    HttpRequest {
        method: "GET",
        path: format!(
            "/computers/{}/status?api-version={}",
            client.computer_id, client.api_version
        ),
        host: client.host.clone(),
        bearer_token: client.bearer_token.clone(),
        headers,
        body: None,
    }
}

/// Map one status response (pure).
///
/// # Errors
/// Returns `backend_error` when the caller is unauthorized (401 →
/// `auth_denied`), when authorization is denied (403 →
/// `pool_authorization_denied`; the principal is not in the pool, the computer
/// was released/evicted, or `x-ms-computerId` is missing/mismatched), for any
/// other status, for a body that is not a parseable status object, or for an
/// unrecognized device-state string.
pub fn map_status_response(resp: &HttpResponse) -> Result<DeviceStatus, MxcError> {
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
        200 => {}
        401 => {
            return Err(MxcError::backend_error("status failed: auth_denied")
                .with_details(details("auth_denied")))
        }
        // One 403 covers three causes and they are not distinguishable today:
        // principal not in the pool, computer released/evicted, or a
        // missing/mismatched x-ms-computerId (a backend invariant violation).
        403 => {
            return Err(
                MxcError::backend_error("status failed: pool_authorization_denied")
                    .with_details(details("pool_authorization_denied")),
            )
        }
        _ => {
            return Err(
                MxcError::backend_error("status failed").with_details(details("status_failed"))
            )
        }
    }

    let body: StatusBody = serde_json::from_str(&resp.body).map_err(|e| {
        MxcError::backend_error(format!("unparsable device status: {e}"))
            .with_details(details("unparsable_response"))
    })?;

    let state = match body.status.as_str() {
        "Waiting" => DeviceState::Waiting,
        "Live" => DeviceState::Live,
        "Ready" => DeviceState::Ready,
        other => {
            return Err(
                MxcError::backend_error(format!("unknown device status '{other}'"))
                    .with_details(json!({ "code": "unknown_device_status" })),
            )
        }
    };

    Ok(DeviceStatus {
        state,
        computer_url: body.computer_url,
        screenshare_url: body.screenshare_url,
    })
}

/// Drive the readiness poll without touching the network or the wall clock.
///
/// The retry/deadline logic lives here, separated from [`poll_until_ready`]'s
/// IO, so the boundary conditions that matter (a device that reaches `Ready` on
/// the final poll, a budget that expires, the clamped per-poll read budget) can
/// be tested deterministically rather than only against a live cluster.
///
/// `fetch` receives the clamped per-poll read budget; `now`/`sleep` are the
/// injected clock.
///
/// # Errors
/// Propagates any error from `fetch`, or returns an `attach_timeout`
/// `backend_error` when the device has not reached `Ready` within
/// `ready_timeout`.
fn drive_poll(
    ready_timeout: Duration,
    poll_interval: Duration,
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
    mut fetch: impl FnMut(Duration) -> Result<DeviceStatus, MxcError>,
) -> Result<DeviceStatus, MxcError> {
    let deadline = now()
        .checked_add(ready_timeout)
        .ok_or_else(|| MxcError::backend_error("ready_timeout is too large to schedule"))?;
    loop {
        // Clamp each poll's read timeout to the remaining budget so one stalled
        // connection cannot overrun `ready_timeout` by up to a full
        // STATUS_POLL_HTTP_TIMEOUT. Floor at 1 ms because `set_read_timeout`
        // rejects a zero Duration — an exhausted budget would otherwise surface
        // as a spurious dial error instead of this loop's own attach_timeout.
        let remaining = deadline.saturating_duration_since(now());
        let per_poll = STATUS_POLL_HTTP_TIMEOUT
            .min(remaining)
            .max(Duration::from_millis(1));
        let status = fetch(per_poll)?;
        if status.state == DeviceState::Ready {
            return Ok(status);
        }
        if now() >= deadline {
            return Err(MxcError::backend_error(format!(
                "start failed: attach_timeout (device still {:?} after {}s)",
                status.state,
                ready_timeout.as_secs()
            ))
            .with_details(json!({
                "code": "attach_timeout",
                "lastState": format!("{:?}", status.state)
            })));
        }
        sleep(poll_interval);
    }
}

/// Poll until the device reports `Ready` or the budget expires (IO).
///
/// An undialled device and a booting device both report `Waiting`, so an
/// expiry is reported as `attach_timeout` without claiming to know which.
///
/// The request is built once, outside the loop: it is identical on every poll,
/// and rebuilding it would re-read the process correlation vector per attempt.
///
/// # Errors
/// Returns `backend_error` for any per-poll HTTP or mapping failure described
/// on [`map_status_response`], or an `attach_timeout` `backend_error` when the
/// device has not reached `Ready` within `ready_timeout`.
pub fn poll_until_ready(
    client: &DpClient,
    ready_timeout: Duration,
    poll_interval: Duration,
) -> Result<DeviceStatus, MxcError> {
    let req = status_request(client);
    drive_poll(
        ready_timeout,
        poll_interval,
        Instant::now,
        sleep,
        |per_poll| map_status_response(&https_json(client.port, per_poll, &req)?),
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    use super::{
        drive_poll, map_status_response, status_request, DeviceState, DeviceStatus, DpClient,
        MxcError, STATUS_POLL_HTTP_TIMEOUT,
    };
    use crate::w365agents_common::http::HttpResponse;
    use crate::w365agents_common::secret::Redacted;

    const C: &str = "538fdbe2-1f9a-40c7-b8dd-f2391d55a24a";

    fn client() -> DpClient {
        DpClient {
            host: "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9.westus3.ari.example.net".to_string(),
            port: 443,
            api_version: "1.0".to_string(),
            computer_id: C.to_string(),
            bearer_token: Redacted::new("DP_TOKEN"),
        }
    }

    fn status(state: DeviceState) -> DeviceStatus {
        DeviceStatus {
            state,
            computer_url: None,
            screenshare_url: None,
        }
    }

    /// A fake clock: `now` advances only when the driver sleeps, so the loop is
    /// deterministic and the test never actually waits.
    struct Clock {
        now: Cell<Instant>,
    }

    impl Clock {
        fn new() -> Self {
            Self {
                now: Cell::new(Instant::now()),
            }
        }
        fn read(&self) -> Instant {
            self.now.get()
        }
        fn advance(&self, d: Duration) {
            self.now.set(self.now.get() + d);
        }
    }

    #[test]
    fn the_poll_loop_returns_as_soon_as_the_device_is_ready() {
        let clock = Clock::new();
        let calls = Cell::new(0usize);
        let out = drive_poll(
            Duration::from_secs(120),
            Duration::from_secs(2),
            || clock.read(),
            |d| clock.advance(d),
            |_| {
                calls.set(calls.get() + 1);
                Ok(status(if calls.get() >= 3 {
                    DeviceState::Ready
                } else {
                    DeviceState::Waiting
                }))
            },
        )
        .expect("device reached Ready");
        assert_eq!(out.state, DeviceState::Ready);
        // Exactly three polls: it must not keep polling after Ready.
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn a_device_that_never_becomes_ready_reports_attach_timeout() {
        let clock = Clock::new();
        let err = drive_poll(
            Duration::from_secs(10),
            Duration::from_secs(2),
            || clock.read(),
            |d| clock.advance(d),
            |_| Ok(status(DeviceState::Waiting)),
        )
        .expect_err("the budget must expire");
        let details = err.details.expect("attach_timeout carries details");
        assert_eq!(details["code"], "attach_timeout");
        assert_eq!(details["lastState"], "Waiting");
    }

    #[test]
    fn a_device_that_becomes_ready_on_the_last_poll_is_not_timed_out() {
        // The deadline check runs *after* the Ready check, so a device that
        // flips on the final allowed poll must still succeed rather than race
        // the budget.
        let clock = Clock::new();
        let calls = Cell::new(0usize);
        let out = drive_poll(
            Duration::from_secs(4),
            Duration::from_secs(2),
            || clock.read(),
            |d| clock.advance(d),
            |_| {
                calls.set(calls.get() + 1);
                Ok(status(if calls.get() == 3 {
                    DeviceState::Ready
                } else {
                    DeviceState::Waiting
                }))
            },
        )
        .expect("Ready on the final poll must win over the deadline");
        assert_eq!(out.state, DeviceState::Ready);
    }

    #[test]
    fn each_poll_budget_is_clamped_to_the_remaining_time_and_never_zero() {
        // One stalled connection must not overrun ready_timeout by a whole
        // STATUS_POLL_HTTP_TIMEOUT, and the floor must stay above zero because
        // `set_read_timeout` rejects a zero Duration.
        let clock = Clock::new();
        let budgets: std::cell::RefCell<Vec<Duration>> = std::cell::RefCell::new(Vec::new());
        let _ = drive_poll(
            Duration::from_secs(3),
            Duration::from_secs(2),
            || clock.read(),
            |d| clock.advance(d),
            |per_poll| {
                budgets.borrow_mut().push(per_poll);
                Ok(status(DeviceState::Waiting))
            },
        );
        let budgets = budgets.borrow();
        assert!(!budgets.is_empty());
        for b in budgets.iter() {
            assert!(*b >= Duration::from_millis(1), "budget floored above zero");
            assert!(*b <= STATUS_POLL_HTTP_TIMEOUT, "budget capped");
        }
        // The budget shrinks as the deadline approaches.
        assert!(budgets.last().unwrap() < budgets.first().unwrap());
    }

    #[test]
    fn a_fetch_error_aborts_the_poll_loop_instead_of_retrying() {
        // A transport failure is surfaced to the caller: silently retrying would
        // hide a misconfigured endpoint until the full ready_timeout elapsed.
        let clock = Clock::new();
        let calls = Cell::new(0usize);
        let err = drive_poll(
            Duration::from_secs(120),
            Duration::from_secs(2),
            || clock.read(),
            |d| clock.advance(d),
            |_| {
                calls.set(calls.get() + 1);
                Err(MxcError::backend_error("dial failed"))
            },
        )
        .expect_err("the fetch error must propagate");
        assert!(err.message.contains("dial failed"));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_ready_timeout_too_large_to_schedule_is_rejected_before_any_poll() {
        // `Instant + Duration::MAX` overflows; the driver must report that
        // rather than panic (a debug build would panic on the `+`).
        let clock = Clock::new();
        let err = drive_poll(
            Duration::MAX,
            Duration::from_secs(2),
            || clock.read(),
            |d| clock.advance(d),
            |_| unreachable!("must fail before the first poll"),
        )
        .expect_err("an unschedulable deadline must be rejected");
        assert!(err.message.contains("too large to schedule"), "{err:?}");
    }

    #[test]
    fn a_zero_ready_timeout_polls_exactly_once() {
        // deadline == now, so the single poll decides it: Ready wins, anything
        // else is an immediate attach_timeout. It must not poll twice.
        let clock = Clock::new();
        let calls = Cell::new(0usize);
        let err = drive_poll(
            Duration::ZERO,
            Duration::from_secs(2),
            || clock.read(),
            |d| clock.advance(d),
            |_| {
                calls.set(calls.get() + 1);
                Ok(status(DeviceState::Waiting))
            },
        )
        .expect_err("a zero budget cannot reach Ready from Waiting");
        assert_eq!(calls.get(), 1);
        assert_eq!(
            err.details.expect("details")["code"],
            serde_json::json!("attach_timeout")
        );
    }

    #[test]
    fn builds_the_status_request_with_the_required_computer_id_header() {
        let req = status_request(&client());
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, format!("/computers/{C}/status?api-version=1.0"));
        // Required on the partner path: a missing or mismatched header makes
        // the authorization handler fail with 403.
        assert_eq!(
            req.headers
                .iter()
                .find(|(k, _)| k == "x-ms-computerId")
                .map(|(_, v)| v.as_str()),
            Some(C)
        );
    }

    #[test]
    fn debug_redacts_the_token() {
        assert!(!format!("{:?}", client()).contains("DP_TOKEN"));
    }

    #[test]
    fn maps_the_three_device_states() {
        for (raw, expected) in [
            ("Waiting", DeviceState::Waiting),
            ("Live", DeviceState::Live),
            ("Ready", DeviceState::Ready),
        ] {
            let resp = HttpResponse {
                status: 200,
                body: format!(r#"{{"status":"{raw}"}}"#),
                request_id: None,
            };
            assert_eq!(map_status_response(&resp).unwrap().state, expected);
        }
    }

    #[test]
    fn carries_the_urls_through_when_present() {
        let resp = HttpResponse {
            status: 200,
            body: r#"{"status":"Ready","computerUrl":"https://cu","screenshareUrl":"https://su"}"#
                .to_string(),
            request_id: None,
        };
        let s = map_status_response(&resp).unwrap();
        assert_eq!(s.computer_url.as_deref(), Some("https://cu"));
        assert_eq!(s.screenshare_url.as_deref(), Some("https://su"));
    }

    #[test]
    fn maps_401_to_auth_denied_and_403_to_pool_authorization_denied() {
        let unauth = HttpResponse {
            status: 401,
            body: String::new(),
            request_id: None,
        };
        assert!(map_status_response(&unauth)
            .unwrap_err()
            .message
            .contains("auth_denied"));

        // 403 conflates: principal not in the pool, computer no longer in the
        // pool (released/evicted), or a missing/mismatched x-ms-computerId.
        let forbidden = HttpResponse {
            status: 403,
            body: String::new(),
            request_id: Some("r".into()),
        };
        let err = map_status_response(&forbidden).unwrap_err();
        assert!(err.message.contains("pool_authorization_denied"));
    }

    #[test]
    fn an_unknown_state_string_is_a_backend_error() {
        let resp = HttpResponse {
            status: 200,
            body: r#"{"status":"Frobnicating"}"#.to_string(),
            request_id: None,
        };
        assert!(map_status_response(&resp).is_err());
    }

    #[test]
    fn status_error_details_carry_a_stable_code() {
        let resp = HttpResponse {
            status: 401,
            body: String::new(),
            request_id: Some("rid".to_string()),
        };
        let err = map_status_response(&resp).unwrap_err();
        assert_eq!(
            err.details.unwrap()["code"],
            serde_json::json!("auth_denied")
        );
    }
}

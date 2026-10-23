// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-phase configs (camelCase on the wire) and ambient deployment coordinates.

use std::time::Duration;

pub use crate::mxc_common::models::{
    W365ProvisionConfig as ProvisionConfig, W365StartConfig as StartConfig,
    W365StopConfig as StopConfig,
};
use crate::mxc_common::mxc_error::MxcError;

use crate::w365agents_common::cp::{CheckoutOptions, SmClient};
use crate::w365agents_common::secret::Redacted;

/// Default client-side checkout timeout, in milliseconds.
///
/// Deliberately above SessionManagement's 30 s checkout cap: a shorter client
/// deadline would abandon an in-flight checkout and orphan a billing VM.
const DEFAULT_PROVISION_TIMEOUT_MS: u64 = 45_000;

/// Default budget, in milliseconds, for a device to reach `Ready` during start.
const DEFAULT_READY_TIMEOUT_MS: u64 = 120_000;

/// Default pause, in milliseconds, between device-status polls during start.
const DEFAULT_POLL_INTERVAL_MS: u64 = 2_000;

/// Default SessionManagement (control-plane) API version.
const DEFAULT_CP_API_VERSION: &str = "2.0";

/// Default RemotingInterface (data-plane) API version.
const DEFAULT_DP_API_VERSION: &str = "1.0";

/// HTTPS port shared by the control plane and the data plane.
const DEFAULT_PORT: u16 = 443;

/// The session kinds SM's `DetermineSessionKind` accepts. Anything else is
/// rejected here rather than sent as an opaque header value.
const ACCEPTED_USER_TYPES: [&str; 3] = ["Local", "HumanUser", "Agentic"];

/// Reject an api-version that could inject extra query parameters.
///
/// The value is spliced into a request path as `?api-version={v}`, so `&`, `#`
/// and `?` would let a caller append or truncate query parameters on a request
/// authenticated with the deployment's token. Control characters are caught
/// again at the wire chokepoint; this is the boundary check that names the
/// offending field.
///
/// # Errors
/// Returns `policy_validation` when `value` is empty or contains a character
/// outside `[A-Za-z0-9.-]`.
pub(crate) fn validate_api_version(field: &str, value: &str) -> Result<(), MxcError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(MxcError::policy_validation(format!(
            "w365_agents: '{field}' must be a version over [A-Za-z0-9.-], got '{value}'"
        )));
    }
    Ok(())
}

/// Deployment coordinates resolved once from the environment.
///
/// Keeping tokens here (rather than in every per-phase config) means they never
/// have to be written to a config file on disk. `Debug` is derived because each
/// token is a [`Redacted`], which redacts itself, so no manual impl is needed.
#[derive(Debug, Clone, Default)]
pub struct Ambient {
    pub cp_base_url: Option<String>,
    pub cp_token: Option<Redacted>,
    pub cp_api_version: Option<String>,
    pub dp_suffix: Option<String>,
    pub dp_token: Option<Redacted>,
    pub dp_api_version: Option<String>,
    pub agent_user_token: Option<Redacted>,
}

impl Ambient {
    /// An all-empty set of coordinates, used by tests.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Read the deployment coordinates from the `W365A_*` environment variables.
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            cp_base_url: get("W365A_CONTROLPLANE_URL"),
            cp_token: get("W365A_CP_TOKEN").map(Redacted::new),
            cp_api_version: get("W365A_CP_API_VERSION"),
            dp_suffix: get("W365A_DP_SUFFIX"),
            dp_token: get("W365A_DP_TOKEN").map(Redacted::new),
            dp_api_version: get("W365A_DP_API_VERSION"),
            agent_user_token: get("W365A_AGENT_USER_TOKEN").map(Redacted::new),
        }
    }
}

/// A resolved value that may be present-but-blank, which the resolver treats as
/// absent so an explicit `""` falls through to the ambient coordinate instead of
/// silently producing an unusable client.
pub(crate) trait MaybeBlank {
    fn is_blank(&self) -> bool;
}

impl MaybeBlank for String {
    fn is_blank(&self) -> bool {
        self.trim().is_empty()
    }
}

impl MaybeBlank for Redacted {
    fn is_blank(&self) -> bool {
        self.expose().trim().is_empty()
    }
}

/// Resolve a required value from the explicit config, then the ambient
/// environment, mapping an absence to a `policy_validation` error.
///
/// Generic over the value type so a `String` coordinate and a [`Redacted`] token
/// share one resolver. A blank value on either side counts as absent: the
/// emptiness check lives here rather than at each call site so a new coordinate
/// cannot forget it. Shared crate-wide (the `exec` phase in `runner` resolves
/// its data-plane coordinates through the same path) so every phase reports a
/// blank/absent coordinate identically.
///
/// # Errors
/// Returns `policy_validation` when neither `explicit` nor `ambient` supplies a
/// non-blank value, naming `field` and `env_var` in the message.
pub(crate) fn require<T: Clone + MaybeBlank>(
    explicit: Option<&T>,
    ambient: Option<&T>,
    field: &str,
    env_var: &str,
) -> Result<T, MxcError> {
    explicit
        .filter(|v| !v.is_blank())
        .or_else(|| ambient.filter(|v| !v.is_blank()))
        .cloned()
        .ok_or_else(|| {
            MxcError::policy_validation(format!(
                "w365_agents requires '{field}' in the phase config or {env_var} in the environment"
            ))
        })
}

/// The four values and four names [`require_host_and_token`] needs, grouped so
/// the host and its token cannot be resolved independently.
pub(crate) struct HostTokenSources<'a> {
    pub explicit_host: Option<&'a String>,
    pub ambient_host: Option<&'a String>,
    pub explicit_token: Option<&'a Redacted>,
    pub ambient_token: Option<&'a Redacted>,
    /// Config key for the host, e.g. `dpSuffix`.
    pub host_field: &'a str,
    /// Environment variable for the host, e.g. `W365A_DP_SUFFIX`.
    pub host_env: &'a str,
    /// Config key for the token, e.g. `dpBearerToken`.
    pub token_field: &'a str,
    /// Environment variable for the token, e.g. `W365A_DP_TOKEN`.
    pub token_env: &'a str,
}

/// Resolve a **host coordinate and its bearer token together**, refusing a
/// combination that would cross a trust boundary.
///
/// [`require`] prefers the explicit config over the ambient environment. For an
/// ordinary coordinate that is right. For a *host*, it is a credential
/// exfiltration primitive: in the deployment this crate documents and
/// recommends, the operator puts the token in `W365A_*` and the caller supplies
/// the phase config, so a caller-chosen `dpSuffix`/`cpBaseUrl` would send the
/// **operator's** token to a host the caller owns. TLS does not help — the
/// attacker holds a valid publicly-trusted certificate for their own domain — and
/// neither does the fixed token audience, which is what makes the captured token
/// replayable against the real service.
///
/// The rule: a caller-supplied host is honoured only when the token is *also*
/// caller-supplied. A single-trust-domain caller that supplies both is
/// unaffected, which keeps the loopback test seam working; so is a deployment
/// with no ambient token, which fails with the ordinary "missing token" error.
///
/// Host and token are resolved **here, together, from the same values**, rather
/// than by callers passing in a separate "did the caller supply a token?" flag.
/// That flag is exactly what went wrong the first time: it was computed with
/// `Option::is_some()` while the token resolver filtered blanks, so an explicit
/// **blank** token (`""`) read as "supplied" to the gate and as "absent" to the
/// resolver — unlocking a caller-chosen host *and* falling back to the ambient
/// token. Deriving both from one blank-aware value makes that drift impossible.
///
/// # Errors
/// Returns `policy_validation` when an explicit host is paired with an ambient
/// token, or when either coordinate is missing from both sources.
pub(crate) fn require_host_and_token(
    s: HostTokenSources<'_>,
) -> Result<(String, Redacted), MxcError> {
    let explicit_host = s.explicit_host.filter(|v| !v.is_blank());
    let explicit_token = s.explicit_token.filter(|v| !v.is_blank());
    let ambient_token_present = s.ambient_token.filter(|v| !v.is_blank()).is_some();

    if explicit_host.is_some() && explicit_token.is_none() && ambient_token_present {
        return Err(MxcError::policy_validation(format!(
            "w365_agents: '{host}' cannot be set in the phase config unless '{token}' is set \
             there too — otherwise the deployment's token from {token_env} would be sent to a \
             caller-chosen host. Set {host_env} instead, or supply a non-blank '{token}' in the \
             same config.",
            host = s.host_field,
            token = s.token_field,
            token_env = s.token_env,
            host_env = s.host_env,
        )));
    }
    // Host first so a deployment that configured neither coordinate is told
    // about the host, matching the pre-existing error contract.
    let host = require(explicit_host, s.ambient_host, s.host_field, s.host_env)?;
    let token = require(explicit_token, s.ambient_token, s.token_field, s.token_env)?;
    Ok((host, token))
}

impl ProvisionConfig {
    /// The client-side checkout timeout, defaulting above the server's 30 s cap.
    pub fn effective_timeout(&self) -> Duration {
        Duration::from_millis(
            self.provision_timeout_ms
                .unwrap_or(DEFAULT_PROVISION_TIMEOUT_MS),
        )
    }

    /// Build the SessionManagement client from explicit config and ambient coordinates.
    ///
    /// # Errors
    /// Returns `policy_validation` when neither the config nor the environment
    /// supplies the control-plane URL (`cpBaseUrl` / `W365A_CONTROLPLANE_URL`) or
    /// the control-plane token (`cpBearerToken` / `W365A_CP_TOKEN`).
    pub fn sm_client(&self, ambient: &Ambient) -> Result<SmClient, MxcError> {
        let api_version = self
            .cp_api_version
            .clone()
            .or_else(|| ambient.cp_api_version.clone())
            .unwrap_or_else(|| DEFAULT_CP_API_VERSION.to_string());
        validate_api_version("cpApiVersion", &api_version)?;
        let (base_host, bearer_token) = require_host_and_token(HostTokenSources {
            explicit_host: self.cp_base_url.as_ref(),
            ambient_host: ambient.cp_base_url.as_ref(),
            explicit_token: self.cp_bearer_token.as_ref(),
            ambient_token: ambient.cp_token.as_ref(),
            host_field: "cpBaseUrl",
            host_env: "W365A_CONTROLPLANE_URL",
            token_field: "cpBearerToken",
            token_env: "W365A_CP_TOKEN",
        })?;
        Ok(SmClient {
            base_host,
            port: self.port.unwrap_or(DEFAULT_PORT),
            api_version,
            bearer_token,
        })
    }

    /// Build the checkout options, validating the pool id and enforcing SM's
    /// agentic co-requirement.
    ///
    /// # Errors
    /// Returns `policy_validation` when `poolId` or `userObjectId` is not a
    /// canonical GUID, when `userType` is not one of SM's accepted session
    /// kinds, or when `agentUserToken` is present without the `userObjectId`
    /// that SM requires to infer an `AgenticUserSession`.
    pub fn checkout_options(&self) -> Result<CheckoutOptions, MxcError> {
        // `poolId` becomes the first segment of the minted sandbox id and is
        // spliced verbatim into the SM request path. It is the one segment
        // `map_checkout_response` cannot check (it never sees it), so validate
        // it here — inside `validate_provision`, before any network call.
        if !crate::w365agents_common::id::is_guid(&self.pool_id) {
            return Err(MxcError::policy_validation(format!(
                "w365_agents: 'poolId' must be a canonical 8-4-4-4-12 GUID, got '{}'",
                self.pool_id
            )));
        }
        if self.agent_user_token.is_some() && self.user_object_id.is_none() {
            return Err(MxcError::policy_validation(
                "w365_agents: 'agentUserToken' requires 'userObjectId' (SM infers an \
                 AgenticUserSession from the auxiliary token and rejects it without the user id)",
            ));
        }
        if let Some(aux) = &self.agent_user_token {
            if aux.expose().chars().any(char::is_control) {
                return Err(MxcError::policy_validation(
                    "w365_agents: 'agentUserToken' contains a control character",
                ));
            }
        }
        // Both reach SM as raw header values. `poolId` was validated above for
        // exactly this reason; these are its siblings.
        if let Some(oid) = &self.user_object_id {
            if !crate::w365agents_common::id::is_guid(oid) {
                return Err(MxcError::policy_validation(format!(
                    "w365_agents: 'userObjectId' must be a canonical 8-4-4-4-12 GUID, got '{oid}'"
                )));
            }
        }
        if let Some(kind) = &self.user_type {
            if !ACCEPTED_USER_TYPES.contains(&kind.as_str()) {
                return Err(MxcError::policy_validation(format!(
                    "w365_agents: 'userType' must be one of {ACCEPTED_USER_TYPES:?}, got '{kind}'"
                )));
            }
        }
        Ok(CheckoutOptions {
            pool_id: self.pool_id.clone(),
            agent_user_token: self.agent_user_token.clone(),
            user_object_id: self.user_object_id.clone(),
            user_type: self.user_type.clone(),
        })
    }
}

impl StartConfig {
    /// The budget for the device to reach `Ready`, defaulting to two minutes.
    pub fn effective_ready_timeout(&self) -> Duration {
        Duration::from_millis(self.ready_timeout_ms.unwrap_or(DEFAULT_READY_TIMEOUT_MS))
    }

    /// The pause between device-status polls, defaulting to two seconds.
    pub fn effective_poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms.unwrap_or(DEFAULT_POLL_INTERVAL_MS))
    }

    /// Resolve the data-plane host suffix **and** token together.
    ///
    /// Returned as a pair rather than by two separate getters: the trust rule in
    /// [`require_host_and_token`] is a property of the *combination*, so a caller
    /// must not be able to take one without the other.
    ///
    /// # Errors
    /// Returns `policy_validation` when `dpSuffix` is set in the config without a
    /// non-blank `dpBearerToken` while the environment supplies the token, or
    /// when either coordinate is missing from both sources.
    pub fn resolve_dp_coordinates(
        &self,
        ambient: &Ambient,
    ) -> Result<(String, Redacted), MxcError> {
        require_host_and_token(HostTokenSources {
            explicit_host: self.dp_suffix.as_ref(),
            ambient_host: ambient.dp_suffix.as_ref(),
            explicit_token: self.dp_bearer_token.as_ref(),
            ambient_token: ambient.dp_token.as_ref(),
            host_field: "dpSuffix",
            host_env: "W365A_DP_SUFFIX",
            token_field: "dpBearerToken",
            token_env: "W365A_DP_TOKEN",
        })
    }

    /// Resolve the data-plane API version, falling back to the built-in default.
    ///
    /// # Errors
    /// Returns `policy_validation` when the resolved version is not a version
    /// over `[A-Za-z0-9.-]` — it is spliced into a query string, so `&`/`?`
    /// would let a caller append parameters to an authenticated request.
    pub fn resolve_dp_api_version(&self, ambient: &Ambient) -> Result<String, MxcError> {
        let v = self
            .dp_api_version
            .clone()
            .or_else(|| ambient.dp_api_version.clone())
            .unwrap_or_else(|| DEFAULT_DP_API_VERSION.to_string());
        validate_api_version("dpApiVersion", &v)?;
        Ok(v)
    }
}

impl StopConfig {
    /// Build the SessionManagement client used to release a session.
    ///
    /// # Errors
    /// Returns `policy_validation` when neither the config nor the environment
    /// supplies the control-plane URL (`cpBaseUrl` / `W365A_CONTROLPLANE_URL`) or
    /// the control-plane token (`cpBearerToken` / `W365A_CP_TOKEN`).
    pub fn sm_client(&self, ambient: &Ambient) -> Result<SmClient, MxcError> {
        let api_version = self
            .cp_api_version
            .clone()
            .or_else(|| ambient.cp_api_version.clone())
            .unwrap_or_else(|| DEFAULT_CP_API_VERSION.to_string());
        validate_api_version("cpApiVersion", &api_version)?;
        let (base_host, bearer_token) = require_host_and_token(HostTokenSources {
            explicit_host: self.cp_base_url.as_ref(),
            ambient_host: ambient.cp_base_url.as_ref(),
            explicit_token: self.cp_bearer_token.as_ref(),
            ambient_token: ambient.cp_token.as_ref(),
            host_field: "cpBaseUrl",
            host_env: "W365A_CONTROLPLANE_URL",
            token_field: "cpBearerToken",
            token_env: "W365A_CP_TOKEN",
        })?;
        Ok(SmClient {
            base_host,
            port: self.port.unwrap_or(DEFAULT_PORT),
            api_version,
            bearer_token,
        })
    }
}

/// Deprovision takes the same shape as stop.
pub type DeprovisionConfig = StopConfig;

#[cfg(test)]
mod tests {
    use super::{Ambient, ProvisionConfig, StartConfig, StopConfig};
    use crate::w365agents_common::secret::Redacted;

    #[test]
    fn provision_config_deserializes_camel_case() {
        let json = r#"{
            "poolId": "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9",
            "agentUserToken": "AUX",
            "userObjectId": "11111111-2222-3333-4444-555555555555",
            "userType": "Agentic",
            "provisionTimeoutMs": 60000,
            "cpBaseUrl": "sm.example.net",
            "cpBearerToken": "TOK"
        }"#;
        let cfg: ProvisionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.pool_id, "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9");
        // `agent_user_token` is a `Redacted`, so compare the exposed value.
        assert_eq!(
            cfg.agent_user_token.as_ref().map(|t| t.expose()),
            Some("AUX")
        );
        assert_eq!(cfg.provision_timeout_ms, Some(60000));
        assert_eq!(cfg.cp_base_url.as_deref(), Some("sm.example.net"));
    }

    #[test]
    fn start_config_defaults_are_applied() {
        let cfg: StartConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.ready_timeout_ms, None);
        assert_eq!(cfg.effective_ready_timeout().as_millis(), 120_000);
        assert_eq!(cfg.effective_poll_interval().as_millis(), 2_000);
    }

    #[test]
    fn provision_timeout_defaults_above_the_server_cap() {
        let cfg: ProvisionConfig =
            serde_json::from_str(r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9"}"#).unwrap();
        // The server caps checkout at 30s; a shorter client timeout would
        // abandon an in-flight checkout and orphan a billing VM.
        assert_eq!(cfg.effective_timeout().as_millis(), 45_000);
        assert!(cfg.effective_timeout().as_secs() > 30);
    }

    #[test]
    fn config_debug_redacts_tokens() {
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBearerToken":"SECRET","agentUserToken":"AUX_SECRET"}"#,
        )
        .unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("SECRET"));
        assert!(!dbg.contains("AUX_SECRET"));
    }

    #[test]
    fn explicit_config_wins_over_ambient_when_the_caller_owns_both() {
        // Explicit still wins — but only when the caller supplies the token too,
        // so no trust boundary is crossed. See `require_host`.
        let ambient = Ambient {
            cp_base_url: Some("ambient.example.net".to_string()),
            cp_token: Some(Redacted::new("AMBIENT")),
            cp_api_version: Some("9.9".to_string()),
            ..Ambient::empty()
        };
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBaseUrl":"explicit.example.net","cpBearerToken":"EXPLICIT"}"#,
        )
        .unwrap();
        let client = cfg.sm_client(&ambient).unwrap();
        assert_eq!(client.base_host, "explicit.example.net");
        assert_eq!(client.api_version, "9.9");
        assert_eq!(client.bearer_token.expose(), "EXPLICIT");
    }

    #[test]
    fn a_blank_explicit_token_cannot_unlock_a_caller_chosen_host() {
        // The bypass the first fix missed: `""` reads as "supplied" to a
        // `is_some()` gate but as "absent" to the blank-aware resolver, so it
        // would unlock the host AND fall back to the ambient token. Resolving
        // both in one place from one blank-aware value makes this impossible.
        let ambient = Ambient {
            cp_base_url: Some("sm.trusted.example.net".to_string()),
            cp_token: Some(Redacted::new("OPERATOR_TOKEN")),
            ..Ambient::empty()
        };
        for blank in ["\"\"", "\"   \""] {
            let cfg: ProvisionConfig = serde_json::from_str(&format!(
                r#"{{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBaseUrl":"evil.example","cpBearerToken":{blank}}}"#
            ))
            .unwrap();
            let err = cfg
                .sm_client(&ambient)
                .expect_err("a blank token must not unlock a caller-chosen host");
            assert_eq!(err.code.as_str(), "policy_validation");
            assert!(err.message.contains("cpBaseUrl"), "{}", err.message);
        }
    }

    #[test]
    fn a_non_blank_explicit_token_is_the_one_that_actually_gets_used() {
        // The counterpart: an explicit host IS allowed with an explicit token,
        // and the token that reaches the wire must be the caller's own -- not
        // the operator's. Otherwise the "same trust domain" rule is cosmetic.
        let ambient = Ambient {
            cp_base_url: Some("sm.trusted.example.net".to_string()),
            cp_token: Some(Redacted::new("OPERATOR_TOKEN")),
            ..Ambient::empty()
        };
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBaseUrl":"caller.example","cpBearerToken":"CALLER_TOKEN"}"#,
        )
        .unwrap();
        let client = cfg.sm_client(&ambient).unwrap();
        assert_eq!(client.base_host, "caller.example");
        assert_eq!(client.bearer_token.expose(), "CALLER_TOKEN");
    }

    #[test]
    fn a_blank_explicit_token_cannot_unlock_a_caller_chosen_host_on_stop() {
        // stop/deprovision share StopConfig, so the same bypass would have
        // leaked the control-plane token on teardown too.
        let ambient = Ambient {
            cp_base_url: Some("sm.trusted.example.net".to_string()),
            cp_token: Some(Redacted::new("OPERATOR_TOKEN")),
            ..Ambient::empty()
        };
        let cfg: StopConfig =
            serde_json::from_str(r#"{"cpBaseUrl":"evil.example","cpBearerToken":""}"#).unwrap();
        let err = cfg.sm_client(&ambient).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("cpBaseUrl"), "{}", err.message);
    }

    #[test]
    fn a_caller_supplied_host_cannot_redirect_an_ambient_token() {
        // The exfiltration primitive: the operator holds the token in the
        // environment, the caller supplies the phase config, so a caller-chosen
        // host would ship the deployment's credential to a host the caller owns.
        // TLS does not help -- the attacker holds a valid certificate for their
        // own domain -- so this must be refused before the dial.
        let ambient = Ambient {
            cp_base_url: Some("sm.trusted.example.net".to_string()),
            cp_token: Some(Redacted::new("OPERATOR_TOKEN")),
            ..Ambient::empty()
        };
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBaseUrl":"evil.example"}"#,
        )
        .unwrap();
        let err = cfg.sm_client(&ambient).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("cpBaseUrl"), "{}", err.message);
        assert!(
            err.message.contains("caller-chosen host"),
            "{}",
            err.message
        );
    }

    #[test]
    fn an_api_version_cannot_smuggle_extra_query_parameters() {
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBaseUrl":"sm.example.net","cpBearerToken":"T","cpApiVersion":"2.0&admin=true"}"#,
        )
        .unwrap();
        let err = cfg.sm_client(&Ambient::empty()).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("cpApiVersion"), "{}", err.message);
    }

    #[test]
    fn a_non_guid_user_object_id_is_rejected_before_it_becomes_a_header() {
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","userObjectId":"x\r\nInjected: 1"}"#,
        )
        .unwrap();
        let err = cfg.checkout_options().unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("userObjectId"), "{}", err.message);
    }

    #[test]
    fn an_unknown_user_type_is_rejected() {
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","userType":"Root"}"#,
        )
        .unwrap();
        let err = cfg.checkout_options().unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("userType"), "{}", err.message);
    }

    #[test]
    fn a_missing_control_plane_url_is_a_policy_validation_error() {
        let cfg: ProvisionConfig =
            serde_json::from_str(r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9"}"#).unwrap();
        let err = cfg.sm_client(&Ambient::empty()).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("W365A_CONTROLPLANE_URL"));
    }

    #[test]
    fn an_explicit_blank_coordinate_falls_back_to_ambient() {
        // An empty string in the wire config must not be accepted as a value:
        // it would build a client pointed at "" and fail later as an opaque
        // connect error instead of a clear policy_validation.
        let ambient = Ambient {
            cp_base_url: Some("ambient.example.net".to_string()),
            cp_token: Some(Redacted::new("AMBIENT")),
            ..Ambient::empty()
        };
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBaseUrl":"","cpBearerToken":"  "}"#,
        )
        .unwrap();
        let client = cfg.sm_client(&ambient).unwrap();
        assert_eq!(client.base_host, "ambient.example.net");
        assert_eq!(client.bearer_token.expose(), "AMBIENT");
    }

    #[test]
    fn an_explicit_blank_with_no_ambient_is_a_policy_validation_error() {
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","cpBaseUrl":""}"#,
        )
        .unwrap();
        let err = cfg.sm_client(&Ambient::empty()).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("cpBaseUrl"));
    }

    #[test]
    fn an_agent_user_token_without_a_user_object_id_is_rejected() {
        let cfg: ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","agentUserToken":"AUX"}"#,
        )
        .unwrap();
        let err = cfg.checkout_options().unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("userObjectId"));
    }

    #[test]
    fn stop_config_accepts_an_empty_object() {
        let cfg: StopConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.cp_base_url.is_none());
    }
}

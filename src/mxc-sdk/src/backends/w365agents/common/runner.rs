// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `W365AgentsRunner` — the `StatefulSandboxBackend` implementation.
//!
//! Lifecycle mapping (see the design spec, §4):
//!   provision   → SM  POST   /api/pools/{poolId}/sessions   (checkout; mints the id)
//!   start       → ARI GET    /computers/{c}/status          (poll to Ready)
//!   exec        → ARI ANY    /computers/{c}/microsoft.mxc-exec
//!   stop        → SM  DELETE /api/sessions/{c}               (check-in; TERMINAL)
//!   deprovision → SM  DELETE /api/sessions/{c}               (idempotent safety net)
//!
//! Every phase routes its id through the single [`W365SandboxId`] parser, so a
//! `w365:{poolId}:{computerId}` minted by `provision` round-trips into the very
//! next `exec` / `stop` / `deprovision`. The legacy dot form
//! (`w365:{poolId}.{sessionId}`) is no longer parsed here and now fails as
//! `malformed_id` (spec §10 — a hard cutover, no dual parser).

use std::time::Duration;

pub use crate::mxc_common::models::W365ExecConfig;
use crate::mxc_common::models::{BaseProcessUiConfig, ContainerPolicy, ExecutionRequest, UiPolicy};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    unsupported_piped_exec, DeprovisionResult, ExecHandle, ExecStdio, ProvisionResult, StartResult,
    StatefulSandboxBackend, StopResult,
};

use crate::w365agents_common::config::{
    require_host_and_token, validate_api_version, Ambient, DeprovisionConfig, HostTokenSources,
    MaybeBlank, ProvisionConfig, StartConfig, StopConfig,
};
use crate::w365agents_common::cp;
use crate::w365agents_common::dp::{self, DpClient};
use crate::w365agents_common::exec::payload::ExecStartPayload;
use crate::w365agents_common::exec::run_exec;
use crate::w365agents_common::exec::transport::UpgradeTarget;
use crate::w365agents_common::http::reject_control_chars;
use crate::w365agents_common::id::W365SandboxId;
use crate::w365agents_common::metadata::{
    ExecDescriptor, McpDescriptor, ProvisionMetadata, ReleaseMetadata, StartMetadata,
};

/// Reverse-DNS capability selected when the exec config omits `capability`.
const DEFAULT_CAPABILITY: &str = "microsoft.mxc-exec";

/// HTTPS port shared by the SessionManagement control plane and the ARI data
/// plane. Both services sit behind the same TLS ingress, so exec and start use
/// one value rather than a per-phase port.
const DEFAULT_PORT: u16 = 443;

/// HTTP read timeout for a single check-in (release) request.
///
/// A check-in is a fire-and-forget `DELETE` that returns as soon as SM registers
/// the CDP operation, so this only bounds a stalled connection — it is not the
/// (asynchronous) VM-reclaim budget, which `ReleaseMetadata` deliberately never
/// claims to observe.
const RELEASE_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Backend runner for the W365 agents lifecycle.
#[derive(Debug, Default)]
pub struct W365AgentsRunner;

impl W365AgentsRunner {
    /// Construct a runner. It holds no state; every phase resolves its own
    /// client from the phase config and ambient coordinates.
    pub fn new() -> Self {
        Self
    }
}

/// Reject anything that is not a reverse-DNS capability name.
///
/// The capability is spliced into the ARI request path, so this is both an
/// injection boundary and a fast-fail: without it a typo costs a full TLS dial
/// plus upgrade round-trip before ARI answers `404 CapabilityNotFound`. `/` and
/// `.` traversal sequences are excluded by the charset.
///
/// # Errors
/// Returns `policy_validation` when `capability` is empty, contains a character
/// outside `[A-Za-z0-9.-]`, or starts or ends with a dot.
fn validate_capability(capability: &str) -> Result<(), MxcError> {
    let ok = !capability.is_empty()
        && !capability.starts_with('.')
        && !capability.ends_with('.')
        && !capability.contains("..")
        && capability
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !ok {
        return Err(MxcError::policy_validation(format!(
            "w365_agents: 'capability' must be a reverse-DNS name over [A-Za-z0-9.-] \
             with no leading, trailing or doubled dot, got '{capability}'"
        )));
    }
    Ok(())
}

/// Parse the sandbox id and build the exec upgrade target.
///
/// The id is parsed through [`W365SandboxId`] first, so a malformed id is
/// rejected before any coordinate resolution or network call.
///
/// # Errors
/// Returns `malformed_id` when `sandbox_id` is not a canonical
/// `w365:{poolId}:{computerId}`; returns `policy_validation` when neither the
/// exec config nor the ambient environment supplies the data-plane suffix
/// (`dpSuffix` / `W365A_DP_SUFFIX`) or the bearer token (`bearerToken` /
/// `W365A_DP_TOKEN`), when a caller-supplied `dpSuffix` would redirect an
/// ambient token (see [`crate::w365agents_common::config::require_host_and_token`]),
/// or when `capability` is not a reverse-DNS name.
pub fn derive_target(
    sandbox_id: &str,
    cfg: &W365ExecConfig,
    ambient: &Ambient,
) -> Result<UpgradeTarget, MxcError> {
    let id = W365SandboxId::parse(sandbox_id)?;
    let (dp_suffix, bearer_token) = require_host_and_token(HostTokenSources {
        explicit_host: cfg.dp_suffix.as_ref(),
        ambient_host: ambient.dp_suffix.as_ref(),
        explicit_token: cfg.bearer_token.as_ref(),
        ambient_token: ambient.dp_token.as_ref(),
        host_field: "dpSuffix",
        host_env: "W365A_DP_SUFFIX",
        token_field: "bearerToken",
        token_env: "W365A_DP_TOKEN",
    })?;
    let capability = cfg
        .capability
        .clone()
        .unwrap_or_else(|| DEFAULT_CAPABILITY.to_string());
    validate_capability(&capability)?;
    Ok(UpgradeTarget {
        host: id.dp_host(&dp_suffix),
        port: cfg.port.unwrap_or(DEFAULT_PORT),
        path: format!("/computers/{}/{}", id.computer_id(), capability),
        computer_id: id.computer_id().to_string(),
        bearer_token,
        capability,
    })
}

/// Map an `ExecutionRequest` into the `EXEC_START` payload.
pub fn build_start(request: &ExecutionRequest) -> ExecStartPayload {
    ExecStartPayload {
        command_line: request.script_code.clone(),
        working_directory: request.working_directory.clone(),
        env: request.env.clone().unwrap_or_default(),
        timeout_ms: request.script_timeout,
        shell: None,
    }
}

/// Reject any request that carries a non-default policy for this backend.
///
/// MXC cannot enforce filesystem / network / UI policy inside a remote Windows
/// 365 Cloud PC it does not control, so it refuses rather than silently ignoring
/// the caller's policy. Exhaustively destructures [`ContainerPolicy`] so
/// `#[serde(skip)]` presence flags (`ui_specified`, `network_specified`,
/// `network_proxy`, etc.) and any future policy fields are checked.
///
/// # Errors
/// Returns `policy_validation` when `request.policy` differs from
/// `ContainerPolicy::default()` or specifies any `ui` / `network` / `proxy` block.
pub fn honor_matrix_check(request: &ExecutionRequest) -> Result<(), MxcError> {
    let ContainerPolicy {
        least_privilege_mode,
        ref capabilities,
        ref readwrite_paths,
        ref readonly_paths,
        ref enumerate_paths,
        ref denied_paths,
        ref network_egress,
        ref network_ingress,
        ref allowed_proxy_peer,
        ref network_proxy,
        network_specified,
        network_mode_specified,
        runtime_network_proxy_specified,
        ref ui,
        ui_specified,
        ref base_process_ui,
        ref capture_denials,
    } = request.policy;

    let UiPolicy {
        disable: ui_disable,
        ref clipboard,
        injection: ui_injection,
    } = *ui;
    let BaseProcessUiConfig {
        ref isolation,
        desktop_system_control,
        ref system_settings,
        ime,
    } = *base_process_ui;
    let def = ContainerPolicy::default();
    let ui_changed = ui_specified
        || ui_disable != def.ui.disable
        || *clipboard != def.ui.clipboard
        || ui_injection != def.ui.injection
        || *isolation != def.base_process_ui.isolation
        || desktop_system_control != def.base_process_ui.desktop_system_control
        || *system_settings != def.base_process_ui.system_settings
        || ime != def.base_process_ui.ime;
    let net_changed = network_specified
        || network_mode_specified
        || runtime_network_proxy_specified
        || network_egress.is_some()
        || network_ingress
            .as_ref()
            .is_some_and(|ing| *ing != crate::mxc_common::models::NetworkIngressPolicy::default())
        || allowed_proxy_peer.is_some()
        || network_proxy.is_enabled();
    let fs_changed = !readwrite_paths.is_empty()
        || !readonly_paths.is_empty()
        || !enumerate_paths.is_empty()
        || !denied_paths.is_empty();
    let other_changed = least_privilege_mode != def.least_privilege_mode
        || !capabilities.is_empty()
        || capture_denials.is_some();

    if fs_changed || net_changed || ui_changed || other_changed {
        return Err(MxcError::policy_validation(
            "w365_agents does not honor filesystem/network/ui policy: the workload runs on a \
             remote Windows 365 Cloud PC that MXC does not control",
        ));
    }
    Ok(())
}

/// Release (check in) the Cloud PC behind `sandbox_id`.
///
/// Shared by `stop` and `deprovision`: SessionManagement has exactly one
/// release verb, so both phases issue the identical call and report the same
/// metadata. The id is parsed first, so a malformed id fails before any IO.
///
/// # Errors
/// Returns `malformed_id` for an unparsable sandbox id, `policy_validation`
/// when the control-plane coordinates are absent, or the `backend_error` that
/// [`cp::release`] maps from the service response.
fn release_phase(
    sandbox_id: &str,
    config: Option<StopConfig>,
) -> Result<ReleaseMetadata, MxcError> {
    let id = W365SandboxId::parse(sandbox_id)?;
    let cfg = config.unwrap_or_default();
    let client = cfg.sm_client(&Ambient::from_env())?;
    cp::release(&client, id.computer_id(), RELEASE_HTTP_TIMEOUT)?;
    Ok(ReleaseMetadata::default())
}

impl StatefulSandboxBackend for W365AgentsRunner {
    const ID_PREFIX: &'static str = "w365";
    const BACKEND_KEY: &'static str = "w365_agents";

    type ProvisionConfig = ProvisionConfig;
    type StartConfig = StartConfig;
    type ExecConfig = W365ExecConfig;
    type StopConfig = StopConfig;
    type DeprovisionConfig = DeprovisionConfig;
    type ProvisionMetadata = ProvisionMetadata;
    type StartMetadata = StartMetadata;
    type StopMetadata = ReleaseMetadata;
    type DeprovisionMetadata = ReleaseMetadata;

    /// Check a Cloud PC out of the pre-provisioned pool and mint the id.
    fn provision(
        &mut self,
        _request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> {
        let cfg = config.ok_or_else(|| {
            MxcError::policy_validation(
                "w365_agents provision requires w365Agents.provision (poolId)",
            )
        })?;
        let ambient = Ambient::from_env();
        let client = cfg.sm_client(&ambient)?;
        let opts = cfg.checkout_options()?;
        let session = cp::checkout(&client, &opts, cfg.effective_timeout())?;

        // computerId == sessionId on the pooled path; map_checkout_response has
        // already rejected any response where they disagree, and permits
        // `computerId: None`, so fall back to sessionId rather than unwrapping.
        let computer_id = session
            .computer_id
            .clone()
            .unwrap_or_else(|| session.session_id.clone());

        Ok(ProvisionResult {
            sandbox_id: W365SandboxId::mint(&cfg.pool_id, &computer_id)?,
            metadata: Some(ProvisionMetadata {
                session_id: session.session_id,
                computer_id,
                status: session.status,
                computer_url: session.computer_url,
                connectivity_url: session.connectivity_url,
                screenshare_url: session.screenshare_url,
            }),
        })
    }

    /// Read-only readiness attach: poll the device's self-reported status.
    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        let id = W365SandboxId::parse(sandbox_id)?;
        let cfg = config.unwrap_or_default();
        let ambient = Ambient::from_env();
        let (dp_suffix, bearer_token) = cfg.resolve_dp_coordinates(&ambient)?;

        let client = DpClient {
            host: id.dp_host(&dp_suffix),
            port: cfg.port.unwrap_or(DEFAULT_PORT),
            api_version: cfg.resolve_dp_api_version(&ambient)?,
            computer_id: id.computer_id().to_string(),
            bearer_token,
        };
        let status = dp::poll_until_ready(
            &client,
            cfg.effective_ready_timeout(),
            cfg.effective_poll_interval(),
        )?;

        Ok(StartResult {
            metadata: Some(StartMetadata {
                // poll_until_ready only returns Ok once the device reports Ready.
                status: "Ready".to_string(),
                computer_url: status.computer_url,
                screenshare_url: status.screenshare_url,
                mcp: McpDescriptor::new(&client.host, id.computer_id(), &client.api_version),
                exec: ExecDescriptor {
                    capability: DEFAULT_CAPABILITY.to_string(),
                },
            }),
        })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::ExecConfig>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        if stdio == ExecStdio::Piped {
            return Err(unsupported_piped_exec("W365 Agents"));
        }
        let cfg = config.unwrap_or_default();
        let target = derive_target(sandbox_id, &cfg, &Ambient::from_env())?;
        run_exec(target, build_start(request))
    }

    /// Check the Cloud PC back in. TERMINAL: the sessionId cannot be recreated,
    /// so `start` after `stop` will not succeed.
    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        Ok(StopResult {
            metadata: Some(release_phase(sandbox_id, config)?),
        })
    }

    /// Idempotent safety net: guarantees nothing stays checked out under this
    /// sandbox even if the caller skipped `stop`. Afterwards the id is dead.
    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        Ok(DeprovisionResult {
            metadata: Some(release_phase(sandbox_id, config)?),
        })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        honor_matrix_check(request)?;
        let cfg = config.ok_or_else(|| {
            MxcError::policy_validation(
                "w365_agents provision requires w365Agents.provision (poolId)",
            )
        })?;
        cfg.checkout_options()?;
        if let Some(v) = &cfg.cp_api_version {
            validate_api_version("cpApiVersion", v)?;
        }
        if let Some(host) = cfg.cp_base_url.as_ref().filter(|v| !v.is_blank()) {
            reject_control_chars("cpBaseUrl", host)?;
        }
        if let Some(tok) = &cfg.cp_bearer_token {
            if tok.expose().chars().any(char::is_control) {
                return Err(MxcError::policy_validation(
                    "w365_agents: the bearer token contains a control character",
                ));
            }
        }
        Ok(())
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<&Self::StartConfig>,
    ) -> Result<(), MxcError> {
        honor_matrix_check(request)?;
        W365SandboxId::parse(sandbox_id)?;
        if let Some(cfg) = config {
            if let Some(v) = &cfg.dp_api_version {
                validate_api_version("dpApiVersion", v)?;
            }
            if let Some(host) = cfg.dp_suffix.as_ref().filter(|v| !v.is_blank()) {
                reject_control_chars("dpSuffix", host)?;
            }
            if let Some(tok) = &cfg.dp_bearer_token {
                if tok.expose().chars().any(char::is_control) {
                    return Err(MxcError::policy_validation(
                        "w365_agents: the bearer token contains a control character",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<&Self::ExecConfig>,
    ) -> Result<(), MxcError> {
        honor_matrix_check(request)?;
        W365SandboxId::parse(sandbox_id)?;
        if let Some(cfg) = config {
            if let Some(cap) = &cfg.capability {
                validate_capability(cap)?;
            }
            if let Some(host) = cfg.dp_suffix.as_ref().filter(|v| !v.is_blank()) {
                reject_control_chars("dpSuffix", host)?;
            }
            if let Some(tok) = &cfg.bearer_token {
                if tok.expose().chars().any(char::is_control) {
                    return Err(MxcError::policy_validation(
                        "w365_agents: the bearer token contains a control character",
                    ));
                }
            }
        }
        build_start(request).encode().map(|_| ())
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<&Self::StopConfig>,
    ) -> Result<(), MxcError> {
        honor_matrix_check(request)?;
        W365SandboxId::parse(sandbox_id)?;
        if let Some(cfg) = config {
            if let Some(v) = &cfg.cp_api_version {
                validate_api_version("cpApiVersion", v)?;
            }
            if let Some(host) = cfg.cp_base_url.as_ref().filter(|v| !v.is_blank()) {
                reject_control_chars("cpBaseUrl", host)?;
            }
            if let Some(tok) = &cfg.cp_bearer_token {
                if tok.expose().chars().any(char::is_control) {
                    return Err(MxcError::policy_validation(
                        "w365_agents: the bearer token contains a control character",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<&Self::DeprovisionConfig>,
    ) -> Result<(), MxcError> {
        self.validate_stop(sandbox_id, request, config)
    }
}

#[cfg(test)]
mod tests {
    use super::{build_start, honor_matrix_check, W365AgentsRunner, W365ExecConfig};
    use crate::mxc_common::models::ExecutionRequest;
    use crate::mxc_common::state_aware_backend::StatefulSandboxBackend;
    use crate::w365agents_common::config::Ambient;
    use crate::w365agents_common::id::W365SandboxId;
    use crate::w365agents_common::secret::Redacted;

    const POOL: &str = "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9";
    const C: &str = "538fdbe2-1f9a-40c7-b8dd-f2391d55a24a";

    fn sandbox_id() -> String {
        W365SandboxId::mint(POOL, C).unwrap()
    }

    fn exec_config() -> W365ExecConfig {
        W365ExecConfig {
            dp_suffix: Some("westus3.ari.example.net".to_string()),
            capability: None,
            bearer_token: Some(Redacted::new("DP_TOKEN")),
            port: None,
        }
    }

    #[test]
    fn backend_identity_constants() {
        assert_eq!(W365AgentsRunner::ID_PREFIX, "w365");
        assert_eq!(W365AgentsRunner::BACKEND_KEY, "w365_agents");
    }

    #[test]
    fn debug_never_prints_the_bearer_token() {
        // W365ExecConfig derives Debug over an Option<Redacted>, so a config
        // dump (into a log line or an error `details`) cannot leak the token.
        let cfg = W365ExecConfig {
            bearer_token: Some(Redacted::new("CONFIG_TOKEN_SECRET")),
            ..exec_config()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("CONFIG_TOKEN_SECRET"),
            "bearer token leaked in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
    }

    #[test]
    fn derives_the_upgrade_target_from_the_three_segment_id() {
        let target =
            super::derive_target(&sandbox_id(), &exec_config(), &Ambient::empty()).unwrap();
        assert_eq!(target.host, format!("{POOL}.westus3.ari.example.net"));
        assert_eq!(target.port, 443);
        assert_eq!(target.path, format!("/computers/{C}/microsoft.mxc-exec"));
        assert_eq!(target.computer_id, C);
        assert_eq!(target.capability, "microsoft.mxc-exec");
    }

    #[test]
    fn a_provisioned_id_round_trips_into_exec() {
        // The crux of the Phase 1..4 unification: an id minted the way
        // `provision` mints it (via W365SandboxId::mint) must be accepted by
        // the exec entry point (derive_target -> W365SandboxId::parse). If the
        // two ever drifted apart, provision would strand every sandbox.
        let minted = W365SandboxId::mint(POOL, C).unwrap();
        let target = super::derive_target(&minted, &exec_config(), &Ambient::empty()).unwrap();
        assert_eq!(target.computer_id, C);
        assert_eq!(target.host, format!("{POOL}.westus3.ari.example.net"));
        assert_eq!(target.path, format!("/computers/{C}/microsoft.mxc-exec"));
    }

    #[test]
    fn rejects_a_malformed_sandbox_id() {
        for bad in [
            format!("w365:{POOL}.{C}"), // the legacy 2-segment (dot) form
            format!("iso:{POOL}:{C}"),
            "w365:not-a-guid:also-bad".to_string(),
        ] {
            let err = super::derive_target(&bad, &exec_config(), &Ambient::empty()).unwrap_err();
            assert_eq!(err.code.as_str(), "malformed_id", "for {bad}");
        }
    }

    #[test]
    fn a_capability_with_a_path_traversal_is_refused() {
        // `capability` is spliced into the ARI request path. `/` and `..` would
        // let a caller reach a different route on an authenticated connection.
        let cfg = W365ExecConfig {
            dp_suffix: Some("dp.example.net".into()),
            capability: Some("../../pools/other".into()),
            bearer_token: Some(Redacted::new("T")),
            port: None,
        };
        let err = super::derive_target(&sandbox_id(), &cfg, &Ambient::empty()).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("capability"), "{}", err.message);
    }

    #[test]
    fn a_capability_with_crlf_is_refused_before_the_dial() {
        let cfg = W365ExecConfig {
            dp_suffix: Some("dp.example.net".into()),
            capability: Some("x\r\nX-Injected: 1".into()),
            bearer_token: Some(Redacted::new("T")),
            port: None,
        };
        let err = super::derive_target(&sandbox_id(), &cfg, &Ambient::empty()).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("capability"), "{}", err.message);
    }

    #[test]
    fn a_blank_explicit_dp_token_cannot_unlock_a_caller_chosen_suffix() {
        // Same bypass on the data plane: `bearerToken: ""` must not unlock a
        // caller-chosen dpSuffix while the operator's W365A_DP_TOKEN is used.
        let ambient = Ambient {
            dp_suffix: Some("trusted.example.net".to_string()),
            dp_token: Some(Redacted::new("OPERATOR_TOKEN")),
            ..Ambient::empty()
        };
        let cfg = W365ExecConfig {
            dp_suffix: Some("evil.example".into()),
            capability: None,
            bearer_token: Some(Redacted::new("")),
            port: None,
        };
        let err = super::derive_target(&sandbox_id(), &cfg, &ambient)
            .expect_err("a blank token must not unlock a caller-chosen suffix");
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("dpSuffix"), "{}", err.message);
    }

    #[test]
    fn a_caller_supplied_dp_suffix_cannot_redirect_an_ambient_token() {
        // Same exfiltration primitive as the control plane: the operator's
        // W365A_DP_TOKEN must not be dialled at a caller-chosen host.
        let ambient = Ambient {
            dp_suffix: Some("trusted.example.net".to_string()),
            dp_token: Some(Redacted::new("OPERATOR_TOKEN")),
            ..Ambient::empty()
        };
        let cfg = W365ExecConfig {
            dp_suffix: Some("evil.example".into()),
            capability: None,
            bearer_token: None,
            port: None,
        };
        let err = super::derive_target(&sandbox_id(), &cfg, &ambient).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("dpSuffix"), "{}", err.message);
        assert!(
            err.message.contains("caller-chosen host"),
            "{}",
            err.message
        );
    }

    #[test]
    fn exec_requires_dataplane_coordinates_from_config_or_ambient() {
        let empty = W365ExecConfig {
            dp_suffix: None,
            capability: None,
            bearer_token: None,
            port: None,
        };
        let err = super::derive_target(&sandbox_id(), &empty, &Ambient::empty()).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("W365A_DP_SUFFIX"));
    }

    #[test]
    fn ambient_coordinates_are_used_when_the_config_omits_them() {
        let ambient = Ambient {
            dp_suffix: Some("ambient.example.net".to_string()),
            dp_token: Some(Redacted::new("AMBIENT_TOKEN")),
            ..Ambient::empty()
        };
        let empty = W365ExecConfig {
            dp_suffix: None,
            capability: None,
            bearer_token: None,
            port: None,
        };
        let target = super::derive_target(&sandbox_id(), &empty, &ambient).unwrap();
        assert_eq!(target.host, format!("{POOL}.ambient.example.net"));
    }

    #[test]
    fn build_start_maps_execution_request_fields() {
        // Struct-update form (not `let mut … = default(); field = …`) to satisfy
        // clippy::field_reassign_with_default under `-D warnings`.
        let request = ExecutionRequest {
            script_code: "whoami".to_string(),
            working_directory: "C:\\Windows".to_string(),
            env: Some(vec!["A=1".to_string()]),
            script_timeout: 5000,
            ..Default::default()
        };
        let start = build_start(&request);
        assert_eq!(start.command_line, "whoami");
        assert_eq!(start.working_directory, "C:\\Windows");
        assert_eq!(start.env, vec!["A=1".to_string()]);
        assert_eq!(start.timeout_ms, 5000);
    }

    #[test]
    fn the_honor_matrix_rejects_any_supplied_policy() {
        let mut request = ExecutionRequest::default();
        assert!(
            honor_matrix_check(&request).is_ok(),
            "a default policy is fine"
        );

        request.policy.readonly_paths = vec!["C:\\secret".to_string()];
        let err = honor_matrix_check(&request).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("does not honor"));

        // Presence flags skipped by serde (`ui_specified`, `network_specified`)
        // must also be caught even when the inner values match `Default`.
        let mut ui_req = ExecutionRequest::default();
        ui_req.policy.ui_specified = true;
        assert_eq!(
            honor_matrix_check(&ui_req).unwrap_err().code.as_str(),
            "policy_validation"
        );

        let mut net_req = ExecutionRequest::default();
        net_req.policy.network_specified = true;
        assert_eq!(
            honor_matrix_check(&net_req).unwrap_err().code.as_str(),
            "policy_validation"
        );
    }

    #[test]
    fn exec_rejects_piped_stdio_before_coordinate_resolution() {
        let mut runner = W365AgentsRunner::new();
        let request = ExecutionRequest::default();
        let err = runner
            .exec(
                "not-even-parsed",
                &request,
                None,
                crate::mxc_common::state_aware_backend::ExecStdio::Piped,
            )
            .unwrap_err();
        assert_eq!(err.code.as_str(), "backend_error");
        assert!(
            err.message
                .contains("the W365 Agents backend cannot return exec streams to the caller"),
            "unexpected message: {}",
            err.message
        );
    }

    #[test]
    fn validate_hooks_reject_a_bad_id_before_any_network_call() {
        let runner = W365AgentsRunner::new();
        let request = ExecutionRequest::default();
        let bad = format!("w365:{POOL}.{C}");
        assert_eq!(
            runner
                .validate_start(&bad, &request, None)
                .unwrap_err()
                .code
                .as_str(),
            "malformed_id"
        );
        assert_eq!(
            runner
                .validate_stop(&bad, &request, None)
                .unwrap_err()
                .code
                .as_str(),
            "malformed_id"
        );
        assert_eq!(
            runner
                .validate_deprovision(&bad, &request, None)
                .unwrap_err()
                .code
                .as_str(),
            "malformed_id"
        );
    }

    #[test]
    fn validate_provision_enforces_the_agentic_co_requirement() {
        let runner = W365AgentsRunner::new();
        let request = ExecutionRequest::default();
        let cfg: crate::w365agents_common::config::ProvisionConfig = serde_json::from_str(
            r#"{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9","agentUserToken":"AUX"}"#,
        )
        .unwrap();
        let err = runner.validate_provision(&request, Some(&cfg)).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("userObjectId"));
    }

    #[test]
    fn validate_provision_rejects_a_non_guid_pool_id_before_any_network_call() {
        // Regression: poolId was never validated, so provision could mint
        // w365:{non-GUID}:{GUID} — an id its own parser rejects. The Cloud PC
        // was then checked out and BILLING, but stop/deprovision parse the id
        // first, so it could never be released. A poolId containing CRLF also
        // spliced straight into the SessionManagement request line.
        let runner = W365AgentsRunner::new();
        let request = ExecutionRequest::default();
        for bad_pool in ["not-a-guid", "a\\r\\nX-Injected: 1", "../../etc", ""] {
            let cfg: crate::w365agents_common::config::ProvisionConfig =
                serde_json::from_str(&format!(r#"{{"poolId":"{bad_pool}"}}"#)).unwrap();
            let err = runner.validate_provision(&request, Some(&cfg)).unwrap_err();
            assert_eq!(err.code.as_str(), "policy_validation", "pool={bad_pool}");
            assert!(err.message.contains("poolId"), "pool={bad_pool}");
        }
    }

    #[test]
    fn provision_requires_its_config() {
        let mut runner = W365AgentsRunner::new();
        let request = ExecutionRequest::default();
        let err = runner.provision(&request, None).unwrap_err();
        assert_eq!(err.code.as_str(), "policy_validation");
        assert!(err.message.contains("w365Agents.provision"));
        let dry_err = runner.validate_provision(&request, None).unwrap_err();
        assert_eq!(dry_err.code.as_str(), "policy_validation");
    }

    #[test]
    fn validate_hooks_enforce_phase_config_and_exec_start_size() {
        let runner = W365AgentsRunner::new();
        let id = sandbox_id();
        let request = ExecutionRequest::default();

        // Bad capability is rejected during dry-run validate_exec.
        let bad_cap = W365ExecConfig {
            capability: Some("../bad".to_string()),
            ..Default::default()
        };
        assert_eq!(
            runner
                .validate_exec(&id, &request, Some(&bad_cap))
                .unwrap_err()
                .code
                .as_str(),
            "policy_validation"
        );

        // Oversized EXEC_START (> 64 KiB) is rejected during validate_exec.
        let huge_request = ExecutionRequest {
            script_code: "x".repeat(70 * 1024),
            ..Default::default()
        };
        assert_eq!(
            runner
                .validate_exec(&id, &huge_request, None)
                .unwrap_err()
                .code
                .as_str(),
            "backend_error"
        );
    }
}

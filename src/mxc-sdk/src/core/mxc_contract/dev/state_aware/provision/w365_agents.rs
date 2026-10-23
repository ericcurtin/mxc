// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exact `1.1.0-alpha` contract types for the `w365_agents` state-aware backend.

use crate::mxc_contract::dev::state_aware::provision::ProvisionPhase;
use crate::mxc_contract::dev::{OptionalField, Telemetry, Version};
use serde::Deserialize;

fn debug_redacted_opt(value: &OptionalField<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

string_marker! {
    /// The `w365_agents` containment of the state-aware configuration contract.
    pub struct W365AgentsContainment => "w365_agents";
}

/// W365 Agents settings accepted during provisioning.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W365AgentsProvision {
    /// Target pool GUID.
    pub pool_id: String,
    /// Optional auxiliary bearer token for agentic user sessions.
    #[serde(default)]
    pub agent_user_token: OptionalField<String>,
    /// Optional Entra user object ID (required when `agentUserToken` is supplied).
    #[serde(default)]
    pub user_object_id: OptionalField<String>,
    /// Optional session kind (`Local`, `HumanUser`, or `Agentic`).
    #[serde(default)]
    pub user_type: OptionalField<String>,
    /// Optional checkout timeout in milliseconds.
    #[serde(default)]
    pub provision_timeout_ms: OptionalField<u64>,
    /// Optional SessionManagement control-plane host override.
    #[serde(default)]
    pub cp_base_url: OptionalField<String>,
    /// Optional SessionManagement control-plane bearer token.
    #[serde(default)]
    pub cp_bearer_token: OptionalField<String>,
    /// Optional SessionManagement API version override.
    #[serde(default)]
    pub cp_api_version: OptionalField<String>,
    /// Optional TLS port override.
    #[serde(default)]
    pub port: OptionalField<u16>,
}

impl std::fmt::Debug for W365AgentsProvision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("W365AgentsProvision")
            .field("pool_id", &self.pool_id)
            .field(
                "agent_user_token",
                &debug_redacted_opt(&self.agent_user_token),
            )
            .field("user_object_id", &self.user_object_id)
            .field("user_type", &self.user_type)
            .field("provision_timeout_ms", &self.provision_timeout_ms)
            .field("cp_base_url", &self.cp_base_url)
            .field(
                "cp_bearer_token",
                &debug_redacted_opt(&self.cp_bearer_token),
            )
            .field("cp_api_version", &self.cp_api_version)
            .field("port", &self.port)
            .finish()
    }
}

/// State-aware W365 Agents provision wrapper.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareW365Agents {
    /// Optional provision-phase settings.
    #[serde(default)]
    pub provision: OptionalField<W365AgentsProvision>,
}

/// W365 Agents settings accepted during the `start` phase.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W365AgentsStart {
    /// Optional readiness timeout in milliseconds.
    #[serde(default)]
    pub ready_timeout_ms: OptionalField<u64>,
    /// Optional status poll interval in milliseconds.
    #[serde(default)]
    pub poll_interval_ms: OptionalField<u64>,
    /// Optional RemotingInterface data-plane DNS suffix override.
    #[serde(default)]
    pub dp_suffix: OptionalField<String>,
    /// Optional RemotingInterface data-plane bearer token.
    #[serde(default)]
    pub dp_bearer_token: OptionalField<String>,
    /// Optional RemotingInterface API version override.
    #[serde(default)]
    pub dp_api_version: OptionalField<String>,
    /// Optional TLS port override.
    #[serde(default)]
    pub port: OptionalField<u16>,
}

impl std::fmt::Debug for W365AgentsStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("W365AgentsStart")
            .field("ready_timeout_ms", &self.ready_timeout_ms)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("dp_suffix", &self.dp_suffix)
            .field(
                "dp_bearer_token",
                &debug_redacted_opt(&self.dp_bearer_token),
            )
            .field("dp_api_version", &self.dp_api_version)
            .field("port", &self.port)
            .finish()
    }
}

/// State-aware W365 Agents `start` wrapper.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareW365AgentsStart {
    /// Optional start-phase settings.
    #[serde(default)]
    pub start: OptionalField<W365AgentsStart>,
}

/// W365 Agents settings accepted during the `exec` phase.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W365AgentsExec {
    /// Optional RemotingInterface data-plane DNS suffix override.
    #[serde(default)]
    pub dp_suffix: OptionalField<String>,
    /// Optional reverse-DNS capability name override.
    #[serde(default)]
    pub capability: OptionalField<String>,
    /// Optional RemotingInterface data-plane bearer token.
    #[serde(default)]
    pub bearer_token: OptionalField<String>,
    /// Optional TLS port override.
    #[serde(default)]
    pub port: OptionalField<u16>,
}

impl std::fmt::Debug for W365AgentsExec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("W365AgentsExec")
            .field("dp_suffix", &self.dp_suffix)
            .field("capability", &self.capability)
            .field("bearer_token", &debug_redacted_opt(&self.bearer_token))
            .field("port", &self.port)
            .finish()
    }
}

/// State-aware W365 Agents `exec` wrapper.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareW365AgentsExec {
    /// Optional exec-phase settings.
    #[serde(default)]
    pub exec: OptionalField<W365AgentsExec>,
}

/// W365 Agents settings accepted during the `stop` and `deprovision` phases.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W365AgentsStop {
    /// Optional SessionManagement control-plane host override.
    #[serde(default)]
    pub cp_base_url: OptionalField<String>,
    /// Optional SessionManagement control-plane bearer token.
    #[serde(default)]
    pub cp_bearer_token: OptionalField<String>,
    /// Optional SessionManagement API version override.
    #[serde(default)]
    pub cp_api_version: OptionalField<String>,
    /// Optional TLS port override.
    #[serde(default)]
    pub port: OptionalField<u16>,
}

impl std::fmt::Debug for W365AgentsStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("W365AgentsStop")
            .field("cp_base_url", &self.cp_base_url)
            .field(
                "cp_bearer_token",
                &debug_redacted_opt(&self.cp_bearer_token),
            )
            .field("cp_api_version", &self.cp_api_version)
            .field("port", &self.port)
            .finish()
    }
}

/// State-aware W365 Agents `stop` wrapper.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareW365AgentsStop {
    /// Optional stop-phase settings.
    #[serde(default)]
    pub stop: OptionalField<W365AgentsStop>,
}

/// State-aware W365 Agents `deprovision` wrapper.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareW365AgentsDeprovision {
    /// Optional deprovision-phase settings.
    #[serde(default)]
    pub deprovision: OptionalField<W365AgentsStop>,
}

/// A complete state-aware `provision` request for `w365_agents`.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W365AgentsProvisionRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    pub version: Version,
    /// Exact `provision` phase marker.
    pub phase: ProvisionPhase,
    /// Exact `w365_agents` containment marker.
    pub containment: W365AgentsContainment,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Optional W365 Agents provision settings.
    #[serde(default)]
    pub w365_agents: OptionalField<StateAwareW365Agents>,
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::config_contract_adapters::dev::common::{
    convert_filesystem, convert_network, convert_process, convert_runtime_config, convert_telemetry,
};
use crate::mxc_common::error::WxcError;
use crate::mxc_common::models::{
    IsolationSessionProvisionConfig, Redacted, W365ExecConfig, W365ProvisionConfig,
    W365StartConfig, W365StopConfig, WslcProvisionConfig, WslcProvisionSessionConfig,
};
use crate::mxc_common::state_aware_input::StateAwareInput;
use crate::mxc_common::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::mxc_common::wire;
use crate::mxc_contract::dev as contract;

fn convert_state_aware_isolation_session(
    value: contract::StateAwareIsolationSession,
) -> Option<IsolationSessionProvisionConfig> {
    let contract::StateAwareIsolationSession { provision } = value;
    provision
        .into_option()
        .map(convert_isolation_session_provision)
}

fn convert_isolation_session_provision(
    value: contract::IsolationSessionProvision,
) -> IsolationSessionProvisionConfig {
    let contract::IsolationSessionProvision { app_id } = value;
    IsolationSessionProvisionConfig {
        app_id: app_id.into_option(),
    }
}

fn convert_isolation_session_network(value: contract::IsolationSessionNetwork) -> wire::Network {
    let contract::IsolationSessionNetwork { egress, ingress } = value;
    let contract::IsolationSessionNetworkEgress {
        default: contract::IsolationSessionNetworkAllow,
    } = egress;
    let contract::IsolationSessionNetworkIngress {
        default: contract::IsolationSessionNetworkAllow,
        host_loopback: contract::IsolationSessionNetworkAllow,
    } = ingress;
    wire::Network {
        egress: Some(wire::NetworkEgress {
            default: Some(wire::NetworkAction::Allow),
            allow: None,
            deny: None,
        }),
        ingress: Some(wire::NetworkIngress {
            default: Some(wire::NetworkAction::Allow),
            host_loopback: Some(wire::NetworkAction::Allow),
        }),
    }
}

fn convert_wslc_port_mapping(
    value: contract::PortMapping,
) -> crate::mxc_common::models::PortMapping {
    let contract::PortMapping {
        windows_port,
        container_port,
        protocol,
    } = value;
    crate::mxc_common::models::PortMapping {
        windows_port: windows_port.get(),
        container_port: container_port.get(),
        protocol: match protocol.into_option() {
            Some(contract::TransportProtocol::Tcp) | None => "tcp".to_string(),
        },
    }
}

fn convert_wslc_provision(value: contract::WslcProvision) -> WslcProvisionConfig {
    let contract::WslcProvision {
        image,
        image_tar_path,
        session_id,
        port_mappings,
    } = value;
    WslcProvisionConfig {
        image: image.into_option(),
        image_tar_path: image_tar_path.into_option(),
        session_id: session_id.into_option(),
        port_mappings: port_mappings.into_option().map(|mappings| {
            mappings
                .into_iter()
                .map(convert_wslc_port_mapping)
                .collect()
        }),
    }
}

fn convert_state_aware_wslc(value: contract::StateAwareWslc) -> Option<WslcProvisionConfig> {
    let contract::StateAwareWslc { provision } = value;
    provision.into_option().map(convert_wslc_provision)
}

fn convert_wslc_provision_session(
    value: contract::WslcProvisionSession,
) -> WslcProvisionSessionConfig {
    let contract::WslcProvisionSession {
        cpu_count,
        memory_mb,
        gpu,
    } = value;
    WslcProvisionSessionConfig {
        cpu_count: cpu_count.into_option(),
        memory_mb: memory_mb.into_option(),
        gpu: gpu.into_option(),
    }
}

fn convert_state_aware_wslc_session(
    value: contract::StateAwareWslcSession,
) -> Option<WslcProvisionSessionConfig> {
    let contract::StateAwareWslcSession { provision_session } = value;
    provision_session
        .into_option()
        .map(convert_wslc_provision_session)
}

fn convert_w365_provision(value: contract::W365AgentsProvision) -> W365ProvisionConfig {
    let contract::W365AgentsProvision {
        pool_id,
        agent_user_token,
        user_object_id,
        user_type,
        provision_timeout_ms,
        cp_base_url,
        cp_bearer_token,
        cp_api_version,
        port,
    } = value;
    W365ProvisionConfig {
        pool_id,
        agent_user_token: agent_user_token.into_option().map(Redacted::new),
        user_object_id: user_object_id.into_option(),
        user_type: user_type.into_option(),
        provision_timeout_ms: provision_timeout_ms.into_option(),
        cp_base_url: cp_base_url.into_option(),
        cp_bearer_token: cp_bearer_token.into_option().map(Redacted::new),
        cp_api_version: cp_api_version.into_option(),
        port: port.into_option(),
    }
}

fn convert_state_aware_w365_provision(
    value: contract::StateAwareW365Agents,
) -> Option<W365ProvisionConfig> {
    let contract::StateAwareW365Agents { provision } = value;
    provision.into_option().map(convert_w365_provision)
}

fn convert_w365_start(value: contract::W365AgentsStart) -> W365StartConfig {
    let contract::W365AgentsStart {
        ready_timeout_ms,
        poll_interval_ms,
        dp_suffix,
        dp_bearer_token,
        dp_api_version,
        port,
    } = value;
    W365StartConfig {
        ready_timeout_ms: ready_timeout_ms.into_option(),
        poll_interval_ms: poll_interval_ms.into_option(),
        dp_suffix: dp_suffix.into_option(),
        dp_bearer_token: dp_bearer_token.into_option().map(Redacted::new),
        dp_api_version: dp_api_version.into_option(),
        port: port.into_option(),
    }
}

fn convert_state_aware_w365_start(value: contract::StateAwareW365AgentsStart) -> W365StartConfig {
    let contract::StateAwareW365AgentsStart { start } = value;
    start
        .into_option()
        .map_or_else(W365StartConfig::default, convert_w365_start)
}

fn convert_w365_exec(value: contract::W365AgentsExec) -> W365ExecConfig {
    let contract::W365AgentsExec {
        dp_suffix,
        capability,
        bearer_token,
        port,
    } = value;
    W365ExecConfig {
        dp_suffix: dp_suffix.into_option(),
        capability: capability.into_option(),
        bearer_token: bearer_token.into_option().map(Redacted::new),
        port: port.into_option(),
    }
}

fn convert_state_aware_w365_exec(value: contract::StateAwareW365AgentsExec) -> W365ExecConfig {
    let contract::StateAwareW365AgentsExec { exec } = value;
    exec.into_option()
        .map_or_else(W365ExecConfig::default, convert_w365_exec)
}

fn convert_w365_stop(value: contract::W365AgentsStop) -> W365StopConfig {
    let contract::W365AgentsStop {
        cp_base_url,
        cp_bearer_token,
        cp_api_version,
        port,
    } = value;
    W365StopConfig {
        cp_base_url: cp_base_url.into_option(),
        cp_bearer_token: cp_bearer_token.into_option().map(Redacted::new),
        cp_api_version: cp_api_version.into_option(),
        port: port.into_option(),
    }
}

fn convert_state_aware_w365_stop(value: contract::StateAwareW365AgentsStop) -> W365StopConfig {
    let contract::StateAwareW365AgentsStop { stop } = value;
    stop.into_option()
        .map_or_else(W365StopConfig::default, convert_w365_stop)
}

fn convert_state_aware_w365_deprovision(
    value: contract::StateAwareW365AgentsDeprovision,
) -> W365StopConfig {
    let contract::StateAwareW365AgentsDeprovision { deprovision } = value;
    deprovision
        .into_option()
        .map_or_else(W365StopConfig::default, convert_w365_stop)
}

fn state_aware_common(
    schema: contract::OptionalField<String>,
    comment: contract::OptionalField<serde_json::Value>,
    _version: contract::Version,
    telemetry: contract::OptionalField<contract::Telemetry>,
) -> crate::mxc_common::common_request_ir::CommonRequestIR {
    crate::mxc_common::common_request_ir::CommonRequestIR {
        schema: schema.into_option(),
        comment: comment.into_option(),
        source_contract: crate::mxc_contract::ContractVersion::V1_1_0Alpha,
        phase: None,
        test_feature: None,
        windows_sandbox: None,
        containment: None,
        container_id: None,
        sandbox_id: None,
        process: None,
        filesystem: None,
        network: None,
        runtime_config: None,
        telemetry: telemetry.into_option().map(convert_telemetry),
        lifecycle: None,
        lxc: None,
        wslc: None,
        process_container: None,
        seatbelt: None,
        ui: None,
        hyperlight: None,
    }
}

pub(super) fn provision_session_into_input(
    request: contract::WslcProvisionSessionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::WslcProvisionSessionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionSessionPhase,
        containment: contract::WslcContainment,
        telemetry,
        wslc,
    } = request;
    let sizing = wslc
        .into_option()
        .and_then(convert_state_aware_wslc_session);
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(common, StateAwareOperation::ProvisionSession(sizing))
}

pub(super) fn provision_into_input(
    request: contract::ProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    match request {
        contract::ProvisionRequest::IsolationSession(request) => {
            isolation_session_provision_into_input(request)
        }
        contract::ProvisionRequest::WindowsSandbox(request) => {
            windows_sandbox_provision_into_input(request)
        }
        contract::ProvisionRequest::Wslc(request) => wslc_provision_into_input(request),
        contract::ProvisionRequest::W365Agents(request) => {
            w365_agents_provision_into_input(request)
        }
    }
}

fn isolation_session_provision_into_input(
    request: contract::IsolationSessionProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::IsolationSessionProvisionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionPhase,
        containment: contract::IsolationSessionContainment,
        network,
        telemetry,
        isolation_session,
    } = request;
    let provision = isolation_session
        .into_option()
        .and_then(convert_state_aware_isolation_session);
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.network = Some(convert_isolation_session_network(network));
    StateAwareInput::new(
        common,
        StateAwareOperation::Provision(StateAwareProvision::IsolationSession(provision)),
    )
}

fn windows_sandbox_provision_into_input(
    request: contract::WindowsSandboxProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::WindowsSandboxProvisionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionPhase,
        containment: contract::WindowsSandboxContainment,
        filesystem,
        telemetry,
    } = request;
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.filesystem = filesystem.into_option().map(convert_filesystem);
    StateAwareInput::new(
        common,
        StateAwareOperation::Provision(StateAwareProvision::WindowsSandbox),
    )
}

fn wslc_provision_into_input(
    request: contract::WslcProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::WslcProvisionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionPhase,
        containment: contract::WslcContainment,
        filesystem,
        network,
        telemetry,
        wslc,
    } = request;
    let provision = wslc.into_option().and_then(convert_state_aware_wslc);
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.filesystem = filesystem.into_option().map(convert_filesystem);
    common.network = network.into_option().map(convert_network);
    StateAwareInput::new(
        common,
        StateAwareOperation::Provision(StateAwareProvision::Wslc(provision)),
    )
}

fn w365_agents_provision_into_input(
    request: contract::W365AgentsProvisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::W365AgentsProvisionRequest {
        schema,
        comment,
        version,
        phase: contract::ProvisionPhase,
        containment: contract::W365AgentsContainment,
        telemetry,
        w365_agents,
    } = request;
    let provision = w365_agents
        .into_option()
        .and_then(convert_state_aware_w365_provision);
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(
        common,
        StateAwareOperation::Provision(StateAwareProvision::W365Agents(provision)),
    )
}

pub(super) fn start_into_input(
    request: contract::StartRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::StartRequest {
        schema,
        comment,
        version,
        phase: contract::StartPhase,
        sandbox_id,
        telemetry,
        w365_agents,
    } = request;
    let w365_agents = w365_agents
        .into_option()
        .map(convert_state_aware_w365_start);
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(
        common,
        StateAwareOperation::Start {
            sandbox_id,
            w365_agents,
        },
    )
}

pub(super) fn exec_into_input(request: contract::ExecRequest) -> Result<StateAwareInput, WxcError> {
    let contract::ExecRequest {
        schema,
        comment,
        version,
        phase: contract::ExecPhase,
        sandbox_id,
        process,
        network,
        runtime_config,
        telemetry,
        w365_agents,
    } = request;
    let w365_agents = w365_agents.into_option().map(convert_state_aware_w365_exec);
    let mut common = state_aware_common(schema, comment, version, telemetry);
    common.process = Some(convert_process(process));
    common.network = network.into_option().map(convert_network);
    common.runtime_config = runtime_config.into_option().map(convert_runtime_config);
    StateAwareInput::new(
        common,
        StateAwareOperation::Exec {
            sandbox_id,
            w365_agents,
        },
    )
}

pub(super) fn stop_into_input(request: contract::StopRequest) -> Result<StateAwareInput, WxcError> {
    let contract::StopRequest {
        schema,
        comment,
        version,
        phase: contract::StopPhase,
        sandbox_id,
        telemetry,
        w365_agents,
    } = request;
    let w365_agents = w365_agents.into_option().map(convert_state_aware_w365_stop);
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(
        common,
        StateAwareOperation::Stop {
            sandbox_id,
            w365_agents,
        },
    )
}

pub(super) fn deprovision_into_input(
    request: contract::DeprovisionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::DeprovisionRequest {
        schema,
        comment,
        version,
        phase: contract::DeprovisionPhase,
        sandbox_id,
        telemetry,
        w365_agents,
    } = request;
    let w365_agents = w365_agents
        .into_option()
        .map(convert_state_aware_w365_deprovision);
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(
        common,
        StateAwareOperation::Deprovision {
            sandbox_id,
            w365_agents,
        },
    )
}

pub(super) fn deprovision_session_into_input(
    request: contract::WslcDeprovisionSessionRequest,
) -> Result<StateAwareInput, WxcError> {
    let contract::WslcDeprovisionSessionRequest {
        schema,
        comment,
        version,
        phase: contract::DeprovisionSessionPhase,
        containment: contract::WslcContainment,
        session_id,
        telemetry,
    } = request;
    let common = state_aware_common(schema, comment, version, telemetry);
    StateAwareInput::new(
        common,
        StateAwareOperation::DeprovisionSession { session_id },
    )
}

#[cfg(test)]
#[path = "state_aware_tests/mod.rs"]
mod tests;

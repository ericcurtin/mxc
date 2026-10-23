// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mxc_common::config_parser::load_mxc_request_from_json;
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::PortMapping;
use crate::mxc_common::mxc_error::MxcErrorCode;
use crate::mxc_common::state_aware_backend::{
    null_pipe_handle, DeprovisionResult, ExecHandle, ExecOutcome, ExecStdio, ProvisionResult,
    StartResult, StopResult,
};
use crate::mxc_common::state_aware_dispatch::{
    dispatch_state_aware, dispatch_state_aware_exec, DispatchOutcome,
};
use crate::mxc_common::state_aware_request::MxcRequest;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Config {
    Absent,
    Unit,
    Isolation(Option<String>),
    Wslc(Option<String>, Option<String>, Option<Vec<PortMapping>>),
    WslcSession(Option<u32>, Option<u64>, Option<bool>),
}

trait Case: Sized {
    type ProvisionConfig;
    const BACKEND: &'static str;
    const PREFIX: &'static str;
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config;
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError>;
}

struct Isolation;
struct WindowsSandbox;
struct Wslc;

impl Case for Isolation {
    type ProvisionConfig = IsolationSessionProvisionConfig;
    const BACKEND: &'static str = "isolation_session";
    const PREFIX: &'static str = "iso";
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config {
        config.map_or(Config::Absent, |config| {
            Config::Isolation(config.app_id.clone())
        })
    }
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError> {
        bind_isolation_session(parsed)
    }
}

impl Case for WindowsSandbox {
    type ProvisionConfig = ();
    const BACKEND: &'static str = "windows_sandbox";
    const PREFIX: &'static str = "wsb";
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config {
        config.map_or(Config::Absent, |_| Config::Unit)
    }
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError> {
        bind_windows_sandbox(parsed)
    }
}

impl Case for Wslc {
    type ProvisionConfig = WslcProvisionConfig;
    const BACKEND: &'static str = "wslc";
    const PREFIX: &'static str = "wslc";
    fn observe(config: Option<&Self::ProvisionConfig>) -> Config {
        config.map_or(Config::Absent, |config| {
            Config::Wslc(
                config.image.clone(),
                config.image_tar_path.clone(),
                config.port_mappings.clone(),
            )
        })
    }
    fn bind(
        parsed: ParsedStateAwareRequest,
    ) -> Result<BoundStateAwareRequest<Recording<Self>>, MxcError> {
        bind_wslc(parsed)
    }
}

#[derive(Debug, PartialEq)]
struct Event {
    validation: bool,
    phase: Phase,
    id: Option<String>,
    common: Value,
    config: Config,
    stdio: Option<ExecStdio>,
}

fn common_snapshot(request: &ExecutionRequest) -> Value {
    let proxy = request.policy.network_proxy.address.as_ref();
    json!({
        "serialized": request,
        "networkSpecified": request.policy.network_specified,
        "networkModeSpecified": request.policy.network_mode_specified,
        "runtimeProxySpecified": request.policy.runtime_network_proxy_specified,
        "uiSpecified": request.policy.ui_specified,
        "proxyAddress": proxy.map(|address| &address.address),
        "proxyPort": proxy.map(|address| address.port),
        "proxyUrl": proxy.and_then(|address| address.original_url.as_ref()),
        "telemetryKind": request.telemetry.as_ref().and_then(|value| value.requested_sandbox_kind),
    })
}

struct Recording<C> {
    events: RefCell<Vec<Event>>,
    reject_validation: bool,
    case: PhantomData<C>,
}

impl<C> Recording<C> {
    fn new(reject_validation: bool) -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            reject_validation,
            case: PhantomData,
        }
    }

    fn observe(
        &self,
        validation: bool,
        phase: Phase,
        id: Option<&str>,
        request: &ExecutionRequest,
        config: Config,
        stdio: Option<ExecStdio>,
    ) -> Result<(), MxcError> {
        self.events.borrow_mut().push(Event {
            validation,
            phase,
            id: id.map(str::to_owned),
            common: common_snapshot(request),
            config,
            stdio,
        });
        if validation && self.reject_validation {
            return Err(MxcError::policy_validation("recorded validation refusal"));
        }
        Ok(())
    }
}

impl<C: Case> StatefulSandboxBackend for Recording<C> {
    const ID_PREFIX: &'static str = C::PREFIX;
    const BACKEND_KEY: &'static str = C::BACKEND;
    type ProvisionConfig = C::ProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = ();
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        self.observe(
            true,
            Phase::Provision,
            None,
            request,
            C::observe(config),
            None,
        )
    }
    fn validate_provision_session(
        &self,
        request: &ExecutionRequest,
        config: Option<&WslcProvisionSessionConfig>,
    ) -> Result<(), MxcError> {
        self.observe(
            true,
            Phase::ProvisionSession,
            None,
            request,
            observe_session(config),
            None,
        )
    }
    fn validate_deprovision_session(
        &self,
        session_id: &str,
        request: &ExecutionRequest,
    ) -> Result<(), MxcError> {
        self.observe(
            true,
            Phase::DeprovisionSession,
            Some(session_id),
            request,
            Config::Absent,
            None,
        )
    }
    fn validate_start(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(true, Phase::Start, Some(id), request, unit(config), None)
    }
    fn validate_exec(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(true, Phase::Exec, Some(id), request, unit(config), None)
    }
    fn validate_stop(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(true, Phase::Stop, Some(id), request, unit(config), None)
    }
    fn validate_deprovision(
        &self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<&()>,
    ) -> Result<(), MxcError> {
        self.observe(
            true,
            Phase::Deprovision,
            Some(id),
            request,
            unit(config),
            None,
        )
    }
    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Provision,
            None,
            request,
            C::observe(config.as_ref()),
            None,
        )?;
        Ok(ProvisionResult {
            sandbox_id: format!("{}:created", C::PREFIX),
            metadata: None,
        })
    }
    fn provision_session(
        &mut self,
        request: &ExecutionRequest,
        config: Option<WslcProvisionSessionConfig>,
    ) -> Result<crate::mxc_common::state_aware_backend::ProvisionSessionResult, MxcError> {
        self.observe(
            false,
            Phase::ProvisionSession,
            None,
            request,
            observe_session(config.as_ref()),
            None,
        )?;
        Ok(
            crate::mxc_common::state_aware_backend::ProvisionSessionResult {
                session_id: "wslcsess:created".to_string(),
            },
        )
    }
    fn deprovision_session(
        &mut self,
        session_id: &str,
        request: &ExecutionRequest,
    ) -> Result<(), MxcError> {
        self.observe(
            false,
            Phase::DeprovisionSession,
            Some(session_id),
            request,
            Config::Absent,
            None,
        )
    }
    fn start(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Start,
            Some(id),
            request,
            unit(config.as_ref()),
            None,
        )?;
        Ok(StartResult { metadata: None })
    }
    fn exec(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        self.observe(
            false,
            Phase::Exec,
            Some(id),
            request,
            unit(config.as_ref()),
            Some(stdio),
        )?;
        Ok(ExecHandle {
            stdin: null_pipe_handle(),
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            waiter: Box::new(|| Ok(ExecOutcome::Exited(7))),
            terminator: Box::new(|| Ok(())),
            stdin_closer: None,
        })
    }
    fn stop(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Stop,
            Some(id),
            request,
            unit(config.as_ref()),
            None,
        )?;
        Ok(StopResult { metadata: None })
    }
    fn deprovision(
        &mut self,
        id: &str,
        request: &ExecutionRequest,
        config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        self.observe(
            false,
            Phase::Deprovision,
            Some(id),
            request,
            unit(config.as_ref()),
            None,
        )?;
        Ok(DeprovisionResult { metadata: None })
    }
}

fn unit(config: Option<&()>) -> Config {
    config.map_or(Config::Absent, |_| Config::Unit)
}

fn observe_session(config: Option<&WslcProvisionSessionConfig>) -> Config {
    config.map_or(Config::Absent, |config| {
        Config::WslcSession(config.cpu_count, config.memory_mb, config.gpu)
    })
}

fn input<C: Case>(phase: Phase) -> Value {
    let mut value = json!({
        "version": if C::BACKEND == "isolation_session" {
            "0.9.0-alpha"
        } else {
            "1.1.0-alpha"
        },
        "phase": phase.as_str(),
        "telemetry": {"enabled": false},
    });
    if phase == Phase::Provision {
        value["containment"] = json!(C::BACKEND);
        if C::BACKEND == "isolation_session" {
            value["network"] = json!({
                "egress": {"default": "allow"},
                "ingress": {"default": "allow", "hostLoopback": "allow"}
            });
        }
    } else {
        value["sandboxId"] = json!(format!("{}:test-id", C::PREFIX));
        if phase == Phase::Exec {
            value["process"] = json!({
                "commandLine": "echo typed",
                "env": ["TYPED_BINDING=preserved"],
                "timeout": 7,
            });
        }
    }
    value
}

fn parse(input: &Value) -> ParsedStateAwareRequest {
    let parsed =
        load_mxc_request_from_json(&input.to_string(), &mut Logger::new(Mode::Buffer)).unwrap();
    let MxcRequest::StateAware(parsed) = parsed else {
        panic!("expected lifecycle request");
    };
    parsed
}

fn assert_dispatch<C: Case>(input: &Value, expected_config: Config) {
    assert_dispatch_parsed::<C>(|| parse(input), expected_config);
}

/// Drive one request through the validation / execution / dry-run matrix.
///
/// Takes a builder rather than a JSON value because session phases have no
/// JSON form to parse.
fn assert_dispatch_parsed<C: Case>(
    build: impl Fn() -> ParsedStateAwareRequest,
    expected_config: Config,
) {
    for (dry_run, reject_validation) in [(false, false), (true, false), (false, true)] {
        let parsed = build();
        let phase = parsed.phase();
        let id = parsed
            .sandbox_id()
            .or_else(|| parsed.session_id())
            .map(str::to_owned);
        let common = common_snapshot(parsed.request());
        let bound = C::bind(parsed).unwrap();
        assert_eq!(bound.phase(), phase);
        assert_eq!(
            bound.sandbox_id().or_else(|| bound.session_id()),
            id.as_deref()
        );
        assert_eq!(common_snapshot(bound.request()), common);
        let mut backend = Recording::<C>::new(reject_validation);
        let outcome = dispatch_state_aware(&mut backend, bound, dry_run);
        if reject_validation {
            let error = outcome.unwrap_err();
            assert_eq!(error.code, MxcErrorCode::PolicyValidation);
            assert_eq!(error.message, "recorded validation refusal");
        } else if phase == Phase::Exec && !dry_run {
            assert!(matches!(
                outcome.unwrap(),
                DispatchOutcome::ExecCompleted { exit_code: 7 }
            ));
        } else {
            assert!(matches!(outcome.unwrap(), DispatchOutcome::Envelope(_)));
        }
        let events = backend.events.into_inner();
        assert_eq!(
            events.len(),
            if dry_run || reject_validation { 1 } else { 2 }
        );
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event.validation, index == 0);
            assert_eq!(event.phase, phase);
            assert_eq!(event.id, id);
            assert_eq!(event.common, common);
            assert_eq!(event.config, expected_config);
            assert_eq!(
                event.stdio,
                (index == 1 && phase == Phase::Exec).then_some(ExecStdio::Relayed)
            );
        }
    }
}

fn lifecycle_matrix<C: Case>() {
    for phase in [
        Phase::Provision,
        Phase::Start,
        Phase::Exec,
        Phase::Stop,
        Phase::Deprovision,
    ] {
        let value = input::<C>(phase);
        assert_dispatch::<C>(&value, Config::Absent);
    }
}

#[test]
fn every_backend_and_phase_preserves_validation_execution_and_dry_run_order() {
    lifecycle_matrix::<Isolation>();
    lifecycle_matrix::<WindowsSandbox>();
    lifecycle_matrix::<Wslc>();
}

#[test]
fn isolation_provision_preserves_each_backend_observable_configuration() {
    let mut value = input::<Isolation>(Phase::Provision);
    value["isolationSession"] = json!({});
    assert_dispatch::<Isolation>(&value, Config::Absent);
    for (config, expected) in [
        (json!({}), Config::Isolation(None)),
        (json!({"appId": ""}), Config::Isolation(Some(String::new()))),
        (
            json!({"appId": "PFN:example"}),
            Config::Isolation(Some("PFN:example".into())),
        ),
    ] {
        value["isolationSession"] = json!({"provision": config});
        assert_dispatch::<Isolation>(&value, expected);
    }
}

#[test]
fn wslc_provision_preserves_each_backend_observable_configuration() {
    let mut value = input::<Wslc>(Phase::Provision);
    value["wslc"] = json!({});
    assert_dispatch::<Wslc>(&value, Config::Absent);
    for (config, expected) in [
        (json!({}), Config::Wslc(None, None, None)),
        (
            json!({"image": "custom"}),
            Config::Wslc(Some("custom".into()), None, None),
        ),
        (
            json!({"imageTarPath": "image.tar"}),
            Config::Wslc(None, Some("image.tar".into()), None),
        ),
        (
            json!({"image": "custom", "imageTarPath": "image.tar"}),
            Config::Wslc(Some("custom".into()), Some("image.tar".into()), None),
        ),
        (
            json!({"image": "", "imageTarPath": ""}),
            Config::Wslc(Some(String::new()), Some(String::new()), None),
        ),
        (
            json!({"portMappings": []}),
            Config::Wslc(None, None, Some(Vec::new())),
        ),
        (
            json!({"portMappings": [{"windowsPort": 8080, "containerPort": 80}]}),
            Config::Wslc(
                None,
                None,
                Some(vec![PortMapping {
                    windows_port: 8080,
                    container_port: 80,
                    protocol: "tcp".into(),
                }]),
            ),
        ),
        (
            json!({
                "image": "custom",
                "portMappings": [
                    {"windowsPort": 8080, "containerPort": 80},
                    {"windowsPort": 8443, "containerPort": 443},
                ],
            }),
            Config::Wslc(
                Some("custom".into()),
                None,
                Some(vec![
                    PortMapping {
                        windows_port: 8080,
                        container_port: 80,
                        protocol: "tcp".into(),
                    },
                    PortMapping {
                        windows_port: 8443,
                        container_port: 443,
                        protocol: "tcp".into(),
                    },
                ]),
            ),
        ),
    ] {
        value["wslc"] = json!({"provision": config});
        assert_dispatch::<Wslc>(&value, expected);
    }
}

fn streaming_matrix<C: Case>() {
    for reject_validation in [false, true] {
        let parsed = parse(&input::<C>(Phase::Exec));
        let common = common_snapshot(parsed.request());
        let mut backend = Recording::<C>::new(reject_validation);
        let result = dispatch_state_aware_exec(&mut backend, C::bind(parsed).unwrap());
        if reject_validation {
            assert_eq!(result.unwrap_err().code, MxcErrorCode::PolicyValidation);
        } else {
            assert_eq!((result.unwrap().waiter)().unwrap(), ExecOutcome::Exited(7));
        }
        let events = backend.events.into_inner();
        assert_eq!(events.len(), if reject_validation { 1 } else { 2 });
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event.phase, Phase::Exec);
            assert_eq!(
                event.id.as_deref(),
                Some(format!("{}:test-id", C::PREFIX).as_str())
            );
            assert_eq!(event.common, common);
            assert_eq!(event.validation, index == 0);
            assert_eq!(event.config, Config::Absent);
            assert_eq!(event.stdio, (index == 1).then_some(ExecStdio::Piped));
        }
    }
    for phase in [
        Phase::Provision,
        Phase::Start,
        Phase::Stop,
        Phase::Deprovision,
    ] {
        let mut backend = Recording::<C>::new(false);
        let error =
            dispatch_state_aware_exec(&mut backend, C::bind(parse(&input::<C>(phase))).unwrap())
                .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert_eq!(
            error.message,
            format!("streaming exec requires the exec phase, got {phase}")
        );
        assert!(backend.events.borrow().is_empty());
    }
}

#[test]
fn streaming_uses_the_same_binding_and_preserves_its_phase_and_validation_gates() {
    streaming_matrix::<Isolation>();
    streaming_matrix::<WindowsSandbox>();
    streaming_matrix::<Wslc>();
}

fn mismatch<C: Case, Other: Case>() {
    for phase in [
        Phase::Provision,
        Phase::Start,
        Phase::Exec,
        Phase::Stop,
        Phase::Deprovision,
    ] {
        let error = C::bind(parse(&input::<Other>(phase))).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert!(error.message.contains("incompatible"));
    }
}

#[test]
fn incompatible_backend_operations_never_bind_as_absent_configuration() {
    mismatch::<Isolation, WindowsSandbox>();
    mismatch::<Isolation, Wslc>();
    mismatch::<WindowsSandbox, Isolation>();
    mismatch::<WindowsSandbox, Wslc>();
    mismatch::<Wslc, Isolation>();
    mismatch::<Wslc, WindowsSandbox>();
}

fn session_parsed(operation: StateAwareOperation) -> ParsedStateAwareRequest {
    ParsedStateAwareRequest::new(ExecutionRequest::default(), operation)
}

#[test]
fn wslc_binding_carries_session_sizing_and_the_session_id_through() {
    let sizing = WslcProvisionSessionConfig {
        cpu_count: Some(4),
        memory_mb: Some(8192),
        gpu: Some(true),
    };
    let bound = bind_wslc::<Recording<Wslc>>(session_parsed(
        StateAwareOperation::ProvisionSession(Some(sizing)),
    ))
    .unwrap();
    assert_eq!(bound.phase(), Phase::ProvisionSession);
    assert_eq!(bound.sandbox_id(), None);
    let (_, operation) = bound.into_parts();
    let BoundStateAwareOperation::ProvisionSession(config) = operation else {
        panic!("expected a bound session provision");
    };
    assert_eq!(config, Some(sizing));

    let bound =
        bind_wslc::<Recording<Wslc>>(session_parsed(StateAwareOperation::DeprovisionSession {
            session_id: "wslcsess:0123456789abcdef0123456789abcdef".into(),
        }))
        .unwrap();
    assert_eq!(bound.phase(), Phase::DeprovisionSession);
    assert_eq!(bound.sandbox_id(), None);
    let (_, operation) = bound.into_parts();
    let BoundStateAwareOperation::DeprovisionSession { session_id } = operation else {
        panic!("expected a bound session deprovision");
    };
    assert_eq!(session_id, "wslcsess:0123456789abcdef0123456789abcdef");
}

#[test]
fn session_operations_never_bind_to_a_backend_without_sessions() {
    for operation in [
        StateAwareOperation::ProvisionSession(None),
        StateAwareOperation::DeprovisionSession {
            session_id: "wslcsess:0123456789abcdef0123456789abcdef".into(),
        },
    ] {
        let error =
            bind_isolation_session::<Recording<Isolation>>(session_parsed(operation.clone()))
                .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        let error = bind_windows_sandbox::<Recording<WindowsSandbox>>(session_parsed(operation))
            .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
    }
}

#[test]
fn session_phases_keep_the_same_validation_execution_and_dry_run_order_as_every_other_phase() {
    assert_dispatch_parsed::<Wslc>(
        || session_parsed(StateAwareOperation::ProvisionSession(None)),
        Config::Absent,
    );

    let sizing = WslcProvisionSessionConfig {
        cpu_count: Some(4),
        memory_mb: Some(8192),
        gpu: Some(true),
    };
    assert_dispatch_parsed::<Wslc>(
        || session_parsed(StateAwareOperation::ProvisionSession(Some(sizing))),
        Config::WslcSession(Some(4), Some(8192), Some(true)),
    );

    assert_dispatch_parsed::<Wslc>(
        || {
            session_parsed(StateAwareOperation::DeprovisionSession {
                session_id: "wslcsess:0123456789abcdef0123456789abcdef".into(),
            })
        },
        Config::Absent,
    );
}

struct DummyW365Backend;

impl StatefulSandboxBackend for DummyW365Backend {
    const ID_PREFIX: &'static str = "w365";
    const BACKEND_KEY: &'static str = "w365_agents";
    type ProvisionConfig = W365ProvisionConfig;
    type StartConfig = W365StartConfig;
    type ExecConfig = W365ExecConfig;
    type StopConfig = W365StopConfig;
    type DeprovisionConfig = W365StopConfig;
    type ProvisionMetadata = ();
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        _: &ExecutionRequest,
        _: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        Ok(ProvisionResult {
            sandbox_id:
                "w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"
                    .into(),
            metadata: Some(()),
        })
    }
    fn start(
        &mut self,
        _: &str,
        _: &ExecutionRequest,
        _: Option<Self::StartConfig>,
    ) -> Result<StartResult<()>, MxcError> {
        Ok(StartResult { metadata: Some(()) })
    }
    fn exec(
        &mut self,
        _: &str,
        _: &ExecutionRequest,
        _: Option<Self::ExecConfig>,
        _: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        Ok(ExecHandle {
            stdin: null_pipe_handle(),
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin_closer: None,
            waiter: Box::new(|| Ok(ExecOutcome::Exited(0))),
            terminator: Box::new(|| Ok(())),
        })
    }
    fn stop(
        &mut self,
        _: &str,
        _: &ExecutionRequest,
        _: Option<Self::StopConfig>,
    ) -> Result<StopResult<()>, MxcError> {
        Ok(StopResult { metadata: Some(()) })
    }
    fn deprovision(
        &mut self,
        _: &str,
        _: &ExecutionRequest,
        _: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        Ok(DeprovisionResult { metadata: Some(()) })
    }
}

#[test]
fn w365_agents_binding_preserves_phase_configs_and_other_backends_reject_them() {
    let w365_id = "w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8";
    let prov: Value = serde_json::from_str(
        r#"{
            "version":"1.1.0-alpha",
            "phase":"provision",
            "containment":"w365_agents",
            "w365Agents":{"provision":{"poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9"}}
        }"#,
    )
    .unwrap();
    let bound_prov = bind_w365_agents::<DummyW365Backend>(parse(&prov)).unwrap();
    assert_eq!(bound_prov.phase(), Phase::Provision);
    let (_, BoundStateAwareOperation::Provision(Some(prov_cfg))) = bound_prov.into_parts() else {
        panic!("expected bound W365 provision config");
    };
    assert_eq!(prov_cfg.pool_id, "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9");

    for (phase, extra) in [
        ("start", r#","w365Agents":{"start":{"port":8443}}"#),
        (
            "exec",
            r#","process":{"commandLine":"echo"},"w365Agents":{"exec":{"capability":"contoso.cap"}}"#,
        ),
        ("stop", r#","w365Agents":{"stop":{"port":8443}}"#),
        (
            "deprovision",
            r#","w365Agents":{"deprovision":{"port":8443}}"#,
        ),
    ] {
        let json: Value = serde_json::from_str(&format!(
            r#"{{"version":"1.1.0-alpha","phase":"{phase}","sandboxId":"{w365_id}"{extra}}}"#
        ))
        .unwrap();
        let bound = bind_w365_agents::<DummyW365Backend>(parse(&json)).unwrap();
        assert_eq!(bound.sandbox_id(), Some(w365_id));
        match bound.into_parts().1 {
            BoundStateAwareOperation::Start {
                config: Some(cfg), ..
            } => assert_eq!(cfg.port, Some(8443)),
            BoundStateAwareOperation::Exec {
                config: Some(cfg), ..
            } => assert_eq!(cfg.capability.as_deref(), Some("contoso.cap")),
            BoundStateAwareOperation::Stop {
                config: Some(cfg), ..
            } => assert_eq!(cfg.port, Some(8443)),
            BoundStateAwareOperation::Deprovision {
                config: Some(cfg), ..
            } => assert_eq!(cfg.port, Some(8443)),
            _ => panic!("expected bound W365 phase config"),
        }

        // Non-W365 backends must reject any request carrying a w365Agents block,
        // even when the sandboxId prefix matches their own backend.
        for (prefix, bind_other) in [
            (
                "iso:example",
                (|p| bind_isolation_session::<Recording<Isolation>>(p).map(|_| ()))
                    as fn(ParsedStateAwareRequest) -> Result<(), MxcError>,
            ),
            ("wsb:01234567", |p| {
                bind_windows_sandbox::<Recording<WindowsSandbox>>(p).map(|_| ())
            }),
            ("wslc:0123456789abcdef", |p| {
                bind_wslc::<Recording<Wslc>>(p).map(|_| ())
            }),
        ] {
            let other_json: Value = serde_json::from_str(&format!(
                r#"{{"version":"1.1.0-alpha","phase":"{phase}","sandboxId":"{prefix}"{extra}}}"#
            ))
            .unwrap();
            let err = bind_other(parse(&other_json)).unwrap_err();
            assert_eq!(err.code, MxcErrorCode::MalformedRequest);
            assert!(err.message.contains("incompatible"), "{}", err.message);
        }
    }

    // Conversely, bind_w365_agents rejects non-W365 provision and sandbox IDs.
    for other_phase in [
        Phase::Provision,
        Phase::Start,
        Phase::Exec,
        Phase::Stop,
        Phase::Deprovision,
    ] {
        let err =
            bind_w365_agents::<DummyW365Backend>(parse(&input::<Wslc>(other_phase))).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(err.message.contains("incompatible"), "{}", err.message);
    }
}

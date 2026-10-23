// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{adapt, assert_clean_common};
use crate::mxc_common::state_aware_operation::{StateAwareOperation, StateAwareProvision};
use crate::mxc_common::wire;
use crate::mxc_contract::dev as contract;

fn source(backend: &str, fields: &str) -> String {
    let network = if backend == "isolation_session" {
        r#","network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}"#
    } else {
        ""
    };
    format!(
        r#"{{"version":"1.1.0-alpha","phase":"provision","containment":"{backend}"{network}{fields}}}"#
    )
}

#[test]
fn isolation_session_configuration_presence_matches_explicit_values() {
    for (fields, expected) in [
        ("", None),
        (r#","isolationSession":{}"#, None),
        (r#","isolationSession":{"provision":{}}"#, Some(None)),
        (
            r#","isolationSession":{"provision":{"appId":""}}"#,
            Some(Some("")),
        ),
        (
            r#","isolationSession":{"provision":{"appId":"example"}}"#,
            Some(Some("example")),
        ),
    ] {
        let json = source("isolation_session", fields);
        let (common, operation) = adapt(&json);
        assert_clean_common(&common);
        assert!(common.filesystem.is_none());
        assert!(common.process.is_none());
        let network = common.network.unwrap();
        assert!(matches!(
            network.egress.as_ref().unwrap().default,
            Some(wire::NetworkAction::Allow)
        ));
        assert!(matches!(
            network.ingress.as_ref().unwrap().default,
            Some(wire::NetworkAction::Allow)
        ));
        assert!(matches!(
            network.ingress.as_ref().unwrap().host_loopback,
            Some(wire::NetworkAction::Allow)
        ));
        let StateAwareOperation::Provision(StateAwareProvision::IsolationSession(config)) =
            operation
        else {
            panic!("wrong operation");
        };
        assert_eq!(
            config.as_ref().map(|config| config.app_id.as_deref()),
            expected
        );
    }
}

#[test]
fn isolation_session_unrestricted_network_forms_map_without_loss() {
    let directional = r#""network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}"#;
    let request = |fields: &str| {
        format!(
            r#"{{"version":"1.1.0-alpha","phase":"provision","containment":"isolation_session"{fields}}}"#
        )
    };

    for (fields, expected_app_id) in [
        (format!(",{directional}"), None),
        (
            format!(
                r#",{directional},"isolationSession":{{"provision":{{"appId":"Contoso.App"}}}}"#
            ),
            Some("Contoso.App"),
        ),
    ] {
        let json = request(&fields);
        let (common, operation) = adapt(&json);
        assert_clean_common(&common);
        assert!(common.network.is_some(), "{json}");
        let StateAwareOperation::Provision(StateAwareProvision::IsolationSession(config)) =
            operation
        else {
            panic!("wrong operation");
        };
        assert_eq!(
            config.and_then(|config| config.app_id),
            expected_app_id.map(str::to_owned),
            "{json}"
        );
    }
}

#[test]
fn isolation_session_provision_requires_a_complete_unrestricted_posture() {
    for fields in [
        "",
        r#","isolationSession":{"provision":{"appId":"Contoso.App"}}"#,
        r#","network":{}"#,
        r#","network":{"defaultPolicy":"block","allowLocalNetwork":true}"#,
        r#","network":{"egress":{"default":"allow"}}"#,
        r#","network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"deny"}}"#,
    ] {
        let json = format!(
            r#"{{"version":"1.1.0-alpha","phase":"provision","containment":"isolation_session"{fields}}}"#
        );
        assert!(contract::parse_request(&json).is_err(), "{json}");
    }
}

#[test]
fn isolation_session_network_is_provision_only() {
    for phase in ["start", "stop", "deprovision"] {
        let json = format!(
            r#"{{"version":"1.1.0-alpha","phase":"{phase}","sandboxId":"iso:example","network":{{"egress":{{"default":"allow"}},"ingress":{{"default":"allow","hostLoopback":"allow"}}}}}}"#
        );
        assert!(contract::parse_request(&json).is_err(), "{json}");
    }
}

#[test]
fn wslc_configuration_matches_explicit_values_without_wire_conversion() {
    for (fields, expected) in [
        ("", None),
        (r#","wslc":{}"#, None),
        (r#","wslc":{"provision":{}}"#, Some((None, None))),
        (
            r#","wslc":{"provision":{"image":"image"}}"#,
            Some((Some("image"), None)),
        ),
        (
            r#","wslc":{"provision":{"imageTarPath":"archive.tar"}}"#,
            Some((None, Some("archive.tar"))),
        ),
        (
            r#","wslc":{"provision":{"image":"image","imageTarPath":"archive.tar"}}"#,
            Some((Some("image"), Some("archive.tar"))),
        ),
        (
            r#","wslc":{"provision":{"image":"","imageTarPath":""}}"#,
            Some((Some(""), Some(""))),
        ),
        (
            r#","wslc":{"provision":{"image":""}}"#,
            Some((Some(""), None)),
        ),
        (
            r#","wslc":{"provision":{"imageTarPath":""}}"#,
            Some((None, Some(""))),
        ),
    ] {
        let json = source("wslc", fields);
        let (common, operation) = adapt(&json);
        assert_clean_common(&common);
        assert!(common.network.is_none());
        let StateAwareOperation::Provision(StateAwareProvision::Wslc(config)) = operation else {
            panic!("wrong operation");
        };
        let observed = config
            .as_ref()
            .map(|config| (config.image.as_deref(), config.image_tar_path.as_deref()));
        assert_eq!(observed, expected);
    }
}

#[test]
fn wslc_port_mappings_convert_without_wire_conversion() {
    for (fields, expected) in [
        (r#","wslc":{"provision":{}}"#, None),
        (r#","wslc":{"provision":{"portMappings":[]}}"#, Some(vec![])),
        (
            r#","wslc":{"provision":{"portMappings":[{"windowsPort":8080,"containerPort":80}]}}"#,
            Some(vec![(8080, 80)]),
        ),
        (
            r#","wslc":{"provision":{"portMappings":[{"windowsPort":8080,"containerPort":80,"protocol":"tcp"}]}}"#,
            Some(vec![(8080, 80)]),
        ),
        (
            r#","wslc":{"provision":{"portMappings":[{"windowsPort":8080,"containerPort":80},{"windowsPort":8443,"containerPort":443}]}}"#,
            Some(vec![(8080, 80), (8443, 443)]),
        ),
    ] {
        let json = source("wslc", fields);
        let (_, operation) = adapt(&json);
        let StateAwareOperation::Provision(StateAwareProvision::Wslc(config)) = operation else {
            panic!("wrong operation");
        };
        let config = config.expect("provision config");
        let observed = config.port_mappings.as_ref().map(|mappings| {
            mappings
                .iter()
                .map(|mapping| (mapping.windows_port, mapping.container_port))
                .collect::<Vec<_>>()
        });
        assert_eq!(observed, expected, "{json}");

        // An omitted protocol normalizes to the only one WSLC implements.
        for mapping in config.port_mappings.iter().flatten() {
            assert_eq!(mapping.protocol, "tcp");
        }
    }
}

#[test]
fn wslc_port_mappings_do_not_leak_into_the_one_shot_wslc_section() {
    let json = source(
        "wslc",
        r#","wslc":{"provision":{"portMappings":[{"windowsPort":8080,"containerPort":80}]}}"#,
    );
    let (common, _) = adapt(&json);
    assert_clean_common(&common);
}

#[test]
fn wslc_rejects_duplicate_windows_ports() {
    let json = source(
        "wslc",
        r#","wslc":{"provision":{"portMappings":[{"windowsPort":8080,"containerPort":80},{"windowsPort":8080,"containerPort":81}]}}"#,
    );
    let request = contract::parse_request(&json).expect("exact contract accepts the shape");
    let Err(error) = crate::mxc_common::config_contract_adapters::dev::adapt_request(request)
    else {
        panic!("duplicate windowsPort must be rejected");
    };
    let message = error.to_string();
    assert!(message.contains("duplicate windowsPort 8080"), "{message}");
    assert!(message.contains("wslc.provision.portMappings"), "{message}");
}

#[test]
fn wslc_accepts_the_same_container_port_behind_distinct_host_ports() {
    let json = source(
        "wslc",
        r#","wslc":{"provision":{"portMappings":[{"windowsPort":8080,"containerPort":80},{"windowsPort":8081,"containerPort":80}]}}"#,
    );
    let (_, operation) = adapt(&json);
    let StateAwareOperation::Provision(StateAwareProvision::Wslc(Some(config))) = operation else {
        panic!("wrong operation");
    };
    assert_eq!(config.port_mappings.expect("port mappings").len(), 2);
}

#[test]
fn provision_common_fields_are_independent_of_backend_payload() {
    for backend in ["isolation_session", "windows_sandbox", "wslc"] {
        for fields in [
            "",
            r#","_comment":null"#,
            r#","telemetry":{}"#,
            r#","$schema":"https://example.com/schema","_comment":"comment","telemetry":{"enabled":false}"#,
        ] {
            let json = source(backend, fields);
            let (common, operation) = adapt(&json);
            assert_clean_common(&common);
            assert_eq!(
                common.source_contract,
                crate::mxc_contract::ContractVersion::V1_1_0Alpha
            );
            assert_eq!(operation.phase().as_str(), "provision");
            assert!(operation.sandbox_id().is_none());
            if backend == "windows_sandbox" {
                assert_eq!(
                    operation,
                    StateAwareOperation::Provision(StateAwareProvision::WindowsSandbox)
                );
            }
            if fields.contains("\"enabled\"") {
                assert_eq!(common.telemetry.unwrap().enabled, Some(false));
            }
        }
    }
    for backend in ["windows_sandbox", "wslc"] {
        let json = source(backend, r#","filesystem":{}"#);
        let (common, _) = adapt(&json);
        let filesystem = common.filesystem.unwrap();
        assert!(filesystem.readonly_paths.is_none());
        assert!(filesystem.readwrite_paths.is_none());
        assert!(filesystem.denied_paths.is_none());

        let json = source(
            backend,
            r#","filesystem":{"readonlyPaths":["/read"],"readwritePaths":["/write"],"deniedPaths":["/deny"]}"#,
        );
        let (common, _) = adapt(&json);
        let filesystem = common.filesystem.unwrap();
        assert_eq!(filesystem.readonly_paths.unwrap(), ["/read"]);
        assert_eq!(filesystem.readwrite_paths.unwrap(), ["/write"]);
        assert_eq!(filesystem.denied_paths.unwrap(), ["/deny"]);
    }
    let (common, _) = adapt(&source("wslc", r#","network":{}"#));
    let network = common.network.unwrap();
    assert!(network.egress.is_none());
    assert!(network.ingress.is_none());
}

#[test]
fn exact_rejections_do_not_inherit_legacy_null_or_unknown_field_acceptance() {
    for (backend, field) in [
        ("isolation_session", "appId"),
        ("wslc", "image"),
        ("wslc", "imageTarPath"),
    ] {
        let section = if backend == "isolation_session" {
            "isolationSession"
        } else {
            "wslc"
        };
        for invalid in ["null", "42", "true", "[]", "{}"] {
            let fields = format!(r#","{section}":{{"provision":{{"{field}":{invalid}}}}}"#);
            let json = source(backend, &fields);
            assert!(contract::parse_request(&json).is_err(), "{json}");
        }
        for payload in [
            format!(r#"{{"{field}":"a","{field}":"b"}}"#),
            r#"{"unknown":true}"#.to_owned(),
        ] {
            let json = source(
                backend,
                &format!(r#","{section}":{{"provision":{payload}}}"#),
            );
            assert!(contract::parse_request(&json).is_err(), "{json}");
        }
    }
    for fields in [
        r#","experimental":{"windows_sandbox":{"provision":{}}}"#,
        r#","experimental":{"provision":{}}"#,
    ] {
        assert!(contract::parse_request(&source("windows_sandbox", fields)).is_err());
    }
}

#[test]
fn non_provision_phases_reject_backend_payloads_and_invalid_wrappers() {
    for phase in ["start", "exec", "stop", "deprovision"] {
        let process = if phase == "exec" {
            r#","process":{"commandLine":"echo"}"#
        } else {
            ""
        };
        for backend in ["isolation_session", "windows_sandbox", "wslc"] {
            let experimental = serde_json::json!({backend: {phase: {}}});
            let json = format!(
                r#"{{"version":"1.1.0-alpha","phase":"{phase}","sandboxId":"id"{process},"experimental":{experimental}}}"#
            );
            assert!(contract::parse_request(&json).is_err(), "{json}");
        }
        for invalid in ["null", "42", "[42]", "true", r#""text""#] {
            let json = format!(
                r#"{{"version":"1.1.0-alpha","phase":"{phase}","sandboxId":"id"{process},"experimental":{invalid}}}"#
            );
            assert!(contract::parse_request(&json).is_err(), "{json}");
        }

        let json = format!(
            r#"{{"version":"1.1.0-alpha","phase":"{phase}","sandboxId":"id"{process},"experimental":{{}},"experimental":{{}}}}"#
        );
        assert!(contract::parse_request(&json).is_err(), "{json}");
    }
}

#[test]
fn w365_agents_provision_and_phase_adapters_preserve_presence_and_redact_tokens() {
    let prov_json = r#"{
        "version":"1.1.0-alpha",
        "phase":"provision",
        "containment":"w365_agents",
        "w365Agents":{
            "provision":{
                "poolId":"6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9",
                "cpBearerToken":"CP_PROVISION_SECRET",
                "agentUserToken":"AGENT_USER_SECRET",
                "userObjectId":"9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"
            }
        }
    }"#;
    let contract_req = contract::parse_request(prov_json).expect("valid W365 provision request");
    let contract_debug = format!("{contract_req:?}");
    assert!(
        !contract_debug.contains("CP_PROVISION_SECRET"),
        "{contract_debug}"
    );
    assert!(
        !contract_debug.contains("AGENT_USER_SECRET"),
        "{contract_debug}"
    );

    let (common, operation) = adapt(prov_json);
    assert_clean_common(&common);
    let runtime_debug = format!("{operation:?}");
    assert!(
        !runtime_debug.contains("CP_PROVISION_SECRET"),
        "{runtime_debug}"
    );
    assert!(
        !runtime_debug.contains("AGENT_USER_SECRET"),
        "{runtime_debug}"
    );
    let StateAwareOperation::Provision(StateAwareProvision::W365Agents(Some(cfg))) = operation
    else {
        panic!("expected W365Agents provision config");
    };
    assert_eq!(cfg.pool_id, "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9");
    assert_eq!(
        cfg.cp_bearer_token.as_ref().map(|t| t.expose()),
        Some("CP_PROVISION_SECRET")
    );
    assert_eq!(
        cfg.agent_user_token.as_ref().map(|t| t.expose()),
        Some("AGENT_USER_SECRET")
    );

    // Empty w365Agents wrapper on non-provision phases preserves Some(default) so
    // non-W365 backends can reject it at binding time.
    for (phase, extra) in [
        ("start", ""),
        ("exec", r#","process":{"commandLine":"echo"}"#),
        ("stop", ""),
        ("deprovision", ""),
    ] {
        let json = format!(
            r#"{{"version":"1.1.0-alpha","phase":"{phase}","sandboxId":"w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"{extra},"w365Agents":{{}}}}"#
        );
        let (_, op) = adapt(&json);
        match op {
            StateAwareOperation::Start { w365_agents, .. } => assert!(w365_agents.is_some()),
            StateAwareOperation::Exec { w365_agents, .. } => assert!(w365_agents.is_some()),
            StateAwareOperation::Stop { w365_agents, .. } => assert!(w365_agents.is_some()),
            StateAwareOperation::Deprovision { w365_agents, .. } => {
                assert!(w365_agents.is_some())
            }
            other => panic!("unexpected operation: {other:?}"),
        }
    }

    // Contract and runtime Debug must redact tokens on start, exec, stop, and deprovision too.
    for (json, secret) in [
        (
            r#"{"version":"1.1.0-alpha","phase":"start","sandboxId":"w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8","w365Agents":{"start":{"dpBearerToken":"DP_START_SECRET"}}}"#,
            "DP_START_SECRET",
        ),
        (
            r#"{"version":"1.1.0-alpha","phase":"exec","sandboxId":"w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8","process":{"commandLine":"echo"},"w365Agents":{"exec":{"bearerToken":"DP_EXEC_SECRET"}}}"#,
            "DP_EXEC_SECRET",
        ),
        (
            r#"{"version":"1.1.0-alpha","phase":"stop","sandboxId":"w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8","w365Agents":{"stop":{"cpBearerToken":"CP_STOP_SECRET"}}}"#,
            "CP_STOP_SECRET",
        ),
        (
            r#"{"version":"1.1.0-alpha","phase":"deprovision","sandboxId":"w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8","w365Agents":{"deprovision":{"cpBearerToken":"CP_DEPROV_SECRET"}}}"#,
            "CP_DEPROV_SECRET",
        ),
    ] {
        let req = contract::parse_request(json).expect("valid W365 phase request");
        assert!(!format!("{req:?}").contains(secret));
        let (_, op) = adapt(json);
        assert!(!format!("{op:?}").contains(secret));
    }
}

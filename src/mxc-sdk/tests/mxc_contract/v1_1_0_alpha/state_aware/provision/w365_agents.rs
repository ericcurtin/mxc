// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::state_aware::common::{
    assert_invalid as assert_invalid_request, assert_valid as assert_valid_request,
};
use mxc_sdk::mxc_contract::dev::W365AgentsProvisionRequest;

fn assert_valid(json: &str) {
    assert_valid_request::<W365AgentsProvisionRequest>(json);
}

fn assert_invalid(json: &str) {
    assert_invalid_request::<W365AgentsProvisionRequest>(json);
}

fn request_with_additional_fields(additional_fields: &str) -> String {
    format!(
        r#"{{
            "version": "1.1.0-alpha",
            "phase": "provision",
            "containment": "w365_agents",
            {additional_fields}
        }}"#
    )
}

fn request_with_containment_value(containment: &str) -> String {
    format!(
        r#"{{
            "version": "1.1.0-alpha",
            "phase": "provision",
            "containment": {containment}
        }}"#
    )
}

#[test]
fn accepts_minimal_provision_request() {
    assert_valid(
        r#"{
            "version": "1.1.0-alpha",
            "phase": "provision",
            "containment": "w365_agents"
        }"#,
    );
}

#[test]
fn accepts_provision_request_with_all_fields() {
    assert_valid(
        r#"{
            "$schema": "https://example.com/provision.schema.json",
            "_comment": "W365 Agents provision",
            "version": "1.1.0-alpha",
            "phase": "provision",
            "containment": "w365_agents",
            "telemetry": {
                "enabled": true
            },
            "w365Agents": {
                "provision": {
                    "poolId": "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9",
                    "agentUserToken": "tok-agent",
                    "userObjectId": "9a1f2b3c-4d5e-6f70-8192-a3b4c5d6e7f8",
                    "userType": "Agentic",
                    "provisionTimeoutMs": 60000,
                    "cpBaseUrl": "https://cp.example.internal",
                    "cpBearerToken": "tok-cp",
                    "cpApiVersion": "2026-06-01-preview",
                    "port": 443
                }
            }
        }"#,
    );
}

#[test]
fn accepts_empty_optional_objects() {
    for field in [r#""telemetry": {}"#, r#""w365Agents": {}"#] {
        assert_valid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_provision_missing_pool_id() {
    assert_invalid(&request_with_additional_fields(
        r#""w365Agents": {"provision": {}}"#,
    ));
}

#[test]
fn rejects_other_containment_values() {
    for containment in ["isolation_session", "windows_sandbox", "wslc", "vm", "unknown"] {
        assert_invalid(&request_with_containment_value(&format!(
            r#""{containment}""#
        )));
    }
}

#[test]
fn rejects_forbidden_fields() {
    for field in [
        r#""process": {"commandLine": "echo"}"#,
        r#""filesystem": {}"#,
        r#""network": {}"#,
        r#""ui": {}"#,
        r#""experimental": {}"#,
        r#""sandboxId": "w365:01234567""#,
        r#""wslc": {}"#,
        r#""isolationSession": {}"#,
        r#""windowsSandbox": {}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

#[test]
fn rejects_unknown_nested_fields() {
    for field in [
        r#""w365Agents": {"unknownField": true}"#,
        r#""w365Agents": {"provision": {"unknownField": true}}"#,
    ] {
        assert_invalid(&request_with_additional_fields(field));
    }
}

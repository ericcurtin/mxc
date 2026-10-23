// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-phase metadata returned to the caller.

use std::collections::BTreeMap;

use serde::Serialize;

/// Returned by `provision`. Note there is no `correlationVector` field: the
/// executor injects the MS-CV into the provision `result` alongside
/// `sandboxId`, so emitting one here would duplicate it.
///
/// `Debug` is hand-written to redact `connectivity_url`, mirroring
/// [`crate::w365agents_common::cp::SessionResponseV1`]: that URL may embed a connection ticket, and
/// it is returned to the caller by design but must never reach a log line or an
/// error `details` object via a `{:?}`.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionMetadata {
    pub session_id: String,
    pub computer_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connectivity_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshare_url: Option<String>,
}

impl std::fmt::Debug for ProvisionMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionMetadata")
            .field("session_id", &self.session_id)
            .field("computer_id", &self.computer_id)
            .field("status", &self.status)
            .field("computer_url", &self.computer_url)
            .field(
                "connectivity_url",
                &self.connectivity_url.as_ref().map(|_| "<redacted>"),
            )
            .field("screenshare_url", &self.screenshare_url)
            .finish()
    }
}

/// Connection descriptor for the in-VM MCP server. MXC never proxies MCP
/// traffic — the caller connects directly using these coordinates.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpDescriptor {
    pub url: String,
    pub transport: String,
    pub auth: String,
    pub required_headers: BTreeMap<String, String>,
}

impl McpDescriptor {
    /// Build from host + path + query. Do **not** string-append to SM's
    /// `computerUrl`, which already carries its own `?api-version`.
    pub fn new(dp_host: &str, computer_id: &str, api_version: &str) -> Self {
        let mut required_headers = BTreeMap::new();
        // The value must equal the path computerId or ARI denies authorization.
        required_headers.insert("x-ms-computerId".to_string(), computer_id.to_string());
        // A placeholder, never a real credential: the caller supplies its own
        // DataPlane-audience token.
        required_headers.insert("Authorization".to_string(), "******".to_string());
        Self {
            url: format!("https://{dp_host}/computers/{computer_id}/mcp?api-version={api_version}"),
            transport: "streamable-http".to_string(),
            auth: "entra-bearer".to_string(),
            required_headers,
        }
    }
}

/// The exec capability the caller may drive through the relay.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecDescriptor {
    pub capability: String,
}

/// Returned by `start`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartMetadata {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshare_url: Option<String>,
    pub mcp: McpDescriptor,
    pub exec: ExecDescriptor,
}

/// Returned by both `stop` and `deprovision`. The field is `releaseRequested`,
/// never `released`: SM registers a fire-and-forget check-in and returns, and
/// the VM reclaim to `Deleted` happens asynchronously afterwards.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseMetadata {
    pub release_requested: bool,
    /// Always `false`. SM cannot recreate a released session id, so a released
    /// sandbox is dead: a caller that treated `stop` as suspend would otherwise
    /// discover this only as an opaque `pool_authorization_denied` from a later
    /// `start`. Emitted as a machine-readable field so an SDK can refuse the
    /// call rather than relying on the operator having read the docs.
    pub restartable: bool,
}

impl Default for ReleaseMetadata {
    fn default() -> Self {
        Self {
            release_requested: true,
            restartable: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{McpDescriptor, ProvisionMetadata, ReleaseMetadata, StartMetadata};

    const POOL: &str = "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9";
    const C: &str = "538fdbe2-1f9a-40c7-b8dd-f2391d55a24a";

    #[test]
    fn provision_metadata_serializes_camel_case() {
        let meta = ProvisionMetadata {
            session_id: C.to_string(),
            computer_id: C.to_string(),
            status: "Succeeded".to_string(),
            computer_url: Some("https://cu".to_string()),
            connectivity_url: None,
            screenshare_url: None,
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["sessionId"], C);
        assert_eq!(v["computerId"], C);
        assert_eq!(v["computerUrl"], "https://cu");
        // Absent options are omitted rather than serialized as null.
        assert!(v.get("connectivityUrl").is_none());
        // The executor injects correlationVector into `result`; the backend must not.
        assert!(v.get("correlationVector").is_none());
    }

    #[test]
    fn mcp_descriptor_is_built_from_host_path_and_query() {
        // Never string-append to SM's computerUrl: it already carries its own
        // ?api-version on the base path.
        let d = McpDescriptor::new(&format!("{POOL}.westus3.ari.example.net"), C, "1.0");
        assert_eq!(
            d.url,
            format!("https://{POOL}.westus3.ari.example.net/computers/{C}/mcp?api-version=1.0")
        );
        assert_eq!(d.transport, "streamable-http");
        assert_eq!(d.auth, "entra-bearer");
        assert_eq!(
            d.required_headers
                .get("x-ms-computerId")
                .map(String::as_str),
            Some(C)
        );
        assert!(d.required_headers.contains_key("Authorization"));
    }

    #[test]
    fn mcp_required_headers_never_contain_a_real_token() {
        let d = McpDescriptor::new("h", C, "1.0");
        let v = serde_json::to_value(&d).unwrap();
        let auth = v["requiredHeaders"]["Authorization"].as_str().unwrap();
        assert!(
            auth.starts_with("******"),
            "must be a placeholder, got: {auth}"
        );
    }

    #[test]
    fn start_metadata_carries_the_descriptors() {
        let meta = StartMetadata {
            status: "Ready".to_string(),
            computer_url: None,
            screenshare_url: None,
            mcp: McpDescriptor::new("h", C, "1.0"),
            exec: super::ExecDescriptor {
                capability: "microsoft.mxc-exec".to_string(),
            },
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["status"], "Ready");
        assert_eq!(v["exec"]["capability"], "microsoft.mxc-exec");
        assert_eq!(v["mcp"]["transport"], "streamable-http");
    }

    #[test]
    fn release_metadata_never_claims_the_vm_is_reclaimed() {
        // Check-in registers a fire-and-forget CDP operation; reclaim is async.
        // Both stop and deprovision report the same honest field.
        let v = serde_json::to_value(ReleaseMetadata::default()).unwrap();
        assert_eq!(v["releaseRequested"], serde_json::json!(true));
        assert!(v.get("released").is_none());
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON payload structures for `EXEC_START`, `EXIT`, and `ERROR` frames.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::mxc_common::mxc_error::MxcError;

use crate::w365agents_common::exec::frame::{encode_frame, FrameType, MAX_FRAME_PAYLOAD};

/// In-memory `EXEC_START`. Rust field names are descriptive; the WIRE form
/// (spec §6, matching the DesktopControl.Exec server / Plan A) is
/// `{command, cwd?, env?, timeoutMs?, shell?, mode:"pipe"}` with `env` a JSON
/// object `{KEY:VALUE}`. Sensitive fields (`command_line`, `env`) are never
/// logged — see the custom `Debug`.
#[derive(Clone)]
pub struct ExecStartPayload {
    pub command_line: String,
    pub working_directory: String,
    /// `"KEY=VALUE"` entries (MXC `ExecutionRequest.env` shape).
    pub env: Vec<String>,
    pub timeout_ms: u32,
    pub shell: Option<String>,
}

impl std::fmt::Debug for ExecStartPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecStartPayload")
            .field("command_line", &"<redacted>")
            .field("working_directory", &self.working_directory)
            .field("env", &format_args!("<redacted:{}>", self.env.len()))
            .field("timeout_ms", &self.timeout_ms)
            .field("shell", &self.shell)
            .finish()
    }
}

impl ExecStartPayload {
    /// Serialize to a spec-§6 `EXEC_START` frame: descriptive Rust fields are
    /// mapped to the wire keys, `env` "KEY=VALUE" entries become a JSON object,
    /// and `mode` is always `"pipe"` (PTY deferred). Fails if the JSON body
    /// exceeds the 64 KiB frame cap (no silent truncation).
    pub fn encode(&self) -> Result<Vec<u8>, MxcError> {
        // "KEY=VALUE" -> {KEY: VALUE}; split on the FIRST '=' (values may contain '=').
        let env_map: BTreeMap<&str, &str> = self
            .env
            .iter()
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (k, v),
                None => (kv.as_str(), ""),
            })
            .collect();

        #[derive(Serialize)]
        struct Wire<'a> {
            command: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            cwd: Option<&'a str>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            env: BTreeMap<&'a str, &'a str>,
            #[serde(rename = "timeoutMs")]
            timeout_ms: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            shell: Option<&'a str>,
            mode: &'static str,
        }

        let wire = Wire {
            command: &self.command_line,
            cwd: if self.working_directory.is_empty() {
                None
            } else {
                Some(self.working_directory.as_str())
            },
            env: env_map,
            timeout_ms: self.timeout_ms,
            shell: self.shell.as_deref(),
            mode: "pipe",
        };

        let json = serde_json::to_vec(&wire)
            .map_err(|e| MxcError::backend_error(format!("encode EXEC_START: {e}")))?;
        if json.len() > MAX_FRAME_PAYLOAD {
            return Err(MxcError::backend_error(format!(
                "EXEC_START payload too large: {} bytes (max {MAX_FRAME_PAYLOAD})",
                json.len()
            )));
        }
        Ok(encode_frame(FrameType::ExecStart, &json))
    }
}

/// JSON body of the terminal `EXIT` frame (spec §6: `{code:i32}`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExitPayload {
    /// Wire key is `code`; kept as `exit_code` in Rust for readability.
    #[serde(rename = "code")]
    pub exit_code: i32,
}

/// JSON body of the terminal `ERROR` frame (spec §6: `{code?, message}`). Only
/// `message` is consumed; the server's `code` (a string category) is ignored —
/// the field is intentionally omitted, and serde skips unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ErrorPayload {
    pub message: String,
}

pub fn parse_exit(payload: &[u8]) -> Result<ExitPayload, MxcError> {
    serde_json::from_slice(payload)
        .map_err(|e| MxcError::backend_error(format!("decode EXIT frame: {e}")))
}

pub fn parse_error(payload: &[u8]) -> Result<ErrorPayload, MxcError> {
    serde_json::from_slice(payload)
        .map_err(|e| MxcError::backend_error(format!("decode ERROR frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::super::payload::{parse_error, parse_exit, ExecStartPayload};

    fn sample() -> ExecStartPayload {
        ExecStartPayload {
            command_line: "echo hi".into(),
            working_directory: "C:\\work".into(),
            env: vec!["SECRET=hunter2".into()],
            timeout_ms: 30_000,
            shell: Some("cmd".into()),
        }
    }

    #[test]
    fn encodes_a_spec_conformant_exec_start_frame() {
        let frame = sample().encode().unwrap();
        // type byte 0x01 then a big-endian length then JSON.
        assert_eq!(frame[0], 0x01);
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(len, frame.len() - 5);
        let json: serde_json::Value = serde_json::from_slice(&frame[5..]).unwrap();
        // Spec §6 wire keys — MUST match the DesktopControl.Exec server (Plan A).
        assert_eq!(json["command"], "echo hi");
        assert_eq!(json["cwd"], "C:\\work");
        assert_eq!(json["env"]["SECRET"], "hunter2"); // env is a JSON object {KEY:VALUE}
        assert_eq!(json["timeoutMs"], 30_000);
        assert_eq!(json["shell"], "cmd");
        assert_eq!(json["mode"], "pipe");
        // Descriptive Rust field names must NOT leak onto the wire.
        assert!(json.get("command_line").is_none());
        assert!(json.get("timeout_ms").is_none());
    }

    #[test]
    fn debug_redacts_env_and_command() {
        let dbg = format!("{:?}", sample());
        assert!(
            !dbg.contains("hunter2"),
            "env values must not appear in Debug: {dbg}"
        );
        assert!(
            !dbg.contains("echo hi"),
            "command_line must not appear in Debug: {dbg}"
        );
        assert!(dbg.contains("env: <redacted:1>"), "got: {dbg}");
    }

    #[test]
    fn parses_exit_payload() {
        let e = parse_exit(br#"{"code":7}"#).unwrap();
        assert_eq!(e.exit_code, 7);
    }

    #[test]
    fn parses_error_payload() {
        // The server's `code` (a string category) is ignored; only `message` is read.
        let e = parse_error(br#"{"code":"spawn_failed","message":"spawn failed"}"#).unwrap();
        assert_eq!(e.message, "spawn failed");
    }
}

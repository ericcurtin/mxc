# W365 Agents Container Lifecycle Operations

> **Audience:** MXC consumers and developers

This document describes **container lifecycle operations** for the Windows 365
Agents (`w365_agents`) backend: `provision → start → exec → stop → deprovision`
calls that check out a Windows 365 Cloud PC from a pool, poll until the device
is ready, stream command execution over the RemotingInterface relay, and release
the session back to the pool. See the [consumer glossary](../../glossary.md) for
terminology.

It complements:

- [Container lifecycle overview](../../container-lifecycle.md) — the public
  lifecycle model across MXC backends.
- [Container lifecycle architecture](../../development/architecture/container-lifecycle.md)
  — the shared lifecycle JSON format, the Rust `StatefulSandboxBackend` trait,
  and backend routing.

`w365_agents` is **lifecycle-only** and **experimental**:

- It requires development contract [`1.1.0-alpha`](../../containment-policy/dev/policy.md).
- It requires runtime experimental authorization (`--experimental` on the
  executor).
- Native builds require the `w365_agents` Cargo feature (`--features w365_agents`).
- Create-and-run execution (requests without a `phase` field) is rejected with
  `unsupported_containment`.
- `exec` relays standard input, output, and error synchronously through the
  calling process (`ExecStdio::Relayed`). Callers requesting returned stream
  handles (`ExecStdio::Piped`) or a caller-controlled PTY receive an explicit
  refusal before any network connection is opened.

## Architecture

```text
wxc-exec.exe --experimental --operation <phase> [--container-id w365:<pool>:<computer>]
  |
  `-- mxc_engine::state_aware
        |
        `-- w365agents_common::W365AgentsRunner (StatefulSandboxBackend)
              |-- provision --------> SessionManagement POST /api/pools/{poolId}/sessions
              |-- start ------------> RemotingInterface GET /computers/{computerId}/status
              |-- exec -------------> RemotingInterface GET /computers/{computerId}/{capability}
              |                         (HTTP/1.1 101 Switching Protocols -> binary frame relay)
              `-- stop / deprovision -> SessionManagement DELETE /api/sessions/{computerId}
```

Unlike Windows Sandbox or WSLc, `w365_agents` spawns **no host daemon** and
writes **no local state files**. The Cloud PC lease lives in the remote
SessionManagement service, and the three-segment sandbox ID
(`w365:<pool-guid>:<computer-guid>`) carries every coordinate needed by later
phases.

### Components

| Component | Location | Role |
|-----------|----------|------|
| Lifecycle runner | `src/mxc-sdk/src/backends/w365agents/common/runner.rs` (`W365AgentsRunner`) | Implements `StatefulSandboxBackend` (`ID_PREFIX = "w365"`, `BACKEND_KEY = "w365_agents"`), per-phase dry-run validation, `W365ExecConfig` resolution, and fail-closed policy checks. |
| Phase configuration & ambient env | `src/mxc-sdk/src/backends/w365agents/common/config.rs` | Validates `W365ProvisionConfig`, `W365StartConfig`, and `W365StopConfig`; resolves `W365A_*` environment variables and enforces host/token co-resolution. |
| Sandbox ID parser | `src/mxc-sdk/src/backends/w365agents/common/id.rs` (`W365SandboxId`) | Parses and formats canonical `w365:<pool-guid>:<computer-guid>` identifiers. |
| Control-plane client | `src/mxc-sdk/src/backends/w365agents/common/cp.rs` (`SmClient`) | Builds SessionManagement checkout and release requests, maps status codes to `MxcError`, and emits `w365_agents event=<...>` audit lines on stderr. |
| Data-plane status poller | `src/mxc-sdk/src/backends/w365agents/common/dp.rs` (`DpClient`) | Polls RemotingInterface `/computers/{computerId}/status` until `status == "Ready"` or the deadline expires. |
| HTTPS transport | `src/mxc-sdk/src/backends/w365agents/common/http.rs` | Minimal HTTP/1.1 client over `rustls` with WebPKI roots, bounded connect/read/write timeouts, CRLF injection guards, and header-value redaction in `Debug`. |
| Exec upgrade & relay | `src/mxc-sdk/src/backends/w365agents/common/exec/` | Performs a WebSocket-shaped HTTP/1.1 upgrade (`101 Switching Protocols`) to `/computers/{computerId}/{capability}`, sends `EXEC_START`, and multiplexes `STDIN`, `STDIN_CLOSE`, `STARTED`, `STDOUT`, `STDERR`, `EXIT`, and `ERROR` frames. |
| Secret wrapper | `src/mxc-sdk/src/core/mxc_common/models.rs` (`Redacted`) | Redacts bearer tokens to `"<redacted>"` in `Debug` and `Display` across contract and runtime types. |

## Container Lifecycle Operations

["MXC request JSON"](../../schema.md#mxc-request-json) carries `phase` and,
after provision, `sandboxId` at the top level. Direct executor invocations omit
those routing fields from the JSON file and supply `--operation <phase>` and
`--container-id <sandboxId>` on the command line.

| Phase | Service call | Result |
|-------|--------------|--------|
| `provision` | `POST /api/pools/{poolId}/sessions?api-version={cpApiVersion}` | Mints `w365:<pool-guid>:<computer-guid>` and returns `ProvisionMetadata` (`sessionId`, `computerId`, `status`, `computerUrl`, `connectivityUrl`, `screenshareUrl`). |
| `start` | `GET /computers/{computerId}/status?api-version={dpApiVersion}` (`x-ms-computerId: {computerId}`, polled) | Blocks until `status == "Ready"` and returns `StartMetadata` (`status`, `computerUrl`, `screenshareUrl`, `mcp`, `exec`). |
| `exec` | `GET /computers/{computerId}/{capability}` (`x-ms-computerId: {computerId}`, `Upgrade: websocket`) | Streams workload stdio over the upgraded TLS socket and returns the remote process exit code. |
| `stop` | `DELETE /api/sessions/{computerId}?api-version={cpApiVersion}` | Releases the Cloud PC session back to the pool (`ReleaseMetadata { releaseRequested: true, restartable: false }`). |
| `deprovision` | `DELETE /api/sessions/{computerId}?api-version={cpApiVersion}` | Identical to `stop` (`ReleaseMetadata { releaseRequested: true, restartable: false }`). HTTP `200`, `202`, `204`, and `404` are all treated as idempotent success on both `stop` and `deprovision`. |

### Stop is terminal

Unlike host-local backends where `stop` returns a container to a restartable
`Provisioned` state, SessionManagement has a single release operation
(`DELETE /api/sessions/{computerId}`). Both `stop` and `deprovision` invoke that
release and return `ReleaseMetadata`:

```json
{
  "releaseRequested": true,
  "restartable": false
}
```

Once `stop` succeeds, the session is released back to the pool (reclamation on
the service side is asynchronous) and the `sandboxId` cannot be restarted with a
subsequent `start` call. Callers that want to run additional commands must keep
the sandbox running until all `exec` calls complete, or provision a new sandbox.

### Sandbox ID format

Provision mints a three-segment identifier:

```text
w365:<pool-guid>:<computer-guid>
```

Both `<pool-guid>` and `<computer-guid>` are 36-character hyphenated ASCII hex
UUIDs (`8-4-4-4-12`). Any other shape or two-segment identifier is rejected
before any network call with `malformed_id`. Callers should treat the returned
`sandboxId` as an opaque identifier and pass it unchanged to later phases.

### Error mapping

| Service condition | `MxcError` code | `details.code` / notes |
|-------------------|-----------------|------------------------|
| Missing `--experimental` or binary compiled without `--features w365_agents` | `backend_unavailable` | Returned before backend dispatch. |
| Malformed `sandboxId` | `malformed_id` | Checked before any network call. |
| Non-GUID `poolId`, missing credentials, unpaired host override, or unsupported policy section | `policy_validation` | Checked before any network call. |
| Exec upgrade HTTP `404` | `policy_validation` | `unknown_capability` |
| Checkout HTTP `404` | `backend_error` | `pool_not_found` |
| Checkout or status poll HTTP `401`, checkout HTTP `403`, or exec upgrade HTTP `401` / `403` | `backend_error` | `auth_denied` |
| Status poll HTTP `403` | `backend_error` | `pool_authorization_denied` (principal not in pool, computer released, or `x-ms-computerId` mismatch). |
| Checkout HTTP `500` | `backend_error` | `provision_timeout` (`possiblySucceeded: true`; never retry automatically). |
| Checkout transport drop or unparseable 2xx body / non-GUID session ID | `backend_error` | `checkout_outcome_unknown`, `unparsable_response`, `malformed_session_id`, or `id_mismatch` (`possiblySucceeded: true`). |
| Readiness poll timeout (`start` exceeds `readyTimeoutMs`) | `backend_error` | `attach_timeout` (includes `lastState`). |
| Exec upgrade HTTP `409`, `412`, `423`, or `503` | `backend_error` | `device_unavailable` (`503` sets `retryable: true`). |
| Exec upgrade HTTP `502` or `504` | `backend_error` | `relay_upstream` (`retryable: true`). |
| Release HTTP `500` | `backend_error` | `release_failed` (`retryable: true`). |

Control- and data-plane HTTP errors populate `MxcError.details` with
`httpStatus`, `requestId` (`x-ms-request-id`), and a stable `code` (plus
`possiblySucceeded: true` or `retryable: true` where applicable). Response
headers and bodies are never copied into `details`.

When a checkout fails with `possiblySucceeded: true`, SessionManagement may have
committed a Cloud PC whose ID never reached the client. Do not retry
automatically; instead, inspect stderr for the
`w365_agents event=checkout_outcome_unknown poolId=<guid> reason=<...> correlationVector=<MS-CV>`
audit line and use the correlation vector to reconcile the session with
SessionManagement.

## Configuration

### Provision

```json
{
  "$schema": "./schemas/dev/mxc-config.schema.1.1.0-alpha.json",
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "w365_agents",
  "w365Agents": {
    "provision": {
      "poolId": "6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9",
      "userType": "Local"
    }
  }
}
```

The schema marks `w365Agents` as optional on the request root, but
`W365AgentsRunner` requires `w365Agents.provision` (with `poolId`) at runtime
and rejects a provision request that omits it with `policy_validation`.

| Field (`w365Agents.provision`) | Type | Default | Description |
|---|---|---|---|
| `poolId` | string (UUID) | **Required** | Target Cloud PC pool GUID. |
| `userType` | string | omitted | Optional session kind (`"Local"`, `"HumanUser"`, or `"Agentic"`). When omitted, no `user-type` header is sent. |
| `userObjectId` | string (UUID) | omitted | Entra user object GUID; required when `agentUserToken` is supplied. |
| `agentUserToken` | string | omitted | Auxiliary bearer token (`x-ms-authorization-auxiliary`) for agentic sessions. |
| `provisionTimeoutMs` | integer | `45000` | Client-side checkout timeout in milliseconds. |
| `cpBaseUrl` | string | `W365A_CONTROLPLANE_URL` | SessionManagement control-plane bare hostname (for example `cp.example.internal`, without `https://`). |
| `cpBearerToken` | string | `W365A_CP_TOKEN` | SessionManagement control-plane bearer token. |
| `cpApiVersion` | string | `W365A_CP_API_VERSION` or `"2.0"` | SessionManagement `api-version` query value (`[A-Za-z0-9.-]+`). |
| `port` | integer | `443` | Control-plane TLS port override. |

### Start

```json
{
  "$schema": "./schemas/dev/mxc-config.schema.1.1.0-alpha.json",
  "version": "1.1.0-alpha",
  "phase": "start",
  "sandboxId": "w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:538fdbe2-1f9a-40c7-b8dd-f2391d55a24a"
}
```

| Field (`w365Agents.start`) | Type | Default | Description |
|---|---|---|---|
| `readyTimeoutMs` | integer | `120000` | Maximum wait in milliseconds for the Cloud PC to report `Ready` (`0` polls once). |
| `pollIntervalMs` | integer | `2000` | Delay in milliseconds between status polls. |
| `dpSuffix` | string | `W365A_DP_SUFFIX` | RemotingInterface DNS suffix (dials `{poolId}.{dpSuffix}`). |
| `dpBearerToken` | string | `W365A_DP_TOKEN` | RemotingInterface bearer token. |
| `dpApiVersion` | string | `W365A_DP_API_VERSION` or `"1.0"` | RemotingInterface `api-version` query value (`[A-Za-z0-9.-]+`). |
| `port` | integer | `443` | Data-plane TLS port override. |

### Exec

```json
{
  "$schema": "./schemas/dev/mxc-config.schema.1.1.0-alpha.json",
  "version": "1.1.0-alpha",
  "phase": "exec",
  "sandboxId": "w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:538fdbe2-1f9a-40c7-b8dd-f2391d55a24a",
  "process": {
    "commandLine": "cmd.exe /c whoami",
    "timeout": 60000
  }
}
```

| Field (`w365Agents.exec`) | Type | Default | Description |
|---|---|---|---|
| `dpSuffix` | string | `W365A_DP_SUFFIX` | RemotingInterface DNS suffix (dials `{poolId}.{dpSuffix}`). |
| `capability` | string | `"microsoft.mxc-exec"` | Reverse-DNS capability segment (`[A-Za-z0-9.-]+`, no leading/trailing dot and no `..`). |
| `bearerToken` | string | `W365A_DP_TOKEN` | RemotingInterface bearer token. |
| `port` | integer | `443` | Data-plane TLS port override. |

### Stop and Deprovision

```json
{
  "$schema": "./schemas/dev/mxc-config.schema.1.1.0-alpha.json",
  "version": "1.1.0-alpha",
  "phase": "deprovision",
  "sandboxId": "w365:6f3a91c2-1d4e-4b0a-9c77-2f5e8a10b3d9:538fdbe2-1f9a-40c7-b8dd-f2391d55a24a"
}
```

`w365Agents.stop` (on `stop`) and `w365Agents.deprovision` (on `deprovision`)
accept the same optional control-plane fields: `cpBaseUrl`, `cpBearerToken`,
`cpApiVersion`, and `port`.

## Ambient Environment Variables and Token Isolation

Operators can supply service coordinates and bearer tokens through environment
variables instead of embedding secrets in request files:

| Environment variable | Used by | Fallback for |
|---|---|---|
| `W365A_CONTROLPLANE_URL` | `provision`, `stop`, `deprovision` | `cpBaseUrl` |
| `W365A_CP_TOKEN` | `provision`, `stop`, `deprovision` | `cpBearerToken` |
| `W365A_CP_API_VERSION` | `provision`, `stop`, `deprovision` | `cpApiVersion` |
| `W365A_DP_SUFFIX` | `start`, `exec` | `dpSuffix` |
| `W365A_DP_TOKEN` | `start`, `exec` | `dpBearerToken` / `bearerToken` |
| `W365A_DP_API_VERSION` | `start` | `dpApiVersion` |

**Host and token co-resolution invariant:** If a request supplies an explicit
non-blank host (`cpBaseUrl` or `dpSuffix`), it **must** also supply an explicit
non-blank bearer token (`cpBearerToken`, `dpBearerToken`, or `bearerToken`) in
the same request. A request that overrides the host without supplying its own
token is rejected with `policy_validation` before dialing, preventing a
caller-chosen host from exfiltrating an ambient operator token.

## Policy Support and Audit Identity

The workload executes on a remote Cloud PC managed by Windows 365 rather than
the local host kernel. Consequently, `w365_agents` **rejects all host-enforced
containment policies**:

- `W365AgentsProvisionRequest`, `StartRequest`, `StopRequest`, and
  `DeprovisionRequest` do not admit `filesystem`, `network`, `ui`, or
  `processContainer` fields (`malformed_request`).
- `ExecRequest` does not admit `filesystem`, `ui`, or `processContainer` fields
  (`malformed_request`), and any supplied `network` or
  `runtimeConfig.networkProxy` field on `exec` is rejected by
  `W365AgentsRunner` with `policy_validation`.
- `process.inheritDefaultEnv` is not configurable over the `DesktopControl.Exec`
  protocol; supplied `process.env` entries are always merged over the remote
  session's environment by the guest service.

In `mxc.PolicyHash` audit records:

- `userType` (on `provision`) and an explicit `capability` (on `exec`) are
  included in the canonical policy projection.
- All bearer tokens (`cpBearerToken`, `dpBearerToken`, `bearerToken`,
  `agentUserToken`), `poolId`, `userObjectId`, `sandboxId`, service hostnames,
  ports, and timeouts are excluded from the hash.

## Exec Relay Protocol

During `exec`, `W365AgentsRunner` dials `{poolId}.{dpSuffix}:{port}` over TLS
and issues a WebSocket-shaped HTTP/1.1 upgrade (required by the
RemotingInterface ingress, while tunneling raw binary frames rather than RFC
6455 WebSocket frames after `101 Switching Protocols`):

```http
GET /computers/{computerId}/{capability} HTTP/1.1
Host: {poolId}.{dpSuffix}
Authorization: Bearer <token>
x-ms-computerId: {computerId}
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
x-ms-correlation-id: <correlation-vector>
```

(`x-ms-correlation-id` is included whenever process telemetry is active and
omitted when the correlation vector is empty.)

After receiving `101 Switching Protocols`, both peers exchange length-prefixed
frames (`[type: u8][length: u32 big-endian][payload]`, maximum payload `64 KiB`):

| Type byte | Name | Direction | Payload |
|-----------|------|-----------|---------|
| `0x01` | `EXEC_START` | client → host | UTF-8 JSON `{command, cwd?, env?, timeoutMs, shell?, mode: "pipe"}` (`env` as `{KEY: VALUE}`). |
| `0x02` | `STDIN` | client → host | Raw stdin bytes (up to `64 KiB` per frame). |
| `0x03` | `STDIN_CLOSE` | client → host | Empty payload signaling stdin EOF. |
| `0x04` | `CANCEL` | client → host | Cancellation signal (reserved). |
| `0x05` | `RESIZE` | client → host | Terminal resize frame (reserved). |
| `0x11` | `STARTED` | host → client | Empty payload confirming process launch. |
| `0x12` | `STDOUT` | host → client | Raw stdout bytes (flushed immediately to caller stdout). |
| `0x13` | `STDERR` | host → client | Raw stderr bytes (flushed immediately to caller stderr). |
| `0x14` | `EXIT` | host → client | UTF-8 JSON `{"code": <i32>}`; terminates the relay. |
| `0x15` | `ERROR` | host → client | UTF-8 JSON `{"code"?: string, "message": string}`; logged to stderr and returns sentinel `-1`. |

`101 Switching Protocols` is the execution commit point: pre-`101` failures
surface as a JSON `{"error": ...}` envelope, whereas post-`101` transport drops
before `EXIT` (or an inbound `ERROR` frame) resolve to sentinel exit code `-1`
(`SENTINEL_ABNORMAL_EXIT`). Malformed or oversized inbound frames still return a
protocol `backend_error`.

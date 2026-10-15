# NVX MicroVM Backend

> **Audience:** MXC consumers and developers

`microvm` is an experimental **Windows x64** backend using the signed native
agent bundled by the official `aci_edge_sandboxes` crate. The previous Nanvix
backend is inactive, including on Linux. This document retains its old location
so existing links continue to work.

## Phase1: minimal signed create-and-run

Build with `build.bat --with-microvm`, or, from `src`:

```text
cargo build -p wxc --features microvm --jobs 2
```

The host needs Windows Hypervisor Platform and hardware virtualization.
Requests require `--experimental`. Unsupported targets fail closed; enabling
the Cargo feature does not enable MicroVM execution on Linux, macOS or ARM64.

MXC uses `AgentConfig::bundled` and `AciEdgeSandbox::agent`, not the standalone
OpenVMM backend. Cargo fetches immutable source revision
`0430ce79d125203c20f0aa69243480513a774296` from
[`microsoft/nvx`](https://github.com/microsoft/nvx), with only `agent-bundled`
enabled and default features disabled. `mxc-sdk` is not publishable while this
development Git dependency is in use.

The dependency's `build.rs` calls `build/agent_bundle.rs` to download
`aci-edge-sandboxes.zip` from release `v0.1.0-dev.0430ce79d125`. It verifies
the archive, layout, component checksums and sandbox ABI, stages the bundle,
and compiles in its manifest and DLL pins. MXC's build module requires the
exact path set and SHA-256 of every file in that official staged bundle,
including all guest, kernel, image-tool, manifest, checksum, provenance, and
licence files. This second check is necessary because Cargo does not inherit a
Git or path dependency's `.cargo/config.toml` when MXC is built by a downstream
consumer. The dependency exposes only the extracted directory to MXC, so the
original ZIP byte stream is no longer available there; the complete extracted
tree identity is pinned instead. MXC does not invoke Cargo recursively,
implement a second downloader, or silently fall back to an unsigned or
standalone backend.

| Release artifact | SHA-256 |
| --- | --- |
| `aci-edge-sandboxes.zip` | `98e3d6011b0664fad6fa783768370a34209639463f5ab812b7776840660ac24e` |
| `bin/aci_edge_agent.dll` | `a203e58b97a642bd4a68824c0387965541895b25582e18db6f55e28947f5f135` |
| `bin/openvmm.exe` | `697f8221e62a1ea4efb3846fefde6f595c89f4f81c0153a2609bf6fb4c81ea9e` |

Distribute the entire `aci-edge-sandboxes/` directory beside `wxc-exec.exe`
or the consuming executable. Cargo test/example executables can discover it in
their parent profile directory. The repository Windows build also copies this
directory with the Node native runtime. Runtime path overrides are not needed
for normal operation; missing or altered assets fail rather than falling back.
Build-time bundle overrides must still match the approved signed component pins.

The control initramfs is not a workload userland. P1 selects the official
example's public workload image,
`mcr.microsoft.com/azurelinux/base/core:3.0`. The native agent pulls/converts it
on the host using bundled `direct-images.exe`; this requires host registry
connectivity and does **not** grant guest network access. There is no P1 public
image-selection or credential API. A private state directory is created for
each run, and stop, deprovision and state-directory removal follow execution.

### Request example

Commands are POSIX shell commands inside the Linux workload, not Python source
or Windows command lines:

```json
{
  "version": "1.1.0-alpha",
  "containment": "microvm",
  "process": {
    "commandLine": "printf 'hello from NVX\\n'; printf 'stderr\\n' >&2; exit 42",
    "timeout": 30000
  }
}
```

```text
wxc-exec.exe --experimental config.json
```

The minimum in-process captured surface is MXC's existing JSON facade,
`mxc_sdk::__ffi::run_json(json, true)`. It returns separate stdout/stderr bytes
and an exit or timeout outcome. This is not a new public Rust lifecycle API.

### Supported and rejected requests

P1 accepts command, timeout (at most one hour), guest working directory without
`..` components, and additive environment entries (at most 32 KiB).
Supplying `process.env` requires `inheritDefaultEnv: true`. Proxy environment
variables are rejected, case-insensitively.

P1 rejects filesystem path grants/denials, explicit network or proxy policy,
explicit UI policy, capture-denials, `destroyOnExit: false`,
`preservePolicy: true`, streaming, PTY and container lifecycle operations.
Policy rejection occurs before bundle discovery or sandbox creation. The
native agent remains responsible for validating and enforcing its own
command/environment/runtime constraints.

## Release attestations versus consumer evidence

The published bundle records `officialSigned=true`, `complete=true`,
`mxcCompatible=false`, and `runtimeValidated=false`. These are producer
attestations, not an MXC test result. MXC does not rewrite them, treat the
negative validation flags alone as proof of runtime failure, or claim that a
successful build proves consumer runtime compatibility.

The bundle embeds NVX revision
`19a359bb3b8974f14bd04b9f2a327a2a3f25d868`, which differs from the crate's
`0430ce79…` source revision. The official build warns about this difference.
Keep the warning and both revisions in validation evidence.

Host validation can check archive/component SHA-256, Windows Authenticode for
the DLL, OpenVMM and image tool, and checksum integrity of the Linux kernel and
guest agent/initramfs. Linux guest files do not carry Authenticode signatures.
Actual guest execution, timeout and cleanup still require a WHP-capable test
host. Ignored tests in `src/mxc-sdk/tests/nvx_e2e.rs` prepare real MXC
facade/executor cases; compiling them or running host-only rejection cases is
not VM smoke evidence.

## Stacked implementation boundary

- **P1:** signed bundled crate, minimum distributable staging, fail-closed
  routing/policy, and captured create-and-run.
- **P2:** deployment/packaging and runtime-policy hardening, including richer
  policy and deployment validation.
- **P3:** public Rust container lifecycle operations and streaming.
- **P4:** CLI work follows P3.

No P2 implementation is implied by P1's necessary bundle staging.

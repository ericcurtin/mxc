# W365 Agents Native Backend Preview Implementation Plan

> **For agentic workers:** Use the `executing-plans` skill for inline execution, or `subagent-driven-development` if the user explicitly chooses delegated execution. Complete tasks in dependency order; unchecked boxes are not evidence of implementation.

**Goal:** Port the W365 Agents backend onto current MXC main as an opt-in native preview, with honest lifecycle semantics, a request-scoped human pool-discovery hook, and live, cancellable execution streams.

**Architecture:** Keep backend logic inside the consolidated `mxc-sdk` package and use the existing exact-contract, typed lifecycle, engine, `ExecHandle`, and FFI boundaries. SM and the Cloud PC remain lifecycle authorities. One per-execution owner bridges bounded local pipes to a single wakeable TLS/protocol driver.

**Tech Stack:** Pinned Rust 1.93, existing HTTP/TLS clients and framing, optional `mio` v1 (`net`, `os-poll`), standard-library pipes, existing native lifecycle adapters, and the development `1.1.0-alpha` contract.

---

### Implementation Plan: W365 Agents native preview

**Design Reference:** User-approved revision 3 of `w365-native-preview-design.md`; SHA256 `687A0400EB4C32B3BA14201A10B3D5648B3B816DC075500BD5355B89E4DC81EB`. Approval was given on 2026-10-23 after the status message identified implementation planning as the next step. The canonical session artifact remains frozen; its historical candidate label is superseded by the separate approval record.

The frozen design and approval record are retained with the planning artifacts,
not in this repository. The implementation requirements and acceptance gates are
recorded below; verify the design hash when consulting those artifacts.

**Overview:** Deliver the five-phase W365 native lifecycle and live execution without publishing a stable contract or adding supported public Rust, Node, or .NET authoring APIs.

#### Baselines and scope

| Item | Exact reference |
|---|---|
| Reviewed design baseline | Main `5c2735dbb927cdb75d916c33c163e2196ad71934` |
| Planning/execution baseline | Main `ffecec04357747d6649714f473436dfb77111be8`, fetched on 2026-10-23 |
| Legacy functionality source | `d0c5eedac37bc96fcf5565ee0c745c98e79ecdca` on `users/vishnu/w365agents` |
| Stable contracts | `0.9.0-alpha`, `1.0.0`; immutable |
| Development contract | `1.1.0-alpha`; SDK major target remains `"1": "1.0.0"` |

Main advanced by two commits during planning: removal of Tier2/Tier3 ProcessContainer fallbacks and an LXC loopback-proxy relay. The relevant shared diff was inspected. In particular, `ContainerPolicy.fallback`, `FallbackPolicy`, `tier2_bfs`, and `force-tier-testing` are gone. Do not recreate them to satisfy historical branch code or the older design's field enumeration. Apply the design's exhaustive-validation rule to the current policy fields instead. The five skipped policy fields and the lifecycle/streaming contracts remain present. No new three-reviewer GREEN is claimed for this newer main SHA.

Execution starts on an isolated fresh-main branch, not by merging main into or replaying the legacy branch. If main advances again, inspect the relevant delta and resolve compatibility before code changes; a changed execution contract or ownership invariant reopens design review.

The delivery excludes discovery-service implementation, human credential acquisition, multi-pool selection, pool creation, a local daemon/database, one-shot execution, PTY, an MCP proxy, and external DesktopControl changes. Discovery initially returns `backend_unavailable`. Custom environment modes and unsupported Relayed stdin sources remain explicitly rejected.

#### File ownership map

All paths are repository-relative Windows paths. A directory plus its enumerated filenames identifies exact files, not permission to restructure the directory.

| Change | Directory and filenames | Responsibility |
|---|---|---|
| Modify | `src\mxc-sdk\Cargo.toml`; `src\tools\wxc\Cargo.toml`; `src\ffi\mxc_ffi\Cargo.toml`; `src\Cargo.lock` | Optional dependencies, additive feature, native consumer forwarding, lockfile |
| Modify | `src\mxc-sdk\src\backends\mod.rs` | Feature-gated backend module registration |
| Create | `src\mxc-sdk\src\backends\w365agents\common\`: `mod.rs`, `config.rs`, `id.rs`, `secret.rs`, `http.rs`, `cp.rs`, `dp.rs`, `metadata.rs`, `runner.rs`, `policy.rs`, `pool_resolver.rs` | Backend-local configuration, clients, lifecycle, validation, resolver seam |
| Create | `src\mxc-sdk\src\backends\w365agents\common\exec\`: `mod.rs`, `frame.rs`, `payload.rs`, `transport.rs`, `driver.rs`, `pipes.rs` | Session ownership, codec, TLS transport, protocol state, private pipes |
| Create | `src\mxc-sdk\src\backends\w365agents\common\exec\pipes\`: `windows.rs`, `unix.rs`, `tests.rs`; `windows\`: `input.rs`, `tests.rs`; `windows\input\tests.rs` | Platform-specific cancellation, stdin classification, real-handle probes and child watchdogs |
| Modify | `src\mxc-sdk\src\core\mxc_common\`: `mod.rs`, `models.rs`, `wire.rs`, `state_aware_operation.rs`, `state_aware_request.rs`, `state_aware_binding.rs`, `state_aware_binding_tests.rs`, `state_aware_input.rs` | Neutral typed inputs and dedicated/unit binding boundaries |
| Modify | `src\mxc-sdk\src\core\mxc_common\`: `config_parser.rs`, `cmdline.rs`, `splice.rs`, `state_aware_dispatch.rs`, `policy_identity.rs`, `sdk_input.rs` | Exact routing, Windows command context, projection, typed-authoring guard |
| Modify | `src\mxc-sdk\src\core\mxc_common\config_contract_adapters\dev\`: `mod.rs`, `state_aware.rs`, `state_aware_tests\mod.rs`, `state_aware_tests\provision.rs`, `state_aware_tests\start.rs`, `state_aware_tests\exec.rs`, `state_aware_tests\stop.rs`, `state_aware_tests\deprovision.rs` | Development-only wire-to-domain conversion and regression tests |
| Modify | `src\mxc-sdk\src\core\mxc_common\config_contract_adapters\v0_9\state_aware.rs`; `src\mxc-sdk\src\core\mxc_common\config_contract_adapters\v1_0\state_aware.rs` | Initialize new neutral optional fields to None without altering published wire contracts |
| Modify | `src\mxc-sdk\src\core\mxc_contract\dev\`: `mod.rs`, `request.rs`, `schema.rs`, `stable.rs`, `state_aware\mod.rs`, `state_aware\provision\mod.rs`, `state_aware\provision\containment.rs`, `state_aware\start.rs`, `state_aware\exec.rs`, `state_aware\stop.rs`, `state_aware\deprovision.rs` | New provision root, containment, and four extended shared roots |
| Create | `src\mxc-sdk\src\core\mxc_contract\dev\w365_agents.rs`; `src\mxc-sdk\src\core\mxc_contract\dev\state_aware\provision\w365_agents.rs` | Closed W365 wire blocks and provision request |
| Modify | `src\mxc-sdk\src\core\mxc_contract\registry.rs` | Request-root metadata, not a new contract version |
| Modify | `src\mxc-sdk\src\core\mxc_engine\`: `backend_registry.rs`, `state_aware.rs`, `run.rs`, `mod.rs` | Native registration, dispatch, context propagation, unsupported one-shot |
| Modify | `src\tools\wxc\src\main.rs`; `src\mxc-sdk\tests\state_aware.rs`; `src\ffi\mxc_ffi\tests\ffi.rs` | Windows CLI preflight and existing native/FFI boundary coverage |
| Modify | `src\mxc-sdk\tests\mxc_contract\v1_1_0_alpha.rs`; `src\mxc-sdk\tests\mxc_contract\v1_1_0_alpha\fixtures.rs` | Development contract test registration |
| Create | `src\mxc-sdk\tests\mxc_contract\v1_1_0_alpha\w365_agents.rs`; `src\mxc-sdk\tests\w365_agents.rs` | Exact-contract and raw native-preview boundary tests |
| Create/extend | `src\mxc-sdk\tests\mxc_contract\v1_1_0_alpha\fixtures\w365_agents_provision\valid`; `src\mxc-sdk\tests\mxc_contract\v1_1_0_alpha\fixtures\w365_agents_provision\invalid`; existing `start`, `exec`, `stop`, `deprovision` fixture directories | Descriptor-driven positive and negative fixtures |
| Regenerate | `schemas\dev\mxc-config.schema.1.1.0-alpha.json`; `sdk\node\src\generated\v1_1_0_alpha\wire.ts` | Generated artifacts only; never hand-edit |
| Modify | `.azure-pipelines\templates\Rust.Build.Job.yml`; `.azure-pipelines\templates\Mac.Build.Job.yml` | Isolated offline feature-on/off validation, not premature artifact publication |
| Modify | `.github\workflows\Build.Windows.Job.yml`; `.github\workflows\Build.Linux.Job.yml`; `.github\workflows\Build.MacOS.Job.yml` | Run the same native offline gate in primary PR and scheduled artifact builds |
| Create | `scripts\ci\test-w365-agents-offline.ps1` | Shared native-only package/probe gate, reusing `TestSuiteResults.ps1`; reject zero/skipped selections and missing child markers |
| Create/modify | `src\mxc-sdk\src\core\mxc_common\unix_io.rs`; `src\mxc-sdk\src\core\mxc_common\mod.rs`; `src\mxc-sdk\src\core\mxc_pty\mod.rs` | Extract the existing worker-local SIGPIPE mask unchanged for neutral reuse |
| Modify | `docs\development\build-and-test\ci-validation-infrastructure.md` | Document offline gate scope, native evidence, and artifact isolation |
| Create | `docs\backends\w365-agents\w365-agents.md`; `docs\backends\w365-agents\qualification.md`; `tests\scripts\run_w365_agents_native_preview_tests.ps1` | Native-preview contract, limitations, authorized qualification |
| Modify | `.github\copilot-instructions.md`; `docs\schema.md`; `docs\development\architecture\versioning.md`; `docs\development\build-and-test\schema-codegen.md` | Directly related architecture, dev-root, build, and generation references |

The legacy file donor is `src\backends\w365agents\common\src` at the pinned legacy SHA. Reuse its compatible clients, codec, validated IDs, metadata and redaction, adapting imports to the consolidated package. Do not copy its crate/build scaffolding, global relay, completed null-pipe process, no-op terminator, raw audit printing or fabricated `-1` exit.

Execution adds the primary GitHub build callers to the CI file map: those reusable
jobs also feed scheduled validation. One shared offline script avoids five copied
test runners and uses the repository's existing nonempty/required-test result
gate. It does not add W365 artifacts or authorize live qualification.

`src\mxc-sdk\src\core\mxc_common\exec_stream.rs`, `state_aware_backend.rs`, `process_util.rs`, and `interruptible_reader.rs` are reuse/reference targets. Keep the existing process adapter and lifecycle traits unchanged. Any newly required shared helper must be narrowly justified; backend-specific machinery stays in W365.

**Phased Implementation Plan**

#### Phase 1: Fresh-main foundation and local I/O feasibility

**Goal:** Establish an isolated, compiling package landing zone and prove the private-pipe cancellation assumptions before depending on them.

- [x] **P1.1** Create an isolated branch from the recorded main baseline using `using-git-worktrees`; preserve the legacy branch, bundle, patch and unrelated `.serena`, carry the plan and frozen design/approval artifacts into the execution context, and record the actual base SHA/relevant delta.
- [x] **P1.2** Add disabled-by-default `w365_agents`, optional TLS/client dependencies and optional `mio` v1 (`net`, `os-poll`) in `src\mxc-sdk\Cargo.toml`; forward the feature only through `wxc` and `mxc_ffi`, declare the backend module, and update the lockfile without changing edition/toolchain.
- [x] **P1.3** Add private standard-pipe/worker helpers in `exec\pipes.rs` and its platform files; own every endpoint and cancellation resource, reuse Unix `InterruptibleReader`, and target Windows synchronous I/O through each worker's owned thread HANDLE.
- [x] **P1.4** Exercise real blocked read/write and cancel-before-I/O races in an owned child-test process with a parent watchdog; prove the active/cancelled gate prevents new I/O, retries issuance races, and permits joining every worker without detached threads or host-stdio mutation.
- [x] **P1.5** Implement/test the Windows Relayed-input classifier: absent/closed stdin, synchronous PIPE, positively identified `\Device\Null`, console, disk, other character device, and failed object-name query; do not consume input or infer NUL from failed `GetConsoleMode`. The user approved explicitly rejecting overlapped pipes for this preview; prove synchronous file mode and read access before accepting a pipe.
- [ ] **P1.6** Compile feature-on/off native packages and run the pipe/classification tests on supported Windows/Linux/macOS hosts; stop for redesign if supported stock-pipe cancellation or owned cleanup cannot be demonstrated.

**Gate:** No transport/live-process implementation proceeds on an unproven worker-cleanup assumption. A watchdog failure, leaked worker, zero selected tests, or skipped supported-host case is not a pass.

#### Phase 2: Development exact contract and neutral lifecycle inputs

**Goal:** Recognize W365 natively without broadening supported SDK contracts or losing phase-config presence.

- [ ] **P2.1** Add internal containment with wire name `w365_agents` and redacted concrete neutral phase inputs in `models.rs`/`state_aware_operation.rs`; retain later-phase IDs plus optional W365 input, initialize existing callers/adapters with None, and keep these types transport-independent.
- [ ] **P2.2** Update compiler-required containment/operation matches together: ID/prefix routing, remote Windows command context and secret-free config projection; use explicit unavailable dispatch until the runner is wired, never temporary successful handles, erased phase blocks or whole-config serialization.
- [ ] **P2.3** Add `W365AgentsProvisionRequest` and its closed provision block with explicit `poolId` or `poolDiscovery: "signedInHuman"`; reject unsupported provision filesystem/network/UI sections and do not add session-only roots.
- [ ] **P2.4** Extend the existing Start/Exec/Stop/Deprovision roots with closed `OptionalField` W365 blocks; adapt them to neutral inputs with absent `None`, present-empty `Some(empty)`, and explicit-null/unknown-field rejection.
- [ ] **P2.5** Extend `registry.rs` with exactly one `w365_agents_provision` request root; register its valid/invalid fixture directories and extend the four existing phase corpora rather than inventing four additional dispatch roots.
- [ ] **P2.6** Reject any present W365 block in other backends' unit-config binding; implement/test the `SdkStateAwareInput::new` and typed test-dispatch authoring guards with `malformed_request`, preserving raw inputs without exposing a public W365 SDK variant.
- [ ] **P2.7** Add exact-parser/version-boundary tests for both valid selector shapes, config presence, wrong backend/phase, malformed IDs, required wire inputs, null/unknown fields and unsupported roots; put semantic selector/auth/policy failures in backend validation tests rather than mislabeling wire-valid JSON as schema-invalid.
- [ ] **P2.8** Regenerate the development schema and TypeScript oracle using `mxc_schema_gen`; pass descriptor/fixture/drift/version gates with published artifacts and SDK major targets unchanged.

**Gate:** Feature-off parsing remains exact and transport-independent. Existing v0.9/v1.0 tests pass; no stable schema, published contract or curated v1 authoring surface changes. Finish all compiler-required exhaustive matches/constructors in this phase, rather than leaving a broken build until Phase 6. The contract-only intermediate state is explicitly unavailable for execution.

#### Phase 3: Validated pool selection and cloud lifecycle

**Goal:** Preserve the cloud lifecycle while making selection, validation, compensation and observability fail closed.

- [ ] **P3.1** Port compatible `config.rs`, `id.rs`, `secret.rs`, `http.rs`, `cp.rs`, `dp.rs`, and `metadata.rs` into the new backend; preserve complete endpoint/token trust-source pairing, bounded service behavior, TLS verification and credential-redacted diagnostics.
- [ ] **P3.2** Add a private, fallibly constructed GUID `PoolId`, explicit/discovery selection, and request-scoped `PoolResolver` seam; keep default concrete-runner construction with discovery unavailable, bypass discovery for explicit pools, and introduce no global human context/cache or agent-token authorization.
- [ ] **P3.3** Expand all phase validators through shared local helpers for required provision config, strict IDs, selector exclusivity, resolver availability, coordinates/token pairing, API versions, capability, shell and command; dry-run performs no discovery/SM/ARI/DesktopControl calls.
- [ ] **P3.4** Add `policy.rs` with exhaustive current `ContainerPolicy` destructuring, all five skipped fields and explicit UI/network presence checks; preserve original env presence and accept only `env: None` plus `inherit_default_env: false`, rejecting even an explicitly empty env before submission.
- [ ] **P3.5** Implement provision/start/stop/deprovision: SM checkout, bounded ARI readiness, direct descriptors, strict pinned `w365:<poolGuid>:<computerGuid>` IDs, `releaseRequested` plus `restartable: false`, and verified already-released handling; never rediscover after provision or imply completed reclamation.
- [ ] **P3.6** Add compensation after a 2xx `Succeeded` checkout with verified GUID session ID and a present invalid/conflicting computer ID; preserve absent-computer fallback, attempt at most one 10-second release, retain the primary `possiblySucceeded: true, retryable: false` failure, and distinguish `releaseAttempted`/`releaseRequested` including immediate SessionNotFound.
- [ ] **P3.7** Add loopback/fake-client tests for neither/both selectors, invalid explicit input never invoking discovery, zero-I/O dry-run/unavailable discovery, invalid resolver results, concurrent human contexts, trust/header injection, no blind checkout retry, bounded readiness/compensation, verified idempotence, redaction and metadata.

**Gate:** Successful explicit provisioning is preserved; unavailable discovery fails before checkout. No claimed local policy enforcement on the existing Cloud PC, no invented identity, no success-shaped release fallback.

#### Phase 4: Wakeable framed transport

**Goal:** Build a bounded, nonblocking, single-owner transport/protocol core that remains responsive to control and deadlines.

- [ ] **P4.1** Port the compatible frame/payload codec into `exec\frame.rs` and `payload.rs`; retain big-endian lengths, 64-KiB payload cap, frame values and non-PTY mode, validate before allocation, and never derive remote env from caller-host variables.
- [ ] **P4.2** Implement `transport.rs` with one `mio` socket/`rustls::ClientConnection` owner and `Waker`; handle partial I/O and `wants_write`, drain decrypted plaintext, cap TLS/plaintext/header staging, and feed post-101 suffix bytes directly into the frame accumulator.
- [ ] **P4.3** Implement one monotonic 30-second connect/TLS/upgrade/entire-START-flush budget, a separate 30-second STARTED wait after flush, and the millisecond workload deadline starting after flush; trickled traffic never renews these deadlines.
- [ ] **P4.4** Add the 16-by-64-KiB stdin channel and independent cancel/shutdown wakeup; drop the sole receiver on shutdown to wake blocked senders and send STDIN_CLOSE only after true EOF and STARTED.
- [ ] **P4.5** Add independent 8-MiB stdout/stderr queues with nonblocking enqueue and bounded driver work batches; overflow or broken pipe latches failure and requests cancellation rather than truncating data or starving control.
- [ ] **P4.6** Implement the single-result state machine in `driver.rs`: EXIT is provisional until bounded output drain, drain/confirmation budgets are fixed at 5 seconds, errors outrank later EXIT(0), and EOF/ERROR/socket close/accepted CANCEL do not fabricate termination.
- [ ] **P4.7** Add deterministic clock/barrier and local TLS-peer tests for fragmented/coalesced frames, unknown/oversized/misordered frames, partial START, upgrade leftovers, sustained output, blocked stdin, no post-101 exec replay, fixed deadlines, and ordinary signed/124 exit codes.

**Gate:** Protocol and boundedness tests run without live services. Test trust roots stay test-local; no production TLS bypass, blocking shared TLS mutex, unbounded queue or per-read timeout renewal.

#### Phase 5: Live process ownership and cancellation

**Goal:** Return a genuinely live existing `ExecHandle` and make stream, terminate, wait and Drop ownership correct.

- [ ] **P5.1** Add `RemoteExecSession` in `exec\mod.rs`, connecting Phase 1 private workers/pipes to Phase 4 driver; hand out stdin-writer/stdout-reader/stderr-reader endpoints, never a completed null-pipe process.
- [ ] **P5.2** Keep owned endpoint originals valid through main's handle duplication and immediate EXIT; implement the idempotent owned stdin-close slot and account for every writer/read alias before assuming EOF or EPIPE.
- [ ] **P5.3** Connect terminate/Drop to independent driver wakeup and private-worker cancellation; observe completion before joins, cover cancel after EXIT while output is blocked, close every resource, and never release the checkout implicitly.
- [ ] **P5.4** Enforce preview stdio modes before connect: cross-platform Piped, Windows Relayed PIPE/NUL/absent input through the shared classifier, and explicit unsupported non-Windows Relayed, console/disk/unknown input and PTY errors.
- [ ] **P5.5** Integrate completion mapping: normal signed exits remain exits; only a winning workload deadline plus qualified remote confirmation permits Piped TimedOut; Relayed timeout and unconfirmed cancellation remain explicit backend errors.
- [ ] **P5.6** Stress fast EXIT, binary-separated stdout/stderr, stdin EOF/extra aliases, abandoned consumers, output below and above queue caps, kill/drop in every worker state, blocked output after EXIT and cancel-before-issuance; require bounded completion and zero outstanding workers/handles.
- [ ] **P5.7** Verify the live handle through the unchanged existing process adapter in backend unit tests: concurrent binary stdout/stderr collectors, early stdin closure, wait/kill/Drop, and clean EOF; diagnostics never enter workload streams.

**Gate:** `ExecSandboxProcess` and `StatefulSandboxBackend` remain unchanged. A queued CANCEL alone, fabricated exit, detached worker, or successful mock is not proof of target-side process-tree termination.

#### Phase 6: Engine, CLI, identity and regression integration

**Goal:** Wire the completed backend into native surfaces without leaking a supported public SDK promise.

- [ ] **P6.1** Add canonical backend registration with feature/experimental availability checks and `ProbeCoverage::NotDetected`; test recognized feature-off requests return `backend_unavailable`, not unknown/fallback, and fail unsupported one-shot/session-only dispatch explicitly.
- [ ] **P6.2** Add the dedicated binder and raw lifecycle/attached/process dispatch using concrete phase inputs and preserved metadata; keep Windows-only typed metadata helpers gated and Phase 2 authoring guards intact, covering raw native/FFI boundaries in `tests\w365_agents.rs`, `tests\state_aware.rs` and FFI tests.
- [ ] **P6.3** Verify Phase 2's `backend_from_prefix`, `state_aware_containment_from_id`, `CommandSource::state_aware_backend` and `CommandLineContext::for_backend` changes through native/CLI paths; test remote Windows cmd/PowerShell argument handling from every caller OS.
- [ ] **P6.4** Verify Phase 2's allowlist projection through full requests: Null for four non-exec configs and default-equivalent capability/shell for exec; rotating/removing credential/identity/discovery/endpoint/API/timing inputs must preserve hashes, while a non-default behavior selector must change them.
- [ ] **P6.5** Carry optional request correlation through raw/attached/process dispatch and Windows CLI into per-dispatch clients, preserving a no-context wrapper; test concurrent-request isolation, omit disabled/empty MS-CV, reject header controls and retain independent MXC telemetry consent.
- [ ] **P6.6** Add isolated Windows/Linux/macOS feature-on/off native and FFI CI coverage, Windows CLI shared-classifier dry-run coverage, and existing-backend regressions; do not add Linux/macOS lifecycle CLI flags or publish feature-enabled release artifacts before qualification.
- [ ] **P6.7** Add/update the mapped native-preview, schema, versioning, codegen and contributor docs with exact build/config examples, all env/stdio/SDK/discovery limits and not-yet-qualified status; preserve stable APIs, artifacts and package versions.

**Gate:** Exact-contract, raw metadata, hash/correlation, dry-run and compatibility checks pass. No full-config serialization in policy hashes, process-global current CV/user, public callback, stable W365 SDK authoring or cross-platform CLI overclaim.

#### Phase 7: Authorized live qualification and preview readiness

**Goal:** Produce target-specific evidence for the implemented preview, or report a clear release-blocked result.

- [ ] **P7.1** Write the qualification script/runbook requiring a freshly built binary, local untracked provision-config path, isolated authorized target and external evidence directory; obtain explicit authorization before setup/service actions and never auto-run the prototype bring-up scripts.
- [ ] **P7.2** Verify explicit-pool checkout, strict pinned identity, bounded start/readiness, direct descriptors, repeated terminal release and unavailable discovery; remote exec cancellation/disconnect must not release the checkout.
- [ ] **P7.3** Verify default remote Windows environment, local rejection of custom/empty/overlay env, separate binary output, cmd/PowerShell quoting, piped Python stdin/EOF, ordinary nonzero/124 exits, and the documented host-stdin restrictions.
- [ ] **P7.4** Qualify cancel, disconnect and timeout using target-side foreground/descendant identity evidence, including creation identity to exclude PID reuse; exercise actual supported-host blocked-pipe/Drop cleanup and fail the affected capability when termination cannot be proved.
- [ ] **P7.5** Archive redacted client SHA, contract, host, target/service build when available, region, scenario results and observer evidence; missing credentials/authorization/target evidence is BLOCKED or NOT RUN, never a SKIP-shaped pass, and deployment changes invalidate prior qualification.
- [ ] **P7.6** Run final code review and independent acceptance verification, reconcile every checklist item with its evidence, and change preview readiness documentation only when offline and required live gates actually pass.

**Gate:** No readiness claim from design GREEN, loopback mocks, stale prototype binaries, merged-output smoke tests, caller capability flags or absent descendant evidence.

**Progress Tracking**

**Task status:**

- [x] P1.1 - Isolate the fresh-main implementation branch and preserve the donor/workspace.
- [x] P1.2 - Add optional feature/dependencies and native forwarding.
- [x] P1.3 - Add owned private-pipe cancellation helpers.
- [x] P1.4 - Prove real blocked-I/O cancellation with a child watchdog.
- [x] P1.5 - Classify Windows Relayed input without consuming it.
- [ ] P1.6 - Pass supported-host foundation/feature gates.
- [ ] P2.1 - Add feature-independent neutral W365 lifecycle inputs.
- [ ] P2.2 - Complete exhaustive matches, routing, safe projection and unavailable staging.
- [ ] P2.3 - Add the closed development provision request.
- [ ] P2.4 - Extend four shared phase blocks with exact presence.
- [ ] P2.5 - Register the single new root and fixture corpus.
- [ ] P2.6 - Reject cross-backend blocks and typed authoring.
- [ ] P2.7 - Add exact-version and malformed-request fixtures.
- [ ] P2.8 - Regenerate artifacts and pass drift/version gates.
- [ ] P3.1 - Port compatible service/config/identity modules.
- [ ] P3.2 - Add validated pool selection and unavailable request-scoped discovery.
- [ ] P3.3 - Share complete local validation and enforce zero-I/O dry-run.
- [ ] P3.4 - Exhaustively reject unsupported current policy/env states.
- [ ] P3.5 - Implement faithful cloud lifecycle and metadata.
- [ ] P3.6 - Add bounded verified-identity compensation.
- [ ] P3.7 - Verify lifecycle, trust, discovery, concurrency and uncertainty faults.
- [ ] P4.1 - Port bounded framing and native START payload.
- [ ] P4.2 - Add single-owner wakeable TLS transport.
- [ ] P4.3 - Enforce monotonic startup/STARTED/workload deadlines.
- [ ] P4.4 - Bound stdin and keep control independent.
- [ ] P4.5 - Bound outputs and prevent control starvation.
- [ ] P4.6 - Implement latched completion/error/drain state.
- [ ] P4.7 - Verify protocol, TLS-peer and deadline faults.
- [ ] P5.1 - Connect the live session to existing ExecHandle.
- [ ] P5.2 - Preserve handoff ownership, aliases and explicit EOF.
- [ ] P5.3 - Complete terminate/Drop with joined local workers.
- [ ] P5.4 - Enforce Piped/Relayed/PTY mode limits before connect.
- [ ] P5.5 - Map exits, timeout and cancellation uncertainty honestly.
- [ ] P5.6 - Stress stream, handoff, queue and cleanup races.
- [ ] P5.7 - Verify the unchanged live-process adapter and concurrent collectors.
- [ ] P6.1 - Register availability/probe and unsupported-dispatch behavior.
- [ ] P6.2 - Wire dedicated binding and raw metadata-preserving dispatch.
- [ ] P6.3 - Verify ID routing and remote Windows command context.
- [ ] P6.4 - Verify canonical secret-free policy projection and hash sensitivity.
- [ ] P6.5 - Propagate request-local consent-respecting correlation.
- [ ] P6.6 - Add isolated cross-host native/FFI/CLI regression coverage.
- [ ] P6.7 - Document native scope and exact preview limitations.
- [ ] P7.1 - Prepare and authorize isolated live qualification.
- [ ] P7.2 - Verify real cloud lifecycle and pinned identity.
- [ ] P7.3 - Verify real remote execution/input/output/env limits.
- [ ] P7.4 - Prove cancellation/timeout/descendant and host-worker cleanup.
- [ ] P7.5 - Archive identity-aware deployment-specific evidence.
- [ ] P7.6 - Complete independent review/verification before readiness.

**Completed:**

- [x] Preserve and compare the legacy branch against main; retain the verified bundle/patch.
- [x] Obtain architect, ms-rust-pro and adversarial-critic GREEN on identical revision 3.
- [x] Obtain user approval to proceed to implementation planning.
- [x] Refresh main and inspect the two-commit planning-baseline delta without changing product source.

**Dependencies & Notes**

#### Sequencing and stop conditions

```text
                    +-> Phase 2 -> Phase 3 --+
Plan -> Phase 1 -----+                       +-> Phase 5 -> Phase 6 -> Phase 7
                    +-> Phase 4 ------------+
```

Phase 4 may proceed independently of contract/lifecycle work once Phase 1 passes. Phase 5 needs the contract inputs, service/config boundary and transport core. Phase 7 additionally needs explicit target authorization and operator/observer access; planning approval does not grant these.

Arrange target/operator availability alongside the early offline work rather than discovering the prerequisite only at release. Missing access does not block honest offline development, but it does block the corresponding live qualification and readiness claim.

Each implementation task starts with a failing, named acceptance test, confirms its intended failure, makes the minimal change and reruns the smallest relevant gate. Prefix new cross-cutting tests with `w365_` so filtered runs select them. Record actual test counts; zero matches and excluded required cases fail a gate. Existing private-module tests stay near their modules; public/raw-boundary tests use `tests\`.

Commit coherent passing slices with explicit file staging; never amend or sweep unrelated work into a commit. Follow the session's commit-trailer requirements if commits are authorized during execution. Do not commit secrets, qualification credentials, `.serena`, or evidence containing authorization headers/descriptors. Do not force a commit boundary through uncompilable enum/binder changes.

If a local cleanup assumption fails, stop before building the live bridge and return the evidence for a narrow design revision. If service cancellation/tree cleanup fails qualification, leave the affected preview capability release-blocked; local socket closure is not a substitute.

#### Exact validation commands

Run from the fresh implementation worktree root. These commands are planned gates, not claimed results. Use the repository-pinned toolchain, and restore dependencies only after a selected command reports missing dependencies or a manifest change requires it.

Schedule gates by their prerequisites: Phase 1 checks native package builds and feature-on private-pipe/classifier tests; feature-off W365 neutral tests and exact-contract/codegen gates start after Phase 2. The new `--test w365_agents` target and Windows CLI W365 tests are required after Phase 6 integration, not before those targets/tests exist. Final validation is cumulative.

| Gate | Command | Required result |
|---|---|---|
| Feature-independent native packages | `cargo check --manifest-path src\Cargo.toml -p mxc-sdk -p mxc_ffi --no-default-features --all-targets` | Exit 0; no transport dependency required by neutral/exact types |
| Feature-on native packages | `cargo check --manifest-path src\Cargo.toml -p mxc-sdk -p mxc_ffi --no-default-features --features w365_agents --all-targets` | Exit 0; optional forwarding and native compilation agree |
| W365 unit tests, feature off | `cargo test --manifest-path src\Cargo.toml -p mxc-sdk --no-default-features --lib w365` | Exit 0; nonzero neutral/routing/guard test count |
| W365 unit tests, feature on | `cargo test --manifest-path src\Cargo.toml -p mxc-sdk --no-default-features --features w365_agents --lib w365` | Exit 0; nonzero supported-host pipe, codec, client and driver tests |
| Exact contracts | `cargo test --manifest-path src\Cargo.toml -p mxc-sdk --no-default-features --test mxc_contract_v0_9_0_alpha --test mxc_contract_v1_0_0 --test mxc_contract_v1_1_0_alpha --test mxc_contract_version_boundaries` | Existing contracts unchanged; new development corpus passes |
| Native boundaries | `cargo test --manifest-path src\Cargo.toml -p mxc-sdk --features w365_agents --test state_aware --test w365_agents` | Exit 0; actual raw/error/metadata/authoring assertions |
| FFI, feature off | `cargo test --manifest-path src\Cargo.toml -p mxc_ffi --no-default-features --lib --test ffi` | Existing unit/ABI boundary regressions pass |
| FFI, feature on | `cargo test --manifest-path src\Cargo.toml -p mxc_ffi --no-default-features --features w365_agents --lib --test ffi` | New native W365 coverage passes without new ABI/status codes |
| Windows CLI compilation, off/on | `cargo check --manifest-path src\Cargo.toml -p wxc --no-default-features --all-targets`; `cargo check --manifest-path src\Cargo.toml -p wxc --no-default-features --features w365_agents --all-targets` | Run on Windows; both native configurations compile |
| Windows CLI assertions | `cargo test --manifest-path src\Cargo.toml -p wxc --no-default-features --features w365_agents w365` | Run after Phase 6 on Windows; nonzero dry-run/input/quoting assertions pass |
| Development schema | `cargo run --manifest-path src\Cargo.toml -p mxc_schema_gen -- schema --version 1.1.0-alpha --out schemas\dev\mxc-config.schema.1.1.0-alpha.json` | Generated current exact contract |
| Development wire oracle | `cargo run --manifest-path src\Cargo.toml -p mxc_schema_gen -- types --version 1.1.0-alpha --out sdk\node\src\generated\v1_1_0_alpha\wire.ts` | Generated oracle only; no supported public SDK authoring addition |
| Contract drift/fixtures | `node scripts\versioning\check-contract-codegen.js` | Exit 0; roots, exact artifacts, fixture/schema agreement and published history pass |
| Versions | `node scripts\versioning\check-schema-versions.js`; `node scripts\check-version-sync.js` | Exit 0; no package/contract promotion |
| Formatting | `cargo fmt --manifest-path src\Cargo.toml --all -- --check` | Exit 0 |
| Feature-on lint | `cargo clippy --manifest-path src\Cargo.toml -p mxc-sdk -p mxc_ffi --all-targets --features w365_agents -- -D warnings` | Exit 0 on supported native hosts |
| Feature-off lint | `cargo clippy --manifest-path src\Cargo.toml -p mxc-sdk -p mxc_ffi --all-targets --no-default-features -- -D warnings` | Exit 0 |

The cross-platform CI gate executes native builds/tests on Windows, Linux and macOS; compiling a cross target on Windows is not Unix runtime evidence. Put feature-on verification in a separate target directory so it cannot overwrite feature-off artifacts subsequently published by an existing job. Keep live credentials out of CI.

The live script's mandatory inputs are the fresh binary path, local provision-config path and evidence directory. The runbook requires separately authorized target-side observation before cancellation/timeout assertions. It must exit unsuccessfully with an explicit blocked/not-run record when these prerequisites are missing, not report a passing skipped suite.

#### Coverage anchors

| Approved design requirement | Implementing tasks |
|---|---|
| Native-only delivery, optional feature, consolidated package | P1.1-P1.2, P2.1, P6.1-P6.2, P6.6-P6.7 |
| Exact development roots, presence, fixture/codegen authority | P2.3-P2.8 |
| Typed binding, raw metadata, public SDK guard | P2.1, P2.4, P2.6, P6.2 |
| Cloud lifecycle authority, IDs, missing-computer fallback, compensation | P3.1, P3.5-P3.7, P7.2 |
| Human discovery seam, unavailable production resolver, identity isolation | P3.2-P3.3, P3.7 |
| Policy presence/env/trust validation and zero-I/O dry-run | P1.5, P3.1-P3.4, P3.7, P5.4, P6.6 |
| Existing errors, secret-free hash, local correlation and consent | P2.2, P3.1, P3.6-P3.7, P4.6, P5.5, P6.4-P6.5 |
| Live pipes, alias ownership, stock-pipe cancellation, bounded teardown | P1.3-P1.6, P5.1-P5.3, P5.6-P5.7 |
| Single TLS owner, protocol/order/size, startup and execution deadlines | P4.1-P4.3, P4.6-P4.7 |
| Bounded stdin/output, control fairness, latched drain/cancel failures | P4.4-P4.7, P5.3, P5.5-P5.6 |
| Explicit platform/stdio/PTY limitations | P1.5, P5.4, P6.3, P6.6-P6.7, P7.3 |
| Actual deployment/descendant evidence, no unsafe helper automation | P7.1-P7.6 |

#### Execution status

The implementation branch is `users/vishnu/w365-native-preview`, based on
`ffecec04357747d6649714f473436dfb77111be8`. The legacy checkout remains untouched.
The frozen design and approval record are unchanged.

P1.1-P1.5 are implemented. P1.6 is blocked on native macOS evidence; Phase 1 is
not complete. The private pipe and classifier modules remain test-only until
their production consumers exist.

The shared offline entry point now passes on native Windows x64 and Ubuntu-24.04
WSL x64. Each run checks feature-off/on compilation of mxc-sdk and mxc_ffi,
plus wxc on Windows, in an isolated target directory. The Windows pipe suite
passed 12 tests and the Linux suite passed seven, each with one intentionally
ignored child entry executed by the watchdog-owning parents. Required passing
test names and every successful child marker were checked.

Coverage includes blocked read/write, cancellation before I/O, binary data/EOF,
broken output, late cancellation, 256 destruction/cancellation iterations, and
watchdog kill/reap. Windows additionally proves cancellation retries after a
deliberately missed pre-kernel issuance attempt. Input probes preserve bytes,
require both synchronous mode and read access, and reject real write-only and
overlapped pipe endpoints, disk files and consoles. NUL requires exact native
identity. Other-character/query-failure cases use injected identification
evidence, not serial-hardware testing.

The user's "reject-for-preview" decision remains the narrow clarification of
the frozen PIPE row. It does not authorize asynchronous input. CLI preflight
integration remains a later task; no runtime backend is exposed yet.

Strict feature-off/on clippy passed on Windows and Linux. Earlier regression
runs recorded 2,716 passing default-off Windows library tests, and 57 passing
Linux pipe/shared-reader/PTY tests. The full Linux default-off run was not green:
two missing-command failures pass with a Linux-only PATH; the third conformance
fixture failure was reproduced on an archived, unchanged execution baseline.
No unrelated assertions or fixtures were changed.

All five CI callers parse as YAML; the shared script parses as PowerShell.
The shared result-oracle regression scenarios pass on Windows and Linux.
The initial Windows gate caught interleaved `--nocapture` output; using
`--show-output` preserves both exact result lines and child markers. A deliberate
native-host mismatch is rejected before creating build outputs. No GitHub or
Azure pipeline execution is claimed, including ARM64 jobs.

Native macOS compilation and pipe cleanup remain NOT RUN. Adding a macOS CI
caller or checking its documented runner architecture does not satisfy P1.6.
No contract, cloud lifecycle, transport or live-process implementation has
started. Publishing this foundation branch is authorized so native CI can run;
it does not complete Phase 1 or authorize W365 credential acquisition, live
service calls or target-host setup.

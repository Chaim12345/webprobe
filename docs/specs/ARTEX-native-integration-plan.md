# ARTEX native integration: implementation plan

Status: implementation plan, not implemented code. Date: 2026-11-22.
Companion document: the design proposal in PR #122 (`docs/specs/ARTEX-native-agent-design.md`, branch `team/artex-agent-design-20261122`). This plan turns that design into ordered milestones and runnable build lanes. Where this plan and the design disagree on approval behavior, this plan reflects the owner's 2026-11-22 steering (section 1) and supersedes the design's strict per-step approval requirement.

Pinned source revisions, verified against live clones on 2026-11-22:

- WebProbe: `parity/2026-11-17` at `7be2efd44949006526df1ea3616290d9979e67c6`. All WebProbe PRs below target this branch. Master is never touched.
- ARTEX: `Chaim12345/artex-rs` (private, AGPL-3.0-only), `main` at `e4652336583acb9cd388fe8c85ea496c14a9bd78` (M86). All ARTEX PRs below target `main`.

## 1. Owner decisions applied

Decisions communicated by the owner on 2026-11-22 and applied throughout this plan:

1. Local-first desktop integration before any team server.
2. Personal BYOK provider keys first; server-managed keys later, separately authorized.
3. **Per-step human approval is dropped for the WebProbe integration.** The agent executes its proposed tool calls directly. No approval cards, no per-request gate, no auto-approve machinery is needed either, because nothing asks.
4. No evasion, stealth, WAF-bypass capability added by this integration.
5. Tests use local owned fixtures only.
6. Include an ACP option: ARTEX exposed as an Agent Client Protocol agent so editors and WebProbe's own UI can drive it (section 3).

Open decision, flagged, not decided here: ARTEX is AGPL-3.0-only and WebProbe has no root license file. Linking `artex-kernel` into the WebProbe binary creates AGPL obligations for the combined work, and AGPL section 13 applies to network service use. Section 9 tracks this as M0; nothing in this plan resolves it.

Optional safety rails, listed for the owner, none of them required by this plan:

- **Scope-only sends.** Agent network sends pass the existing `net::in_scope` check, so the agent stays inside the target scope the user already configured. One function call in the send tool.
- **No shell, ever.** The integration only registers the typed WebProbe tools in section 5. ARTEX's `BashTool` and default dispatcher are never linked. This is inherent to the design, not a feature to build; listing it so it is a conscious choice.
- **Per-task budgets.** Turn, token, request-count and wall-time caps per agent task, already in ARTEX's `Budget` type. Cheap and independent of approval UX.
- **Approval as a later toggle.** The kernel keeps a single `PolicyGate` hook (section 5.1). If the owner later wants "ask me before sends," it plugs in without a refactor.

## 2. What ACP is, verified

Parent hypothesis checked against the official specification at agentclientprotocol.com (fetched 2026-11-22, sources in section 11): ACP is the Agent Client Protocol, a JSON-RPC protocol standardizing communication between code editors ("clients") and coding agents ("agents"). The hypothesis is correct; no misreading found. Verified facts that shape this plan:

- **Transport.** The only stable transport is stdio: the client launches the agent as a subprocess and exchanges newline-delimited JSON-RPC. A Streamable HTTP / WebSocket transport is an RFD (draft), not shipped. Custom transports are allowed but must preserve the JSON-RPC message format.
- **Versions.** v1 is the documented stable protocol. v2 is a draft family of RFDs; the v2 Permission Requests RFD moved to Preview on 2026-11-20. Target v1 now; design so v2 is a drop-in schema upgrade.
- **Permission requests.** The agent may call `session/request_permission` with option kinds `allow_once`, `allow_always`, `reject_once`, `reject_always`; the client answers `selected` or `cancelled`. Under decision 3 this mechanism is optional for us, not the backbone of the integration.
- **Rust support.** An official `agent-client-protocol` crate implements both sides of the protocol.
- **Extensibility.** Optional `_meta` fields can carry WebProbe-specific metadata such as evidence IDs.

## 3. What ACP can and cannot do for this integration

From the spec's own Security Considerations page and tool-call guidance:

ACP **can**:

- Give ARTEX a standard agent surface: any compliant client (Zed-class editors, or WebProbe's desktop acting as a client) can start sessions, send prompts, and watch tool calls stream by as `session/update` notifications with `pending` / `in_progress` / `completed` / `failed` states.
- Carry plans, tool-call titles, kinds and content, so one protocol serves both the WebProbe Agent workspace and external editors.
- Carry WebProbe metadata (evidence IDs, project/task IDs) in `_meta`.
- Offer permission prompts later, if the owner re-enables approvals, with no protocol change.

ACP **cannot**:

- **Enforce anything.** The spec is explicit that permission requests are advisory, the agent performs its own operations, and ACP does not sandbox the agent. Any real limit (scope, budgets) must live in the kernel and tools, not in the protocol. With per-step approval dropped this matters less, but it caps what "approval over ACP" could ever mean.
- **Prove a human answered.** Clients may automatically allow or reject permission requests per user settings. If approvals are ever re-enabled, only WebProbe's own UI is a trustworthy approver.
- **Provide a remote transport or identity, stably.** stdio only in v1; client identity is self-reported and not usable for security decisions. ACP is not the team-server channel.

Consequence for the plan: ACP is the agent-exposure layer in milestone M4. ARTEX runs as an `artex-acp` stdio subprocess; WebProbe's Agent workspace talks to the same kernel in-process, and optionally through ACP for parity with editors. ACP stdio's process separation is also a possible answer to the M0 license question, since the kernel contract is identical in-process and over stdio.

## 4. Verified file and crate map

Anchors below were read in the pinned checkouts, not inferred.

WebProbe (`app/` is the Cargo workspace root; members `["core"]`, default `[ ".", "core"]`):

| Area | Path | Key items |
| --- | --- | --- |
| History store | `app/core/src/history.rs` | `ProxyHistory` (line 13): `snapshot`, `with_rows`, `get(id)`; entries are `net::HistEntry` |
| Exchange record | `app/core/src/net.rs` | `HistEntry` (line 24); `in_scope` (line 308); `send_raw` (line 1350), `send_tls_raw` (line 1919) |
| Repeater state | `app/core/src/repeater_run.rs` | `RepeaterRun` generation/busy model (lines 17-93) |
| Repeater UI ops | `app/src/repeater_ops.rs` | `Service`, redirect/cookie helpers |
| AI chat | `app/core/src/ai.rs` | `AiChat` (line 20): `endpoint`, `model`, `api_key`, env fallbacks `WEBPROBE_AI_ENDPOINT`/`WEBPROBE_AI_KEY`, `complete` (line 105) |
| Project save | `app/core/src/project.rs` | `save` (line 1268): temp-file, fsync, atomic rename; background saver (line 1361) |
| Intruder run | `app/core/src/intruder_run.rs` | `start` (line 673), whole-job execution today |
| Scanner run | `app/core/src/scan.rs` | `start_active_scan` (line 895), whole-job execution today |
| Desktop wiring | `app/src/main.rs` | `ai: ai::AiChat` field (line 166), init (line 794) |
| Desktop UI | `app/src/ui.rs` | AI chat panel at line 4246 (`ai_chat` scroll area) |
| Core module list | `app/core/src/lib.rs` | `pub mod` lines 6-71 |

ARTEX (workspace root `Cargo.toml`, 12 member crates, `license = "AGPL-3.0-only"`):

| Area | Path | Key items |
| --- | --- | --- |
| Types | `crates/artex-types/src/lib.rs` | `Budget` (390), `Task` (573), `Finding` (254), `AuditEntry` (377) |
| Engine | `crates/artex-engine/src/lib.rs` | `ToolProposal` text format (39), `parse_proposal` line parser (49), `Engine<C: LlmClient>` (118) with concrete `artex_db::Store` + `artex_tools::Dispatcher` fields |
| Guard | `crates/artex-guard/src/lib.rs` | `Guard` (76), `evaluate` (120): rule/judge/timeout paths we simply do not link |
| Tools | `crates/artex-tools/src/lib.rs` | `Tool` trait (41), `Dispatcher::new` auto-registers `BashTool` (130); do not reuse |
| LLM | `crates/artex-llm/src/lib.rs` | `LlmClient` trait (53), `MeteredClient` (60); `openai.rs` `OpenAiCompat` |
| DB | `crates/artex-db/src/lib.rs` | concrete PostgreSQL/sqlx `Store` (78); not linked into the kernel |
| Fixture | `crates/artex-fixture` | local fixture crate, pattern to reuse for the M1 fixture |

## 5. Cross-lane contracts

These signatures are the contracts every lane codes against, so lanes proceed in parallel without negotiating interfaces. Names are new designs. Rust 2021, `serde` with `deny_unknown_fields`, `uuid` v7 IDs, `time` timestamps, all already in ARTEX's workspace dependency set.

### 5.1 `artex-kernel` (new crate in artex-rs)

```rust
// crates/artex-kernel/src/call.rs
pub enum ToolName { ProxyHistoryList, RepeaterSendOne, /* later variants added per milestone */ }

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub schema: u16,                    // 1
    pub task: TaskId, pub id: CallId,
    pub revision: u64,                  // monotonic per task
    pub tool: ToolName,
    pub args: serde_json::Value,        // size-capped (16 KiB), max depth 8
    pub target: Option<TargetOrigin>,   // scheme, host, port for network steps
    pub budget: StepBudget,             // response byte cap, wall-clock timeout
}

// crates/artex-kernel/src/ports.rs
pub trait AgentStore: Send + Sync {
    fn begin_task(&self, spec: &TaskSpec) -> Result<TaskId, KernelError>;
    fn record_call(&self, call: &ToolCall) -> Result<(), KernelError>;
    fn record_result(&self, id: CallId, outcome: &ToolOutcome) -> Result<(), KernelError>;
    fn events(&self, task: TaskId, after: u64, limit: u32) -> Vec<AgentEvent>;
}

#[async_trait]
pub trait ModelPort: Send + Sync {
    /// One bounded completion. No retries inside the port; the kernel budgets retries.
    async fn complete(&self, req: ModelRequest) -> Result<ModelResponse, KernelError>;
}

pub trait AgentTool: Send + Sync {
    fn name(&self) -> ToolName;
    fn execute(&self, call: &ToolCall) -> Result<ToolOutcome, KernelError>;
}

/// Optional rail (section 1). Default implementation allows everything.
/// A scope-checking or approval-asking policy plugs in here later with no refactor.
pub trait PolicyGate: Send + Sync {
    fn check(&self, call: &ToolCall) -> Result<(), KernelError>;
}
```

The kernel loop (`src/kernel.rs`) is one frontier turn: model proposes one schema-validated `ToolCall`, the policy gate checks it, the tool executes, the result is journaled, repeat until the task ends or a budget runs out. The kernel dependency closure excludes `sqlx`, any PostgreSQL driver, `artex-traffic`, `artex-server`, `artex-guard`, `artex-tools`, process spawning and raw sockets. `cargo tree -p artex-kernel` is the audit artifact. `src/store_memory.rs` provides `MemoryStore` for tests only.

### 5.2 `webprobe` agent module (new, feature-gated `agent`, default off)

```rust
// app/core/src/agent/coordinator.rs
pub struct Coordinator { /* kernel loop, journal, tool registry, budgets */ }
impl Coordinator {
    pub fn start_task(&mut self, goal: &str, ctx: TaskContext) -> Result<TaskHandle, AgentError>;
    pub fn stop(&mut self, task: TaskId);
    pub fn poll_events(&self, task: TaskId) -> Vec<AgentEvent>; // bounded, nonblocking, for the UI thread
}

// app/core/src/agent/capabilities.rs
pub struct ProxyHistoryListTool { /* read-only */ }   // impl AgentTool: metadata rows, page cap 50
pub struct RepeaterSendOneTool  { /* one send */ }    // impl AgentTool: exact bytes, one net::send_raw/send_tls_raw call
```

`RepeaterSendOneTool` rules: request bytes come from the call arguments as-is; no macros, session rules, redirects, retries or extension hooks run on the agent path; the response is recorded as a new history entry tagged to the agent task and its ID returned as evidence. If the owner picks the scope-only rail, one `net::in_scope` check is added here.

### 5.3 Journal and UI

`app/core/src/agent/journal.rs`: project-local append journal `<project>.agent.json` written through the same temp-file/fsync/atomic-rename discipline as `project::save` (line 1268), single-writer enforced by a lock file. It stores task metadata, tool calls, results and evidence IDs. Request/response bodies stay in the existing history store; the journal references IDs only.

`app/src/agent_ui.rs`: Agent workspace panel beside the AI chat. Shows task goal, model destination, budget counters, the running plan as a visible hypothesis, the tool-call timeline with results, and evidence links. Controls are Start, Stop, and Expand. There is no approval UI under decision 3.

## 6. Milestones

### M0: decisions and pins (no code)

- Resolve the AGPL-3.0 licensing strategy for combining ARTEX and WebProbe (open, owner decision). ACP stdio process separation (M4) is one candidate answer.
- Pin revisions: artex-rs `e465233`, webprobe `7be2efd`; record them in each PR body.
- Owner picks any optional safety rails from section 1; defaults ship without them except budgets, which are nearly free and already typed in ARTEX.
- Exit: decisions recorded; lanes start.

### M1: thin vertical slice (required first milestone)

Goal: an embeddable ARTEX kernel with a storage port (no PostgreSQL), typed read-only `proxy.history_list`, and a working `repeater.send_one`, driven by a mock model end to end against a local fixture, with results visible in a desktop Agent panel.

Repos and bases: artex-rs branch off `main`@`e465233`; webprobe branch off `parity/2026-11-17`@`7be2efd`.

New files, artex-rs:

- `crates/artex-kernel/Cargo.toml`, `src/lib.rs`, `src/call.rs`, `src/ports.rs`, `src/kernel.rs`, `src/store_memory.rs`, `src/tests.rs`.
- Root `Cargo.toml` members list and `Cargo.lock` (owned by lane L1 alone this wave).

New files, webprobe:

- `app/core/src/agent/mod.rs`, `errors.rs`, `coordinator.rs`, `journal.rs`, `capabilities.rs`, `tools/proxy_history.rs`, `tools/repeater_send.rs`, `fixture.rs` (`#[cfg(test)]` loopback HTTP fixture on `std::net`, fixed response, bound to 127.0.0.1).
- `app/core/src/lib.rs`: one `#[cfg(feature = "agent")] pub mod agent;` line (owned by lane L2).
- `app/Cargo.toml`: `agent` feature, `artex-kernel` git dependency pinned to the merged L1 revision, `Cargo.lock` (owned by lane L2).
- `app/src/agent_ui.rs`, plus wiring in `app/src/main.rs` (field + init, beside `ai` at lines 166/794) and `app/src/ui.rs` (new Agent tab beside the AI chat panel at line 4246). Owned by lane L3.

Tests:

- Kernel: call parsing rejects unknown fields and oversized payloads; mock-model loop runs a two-call task to completion; budget exhaustion stops the loop; store is mocked; dependency-closure audit (no sqlx/Postgres/traffic/server/guard/tools/process).
- WebProbe core: fixture end-to-end: scripted mock model calls `proxy.history_list`, gets capped metadata rows; then `repeater.send_one`, fixture receives the exact bytes, response recorded, evidence ID in the journal; journal survives a simulated restart.
- UI: panel renders the call timeline and result links; Stop cancels a running task; feature-off build has no Agent tab.

Acceptance: from `app/`, `cargo test --workspace --no-run`, `cargo test --workspace`, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, with `agent` on and off. Same suite in artex-rs. Feature-off build must not compile any agent code and the manual Proxy/Repeater flow is unchanged.

### M2: persistence, BYOK and budgets

WebProbe only, off `parity/2026-11-17` rebased on merged M1.

- `journal.rs`: full `AgentStore` implementation on the project journal; `store_memory.rs` stays test-only.
- `app/core/src/agent/provider.rs`: unify provider settings with `ai.rs` `AiChat` (one endpoint/model/key store); key moves to an OS credential-store reference with session-only fallback, never in project files, logs or model context; env-based legacy configuration cannot enable Agent mode.
- Redaction of `Authorization`, `Cookie`, `Set-Cookie`, bearer tokens and configured fields before any provider disclosure; synthetic preview.
- Budgets: per-task turns, tokens, wall time, request count, response bytes, provider retries, spend ceiling; fail closed on missing usage data.
- Tests: secret canary never appears in prompts/logs/exports; offline start makes zero network calls; budget exhaustion halts the loop mid-task.

### M3: drafts, reads and findings

- `proxy.exchange_read` with explicit ID and bounded slices; `repeater.prepare` draft service (UI-independent, returns draft ID and raw diff, no send); `findings.draft` creating unverified drafts referencing evidence IDs.
- Result entries in `agent_ui.rs` link to the actual Proxy exchange, Repeater draft and finding draft.
- Tests: cross-project evidence ID rejection; findings remain unverified until human confirmation.

### M4: ACP exposure

Repos: artex-rs branch off `main` (after L1 merges); webprobe branch off `parity/2026-11-17` (after M1 merges).

- New crate `crates/artex-acp` in artex-rs: an ACP agent over stdio using the official `agent-client-protocol` crate. Implements `initialize`, session setup, `session/prompt`, and `session/update` tool-call reporting. No permission requests are emitted under decision 3; the code path exists behind the `PolicyGate` hook for later.
- WebProbe side: `app/core/src/agent/acp_client.rs` lets the desktop drive a kernel subprocess over ACP stdio as an alternative to in-process linking, selected at build/run time. This is also the process-separation fallback for the M0 license decision.
- Files owned: artex-rs `crates/artex-acp/**`, root `Cargo.toml`/`Cargo.lock` (lane L7 owns them this wave); webprobe `app/core/src/agent/acp_client.rs` and `app/Cargo.toml` feature `agent-acp`.
- Tests: JSON-RPC conformance against the official ACP test harness if available, plus scripted client transcripts; session lifecycle (start, prompt, cancel, shutdown); v1 message shapes fixed so the v2 schema is a drop-in upgrade.

### M5: Intruder and Scanner tools (later, optional)

If the owner wants the agent to drive Intruder/Scanner: `intruder.prepare`/`intruder.send_next` against `app/core/src/intruder_run.rs` `start` (line 673), and `scanner.plan`/`scanner.send_next` against `app/core/src/scan.rs` `start_active_scan` (line 895), both as per-candidate step interfaces so the agent steers individual sends rather than opaque whole jobs. Not scheduled; the milestone exists so the tool enum and UI leave room.

### M6: team service (later)

Out of scope for scheduling until M1-M4 land and the design's section 9 conditions (identity, RBAC, worker enrollment) are resourced. No lanes defined here on purpose.

## 7. Build lanes

Each brief is runnable as-is. Rules for every lane: work in your own worktree; branch names and PR targets exactly as given; push after every commit; never touch master, existing PR branches, or files owned by another lane; run the acceptance commands and report verified numbers. Root `Cargo.toml` and `Cargo.lock` have exactly one owner per repo per wave, named below.

### Wave 1

**L1, ARTEX kernel.** Repo artex-rs, base `main`@`e465233`, branch `team/artex-kernel-20261122`, PR into `main`.
Owns: `crates/artex-kernel/**`, root `Cargo.toml`, `Cargo.lock`. Forbidden: every other crate, `.github/**`.
Build: section 5.1 exactly. No PostgreSQL, traffic, server, guard, tools or process dependencies. `MemoryStore` + mock model tests from the M1 test list.
Acceptance: full artex-rs workspace `test --no-run`, `test`, `fmt --check`, `clippy --all-targets -D warnings`; `cargo tree -p artex-kernel` attached showing the dependency closure.

**L8, governance.** Repo webprobe, base `parity/2026-11-17`, branch `team/artex-governance-20261122`, PR into `parity/2026-11-17`.
Owns: `docs/specs/ARTEX-licensing-review.md`.
Build: licensing options for the owner (AGPL compliance path vs ACP process separation; section 13 impact). Docs only; the lane makes no decision.

### Wave 2 (starts when L1's PR is open; pin L1's head SHA)

**L2, agent core slice.** Repo webprobe, base `parity/2026-11-17`, branch `team/agent-m1-core-20261122`, PR into `parity/2026-11-17`.
Owns: `app/core/src/agent/**`, the one `lib.rs` mod line, `app/Cargo.toml`, `app/Cargo.lock`. Forbidden: `app/src/**`, all existing core files except the `lib.rs` line.
Build: section 5.2 and the M1 core test list, including the fixture end-to-end. Feature `agent` default off.
Acceptance: M1 acceptance commands, feature on and off, verified numbers in the PR body.

**L3, Agent UI.** Repo webprobe, base `parity/2026-11-17`, branch `team/agent-m1-ui-20261122`, PR into `parity/2026-11-17`.
Owns: `app/src/agent_ui.rs`, `app/src/main.rs` (the two wiring spots only), `app/src/ui.rs` (the new tab only). Forbidden: `app/core/**`, manifests.
Build: section 5.3 against the `Coordinator` API in section 5.2; compile against L2's branch head. Visual check of the panel at small window and high DPI, screenshots attached to the PR.
Acceptance: same commands; manual Proxy/Repeater flow unchanged with the feature off.

### Wave 3

**L4, persistence and BYOK (M2).** Branch `team/agent-m2-byok-20261122`, owns `app/core/src/agent/{journal,provider,redaction,budget}.rs`, `app/core/src/ai.rs` (settings unification only), manifests. Forbidden: UI, tools.

### Wave 4

**L5, drafts and findings (M3).** Branch `team/agent-m3-drafts-20261122`, owns `app/core/src/agent/tools/{exchange_read,repeater_prepare,findings_draft}.rs`, `app/core/src/repeater_run.rs` (draft service seam only), result links in `app/src/agent_ui.rs`.

**L7, ACP (M4).** Two PRs, parallel with L5. artex-rs: branch `team/artex-acp-20261122` off `main`, owns `crates/artex-acp/**`, root manifest and lock. webprobe: branch `team/agent-m4-acp-client-20261122`, owns `app/core/src/agent/acp_client.rs` and the `agent-acp` feature. Build and tests per M4.

### Wave 5 (only if the owner asks for M5)

**L6a, Intruder tools.** Branch `team/agent-m5-intruder-20261122`, owns `app/core/src/agent/tools/intruder_*.rs`, `app/core/src/intruder_run.rs`, `app/core/src/intruder.rs`.

**L6b, Scanner tools.** Branch `team/agent-m5-scanner-20261122`, owns `app/core/src/agent/tools/scanner_*.rs`, `app/core/src/scan.rs`, `app/core/src/scan_run.rs`, `app/core/src/scan_config.rs`. L6a and L6b run in parallel; their files are disjoint and whichever lands second rebases the manifests.

## 8. Global acceptance evidence

Every code PR records: exact base and head revisions, toolchain, `cargo test --workspace --no-run`, `cargo test --workspace`, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` outputs with totals, failures and ignored counts, feature-on and feature-off variants where a feature flag exists. All traffic-bearing tests bind loopback fixtures; public targets, public OAST, live providers and automatic downloads are denied by test, not by convention. A historic test count is never a result for a new branch.

## 9. Risks carried from the design

Licensing (M0 blocker for distribution, not for local development); prompt injection through captured traffic (provenance and redaction in M2; the model is fed evidence, not authority, and with approval dropped the remaining guardrails are scope and budgets); crash-after-send ambiguity (journaled call intent, no automatic replay); cross-repo drift (pinned revisions, re-audit on updates). The dropped approval requirement is itself a risk the owner accepted on 2026-11-22; the `PolicyGate` hook keeps the way back cheap.

## 10. Verification of this docs-only change

Only this Markdown plan is added. No engine, manifest, dependency, model or server behavior changes. File paths and line anchors in sections 4-7 were verified against live clones of both repositories at the pinned revisions on 2026-11-22. The ACP claims in sections 2-3 were verified against the official specification pages listed in section 11, fetched 2026-11-22. The authoring environment has no Rust toolchain, so compilation, tests, rustfmt and clippy were not run for this branch and no test-count claim is made; the diff is documentation-only and whitespace-checked.

## 11. Sources

1. [webprobe PR #122: native ARTEX agent integration design](https://github.com/Chaim12345/webprobe/pull/122)
2. [ACP documentation index](https://agentclientprotocol.com/llms.txt)
3. [ACP v1 Tool Calls, including session/request_permission](https://agentclientprotocol.com/protocol/v1/tool-calls.md)
4. [ACP v1 Security Considerations](https://agentclientprotocol.com/protocol/v1/security.md)
5. [ACP v1 Transports](https://agentclientprotocol.com/protocol/v1/transports.md)
6. [ACP v2 Permission Requests RFD (Preview, 2026-11-20)](https://agentclientprotocol.com/rfds/v2/permission-requests.md)
7. [ACP Rust library](https://agentclientprotocol.com/libraries/rust.md)
8. [artex-rs at e465233](https://github.com/Chaim12345/artex-rs/tree/e4652336583acb9cd388fe8c85ea496c14a9bd78)
9. [webprobe parity/2026-11-17 at 7be2efd](https://github.com/Chaim12345/webprobe/tree/7be2efd44949006526df1ea3616290d9979e67c6)

# ARTEX as WebProbe's native agent

Status: design proposal, not an implemented feature. Date: 2026-11-22.

## Decision

Integrate a small, Rust-native ARTEX kernel behind WebProbe's own typed capability and mandatory human-approval boundary. Keep the existing AI chat entry points and add a first-class Agent workspace with tasks, proposals, approvals, evidence and findings. Do not embed the complete ARTEX server, run its default shell dispatcher, or route the desktop through a second proxy.

This is feasible, but not a drop-in dependency. Three prerequisites block direct reuse today: approval behavior does not match the README's strict promise, the engine depends on a concrete PostgreSQL store, and the default dispatcher installs unrestricted process execution. Team service is in scope as a later deployment of the same contracts, not as permission to ship the current single-user ARTEX server as a multi-user service.

No code or Cargo dependency changes are included in this proposal. Suggested crate names and APIs below are new designs, not existing exports. Implementation must be separately reviewed before any cross-repository refactor.

## 1. Verified starting point

Inspected from live GitHub and local, read-only source checkouts:

| Component | Observed state | Consequence |
| --- | --- | --- |
| `Chaim12345/artex-rs` | Private repository exists. Default branch `main`, head `e4652336583acb9cd388fe8c85ea496c14a9bd78`, latest milestone M86 task deadlines. Workspace has 12 crates. | The Rust port is real and substantial, but milestone count is not proof of finished integration or Go parity. |
| `Chaim12345/artex` | Original Go repository exists; default branch `english-ui`. | Do not confuse the original with the Rust integration target. |
| ARTEX README | Calls itself work in progress, promises per-call human approval and excludes autonomous mode and evasion. Its status section still says Phase 1. | README status is stale relative to the source tree. Inspect behavior, not the phase label. |
| `artex-engine` | Frontier intent loop, metered provider, tool proposal, dispatcher call, outcome graph write-back, turn cap and optional pause control. Concrete `artex_db::Store` and `artex_tools::Dispatcher` fields; dependency on `artex-traffic`. | Extract interfaces before linking the loop into the desktop. |
| `artex-guard` | Allows matching Allow rules, default-proceeds on unlisted tools unless a setting requests approval, accepts judge Allow, and supports timeout Allow. | Calling the existing guard is not equivalent to fresh human approval for every step. Integration must not expose these bypass paths. |
| `artex-tools` | `Dispatcher::new` automatically registers `BashTool`. `Tool::run` accepts argv; `ToolProposal` uses a text format and a hand-written argv parser. | A new typed, deny-by-construction capability surface is necessary. Do not merely hide shell tools in the UI. |
| `artex-db` | PostgreSQL/sqlx concrete storage; embedded PostgreSQL is a dev dependency. | Desktop embedding without an external database is not currently implemented. |
| `artex-llm` | OpenAI-compatible chat completions, optional API key, metering abstraction; current adapter is not streaming. | Reuse provider concepts, not claims of universal provider compatibility or native structured tool calling. |
| `artex-server` | Auth uses a single `operator` subject and long-lived JWTs; event streams can accept tokens in query strings. | Not a team identity, project authorization or secure worker-enrollment design. |
| WebProbe | `app` desktop and `app/core` engine already separate; `ai::AiChat` supports configurable OpenAI-compatible chat. | Extend existing AI UX rather than introducing another app or duplicate provider settings. |

### Source revision boundaries

This docs-only branch starts from the actual PR target, `parity/2026-11-17` at `7be2efd44949006526df1ea3616290d9979e67c6`. PR #45 head `4cddee0f8149c6629dc0d49673443dc87ba87a0a` was also inspected to account for the newer decomposition. At #45, `net.rs` and `scan.rs` are directory modules, and support/report code has separate crates. Later team PRs are not assumed merged. There was no matching ARTEX integration-design PR in the most recently updated 100 PRs checked; this is not a claim about every historical branch.

The proposal uses stable concepts, not a dependency on one unmerged branch layout. Recheck the chosen implementation base and existing PRs before coding.

## 2. Non-negotiable behavior

1. Every agent tool invocation, including reads and local draft mutations, requires a fresh human decision for that exact invocation. No auto-approve flag, remembered Allow rule, target-wide permission, judge approval or timeout approval.
2. Model reasoning can suggest a plan; it cannot authorize an action. A plan is not an approval for its child steps.
3. No evasion, stealth, anti-detection, WAF-bypass or unrestricted shell capability is registered. A denylist of a few command names is not sufficient.
4. Tests use only local owned fixtures, synthetic traffic and mock model servers. No public targets, public OAST, live-provider spending or automatic downloads are needed for the acceptance suite.
5. Ordinary manual Proxy, Repeater, Intruder and Scanner use remains separate. Adding Agent mode must not silently grant the agent those manual privileges or change the user's existing manual workflow.
6. No provider or team-server network activity occurs on a fresh install. Offline work remains available if AI is unconfigured or unreachable.

These are requirements for this integration, not a claim that the inspected ARTEX implementation already enforces them.

## 3. Options

| Rank | Option | Fit | Decision |
| --- | --- | --- | --- |
| 1 | Extract a small embeddable ARTEX kernel and adapt WebProbe operations | Native UI, shared evidence, no second proxy or mandatory server; some upstream work | Recommended staged path. |
| 2 | Connect desktop to ARTEX server as a service | Useful experimental reference and eventual remote backend | Later only, after team auth, strict execution mediation and storage boundaries exist. Not the default native integration. |
| 3 | Link today's entire engine/server unchanged | Least initial wiring | Reject: PostgreSQL dependency, built-in shell, permissive guard paths and duplicate traffic engine. |
| 4 | Reimplement the entire agent inside WebProbe | Full local control | Avoid: duplicates metering, frontier logic and maintenance without reusing the requested project. |

## 4. Proposed boundaries

| Proposed unit | Owns | Must not own |
| --- | --- | --- |
| `artex-kernel` in ARTEX | Frontier loop, immutable proposals, budget/deadline accounting, cancellation, event types, `AgentStore` and `ProposalSink` ports | Concrete Postgres, egui, HTTP listeners, raw sockets, process spawning, WebProbe dependency |
| `artex-provider` adapter | Existing provider/metering behavior adapted behind a bounded model-call port | Tool execution, application-wide secrets, implicit provider fallback |
| `artex-store-pg` | Existing PostgreSQL implementation of store ports for server deployments | Desktop startup requirements or UI types |
| `webprobe-agent` in WebProbe | Coordinator, typed commands, approval ledger, context selection, project-bound capability adapter, local store adapter | A second proxy, shell bridge or approval policy chosen by an LLM |
| `webprobe-core` | Existing engine and bounded operations; new mediated agent entry points | Model/provider dependencies or egui widgets |
| Desktop Agent UI | Task list, plan display, per-step review, result/evidence navigation | Direct calls to execution methods or mutation of approval records |
| Future `webprobe-team` | Authenticated identities, project membership, authoritative approvals, worker leases, event synchronization | Desktop secrets by default or bypassing the same execution boundary |

Dependency direction: desktop UI -> agent coordinator -> kernel/provider/store ports; coordinator -> narrow WebProbe core capability adapter. The kernel never depends back on WebProbe. Remove `artex-traffic` from the kernel dependency closure by moving capture bridging into a separate adapter. ARTEX's existing traffic crate must not become WebProbe's transport implementation: it already contains reused WebProbe code, which would increase circular integration and duplicated-fix risk.

Initially keep WebProbe's project persistence format unchanged. Add a versioned, project-local agent journal using the existing project save/atomic-write pattern for task metadata, approval transitions and evidence references. Do not copy full request/response bodies into two stores. Its adapter needs explicit single-writer exclusion and durable fsync/atomic-rename behavior. If a transactional embedded store is later chosen, select and review it as a separate dependency decision. Do not introduce a vector database to satisfy basic agent state.

`AgentStore` requires atomic claim, approval-consume and execution-record operations, not a generic SQL escape hatch. A backend that cannot supply the required atomicity is unsupported; an in-memory mock is for tests only.

## 5. Agent loop and exact approval binding

Proposed state flow:

```text
Idle -> ContextReview -> ModelTurn -> Proposed -> AwaitingHuman
                                             -> Denied/Expired
AwaitingHuman -> Approved -> ClaimAndValidate -> Executing -> Result
                                                        -> NeedsReconciliation
Result -> ModelTurn or Completed
Any active state -> Cancelled/Stopped
```

- Starting a task captures the project ID, actor ID, scope revision, chosen evidence IDs, provider destination, maximum turns, tokens, elapsed time, request count and spend ceiling. Initial context is explicitly previewed before a provider call.
- The model returns one schema-validated proposal. Replace the current line/argv parser with a versioned enum, reject unknown fields, cap sizes and nesting, and use structured decoding even for providers without native tool calling.
- The coordinator resolves record IDs, effective request bytes, destination, cookies/session transformations and effects before presenting approval. It rejects prohibited tools and out-of-scope targets before asking.
- Each immutable proposal carries actor/project/task/proposal IDs, monotonic revision, tool/schema version, canonical arguments, content hashes, target origin, scope/config revisions, request budget and expiry. Secrets are referenced by opaque handles, not shown in argument JSON or logs.
- Approval UI binds a human decision to that immutable digest. Editing any argument creates a new proposal and invalidates the old approval. The server/coordinator records the approving identity, time and policy version.
- Immediately before execution, atomically consume one unexpired approval, reserve the request/token budget, claim the task lease and validate current actor/project scope. A private, non-cloneable execution permit is available only to the trusted adapter. A model-supplied `approved=true` field never creates one.
- If cookies, session macros, routing, extension hooks, request bytes, DNS policy or scope changed since preview, regenerate the effective request and ask again. No invisible mutation after approval. Bind the network destination to the validated resolution, reject unexpected redirects and revalidate every new connection.
- Persist Executing before the effect. Store its bounded result and evidence IDs after. If the process dies after send but before recording the result, mark the action uncertain and require operator reconciliation. Never automatically replay a possibly completed request. Local idempotent journal operations may be retried with the same operation ID.
- Denial, timeout, cancellation, disconnected UI, audit-write failure, stale approval or missing policy all stop that step without execution. A blocked step cannot spawn follow-up executions.
- Every retry that would repeat a target request, redirect, session preflight or scanner-generated request is another step requiring approval. Provider-transport retries may reuse the already approved, unchanged context within a visible bounded retry/cost budget; they cannot execute tools.

Cancellation stops new claims and sends, invalidates unused approvals and propagates to workers. It cannot unsend a network request or promise rollback of remote effects. Document this in the UI.

## 6. Typed tool API and engine mapping

The following names are proposed API contracts, not existing callable methods. Each successful invocation consumes an approval. Local preparation and target-network execution are separate capabilities.

| Proposed tool | Inputs and bounded output | Existing anchor / necessary change |
| --- | --- | --- |
| `proxy.history_list` | Filter, pagination cap; project-local metadata IDs only | `Shared.history` / history storage. Never bulk-export the project to the model. |
| `proxy.exchange_read` | Explicit exchange ID and allowed body/header slices; redacted snapshot | Resolve current project ownership and body storage; source bytes remain immutable evidence. |
| `repeater.prepare` | Source exchange ID and explicit patch; draft ID and raw diff | Core Repeater state plus desktop `repeater_ops`; introduce a UI-independent draft service. No send. |
| `repeater.send_one` | Immutable draft/version, effective bytes and resolved destination; bounded response/evidence ID | `net::send_raw` / TLS equivalent and `RepeaterRun` generations. Agent adapter needs a one-send path with no implicit macros, retries, redirects or extension mutations. |
| `intruder.prepare` | Template, selected insertion points, bounded literal payload list; count and preview | `intruder::Template`, request generation and count helpers. Reject unbounded or executable payload sources. |
| `intruder.send_next` | Prepared job/version and exact next candidate; one exchange result | `intruder_run::start` currently runs a job. Add a candidate/step interface; do not wrap whole-job start as one approved call. |
| `scanner.plan` | Selected request IDs and permitted check IDs; finite candidate list with limits | `scan::start_active_scan` currently launches check work. Separate planning from sending, including baselines and verification requests. |
| `scanner.send_next` | Exact planned candidate, immutable config and destination; evidence result | New per-send mediation below checks. Disable active execution until every internal send, redirect and retry reaches this boundary. |
| `findings.draft` | Evidence IDs, structured title/severity/rationale; unverified local draft | Existing issue model. Model output is a draft, not a verified vulnerability. Human verification is distinct. |

Do not expose arbitrary raw URL fetching, shell/process execution, custom scripts, extension installation, certificates, proxy listener changes, credential extraction, general filesystem access or team-admin methods. Stop/pause controls are direct human controls, not tools the agent must approve to stop itself.

Read-only calls also need per-step approval under the strict requirement. Already selected, previewed evidence can be part of initial context; adding another record requires another review. Sending that data to a remote provider is separately shown as an outbound disclosure, even if the underlying tool was a local read.

### Fan-out and hidden effects

A Scanner or Intruder job is not one network step. Approving a whole scan and then emitting hundreds of requests would violate this design. Stage the UI to show the next exact request, its reason, destination and remaining budget. There is no Approve All button. Cost is more operator clicks; that is intentional under the per-step requirement. Batch automation is an unresolved future product change, not a back door in this design.

Agent tasks use a distinct bounded resource pool and ownership tag so they do not replace the user's active scan or Repeater generation. No mutex is held while waiting for an operator or provider. Do not run Tokio network work or blocking engine operations on the egui frame thread. Use bounded channels; use nonblocking UI sends and a separate blocking worker pool. Progress can coalesce, but approval and audit transitions must be durable before notification.

## 7. Native desktop UX

- Add an Agent workspace beside the current AI conversation. Preserve Send to AI as explain-only, and add Send to Agent with an evidence preview. Existing chat is not silently converted into an executor.
- Show task status, selected project and target scope, model destination, request/token/spend counters, plan, next proposed step and evidence timeline. A plan is a visible hypothesis, not a script already scheduled to run.
- Each approval card shows tool, purpose, exact target, request diff, headers/body disclosure, hidden-value indicators, maximum effects, timeout and whether it contacts a target or model. Expandable raw-byte inspection must escape control characters and visibly flag binary/large bodies.
- Offer Approve This Step, Deny, Edit and Stop. No pin/remember/auto-approve options. Keyboard approval must be deliberate, cannot share Enter with chat submission, and must not fire after a proposal changes.
- Result cards link to the actual Proxy exchange, Repeater draft, Intruder candidate, scan evidence and finding draft. Mark partial, truncated, model-generated, uncertain and manually verified states distinctly.
- A disconnected or closed approval view cannot approve. Restart restores tasks as paused and approvals as expired. No task resumes because a project was opened or a scheduler ticked.
- Acceptance includes visual checks at small window size, high DPI, keyboard-only navigation and long/binary request previews. This PR does not implement or visually validate that future UI.

## 8. BYOK and offline-safe defaults

Unify provider settings with current `AiChat`; do not keep two independent key stores or conflicting endpoint interpretations.

| Setting | Default / rule |
| --- | --- |
| AI enabled | Off. Environment-based legacy configuration must not silently start Agent mode. |
| Provider endpoint and model | Empty until chosen; explicit local/OpenAI-compatible preset or custom endpoint. Provider-specific support is tested, not assumed. |
| API key | Opaque OS credential-store reference; never in project exports, logs, team events, model context or source control. Missing credential store means session-only key, not plaintext fallback. |
| Network destination | Loopback local endpoint allowed only after user selection; remote endpoints require HTTPS and a disclosure preview. Reject credentials in URL, endpoint redirects and unexpected destination changes. |
| Fallback | None. A failed local model must not fall back to a hosted provider. |
| Context | Explicitly selected snapshots; mask Authorization, Cookie, Set-Cookie, bearer tokens, API keys and configured sensitive fields before provider disclosure. User can review a synthetic/redacted preview. |
| Limits | Finite per-task turns, input/output tokens, wall time, request count, response bytes, provider retries and spend ceiling. No zero-as-unlimited interpretation. |
| Accounting | When provider usage is missing, reserve using conservative local estimates; absent trustworthy pricing means fail closed at a token ceiling, not a false $0 estimate. |
| Telemetry | No automatic model telemetry or project upload. Team synchronization is separately configured. |

Do not route model API traffic through ordinary captured-target history where a provider key could be saved or fed back to the model. Use a separate provider transport with TLS validation, explicit proxy behavior, bounded response reading, redacted diagnostics and origin-bound credentials. A local server is still a data recipient; loopback is not a reason to omit the context preview.

Offline default means zero automatic external calls, not a bundled model or a promise that hosted AI works without internet. In strict network-disabled mode, selected local model use can be enabled explicitly while target sends remain denied. Normal non-AI WebProbe tools keep working when the provider is down.

## 9. Team-server implications

Use the same proposal and approval schema for desktop and remote mode. Team mode is explicit opt-in, not a new startup listener.

- Each request is authenticated as a person or an enrolled worker, scoped to an organization/project/task. Suggested roles: viewer, operator, approver and administrator. Project membership alone cannot grant approval rights. An agent service identity cannot approve its own proposal.
- Server is authoritative for proposal versions, one-use approvals, actor grants, budgets and task ownership. Store approval consumption and the worker execution claim transactionally. Multiple workers need expiring leases with fencing tokens; split brain, stale workers or unavailable ledger means no execution.
- Workers receive only approved typed operations and minimal project-scoped evidence. A remote worker rechecks the approval digest, lease fence, destination and policy immediately before the effect. A signed envelope alone is not execution permission.
- Use authenticated TLS, explicit worker enrollment/revocation and scoped short-lived credentials. Do not reuse ARTEX's shared operator JWT or URL-query bearer tokens as team identity. Event streams need authenticated session handling and revocation as well as authorization on replay and resume.
- Separate provider secrets from project data. A task declares whether inference occurs on the operator desktop or team service. Desktop keys never sync by default; server-managed BYOK uses server secret references with authorized usage and redacted logs. An administrator changing inference location invalidates context-disclosure approval.
- Existing Proxy/Repeater state is not a multiwriter data model. The worker owns execution state; clients receive versioned snapshots and command results. Use optimistic revision checks for drafts and scope. Never mirror raw `Shared` mutex state over WebSockets.
- Team events contain bounded metadata/evidence references, not automatic full traffic bodies. Check project authorization again when fetching bodies or findings. Add retention, deletion, export authorization, encrypted backups and audit access before broader deployment.
- Collaboration disconnect stops new effects. Reconnection shows durable state and uncertain sends; it must not replay old approvals. Define exactly which execution host's scope, DNS, network and trust roots apply.

No team-server implementation is present in this PR. Existing ARTEX auth and PostgreSQL are useful reference code, not proof that isolation and authorization are solved.

## 10. Risks and release blockers

| Risk | Mitigation / release condition |
| --- | --- |
| Existing guard differs from safety promise | New strict execution boundary, no legacy dispatcher registration; negative tests for every identified bypass. |
| In-process native code is not a hostile-plugin sandbox | Restrict capabilities and dependencies; untrusted plugins are excluded from agent execution. A separate hardened worker process may later add isolation. Rust types alone are not OS containment. |
| Prompt injection in captured traffic or evidence | Treat all traffic, tool output and model text as untrusted data. Keep provenance, redact secrets and separate instructions from evidence. Enforce approval and scope outside the model; sanitization is not authorization. |
| Cookies, macros, extensions or retries change approved effects | Immutable effective-request preview, versioned config and per-send mediation. Unsupported paths denied until intercepted completely. |
| PostgreSQL coupling inflates desktop install | Extract storage ports; desktop local journal first. Do not silently download or launch a database at startup. |
| Dependency/license obligations | ARTEX workspace declares AGPL-3.0-only and NOTICE identifies upstream derivative code. WebProbe has no root license file in inspected tree. Resolve WebProbe licensing and contributor rights before combining/distributing or running a modified network service. Retain notices and obtain license review, including AGPL section 13. Ownership of the fork alone does not remove upstream obligations. |
| Model/provider leakage and runaway cost | Preview/redaction, origin-bound key handling, bounded tokens/retries and explicit spend limits; missing usage is not free usage. |
| Crash after send / worker partition | Durable execution intent, no automatic repeat, fenced leases and operator reconciliation. Exactly-once arbitrary HTTP effects are not promised. |
| Upstream drift | Pin the reviewed Rust revision and maintain explicit kernel/adapter contracts. No floating branch dependency. Re-audit on updates. |
| UI stalls or memory growth | Bounded channels/body slices, worker isolation, no locks during human waits, measured cancellation and responsiveness. |

## 11. Milestones and exit criteria

No duration promises until the dependency extraction and engine mediation spikes are measured.

| Milestone | Scope | Exit evidence |
| --- | --- | --- |
| A0: contract and license review | Resolve licensing, approve strict gate semantics and source boundary | Written decisions; pinned revisions; bypass tests specified before implementation. |
| A1: embeddable kernel | ARTEX ports for store/proposals/provider; remove traffic/server/process dependencies from kernel | Dependency graph audit; mock provider/store tests; no Postgres/server needed for kernel tests. Separate upstream PR. |
| A2: desktop task and approval skeleton | Versioned journal, context preview, strict gate, fake tool and fake model | Deny/timeout/restart/stale/duplicate approval tests all pass; zero effects before approval; visual review. |
| A3: bounded reads and Repeater | Selected evidence reads, draft preparation and one-request execution | Local fixture end-to-end proof, exact effective-request bytes, evidence navigation, no shell/process capability. |
| A4: Intruder and Scanner mediation | Candidate planners and approval before each internal send | Fan-out/redirect/retry/macro bypass tests; no whole-job approval shortcut; manual-tool regression tests. |
| A5: BYOK and hardening | Shared provider settings, secret store, redaction, cost accounting and offline mode | Mock-provider matrix, traffic-leak canaries, cost-limit tests and offline network trace. |
| A6: team service | Identity/RBAC, authoritative approvals, worker enrollment, fenced execution, retention | Two-user/two-worker isolation tests, disconnect/revocation/replay tests and deployment threat-model review. |

Local-first path: A0 -> A1 -> A2 -> A3. A4 is not enabled until every send is mediated. A5 safety foundations apply before any real-provider testing. A6 shares contracts but is a separate rollout. Desktop Agent must remain unavailable, not silently weaker, when prerequisites are missing.

## 12. Acceptance checks for implementation

All traffic-bearing tests bind local owned fixtures to loopback and use mock inference. Local names that resolve to public IPs, redirect to nonfixture hosts or try public OAST must be denied. No live customer data or real provider keys in fixtures.

### Approval and execution

- Given each of the legacy permissive cases (Allow rule, unlisted tool, judge Allow, timeout Allow, remembered target approval), no tool executes without a new human decision.
- Unknown tool, shell/process name, malformed schema, extra fields or forged approval flag is denied. Test arbitrary process invocation, not only a tool named bash.
- Every read, draft mutation and target request consumes exactly one actor/project/argument-bound approval. Parallel consumption succeeds once. Expiry, mutation, actor removal and scope edits invalidate it.
- Scan/Intruder baseline, payload, verification, redirect, session macro and retry traffic is individually accounted for. Pause or cancellation before a send prevents it. Unsupported extension hooks cannot mutate an approved request.
- Crash at each transition yields no silent resume. Crash after network send yields NeedsReconciliation, not an automatic retry. Audit-storage failure prevents dispatch.

### Data, provider and offline

- Fresh install, project open, provider failure and task restore produce zero automatic provider/team/target calls. A configured local endpoint never falls back to a remote host.
- Synthetic secret canaries in HTTP headers, bodies, provider errors and team events never appear in prompts/logs/project exports unless an explicitly reviewed disclosure allows that exact data. Keys themselves are never model context.
- Provider key stays origin-bound across redirects, endpoint edits and proxy changes. Responses are byte-bounded, Unicode-safe and timeout-bounded. Missing usage/pricing cannot bypass token/spend limits.
- Evidence IDs cannot cross projects. Findings remain unverified until human confirmation and retain original exchange references.

### UI, performance and team

- Approval card raw-byte/diff previews match the bytes executed; changing a proposal cannot activate a stale keyboard shortcut. Small-window/high-DPI/keyboard-only review remains usable.
- Suggested performance target, to be measured on declared hardware: no frame-thread network/blocking waits; cancellation blocks new sends within 250 ms; a stalled model or approval UI cannot block manual Proxy/Repeater use. These are targets, not benchmark results.
- Cross-project read/approval, expired membership, revoked worker, duplicated approval, stale fencing token, replayed event and network-partition tests fail closed across two server instances.
- Normal manual tool behavior and project save/recovery tests remain green with Agent feature disabled and enabled.

### Required build evidence for code milestones

From WebProbe's `app/` directory, run `cargo test --workspace --no-run`, `cargo test --workspace`, `cargo fmt --all --check`, and `cargo clippy --workspace --all-targets -- -D warnings`; include relevant feature-on and default feature-off variants. Run the analogous ARTEX workspace checks for kernel changes, using only local fixtures. Record exact source revisions, test totals, failures, ignored tests, toolchain and logs. A historic 782-test baseline is not a result for a new branch.

## 13. Decisions still needed

1. Confirm the recommended scope order: local native agent first, shared team execution after per-step mediation is proven.
2. Resolve license strategy for the combined desktop and team distribution before copying/linking ARTEX code. AGPL compliance or a separately validated licensing route is a release decision.
3. Confirm that strict per-request approval, including every generated Scanner/Intruder request, is the intended UX. Recommendation: yes; otherwise leave those execution tools unavailable rather than quietly weakening the accepted requirement.
4. For team mode, choose inference location and key ownership. Recommendation: personal desktop BYOK by default, separately authorized server-managed credentials later.

These questions do not block reviewing the design. They do block committing to an implementation or changing the stated safety contract.

## 14. Verification of this docs-only change

Only this Markdown design is added. No engine, tool, manifest, dependency, model or server behavior changes. Source inspection is not a successful build or runtime test. The authoring environment has no Rust toolchain, so compilation, Rust tests, rustfmt and clippy were not run for this branch; no test-count claim is made. Documentation structure, source references and whitespace/diff checks passed. Local rendered previews of the overview and approval/tool sections were visually inspected for readable headings, tables and complete visible content; they are documentation previews, not an implemented application UI. Future UI acceptance above is a requirement, not a claim of a shipped or visually tested interface.

## Sources

Source links below were returned by live GitHub content/PR APIs or fetched from the named documentation sites on 2026-11-22. Repository code is the evidence for current behavior; README and source comments are claims to compare with code, not permission records. Source coverage includes primary implementation, repository manifests/license documents, and independent security/runtime guidance. The linked repositories are private where noted and require repository access.

1. [artex-rs: README.md](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/README.md)

2. [artex-rs: Cargo.toml](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/Cargo.toml)

3. [artex-rs: LICENSE](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/LICENSE)

4. [artex-rs: NOTICE](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/NOTICE)

5. [artex-rs: crates/artex-engine/src/lib.rs](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/crates/artex-engine/src/lib.rs)

6. [artex-rs: crates/artex-tools/src/lib.rs](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/crates/artex-tools/src/lib.rs)

7. [artex-rs: crates/artex-guard/src/lib.rs](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/crates/artex-guard/src/lib.rs)

8. [artex-rs: crates/artex-db/src/lib.rs](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/crates/artex-db/src/lib.rs)

9. [artex-rs: crates/artex-llm/src/openai.rs](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/crates/artex-llm/src/openai.rs)

10. [artex-rs: crates/artex-server/src/auth.rs](https://github.com/Chaim12345/artex-rs/blob/e4652336583acb9cd388fe8c85ea496c14a9bd78/crates/artex-server/src/auth.rs)

11. [webprobe: app/Cargo.toml](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/app/Cargo.toml)

12. [webprobe: app/core/src/lib.rs](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/app/core/src/lib.rs)

13. [webprobe: app/core/src/net.rs](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/app/core/src/net.rs)

14. [webprobe: app/core/src/repeater_run.rs](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/app/core/src/repeater_run.rs)

15. [webprobe: app/core/src/scan.rs](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/app/core/src/scan.rs)

16. [webprobe: app/core/src/intruder_run.rs](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/app/core/src/intruder_run.rs)

17. [webprobe: docs/specs/R-15-cli-rest.research.md](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/docs/specs/R-15-cli-rest.research.md)

18. [webprobe: app/core/src/ai.rs](https://github.com/Chaim12345/webprobe/blob/7be2efd44949006526df1ea3616290d9979e67c6/app/core/src/ai.rs)

19. [webprobe: app/core/src/net/send.rs](https://github.com/Chaim12345/webprobe/blob/4cddee0f8149c6629dc0d49673443dc87ba87a0a/app/core/src/net/send.rs)

20. [webprobe: app/core/src/scan/engine.rs](https://github.com/Chaim12345/webprobe/blob/4cddee0f8149c6629dc0d49673443dc87ba87a0a/app/core/src/scan/engine.rs)

21. [webprobe: app/core/src/net/shared.rs](https://github.com/Chaim12345/webprobe/blob/4cddee0f8149c6629dc0d49673443dc87ba87a0a/app/core/src/net/shared.rs)

- [WebProbe PR #45, inspected hardening baseline](https://github.com/Chaim12345/webprobe/pull/45).

- [OWASP LLM06, Excessive Agency](https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html).

- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

- [Tokio bounded mpsc and clean shutdown](https://docs.rs/tokio/latest/tokio/sync/mpsc/).

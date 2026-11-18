# Architecture review, 2026-11-18

Read-only review of the architecture and of how data and control flow through WebProbe, checked against current Rust practice. This review is not a bug hunt; `PANIC-AUDIT-2026-11-18.md` already covers robustness.
Branch `parity/2026-11-17`, HEAD `ee2ef00`. Paths are relative to `app/`.

How it was done:
- I read the code and ran greps and a small script that splits test code from non-test code (it masks `*_tests.rs` files and `#[cfg(test)]` items).
- No build, no test run and no cargo command.
- Line numbers drift because another agent is editing, so each citation names the function as well; treat the function name as the stable reference.
- The free-model R-18 plan (`docs/specs/R-18-decomposition.research.md`) was checked rather than trusted; see F6.

## Verdict

WebProbe has a sound skeleton: a real engine/UI crate split, a good message-body store, a virtualized UI, and owned subsystem types where they exist.
Its control flow has grown around three habits that will cost it as Burp parity widens.
1. **Engine work driven by the UI frame.** Collaborator id supply and matching, the Logger mirror, project capture and restore, and extension "tool sends" all run from `App::ui`. Because of this the headless binary is functionally weaker today, not just less polished.
2. **Shared mutable state reached field by field.** `Shared` has 72 fields, about 25 of them individual settings atomics or mutexes. The UI touches more than 60 of them directly. Rules are stored as strings and recompiled per message, often while a shared lock is held.
3. **Ad-hoc threads without a lifecycle.** About 43 non-test spawn sites, 9 of them named, 4 joins, no shutdown signal. Loops poll with 2 to 500 ms sleeps. Implicit context travels in five thread-locals.

None of this needs an async rewrite; the evidence points the other way (section "Sync vs async").
It needs about eight incremental, mostly S/M changes, ordered so that each one unlocks the next:
1. Move engine duties out of `App`.
2. Make settings one snapshot value.
3. Pass send context explicitly.
4. Add a lifecycle and a worker pool.

The R-18 split should come after these, not before.

## Scorecard

| Area | Grade | One line |
|---|---|---|
| 1. Layering and boundaries | adequate | The crate split is real and test-enforced (`src/main.rs` `layering_tests`). But Collaborator, project capture/restore and the Logger feed live in the desktop crate, and the core API is almost entirely `pub` (every non-test module is `pub mod`, and there are about 1,040 `pub` fields in core). |
| 2. State ownership and data flow | weak | `Shared` is a 72-field god object and settings are scattered across about 25 fields. Engine-to-UI traffic uses five different mechanisms, and the UI polls by diffing the whole history. Seven owned types (`ProxyHistory`, `ScanRun`, `OobState`, ...) show the right pattern. |
| 3. Concurrency model | weak | Connections are bounded, the scan claim is panic-safe, and lock order is mostly clean. But there is no shutdown or cancellation, and the loops poll by sleeping. The scanner is serial. One Java extension serialises the whole proxy. Context travels in thread-locals. |
| 4. Error handling | weak | 134 functions return `Result<_, String>` and there are no typed errors at the module boundaries. String matching on error text already occurs. Panics reachable from input are close to none (strong, thanks to the panic audit). |
| 5. Extensibility seams | adequate | Active checks use trait registries; passive checks use a different table plus a second metadata list. There are two JSON-lines extension protocols with duplicated transport code. Severity, confidence, session actions and extension ops are strings. |
| 6. Performance architecture | adequate | The body store, the incremental history cache and virtualized tables are right. But regexes are compiled per message and per row; history filtering runs under the proxy's history lock; the Logger sync is O(n) per frame; there is no client keep-alive; and the whole project is rewritten as one JSON document on every save. |
| 7. Testing architecture | adequate | 787 tests, a seeded parser fuzz suite and live-lab tests. Weak points: about 80 wall-clock sleeps in tests, desktop tests touching the user's real CA directory, a 2048-bit RSA key per `Shared`, no coverage-guided fuzzing and no `tests/` integration layer. |
| 8. Build and tooling hygiene | weak | No `[lints]` table, no clippy step in `scripts/ci.sh`, no rustfmt config, and `#[allow]` where `#[expect]` would do. `unsafe` is minimal and justified (strong). |

### The unwrap question

| Bucket | Count | Notes |
|---|---|---|
| `unwrap()`/`expect()` in test code | 1,499 | 1,428 + 71 |
| In non-test code | 466 | |
| ...on locks | ~437 | 430 one-line `.lock().unwrap()` plus about 7 written across two lines (`net.rs` `handle_connect`, `ext_calls.rs` `dispatch`, `ui.rs`, `tools.rs`, `repeater_ops.rs`) |
| ...other | ~29 | All invariants or static patterns |

The lock unwraps are infallible only where the `core/src/sync.rs` wrapper is used. That wrapper's `lock()` returns `Result<_, Infallible>`. About 18 files still use `std::sync::Mutex` directly (for example `tools.rs` `save_results`, `scan_run.rs`, `notice.rs`, `body.rs`). So the reader cannot tell a poisonable unwrap from an infallible one (see F14).

The ~29 other non-test unwraps are invariants or static patterns, for example:
- `shortcuts.rs` `parse`: `split_last` after an emptiness check.
- `ui.rs` comparer: the button is enabled only when both selections exist.
- `decoder_ops.rs`: `try_into` on fixed `chunks_exact` blocks.
- `MitmAuthority::new().expect` at startup.

**None of them consumes external input.** Share on external input: 0 of 466, which is 0% of the non-test unwraps. The input-reachable panic that remains is a slice, `retirejs::file_name` (panic audit H3), not an unwrap.

## Findings, ranked by impact

Each finding gives its evidence, why it matters, the change, its size (S/M/L), its risk, and whether it can be done incrementally alongside feature work.

### F1. Engine work runs on the UI frame, so headless runs are incomplete

**Evidence**
- `App::ui` (`src/main.rs`) calls `refill_oob_pool`, which does `shared.oob.refill(...)` with `App.collab_state` generating payloads, and `match_oob`, which calls `scan::match_new_interactions`. These are the only callers in the tree.
- `scan::pooled_oob` (`core/src/scan.rs`) says "Wake the front end now so it stocks the pool on its next frame", then waits `oob.take(..., 1500 ms)`.
  - `OobState::take` (`core/src/oob.rs`) waits, in a 25 ms sleep loop, only while a supplier is registered.
  - `crawl_and_audit` reaches `pooled_oob`, and that is the headless `scan` path.
- `webprobe-headless` (`core/src/bin/webprobe-headless.rs`) never refills or matches.
- Project capture and restore are desktop-only: `tools.rs` `project_snapshot` (about 180 lines) and `apply_project` / `restore_j01_sections`. The headless `save_project` writes only history and issues (`webprobe-headless.rs`, `save_project`), so settings, rules and scope are lost.
- The Logger mirror (`App::sync_logger`) and extension tool sends (`tools::drain_tool_sends`, which drains `Shared.tool_sends`) are also frame-driven.

**Why it matters**
- A headless scan (or a future REST/CLI run, R-15) gets no Collaborator ids. With no supplier registered, `take` returns empty at once, so every out-of-band probe is skipped and no OOB issue is ever matched.
- In the GUI, every scan item that needs more ids than the pool holds waits up to 1.5 s for the next frame.
- In the GUI, OOB scanning depends on the window repainting. Repaint wake-ups are known to be ignored for minimized windows on Wayland ([egui issue 5136](https://www.goodfirstissue.org/de-DE/emilk/egui/issues/5136)).
- Each new front end has to re-implement the project mapping.

**Change**
- A core `CollaboratorService` that owns `CollaboratorState`, with its own thread that refills the pool and matches interactions on a timer or condvar. `OobState` already has the take/refill API.
- `project::capture(&Shared) -> ProjectData` and `project::restore(&Shared, &ProjectData, Sections)` in core. The desktop adds only its own view layout.
- Tool sends become typed engine events (see F11).

**Size** M. **Risk** low to medium; the `log_seen` watermark and the save JSON keys must not change. **Incremental** yes, one duty at a time. This unlocks R-15 and makes R-18 smaller.

### F2. One Java extension serialises the proxy and holds a lock across network I/O

**Evidence**
- `JavaSidecar::exchange_with` (`core/src/ext_host.rs`) takes `io_lock`, then the `from_bridge` receiver, for the whole round trip.
- `scan_active` passes an `on_call` closure that runs `helper.send(&raw)`, which is real upstream HTTP. It runs while `io_lock` is held, and every answered call resets the 15 s deadline.
- Proxy hooks (`run` with `HOOK_TIMEOUT`) for every connection thread queue on the same mutex.
- A 15 s silence marks the sidecar dead and kills the JVM.

**Why it matters**
- While an extension's active check runs, every proxied request and response through that extension waits behind it, with no upper bound. With N browser connections, hook latency becomes serial.
- A GC pause or a slow extension check permanently disables the extension.
- This is the brief's "lock held across sidecar calls/I/O".

**Change**
- Demultiplex. One reader thread routes each reply by `id` into a per-call one-shot channel (`HashMap<u64, SyncSender<Value>>`). Writers send without holding a lock across the wait.
- Scan-time `call` messages carry the `sid` they already have, so they can be routed the same way.
- The Java side must accept concurrent requests (a request executor in `MontoyaBridge`). As a first step, keep one lane for proxy hooks and a separate lane for scan checks.
- Keep the "dead → pass-through" degradation, but make it per call. Mark the sidecar dead only on EOF or repeated timeouts.

**Size** M (Rust S, Java M). **Risk** medium: extension semantics assume sequential handler calls in Burp too, so serialise per handler on the Java side, not globally. **Incremental** yes, and it is independent of the rest. Do it before R-20.

### F3. Rules are recompiled per message, and CPU work runs under shared locks

**Evidence (per-call `Regex::new`)**
- `net::pattern_matches`, used by `in_scope` and session host matching.
- `rules::apply_rule`, which calls `compile(&rule.match_)` per rule per message.
- `ResponseInterceptRules::matches`.
- `intercept_rules::regex_hit`.
- `ws_rules` (per frame).
- `intruder_run::grep_match_flags` and `extract_value` (per result).
- `history_filter::matches` (per row, twice).
- `repeater_ops` search; `tools.rs` line 206 compiles a static pattern on each call.

**Evidence (work under shared locks)**
- `in_scope` clones the whole scope `Vec` on every call.
- `upstream_and_deliver` calls `apply_rules(&req, &shared.mr_request.lock().unwrap())`. The guard is a temporary that lives for the whole call, so every connection thread serialises its match-and-replace work, including compilation, on `mr_request`, and likewise on `mr_response`.
- `proxy_history` runs `history_view(..., |e| app.hist_filter.matches(e, &app.shared))` inside `ProxyHistory::with_rows`. That holds the history mutex, which every proxy thread needs in `push_history`, while each row is regex-filtered, mime-parsed (`mime_of` parses the stored response) and scope-checked (another regex compile per row).

**Why it matters**
- The [regex docs](https://docs.rs/regex/latest/regex/#avoid-re-compiling-regexes-especially-in-a-loop) say compilation takes "a few microseconds to a few milliseconds". 100k rows with a regex filter and a regex scope means seconds of UI freeze with proxy recording blocked.
- Under traffic, every connection queues on the match-and-replace lock.

**Change**
- Compiled rule-set types (`CompiledScope`, `CompiledMrRules`, `CompiledInterceptRules`, `CompiledWsRules`, `CompiledGrep`), built when the user edits the rules. Building at edit time also gives the editor its validation error.
- Store each as `Mutex<Arc<Compiled…>>`. Readers clone the `Arc` and release the lock at once. `arc-swap` is optional.
- Compile the history filter once per filter key.
- Filter outside the history lock: take the `Arc` rows (see F11) and filter without the lock.

**Size** M, done as about 6 S steps. **Risk** low: the rule text and evaluation order stay the same. **Incremental** yes. This is the best value-for-effort item.

### F4. No lifecycle: workers never stop, and loops poll by sleeping

**Evidence**
- `start_proxy` runs `loop` with a non-blocking `accept` and a 50 ms sleep. It has no exit condition, only restart.
- `start_extra_listeners` is a supervisor that polls `listener_generation` every 250 ms. `listener_worker` does the same with a 100 ms sleep.
- `browser_listener` runs an infinite `incoming()` loop.
- `tasks::ensure_runner` polls `tasks` every 200 ms. `tasks::wait_while_paused` polls every 100 ms.
- `relay_ws_tls` and `write_nonblocking` poll every 2 ms per open WebSocket, so an idle socket wakes about 500 times per second. `h2_server::serve` has the same pattern.
- `net::resolve` spawns a thread per DNS lookup and abandons it on timeout.
- `App::on_exit` only releases intercepts, closes browsers and saves. Nothing stops listeners, scans, Intruder, crawls, Collaborator or sidecars.
- Only 9 of about 43 non-test spawn sites are named (`thread::Builder`), and there are 4 `.join()` calls.
  - Counted as `thread::spawn`/`thread::Builder` text matches: 43 non-test plus 105 test, 148 in all. The brief's figure of about 139 counts the same sites.
  - Bare `spawn(` calls (via `use std::thread`) add a few more. Most sites are in `net.rs`, `ext_host.rs`, `ext_process.rs`, `scan.rs` and `collaborator.rs`.

**Why it matters**
- "Project close", "scan stop" and "app exit" are not structural states. Each feature adds its own flag (`listener_restart`, `listener_generation`, `scan.stop`, `seq_live_stop`, `Attack.stop`, ...).
- Tests cannot tear down a `Shared`, so they leak threads and ports across tests.
- Sleep loops add latency and burn CPU.
- The [Tokio shutdown guide](https://tokio.rs/tokio/topics/shutdown) describes the standard shape, which applies equally to threads: (1) decide when to shut down, (2) tell every part to stop (a cancellation token), (3) wait for each part (a task tracker).

**Change (no async needed)**
- A core `Lifecycle` with a `Cancel` token (`Arc<AtomicBool>` + `Condvar`, cheap to clone) and a `Workers` registry (`spawn_named(name, cancel, f)` keeps the `JoinHandle`).
- `Shared::shutdown()` cancels and joins with a deadline.
- Replace the sleep loops with blocking waits:
  - Listeners: blocking `accept`, woken for stop or restart by a self-connect.
  - Task runner: a condvar on `tasks`.
  - Pause: a condvar in `ScanRun`.
  - Extra-listener supervisor: a channel.
- For WebSockets over plain TCP, use two blocking threads, as `relay_tunnel` already does.
- For TLS WebSockets and the h2 client side, either block on readiness with the `polling` crate (epoll/kqueue) instead of `sleep(2ms)`, or keep the loop with an adaptive back-off. `rustls::StreamOwned` cannot be split, which is why these loops exist.

**Size** M (listener, runner and pause: S each; relay: M). **Risk** medium for the relays, low for the rest. **Incremental** yes.

### F5. Settings are scattered, `Shared` is a god object, and the project mapping is duplicated (the R-18 engine half)

**Evidence**
- `Shared` (`core/src/net.rs`, `pub struct Shared`) has 72 fields.
- About 25 of them are individual settings:
  - `ws_intercept_client`, `ws_intercept_server`, `ws_intercept_in_scope`, `ws_strip_extensions`, `ws_rules_in_scope_only`
  - `scan_speed`, `scan_accuracy`, `extra_checks`, `keep_alive`, `h2c_upgrade`, `listener_http2`
  - `streaming`, `tls_bypass`, `upstream`, `upstream_rules`, `response_rules`, `intercept_rules`, `listener_redirects`, `scope`, `mr_request`, `mr_response`, ...
- The UI reaches more than 60 distinct `Shared` fields directly. `tools.rs` has 79 `.lock()` sites on `shared.*`, and `ui.rs` 51.
- The project mapping exists twice: in full in the desktop (`project_snapshot`, `apply_project`, `restore_j01_sections`) and partially in headless.
- The only simultaneous two-lock site is `Shared::upstream_for` (`upstream_rules` then `upstream`). `tools::upstream_options` takes them in the other order, but sequentially, so it cannot deadlock today.
- The comment in `project_snapshot` records two real past hangs: a self-deadlock on `scan_config`, and an `issues`/`tasks` order inversion.

**Why it matters**
- One request reads a dozen settings at different instants, so there is no consistent snapshot.
- Each new Burp option means a new field, a UI binding, two project mappings and a restore path.
- The lock-order hazards come from reaching into many fields at once.

**Change**
- One `ProjectSettings` value (serde, versioned; it already exists as the sections of `ProjectData`), held as `RwLock<Arc<ProjectSettings>>`.
- Proxy, scanner and tools take `let s = shared.settings();` once per request. Editors replace the whole value.
- Runtime state (history, issues, tasks, live sockets, pools) splits into owners as R-18 proposes.
- `Shared` fields become `pub(crate)`, with methods at the boundary.

**On the R-18 plan.** The free-model draft is accurate where I spot-checked it:
- The 72-field and 198-field counts.
- Five of its 15 "unread `App` fields" each have exactly two hits: the declaration and the initialiser.
- The `upstream_for` double lock, and the comment in `project_snapshot`.

Its line numbers have drifted (for example, `record_entry` is now at about line 2379, not 2336).

Its ordering is mechanical: it groups fields by the sites that touch them, it keeps strings and polling, and it forbids `RwLock`. That is acceptable for a pure move. **Do F1 and the settings snapshot first**, so that R-18 moves fewer fields and the new view structs do not inherit engine duties.

**Size** M for settings, L for the full split. **Risk** medium. **Incremental** yes, one settings section at a time.

### F6. Implicit context in thread-locals

**Evidence** (`core/src/net.rs`)
- `TOOL` (`tool_scope`): logging, the cookie jar, streaming sinks.
- `H2_CHOICE` (`http2_scope`) and `LAST_PROTOCOL` (`last_protocol()`): an *output* returned through a thread-local.
- `LISTENER_PORT` (`listener_port`, `upstream_target`).
- `IN_SESSION` (recursion guard for session rules).
- `serve_h2_client` already has to re-seed `LISTENER_PORT` in each per-stream thread.

**Why it matters**
- Any move of work to another thread (a scanner pool, R-12 send groups, an h2 stream thread) silently loses the context. The bugs that follow are wrong history attribution, the wrong protocol, and missed session rules.
- These are hidden parameters, so they are untestable as inputs.

**Change**
- A `SendCtx { tool, h2: Http2Choice, listener: Option<u16>, in_session: bool }` passed to `send_*_with`.
- Return the protocol used in `Upstream` instead of setting `LAST_PROTOCOL`.
- Keep the thread-local functions as thin shims during migration.

**Size** M. **Risk** low to medium. **Incremental** yes. It is a precondition for F8 and R-12.

### F7. Errors are strings at every layer

**Evidence**
- 134 non-test functions return `Result<_, String>`; the largest users are `tls.rs`, `collaborator.rs`, `ext_host.rs`, `project.rs`, `headless.rs` and `h2.rs`.
- `Upstream { resp: Option<Vec<u8>>, error: Option<String> }` is a `Result` in disguise.
- `ext_host.rs` (the extension-load path) matches `e.contains("java launch failed")`.
- `tools.rs` filters the event log by substring ("Sidecar", "Extension").
- Project-load tests assert on message fragments ("magic", "version", "newer", "parse").
- There are about four typed errors in the whole tree: `paths::Missing`, `HttpParseError`, `DnsParseError` and `h2_server::ConnError`.

**Why it matters**
- Callers cannot branch on the cause. The UI cannot offer "open with newer version" or "retry DNS". The future REST API (R-15) cannot map errors to status codes. Messages cannot change without breaking behaviour.
- [Rust API guideline C-GOOD-ERR](https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err) and the local Apollo handbook (ch. 4) recommend `thiserror` enums for a library and `anyhow`/strings only in binaries.

**Change**
- `thiserror` enums at the module boundaries that callers branch on:
  - `ProjectError {Magic, NewerVersion{found, max}, Parse, Io, TooLarge}`
  - `SendError {Dns, Connect, Tls, Timeout, TooLarge, Closed}`, carried in `Upstream` as `Result<Response, SendError>`
  - `ExtError {Launch, Dead, Timeout, Protocol}`
  - `CaError`
- Internal helpers may keep `String` for now.
- The event log becomes typed `Event {level, source, text}` (F11).

**Size** M, one module at a time. **Risk** low. **Incremental** yes.

### F8. The scanner is serial, and the passive audit runs on the proxy thread

**Evidence**
- `tasks::run` runs one item at a time: `start_active_scan` then `wait_idle`.
- `ScanRun` is a single global claim.
- `checks::run_point_checks` and `run_request_checks` loop sequentially, sharing one `ScanState`.
- The only real worker pool is Intruder's (`intruder_run`, `max_concurrent`).
- `record_entry` runs `passive_check_for` synchronously on the connection thread after the response is delivered.

**Why it matters**
- Burp audits with configurable resource pools (concurrent requests plus throttling). A serial scanner makes large audits take many times longer than Burp's.
- R-13 (DOM/JavaScript analysis) will put CPU-heavy passive work on the proxy connection threads.

**Change**
- A bounded per-task worker pool, shaped like Intruder's: `max_concurrent`, delay, and a shared progress counter. Parallelise across insertion points and across items.
- Make per-point state explicit (`PointRun` already exists; split `ScanState`).
- Keep `concurrency = 1` for the parity tests so issue order stays deterministic.
- Passive audit goes onto a bounded queue (drop or coalesce when full, with a counter) served by 1–2 workers.
- Use plain threads, not Tokio: this is CPU plus blocking I/O ([Tokio: when not to use Tokio](https://tokio.rs/tokio/tutorial)).

**Size** L for the pool, S for the passive queue. **Risk** medium: check side effects and the order of the stored-input stages A1–A4. **Incremental** yes, after F6.

### F9. Proxy connection model: one request per client connection, and HTTP intercept without liveness

**Evidence**
- `handle_conn` reads one request, calls `upstream_and_deliver` and returns.
- `handle_connect` does the same and then sends `close_notify`. No loop reads a second request, so with HTTP/1.1 each HTTPS request costs a CONNECT, a TLS handshake and a thread.
- HTTP/2 via ALPN (on by default) mitigates this for browsers.
- `intercept_request` and `intercept_response` block in `rx.recv()` with no liveness check. The WebSocket path uses `intercept_wait`, which has an `alive()` probe.

**Why it matters**
- Non-h2 clients (tools, mobile stacks, a listener with HTTP/2 off) pay a full handshake per request.
- A held request whose browser has left keeps its thread and connection slot, and shows a dead item to the user.
- I did not check Burp's listener reuse against the RE tree; confirm before treating this as a parity gap.

**Change**
- A request loop on both paths, honouring `Connection: close`, HTTP/1.0, upgrades and streaming responses.
- Use `intercept_wait` for HTTP too.

**Size** M. **Risk** medium (framing edge cases; the fuzz suite helps). **Incremental** yes.

### F10. Tool state stores messages as text; a proxy needs bytes

**Evidence**
- `RepTab.request: String`, and `RepTab.history` holds `String` requests.
- `InterceptItem.edited: String` and `mpsc::Sender<Option<String>>`.
- `ext_calls` `intruder.send` stores `String::from_utf8_lossy(&req)`.
- There are 290 `from_utf8_lossy` calls in non-test code.
- `net::forwarded` keeps the original bytes only when the text is unchanged, so any edit of a binary body corrupts it.

**Why it matters**
- Burp edits bytes, showing them through a lossless ISO-8859-1 view.
- Lossy text is also why `rules.rs` needs its "Java ISO-8859-1" special case.
- A general "prefer `&str`/`String`" guide does not apply here: an intercepting proxy must keep raw bytes end to end.

**Change**
- Engine types hold `Vec<u8>` or `Body`.
- Conversion happens at the editor edge only, with a Latin-1 mapping (lossless, byte = char) for the text view, as Burp does.

**Size** M. **Risk** medium: it touches the Repeater, intercept and Intruder editors. **Incremental** per tool.

### F11. Engine-to-UI data flow is polling and diffing, over five channels

**Evidence**

The five channels:
1. `Shared.events`, a `Vec<String>` capped by `drain(..n-500)`.
2. The global `notice::QUEUE` plus a second global `WAKER`.
3. `Shared.tool_sends`.
4. `Shared.tool_log`, which uses `remove(0)` past 5,000 entries.
5. `Shared.waker`.

The polling and per-call costs:
- `App::sync_logger` walks the whole history every frame under the history lock to find new ids.
- `ProxyHistory::snapshot` is documented as "cheap", but it clones about 9 `String`s per entry. It is called per traffic change by the site map (`ui.rs` `target`, `engagement::site_entries`) and per request by `latest_cookie`, which also re-parses every response.
- `ProxyHistory::get` and `update` are O(n) scans.

**Why it matters**
- UI cost and history-lock hold time grow linearly with history size, five times a second while busy.
- Each new tool invents its own channel.

**Change**
- History becomes append-only with a sequence number: `rows_since(seq) -> Vec<Arc<HistEntry>>`, plus an `id → index` map.
- `HistEntry` metadata goes behind an `Arc`, so a snapshot is a vector of pointers.
- One typed `EngineEvent` enum (`HistoryAppended(seq)`, `IssueAdded`, `Notice{level,text}`, `ToolSend(..)`, `Log{..}`) on a bounded channel, with drop-oldest for logs, plus the existing waker.
- This is the standard egui pattern: worker → channel → `try_recv` in `ui()` → `request_repaint` ([egui PR 1389 on background threads](https://github-redirect.dependabot.com/emilk/egui/pull/1389)).
- `latest_cookie` should read the cookie jar or keep a per-name index.

**Size** M. **Risk** low to medium. **Incremental** yes, one channel at a time.

### F12. Lints, the lock API and dead code

**Evidence**
- `scripts/ci.sh` runs tests and builds, but no `cargo clippy`.
- There is no `[lints]`/`[workspace.lints]` table, no rustfmt config and no crate-level `#![deny]`.
- There are 11 `allow(dead_code)` and 4 `allow(clippy::too_many_arguments)`. Registry metadata (`PointCheck::id`/`issue`) is marked `cfg_attr(not(test), allow(dead_code))`, so it is unused at runtime.
- `sync::Mutex::lock` returns `Result<_, Infallible>`, which keeps about 650 `.unwrap()` calls alive and mixes them with poisonable std locks (see the unwrap section).
- Dead code: `net::start_attack` and `Shared.attack` (an old Intruder engine) are reached only by the test at `net.rs` (`start_attack(shared.clone(), ...)` in `mod tests`); the 15 dead `App` fields.

**Change**
- `[workspace.lints.clippy]` with `all = "warn"`, `redundant_clone`, `needless_collect`, `large_enum_variant`, and `unwrap_used = "warn"` for non-test code once the lock API changes.
- Add `cargo clippy --all-targets -- -D warnings` to `ci.sh` (through `wp-queue`).
- Replace `allow` with `expect` plus a reason (handbook ch. 2).
- Make `sync::Mutex::lock()` return the guard directly, as `parking_lot` does and as the unstable [`std::sync::nonpoison::Mutex`](https://doc.rust-lang.org/unstable-book/library-features/nonpoison-mutex.html) (rust-lang/rust#134645) does. Migrate the std-Mutex files to the wrapper.
- Delete the legacy attack engine and the dead fields.

**Size** S, though the lint-clean pass is M if done in one go; enable warnings first. **Risk** low. **Incremental** yes.

### F13. Test seams

**Evidence**
- `MitmAuthority::new` uses `cfg!(test)` to avoid the user's CA directory. That flag is false when core is compiled as a dependency of the desktop crate's tests, so `src/ui.rs` and `src/tools.rs` tests that call `net::Shared::new()` read, or create and write, `~/.config/webprobe/ca.json` unless `WEBPROBE_CA_DIR` is set.
- 129 `Shared::new()` call sites each generate a 2048-bit RSA key. `Cargo.toml` raises dependency optimisation for exactly this reason.
- Tests contain about 80 `thread::sleep` calls. For example, `tasks.rs` tests sleep 400, 800 and 2,500 ms and assert counts.
- There is no `tests/` directory: 18.5k test lines live inside `src`.
- Fuzzing is a hand-written seeded generator (`fuzz_tests.rs`), with no coverage guidance.
- QA hooks sit in production paths: 49 environment variables, `WEBPROBE_SEED_REPEATER` inside `Shared::new`, and the self-test inside `App::ui`.

**Change**
- `Shared::builder().ca(test_ca()).build()`, with the test CA cached in a `OnceLock`.
- Event-driven waits (`ScanRun::wait_idle` already exists; add `TaskRun::wait_state`) instead of sleeps.
- An injectable clock where timing matters.
- `cargo-fuzz` targets for `codec`, `h2`/`h2_server`, WebSocket frames, `project::load` and `collaborator` DNS/HTTP parsing ([cargo-fuzz book](https://rust-fuzz.github.io/book/cargo-fuzz.html)).
- One `Config` struct parsed at start-up; QA hooks behind a `qa` feature.
- Move live-lab tests to `core/tests/` with `#[ignore]` plus an env gate.

**Size** S–M. **Risk** low. **Incremental** yes. The flaky headless crawl test belongs here (event wait instead of wall clock).

### F14. Extensibility seams are close, but not one pattern

**Evidence**
- Active checks: `PointCheck`/`RequestCheck`/`StoredCheck` traits in static slices.
- Passive checks: a `unit!` function table (`passive_checks::PASSIVE_CHECKS`) plus a separate `scan::PASSIVE_LIBRARY` metadata list. That is two lists to keep in step.
- `ScanIssue.sev`/`confidence` are `String`; `is_burp_issue` scans a text file per call.
- Session-rule actions are matched by string (`"set header"`, `"check session"`, ...), and so are `ext_calls` ops.
- Two JSON-lines protocols (`ext_process` API v1 and the Montoya bridge), each with its own deadline, dead-marking and line-cap code.
- On the positive side, the `ProxyHooks` trait unifies both protocols at the pipeline.

**Change**
- One `CheckMeta { id, issue, severity: Severity, confidence: Confidence }` used by all check kinds, with passive checks registered like active ones.
- `Severity` and `Confidence` enums with serde names, so the project format is unchanged.
- A shared `JsonLinesPeer` transport (it pairs with F2) and serde-tagged enums for wire messages.
- Session actions as an enum.

**Size** M. **Risk** low. **Incremental** yes.

### F15. Project persistence is one JSON document

**Evidence**
- `project::save` writes the whole `ProjectData` as pretty JSON (`to_writer_pretty`), with bodies as text or base64.
- Autosave rewrites it every 60 s when anything changed (`App::ui`, `tools::autosave_project`). This runs off the UI thread, but `project_snapshot` builds the data on it.
- `restore_project` runs `project::load` on the UI thread.
- `project::load` memory-maps a user file (`unsafe Mmap::map`); external truncation while it is mapped raises SIGBUS.
- The session body store (`body.rs`) is a separate, unlinked segment store that saving does not reuse.

**Why it matters**
- Save cost is proportional to all traffic ever captured. Burp's project file is incremental.

**Change (when the trigger is hit)**
- A segmented project: persisted append-only body segments (the `body.rs` design, kept rather than unlinked), plus a small index document with history metadata, settings and issues. Saves become incremental. The JSON export stays.
- Read the index with `read`, not `mmap`.
- Trigger: a project over about 100 MB, or an autosave longer than about 1 s.

**Size** L. **Risk** medium (format migration; `PROJECT_VERSION` already exists). **Incremental** yes, behind a version bump.

## Sync vs async: verdict

Keep the synchronous, thread-based engine. The evidence does not justify a Tokio rewrite:
- The pipeline is request-scoped blocking I/O plus CPU work (parsing, checks, regexes). It runs at Burp-like concurrency: one browser with tens of connections, capped at `MAX_CONNECTIONS = 1024`.
- `codec`, `h2`, `h2_server` and the whole `net.rs` pipeline are generic over `Read + Write`.
- Tokio's own guide lists CPU-bound parallel work as a case where Tokio "is not a good fit" ([tokio.rs tutorial](https://tokio.rs/tokio/tutorial)).
- Async code must reach an `.await` roughly every 10–100 µs ([Alice Ryhl, "Async: What is blocking?"](https://ryhl.io/blog/async-what-is-blocking/)). Scanner checks and passive analysis would need `spawn_blocking` or rayon anyway.
- A port would cost L–XL (about 10k lines of I/O code and its tests), with high risk and no parity gain.

Where an event-driven model does pay is the long-lived bidirectional streams: WebSocket relays, the h2 client side and pass-through tunnels. Today these poll every 2 ms because `rustls::StreamOwned` cannot be split. Use readiness waits (`polling`/`mio`) or two blocking threads where the stream can be split (plain TCP). If more than a handful of such streams ever need multiplexing, a small Tokio island (`tokio-rustls`) for relays only is a reasonable later step; tokio is already an optional dependency.

What the guides contribute regardless of runtime:
- Cancellation tokens plus a task tracker (F4).
- Bounded queues with backpressure: the passive queue (F8), the event channel (F11) and the sidecar writer (F2).
- Never hold a lock across I/O (F2, F3).

## Proposed sequence

1. **Now: small items that do not conflict with feature work.**
   - F12: warn-level lints, clippy in CI, guard-returning lock, dead-code removal.
   - F3: compiled rule sets; the filter outside the history lock.
   - F9 (the intercept-liveness half): liveness for HTTP intercept.
   - F13: test CA injection and the CA-directory fix.
2. **F1: engine duties into core** (Collaborator service, project capture/restore, typed tool sends). This fixes headless scans and unlocks R-15.
3. **Settings snapshot (F5, first half)**, then the **R-18 engine split of `Shared`** (F5, second half), with F7 typed errors at the boundaries this touches (`project`, `net` send).
4. **F6 explicit `SendCtx`**, then **F8 scanner pool and passive queue**, then **F4 lifecycle** (listeners, runner, relays).
   - R-12 send groups and single-packet attack need F6.
   - R-13 needs the passive queue from F8.
5. **R-18 UI split** of `App` and `ui.rs` into per-tool view structs (the draft's §5 steps 1–14 and §6 file split). It is cheaper after steps 2–3 because fewer fields move and views no longer carry engine logic.
6. **F11 event channel and append-only history**: can run in parallel with step 5, and should come before history sizes grow past about 50k rows.
7. **Independent items.**
   - F2 sidecar demultiplexing: before R-20.
   - F10 bytes in tool state: before the R-05 protocol switch work grows the editors further.
   - F14 seam consistency: alongside R-13/R-14.
   - F15 project format: when its trigger is hit.

## Keep as is

- **The crate split**, with no GUI dependency in `webprobe-core`, enforced by `layering_tests`.
- **`body::Body`**: inline `Arc<[u8]>` or append-only mapped segments. Writes go through `pwrite` and reads through a read-only map, with a `SAFETY` comment. This is the right large-history design.
- **`ProxyHistory` encapsulation**: private rows, every write spills, scoped readers. Extend it (F11) rather than replace it.
- **`ScanRun` with `ScanGuard` and a condvar**: panic-safe claim and release, and `wait_idle` without polling.
- **Extension hooks run after the registry lock is dropped** (`Shared::ext_handle_request`), and failures degrade to pass-through.
- **Session rules do not hold locks across macro sends** (`apply_session_rules_for`, `run_macro_text`).
- **`util::read_capped` / `capped_lines` everywhere input is read**; `MAX_CONNECTIONS`; `MAX_CONCURRENT_STREAMS`; `catch_unwind` around HPACK.
- **The seeded parser fuzz suite and the live-lab tests.** Add to them; do not replace them.
- **Waker-driven repaint with 200/1000 ms fallbacks** (`App::ui`), and the incremental, virtualized history table (`proxy_history`, `table.rs`).
- **The Intruder worker pool** (`intruder_run`, `max_concurrent`): the template for F8.
- **Minimal `unsafe`**: three real sites, each justified. The `project.rs` mmap is revisited in F15.

## Sources consulted

Local:
- `qa/ZOOM-OUT-REVIEW-2026-11-18.md`, `qa/PANIC-AUDIT-2026-11-18.md`, `docs/specs/R-18-decomposition.research.md`, `tasks.json`, `app/graphify-out/GRAPH_REPORT.md` (god nodes: `Shared` 211 edges, `App` 170).
- `/root/.agents/skills/rust-best-practices` (Apollo handbook ch. 2 linting, ch. 4 errors), `rust-patterns`, `rust-async-patterns`, `rust-testing`.

Web (fetched or searched for this review):
- regex crate, "Avoid re-compiling regexes, especially in a loop": https://docs.rs/regex/latest/regex/#avoid-re-compiling-regexes-especially-in-a-loop
- Tokio tutorial, "When not to use Tokio": https://tokio.rs/tokio/tutorial
- Tokio graceful shutdown (CancellationToken, TaskTracker): https://tokio.rs/tokio/topics/shutdown
- Alice Ryhl, "Async: What is blocking?": https://ryhl.io/blog/async-what-is-blocking/
- `std::sync::nonpoison::Mutex` (unstable, rust-lang/rust#134645): https://doc.rust-lang.org/unstable-book/library-features/nonpoison-mutex.html
- egui background threads and repaint: https://github-redirect.dependabot.com/emilk/egui/pull/1389 ; Wayland minimized-repaint issue: https://www.goodfirstissue.org/de-DE/emilk/egui/issues/5136

Cited from known references, not fetched in this session:
- Rust API Guidelines C-GOOD-ERR: https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err
- cargo-fuzz book: https://rust-fuzz.github.io/book/cargo-fuzz.html

## Not verified

- Run-time behaviour; nothing was built or run.
- Burp's own browser-side connection reuse (F9).
- Whether the Java bridge can handle concurrent requests without changes (F2).
- Exact cost figures. The regex compile cost is the regex docs' range; nothing was measured on this code.

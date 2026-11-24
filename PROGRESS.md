# WebProbe build progress

## Status 2026-11-18

`tasks.json` is the source of truth: 125 tasks, 101 done, 2 rejected, 22 todo (D-09, D-10, D-11 and the roadmap epic R-01..R-19). Where the project stands per area, and the roadmap: `qa/ZOOM-OUT-REVIEW-2026-11-18.md`. Per-wave detail after P-13: `qa/SOURCE-PARITY-2026-11-15.md`. The round log below is history and stops at 2026-11-15; three of its statements are no longer true and are corrected in place: the Intruder engine is wired to the tab (P-10, done), there is an embedded-browser launcher (L-05, done), and the engine modules moved from `app/src/` to `app/core/src/` (N-07).

## Round log

- 2026-11-12 (agent session): Took over the build directly after the builder agent hit repeated
  provider failures (kilo free quota 429, then opencode plugin-activation 503s). Fixed builder
  reliability: builder now runs on opencode/zen free model with a plugin-free config dir.

- A-01 ✅ Decode Transfer-Encoding: chunked (req+resp) — app/src/codec.rs decode_chunked,
  normalize_request/normalize_response, read_message framing; tests: single/multi-chunk, trailers,
  incomplete, 4 MiB body. Content-Length corrected; byte counts exact.
- A-02 ✅ Decode Content-Encoding gzip/deflate/br — decode_content (flate2/brotli); wire bytes
  forwarded untouched; tests per codec + unknown-encoding passthrough + proxy integration.
- A-03 ✅ Keep-alive and connection reuse — Shared.pool/tls_pool per (host, port), keep_alive
  default false per ProjectDefaults http.http1.enable_keep_alive, Connection header set accordingly,
  pipelining off; test asserts 1 upstream connection for 2 requests (pool_hits=1).
- A-04 ✅ Robust HTTP/1.x parsing — parse_http: absolute-form→origin-form, obsolete folding joined,
  duplicate headers preserved, Transfer-Encoding wins over Content-Length (RFC 9112 §6.3), malformed
  input never panics; tests in util.rs + codec.rs + net.rs.

Verification: `cargo test` → 52 passed, 0 failed. `cargo build` clean.
- A-05 ✅ HTTP/2 upstream and h2c — app/src/h2.rs: minimal sync HTTP/2 client (RFC 9113 subset: preface,
  SETTINGS/ACK, HEADERS with HPACK, CONTINUATION, DATA, WINDOW_UPDATE flow control, PING, GOAWAY, push
  refusal), responses normalized to HTTP/1.1 shape. net.rs: ALPN ["h2","http/1.1"] offered on upstream TLS;
  ALPN h2 → h2 client; direct plain connections attempt h2c Upgrade (RFC 7540 §3.2) with HTTP2-Settings,
  non-101 replies fall back to the HTTP/1.1 response. tls.rs: server_config_with_alpn for h2 test servers.
  Tests: h2c upgrade roundtrip, h2c decline → HTTP/1.1 fallback, TLS ALPN h2 roundtrip. 57 tests pass.
- A-06 ✅ TLS pass-through and mTLS — net.rs: `tls_bypass` host list (exact + `*.wildcard`, one label) gives a raw byte relay
  (relay_tunnel) in handle_connect instead of MITM; `ClientCertRule` list + `tls_client_config()` presents a per-host
  client certificate to upstream TLS; tls.rs: `client_auth_config`, `MitmAuthority::client_certificate` (CA-signed, clientAuth
  EKU), `server_config_with_client_auth`. Tests: bypass relays raw bytes, client cert presented to an mTLS-required server,
  host matching (exact/wildcard/case). 60 tests pass.
- A-07 ✅ Proxy listener options — net.rs: `ListenerSpec`/`ListenerState`, extra listener workers (non-blocking
  accept, generation-based restart without losing history), `set_listeners` validation (empty bind, port 0,
  duplicate bind:port), `listener_status` snapshot; ui.rs dashboard lists every listener with running/error state.
  Tests: extra_listener_serves_traffic, listener_validation, listener_restart_keeps_history. 65 tests pass.
- A-08 ✅ Invisible proxying — origin-form requests routed by Host header (host_of), absolute-form converted
  to origin-form upstream (util::origin_form). Tests: invisible_proxying_uses_host_header, absolute_form_forwarded_as_origin_form.
- M-01 ✅ Design tokens — theme.rs is the single token module: spacing scale, radius, typography scale,
  named colors; the last ad-hoc hex colors in ui.rs now use tokens.
- M-05 ✅ Theming and density — Palette (dark / light / high contrast) + Density (compact / comfortable) +
  font scale, applied live (apply_current each frame), persisted in ProjectData.appearance with serde
  defaults (older project files keep working), editable from the dashboard Appearance section.
- M-02 ✅ Table component — app/src/table.rs: Column + TableState (sort column/direction + filter), sort_rows/
  filter_rows helpers, and table_body/data_table rendering a sortable header plus a virtualized body
  (ScrollArea::show_rows) with clickable rows. Wired into Proxy history, Target requests, Scanner issues,
  Intruder results and the Collaborator interaction list (table + detail pane). History filtering/sorting
  happens over the full snapshot before the 1000-row render cap. Tests: sort asc/desc, stable unsorted order,
  case-insensitive filter, empty filter. 71 tests pass.
- M-03 ✅ Editor component — app/src/editor.rs: one EditorState (wrap + find), message_editor (monospace code
  editor with match count) and message_view (head lines tinted, body as one block so large bodies stay cheap),
  plus bytes_view and split_message/match_count helpers. Wired into the Proxy detail raw view, Proxy intercept,
  Repeater, Intruder, Sequencer manual samples and Decoder. Tests: CRLF/LF splitting, message without body,
  case-insensitive match counting. 74 tests pass.
- M-04 ✅ Feedback and errors — app/src/feedback.rs: Toasts (6 s TTL, max 4, dismissable) fed by a process-wide
  queue so worker threads can raise them without a UI handle; progress bar with Cancel; inline error with Retry;
  shared empty and loading states. Wired into the frame loop, project save/restore, Scanner (start, progress,
  cancel, finish), Intruder (progress, cancel, empty state), target site map (loading, filter-empty),
  Repeater (inline error + Retry, completion toasts) and listener bind failures. Table filter boxes now
  actually filter (target, scanner, intruder) before the row count is shown. Tests: TTL expiry, toast cap,
  queue drain. 77 tests pass.
- M-06 ✅ Keyboard and accessibility — app/src/shortcuts.rs. ACTIONS is Burp's own 50-pair default table,
  lifted from resources/Preferences/UserDefaults.json → user_options.misc.hotkeys and joined to the command
  ids/labels/categories of burp.Zmcg (48 of 50 map; send_to_burp_at and open_burp_at are extension-provided).
  Every hotkey must include Ctrl (Burp's shipped rule), and all 50 defaults parse and format back unchanged.
  Duplicate refusal matches burp.Zfhv.ZT in both directions (chord taken, or action already bound). Bindings
  are user-level (~/.config/webprobe/hotkeys.json) and file-authoritative like burp.Zfhv.Zh, so clearing a
  hotkey survives a restart. Ctrl+K opens the command palette: wired commands, recents first, category and
  chord beside each row, arrows/Enter/Escape, and clicking a row runs it. The top bar's Settings window holds
  Appearance and a Hotkeys table with per-row Clear/Reset plus inline conflict and save errors. Only wired
  chords are consumed, so Ctrl+C/V/X/Z/Y/A and word navigation still reach the focused editor. 86 tests pass.

- M-07 ✅ Onboarding — app/src/onboarding.rs. The checklist is computed from live state (listener running, CA
  trusted, traffic seen, intercept state) so it can never claim a step that has not happened. The proxy answers
  http://webprobe and http://burpsuite itself instead of forwarding upstream — the shipped docs make clear the CA
  is fetched *through* the listener (certificate/index.html, proxy-troubleshooting.html) — serving a setup page
  with the CA in both formats (/webprobe-ca.pem, /webprobe-ca.der) and the real listener port. "Send sample
  traffic" routes one request through the listener and reports the status line. Dashboard panel with Hide, docs
  links to the public pages, and an explicit note that WebProbe has no bundled browser (true then; L-05 has since added the launcher). 91 tests pass.

- P-13 ✅ WSL2 rendering fix + QA driver (2026-11-15) — root cause was LIBGL_ALWAYS_INDIRECT=1 from ~/.zshrc plus no /dev/dri render node (Mesa 26 fell through to zink). app/src/gl_env.rs repairs the process environment before any window exists; qa/qa.sh drives the live window on Xvfb (proxy 6566, never 8080/8081). 107 tests then.
- P-14 ✅ UI wiring repair — a bad edit had dropped calls into tested helpers (history filter bar, Comparer, scope editor, project controls, listeners, appearance); restored from the dead-code warnings, one history_view pipeline, unique scroll ids, glyph fallback font.
- B-01 ✅ History table — filter/sort/columns/virtualization verified live. B-02, B-05, C-01, C-02 in progress (see tasks.json evidence).
- Intruder engine core (C-01/C-02): app/src/intruder.rs, 10 tests, 117 pass. Wired to the tab since (P-10, done 2026-11-16); the engine now lives in app/core/src/.
- Gap analysis vs live Burp Pro v2026.7.3: 12 new open tasks P-01..P-12 in TASKS.md section 7 and tasks.json (qa/GAP-REPORT-2026-11-15.md).

- 2026-11-24 ✅ Integration and roadmap reconciliation — parity `7648c40` now contains #203 (h2 diagnostic/fmt), #163 (TLS check), #181 (M8/R-10 checks), #190 (R-15 CLI/REST), #205 (host-probe correction #201, DOM composition #200, D-12/R-12 #192, Rust 2024/MSRV 1.95 #196) and #206 (TLS chain-validity). `scripts/ci.sh` all five gates green; `cargo test --workspace` 164 desktop + 1209 core passed, 15 ignored, 0 failed; clippy/fmt clean; hosted CI green including 1.95.0. `tasks.json` reconciled to **120 done / 15 todo / 2 rejected** (D-12, R-11, R-12, R-14, R-17 moved to done with evidence; R-13 stays open: 14 DOM families plus prototype pollution landed, but stored submission is disabled and the coverage matrix lists uncovered sinks). Craft confirmed the rebuilt binary contains the `/v0.1/scan` route, prototype-pollution check, send-group path, BCheck generation and Flash/Silverlight policy checks.

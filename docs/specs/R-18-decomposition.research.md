# R-18 decomposition research — splitting `App` and `Shared` into owned subsystem types

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

Read-only structural analysis. No files in `app/` were edited; no build, test, app run, git operation or network access was used. Every WebProbe claim below carries a `file:line` (line numbers are from the files as read on 2026-11-18). Anything that could not be established is marked **not established** and listed at the end.

## 0. Scope and method

* Target structs: `pub struct App` at `src/main.rs:74`–`357` and `pub struct Shared` at `core/src/net.rs:772`–`920`.
* The brief said "about 197" `App` fields and "about 62" `Shared` fields. The declarations contain **198** and **72** fields respectively (every `pub`/`pub(crate)` field line between the braces was counted); the full lists are in §1. This is a discrepancy with the brief, not a missing field.
* Touch counts (§2) come from one pass over every `.rs` file under `app/` except `target/` and `graphify-out/`, matching the regex `(?<![\w.])(?:self|app|shared|sh)\.<field>\b` exactly as the brief specified. `self.<field>` inside *other* structs with the same field name is included (e.g. `self.tab` at `core/src/ext_process.rs:282` belongs to an extension-process struct, not `App`); these few false positives are called out where relevant. Constructor field initialisers (`App::new`, `src/main.rs:728`–`939`; `Shared::new`, `core/src/net.rs:924`–`1023`) do **not** match the four prefixes and are therefore not counted.
* Owned-type pattern to follow (read): `core/src/history.rs:1`–`132` (private `Mutex<Vec<HistEntry>>`, methods `push`/`extend`/`replace_all`/`clear`/`len`/`stamp`/`get`/`with_rows`/`snapshot`), `core/src/scan_run.rs:1`–`114` (private busy lock + condvar, public atomics for progress), `core/src/oob.rs:1`–`321`, `core/src/repeater_run.rs:1`–`127` (one `Mutex<State>` so a superseded send cannot overwrite a newer one), `core/src/stored.rs:1`–`317`, `core/src/passive_state.rs:1`–`97`. Common shape: `#[derive(Default)]` or explicit `Default`, private fields, public methods that own each invariant, `Arc<Subsystem>` stored inside `Shared`/`App` where worker threads need it.

## 1. Full field lists

### 1.1 `App` — 198 fields (`src/main.rs:74`–`357`)


| field | type | purpose (evidence: declaration) |
|---|---|---|
| `shared` | `Arc<net::Shared>` | Arc to engine state shared with worker threads. (L75) |
| `logger` | `logger::Logger` | Cross-tool HTTP Logger mirrored from proxy history every frame. (L77) |
| `log_filter` | `logger::LogQuery` | Filter driving the Logger view. (L79) |
| `log_seen` | `u64` | Highest proxy history id already mirrored into logger. (L81) |
| `log_sel` | `Option<u64>` | Selected Logger row. (L83) |
| `org_sel` | `Option<u64>` | Selected Organizer item. (L85) |
| `intr_sub` | `usize` | Intruder sub-tab (0 Positions, 1 Payloads). (L87) |
| `intercept_fwd_all` | `bool` | "Forward all" mode of the Intercept Forward split button (src/ui.rs:2841-2856). (L90) |
| `intercept_drop_all` | `bool` | "Drop all" mode of the Intercept Drop split button (src/ui.rs:2858-2873). (L91) |
| `ws_sel` | `Option<u64>` | Declared and initialised only; no read/write found under the four prefixes; overlaps State::ws_sel in src/repeater_ops.rs:1050 (see not-established). (L93) |
| `tab` | `ui::Tab` | Currently open top-level tool tab (src/main.rs:1144, src/menus.rs:81). (L94) |
| `proxy_sub` | `usize` | Selected Proxy sub-tab (src/ui.rs:2777-2783). (L95) |
| `history_sel` | `Option<u64>` | Selected row in Proxy > HTTP history (src/ui.rs). (L96) |
| `history_multi` | `table::MultiSelect` | Ctrl/Shift multi-selection in the proxy history table. (L98) |
| `waker_installed` | `bool` | Whether the engine wake-up calls point at this window yet. (L100) |
| `mcp` | `mcp_hook::Mcp` | UI automation hook (no-op without the mcp feature). (L102) |
| `split_detail` | `f32` | Height of the Proxy message pane, dragged by a splitter. (L104) |
| `rep_split` | `f32` | Repeater request pane's share of the request\|response width. (L106) |
| `map_split` | `f32` | Site map tree share of the Target width. (L108) |
| `target_host_sel` | `Option<String>` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L109) |
| `target_hosts` | `Vec<String>` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L110) |
| `target_items` | `Vec<(String, String, String, u64)>,` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L111) |
| `map_cache_len` | `usize` | Site-map cache invalidation sentinel: set to usize::MAX to force a rebuild (src/discovery.rs:580, src/tools.rs:2092). (L112) |
| `autosave_at` | `std::time::Instant` | When the project autosave last ran (src/main.rs:540-541). (L115) |
| `autosave_sig` | `(usize, usize, usize)` | (history, issues, repeaters) counts seen by the last autosave (src/main.rs:509-513, 1158). (L116) |
| `hist_table` | `table::TableState` | Table state for Proxy HTTP history (sort, filter, columns). (L118) |
| `hist_filter` | `history_filter::HistoryFilter` | Proxy HTTP history filter bar. (L120) |
| `hist_cache` | `Arc<Vec<net::HistEntry>>` | Cached filtered/sorted history rows, keyed on filter inputs. (L123) |
| `hist_cache_len` | `usize` | Source row count the cache was built from; detects history growth (src/ui.rs:698-708). (L124) |
| `hist_cache_key` | `String` | Filter inputs the cache was built for; cleared to invalidate (src/ui.rs:657, src/engagement.rs:386). (L125) |
| `hist_cache_truncated` | `bool` | Whether the cache was cut short at the row limit (src/ui.rs:703, 716). (L126) |
| `scan_table` | `table::TableState` | Table state for the scanner issue list. (L128) |
| `intr_table` | `table::TableState` | Table state for the intruder result list. (L130) |
| `target_table` | `table::TableState` | Table state for the target site-map request list. (L132) |
| `toasts` | `feedback::Toasts` | Transient toast notifications. (L134) |
| `shortcuts` | `shortcuts::Shortcuts` | User hotkey bindings, persisted in ~/.config/webprobe/hotkeys.json. (L137) |
| `palette` | `shortcuts::Palette` | Command palette state (Ctrl+K). (L139) |
| `hotkey_capture` | `Option<usize>` | Action index waiting for a key press in the hotkey settings table. (L141) |
| `hotkey_notice` | `Option<String>` | Last hotkey-settings message (conflict or save error). (L143) |
| `settings_open` | `bool` | Whether the Settings window is open. (L145) |
| `settings_help` | `ui::SettingsPane` | Selected pane inside the Settings window. (L146) |
| `onboarding_hidden` | `bool` | First-run setup panel dismissed for this session. (L148) |
| `dec_hex` | `bool` | Whether Decoder stage 0 input is shown as hex (src/ui.rs:2334, 2352). (L150) |
| `intercept_edit` | `String` | Declared and initialised only; the editable Intercept pane uses intercept_text instead (src/ui.rs:2954). (L151) |
| `detail_sub` | `usize` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L152) |
| `req_pane` | `msgpane::PaneState` | Message-pane state of the Proxy history request viewer (src/ui.rs:1275). (L154) |
| `resp_pane` | `msgpane::PaneState` | Message-pane state of the Proxy history response viewer. (L155) |
| `issue_tab` | `usize` | Selected tab of the scanner issue detail view (src/issue_view.rs:319-324). (L158) |
| `issue_pane` | `msgpane::PaneState` | Message-pane state of the scanner issue detail view. (L159) |
| `issue_filter` | `issue_view::IssueFilter` | Filter and grouping state for the issue list. (L160) |
| `insp_state` | `msgpane::InspectorState` | State of the Inspector message pane. (L161) |
| `dock_sel` | `usize` | Right dock selection: 0 Inspector, 1 Notes, 2 collapsed. (L163) |
| `ai` | `ai::AiChat` | WebProbe AI chat state. (L165) |
| `browser_url` | `Option<(String, String)>` | Queued "show response in browser" dialog (title, URL) (src/ui.rs:447-464, 1049). (L167) |
| `csrf_poc` | `Option<String>` | Queued CSRF PoC HTML dialog (src/ui.rs:467-483, 1071). (L168) |
| `hist_window_open` | `bool` | Whether the extra HTTP history window is open. (L169) |
| `hist_window_filter` | `String` | Search text in the extra history window. (L170) |
| `hist_window_table` | `table::TableState` | Table state of the extra history window. (L171) |
| `ext_sub` | `usize` | Selected Extensions sub-tab (src/tools.rs:1212-1216). (L173) |
| `ext_sel` | `Option<usize>` | Selected extension row (src/tools.rs:1396-1451). (L174) |
| `ext_table` | `table::TableState` | Table state of the extension list. (L175) |
| `ext_detail` | `usize` | Selected detail tab inside the extension view (src/tools.rs:1473-1480). (L176) |
| `ext_add_open` | `bool` | Whether the Add extension dialog is open. (L177) |
| `ext_add_path` | `String` | File path entered in the Add extension dialog. (L178) |
| `ext_add_kind` | `webprobe_core::ext_store::Kind` | Add dialog kind: Java jar or WebProbe process extension. (L180) |
| `ext_loading` | `std::sync::Arc<std::sync::atomic::AtomicBool>` | Flag set while an extension is loading in the background. (L182) |
| `ext_add_done` | `std::sync::Arc<std::sync::atomic::AtomicBool>` | Flag set when an Add-dialog load succeeds (closes the dialog). (L184) |
| `ext_tab_busy` | `std::sync::Arc<std::sync::atomic::AtomicBool>` | Flag guarding the background extension-tab refresh. (L186) |
| `ext_tab_at` | `f64` | When the last extension-tab refresh started (UI time). (L187) |
| `seq_sub` | `usize` | Selected Sequencer sub-tab (Live capture, Manual load, settings). (L190) |
| `seq_requests` | `Vec<net::HistEntry>` | Requests sent to Sequencer (copies of history entries). (L191) |
| `seq_req_sel` | `Option<usize>` | Selected row in the Sequencer request list. (L192) |
| `seq_table` | `table::TableState` | Table state of the Sequencer request list. (L193) |
| `seq_loc` | `usize` | Token location kind: 0 cookie, 1 form field, 2 custom regex. (L194) |
| `seq_field` | `String` | Selected form-field name (src/tools.rs:344-365). (L195) |
| `seq_custom` | `String` | Custom regex for the token location (src/tools.rs:374, 482). (L196) |
| `seq_load_path` | `String` | File path for Manual load (src/tools.rs:393-398). (L197) |
| `seq_live_buf` | `Option<Arc<Mutex<Vec<Vec<u8>>>>>` | Shared buffer of tokens captured live (src/tools.rs:217, 499). (L198) |
| `seq_live_stop` | `Option<Arc<std::sync::atomic::AtomicBool>>` | Stop flag for live capture (src/tools.rs, src/main.rs). (L199) |
| `intercept_cur` | `Option<u64>` | Id of the held Intercept item currently being edited. (L201) |
| `intercept_text` | `String` | Edited text of the held Intercept item. (L202) |
| `intercept_pane` | `msgpane::PaneState` | Message-pane state of the Intercept editor. (L203) |
| `dec_chain` | `Vec<(String, bool)>` | Decoder stages after stage 0: (text, hex view) pairs. (L205) |
| `cmp_items` | `Vec<String>` | Items shown in the two Comparer tables. (L207) |
| `cmp_sel1` | `Option<usize>` | Selected item in Comparer table 1. (L208) |
| `cmp_sel2` | `Option<usize>` | Selected item in Comparer table 2. (L209) |
| `cmp_table1` | `table::TableState` | Table state of Comparer table 1. (L210) |
| `cmp_table2` | `table::TableState` | Table state of Comparer table 2. (L211) |
| `cmp_paste_pending` | `bool` | Flag: a Paste command is waiting for clipboard text (src/ui.rs:4022, 4070). (L212) |
| `cmp_load_path` | `String` | File path for the Comparer Load action. (L213) |
| `cmp_window` | `Option<(usize, usize, bool)>` | Which Compare button opened the result window: (i1, i2, open). (L214) |
| `cmp_result` | `Option<compare::Comparison>` | Token-level comparison shown in the compare window. (L217) |
| `cmp_hex` | `bool` | Hex view toggle in the comparison window. (L219) |
| `cmp_sync` | `bool` | Sync-views toggle in the comparison window. (L220) |
| `cmp_scroll` | `egui::Vec2` | Scroll offset shared by the two comparison panes. (L221) |
| `cmp_export_path` | `String` | File path the comparison Export button writes. (L222) |
| `cmp_unit_label` | `&'static str` | Comparison unit of the open window: Words, Bytes or Characters. (L224) |
| `log_on` | `bool` | Whether the Logger tool is enabled (src/main.rs:395, src/ui.rs:4279). (L226) |
| `log_table` | `table::TableState` | Table state of the Logger view. (L227) |
| `log_req_pane` | `msgpane::PaneState` | Message-pane state of the Logger request viewer. (L228) |
| `log_resp_pane` | `msgpane::PaneState` | Message-pane state of the Logger response viewer. (L229) |
| `org_search` | `String` | Search text in the Organizer view. (L230) |
| `org_table` | `table::TableState` | Table state of the Organizer view. (L231) |
| `org_req_pane` | `msgpane::PaneState` | Message-pane state of the Organizer request viewer. (L232) |
| `org_resp_pane` | `msgpane::PaneState` | Message-pane state of the Organizer response viewer. (L233) |
| `intr_target` | `String` | Target URL text for Intruder attacks. (L237) |
| `intr_update_host` | `bool` | Whether to rewrite the Host header to match the target. (L238) |
| `intr_pane` | `msgpane::PaneState` | Message-pane state of the Intruder base-request editor. (L239) |
| `intr_dock` | `usize` | Intruder right dock: 0 Payloads, 1 Resource pool, 2 Settings, 3 closed. (L240) |
| `intr_set_sel` | `usize` | Selected payload set index. (L241) |
| `intr_add` | `String` | Text entered by the Add payload-item action. (L242) |
| `intr_load_path` | `String` | File path for the payload Load action. (L243) |
| `intr_paste_pending` | `bool` | Flag: a Paste command is waiting for clipboard text. (L244) |
| `intr_results_open` | `bool` | Whether the Intruder attack-results window is open. (L245) |
| `intr_attack_no` | `usize` | Sequence number shown in the attack-results window title. (L246) |
| `intr_row_sel` | `Option<usize>` | Selected row in the attack-results table. (L247) |
| `intr_res_req_pane` | `msgpane::PaneState` | Message-pane state of the attack-results request viewer. (L248) |
| `intr_res_resp_pane` | `msgpane::PaneState` | Message-pane state of the attack-results response viewer. (L249) |
| `intr_x` | `intruder_ui::IntruderExtra` | Intruder attack settings, running attack and results-window state (owned type in src/intruder_ui.rs). (L251) |
| `target_sub` | `usize` | Selected Target sub-tab (Site map, Scope, Issues). (L253) |
| `target_view` | `usize` | Selected Target view: 0 tree, 1 table. (L254) |
| `target_node` | `Option<(String, String)>` | Selected site-map tree node (origin, path). (L255) |
| `site_filter` | `site_map::SiteFilter` | Site map filter inputs (text, in-scope only, hide unrequested). (L258) |
| `site_cache` | `Arc<(Vec<net::HistEntry>, Vec<(String, String)>)>` | Filtered site-map contents (history rows, unrequested links). (L259) |
| `site_cache_key` | `String` | Inputs the site cache was built for. (L260) |
| `site_tree` | `Arc<std::collections::BTreeMap<String, ui::MapNode>>` | Site map tree built from site_cache. (L262) |
| `site_tree_key` | `String` | Key the site tree was built for. (L263) |
| `site_rows` | `Arc<Vec<usize>>` | Indices into site_cache for the selected site-map node. (L265) |
| `site_rows_key` | `String` | Key the site_rows index was built for. (L266) |
| `target_entry` | `Option<u64>` | Selected site-map history entry id. (L267) |
| `site_req_pane` | `msgpane::PaneState` | Message-pane state of the site-map request viewer. (L268) |
| `site_resp_pane` | `msgpane::PaneState` | Message-pane state of the site-map response viewer. (L269) |
| `dash_task` | `usize` | Selected Dashboard task card (0 crawl, 1 live audit, 2 active scan). (L272) |
| `dash_sub` | `usize` | Selected Dashboard sub-tab (Summary, Audit items, Issues, Event log, Logger, ...). (L273) |
| `dash_search` | `String` | Search text in the Dashboard task list. (L274) |
| `dash_items_table` | `table::TableState` | Table state of the Dashboard task list. (L275) |
| `new_scan_open` | `bool` | Whether the New scan dialog is open. (L276) |
| `new_scan_urls` | `String` | URL text in the New scan dialog. (L277) |
| `new_scan_type` | `usize` | New scan type: 0 Crawl and audit, 1 Audit selected items. (L279) |
| `rep_req_pane` | `msgpane::PaneState` | Message-pane state of the Repeater request editor. (L281) |
| `rep_resp_pane` | `msgpane::PaneState` | Message-pane state of the Repeater response viewer. (L282) |
| `rep_target_edit` | `bool` | Whether the Repeater Configure-target dialog is open. (L283) |
| `rep_update_cl` | `bool` | Whether Repeater updates Content-Length on edit. (L284) |
| `search_open` | `bool` | Whether the Search window is open. (L286) |
| `event_log_open` | `bool` | Whether the Event log window is open. (L287) |
| `event_log_table` | `table::TableState` | Table state of the Event log window. (L288) |
| `mem` | `(f64, f64)` | (process MB, machine MB) cached for the status-bar memory gauge. (L290) |
| `mem_at` | `Option<std::time::Instant>` | When the memory gauge cache was last refreshed. (L291) |
| `detail_view` | `usize` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L292) |
| `scan_sel` | `Option<u64>` | Selected scanner issue row. (L293) |
| `intr_req` | `String` | Base request text for Intruder. (L294) |
| `intr_https` | `bool` | Whether the Intruder target is HTTPS. (L295) |
| `intr_payloads` | `String` | Declared and initialised only; payload text lives in intr_sets (src/main.rs:300). (L296) |
| `intr_attack` | `intruder::AttackType` | Intruder attack type (the four C-01 variants). (L298) |
| `intr_sets` | `Vec<String>` | Raw payload text per payload set, one payload per line. (L300) |
| `intr_sources` | `Vec<intruder::PayloadSource>` | Payload type per set (Simple list, generated, extension, ...). (L303) |
| `intr_ext_proc` | `Vec<String>` | Per-set extension payload processor name, "" for none. (L306) |
| `dec_input` | `String` | Decoder input text. (L307) |
| `dec_results` | `Vec<(String, String)>` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L308) |
| `dec_output` | `String` | Latest Decoder output text. (L310) |
| `dec_sel_decode` | `Option<decoder_ops::Op>` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L311) |
| `dec_sel_encode` | `Option<decoder_ops::Op>` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L312) |
| `dec_sel_hash` | `Option<decoder_ops::Op>` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L313) |
| `scope_only` | `bool` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L314) |
| `seq_mode` | `usize` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L315) |
| `seq_ignore_abnormal` | `bool` | Whether abnormal-length tokens are ignored (src/tools.rs, src/settings_dialog.rs). (L316) |
| `seq_capture_limit` | `usize` | Stop live capture after this many tokens (clamped 100..=20_000). (L318) |
| `seq_auto_analyze` | `bool` | Re-analyse every 100 tokens during live capture. (L319) |
| `seq_selector` | `String` | Selected cookie name for the token location. (L320) |
| `seq_manual` | `String` | Token text entered in the Manual load pane. (L321) |
| `seq_samples` | `Vec<Vec<u8>>` | Tokens captured or loaded for analysis. (L322) |
| `seq_stats` | `Option<analysis::TokenStats>` | Token statistics computed from seq_samples. (L323) |
| `seq_report` | `Option<analysis::SequencerReport>` | Sequencer analysis report. (L324) |
| `seq_bits` | `Option<seq_bits::BitReport>` | Bit-level analysis of seq_samples (None below 100 tokens). (L327) |
| `seq_export_path` | `String` | File path for the bit-report export buttons. (L328) |
| `seq_status` | `String` | Status line under the Sequencer panes. (L329) |
| `comparer_state` | `analysis::ComparerState` | Left/right strings and recompute state for the analysis comparer. (L330) |
| `search_query` | `String` | Search text in the Search window. (L331) |
| `search_case` | `bool` | Case-sensitive toggle in the Search window. (L332) |
| `search_results` | `Vec<analysis::SearchHit>` | Hits produced by the last Search-all-tools run. (L333) |
| `project_path` | `String` | Path of the current project file. (L334) |
| `project_status` | `String` | Status line shown for project open/save actions. (L335) |
| `chooser` | `project_start::Chooser` | Start-window / Project-menu chooser state. (L337) |
| `collab_state` | `collaborator::CollaboratorState` | Collaborator client state (registered ids, interactions). (L338) |
| `macro_name` | `String` | Name field of the macro editor in Session handling settings. (L339) |
| `macro_request` | `String` | Request text field of the macro editor. (L340) |
| `rep_sel` | `usize` | Selected Repeater tab index. (L341) |
| `rops` | `repeater_ops::State` | Repeater/intercept/WebSockets owned state (src/repeater_ops.rs). (L343) |
| `rep_view` | `usize` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L345) |
| `rep_req_view` | `usize` | Declared and initialised only; no read/write found under the four prefixes (see not-established). (L347) |
| `port_txt` | `String` | Proxy listener port text field in the status bar (src/ui.rs:1156-1162). (L348) |
| `frames` | `usize` | Frame counter used by the QA selftest/screenshot hook (src/main.rs:587-638). (L349) |
| `saved` | `bool` | Whether the QA selftest finished successfully (src/main.rs:642). (L350) |
| `shot_added` | `bool` | Whether the QA screenshot was already captured (src/main.rs:625-635). (L351) |
| `selftest_done` | `bool` | Whether the QA selftest already ran (src/main.rs:587-588). (L352) |
| `grab_done` | `Option<Arc<Mutex<bool>>>` | Completion flag for the QA screenshot grab (src/main.rs:629-635). (L353) |
| `screenshot` | `Option<PathBuf>` | Output path for the QA screenshot (src/main.rs). (L354) |
| `eng` | `engagement::State` | Engagement, content-discovery, reporting and recovery owned state (src/engagement.rs). (L356) |


### 1.2 `Shared` — 72 fields (`core/src/net.rs:772`–`920`)


| field | type | purpose (evidence: declaration) |
|---|---|---|
| `mitm` | `crate::tls::MitmAuthority` | Local HTTPS CA and server configs for MITM. (L773) |
| `tls_upstream` | `Arc<rustls::ClientConfig>` | Shared rustls client config for upstream TLS. (L774) |
| `intercept_on` | `AtomicBool` | Whether HTTP Intercept is enabled. (L775) |
| `response_rules` | `Mutex<ResponseInterceptRules>` | Response interception rules from Proxy settings. (L777) |
| `queue` | `Mutex<Vec<InterceptItem>>` | Messages held by Intercept. (L778) |
| `history` | `crate::history::ProxyHistory` | Proxy HTTP history (owned ProxyHistory). (L779) |
| `events` | `Mutex<Vec<String>>` | Event log lines (capped at 500 by `Shared::log`, core/src/net.rs:1025–1035). (L780) |
| `h2c_upgrade` | `AtomicBool` | Attempt h2c upgrade on cleartext (WEBPROBE_H2C=1). (L783) |
| `crawl_capture` | `AtomicBool` | Live passive crawl of proxied responses into the site map. (L786) |
| `site_links` | `Mutex<std::collections::BTreeSet<(String, String)>>` | Unrequested site-map items discovered by the live crawl. (L789) |
| `crawl_items` | `crate::history::ProxyHistory` | Crawler-requested site-map items (owned ProxyHistory). (L792) |
| `extra_checks` | `AtomicBool` | Report WebProbe-only passive checks. (L794) |
| `attack` | `Mutex<Arc<Attack>>` | Current Intruder attack snapshot (Mutex<Arc<Attack>>). (L795) |
| `repeaters` | `Mutex<Vec<RepTab>>` | Repeater tabs (host, port, https, request, response, result). (L796) |
| `next_id` | `AtomicU64` | Monotonic history entry id allocator. (L797) |
| `proxy_port` | `std::sync::atomic::AtomicU16` | Primary proxy listener port. (L798) |
| `browser_port` | `std::sync::atomic::AtomicU16` | Private listener port of the embedded browser. (L800) |
| `browsers` | `Mutex<Vec<(u32, String)>>` | Browsers opened from WebProbe: (pid, profile dir). (L802) |
| `issues` | `Mutex<Vec<crate::scan::ScanIssue>>` | Scanner issues found so far. (L803) |
| `listener_http2` | `AtomicBool` | Primary listener's ALPN h2 support flag. (L807) |
| `streaming` | `Mutex<crate::streaming::StreamSettings>` | Streaming response settings. (L809) |
| `stream_skips` | `Mutex<std::collections::HashSet<(String, &'static str)>>` | (host, reason) pairs already reported as stream-skipped. (L812) |
| `organizer` | `Mutex<crate::organizer::Organizer>` | Organizer's shared item store. (L814) |
| `tool_sends` | `Mutex<Vec<crate::ext_calls::ToolSend>>` | Tool-send messages from extensions waiting for the UI. (L817) |
| `scan_enabled` | `AtomicBool` | Whether the scanner is enabled. (L818) |
| `scan` | `crate::scan_run::ScanRun` | Active scan run state (owned ScanRun). (L820) |
| `oob` | `crate::oob::OobState` | Collaborator ids and interaction matching (owned OobState). (L822) |
| `stored` | `crate::stored::StoredInputs` | Stored-input pairing for the current scan run (owned StoredInputs). (L824) |
| `passive` | `crate::passive_state::PassiveState` | Passive-scan state across responses (owned PassiveState). (L827) |
| `rep` | `crate::repeater_run::RepeaterRun` | Repeater send-in-flight state (owned RepeaterRun). (L829) |
| `active_connections` | `AtomicUsize` | Number of client connections currently handled. (L831) |
| `tasks` | `Mutex<Vec<crate::tasks::ScanTask>>` | Scan task queue. (L833) |
| `next_task_id` | `AtomicU64` | Monotonic scan-task id allocator. (L834) |
| `task_runner` | `AtomicBool` | Whether the task-runner loop is active. (L835) |
| `waker` | `Mutex<Option<Arc<dyn Fn() + Send + Sync>>>` | Front-end redraw callback. (L839) |
| `scan_speed` | `AtomicU8` | Audit speed: 0 fast, 1 normal, 2 thorough. (L841) |
| `scan_config` | `Mutex<crate::scan_config::ScanConfig>` | Which passive/active checks and insertion types run. (L843) |
| `scan_accuracy` | `AtomicU8` | Audit accuracy: 0 few false negatives, 2 few false positives. (L846) |
| `scan_locations` | `Mutex<std::collections::BTreeSet<String>>` | Locations already passively audited. (L848) |
| `mr_request` | `Mutex<Vec<crate::rules::MrRule>>` | Request match-and-replace rules. (L850) |
| `mr_response` | `Mutex<Vec<crate::rules::MrRule>>` | Response match-and-replace rules. (L851) |
| `scope` | `Mutex<Vec<ScopeRule>>` | Target scope include/exclude rules. (L853) |
| `session_rules` | `Mutex<Vec<SessionRule>>` | Session handling rules and their actions. (L855) |
| `browser_recovery` | `BrowserRecovery` | In-browser "check session" recovery prompt state. (L857) |
| `macros` | `Mutex<Vec<Macro>>` | Reusable session-handling request macros. (L858) |
| `ws_history` | `Mutex<Vec<WsEntry>>` | Captured WebSocket handshakes and frames. (L860) |
| `diff_tracker` | `Mutex<DiffTracker>` | Diff-count state for the history table. (L862) |
| `ext_host` | `Mutex<crate::ext_host::ExtensionHost>` | Loaded extensions and their hook registry. (L864) |
| `ws_intercept_client` | `AtomicBool` | Intercept client-to-server WebSocket messages. (L868) |
| `ws_intercept_server` | `AtomicBool` | Intercept server-to-client WebSocket messages. (L869) |
| `ws_edited` | `Mutex<std::collections::HashSet<u64>>` | WebSocket history ids whose payload was edited. (L872) |
| `ip_cache` | `Mutex<std::collections::HashMap<String, String>>` | Host to IP cache for the history IP column. (L874) |
| `tool_log` | `Mutex<Vec<ToolExchange>>` | Tool exchanges waiting for the Logger. (L878) |
| `cookie_jar` | `Mutex<crate::cookie_jar::CookieJar>` | Suite-wide session-handling cookie jar. (L882) |
| `macro_last_response` | `Mutex<Vec<u8>>` | Last macro response, used to fill session-rule placeholders. (L886) |
| `intercept_rules` | `Mutex<Vec<crate::intercept_rules::InterceptRule>>` | HTTP request interception rules. (L889) |
| `listener_redirects` | `Mutex<std::collections::HashMap<u16, (String, u16)>>` | Listener port to (host, port) redirect map. (L893) |
| `messages` | `std::sync::atomic::AtomicUsize` | Monotonic count of proxied messages. (L895) |
| `upstream` | `Mutex<crate::upstream::UpstreamConfig>` | Global direct/HTTP/SOCKS upstream route. (L897) |
| `upstream_rules` | `Mutex<Vec<crate::upstream::UpstreamRule>>` | Per-destination upstream proxy rules. (L899) |
| `listener_running` | `AtomicBool` | Whether the primary listener is running. (L900) |
| `listener_restart` | `AtomicBool` | Whether a listener restart was requested. (L901) |
| `keep_alive` | `AtomicBool` | Whether outgoing HTTP/1.x keep-alive is enabled. (L904) |
| `tls_bypass` | `Mutex<Vec<String>>` | Hosts exempt from MITM (SSL pass-through). (L907) |
| `client_certs` | `Mutex<Vec<ClientCertRule>>` | Client certificates for upstream mTLS. (L909) |
| `tls_roots` | `Mutex<rustls::RootCertStore>` | Trusted roots for upstream TLS. (L911) |
| `pool` | `Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>` | Idle HTTP/1.x upstream connections by (host, port). (L913) |
| `tls_pool` | `Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>` | Idle TLS upstream connections by (host, port). (L914) |
| `listeners` | `Mutex<Vec<Arc<ListenerState>>>` | Extra proxy listeners beyond the primary one. (L916) |
| `listener_generation` | `AtomicU64` | Generation counter bumped when the listener set changes. (L918) |
| `conns_opened` | `AtomicUsize` | Count of upstream connections opened. (L919) |
| `pool_hits` | `AtomicUsize` | Count of connections reused from the pool. (L920) |


## 2. Which files touch each field

Counting method: see §0. A `—` row means the field has no `self.`/`app.`/`shared.`/`sh.` hit anywhere; a bare-name search was then used to check whether it is only declared/initialised (results folded into the purpose column in §1).

### 2.1 `App`


| field | files that touch it (hits per file) | total |
|---|---|---|
| `shared` | `src/ui.rs`:177, `src/tools.rs`:139, `src/repeater_ops.rs`:21, `src/proxy_settings.rs`:20, `core/src/collaborator.rs`:18, `src/engagement.rs`:17, `src/main.rs`:15, `core/src/scan_checks.rs`:13, `src/onboarding.rs`:11, `src/settings_dialog.rs`:6, `src/discovery.rs`:4, `src/intruder_ui.rs`:4, `core/src/scan.rs`:2, `src/menus.rs`:2, `src/report.rs`:2, `core/src/net.rs`:1, `core/src/scan_run.rs`:1, `src/project_start.rs`:1, `src/sitemap_compare_ui.rs`:1 | 455 |
| `logger` | `src/ui.rs`:5, `src/tools.rs`:4, `src/main.rs`:2 | 11 |
| `log_filter` | `src/ui.rs`:3 | 3 |
| `log_seen` | `src/main.rs`:5, `src/tools.rs`:1 | 6 |
| `log_sel` | `src/ui.rs`:4, `src/tools.rs`:1 | 5 |
| `org_sel` | `src/ui.rs`:6, `src/tools.rs`:1 | 7 |
| `intr_sub` | `src/tools.rs`:2 | 2 |
| `intercept_fwd_all` | `src/ui.rs`:6 | 6 |
| `intercept_drop_all` | `src/ui.rs`:6 | 6 |
| `ws_sel` | — (0 hits under all four prefixes) | 0 |
| `tab` | `src/ui.rs`:35, `src/repeater_ops.rs`:4, `src/menus.rs`:3, `core/src/ext_process.rs`:2, `src/tools.rs`:2, `src/main.rs`:1 | 47 |
| `proxy_sub` | `src/ui.rs`:3, `src/tools.rs`:2 | 5 |
| `history_sel` | `src/ui.rs`:17, `src/project_start.rs`:1, `src/tools.rs`:1 | 19 |
| `history_multi` | `src/ui.rs`:6 | 6 |
| `waker_installed` | `src/main.rs`:2 | 2 |
| `mcp` | `src/main.rs`:3 | 3 |
| `split_detail` | `src/ui.rs`:5, `src/tools.rs`:2 | 7 |
| `rep_split` | `src/tools.rs`:2, `src/ui.rs`:2 | 4 |
| `map_split` | `src/tools.rs`:2, `src/ui.rs`:2 | 4 |
| `target_host_sel` | — (0 hits under all four prefixes) | 0 |
| `target_hosts` | — (0 hits under all four prefixes) | 0 |
| `target_items` | — (0 hits under all four prefixes) | 0 |
| `map_cache_len` | `src/discovery.rs`:1, `src/tools.rs`:1 | 2 |
| `autosave_at` | `src/main.rs`:2 | 2 |
| `autosave_sig` | `src/main.rs`:3 | 3 |
| `hist_table` | `src/ui.rs`:13 | 13 |
| `hist_filter` | `src/ui.rs`:4 | 4 |
| `hist_cache` | `src/ui.rs`:4 | 4 |
| `hist_cache_len` | `src/ui.rs`:6 | 6 |
| `hist_cache_key` | `src/ui.rs`:6, `src/project_start.rs`:2, `src/engagement.rs`:1 | 9 |
| `hist_cache_truncated` | `src/ui.rs`:2 | 2 |
| `scan_table` | `src/ui.rs`:3 | 3 |
| `intr_table` | `src/intruder_ui.rs`:3 | 3 |
| `target_table` | `src/ui.rs`:2 | 2 |
| `toasts` | `src/main.rs`:3 | 3 |
| `shortcuts` | `src/ui.rs`:4, `src/shortcuts.rs`:1 | 5 |
| `palette` | `src/ui.rs`:5, `src/main.rs`:1 | 6 |
| `hotkey_capture` | `src/ui.rs`:3, `src/shortcuts.rs`:2 | 5 |
| `hotkey_notice` | `src/ui.rs`:4, `src/shortcuts.rs`:2 | 6 |
| `settings_open` | `src/settings_dialog.rs`:3, `src/ui.rs`:3, `src/main.rs`:1, `src/menus.rs`:1 | 8 |
| `settings_help` | `src/settings_dialog.rs`:5, `src/main.rs`:1, `src/menus.rs`:1, `src/ui.rs`:1 | 8 |
| `onboarding_hidden` | `src/ui.rs`:2, `src/menus.rs`:1 | 3 |
| `dec_hex` | `src/ui.rs`:2 | 2 |
| `intercept_edit` | — (0 hits under all four prefixes) | 0 |
| `detail_sub` | — (0 hits under all four prefixes) | 0 |
| `req_pane` | `src/ui.rs`:1 | 1 |
| `resp_pane` | `src/ui.rs`:1 | 1 |
| `issue_tab` | `src/issue_view.rs`:5 | 5 |
| `issue_pane` | `src/issue_view.rs`:1 | 1 |
| `issue_filter` | `src/ui.rs`:4 | 4 |
| `insp_state` | `src/ui.rs`:2 | 2 |
| `dock_sel` | `src/ui.rs`:10, `src/tools.rs`:2 | 12 |
| `ai` | `src/ui.rs`:12 | 12 |
| `browser_url` | `src/ui.rs`:5 | 5 |
| `csrf_poc` | `src/ui.rs`:4 | 4 |
| `hist_window_open` | `src/ui.rs`:3 | 3 |
| `hist_window_filter` | `src/ui.rs`:2 | 2 |
| `hist_window_table` | `src/ui.rs`:2 | 2 |
| `ext_sub` | `src/tools.rs`:3 | 3 |
| `ext_sel` | `src/tools.rs`:6 | 6 |
| `ext_table` | `src/tools.rs`:2 | 2 |
| `ext_detail` | `src/tools.rs`:6 | 6 |
| `ext_add_open` | `src/tools.rs`:4 | 4 |
| `ext_add_path` | `src/tools.rs`:3 | 3 |
| `ext_add_kind` | `src/tools.rs`:4 | 4 |
| `ext_loading` | `src/tools.rs`:6 | 6 |
| `ext_add_done` | `src/tools.rs`:2 | 2 |
| `ext_tab_busy` | `src/tools.rs`:2 | 2 |
| `ext_tab_at` | `src/tools.rs`:2 | 2 |
| `seq_sub` | `src/tools.rs`:5 | 5 |
| `seq_requests` | `src/tools.rs`:6, `src/repeater_ops.rs`:2, `src/ui.rs`:2 | 10 |
| `seq_req_sel` | `src/tools.rs`:6, `src/repeater_ops.rs`:1, `src/ui.rs`:1 | 8 |
| `seq_table` | `src/tools.rs`:2 | 2 |
| `seq_loc` | `src/tools.rs`:13 | 13 |
| `seq_field` | `src/tools.rs`:6 | 6 |
| `seq_custom` | `src/tools.rs`:2 | 2 |
| `seq_load_path` | `src/tools.rs`:2 | 2 |
| `seq_live_buf` | `src/tools.rs`:2 | 2 |
| `seq_live_stop` | `src/tools.rs`:3, `src/main.rs`:1 | 4 |
| `intercept_cur` | `src/ui.rs`:6 | 6 |
| `intercept_text` | `src/ui.rs`:7 | 7 |
| `intercept_pane` | `src/ui.rs`:2 | 2 |
| `dec_chain` | `src/ui.rs`:7 | 7 |
| `cmp_items` | `src/ui.rs`:11, `src/repeater_ops.rs`:8, `src/tools.rs`:3, `src/intruder_ui.rs`:2 | 24 |
| `cmp_sel1` | `src/ui.rs`:7 | 7 |
| `cmp_sel2` | `src/ui.rs`:7 | 7 |
| `cmp_table1` | `src/ui.rs`:2 | 2 |
| `cmp_table2` | `src/ui.rs`:2 | 2 |
| `cmp_paste_pending` | `src/ui.rs`:3 | 3 |
| `cmp_load_path` | `src/ui.rs`:2 | 2 |
| `cmp_window` | `src/ui.rs`:4 | 4 |
| `cmp_result` | `src/ui.rs`:2 | 2 |
| `cmp_hex` | `src/ui.rs`:4 | 4 |
| `cmp_sync` | `src/ui.rs`:2 | 2 |
| `cmp_scroll` | `src/ui.rs`:3 | 3 |
| `cmp_export_path` | `src/ui.rs`:2 | 2 |
| `cmp_unit_label` | `src/ui.rs`:2 | 2 |
| `log_on` | `src/main.rs`:1, `src/ui.rs`:1 | 2 |
| `log_table` | `src/ui.rs`:2 | 2 |
| `log_req_pane` | `src/ui.rs`:1 | 1 |
| `log_resp_pane` | `src/ui.rs`:1 | 1 |
| `org_search` | `src/ui.rs`:2 | 2 |
| `org_table` | `src/ui.rs`:2 | 2 |
| `org_req_pane` | `src/ui.rs`:1 | 1 |
| `org_resp_pane` | `src/ui.rs`:1 | 1 |
| `intr_target` | `src/ui.rs`:4, `src/intruder_ui.rs`:3, `src/tools.rs`:3, `src/menus.rs`:1 | 11 |
| `intr_update_host` | `src/ui.rs`:2 | 2 |
| `intr_pane` | `src/ui.rs`:3 | 3 |
| `intr_dock` | `src/ui.rs`:9 | 9 |
| `intr_set_sel` | `src/ui.rs`:3, `src/tools.rs`:1 | 4 |
| `intr_add` | `src/ui.rs`:4 | 4 |
| `intr_load_path` | `src/ui.rs`:2 | 2 |
| `intr_paste_pending` | `src/ui.rs`:3 | 3 |
| `intr_results_open` | `src/intruder_ui.rs`:3, `src/ui.rs`:2 | 5 |
| `intr_attack_no` | `src/intruder_ui.rs`:1, `src/ui.rs`:1 | 2 |
| `intr_row_sel` | `src/intruder_ui.rs`:4 | 4 |
| `intr_res_req_pane` | `src/intruder_ui.rs`:1 | 1 |
| `intr_res_resp_pane` | `src/intruder_ui.rs`:1 | 1 |
| `intr_x` | `src/intruder_ui.rs`:27, `src/settings_dialog.rs`:2, `src/ui.rs`:2 | 31 |
| `target_sub` | `src/ui.rs`:3, `src/tools.rs`:2 | 5 |
| `target_view` | `src/ui.rs`:5, `src/tools.rs`:2 | 7 |
| `target_node` | `src/ui.rs`:6 | 6 |
| `site_filter` | `src/ui.rs`:7 | 7 |
| `site_cache` | `src/ui.rs`:2 | 2 |
| `site_cache_key` | `src/ui.rs`:3, `src/project_start.rs`:2 | 5 |
| `site_tree` | `src/ui.rs`:2 | 2 |
| `site_tree_key` | `src/ui.rs`:3 | 3 |
| `site_rows` | `src/ui.rs`:2 | 2 |
| `site_rows_key` | `src/ui.rs`:2 | 2 |
| `target_entry` | `src/ui.rs`:3 | 3 |
| `site_req_pane` | `src/ui.rs`:1 | 1 |
| `site_resp_pane` | `src/ui.rs`:1 | 1 |
| `dash_task` | `src/ui.rs`:10, `src/tools.rs`:2 | 12 |
| `dash_sub` | `src/ui.rs`:4 | 4 |
| `dash_search` | `src/ui.rs`:2 | 2 |
| `dash_items_table` | `src/ui.rs`:2 | 2 |
| `new_scan_open` | `src/ui.rs`:5 | 5 |
| `new_scan_urls` | `src/ui.rs`:2 | 2 |
| `new_scan_type` | `src/ui.rs`:3 | 3 |
| `rep_req_pane` | `src/ui.rs`:2 | 2 |
| `rep_resp_pane` | `src/ui.rs`:1 | 1 |
| `rep_target_edit` | `src/ui.rs`:4 | 4 |
| `rep_update_cl` | `src/menus.rs`:1, `src/repeater_ops.rs`:1, `src/settings_dialog.rs`:1, `src/ui.rs`:1 | 4 |
| `search_open` | `src/ui.rs`:5 | 5 |
| `event_log_open` | `src/ui.rs`:4, `src/menus.rs`:1 | 5 |
| `event_log_table` | `src/ui.rs`:2 | 2 |
| `mem` | `src/ui.rs`:2 | 2 |
| `mem_at` | `src/ui.rs`:2 | 2 |
| `detail_view` | — (0 hits under all four prefixes) | 0 |
| `scan_sel` | `src/ui.rs`:6 | 6 |
| `intr_req` | `src/ui.rs`:19, `src/intruder_ui.rs`:3, `src/menus.rs`:3, `src/tools.rs`:3 | 28 |
| `intr_https` | `src/tools.rs`:3, `src/ui.rs`:3, `src/menus.rs`:1 | 7 |
| `intr_payloads` | — (0 hits under all four prefixes) | 0 |
| `intr_attack` | `src/ui.rs`:4, `src/intruder_ui.rs`:3, `src/tools.rs`:2 | 9 |
| `intr_sets` | `src/ui.rs`:7, `src/tools.rs`:2, `src/intruder_ui.rs`:1 | 10 |
| `intr_sources` | `src/ui.rs`:9, `src/intruder_ui.rs`:1 | 10 |
| `intr_ext_proc` | `src/ui.rs`:4, `src/intruder_ui.rs`:2 | 6 |
| `dec_input` | `src/tools.rs`:3, `src/ui.rs`:2, `src/repeater_ops.rs`:1 | 6 |
| `dec_results` | — (0 hits under all four prefixes) | 0 |
| `dec_output` | `src/tools.rs`:2, `src/ui.rs`:1 | 3 |
| `dec_sel_decode` | — (0 hits under all four prefixes) | 0 |
| `dec_sel_encode` | — (0 hits under all four prefixes) | 0 |
| `dec_sel_hash` | — (0 hits under all four prefixes) | 0 |
| `scope_only` | — (0 hits under all four prefixes) | 0 |
| `seq_mode` | — (0 hits under all four prefixes) | 0 |
| `seq_ignore_abnormal` | `src/tools.rs`:2, `src/settings_dialog.rs`:1 | 3 |
| `seq_capture_limit` | `src/tools.rs`:2 | 2 |
| `seq_auto_analyze` | `src/tools.rs`:2 | 2 |
| `seq_selector` | `src/tools.rs`:6 | 6 |
| `seq_manual` | `src/tools.rs`:8 | 8 |
| `seq_samples` | `src/tools.rs`:19 | 19 |
| `seq_stats` | `src/tools.rs`:6 | 6 |
| `seq_report` | `src/tools.rs`:5 | 5 |
| `seq_bits` | `src/tools.rs`:4 | 4 |
| `seq_export_path` | `src/tools.rs`:1 | 1 |
| `seq_status` | `src/tools.rs`:8 | 8 |
| `comparer_state` | `src/ui.rs`:5 | 5 |
| `search_query` | `src/tools.rs`:3, `src/ui.rs`:1 | 4 |
| `search_case` | `src/tools.rs`:2 | 2 |
| `search_results` | `src/tools.rs`:3 | 3 |
| `project_path` | `src/tools.rs`:9, `src/recovery.rs`:6, `src/menus.rs`:4, `src/project_start.rs`:3, `src/main.rs`:2, `src/ui.rs`:1 | 25 |
| `project_status` | `src/tools.rs`:6, `src/project_start.rs`:2, `src/recovery.rs`:2 | 10 |
| `chooser` | `src/project_start.rs`:10, `src/main.rs`:2, `src/ui.rs`:2 | 14 |
| `collab_state` | `src/tools.rs`:7, `src/ui.rs`:5, `src/main.rs`:3, `src/settings_dialog.rs`:1 | 16 |
| `macro_name` | `src/tools.rs`:7 | 7 |
| `macro_request` | `src/tools.rs`:12 | 12 |
| `rep_sel` | `src/repeater_ops.rs`:16, `src/ui.rs`:13, `src/tools.rs`:2, `src/intruder_ui.rs`:1, `src/menus.rs`:1 | 33 |
| `rops` | `src/repeater_ops.rs`:23, `src/ui.rs`:12, `src/menus.rs`:5, `src/settings_dialog.rs`:2 | 42 |
| `rep_view` | — (0 hits under all four prefixes) | 0 |
| `rep_req_view` | — (0 hits under all four prefixes) | 0 |
| `port_txt` | `src/ui.rs`:2, `src/main.rs`:1 | 3 |
| `frames` | `src/main.rs`:5 | 5 |
| `saved` | `src/main.rs`:1 | 1 |
| `shot_added` | `src/main.rs`:3 | 3 |
| `selftest_done` | `src/main.rs`:2 | 2 |
| `grab_done` | `src/main.rs`:2 | 2 |
| `screenshot` | `src/main.rs`:2 | 2 |
| `eng` | `src/discovery.rs`:15, `src/report.rs`:14, `src/recovery.rs`:12, `src/engagement.rs`:8, `src/ui.rs`:6, `src/sitemap_compare_ui.rs`:4, `src/main.rs`:2, `src/tools.rs`:1 | 62 |


### 2.2 `Shared`


| field | files that touch it (hits per file) | total |
|---|---|---|
| `mitm` | `core/src/net.rs`:17, `core/src/h2_server_tests.rs`:5, `core/src/headless.rs`:2, `src/tools.rs`:1 | 25 |
| `tls_upstream` | `core/src/net.rs`:2 | 2 |
| `intercept_on` | `core/src/net.rs`:11, `core/src/ext_host.rs`:3, `core/src/ext_calls.rs`:2, `core/src/streaming_tests.rs`:2, `core/src/h2_server_tests.rs`:1, `src/main.rs`:1 | 20 |
| `response_rules` | `core/src/net.rs`:3, `core/src/streaming_tests.rs`:3, `core/src/h2_server_tests.rs`:1 | 7 |
| `queue` | `core/src/net.rs`:15, `core/src/streaming_tests.rs`:3, `core/src/ext_host.rs`:1, `core/src/h2_server_tests.rs`:1 | 20 |
| `history` | `core/src/net.rs`:12, `core/src/headless.rs`:5, `core/src/bin/webprobe-headless.rs`:3, `core/src/h2_server_tests.rs`:3, `src/main.rs`:3, `core/src/ext_calls.rs`:2, `core/src/project.rs`:2, `src/onboarding.rs`:2, `src/repeater_ops.rs`:2, `core/src/ext_host.rs`:1, `core/src/streaming_tests.rs`:1 | 36 |
| `events` | `core/src/scan.rs`:3, `core/src/streaming_tests.rs`:2, `core/src/net.rs`:1 | 6 |
| `h2c_upgrade` | `core/src/net.rs`:4 | 4 |
| `crawl_capture` | `core/src/net.rs`:1 | 1 |
| `site_links` | `core/src/net.rs`:1 | 1 |
| `crawl_items` | `core/src/ext_calls.rs`:2, `core/src/bin/webprobe-headless.rs`:1, `core/src/net.rs`:1, `core/src/scan.rs`:1 | 5 |
| `extra_checks` | `core/src/scan.rs`:3, `core/src/scan_checks.rs`:1 | 4 |
| `attack` | `core/src/net.rs`:2 | 2 |
| `repeaters` | `src/ui.rs`:6, `core/src/ext_calls.rs`:2, `core/src/ext_host.rs`:1, `src/repeater_ops.rs`:1 | 10 |
| `next_id` | `core/src/net.rs`:6, `core/src/crawl.rs`:4, `core/src/ext_host.rs`:3, `core/src/logger.rs`:3, `core/src/organizer.rs`:3, `core/src/ext_process.rs`:2, `core/src/scan.rs`:2, `src/main.rs`:2, `core/src/collaborator.rs`:1, `core/src/ext_calls.rs`:1 | 27 |
| `proxy_port` | `core/src/net.rs`:7, `core/src/headless.rs`:3, `src/main.rs`:3, `core/src/h2_server_tests.rs`:2, `core/src/streaming_tests.rs`:2, `src/onboarding.rs`:2, `core/src/bin/webprobe-headless.rs`:1, `core/src/fuzz_tests.rs`:1, `src/repeater_ops.rs`:1 | 22 |
| `browser_port` | `core/src/net.rs`:2 | 2 |
| `browsers` | `src/tools.rs`:2 | 2 |
| `issues` | `core/src/scan.rs`:16, `core/src/passive_checks.rs`:8, `core/src/bin/webprobe-headless.rs`:3, `core/src/tasks.rs`:3, `core/src/ext_host.rs`:2, `core/src/ext_process.rs`:2, `core/src/net.rs`:2, `core/src/ext_calls.rs`:1 | 37 |
| `listener_http2` | `core/src/net.rs`:2 | 2 |
| `streaming` | `core/src/streaming_tests.rs`:3, `core/src/h2.rs`:2, `core/src/net.rs`:2, `core/src/streaming.rs`:2, `src/repeater_ops.rs`:1 | 10 |
| `stream_skips` | `core/src/net.rs`:1 | 1 |
| `organizer` | `core/src/ext_calls.rs`:2 | 2 |
| `tool_sends` | `core/src/ext_calls.rs`:2, `core/src/ext_host.rs`:1 | 3 |
| `scan_enabled` | `core/src/net.rs`:3 | 3 |
| `scan` | `core/src/scan.rs`:31, `core/src/tasks.rs`:15, `core/src/scan_run.rs`:6, `core/src/crawl.rs`:3, `core/src/scan_checks.rs`:3, `core/src/bin/webprobe-headless.rs`:1, `core/src/headless.rs`:1 | 60 |
| `oob` | `core/src/scan.rs`:14, `core/src/ext_calls.rs`:3, `core/src/ext_host.rs`:2, `core/src/tasks.rs`:2, `src/main.rs`:1 | 22 |
| `stored` | `core/src/scan.rs`:13, `core/src/scan_checks.rs`:1 | 14 |
| `passive` | `core/src/scan.rs`:1 | 1 |
| `rep` | `src/ui.rs`:11, `src/repeater_ops.rs`:3, `core/src/ext_calls.rs`:1 | 15 |
| `active_connections` | `core/src/net.rs`:6, `core/src/fuzz_tests.rs`:2 | 8 |
| `tasks` | `core/src/tasks.rs`:12, `core/src/scan.rs`:1 | 13 |
| `next_task_id` | `core/src/tasks.rs`:1 | 1 |
| `task_runner` | `core/src/tasks.rs`:1 | 1 |
| `waker` | `core/src/net.rs`:2 | 2 |
| `scan_speed` | `core/src/scan.rs`:2, `core/src/bin/webprobe-headless.rs`:1 | 3 |
| `scan_config` | `core/src/scan.rs`:5, `core/src/passive_checks.rs`:4, `core/src/crawl.rs`:3, `core/src/scan_checks.rs`:2, `core/src/headless.rs`:1 | 15 |
| `scan_accuracy` | `core/src/scan.rs`:1 | 1 |
| `scan_locations` | `core/src/net.rs`:1 | 1 |
| `mr_request` | `core/src/net.rs`:3, `src/main.rs`:2 | 5 |
| `mr_response` | `core/src/net.rs`:2, `core/src/streaming_tests.rs`:1 | 3 |
| `scope` | `core/src/net.rs`:2, `src/history_filter.rs`:2, `src/repeater_ops.rs`:2, `core/src/ext_calls.rs`:1, `core/src/rules.rs`:1 | 8 |
| `session_rules` | `core/src/net.rs`:9, `core/src/ext_host.rs`:2 | 11 |
| `browser_recovery` | `core/src/net.rs`:4 | 4 |
| `macros` | `core/src/net.rs`:5 | 5 |
| `ws_history` | `core/src/net.rs`:5, `core/src/ext_calls.rs`:1 | 6 |
| `diff_tracker` | `core/src/net.rs`:1 | 1 |
| `ext_host` | `core/src/ext_store.rs`:5, `core/src/net.rs`:5, `src/ext_menu.rs`:4, `core/src/ext_calls.rs`:3, `core/src/ext_host.rs`:2, `src/main.rs`:2, `core/src/scan.rs`:1 | 22 |
| `ws_intercept_client` | `core/src/ext_host.rs`:1, `core/src/net.rs`:1 | 2 |
| `ws_intercept_server` | `core/src/net.rs`:2 | 2 |
| `ws_edited` | `core/src/net.rs`:3 | 3 |
| `ip_cache` | `core/src/net.rs`:3 | 3 |
| `tool_log` | `core/src/net.rs`:4 | 4 |
| `cookie_jar` | `core/src/net.rs`:17, `core/src/ext_calls.rs`:2 | 19 |
| `macro_last_response` | `core/src/net.rs`:2 | 2 |
| `intercept_rules` | `core/src/net.rs`:1 | 1 |
| `listener_redirects` | `core/src/net.rs`:3 | 3 |
| `messages` | `core/src/ai.rs`:3, `core/src/net.rs`:1 | 4 |
| `upstream` | `core/src/net.rs`:1 | 1 |
| `upstream_rules` | `core/src/net.rs`:1 | 1 |
| `listener_running` | `core/src/net.rs`:6, `core/src/headless.rs`:2, `src/onboarding.rs`:2, `core/src/bin/webprobe-headless.rs`:1, `core/src/fuzz_tests.rs`:1, `core/src/h2_server_tests.rs`:1, `core/src/streaming_tests.rs`:1 | 14 |
| `listener_restart` | `core/src/net.rs`:4 | 4 |
| `keep_alive` | `core/src/net.rs`:3 | 3 |
| `tls_bypass` | `core/src/net.rs`:1 | 1 |
| `client_certs` | `core/src/net.rs`:1 | 1 |
| `tls_roots` | `core/src/net.rs`:2 | 2 |
| `pool` | `core/src/net.rs`:4, `core/src/oob.rs`:4 | 8 |
| `tls_pool` | `core/src/net.rs`:2 | 2 |
| `listeners` | `core/src/net.rs`:6 | 6 |
| `listener_generation` | `core/src/net.rs`:9 | 9 |
| `conns_opened` | `core/src/net.rs`:6 | 6 |
| `pool_hits` | `core/src/net.rs`:3 | 3 |


## 3. Proposed subsystem types

Two families of types are proposed. `AppSubsystem` types are **single-threaded UI state**: plain `struct`s with private fields and methods, stored by value on `App`; their methods take `&mut self` (and `&Shared` where they need engine data) and are called from the egui callbacks. `SharedSubsystem` types are **thread-safe**: private `Mutex`/atomics plus methods, stored by value or in `Arc` inside `Shared`; they follow the six owned types already in `core/src/`. No behaviour, persistence format or wire format changes.

Guiding rule from the existing pattern: fields become private, and *every* read/write site from §2 becomes a method call. A field with ≥4 touching files gets a narrow API (named verbs, no returned `&mut` handle); a field with 1–2 touching files may keep a pub(crate) accessor inside its owning module.

### 3.1 `App`: 16 proposed groups

#### A1. `AppShared` — root engine handle (do not extract)
* **Fields**: `shared` (L75). **Owner**: `src/main.rs`. **Files**: all 19 files in §2.1.
* **Methods**: none on the new type; `App::shared()` / `App::shared_mut()` are already satisfied by the public field. Keep this one field public on `App`: 455 hits in 19 files, including all engine call sites (`core/src/collaborator.rs:314`–`486`, `core/src/scan_checks.rs:131`–`726`). Extracting it would add an indirection with no benefit.
* **Narrow API need**: not a group to split; instead split `Shared` itself (§3.2), so call sites become `app.shared.proxy.*`, `app.shared.scan.*`, etc.

#### A2. `ProxyView` — Proxy HTTP history, filter, cache, message panes, extra window
* **Owner file**: new `src/proxy_view.rs` (or `src/proxy_settings.rs`, which already owns `proxy_settings` UI). **Fields**: `proxy_sub`, `history_sel`, `history_multi`, `hist_table`, `hist_filter`, `hist_cache`, `hist_cache_len`, `hist_cache_key`, `hist_cache_truncated`, `split_detail`, `req_pane`, `resp_pane`, `detail_sub`, `insp_state`, `dock_sel`, `browser_url`, `csrf_poc`, `hist_window_open`, `hist_window_filter`, `hist_window_table`. 20 fields.
* **Files to edit**: `src/ui.rs` (history view 689–1102, detail 1249–1316, menu windows 446–542, helpers 405–442, 563–605), `src/project_start.rs` (invalidate at 23–25, 68–70), `src/engagement.rs:386`, `src/tools.rs:768, 1944, 2168, 2175`.
* **Methods derived from the sites**: `selected()`, `select(id)`, `multi()`, `table_mut()`, `filter_mut()`, `invalidate()` (clears `hist_cache_key`; 6 files touch the key at `src/ui.rs:657,679,698,704,1085,1302`, `src/project_start.rs:23,68`, `src/engagement.rs:386`), `cache_mut()` (rebuild at `src/ui.rs:698–716`), `extra_window_mut()`, `queue_browser_url()`, `queue_csrf_poc()`, `panes_mut()`, `split_mut()`.
* **Narrow API**: `hist_cache_key` / `hist_cache` / `hist_cache_len` / `hist_cache_truncated` (invariant: cache and key travel together) and `history_sel` / `history_multi` (19 and 6 hits). Do not expose the four cache fields; `invalidate()` plus a `cached_rows(&Shared)` method should replace the 9 direct key writes.

#### A3. `InterceptView` — held message UI
* **Owner file**: `src/proxy_view.rs` (same module as A2; it shares the Proxy tab and the held-id handoff at `src/ui.rs:2436`). **Fields**: `intercept_fwd_all`, `intercept_drop_all`, `intercept_cur`, `intercept_text`, `intercept_pane`, `intercept_edit`. 6 fields.
* **Files to edit**: `src/ui.rs` (2807–3011, 2436, etc.; 6 hits each on the two split-button flags at 2841–2873), `src/main.rs:779`.
* **Methods**: `held_id()`, `hold(id, text)`, `release(&Shared)`, `edited_text()`, `pane_mut()`, `forward_all()`, `drop_all()`.
* **Narrow API**: `intercept_cur` + `intercept_text` must be released together (`src/ui.rs:2436`: `intercept_cur.take()` then a cloned `intercept_text` passed to `net::intercept_release`); one `release()` method keeps that pairing. `intercept_edit` is dead (§1.1) and can simply be deleted as part of the move (structure-only removal of an unread field — no behaviour change).

#### A4. `IntruderView` — Intruder tool state
* **Owner file**: new `src/intruder_view.rs`; the attack engine/results logic is already in `src/intruder_ui.rs` (`IntruderExtra` at `src/main.rs:251`). **Fields**: `intr_sub`, `intr_table`, `intr_target`, `intr_update_host`, `intr_pane`, `intr_dock`, `intr_set_sel`, `intr_add`, `intr_load_path`, `intr_paste_pending`, `intr_results_open`, `intr_attack_no`, `intr_row_sel`, `intr_res_req_pane`, `intr_res_resp_pane`, `intr_x`, `intr_req`, `intr_https`, `intr_attack`, `intr_sets`, `intr_sources`, `intr_ext_proc`, `intr_payloads`. 23 fields.
* **Files to edit**: `src/ui.rs` (1583–1928), `src/intruder_ui.rs` (31 hits on `intr_x`, 27 on `intr_req`), `src/tools.rs` (project snapshot 1927/1932, restore 2190–2195, menus 1757–1758), `src/menus.rs` (75–77, 130–137), `src/settings_dialog.rs:103–105`.
* **Methods**: `target()`, `set_target()`, `base_request_mut()`, `attack_config()` (returns `intr_x` plus `intr_attack`/`intr_sets`/`intr_sources`/`intr_ext_proc` as a single config view), `payload_set_mut(n)`, `begin_attack()`, `results_mut()`, `select_row()`, `sub_tab()`, `dock_mut()`.
* **Narrow API**: `intr_x` (31 hits in 3 files), `intr_req` (28 hits in 4 files), `cmp_items` interaction at `src/intruder_ui.rs:839–843` should go through `app.comparer().push_item()` (see A9), `intr_target` (11 hits, 4 files).

#### A5. `RepeaterView` — Repeater tabs, panes, views
* **Owner file**: `src/repeater_ops.rs` (already owns `State` = `rops`). **Fields**: `rep_split`, `rep_req_pane`, `rep_resp_pane`, `rep_target_edit`, `rep_update_cl`, `rep_sel`, `rops`, `rep_view`, `rep_req_view`. 9 fields.
* **Files to edit**: `src/repeater_ops.rs` (23 hits on `rops`, 16 on `rep_sel` — it should become the owner module with methods), `src/ui.rs` (1933–2307 and 2616–2658), `src/menus.rs` (135, 163–175), `src/settings_dialog.rs:113–116`, `src/intruder_ui.rs:680`, `src/tools.rs:1954, 2179`.
* **Methods**: `current_tab()`, `select_tab(i)`, `tabs_mut()`, `send(&Shared)`, `cancel(&Shared)` (already `ui::repeater_send`/`cancel_repeater_send` at `src/ui.rs:2194, 2312`), `set_view()`, `panes_mut()`, `target_dialog_mut()`.
* **Narrow API**: `rops` (42 hits, 4 files) and `rep_sel` (33 hits, 5 files) are the widest UI fields after `shared`/`tab`. Add `RepeaterView::current()` and `RepeaterView::send_state()` so `src/ui.rs` and `src/menus.rs` stop indexing `app.rops.tabs[app.rep_sel]` directly. `rep_view`/`rep_req_view` are dead (§1.1).

#### A6. `ScannerView` — issue list and issue detail
* **Owner file**: `src/issue_view.rs` (already owns `IssueFilter`). **Fields**: `scan_table`, `issue_tab`, `issue_pane`, `issue_filter`, `scan_sel`, `insp_state`, `dock_sel`. 7 fields.
* **Files to edit**: `src/ui.rs` (1341–1549, 1249–1316), `src/issue_view.rs` (5 hits on `issue_tab`, 1 on `issue_pane` — becomes owner module).
* **Methods**: `selected_issue()`, `select_issue()`, `filter_mut()`, `table_mut()`, `detail_tab_mut()`, `pane_mut()`, `inspector_mut()`, `dock_mut()`.
* **Narrow API**: `issue_filter` (4 hits, all in `src/ui.rs:1430–1463`) can move verbatim into `issue_view.rs`; `scan_sel`/`dock_sel` need named methods because dashboard/repeater/issue panes all read `dock_sel` (12 hits in 2 files).

#### A7. `DashboardView` — task cards and New scan dialog
* **Owner file**: new `src/dashboard_view.rs` (or `src/issue_view.rs` if keeping file count low). **Fields**: `dash_task`, `dash_sub`, `dash_search`, `dash_items_table`, `new_scan_open`, `new_scan_urls`, `new_scan_type`. 7 fields.
* **Files to edit**: `src/ui.rs` (3120–3613), `src/tools.rs:1949, 2174`.
* **Methods**: `task()`, `select_task()`, `sub_tab_mut()`, `search_mut()`, `items_table_mut()`, `new_scan_mut()` (dialog fields travel together).
* **Narrow API**: `dash_task` (12 hits, 2 files) and the three `new_scan_*` fields should be encapsulated; the dialog has a single open/save cycle at `src/ui.rs:3176,3446,3471,3475`.

#### A8. `SequencerView`
* **Owner file**: new `src/sequencer_view.rs` (the analysis is in `src/tools.rs:177–505`). **Fields**: `seq_sub`, `seq_requests`, `seq_req_sel`, `seq_table`, `seq_loc`, `seq_field`, `seq_custom`, `seq_load_path`, `seq_live_buf`, `seq_live_stop`, `seq_mode`, `seq_ignore_abnormal`, `seq_capture_limit`, `seq_auto_analyze`, `seq_selector`, `seq_manual`, `seq_samples`, `seq_stats`, `seq_report`, `seq_bits`, `seq_export_path`, `seq_status`. 22 fields.
* **Files to edit**: `src/tools.rs` (most hits), `src/repeater_ops.rs:1448–1449, 1454–1458` (send-to-sequencer/comparer actions), `src/ui.rs:2 hits`, `src/main.rs:582`, `src/settings_dialog.rs`.
* **Methods**: `add_request(e)`, `selected_request()`, `samples_mut()`, `push_sample()` (15+ hits on `seq_samples`), `analyse()`, `analyse_bits()`, `start_live(limit)`, `stop_live()`, `status()`, `location_mut()` (`seq_loc`/`seq_field`/`seq_custom`/`seq_selector` form one token-location config), `export_path_mut()`, `sub_tab_mut()`, `table_mut()`.
* **Narrow API**: `seq_live_buf` + `seq_live_stop` must be owned by `start_live`/`stop_live` (they are Arc/Atomic handles shared with a background thread: `src/tools.rs:217,499`, `src/main.rs:582`); `seq_samples` (19 hits) should never be exposed by reference to another module. `seq_mode` is dead (§1.1).

#### A9. `ComparerView` — Comparer items, tables, comparison window
* **Owner file**: `src/compare_view.rs` (new) or `src/analysis_ui.rs` (already renders the diff). **Fields**: `cmp_items`, `cmp_sel1`, `cmp_sel2`, `cmp_table1`, `cmp_table2`, `cmp_paste_pending`, `cmp_load_path`, `cmp_window`, `cmp_result`, `cmp_hex`, `cmp_sync`, `cmp_scroll`, `cmp_export_path`, `cmp_unit_label`, `comparer_state`. 15 fields.
* **Files to edit**: `src/ui.rs` (3953–4174), `src/repeater_ops.rs:1454–1523` (8 hits on `cmp_items`), `src/intruder_ui.rs:839–843` (2 hits), `src/tools.rs:1764, 1958, 2182`.
* **Methods**: `push_item(s)` (replaces the four cross-tool `cmp_items.push` sites), `select(kind, i)`, `paste_pending()`, `load(path)`, `open_window(unit, a, b)`, `compare()` (updates `comparer_state` and `cmp_result` together — `src/ui.rs:4053–4062`), `window_view_mut()` (`cmp_hex`/`cmp_sync`/`cmp_scroll` at 4130–4171), `export_path_mut()`.
* **Narrow API**: `cmp_items` (24 hits, 4 files) — the "Send to Comparer" actions in the Repeater and Intruder modules must call `push_item()`; `comparer_state` + `cmp_result` are one invariant.

#### A10. `LoggerOrganizerView` — Logger and Organizer tabs
* **Owner file**: new `src/logger_view.rs`. **Fields**: `logger`, `log_filter`, `log_seen`, `log_sel`, `log_table`, `log_req_pane`, `log_resp_pane`, `log_on`, `org_sel`, `org_search`, `org_table`, `org_req_pane`, `org_resp_pane`. 13 fields.
* **Files to edit**: `src/main.rs:395, 427–431` (mirror loop), `src/tools.rs:1895, 2212, 2227–2228`, `src/ui.rs:4262–4535`.
* **Methods**: `set_enabled(bool)`, `mirror(&Shared)` (advances `log_seen` and appends to `logger` in one step: `src/main.rs:396–429`), `filter_mut()`, `table_mut()`, `panes_mut()`, `org_selected()`, `org_search_mut()`.
* **Narrow API**: `log_seen` + `logger` (used in `src/main.rs:395–431` and `src/tools.rs:2227–2228`) must be encapsulated so no other module can forget to advance the watermark; `org_sel` (7 hits) is a plain selector but 6 are in `src/ui.rs`, so a simple accessor is enough.

#### A11. `ExtensionsView`
* **Owner file**: `src/ext_menu.rs` (already owns extension menu UI). **Fields**: `ext_sub`, `ext_sel`, `ext_table`, `ext_detail`, `ext_add_open`, `ext_add_path`, `ext_add_kind`, `ext_loading`, `ext_add_done`, `ext_tab_busy`, `ext_tab_at`. 11 fields.
* **Files to edit**: `src/tools.rs` (all hits, 1200–1612), `src/main.rs` (constructor only).
* **Methods**: `sub_tab_mut()`, `selected_mut()`, `table_mut()`, `detail_mut()`, `add_dialog_mut()`, `begin_load()` (sets `ext_loading`, clears `ext_add_done`), `finish_load()`, `refresh_if_due()`.
* **Narrow API**: `ext_loading`/`ext_add_done`/`ext_tab_busy` are Arc<AtomicBool> handles shared with background loads (`src/tools.rs:1489–1491`); they should only be touched by `begin_load`/`finish_load`/`refresh_if_due`.

#### A12. `SettingsDialogState` — Settings, hotkeys, palette, Search/Event-log/AI windows, toasts
* **Owner file**: `src/settings_dialog.rs` (already owns the Settings window). **Fields**: `shortcuts`, `palette`, `hotkey_capture`, `hotkey_notice`, `settings_open`, `settings_help`, `onboarding_hidden`, `search_open`, `search_query`, `search_case`, `search_results`, `event_log_open`, `event_log_table`, `toasts`, `ai`, `mcp`. 16 fields.
* **Files to edit**: `src/settings_dialog.rs` (3–5 hits each on `settings_open`/`settings_help`), `src/shortcuts.rs` (810), `src/ui.rs` (55–404, 2413–2471, 3014–3080, 4185–4255), `src/menus.rs:199–209`, `src/main.rs` (constructor + `App::ui` toast draw).
* **Methods**: `capture_chord()` (the 30-line sequence at `src/ui.rs:59–91` becomes one method), `palette_ui(&Shared)`, `open_settings()`, `settings_pane_mut()`, `search_mut()`, `event_log_mut()`, `toasts_mut()`, `ai_mut()`.
* **Narrow API**: `shortcuts`/`palette`/`hotkey_capture`/`hotkey_notice` are one hotkey subsystem (4 files); `settings_open`/`settings_help` are one dialog (4 files); `ai` (12 hits, all `src/ui.rs`) can stay exposed inside the new module.

#### A13. `TargetView` — Site map, scope, target panes
* **Owner file**: `src/site_map.rs` (already defines `SiteFilter`). **Fields**: `tab`, `target_sub`, `target_view`, `target_node`, `target_table`, `site_filter`, `site_cache`, `site_cache_key`, `site_tree`, `site_tree_key`, `site_rows`, `site_rows_key`, `target_entry`, `site_req_pane`, `site_resp_pane`, `map_split`, `map_cache_len`, `target_host_sel`, `target_hosts`, `target_items`. 20 fields.
* **Files to edit**: `src/ui.rs` (3647–3952, including the nested `MapNode::insert`/`any_requested`/`path_segments`/`draw` helpers 3607–3946), `src/tools.rs:1943, 1945–1953, 2092, 2164–2178`, `src/discovery.rs:580`.
* **Methods**: `sub_tab_mut()`, `view_mut()`, `select_node()`, `filter_mut()`, `invalidate()` (clears all four `*_cache_key`/`*_tree_key`/`*_rows_key`/`map_cache_len` invalidation fields individually — `src/ui.rs:3751–3752, 3864–3865`, `src/discovery.rs:580`, `src/tools.rs:2092`), `rebuild_cache(&Shared)`, `rebuild_tree()`, `rebuild_rows()`, `panes_mut()`.
* **Narrow API**: `tab` (47 hits, 6 files) is navigation, not target state — better placed in A15 (`Layout`); site cache/tree/rows are three derived views with separate keys and must be rebuilt in that order, so expose `refresh(&Shared)` only. `target_host_sel`/`target_hosts`/`target_items` are dead (§1.1).

#### A14. `ProjectSession` — project file, chooser, autosave, status bar/QA
* **Owner file**: `src/project_start.rs` + `src/menus.rs` (project window). **Fields**: `project_path`, `project_status`, `chooser`, `autosave_at`, `autosave_sig`, `port_txt`, `scope_only`, `mem`, `mem_at`, `frames`, `saved`, `shot_added`, `selftest_done`, `grab_done`, `screenshot`. 15 fields.
* **Files to edit**: `src/project_start.rs` (10 hits on `chooser`), `src/recovery.rs` (6 on `project_path`), `src/tools.rs:1985, 2096–2102, 2236–2365`, `src/menus.rs:38–42`, `src/main.rs:509–513, 540–541, 587–642, 1148–1174`, `src/ui.rs:223, 1156–1162, 3025–3034`.
* **Methods**: `path()`, `set_path()`, `status_mut()`, `chooser_mut()`, `autosave_due()`, `mark_autosaved(sig)` (pairs `autosave_at` and `autosave_sig`), `listener_port_mut()`, `memory_mut()` (pairs `mem`/`mem_at`), `qa_tick()`.
* **Narrow API**: `project_path` (25 hits, 6 files) → `path()`/`set_path()`; the QA fields (`frames`, `saved`, `shot_added`, `selftest_done`, `grab_done`, `screenshot` — all only `src/main.rs`) can move into a private `QaState` inside this group or stay as one struct on `App`.

#### A15. `Layout` — tool tabs and splitters (cross-tool)
* **Owner file**: new `src/layout.rs`. **Fields**: `tab` (from A13), `split_detail`, `rep_split`, `map_split`, `proxy_sub`, `intr_sub`, `ext_sub`, `seq_sub`, `target_sub`, `target_view`, `dash_task`, `dash_sub`, `dock_sel`. 13 fields (splitters also listed in their tool groups above; choose one owner — proposed: `Layout` owns the three `*_split` floats and the current-tab/sub-tab indices, tools own their own dock indices).
* **Files to edit**: `src/ui.rs` (35 hits on `tab`: 55–404, plus 142, 210, 218, 243, 259, 274, 326, 378, 639, 653, 1019–1076, 1611, 2420–2481, 2611, 2630, 2658, 2909, 3186, 3733), `src/menus.rs:81,137,194`, `src/repeater_ops.rs` (4 hits on `tab`), `src/tools.rs` (layout snapshot 1943–1953, restore 2164–2179), `core/src/ext_process.rs:282,326` (**false positives**: `self.tab` there belongs to the extension-process struct — verify before editing).
* **Methods**: `current()`, `go_to(Tab)`, `cycle(i32)` (replaces `ui::cycle_tab` at 2477–2481), `snapshot()`, `restore()`, `split_mut(id)`.
* **Narrow API**: `tab` needs `current()`/`go_to()` because 6 files write it directly; `Layout::snapshot()` must keep the exact field set currently serialised at `src/tools.rs:1943–1953` and restored at 2164–2179 — do not change the project JSON.

#### A16. standalone owned states already present (leave as-is, but stop reaching through them)
* **Fields**: `eng` (62 hits, 8 files), `collab_state` (16 hits, 5 files), `macro_name`, `macro_request` (7/12 hits, `src/tools.rs` only).
* **Owner files**: `src/engagement.rs` (`engagement::State`), `core/src/collaborator.rs` (`CollaboratorState`), `src/tools.rs` (macro editor).
* **Methods**: add to `engagement::State` the verbs its callers need (`discovery_mut()`, `report_mut()`, `recovery_mut()`, `sitemap_compare_mut()`) so the 8 files stop reaching into `eng.discovery` (`src/discovery.rs:483` etc.); add `collab_state` accessors in `src/collaborator_ui.rs`.
* **Narrow API**: `eng` is the second widest UI field and is already an owned type — the remaining work is methodising its internals, not moving it.

### 3.2 `Shared`: 7 proposed groups

`Shared` already has six extracted subsystems (`history`, `crawl_items`, `scan`, `oob`, `stored`, `passive`, `rep`); the proposal keeps them and groups the remaining 65 bare fields. Suggested owner files: new `core/src/proxy_state.rs`, `core/src/listener_state.rs`, `core/src/session_state.rs`, `core/src/engine_state.rs`, plus the existing `core/src/ext_host.rs`/`core/src/organizer.rs`.

#### S1. `ProxyState` (interception, history helpers, match/replace, WebSockets, logger feed)
* **Fields**: `intercept_on`, `response_rules`, `queue`, `history`, `events`, `waker`, `messages`, `diff_tracker`, `ip_cache`, `intercept_rules`, `mr_request`, `mr_response`, `streaming`, `stream_skips`, `ws_history`, `ws_intercept_client`, `ws_intercept_server`, `ws_edited`, `tool_log`. (19 fields; `history` stays the existing `ProxyHistory`.)
* **Owner file**: `core/src/proxy_state.rs`. **Files to edit**: `core/src/net.rs` (proxy pipeline 1064–1070, 2338–2433, 2686–2771, 3289–3345, 3457–3552, 3780–3828, 4768–4943), `core/src/streaming.rs`/`streaming_tests.rs`, `core/src/h2.rs`, `src/proxy_settings.rs`, `src/repeater_ops.rs:1714–1716`, `src/ui.rs`, `src/tools.rs`.
* **Methods**: `log()` (already `core/src/net.rs:1025`), `wake()`/`set_waker()`, `hold()`/`release()` (queue+intercept), `count_waiting()` (already 1063), `apply_match_replace()` (mr_request/mr_response together), `record_entry()` (history + diff_tracker + site_links + scan_locations at 2338–2433 — the site-map/scan writes stay with S5/S6, so this method takes those subsystems as arguments), `ws_hold()`/`ws_edit()`/`ws_forward()` (queue/ws_history/ws_edited), `note_stream_skip()`, `drain_tool_log()`.
* **Narrow API**: `queue` (20 hits, 6 files), `mr_request` (5), `mr_response` (3), `ws_history` (6), `ws_edited` (3) — all must have named verbs; do not expose their guards. `upstream_for()` at `core/src/net.rs:1069–1071` is the one place that holds two Mutex guards in one expression (§4).

#### S2. `ListenerState` (listener, TLS, upstream, connection pools)
* **Fields**: `mitm`, `tls_upstream`, `proxy_port`, `browser_port`, `browsers`, `listener_http2`, `listener_running`, `listener_restart`, `listener_redirects`, `listeners`, `listener_generation`, `active_connections`, `h2c_upgrade`, `keep_alive`, `upstream`, `upstream_rules`, `tls_bypass`, `client_certs`, `tls_roots`, `pool`, `tls_pool`, `conns_opened`, `pool_hits`. 23 fields.
* **Owner file**: `core/src/listener_state.rs` (name collision with `pub struct ListenerState` in `net.rs` — call the new type `NetState`). **Files to edit**: `core/src/net.rs` (1801–1917, 2135–2218, 2960/3052, 4466–4467), `core/src/tls.rs`, `core/src/h2.rs`, `core/src/h2_server.rs`, `src/onboarding.rs`, `src/tools.rs:66–100, 983, 1187`, `core/src/bin/webprobe-headless.rs`, tests (`fuzz_tests`, `h2_server_tests`, `streaming_tests`, `h2_server_tests`).
* **Methods**: `port()`, `set_port()`, `start()/stop()`, `restart_requested()`, `generation()`, `choose_upstream(host)` (replaces `Shared::upstream_for`, `core/src/net.rs:1069`), `tls_config()` (tls_roots + client_certs at 4466–4467), `pool_get()/pool_put()` (1801–1868), `stats()` (conns_opened/pool_hits).
* **Narrow API**: `upstream` + `upstream_rules` are locked in opposite orders (`core/src/net.rs:1070` vs `src/tools.rs:68,100`), so `choose_upstream()` is mandatory; `listener_generation` (9 hits) should only be bumped/read via `bump_generation()`/`generation()`.

#### S3. `SessionState`
* **Fields**: `scope`, `session_rules`, `macros`, `macro_last_response`, `browser_recovery`, `cookie_jar`, `organizer`, `tool_sends`. 8 fields.
* **Owner file**: `core/src/session_state.rs`. **Files to edit**: `core/src/net.rs` (509–529, 589–656, 5412–5483, 5509–5581), `src/history_filter.rs` (2 hits on scope), `src/repeater_ops.rs` (2 on scope), `src/tools.rs` (30–60 scope rules UI, 639–673 session-rules UI), `core/src/ext_calls.rs` (scope, organizer, tool_sends), `core/src/organizer.rs`.
* **Methods**: `run_macro(text)` (cookie_jar + macro_last_response at 517/529), `apply_session_rules()` (session_rules + cookie_jar + ext_host at 593/600/628 — ext_host stays in S7 and is passed in), `check_session()` (macros/session_rules/cookie_jar at 5454/5458/5479), `cookie_jar()`, `scope_allows()`, `organizer()`, `drain_tool_sends()`.
* **Narrow API**: `session_rules`, `macros`, `cookie_jar`, `macro_last_response` are locked in several different orders across `core/src/net.rs:509–5581`, `src/tools.rs:639–673` and the project snapshot (§4); one `SessionState` owning all five removes the cross-field ordering question entirely.

#### S4. `ExtensionState`
* **Fields**: `ext_host` (22 hits, 7 files). Keep as one field; the type `crate::ext_host::ExtensionHost` already owns the registry.
* **Owner file**: `core/src/ext_host.rs`. **Files to edit**: `src/ext_menu.rs:4 hits`, `core/src/ext_store.rs:5`, `core/src/ext_calls.rs:3`, `core/src/scan.rs:1`, `src/main.rs:2`.
* **Methods**: `register()`, `active()` (already exists), `run_request_hooks()`/`run_response_hooks()` (already `Shared::ext_handle_request/response`, `core/src/net.rs:1078–1098`), `take_issues()`, `install_from_store()`.
* **Narrow API**: no change needed beyond moving the two `Shared` helper methods onto `ExtensionState`; do not let callers hold the registry guard (the comment at `core/src/net.rs:1075–1077` already documents why).

#### S5. `TargetState`
* **Fields**: `site_links`, `crawl_items`, `crawl_capture`, `diff_tracker` (diff_tracker listed in S1; pick one owner — proposed: `TargetState` owns `diff_tracker` and `site_links`; `ProxyState::record_entry` calls it), plus `h2c_upgrade`? (no — that is listener). 3–4 fields.
* **Owner file**: `core/src/target_state.rs` (or fold into `ProxyState`). **Files to edit**: `core/src/net.rs:786–792, 2338–2433`, `core/src/scan.rs:1 hit on crawl_items`, `core/src/ext_calls.rs:2`, `core/src/bin/webprobe-headless.rs:1`, `src/engagement.rs:319–385`, `src/ui.rs:3647–3702`.
* **Methods**: `add_crawl_items()` (already `Shared::add_crawl_items`), `note_link()`, `in_scope()`, `links()`.
* **Narrow API**: `scope` (S3) is read with `site_links` in `src/engagement.rs:319–385` and `src/ui.rs:3647–3702`; a `in_scope()` method taking the session's scope avoids exposing both.

#### S6. `ScanState` (config, tasks, issues)
* **Fields**: `scan_enabled`, `scan`, `scan_speed`, `scan_accuracy`, `scan_config`, `scan_locations`, `issues`, `extra_checks`, `tasks`, `next_task_id`, `task_runner`, `oob`, `stored`, `passive`, `crawl_capture` (also S5). 15 fields.
* **Owner file**: `core/src/scan_state.rs`. **Files to edit**: `core/src/scan.rs` (60 hits on `scan`, 37 on `issues`, 13 on `stored`, 14 on `oob`), `core/src/tasks.rs` (12 on `tasks`), `core/src/scan_checks.rs`, `core/src/passive_checks.rs`, `core/src/crawl.rs`, `core/src/bin/webprobe-headless.rs`, `src/main.rs:509–513`, `src/ui.rs:3120–3480`.
* **Methods**: `add_issue()` (replaces the 16 `issues.lock().unwrap().push` sites in `core/src/scan.rs`), `issues_snapshot()`, `enqueue()/next_task()/set_state()` (tasks + next_task_id), `config()` (scan_config + scan_speed + scan_accuracy), `note_location()`, `set_enabled()`.
* **Narrow API**: `issues` (37 hits, 9 files) and `scan` (60 hits, 7 files — already `ScanRun`) need the narrowest API: `add_issue`, `issues_snapshot`, `is_busy`, `claim`, `wait_idle` (the last three already exist in `core/src/scan_run.rs:30–60`). `scan_config` (15 hits) + the two atomic config flags must travel together.

#### S7. `RepeaterIntruderState`
* **Fields**: `attack`, `repeaters`, `rep`, `tool_sends` (also S3). 3–4 fields.
* **Owner file**: `core/src/repeater_run.rs` (already owns `rep`). **Files to edit**: `core/src/net.rs:3619, 4689` (attack), `core/src/ext_calls.rs:229, 362`, `core/src/ext_host.rs:1548`, `src/repeater_ops.rs:1224`, `src/ui.rs:6 hits on repeaters`.
* **Methods**: `attack_snapshot()` (already a `Mutex<Arc<Attack>>` clone at 3619/4689), `begin_attack()`/`set_attack_progress()`, `add_repeater_tab()`, `tabs_snapshot()`, `send_state()` (`rep` is already `RepeaterRun`).
* **Narrow API**: `repeaters` (10 hits, 4 files) — extension callers must use `add_repeater_tab()` instead of `shared.repeaters.lock().unwrap().push(...)` (`core/src/ext_calls.rs:229`); `attack` (2 hits) can stay internal.


## 4. Locks and threading notes for `Shared`

### 4.1 Lock kinds per field

`crate::sync::Mutex` is a poison-tolerant wrapper over `std::sync::Mutex` (`core/src/sync.rs:1`–`22`): `.lock()` returns `Result<_, Infallible>`, so `.unwrap()` at the call sites never panics on poisoning. `std::sync` atomics use `Ordering::SeqCst` at every site read. No `RwLock` appears in `Shared`; the only `RwLock` in the engine is a static in `core/src/retirejs.rs:176`, unrelated to `Shared`. Owned types carry their own locks, so moving them into subgroups moves their lock ownership too.

| field | declared type (L = declaration line in `core/src/net.rs`) | lock kind |
|---|---|---|

| `mitm` | `crate::tls::MitmAuthority` (L773) | plain / no lock |
| `tls_upstream` | `Arc<rustls::ClientConfig>` (L774) | plain / no lock |
| `intercept_on` | `AtomicBool` (L775) | Atomic |
| `response_rules` | `Mutex<ResponseInterceptRules>` (L777) | crate Mutex |
| `queue` | `Mutex<Vec<InterceptItem>>` (L778) | crate Mutex |
| `history` | `crate::history::ProxyHistory` (L779) | owned: internal crate Mutex |
| `events` | `Mutex<Vec<String>>` (L780) | crate Mutex |
| `h2c_upgrade` | `AtomicBool` (L783) | Atomic |
| `crawl_capture` | `AtomicBool` (L786) | Atomic |
| `site_links` | `Mutex<std::collections::BTreeSet<(String, String)>>` (L789) | crate Mutex |
| `crawl_items` | `crate::history::ProxyHistory` (L792) | owned: internal crate Mutex |
| `extra_checks` | `AtomicBool` (L794) | Atomic |
| `attack` | `Mutex<Arc<Attack>>` (L795) | crate Mutex |
| `repeaters` | `Mutex<Vec<RepTab>>` (L796) | crate Mutex |
| `next_id` | `AtomicU64` (L797) | Atomic |
| `proxy_port` | `std::sync::atomic::AtomicU16` (L798) | Atomic |
| `browser_port` | `std::sync::atomic::AtomicU16` (L800) | Atomic |
| `browsers` | `Mutex<Vec<(u32, String)>>` (L802) | crate Mutex |
| `issues` | `Mutex<Vec<crate::scan::ScanIssue>>` (L803) | crate Mutex |
| `listener_http2` | `AtomicBool` (L807) | Atomic |
| `streaming` | `Mutex<crate::streaming::StreamSettings>` (L809) | crate Mutex |
| `stream_skips` | `Mutex<std::collections::HashSet<(String, &'static str)>>` (L812) | crate Mutex |
| `organizer` | `Mutex<crate::organizer::Organizer>` (L814) | crate Mutex |
| `tool_sends` | `Mutex<Vec<crate::ext_calls::ToolSend>>` (L817) | crate Mutex |
| `scan_enabled` | `AtomicBool` (L818) | Atomic |
| `scan` | `crate::scan_run::ScanRun` (L820) | owned: std Mutex + Condvar + atomics |
| `oob` | `crate::oob::OobState` (L822) | owned: crate Mutex + atomics |
| `stored` | `crate::stored::StoredInputs` (L824) | owned: crate Mutex + AtomicBool |
| `passive` | `crate::passive_state::PassiveState` (L827) | owned: std Mutex |
| `rep` | `crate::repeater_run::RepeaterRun` (L829) | owned: crate Mutex + AtomicU64 |
| `active_connections` | `AtomicUsize` (L831) | Atomic |
| `tasks` | `Mutex<Vec<crate::tasks::ScanTask>>` (L833) | crate Mutex |
| `next_task_id` | `AtomicU64` (L834) | Atomic |
| `task_runner` | `AtomicBool` (L835) | Atomic |
| `waker` | `Mutex<Option<Arc<dyn Fn() + Send + Sync>>>` (L839) | crate Mutex |
| `scan_speed` | `AtomicU8` (L841) | Atomic |
| `scan_config` | `Mutex<crate::scan_config::ScanConfig>` (L843) | crate Mutex |
| `scan_accuracy` | `AtomicU8` (L846) | Atomic |
| `scan_locations` | `Mutex<std::collections::BTreeSet<String>>` (L848) | crate Mutex |
| `mr_request` | `Mutex<Vec<crate::rules::MrRule>>` (L850) | crate Mutex |
| `mr_response` | `Mutex<Vec<crate::rules::MrRule>>` (L851) | crate Mutex |
| `scope` | `Mutex<Vec<ScopeRule>>` (L853) | crate Mutex |
| `session_rules` | `Mutex<Vec<SessionRule>>` (L855) | crate Mutex |
| `browser_recovery` | `BrowserRecovery` (L857) | owned: std Mutex + Condvar (core/src/net.rs:412–415) |
| `macros` | `Mutex<Vec<Macro>>` (L858) | crate Mutex |
| `ws_history` | `Mutex<Vec<WsEntry>>` (L860) | crate Mutex |
| `diff_tracker` | `Mutex<DiffTracker>` (L862) | crate Mutex |
| `ext_host` | `Mutex<crate::ext_host::ExtensionHost>` (L864) | crate Mutex |
| `ws_intercept_client` | `AtomicBool` (L868) | Atomic |
| `ws_intercept_server` | `AtomicBool` (L869) | Atomic |
| `ws_edited` | `Mutex<std::collections::HashSet<u64>>` (L872) | crate Mutex |
| `ip_cache` | `Mutex<std::collections::HashMap<String, String>>` (L874) | crate Mutex |
| `tool_log` | `Mutex<Vec<ToolExchange>>` (L878) | crate Mutex |
| `cookie_jar` | `Mutex<crate::cookie_jar::CookieJar>` (L882) | crate Mutex |
| `macro_last_response` | `Mutex<Vec<u8>>` (L886) | crate Mutex |
| `intercept_rules` | `Mutex<Vec<crate::intercept_rules::InterceptRule>>` (L889) | crate Mutex |
| `listener_redirects` | `Mutex<std::collections::HashMap<u16, (String, u16)>>` (L893) | crate Mutex |
| `messages` | `std::sync::atomic::AtomicUsize` (L895) | Atomic |
| `upstream` | `Mutex<crate::upstream::UpstreamConfig>` (L897) | crate Mutex |
| `upstream_rules` | `Mutex<Vec<crate::upstream::UpstreamRule>>` (L899) | crate Mutex |
| `listener_running` | `AtomicBool` (L900) | Atomic |
| `listener_restart` | `AtomicBool` (L901) | Atomic |
| `keep_alive` | `AtomicBool` (L904) | Atomic |
| `tls_bypass` | `Mutex<Vec<String>>` (L907) | crate Mutex |
| `client_certs` | `Mutex<Vec<ClientCertRule>>` (L909) | crate Mutex |
| `tls_roots` | `Mutex<rustls::RootCertStore>` (L911) | crate Mutex |
| `pool` | `Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>` (L913) | crate Mutex |
| `tls_pool` | `Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>` (L914) | crate Mutex |
| `listeners` | `Mutex<Vec<Arc<ListenerState>>>` (L916) | crate Mutex |
| `listener_generation` | `AtomicU64` (L918) | Atomic |
| `conns_opened` | `AtomicUsize` (L919) | Atomic |
| `pool_hits` | `AtomicUsize` (L920) | Atomic |

**Summary.** 39 fields are `crate::sync::Mutex`, 23 are atomics (AtomicBool/U64/U8/USize/U16), 9 are already-owned types with internal locks (`history`, `crawl_items`, `scan`, `oob`, `stored`, `passive`, `rep`, `browser_recovery` — whose inner `std::sync::Mutex` + `Condvar` is at `core/src/net.rs:412`–`415` — and `mitm`), and 1 (`tls_upstream`) is a plain `Arc<rustls::ClientConfig>`. `browser_recovery` is declared without a `Mutex` on the outer field (`core/src/net.rs:857`) but owns a `std::sync::Mutex<RecoveryState>` internally.

### 4.2 Functions that lock two or more `Shared` fields

Found by scanning each function body for `self.|shared.|sh.|s.<field>.lock(` where `<field>` is a `Shared` field; the list below is every function with at least two **distinct** fields (52 functions). The lock line is the first occurrence of that field in the function. Fields repeated in a function (e.g. `cookie_jar` at `core/src/net.rs:517` and `520`) are listed once.

| function | file:line (function start) | locks in textual order (field@line) |
|---|---|---|

| `dispatch` | `core/src/ext_calls.rs:178` | ws_history@182 → scope@195 → repeaters@229 → tool_sends@247 → organizer@266 → cookie_jar@285 |
| `calls_reach_the_engine` | `core/src/ext_calls.rs:353` | repeaters@362 → issues@367 |
| `stopped` | `core/src/ext_host.rs:1511` | issues@1519 → repeaters@1548 → tool_sends@1552 → session_rules@1579 → queue@1598 → ext_host@1610 |
| `an_h2_response_can_be_intercepted_and_edited` | `core/src/h2_server_tests.rs:276` | response_rules@280 → queue@286 |
| `run_macro_text` | `core/src/net.rs:509` | cookie_jar@517 → macro_last_response@529 |
| `apply_session_rules_for` | `core/src/net.rs:589` | session_rules@593 → cookie_jar@600 → ext_host@628 |
| `upstream_for` | `core/src/net.rs:1069` | upstream_rules@1070 → upstream@1070 |
| `record_entry` | `core/src/net.rs:2336` | cookie_jar@2354 → diff_tracker@2409 → site_links@2417 → scan_locations@2431 |
| `intercept_ws_stream` | `core/src/net.rs:2684` | queue@2733 → ws_edited@2769 |
| `intercept_request` | `core/src/net.rs:3287` | intercept_rules@3306 → queue@3313 |
| `intercept_response` | `core/src/net.rs:3329` | response_rules@3336 → queue@3343 |
| `report_stream_skips` | `core/src/net.rs:3455` | response_rules@3461 → mr_response@3466 → ext_host@3469 → stream_skips@3473 |
| `upstream_and_deliver` | `core/src/net.rs:3479` | mr_request@3523 → mr_response@3550 |
| `passive_audit_runs_for_in_scope_traffic` | `core/src/net.rs:3770` | scope@3773 → issues@3776 |
| `matching_responses_are_held_and_forwarded_edited` | `core/src/net.rs:3795` | response_rules@3810 → queue@3826 |
| `client_certificate_presented_to_mtls_server` | `core/src/net.rs:4459` | tls_roots@4464 → client_certs@4465 |
| `ws_intercept_off_relays_raw_bytes_and_control_frames_pass` | `core/src/net.rs:4766` | queue@4782 → ws_history@4783 |
| `ws_intercept_queues_edits_and_drops` | `core/src/net.rs:4810` | ws_history@4840 → ws_edited@4843 |
| `ws_messages_are_held_edited_and_forwarded_end_to_end` | `core/src/net.rs:4851` | ws_history@4938 → ws_edited@4941 |
| `jar_is_applied_to_covered_tools_and_fed_by_monitored_ones` | `core/src/net.rs:5325` | cookie_jar@5329 → tool_log@5358 |
| `browser_recovery_waits_for_the_login_and_uses_the_new_cookie` | `core/src/net.rs:5410` | session_rules@5425 → cookie_jar@5426 |
| `check_session_logs_in_once_and_only_for_tools_in_scope` | `core/src/net.rs:5449` | macros@5452 → session_rules@5456 → cookie_jar@5477 |
| `header_cookie_and_post_request_actions_apply_in_order` | `core/src/net.rs:5481` | macros@5484 → session_rules@5486 |
| `multi_step_macro_derives_a_token_and_carries_cookies` | `core/src/net.rs:5507` | cookie_jar@5539 → macros@5545 |
| `recorded_login_supplies_a_bearer_token_to_later_requests` | `core/src/net.rs:5551` | macros@5574 → session_rules@5579 |
| `passive_check_for` | `core/src/scan.rs:821` | scan_config@822 → ext_host@825 |
| `start_active_scan` | `core/src/scan.rs:878` | scan_config@891 → issues@948 |
| `live_lab_scan` | `core/src/scan.rs:3261` | issues@3304 → events@3308 |
| `live_juice_crawl_scan` | `core/src/scan.rs:3338` | issues@3344 → events@3349 |
| `live_juice_scan` | `core/src/scan.rs:3362` | issues@3388 → events@3392 |
| `scan_configuration_switches_checks_and_insertion_types_off` | `core/src/scan.rs:4814` | scan_config@4819 → issues@4830 |
| `streaming_passes_intercept_and_match_replace_and_says_so_once` | `core/src/streaming_tests.rs:151` | response_rules@154 → mr_response@158 → queue@164 → events@183 |
| `other_content_with_intercept_on_stays_buffered_and_editable` | `core/src/streaming_tests.rs:191` | response_rules@195 → queue@201 |
| `run` | `core/src/tasks.rs:182` | issues@183 → tasks@219 |
| `site_map_menu` | `src/engagement.rs:319` | scope@326 → issues@367 → site_links@385 |
| `autosave_signature` | `src/main.rs:509` | issues@512 → repeaters@513 |
| `main` | `src/main.rs:945` | mr_request@1039 → ext_host@1051 |
| `response_rules_and_pass_through` | `src/proxy_settings.rs:238` | response_rules@240 → tls_bypass@281 |
| `apply_action` | `src/repeater_ops.rs:1426` | organizer@1467 → repeaters@1471 |
| `ws_history_view` | `src/repeater_ops.rs:1714` | ws_history@1715 → ws_edited@1716 |
| `upstream_options` | `src/tools.rs:66` | upstream@68 → upstream_rules@100 |
| `sessions` | `src/tools.rs:639` | session_rules@643 → macros@644 → ext_host@673 |
| `search` | `src/tools.rs:818` | repeaters@838 → issues@850 → ws_history@858 |
| `extensions_installed` | `src/tools.rs:1310` | ext_host@1318 → events@1500 |
| `project_snapshot` | `src/tools.rs:1788` | mr_request@1797 → mr_response@1798 → scope@1799 → cookie_jar@1805 → intercept_rules@1806 → session_rules@1807 → macros@1817 → repeaters@1821 → issues@1831 → ws_history@1832 → upstream@1840 → upstream_rules@1841 → site_links@1842 → scan_config@1843 → listener_redirects@1856 → response_rules@1860 → tls_bypass@1861 → streaming@1862 → tasks@1868 → organizer@1912 → ext_host@1939 |
| `apply_project` | `src/tools.rs:2004` | mr_request@2008 → mr_response@2009 → scope@2010 → cookie_jar@2016 → intercept_rules@2017 → session_rules@2018 → macros@2028 → repeaters@2033 → issues@2045 → ext_host@2049 → ws_history@2050 → upstream@2059 → upstream_rules@2060 |
| `restore_j01_sections` | `src/tools.rs:2112` | site_links@2115 → scan_config@2128 → streaming@2133 → response_rules@2136 → tls_bypass@2137 → listener_redirects@2138 → tasks@2153 → organizer@2197 |
| `bulk_history_command` | `src/ui.rs:609` | scope@614 → organizer@645 |
| `proxy_history` | `src/ui.rs:689` | scope@1012 → organizer@1029 |
| `mr_table` | `src/ui.rs:1225` | mr_request@1227 → mr_response@1230 |
| `dashboard` | `src/ui.rs:3120` | issues@3143 → tasks@3155 → events@3425 |
| `target` | `src/ui.rs:3647` | scope@3689 → site_links@3702 |


**Important qualification.** In all but one case the guards are released at the end of their own statement; the functions list the fields in textual order but do not hold all of them at once. The clearest example is `project_snapshot` (`src/tools.rs:1791`–`1795`), whose comment says: *"Each shared lock is taken and released in its own statement: in one struct literal every guard would live to the end of the statement, so a second lock of the same mutex deadlocked (scan_config, every save hung) and holding ~17 locks at once risked lock-order deadlocks with engine threads (issues -> tasks here, tasks -> issues in the runner)."* The same style is used by `apply_project` (`src/tools.rs:2008`–`2060`) and `restore_j01_sections` (`src/tools.rs:2114`–`2153`). The one function that provably holds two guards in a **single expression** is `Shared::upstream_for` at `core/src/net.rs:1069`–`1071`:

```rust
crate::upstream::choose(&self.upstream_rules.lock().unwrap(), &self.upstream.lock().unwrap(), host)
```

Rust evaluates the arguments left to right and the temporaries live until the call returns, so this takes `upstream_rules` then `upstream` simultaneously.

### 4.3 Opposite orders flagged

Pairs below appear as A→B in one function and B→A in another. "sequential" means both functions take and release each guard in separate statements (so no deadlock today); "simultaneous" means at least one side holds both guards at once.

| pair | A→B evidence | B→A evidence | class |
|---|---|---|---|
| `upstream_rules` / `upstream` | `Shared::upstream_for`, `core/src/net.rs:1069` (both in one expression at L1070) | `ui::upstream_options`, `src/tools.rs:66` (`upstream`@68, `upstream_rules`@100); `project_snapshot`, `src/tools.rs:1788`; `apply_project`, `src/tools.rs:2004` | **simultaneous on one side** — smallest real ordering hazard; `NetState::choose_upstream()` (§3.2 S2) should be the only caller. |
| `repeaters` / `organizer` | `dispatch`, `core/src/ext_calls.rs:178` (`repeaters`@229, `organizer`@266); `project_snapshot`, `src/tools.rs:1788` | `apply_action`, `src/repeater_ops.rs:1426` (`organizer`@1467, `repeaters`@1471) | sequential; fix by making `SessionState::organizer()` and `RepeaterIntruderState::add_repeater_tab()` the only accessors. |
| `issues` / `repeaters` | `stopped`, `core/src/ext_host.rs:1511` (`issues`@1519, `repeaters`@1548); `autosave_signature`, `src/main.rs:509` (L512, L513) | `calls_reach_the_engine`, `core/src/ext_calls.rs:353` (L362, L367); `ui::search`, `src/tools.rs:818` (L838, L850); project snapshot/restore | sequential. |
| `session_rules` / `macros` | `sessions`, `src/tools.rs:639` (L643, L644); `project_snapshot`, `src/tools.rs:1788`; `apply_project`, `src/tools.rs:2004` | `check_session_logs_in_once…`, `core/src/net.rs:5451` (L5454, L5458); `header_cookie_and_post_request_actions_apply_in_order`, `core/src/net.rs:5483` (L5486, L5488); `recorded_login_supplies_a_bearer_token…`, `core/src/net.rs:5553` (L5576, L5581) | sequential; `SessionState::check_session()` makes the order single-owner. |
| `session_rules` / `cookie_jar` | `apply_session_rules_for`, `core/src/net.rs:589` (L593, L600); `browser_recovery_waits…`, `core/src/net.rs:5412` (L5427, L5428); `check_session_logs_in_once…`, `core/src/net.rs:5451` (L5458, L5479) | `project_snapshot`, `src/tools.rs:1788`; `apply_project`, `src/tools.rs:2004` | sequential. |
| `cookie_jar` / `macros` | `multi_step_macro_derives_a_token…`, `core/src/net.rs:5509` (L5541, L5547); project snapshot/restore | `check_session_logs_in_once…`, `core/src/net.rs:5451` (L5454, L5479) | sequential. |
| `response_rules` / `mr_response` | `report_stream_skips`, `core/src/net.rs:3457` (L3463, L3468); `streaming_passes_intercept…`, `core/src/streaming_tests.rs:151` (L154, L158) | `project_snapshot`, `src/tools.rs:1788` | sequential. |
| `listener_redirects` / `response_rules` | `restore_j01_sections`, `src/tools.rs:2112` (L2136, L2138) | `project_snapshot`, `src/tools.rs:1788` | sequential. |
| `streaming` / `response_rules` | `restore_j01_sections`, `src/tools.rs:2112` (L2133, L2136) | `project_snapshot`, `src/tools.rs:1788` | sequential. |
| `streaming` / `tls_bypass` | `project_snapshot`, `src/tools.rs:1788` (L1861, L1862) | `restore_j01_sections`, `src/tools.rs:2112` (L2133, L2137) | sequential. |
| `ext_host` / `ws_history` | `apply_project`, `src/tools.rs:2004` (L2049, L2050) | `project_snapshot`, `src/tools.rs:1788` (L1832, L1939) | sequential. |
| `scope` / `ws_history` | `project_snapshot`, `src/tools.rs:1788`; `apply_project`, `src/tools.rs:2004` | `dispatch`, `core/src/ext_calls.rs:178` (`ws_history`@182, `scope`@195) | sequential. |

The remaining opposite pairs follow the same pattern (all from the three project snapshot/restore functions against the engine path): `cookie_jar`/`organizer`, `cookie_jar`/`repeaters`, `cookie_jar`/`ws_history`, `ext_host`/`upstream`, `ext_host`/`upstream_rules`, `issues`/`scan_config`, `issues`/`session_rules`, `listener_redirects`/`streaming`, `listener_redirects`/`tls_bypass`, `macros`/`cookie_jar`, `organizer`/`cookie_jar`, `repeaters`/`cookie_jar`, `repeaters`/`session_rules`, `repeaters`/`ws_history`, `response_rules`/`listener_redirects`, `scan_config`/`issues`, `session_rules`/`issues`, `session_rules`/`repeaters`, `streaming`/`listener_redirects`, `tls_bypass`/`listener_redirects`, `tls_bypass`/`streaming`, `upstream`/`ext_host`, `upstream_rules`/`ext_host`, `ws_history`/`cookie_jar`, `ws_history`/`ext_host`, `ws_history`/`repeaters`, `ws_history`/`scope`. Their evidence is the same three function starts (`src/tools.rs:1788`, `2004`, `2112`) and the engine sites listed in §4.2. **Not established:** whether any thread can hold one of these guards across an `await`/callback while another takes the reverse order; the code is all synchronous (no `async fn` in the 52 functions), and the one simultaneous case is `upstream_for`. A full proof would require tracing each guard's lifetime, which is outside this read-only structural note.


## 5. Mechanical refactoring order

Ordering rule: fewest touching files first (§2), then groups whose fields are already owned types or already confined to one module. Every step is independently compilable: after the step, `App`/`Shared` still have the same public behaviour and the project JSON (`src/tools.rs:1788`–`2200`) is byte-for-byte identical in content. "Risk" below is the risk of an accidental behaviour change if the step is done carelessly, not a requested change.

| # | Step | Fields moved | Files edited | Risk |
|---|---|---|---|---|
| 1 | **Delete the 15 unread `App` fields.** Bare-name search (`§1.1`, `§2.1`) found only the declaration and the constructor initialiser for: `ws_sel`, `target_host_sel`, `target_hosts`, `target_items`, `intercept_edit`, `detail_sub`, `intr_payloads`, `dec_results`, `dec_sel_decode`, `dec_sel_encode`, `dec_sel_hash`, `scope_only`, `seq_mode`, `rep_view`, `rep_req_view`. Delete the field and its initialiser only. | 15 (listed) | `src/main.rs` (declarations L93, 109–111, 151–152, 296, 308, 311–315, 345, 347; initialisers in `App::new`, L728–939) | Low. `App` has no `Serialize`/derive that reads fields by name (`src/main.rs:74`); the only non-declaration hit for `intercept_edit` is the string id `"intercept_edit"` at `src/ui.rs:2954`, which must stay. `ws_sel` overlaps `repeater_ops::State.ws_sel` at `src/repeater_ops.rs:1050` — do not delete that one. |
| 2 | **QA/selftest state → private `QaState` in `main.rs`.** Move the six QA fields plus `screenshot` into a struct held by `App`; keep the existing `App::ui` call sites unchanged via a `qa()` accessor. | `frames`, `saved`, `shot_added`, `selftest_done`, `grab_done`, `screenshot` (6) | `src/main.rs` only (L349–354; L587–642; initialisers) | Low: single file. Keep the frame thresholds (5/100/400) and the `grab_done` Arc handshake exactly as-is. |
| 3 | **Macro editor state → module-local struct in `src/tools.rs`.** `macro_name`/`macro_request` are read/written only by `src/tools.rs:744–776`; wrap them in a private `MacroEditor` local to that module (or add it to `SessionState` later). | `macro_name`, `macro_request` (2) | `src/main.rs`, `src/tools.rs` | Low. The generated `net::Macro` at `src/tools.rs:760` must keep the same name/request strings. |
| 4 | **`ExtensionsView` → `src/ext_menu.rs`.** Add the struct with `#[derive(Default)]`, move all 11 fields, turn each `app.ext_*` hit in `src/tools.rs` into a method call; keep the three `Arc<AtomicBool>` handles. | 11 (A11) | `src/main.rs`, `src/ext_menu.rs`, `src/tools.rs` | Medium: `ext_loading`/`ext_add_done`/`ext_tab_busy` are shared with background threads (`src/tools.rs:1489–1491`); moving the Arc must not change which atomic each closure captures. Add `Default` impl that reproduces the initial values at `src/main.rs` initialisers. |
| 5 | **`DashboardView` → new `src/dashboard_view.rs`.** Move the 7 dashboard/New-scan fields; `new_scan_*` become one `NewScanDialog` inside it. | 7 (A7) | `src/main.rs`, `src/ui.rs` (3120–3613), `src/tools.rs` (1949, 2174) | Low–medium: layout snapshot keys `dashboard_task`, `new_scan_*` at `src/tools.rs:1949/2174` must keep the same JSON names. |
| 6 | **`ScannerView` → `src/issue_view.rs`.** Move `scan_table`, `issue_tab`, `issue_pane`, `issue_filter`, `scan_sel`; leave `insp_state`/`dock_sel` in `Layout` until step 12 but expose them via accessors. | 5 (A6) | `src/main.rs`, `src/issue_view.rs`, `src/ui.rs` (1249–1316, 1341–1549) | Low: 2 touching files. The issue filter's `bar()` and `matches()` methods stay unchanged. |
| 7 | **`LoggerOrganizerView` → new `src/logger_view.rs`.** Move the 13 Logger/Organizer fields; the mirror loop in `App::ui` becomes `app.logger_view.mirror(&app.shared)`. | 13 (A10) | `src/main.rs` (395–431), `src/tools.rs` (1895, 2212, 2227–2228), `src/ui.rs` (4262–4535) | Medium: the `log_seen` watermark must advance at exactly the same points (`src/main.rs:396–429`); an off-by-one would duplicate or drop logger rows. |
| 8 | **`ComparerView` → new `src/compare_view.rs`.** Move the 15 fields; the four cross-tool `cmp_items.push` sites become `push_item(s)`. | 15 (A9) | `src/main.rs`, `src/ui.rs` (3953–4174), `src/repeater_ops.rs` (1454–1523), `src/intruder_ui.rs` (839–843), `src/tools.rs` (1764, 1958, 2182) | Medium: `comparer_state.recompute()` and `compare()` at `src/ui.rs:4053–4062` must stay in the same order. Project snapshot keys `comparer_items`/`...` at `src/tools.rs:1958/2182` must not change. |
| 9 | **`SequencerView` → new `src/sequencer_view.rs`.** Move the 22 fields; keep the live-capture Arc/Atomic handles inside `start_live()`/`stop_live()`. | 22 (A8) | `src/main.rs` (582), `src/tools.rs` (177–505), `src/repeater_ops.rs` (1448–1458), `src/ui.rs` (2 hits), `src/settings_dialog.rs` | Medium: the live-capture thread at `src/tools.rs:217,499` must receive the same `Arc<Mutex<Vec<Vec<u8>>>>` and stop flag; `seq_samples`/`seq_stats`/`seq_bits` invalidation order (`src/tools.rs:227,457–472`) must be preserved. |
| 10 | **`RepeaterView` → `src/repeater_ops.rs`.** Move `rep_split`, `rep_req_pane`, `rep_resp_pane`, `rep_target_edit`, `rep_update_cl`, `rep_sel`, `rep_view`, `rep_req_view` alongside the existing `rops`; `repeater_ops.rs` becomes the owner module with `current()`/`panes_mut()`/`send()`. | 8 (A5, `rops` already owned) | `src/main.rs`, `src/repeater_ops.rs`, `src/ui.rs` (1933–2307, 2616–2658), `src/menus.rs` (135, 163–175), `src/settings_dialog.rs` (113–116), `src/intruder_ui.rs:680`, `src/tools.rs` (1954, 2179) | Medium–high: `rep_sel` indexes into `rops.tabs`; the new `current()` must reproduce the exact clamping/fallback at `src/repeater_ops.rs:1264–1293`. Layout key `repeater_sel` at `src/tools.rs:1954/2179` must stay. |
| 11 | **`ProxyView` + `InterceptView` → `src/proxy_view.rs`.** Move the 20 + 6 fields; keep the cache key/len/truncated quadruple together behind `invalidate()`/`cache_mut()` and the held-message pair behind `hold()`/`release()`. | 26 (A2 + A3) | `src/main.rs`, `src/ui.rs` (405–442, 446–605, 689–1102, 1249–1316, 2436, 2807–3011), `src/project_start.rs` (23–25, 68–70), `src/engagement.rs:386`, `src/tools.rs` (768, 1944, 2168, 2175) | High: the history cache rebuild at `src/ui.rs:698–716` must keep its exact `key != ... || total < ... || (total > ... && !newest_first)` condition; `release()` must pass the same edited text to `net::intercept_release` (`src/ui.rs:2436`). |
| 12 | **`TargetView` + `Layout` → `src/site_map.rs` / new `src/layout.rs`.** Move the 20 target fields (minus `tab` which goes to `Layout`) and the 13 layout fields; keep `MapNode`, `path_segments`, `insert`, `any_requested`, `draw` with `TargetView`. | 33 (A13 + A15) | `src/main.rs`, `src/ui.rs` (142–404, 3614–3952), `src/menus.rs` (81, 137, 194), `src/repeater_ops.rs` (4 `tab` hits), `src/tools.rs` (1943–1953, 2092, 2164–2179), `src/discovery.rs:580` | High: `tab` is the widest UI field (47 hits in 6 files) and `Layout::snapshot()` must serialise exactly the fields at `src/tools.rs:1943–1953`. Do not edit `core/src/ext_process.rs:282/326` — those `self.tab` hits are a different struct (§2.1). |
| 13 | **`IntruderView` → new `src/intruder_view.rs`.** Move the 23 fields; `IntruderExtra` (`intr_x`) stays as-is but becomes reachable through `attack_config()`. | 23 (A4) | `src/main.rs`, `src/ui.rs` (1583–1928), `src/intruder_ui.rs`, `src/tools.rs` (1757–1758, 1927/1932, 2190–2195), `src/menus.rs` (75–77, 130–137), `src/settings_dialog.rs` (103–105) | High: `intr_x` (31 hits) carries the running-attack state; moving it must not change which attack the results window reads. Keep `cmp_items.push` calls from `src/intruder_ui.rs:839–843` pointed at `ComparerView::push_item` (step 8). |
| 14 | **`SettingsDialogState` → `src/settings_dialog.rs`.** Move the 16 fields; the hotkey capture sequence at `src/ui.rs:59–91` becomes `capture_chord()`. | 16 (A12) | `src/main.rs`, `src/ui.rs` (55–404, 2413–2471, 3014–3080, 4185–4255), `src/settings_dialog.rs`, `src/shortcuts.rs:810`, `src/menus.rs` (199–209) | High: `shortcuts.save()` writes `~/.config/webprobe/hotkeys.json`; the save/error path at `src/ui.rs:73–90` must stay identical. |
| 15 | **`Shared` S4 → `ExtensionState`.** Move `ext_host` into a one-field owned type in `core/src/ext_host.rs`; move `Shared::ext_handle_request/response` (`core/src/net.rs:1078–1098`) onto it. | 1 (+2 methods) | `core/src/net.rs`, `core/src/ext_host.rs`, `src/main.rs`, `src/ext_menu.rs`, `core/src/ext_store.rs`, `core/src/ext_calls.rs`, `core/src/scan.rs` | Low–medium: the guard must still be dropped before hooks run (`core/src/net.rs:1075`). |
| 16 | **`Shared` S7 → `RepeaterIntruderState`.** Move `attack`, `repeaters`, `rep` into `core/src/repeater_run.rs` (alongside `rep`). | 3 | `core/src/net.rs`, `core/src/repeater_run.rs`, `core/src/ext_calls.rs`, `core/src/ext_host.rs`, `src/repeater_ops.rs`, `src/ui.rs` | Medium: extension-created repeater tabs (`core/src/ext_calls.rs:229`) must still appear in the UI list; `rep` generation ids must keep monotonicity. |
| 17 | **`Shared` S5 → `TargetState`.** Move `site_links`, `crawl_items`, `crawl_capture`, `diff_tracker`; make `record_entry` call into it. | 4 | `core/src/net.rs` (786–792, 2338–2433), `core/src/scan.rs`, `core/src/ext_calls.rs`, `core/src/bin/webprobe-headless.rs`, `src/engagement.rs`, `src/ui.rs` | Medium: `record_entry` currently locks `cookie_jar → diff_tracker → site_links → scan_locations` (`core/src/net.rs:2356, 2411, 2419, 2433`); the new method must not reorder those writes. |
| 18 | **`Shared` S3 → `SessionState`.** Move `scope`, `session_rules`, `macros`, `macro_last_response`, `browser_recovery`, `cookie_jar`, `organizer`, `tool_sends`. This single owner resolves the opposite orders in §4.3. | 8 | `core/src/net.rs` (509–656, 5412–5581), `core/src/session_state.rs` (new), `src/history_filter.rs`, `src/repeater_ops.rs`, `src/tools.rs`, `core/src/ext_calls.rs`, `core/src/organizer.rs` | High: the macro/cookie/session-rule order differs between `core/src/net.rs:509–5581` and `src/tools.rs:639–673`; preserve each existing sequence inside the corresponding new method, do not "unify" it. |
| 19 | **`Shared` S1 → `ProxyState`.** Move the 19 interception/history/WebSocket/logger-feed fields. | 19 | `core/src/proxy_state.rs` (new), `core/src/net.rs`, `core/src/streaming.rs`, `core/src/h2.rs`, `src/proxy_settings.rs`, `src/repeater_ops.rs`, `src/ui.rs`, `src/tools.rs`, tests | High: `upstream_rules`/`upstream` (step 20) is the other half of `upstream_for`; until step 20 lands, keep `Shared::upstream_for` delegating to both new owners. |
| 20 | **`Shared` S2 → `NetState` + S6 → `ScanState`.** Last: `NetState` (23 fields, including the simultaneous double-lock in `upstream_for`) and `ScanState` (15 fields, `issues`/`scan`/`tasks`). | 38 | `core/src/net.rs` (1801–2218, 2960/3052, 4466–4467), `core/src/scan.rs`, `core/src/tasks.rs`, `core/src/scan_checks.rs`, `core/src/passive_checks.rs`, `core/src/crawl.rs`, `src/ui.rs` (3120–3480), headless binary, tests | Highest: `issues` (37 hits, 9 files) and `scan` (60 hits, 7 files) are the widest engine fields; `choose_upstream()` must take the two guards in the *same* order as `core/src/net.rs:1070`, and `add_issue()` must preserve the current one-issue-per-check semantics. |

Cross-cutting mechanical rules for every step:
1. Add the new type with the exact field types from §1; derive `Default` only when the constructor values in `App::new`/`Shared::new` are all `Default` (otherwise write an explicit `Default`/`new` copying them).
2. Move one group at a time; do not rename JSON keys, egui widget ids (`"intercept_edit"`, `"map_split"`, `"intr_req"`, …) or log text — those are behaviour.
3. Keep `pub(crate)` on accessors only where a second module needs the value; prefer a verb method over a getter for any field with ≥4 hit sites.
4. Keep the existing `Mutex` wrapper (`core/src/sync.rs`) and `Ordering::SeqCst`; do not introduce `RwLock` or new lock scopes as part of a structural move.
5. Verify by compiling after each step; the research task did not allow builds, so no step here has been compiled.


## 6. Split plan for `src/ui.rs` (4,686 lines)

Line ranges are inclusive and taken from the function-definition scan of `src/ui.rs` (79 `fn` defs). Ranges include the function's doc comment where one precedes it. `show` (55–404) stays in `src/ui.rs` as the shell: menu bar, tab bar, status bar, `settings_window`/`search_window`/`event_log_window`/`history_menu_windows` calls and the `match app.tab` dispatcher (lines 370–403). The `#[cfg(test)] mod`s at 4530–4686 move with their subjects. **Mechanical rule for each move:** cut the function verbatim, keep `pub(crate)` visibility, add `pub(crate) use moved_function;` to `src/ui.rs` so existing `crate::ui::…` call sites keep compiling; delete the re-export only in a later, separate step. No widget ids or strings change.

| Destination file | Functions (line ranges in current `src/ui.rs`) | Notes |
|---|---|---|
| `src/proxy_view_ui.rs` (new) | `history_new_rows` 405–406; `time_of_day` 415–417; `csrf_poc_html` 422–442; `history_menu_windows` 446–542; `highlight_colours` 543–560; `history_time` 563–572; `history_view` 576–605; `bulk_history_command` 609–681; `proxy_history` 689–1108; `proxy_options` 1148–1222; `mr_table` 1225–1231; `history_url` 2535–2541; `curl_command_of` 2545–2546; `links_in_response` 2551–2573; `proxy` 2770–2793; `proxy_match_replace` 2797–2804; `proxy_intercept` 2807–2968; `set_intercept` 2974–3011; `send_history_to_repeater` 2591–2611; `send_history_to_intruder` 2652–2658 | `proxy_history` contains the cache rebuild at 698–716; move it together with `history_view`. `links_in_response` has a test at 4536–4544 that moves too. |
| `src/detail_ui.rs` (new, optional) | `detail` 1249–1316; `insp_state`/`dock_sel` rendering shared by Proxy and Scanner | Only if step 6 of §5 keeps `insp_state`/`dock_sel` in `Layout`; otherwise leave `detail` in `src/ui.rs` until `ScannerView` owns them. |
| `src/scan_ui.rs` (new) | `scan_sev_color` 1321–1326; `scan_sev_label` 1332–1337; `scanner` 1341–1549; `run_active_scan_on` 2506–2530 | `run_active_scan_on` is called from the history context menu (`src/ui.rs:1050`-area); keep the re-export until all callers import from `scan_ui`. |
| `src/dashboard_ui.rs` (new) | `dashboard` 3120–3480; `dashboard_summary` 3487–3593; `start_url_scan` 3598–3613 | New-scan dialog fields move with the functions (§5 step 5). |
| `src/intruder_ui.rs` (existing) | `add_marker` 1560–1568; `with_target_host` 1573–1580; `intruder` 1583–1928; `payload_source_config` 2663–2664; test `add_marker_wraps_the_selection` 4655–4660 | The file already owns `IntruderExtra`; this is an append, not a new module. |
| `src/repeater_ops.rs` (existing) | `repeater` 1933–2189; `update_content_length` 2190–2191; `repeater_send` 2194–2307; `cancel_repeater_send` 2312–2316; `current_repeater` 2616–2619; `repeater_tab_to_intruder` 2622–2630; `repeater_tab_to_new_tab` 2633–2649; tests `cancel_abandons_the_in_flight_send` 4545–4561, `repeater_tab_ids_are_never_reused` 4562–4575, `repeater_updates_content_length` 4667–4674 | `repeater_send`/`cancel_repeater_send` are already called from other modules (`pub(crate)`), so the re-export in `ui.rs` must stay until callers are updated. |
| `src/decoder_ui.rs` (new) | `decoder` 2323–2383; `op_label` 2387–2405 | Self-contained (23 + 19 lines). |
| `src/sequencer_ui.rs` (new) | none in `ui.rs` — the Sequencer tab is drawn by `crate::tools::sequencer` (`src/ui.rs:395`–`398`) | Splitting `src/tools.rs` is a separate follow-up; only the tab dispatch line changes if desired. |
| `src/analysis_ui.rs` (existing) | `comparer` 3953–4184 | The file already renders the token-level diff; move the wrapper that supplies selections/export paths. |
| `src/target_ui.rs` (new) | `MapNode` + `impl MapNode` 3607–3622; `path_segments` 3626–3644; `target` 3647–3802; nested `draw` 3804–3946; `sub_tabs` 2757–2767 if only used here (verify with §2 counts first) | `draw` is nested inside `target` — move the whole 3647–3946 block verbatim. |
| `src/logger_ui.rs` (new) | `logger_view` 4262–4387; `organizer_view` 4394–4535 | The two tabs share the Logger/Organizer state group (§3.1 A10). |
| `src/settings_ui.rs` (new) | `settings_window` 3014–3018; `event_log_window` 3038–3065; `search_window` 3070–3080; `run_shortcut` 2413–2472; `cycle_tab` 2477–2481; `burp_ai` 4185–4255 | `run_shortcut` is called from `show` (55–404) and the palette; keep the re-export. |
| `src/discovery_ui.rs` (new) | `discover` 3085–3114 | Small; could stay in `ui.rs` if avoiding a new file is preferred. |
| `src/ui.rs` (stays) | `show` 55–404; shared widget helpers `vsplit_handle` 1109–1119, `splitter` 1122–1144, `facts` 1235–1242, `menu_action` 2489–2497, `note` 2665–2667, `row` 2669–2738, `hint` 2742–2747, `sub_tabs_pub` 2753–2754, `memory_usage` 3023–3034; tests `entry` 4577–4604, `history_view_keeps_every_match…` 4605–4629, `history_sorts_by_method_before_limiting` 4630–4642, `csrf_poc_replays_the_body` 4643–4654, `tools_get_origin_form_without_proxy_connection` 4661–4666, `a_sort_sees_the_whole_history` 4675–4684 | Keep one small `ui.rs` (shell + generic widgets + re-exports); the history tests can move to `proxy_view_ui.rs` with their functions instead. |

Dependency order for the moves (each compiles on its own with the re-exports in place): (1) `decoder_ui`, `discovery_ui`, `settings_ui`, `scan_ui`, `dashboard_ui`; (2) `intruder_ui`, `repeater_ops`, `analysis_ui`; (3) `proxy_view_ui`, `logger_ui`; (4) `target_ui` and the optional `detail_ui`; (5) remove re-exports and update `crate::ui::…` imports in `src/menus.rs`, `src/tools.rs`, `src/repeater_ops.rs`, `src/intruder_ui.rs` and `src/main.rs`. This file split is independent of §5: doing it first makes each later subsystem move touch one UI file instead of `ui.rs` (§5 steps 10–14).

## 7. Points marked "not established"

1. **Purpose of 15 unread `App` fields** (`§1.1`, `§2.1`): `ws_sel`, `target_host_sel`, `target_hosts`, `target_items`, `intercept_edit`, `detail_sub`, `intr_payloads`, `dec_results`, `dec_sel_decode`, `dec_sel_encode`, `dec_sel_hash`, `scope_only`, `seq_mode`, `rep_view`, `rep_req_view`. Looked at: all four-prefix counts (0 hits), plus bare-name `grep -rn --include='*.rs'` over `app/` (excluding `target/`, `graphify-out/`), which found only the declaration and the `App::new` initialiser (and, for `ws_sel`, the separate `State::ws_sel` in `src/repeater_ops.rs:1050`; for `intercept_edit`, the egui id string at `src/ui.rs:2954`). They are treated as dead, but their original intent is not established.
2. **Whether any dead field is read through egui persisted state or another non-source path.** Looked at: the `App` declaration (`src/main.rs:74` has no derive) and all `.rs` files; did not and could not inspect runtime egui `data_mut` string keys comprehensively. No claim is made beyond the bare-name search above.
3. **Whether any thread can hold a `Shared` guard across a callback while another thread takes the reverse order** for the 27 opposite-order pairs not involving `upstream_rules`/`upstream` (§4.3). Looked at: the 52 multi-lock functions and their lock lines; found all synchronous, guards scoped per statement (explicit comment at `src/tools.rs:1791`–`1795`), with only `core/src/net.rs:1070` holding two guards in one expression. A full guard-lifetime proof is not established.
4. **No Burp claims are made in this note.** The decompiled tree (`/root/burp-re/out/readable_strict/root/`) and resources (`/root/burp-re/in/extract/resources/`) were not read; every source line about Burp in WebProbe comments (e.g. `src/main.rs:89`, `core/src/net.rs:807`, `core/src/net.rs:848`) is quoted as a *WebProbe comment*, not as independent Burp evidence.
5. **Actual current field counts behind the brief's "197"/"62"** are established as 198/72 (§0), but why the brief differs is not established; no additional struct definition was found (`grep` for `struct App`/`struct Shared` in `src/*.rs` and `core/src/*.rs` found only `src/main.rs:74` and `core/src/net.rs:772`).

// WebProbe entry point.
// Normal start: opens the desktop app. `--screenshot <file.png>`: draws ~120
// frames without taking focus, saves the window picture as PNG and exits.

mod ai;
mod analysis;
mod burp_checks;
mod codec;
mod analysis_ui;
mod collaborator;
mod crawl;
mod collaborator_ui;
mod decoder_ops;
mod editor;
mod ext_host;
mod feedback;
mod gl_env;
mod h2;
mod interactsh;
mod history_filter;
mod intruder;
mod logger;
mod msgpane;
mod net;
mod onboarding;
mod organizer;
mod project;
mod rules;
mod rules_ui;
mod scan;
mod shortcuts;
mod table;
mod theme;
mod tls;
mod tools;
mod ui;
mod upstream;
mod util;
mod variations;
mod xss;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use eframe::egui::{self, ViewportCommand};

use crate::ext_host::ProxyHooks as _;

pub struct App {
    pub shared: Arc<net::Shared>,
    /// Cross-tool HTTP Logger, mirrored from proxy history every frame.
    pub logger: logger::Logger,
    /// Saved request/response collection (Organizer tab).
    pub organizer: organizer::Organizer,
    /// Filter driving the Logger view.
    pub log_filter: logger::LogQuery,
    /// Highest proxy history id already mirrored into `logger`.
    pub log_seen: u64,
    /// Selected Logger row.
    pub log_sel: Option<u64>,
    /// Selected Organizer item.
    pub org_sel: Option<u64>,
    /// Intruder sub-tab (0 = Positions, 1 = Payloads).
    pub intr_sub: usize,
    /// Selected WebSocket history row.
    pub ws_sel: Option<u64>,
    pub tab: ui::Tab,
    pub proxy_sub: usize,
    pub history_sel: Option<u64>,
    /// Height of the Proxy message pane, dragged by the splitter (B-05).
    pub split_detail: f32,
    pub target_host_sel: Option<String>,
    pub target_hosts: Vec<String>,
    pub target_items: Vec<(String, String, String, u64)>, // host, method, path, hist id
    pub map_cache_len: usize,
    /// Shared table state for proxy history (sort, filter, columns).
    pub hist_table: table::TableState,
    /// Proxy HTTP history filter bar (B-01).
    pub hist_filter: history_filter::HistoryFilter,
    /// Cached filtered/sorted view of the history (N-02): recomputing it every
    /// frame is a full scan of every entry, so it is keyed on the inputs.
    pub hist_cache: Vec<net::HistEntry>,
    pub hist_cache_len: usize,
    pub hist_cache_key: String,
    pub hist_cache_truncated: bool,
    /// Shared table state for the scanner issue list.
    pub scan_table: table::TableState,
    /// Shared table state for the intruder result list.
    pub intr_table: table::TableState,
    /// Shared table state for the target site map request list.
    pub target_table: table::TableState,
    /// Transient toasts (M-04).
    pub toasts: feedback::Toasts,
    /// User hotkey bindings (M-06). Burp stores these as user settings, so they
    /// live in `~/.config/webprobe/hotkeys.json`, not the project file.
    pub shortcuts: shortcuts::Shortcuts,
    /// Command palette state (Ctrl+K).
    pub palette: shortcuts::Palette,
    /// Action index waiting for a key press in the hotkey settings table.
    pub hotkey_capture: Option<usize>,
    /// Last hotkey-settings message (conflict, save error).
    pub hotkey_notice: Option<String>,
    /// Burp's Settings window (appearance + hotkeys).
    pub settings_open: bool,
    pub settings_help: ui::SettingsPane,
    /// First-run setup panel dismissed for this session (M-07).
    pub onboarding_hidden: bool,
    /// Shared editor state for each message editor/view (M-03).
    pub detail_editor: editor::EditorState,
    pub intercept_editor: editor::EditorState,
    pub intr_editor: editor::EditorState,
    pub rep_editor: editor::EditorState,
    pub seq_editor: editor::EditorState,
    pub dec_editor: editor::EditorState,
    pub intercept_edit: String,
    pub detail_sub: usize,
    /// Burp message panes and Inspector under the Proxy history.
    pub req_pane: msgpane::PaneState,
    pub resp_pane: msgpane::PaneState,
    pub insp_state: msgpane::InspectorState,
    /// Right dock: 0 Inspector, 1 Notes, 2 collapsed.
    pub dock_sel: usize,
    /// WebProbe AI (Burp AI slot).
    pub ai: ai::AiChat,
    /// History context-menu dialogs: browser URL, CSRF PoC, extra history window.
    pub browser_url: Option<(String, String)>,
    pub csrf_poc: Option<String>,
    pub hist_window_open: bool,
    pub hist_window_filter: String,
    pub hist_window_table: table::TableState,
    /// Extensions (Burp layout).
    pub ext_sub: usize,
    pub ext_sel: Option<usize>,
    pub ext_table: table::TableState,
    pub ext_detail: usize,
    pub ext_add_open: bool,
    pub ext_add_path: String,
    /// Sequencer (Burp layout): sub-tab, requests sent here, token location
    /// (0 cookie, 1 form field, 2 custom regex), live capture state.
    pub seq_sub: usize,
    pub seq_requests: Vec<net::HistEntry>,
    pub seq_req_sel: Option<usize>,
    pub seq_table: table::TableState,
    pub seq_loc: usize,
    pub seq_field: String,
    pub seq_custom: String,
    pub seq_load_path: String,
    pub seq_live_buf: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    pub seq_live_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Intercept: the held item being edited and its text.
    pub intercept_cur: Option<u64>,
    pub intercept_text: String,
    pub intercept_pane: msgpane::PaneState,
    /// Decoder stages after the input: (text, hex view).
    pub dec_chain: Vec<(String, bool)>,
    /// Comparer items (shown in both tables), selections, comparison window.
    pub cmp_items: Vec<String>,
    pub cmp_sel1: Option<usize>,
    pub cmp_sel2: Option<usize>,
    pub cmp_table1: table::TableState,
    pub cmp_table2: table::TableState,
    pub cmp_paste_pending: bool,
    pub cmp_load_path: String,
    pub cmp_window: Option<(usize, usize, bool)>,
    /// Logger / Organizer (Burp layouts).
    pub log_on: bool,
    pub log_table: table::TableState,
    pub log_req_pane: msgpane::PaneState,
    pub log_resp_pane: msgpane::PaneState,
    pub org_search: String,
    pub org_table: table::TableState,
    pub org_req_pane: msgpane::PaneState,
    pub org_resp_pane: msgpane::PaneState,
    /// Intruder (Burp 2026 layout): target, Host update, editor pane, right
    /// dock (0 Payloads, 1 Resource pool, 2 Settings, 3 closed), selected
    /// payload set, add/load fields, results window.
    pub intr_target: String,
    pub intr_update_host: bool,
    pub intr_pane: msgpane::PaneState,
    pub intr_dock: usize,
    pub intr_set_sel: usize,
    pub intr_add: String,
    pub intr_load_path: String,
    pub intr_paste_pending: bool,
    pub intr_results_open: bool,
    pub intr_attack_no: usize,
    pub intr_row_sel: Option<usize>,
    pub intr_res_req_pane: msgpane::PaneState,
    pub intr_res_resp_pane: msgpane::PaneState,
    /// Target: sub-tab, URL/Crawl paths view, selected tree node and entry, panes.
    pub target_sub: usize,
    pub target_view: usize,
    pub target_node: Option<(String, String)>,
    pub target_entry: Option<u64>,
    pub site_req_pane: msgpane::PaneState,
    pub site_resp_pane: msgpane::PaneState,
    /// Dashboard: selected task (0 crawl, 1 live audit, 2 active scan), task
    /// sub-tab, task search, New scan dialog, crawl capture switch.
    pub dash_task: usize,
    pub dash_sub: usize,
    pub dash_search: String,
    pub dash_items_table: table::TableState,
    pub new_scan_open: bool,
    pub new_scan_urls: String,
    /// New scan type: 0 Crawl and audit (Burp's default), 1 Audit selected items.
    pub new_scan_type: usize,
    /// Repeater: message panes and the Configure-target dialog.
    pub rep_req_pane: msgpane::PaneState,
    pub rep_resp_pane: msgpane::PaneState,
    pub rep_target_edit: bool,
    pub rep_update_cl: bool,
    /// Burp's Search window and Event log window.
    pub search_open: bool,
    pub event_log_open: bool,
    pub event_log_table: table::TableState,
    /// Status-bar memory gauge cache (process MB, machine MB).
    pub mem: (f64, f64),
    pub mem_at: Option<std::time::Instant>,
    pub detail_view: usize,
    pub scan_sel: Option<u64>,
    pub intr_req: String,
    pub intr_https: bool,
    pub intr_payloads: String,
    /// Which of the four attack types (C-01).
    pub intr_attack: intruder::AttackType,
    /// Raw payload text per position, one payload per line (C-03 UI side).
    pub intr_sets: Vec<String>,
    pub dec_input: String,
    pub dec_results: Vec<(String, String)>,
    /// Latest Decoder output (P-07).
    pub dec_output: String,
    pub dec_sel_decode: Option<decoder_ops::Op>,
    pub dec_sel_encode: Option<decoder_ops::Op>,
    pub dec_sel_hash: Option<decoder_ops::Op>,
    pub scope_only: bool,
    pub seq_mode: usize,
    pub seq_ignore_abnormal: bool,
    pub seq_selector: String,
    pub seq_manual: String,
    pub seq_samples: Vec<Vec<u8>>,
    pub seq_stats: Option<analysis::TokenStats>,
    pub seq_report: Option<analysis::SequencerReport>,
    pub seq_status: String,
    pub comparer_state: analysis::ComparerState,
    pub search_query: String,
    pub search_case: bool,
    pub search_results: Vec<analysis::SearchHit>,
    pub project_path: String,
    pub project_status: String,
    pub collab_state: collaborator::CollaboratorState,
    pub macro_name: String,
    pub macro_request: String,
    pub rep_sel: usize,
    /// Repeater response view: 0 Raw, 1 Hex, 2 Pretty (P-04).
    pub rep_view: usize,
    /// Repeater request view: 0 Pretty, 1 Raw, 2 Hex (P-04).
    pub rep_req_view: usize,
    pub port_txt: String,
    pub frames: usize,
    pub saved: bool,
    pub shot_added: bool,
    pub selftest_done: bool,
    pub grab_done: Option<Arc<Mutex<bool>>>,
    pub screenshot: Option<PathBuf>,
}

/// One proxy history row flattened for mirroring: `(id, ts, method, host,
/// port, path, status, req_len, resp_len, mime)`.
///
/// `ts` and `mime` are carried alongside the fields the Logger stores so the
/// mirroring step stays pure: it never touches `Shared` and can be tested
/// without a window or a `net::Shared`.
type HistRow = (u64, u64, String, String, u16, String, String, usize, usize, String);

impl App {
    /// Mirror proxy history into the Logger, once per history id.
    ///
    /// Rows are copied out under the history lock, the lock is dropped, and
    /// only then is the Logger touched: nothing here may re-enter the history
    /// mutex (the proxy thread holds it while appending).
    fn sync_logger(&mut self) {
        // Logger's "Logging on" switch: while off, new traffic is not mirrored.
        if !self.log_on {
            if let Ok(h) = self.shared.history.lock() {
                self.log_seen = h.iter().map(|e| e.id).max().unwrap_or(self.log_seen);
            }
            return;
        }
        let seen = self.log_seen;
        let mut newest = 0u64;
        let mut rows: Vec<HistRow> = Vec::new();
        {
            let Ok(hist) = self.shared.history.lock() else { return };
            for e in hist.iter() {
                newest = newest.max(e.id);
            }
            // Loading a project replaces history with ids that can be lower
            // than what was already mirrored; resync rather than go dark.
            let resync = newest < seen;
            for e in hist.iter().filter(|e| resync || e.id > seen) {
                rows.push((
                    e.id,
                    e.ts,
                    e.method.clone(),
                    e.host.clone(),
                    e.port,
                    e.path.clone(),
                    e.status.clone(),
                    e.req_raw.len(),
                    e.resp_raw.as_ref().map(|r| r.len()).unwrap_or(e.resp_len),
                    response_mime(e),
                ));
            }
        }
        if newest < seen {
            self.log_seen = 0;
        }
        mirror_history(&mut self.logger, &mut self.log_seen, &rows);
    }
}

/// Append `rows` to `logger` in order, skipping any id at or below `*seen`,
/// and advance `*seen` to the highest id mirrored. Pure: no locks, no I/O.
fn mirror_history(logger: &mut logger::Logger, seen: &mut u64, rows: &[HistRow]) {
    for (id, ts, method, host, port, path, status, req_len, resp_len, mime) in rows {
        if *id <= *seen {
            continue;
        }
        logger.push(logger::LogEntry {
            ts: *ts,
            tool: "Proxy".to_string(),
            method: method.clone(),
            host: host.clone(),
            port: *port,
            path: path.clone(),
            status: status.clone(),
            req_len: *req_len,
            resp_len: *resp_len,
            mime: mime.clone(),
            source: "proxy".to_string(),
            ..Default::default() // `push` assigns the logger id
        });
        *seen = (*seen).max(*id);
    }
}

/// `type/subtype` of the recorded response's Content-Type, else the entry's
/// URL extension, else empty. Reads only the response head.
fn response_mime(entry: &net::HistEntry) -> String {
    if let Some(resp) = &entry.resp_raw {
        let head_end = util::find_head_end(resp).unwrap_or(resp.len());
        let head = String::from_utf8_lossy(&resp[..head_end]);
        for line in head.split("\r\n").flat_map(|l| l.split('\n')) {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-type") {
                    let essence = value.split(';').next().unwrap_or("").trim().to_lowercase();
                    if !essence.is_empty() {
                        return essence;
                    }
                }
            }
        }
    }
    entry.extension.clone()
}

impl eframe::App for App {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        tools::close_launched_browsers(&self.shared);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        theme::apply_current(ctx);
        feedback::drain(&mut self.toasts);
        self.toasts.tick(std::time::Instant::now());
        // Mirror new proxy traffic before drawing, so the Logger view and the
        // history table show the same frame's entries.
        self.sync_logger();
        ui::show(self, ctx);
        self.toasts.show(ctx);

        // Poll background state (proxy traffic, scans, Repeater) five times a
        // second instead of redrawing flat out: continuous repaint under the
        // software renderer pinned ~6 cores and starved the network threads
        // (a 60 ms Repeater send took 22 s). Input still repaints at once.
        ctx.request_repaint_after(std::time::Duration::from_millis(200));

        // Optional self test: route one request through our own proxy so the
        // passive-audit pipeline can be exercised in screenshot runs.
        if !self.selftest_done && self.frames >= 5 {
            self.selftest_done = true;
            if let Ok(url) = std::env::var("WEBPROBE_SELFTEST") {
                let port = self.shared.proxy_port.load(Ordering::SeqCst);
                let sh = self.shared.clone();
                std::thread::spawn(move || {
                    // absolute-form request through the proxy; the Host header carries the authority
                    if let Some(rest) = url.strip_prefix("http://") {
                        let auth = rest.split('/').next().unwrap_or_default();
                        let path_rest = &url["http://".len() + auth.len()..];
                        let path = if path_rest.is_empty() { "/" } else { path_rest };
                        let req = format!("GET {path} HTTP/1.1\r\nHost: {auth}\r\nUser-Agent: WebProbe/1.0\r\nConnection: close\r\n\r\n");
                        let out = crate::send_internal_probe(port, req.as_bytes());
                        sh.log(&format!("Selftest probe got {} byte(s) via proxy :{port}", out.len()));
                        // verify a request rule was applied if one was preloaded
                        if !sh.mr_request.lock().unwrap().is_empty() {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            let hit = sh
                                .history
                                .lock()
                                .unwrap()
                                .last()
                                .map(|e| e.req_raw.windows(11).any(|w| w == b"WebProbe-MR"))
                                .unwrap_or(false);
                            sh.log(&format!(
                                "Selftest match-and-replace: rule {}",
                                if hit { "applied (request carries rewritten value)" } else { "not applied" }
                            ));
                        }
                        // optionally exercise the light active scan on the just-stored request
                        if std::env::var("WEBPROBE_SELFTEST_SCAN").as_deref() == Ok("1") {
                            std::thread::sleep(std::time::Duration::from_millis(800));
                            let e = sh.history.lock().unwrap().last().cloned();
                            if let Some(e) = e {
                                crate::scan::start_active_scan(sh.clone(), e, &[], &[]);
                            }
                        }
                    }
                });
            }
        }

        if let Some(path) = self.screenshot.clone() {
            self.frames += 1;
            if self.frames == 100 && !self.shot_added {
                // paint callback runs while the frame's own framebuffer still holds the image
                let rect = ctx.screen_rect();
                let done = Arc::new(Mutex::new(false));
                self.grab_done = Some(done.clone());
                schedule_grab(ctx, &path, rect, done);
                self.shot_added = true;
            }
            if self.shot_added {
                let mut finished = false;
                if let Some(done) = &self.grab_done {
                    finished = *done.lock().unwrap();
                }
                if !finished && self.frames > 400 {
                    eprintln!("screenshot: paint callback never completed for {path:?}");
                }
                if finished || self.frames > 400 {
                    self.saved = finished;
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
            }
        }
    }
}

/// Route one raw absolute-URI request through our own proxy listener (test hook).
pub fn send_internal_probe(port: u16, request: &[u8]) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut out = Vec::new();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10)) {
        Ok(mut s) => {
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(20)));
            if s.write_all(request).is_ok() {
                let mut buf = [0u8; 65536];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
            }
        }
        Err(_) => {}
    }
    out
}

fn schedule_grab(ctx: &egui::Context, path: &PathBuf, rect: egui::Rect, done: Arc<Mutex<bool>>) {
    let painter = egui::Painter::new(
        ctx.clone(),
        egui::LayerId::new(egui::Order::Tooltip, egui::Id::new("shot_grab")),
        rect,
    );
    let path = path.clone();
    let cb = egui_glow::CallbackFn::new(move |info, painter| {
        use eframe::glow::HasContext;
        let gl = painter.gl();
        let ppp = info.pixels_per_point;
        let w = ((info.viewport.width()) * ppp).round() as i32;
        let h = ((info.viewport.height()) * ppp).round() as i32;
        let ok = unsafe {
            gl.flush();
            let mut pixels = vec![0u8; w as usize * h as usize * 4];
            gl.read_pixels(
                0,
                0,
                w,
                h,
                eframe::glow::RGBA,
                eframe::glow::UNSIGNED_BYTE,
                eframe::glow::PixelPackData::Slice(&mut pixels),
            );
            // flip rows (GL reads bottom-up) and force opaque alpha if the surface has none
            let stride = w as usize * 4;
            let mut flipped = pixels.clone();
            for y in 0..h as usize {
                let (dst, src) = (y * stride, (h as usize - 1 - y) * stride);
                flipped[dst..dst + stride].copy_from_slice(&pixels[src..src + stride]);
            }
            if flipped.iter().skip(3).step_by(4).all(|&a| a == 0) {
                for a in flipped.iter_mut().skip(3).step_by(4) {
                    *a = 255;
                }
            }
            let ok = if let Ok(png) = std::panic::catch_unwind(|| util::encode_png(w as u32, h as u32, &flipped)) {
                std::fs::write(&path, png).is_ok()
            } else {
                false
            };
            ok
        };
        *done.lock().unwrap() = ok;
    });
    painter.add(egui::PaintCallback { rect, callback: Arc::new(cb) });
}

fn main() {
    // Must run before any thread or window exists (see gl_env for why).
    gl_env::apply();

    let mut screenshot: Option<PathBuf> = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--screenshot" {
            if let Some(v) = args.get(i + 1) {
                screenshot = Some(PathBuf::from(v));
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    let shared = net::Shared::new();
    if let Some(p) = std::env::var("WEBPROBE_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
    {
        shared.proxy_port.store(p, Ordering::SeqCst);
    }
    if std::env::var("WEBPROBE_INTERCEPT").as_deref() == Ok("1") {
        shared.intercept_on.store(true, Ordering::SeqCst);
    }
    let mut collab_state = collaborator::CollaboratorState::new();
    if let Some(p) = std::env::var("WEBPROBE_COLLAB_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
    {
        collab_state.http.port = p;
    }
    // Test hook: seed synthetic history, e.g. WEBPROBE_SEED_HISTORY=10000.
    // Used by the performance checks (N-02) and by screenshot runs that need a
    // populated table without network access.
    if let Some(n) = std::env::var("WEBPROBE_SEED_HISTORY").ok().and_then(|v| v.trim().parse::<usize>().ok()) {
        let base = shared.next_id.load(Ordering::SeqCst);
        let mut hist = shared.history.lock().unwrap();
        for i in 0..n {
            let id = base + i as u64 + 1;
            let status = ["200", "301", "404", "500"][i % 4];
            let method = if i % 7 == 0 { "POST" } else { "GET" };
            let host = format!("host{}.example.com", i % 25);
            let path = format!("/api/v1/resource/{i}");
            let body = format!("{i}").repeat(8);
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            hist.push(net::HistEntry {
                id,
                ts: i as u64,
                method: method.into(),
                host,
                port: if i % 3 == 0 { 443 } else { 80 },
                path: path.clone(),
                status: status.into(),
                resp_len: resp.len(),
                req_raw: format!("{method} {path} HTTP/1.1\r\nHost: h\r\n\r\n").into_bytes(),
                resp_raw: Some(resp.into_bytes()),
                https: i % 3 == 0,
                note: None,
                highlight: None,
                audited: false,
                params: i % 2 == 0,
                edited: false,
                extension: "json".to_string(),
                title: String::new(),
                cookies: String::new(),
                listener_port: 6566,
                ip: String::new(),
                diffs: 0,
            });
        }
        shared.next_id.store(base + n as u64, Ordering::SeqCst);
        shared.log(&format!("Seeded {n} history entries"));
    }

    // Test hook: pre-load one request rule, e.g. WEBPROBE_MR_TEST="WebProbe/1.0|WebProbe-MR"
    if let Ok(spec) = std::env::var("WEBPROBE_MR_TEST") {
        let mut parts = spec.splitn(2, '|');
        let m = parts.next().unwrap_or_default().to_string();
        let r = parts.next().unwrap_or_default().to_string();
        if !m.is_empty() {
            shared.mr_request.lock().unwrap().push(rules::MrRule {
                enabled: true,
                match_: m,
                replacement: r,
                comment: String::new(),
                is_regex: false,
                scope: rules::MrScope::RequestHeader,
            });
        }
    }
    // Test hook: register the built-in example extension, e.g. WEBPROBE_EXT_TEST=1
    if std::env::var("WEBPROBE_EXT_TEST").is_ok() {
        shared.ext_host.lock().unwrap().extensions.push(ext_host::LoadedExtension {
            enabled: true,
            hooks: Box::new(ext_host::ExampleHeaderExtension),
        });
        shared.log("Registered example extension: Example header add (ProxyRequestHandler)");
    }
    // Path B: load a real Montoya .jar extension through the sidecar JVM,
    // e.g. WEBPROBE_EXT_JAR=app/sidecar/demo-ext/demo-ext.jar
    if let Ok(ext_jar) = std::env::var("WEBPROBE_EXT_JAR") {
        match ext_host::JavaSidecar::spawn(&ext_jar) {
            Ok(sidecar) => {
                shared.log(&format!(
                    "Sidecar JVM loaded Montoya extension: {} ({})",
                    sidecar.extension_name(),
                    sidecar.hooks_registered()
                ));
                shared.ext_host.lock().unwrap().extensions.push(ext_host::LoadedExtension {
                    enabled: true,
                    hooks: Box::new(sidecar),
                });
            }
            Err(e) => shared.log(&format!("Sidecar JVM failed to load {ext_jar}: {e}")),
        }
    }
    net::start_proxy(shared.clone());

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder {
            title: Some("WebProbe".into()),
            inner_size: Some(egui::vec2(1440.0, 900.0)),
            active: screenshot.as_ref().map(|_| false), // screenshot checks must not steal focus
            ..Default::default()
        },
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    #[cfg(windows)]
    let options = if screenshot.is_some() {
        eframe::NativeOptions {
            viewport: options.viewport.with_window_level(egui::WindowLevel::AlwaysOnBottom),
            ..options
        }
    } else {
        options
    };

    let port_txt = shared.proxy_port.load(Ordering::SeqCst).to_string();
    let tab = match std::env::var("WEBPROBE_TAB").unwrap_or_default().to_ascii_lowercase().as_str() {
        "target" => ui::Tab::Target,
        "proxy" => ui::Tab::Proxy,
        "scanner" => ui::Tab::Scanner,
        "intruder" => ui::Tab::Intruder,
        "repeater" => ui::Tab::Repeater,
        "sequencer" => ui::Tab::Sequencer,
        "comparer" => ui::Tab::Comparer,
        "sessions" => ui::Tab::Sessions,
        "decoder" => ui::Tab::Decoder,
        "search" => ui::Tab::Search,
        "collaborator" => ui::Tab::Collaborator,
        "extensions" => ui::Tab::Extensions,
        "logger" => ui::Tab::Logger,
        "organizer" => ui::Tab::Organizer,
        "discover" => ui::Tab::Discover,
        _ => ui::Tab::Dashboard,
    };
    let project_path = std::env::current_dir()
        .map(|d| d.join("webprobe-project.json").display().to_string())
        .unwrap_or_else(|_| "webprobe-project.json".to_string());
    // Debug hook: WEBPROBE_SETTINGS=hotkeys|appearance opens Burp's Settings
    // window on that pane (used by the screenshot checks).
    let settings_help = match std::env::var("WEBPROBE_SETTINGS").unwrap_or_default().as_str() {
        "hotkeys" => ui::SettingsPane::Hotkeys,
        _ => ui::SettingsPane::Appearance,
    };
    let settings_open = std::env::var("WEBPROBE_SETTINGS").is_ok();
    // Debug hook: WEBPROBE_PALETTE=<query> opens the command palette with that
    // text already typed (used by the screenshot checks).
    let palette_query = std::env::var("WEBPROBE_PALETTE").unwrap_or_default();
    // QA hook: WEBPROBE_DENSITY=compact|comfortable and WEBPROBE_THEME=light|dark.
    if std::env::var("WEBPROBE_DENSITY").is_ok() || std::env::var("WEBPROBE_THEME").is_ok() {
        let (p, d, f) = theme::appearance();
        let p = std::env::var("WEBPROBE_THEME").map(|v| theme::Palette::parse(&v)).unwrap_or(p);
        let d = std::env::var("WEBPROBE_DENSITY").map(|v| theme::Density::parse(&v)).unwrap_or(d);
        theme::set_appearance(p, d, f);
    }
    let palette = shortcuts::Palette {
        open: !palette_query.is_empty(),
        query: palette_query,
        sel: 0,
    };
    let app = App {
        shared,
        logger: logger::Logger::new(5000),
        organizer: organizer::Organizer::new(),
        log_filter: logger::LogQuery::default(),
        log_seen: 0,
        log_sel: None,
        org_sel: None,
        intr_sub: 0,
        ws_sel: None,
        tab,
        proxy_sub: std::env::var("WEBPROBE_PROXY_SUB")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(|v| v.min(4))
            .unwrap_or(1),
        // QA hook: WEBPROBE_SELECT_ID=<id> preselects a row so the selected-row
        // highlight can be inspected without a pointer.
        history_sel: std::env::var("WEBPROBE_SELECT_ID").ok().and_then(|v| v.trim().parse().ok()),
        split_detail: 260.0,
        target_host_sel: None,
        target_hosts: Vec::new(),
        target_items: Vec::new(),
        map_cache_len: usize::MAX,
        // Proxy history opens newest-first, like Burp's HTTP history.
        hist_table: table::TableState { sort_col: 0, sort_asc: false, ..Default::default() },
        hist_filter: history_filter::HistoryFilter::default(),
        hist_cache: Vec::new(),
        hist_cache_len: 0,
        hist_cache_key: String::new(),
        hist_cache_truncated: false,
        scan_table: table::TableState::new(),
        intr_table: table::TableState::new(),
        target_table: table::TableState::new(),
        toasts: feedback::Toasts::new(),
        shortcuts: shortcuts::Shortcuts::load(),
        palette,
        hotkey_capture: None,
        hotkey_notice: None,
        settings_open,
        settings_help,
        onboarding_hidden: false,
        detail_editor: editor::EditorState::default(),
        intercept_editor: editor::EditorState::default(),
        intr_editor: editor::EditorState::default(),
        rep_editor: editor::EditorState::default(),
        seq_editor: editor::EditorState::default(),
        dec_editor: editor::EditorState::default(),
        intercept_edit: String::new(),
        detail_sub: 0,
        req_pane: msgpane::PaneState::default(),
        resp_pane: msgpane::PaneState::default(),
        insp_state: msgpane::InspectorState::default(),
        dock_sel: 0,
        ai: ai::AiChat::default(),
        browser_url: None,
        csrf_poc: None,
        hist_window_open: false,
        hist_window_filter: String::new(),
        hist_window_table: table::TableState::default(),
        ext_sub: 0,
        ext_sel: None,
        ext_table: table::TableState::default(),
        ext_detail: 0,
        ext_add_open: false,
        ext_add_path: String::new(),
        seq_sub: 0,
        seq_requests: Vec::new(),
        seq_req_sel: None,
        seq_table: table::TableState::default(),
        seq_loc: 0,
        seq_field: String::new(),
        seq_custom: String::new(),
        seq_load_path: String::new(),
        seq_live_buf: None,
        seq_live_stop: None,
        intercept_cur: None,
        intercept_text: String::new(),
        intercept_pane: msgpane::PaneState { view: 1, ..Default::default() },
        dec_chain: Vec::new(),
        cmp_items: Vec::new(),
        cmp_sel1: None,
        cmp_sel2: None,
        cmp_table1: table::TableState::default(),
        cmp_table2: table::TableState::default(),
        cmp_paste_pending: false,
        cmp_load_path: String::new(),
        cmp_window: None,
        log_on: true,
        log_table: table::TableState::default(),
        log_req_pane: msgpane::PaneState::default(),
        log_resp_pane: msgpane::PaneState::default(),
        org_search: String::new(),
        org_table: table::TableState::default(),
        org_req_pane: msgpane::PaneState::default(),
        org_resp_pane: msgpane::PaneState::default(),
        intr_target: String::new(),
        intr_update_host: true,
        intr_pane: msgpane::PaneState { view: 1, ..Default::default() },
        intr_dock: 0,
        intr_set_sel: 0,
        intr_add: String::new(),
        intr_load_path: String::new(),
        intr_paste_pending: false,
        intr_results_open: false,
        intr_attack_no: 0,
        intr_row_sel: None,
        intr_res_req_pane: msgpane::PaneState::default(),
        intr_res_resp_pane: msgpane::PaneState::default(),
        target_sub: 0,
        target_view: 0,
        target_node: None,
        target_entry: None,
        site_req_pane: msgpane::PaneState::default(),
        site_resp_pane: msgpane::PaneState::default(),
        dash_task: 1,
        dash_sub: 0,
        dash_search: String::new(),
        dash_items_table: table::TableState::default(),
        new_scan_open: false,
        new_scan_urls: String::new(),
        new_scan_type: 0,
        rep_req_pane: msgpane::PaneState { view: 1, ..Default::default() },
        rep_resp_pane: msgpane::PaneState::default(),
        rep_target_edit: false,
        rep_update_cl: true,
        search_open: false,
        event_log_open: false,
        event_log_table: table::TableState::default(),
        mem: (0.0, 0.0),
        mem_at: None,
        detail_view: 0,
        scan_sel: None,
        // Burp starts with no Intruder request (its "To get started" state).
        intr_req: String::new(),
        intr_https: false,
        intr_payloads: "admin\n' OR 1=1--\ntest".to_string(),
        intr_attack: intruder::AttackType::Sniper,
        intr_sets: vec![String::new()],
        dec_input: String::new(),
        dec_results: Vec::new(),
        dec_output: String::new(),
        dec_sel_decode: None,
        dec_sel_encode: None,
        dec_sel_hash: None,
        scope_only: false,
        seq_mode: 0,
        seq_ignore_abnormal: true,
        seq_selector: "session".to_string(),
        seq_manual: String::new(),
        seq_samples: Vec::new(),
        seq_stats: None,
        seq_report: None,
        seq_status: String::new(),
        comparer_state: analysis::ComparerState::default(),
        search_query: String::new(),
        search_case: false,
        search_results: Vec::new(),
        project_path,
        project_status: String::new(),
        collab_state,
        macro_name: "Macro 1".to_string(),
        macro_request: "GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        rep_sel: 0,
        rep_view: 0,
        rep_req_view: 1,
        port_txt,
        frames: 0,
        saved: false,
        shot_added: false,
        selftest_done: false,
        grab_done: None,
        screenshot,
    };

    eframe::run_native(
        "WebProbe",
        options,
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app) as Box<dyn eframe::App>)
        }),
    )
    .expect("failed to start app");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u64, path: &str) -> HistRow {
        (
            id,
            id * 10,
            "GET".to_string(),
            "example.com".to_string(),
            80,
            path.to_string(),
            "200".to_string(),
            42,
            128,
            "text/html".to_string(),
        )
    }

    #[test]
    fn mirror_appends_new_rows_in_history_order() {
        let mut log = logger::Logger::new(10);
        let mut seen = 0;
        mirror_history(&mut log, &mut seen, &[row(1, "/a"), row(2, "/b"), row(3, "/c")]);
        let paths: Vec<&str> = log.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/a", "/b", "/c"]);
        assert_eq!(seen, 3);
    }

    #[test]
    fn mirror_assigns_monotonic_ids_and_copies_fields() {
        let mut log = logger::Logger::new(10);
        let mut seen = 0;
        mirror_history(&mut log, &mut seen, &[row(7, "/a"), row(8, "/b")]);
        let ids: Vec<u64> = log.entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![1, 2], "logger ids are its own, monotonic counter");
        let e = &log.entries[0];
        assert_eq!(e.ts, 70);
        assert_eq!(e.tool, "Proxy");
        assert_eq!(e.source, "proxy");
        assert_eq!(e.method, "GET");
        assert_eq!(e.host, "example.com");
        assert_eq!(e.port, 80);
        assert_eq!(e.status, "200");
        assert_eq!(e.req_len, 42);
        assert_eq!(e.resp_len, 128);
        assert_eq!(e.mime, "text/html");
    }

    #[test]
    fn second_call_with_same_rows_adds_nothing() {
        let mut log = logger::Logger::new(10);
        let mut seen = 0;
        let rows = [row(1, "/a"), row(2, "/b")];
        mirror_history(&mut log, &mut seen, &rows);
        mirror_history(&mut log, &mut seen, &rows);
        assert_eq!(log.len(), 2, "no duplicates on re-mirror");
        assert_eq!(seen, 2);

        // A later call only appends the ids that are new.
        mirror_history(&mut log, &mut seen, &[row(1, "/a"), row(2, "/b"), row(3, "/c")]);
        assert_eq!(log.len(), 3);
        assert_eq!(log.entries[2].path, "/c");
        assert_eq!(seen, 3);
    }

    #[test]
    fn mirror_skips_ids_below_seen_and_advances_past_gaps() {
        let mut log = logger::Logger::new(10);
        let mut seen = 5;
        mirror_history(&mut log, &mut seen, &[row(3, "/old"), row(6, "/new"), row(9, "/gap")]);
        let paths: Vec<&str> = log.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/new", "/gap"]);
        assert_eq!(seen, 9);
    }

    #[test]
    fn mirror_respects_the_logger_cap() {
        let mut log = logger::Logger::new(2);
        let mut seen = 0;
        mirror_history(&mut log, &mut seen, &[row(1, "/a"), row(2, "/b"), row(3, "/c")]);
        let paths: Vec<&str> = log.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/b", "/c"], "oldest evicted, seen still advanced");
        assert_eq!(seen, 3);
    }

    #[test]
    fn response_mime_prefers_content_type_then_extension() {
        let mut entry = net::HistEntry {
            id: 1,
            ts: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            https: false,
            path: "/a".into(),
            status: "200".into(),
            resp_len: 0,
            req_raw: b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            resp_raw: Some(
                b"HTTP/1.1 200 OK\r\nContent-Type: Application/JSON; charset=utf-8\r\n\r\n{}".to_vec(),
            ),
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: "bin".into(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 8080,
            ip: String::new(),
            diffs: 0,
        };
        assert_eq!(response_mime(&entry), "application/json");
        entry.resp_raw = None;
        assert_eq!(response_mime(&entry), "bin", "falls back to the URL extension");
    }
}

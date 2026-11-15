// WebProbe entry point.
// Normal start: opens the desktop app. `--screenshot <file.png>`: draws ~120
// frames without taking focus, saves the window picture as PNG and exits.

mod analysis;
mod codec;
mod analysis_ui;
mod collaborator;
mod collaborator_ui;
mod editor;
mod feedback;
mod h2;
mod history_filter;
mod net;
mod onboarding;
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

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use eframe::egui::{self, ViewportCommand};

pub struct App {
    pub shared: Arc<net::Shared>,
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
    pub detail_view: usize,
    pub scan_sel: Option<u64>,
    pub intr_req: String,
    pub intr_https: bool,
    pub intr_payloads: String,
    pub dec_input: String,
    pub dec_results: Vec<(String, String)>,
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
    pub port_txt: String,
    pub frames: usize,
    pub saved: bool,
    pub shot_added: bool,
    pub selftest_done: bool,
    pub grab_done: Option<Arc<Mutex<bool>>>,
    pub screenshot: Option<PathBuf>,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        theme::apply_current(ctx);
        feedback::drain(&mut self.toasts);
        self.toasts.tick(std::time::Instant::now());
        ui::show(self, ctx);
        self.toasts.show(ctx);

        ctx.request_repaint(); // keep drawing even when the window is not focused

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
                                crate::scan::start_active_scan(sh.clone(), e);
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
    let palette = shortcuts::Palette {
        open: !palette_query.is_empty(),
        query: palette_query,
        sel: 0,
    };
    let app = App {
        shared,
        tab,
        proxy_sub: std::env::var("WEBPROBE_PROXY_SUB")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(|v| v.min(3))
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
        detail_view: 0,
        scan_sel: None,
        intr_req: "GET /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: WebProbe/1.0\r\n\r\n".to_string(),
        intr_https: false,
        intr_payloads: "admin\n' OR 1=1--\ntest".to_string(),
        dec_input: String::new(),
        dec_results: Vec::new(),
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

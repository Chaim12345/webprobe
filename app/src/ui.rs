// UI panels: Dashboard, Target (site map), Proxy (intercept/history/options),
// Intruder, Repeater, Decoder. Styling per theme.rs (DarkTheme.json evidence).

use std::sync::atomic::Ordering;

use eframe::egui::{self, RichText, Ui};

use crate::editor;
use crate::intruder;
use crate::feedback;
use crate::net;
use crate::scan;
use crate::table;
use crate::theme::{self, c};
use crate::util;
use crate::App;

#[derive(PartialEq, Clone, Copy)]
pub enum Tab {
    Dashboard,
    Target,
    Proxy,
    Scanner,
    Intruder,
    Repeater,
    Sequencer,
    Comparer,
    Logger,
    Organizer,
    Sessions,
    Decoder,
    Search,
    Collaborator,
    Extensions,
    BurpAi,
    Discover,
}

/// Burp's 13 top-level tools, in Burp's order (live 52685 window).
const TABS: [(&str, Tab); 13] = [
    ("Dashboard", Tab::Dashboard),
    ("Target", Tab::Target),
    ("Proxy", Tab::Proxy),
    ("Intruder", Tab::Intruder),
    ("Repeater", Tab::Repeater),
    ("Collaborator", Tab::Collaborator),
    ("Sequencer", Tab::Sequencer),
    ("Decoder", Tab::Decoder),
    ("Comparer", Tab::Comparer),
    ("Logger", Tab::Logger),
    ("Organizer", Tab::Organizer),
    ("Extensions", Tab::Extensions),
    ("Discover", Tab::Discover),
];

pub fn show(app: &mut App, ctx: &egui::Context) {
    // M-06: key capture for the hotkey settings table comes first, so the
    // pressed chord becomes a binding instead of firing a command.
    if app.hotkey_capture.is_some() {
        match crate::shortcuts::capture(ctx) {
            crate::shortcuts::Capture::Idle => {}
            crate::shortcuts::Capture::Cancelled => {
                app.hotkey_capture = None;
                app.hotkey_notice = None;
            }
            crate::shortcuts::Capture::Chord(chord) => {
                let idx = app.hotkey_capture.take().unwrap_or(0);
                let label = crate::shortcuts::ACTIONS
                    .get(idx)
                    .map(|d| d.label)
                    .unwrap_or("hotkey");
                let shown = chord.format();
                match app.shortcuts.set(idx, Some(chord)) {
                    Ok(()) => {
                        app.hotkey_notice = None;
                        match app.shortcuts.save() {
                            Ok(()) => feedback::toast(
                                feedback::Level::Success,
                                format!("{label}: {shown}"),
                            ),
                            Err(e) => app.hotkey_notice = Some(e),
                        }
                    }
                    Err(e) => {
                        // Refused duplicate: keep the table as it was.
                        app.hotkey_notice = Some(e);
                    }
                }
            }
        }
    } else {
        for idx in app.shortcuts.handle(ctx) {
            run_shortcut(app, idx);
        }
    }
    // Command palette (Ctrl+K) and the Settings window are drawn above every tab.
    if let Some(idx) = crate::shortcuts::palette_ui(&mut app.palette, &mut app.shortcuts, ctx) {
        run_shortcut(app, idx);
    }
    settings_window(app, ctx);
    app.toasts.show(ctx);

    // P-01: Burp's menu row sits above the tab row. Only items that do
    // something real are here; the rest of Burp's menus arrive with their
    // features (P-03 Settings, D-06 issues, K-03 extensions).
    egui::TopBottomPanel::top("menu_bar")
        .exact_height(26.0)
        .frame(
            egui::Frame::default()
                .fill(theme::chrome_alt())
                .inner_margin(egui::Margin::symmetric(6.0, 2.0)),
        )
        .show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("WebProbe", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("Search").clicked() {
                        app.search_open = true;
                        ui.close_menu();
                    }
                    if ui.button("Settings").clicked() {
                        app.settings_open = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Project", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("Project options\u{2026}").clicked() {
                        app.settings_open = true;
                        ui.close_menu();
                    }
                });
                ui.menu_button("Intruder", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("Send to Intruder").clicked() {
                        send_history_to_intruder(app);
                        app.tab = Tab::Intruder;
                        ui.close_menu();
                    }
                });
                ui.menu_button("Repeater", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("Send to Repeater").clicked() {
                        send_history_to_repeater(app);
                        app.tab = Tab::Repeater;
                        ui.close_menu();
                    }
                    if ui.button("Send request").clicked() {
                        repeater_send(app);
                        ui.close_menu();
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    // Burp: "Restore default tab layout", then the tools
                    // alphabetically (theme lives in Settings > Appearance).
                    if ui.button("Restore default tab layout").clicked() {
                        app.tab = Tab::Dashboard;
                        ui.close_menu();
                    }
                    ui.separator();
                    let mut names: Vec<(&str, Tab)> = TABS.to_vec();
                    names.sort_by_key(|(n, _)| *n);
                    for (name, tab) in names {
                        if ui.button(name).clicked() {
                            app.tab = tab;
                            ui.close_menu();
                        }
                    }
                });
                let title = format!("WebProbe - {}", std::path::Path::new(&app.project_path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default());
                let full = ui.max_rect();
                ui.painter().text(full.center(), egui::Align2::CENTER_CENTER, title, egui::FontId::proportional(12.5), theme::ink_dim());
                ui.menu_button("Help", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("Keyboard shortcuts").clicked() {
                        app.settings_help = SettingsPane::Hotkeys;
                        app.settings_open = true;
                        ui.close_menu();
                    }
                    if ui.button("About WebProbe").clicked() {
                        feedback::toast(feedback::Level::Info, "WebProbe \u{2014} Burp-compatible proxy");
                        ui.close_menu();
                    }
                });
            });
        });

    egui::TopBottomPanel::top("main_bar")
        .exact_height(38.0)
        .frame(egui::Frame::default().fill(theme::surface()).inner_margin(egui::Margin::symmetric(0.0, 0.0)))
        .show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                // Burp's tool tabs: plain labels, orange[1] underline on the
                // active one, no branding in the row.
                for (name, tab) in &TABS {
                    let sel = app.tab == *tab;
                    let galley = ui.painter().layout_no_wrap(name.to_string(), egui::FontId::proportional(12.5), theme::ink());
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(galley.size().x + 22.0, 38.0), egui::Sense::click());
                    if resp.hovered() && !sel {
                        ui.painter().rect_filled(rect, 0.0, theme::zebra());
                    }
                    ui.painter().galley(egui::pos2(rect.left() + 11.5, rect.center().y - galley.size().y / 2.0), galley, theme::ink());
                    if sel {
                        ui.painter().line_segment(
                            [egui::pos2(rect.left(), rect.bottom() - 1.5), egui::pos2(rect.right(), rect.bottom() - 1.5)],
                            egui::Stroke::new(3.0, c(theme::ORANGE_1)),
                        );
                    }
                    if resp.clicked() {
                        app.tab = *tab;
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.add_space(10.0);
                    // The AI pill (Burp AT). WebProbe's assistant view.
                    let pill = egui::Button::new(
                        RichText::new(format!("{}  WebProbe AI", theme::icon::LIGHTNING)).strong().size(12.5).color(theme::ink()),
                    )
                    .fill(theme::surface())
                    .stroke(egui::Stroke::new(1.5, c(0xFFB090)))
                    .rounding(6.0)
                    .min_size(egui::vec2(112.0, 26.0));
                    if ui.add(pill).clicked() {
                        app.tab = Tab::BurpAi;
                    }
                    ui.add_space(8.0);
                    let icon_btn = |ui: &mut Ui, glyph: &str, tip: &str| {
                        ui.add(egui::Button::new(RichText::new(glyph).size(17.0).color(theme::ink_dim())).frame(false).min_size(egui::vec2(24.0, 24.0)))
                            .on_hover_text(tip)
                            .clicked()
                    };
                    if icon_btn(ui, theme::icon::GEAR, "Settings") {
                        app.settings_open = true;
                    }
                    if icon_btn(ui, theme::icon::MAGNIFYING_GLASS, "Search") {
                        app.search_open = true;
                    }
                    if icon_btn(ui, theme::icon::TERMINAL, "Command palette (Ctrl+K)") {
                        app.palette.open = true;
                    }
                    if icon_btn(ui, theme::icon::GLOBE, "Open browser") {
                        match crate::tools::launch_preconfigured_browser(&app.shared) {
                            Ok(m) => feedback::toast(feedback::Level::Success, m),
                            Err(e) => feedback::toast(feedback::Level::Error, e),
                        }
                    }
                });
            });
            let r = ui.max_rect();
            ui.painter().hline(r.x_range(), r.bottom() - 0.5, egui::Stroke::new(1.0, theme::line()));
        });

    // Status bar, as Burp draws it: "Event log" and "All issues" on the left,
    // the memory gauge on the right. WebProbe adds the listener and intercept
    // state in the same muted style, because there is no title-bar for them.
    egui::TopBottomPanel::bottom("status_bar")
        .exact_height(36.0)
        .frame(
            egui::Frame::default()
                .fill(theme::chrome())
                .inner_margin(egui::Margin::symmetric(8.0, 3.0)),
        )
        .show(ctx, |ui| {
            let r = ui.max_rect();
            ui.painter().hline(r.x_range(), r.top() - 3.0, egui::Stroke::new(1.0, theme::line()));
            ui.horizontal_centered(|ui| {
                let link = |ui: &mut Ui, t: &str| {
                    ui.add(egui::Button::new(RichText::new(t).size(12.5).color(theme::ink())).frame(false).min_size(egui::vec2(0.0, 24.0))).clicked()
                };
                ui.add_space(6.0);
                if link(ui, "Event log") {
                    app.event_log_open = !app.event_log_open;
                }
                ui.add_space(14.0);
                if link(ui, "All issues") {
                    app.tab = Tab::Scanner;
                }
                let on = app.shared.intercept_on.load(Ordering::SeqCst);
                let waiting = app.shared.count_waiting();
                let port = app.shared.proxy_port.load(Ordering::SeqCst);
                let (busy, done, scan_total) = (
                    app.shared.scan_busy.load(Ordering::SeqCst),
                    app.shared.scan_done.load(Ordering::SeqCst),
                    app.shared.scan_total.load(Ordering::SeqCst),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    let (used, total) = memory_usage(app);
                    let (bar, _) = ui.allocate_exact_size(egui::vec2(48.0, 6.0), egui::Sense::hover());
                    ui.painter().rect_filled(bar, 3.0, theme::line());
                    let frac = if total > 0.0 { (used / total).clamp(0.02, 1.0) } else { 0.0 };
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(bar.min, egui::vec2(bar.width() * frac as f32, bar.height())),
                        3.0,
                        c(0x5384B2),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(format!("Memory: {:.1}MB of {:.2}GB", used, total / 1024.0))
                            .size(12.5)
                            .color(theme::ink_dim()),
                    );
                    ui.label(RichText::new(theme::icon::INFO).size(14.0).color(theme::ink_dim()));
                    ui.add_space(18.0);
                    if busy || scan_total > 0 {
                        ui.label(RichText::new(format!("Scan {done}/{scan_total}")).size(12.0).color(if busy { c(theme::ORANGE) } else { theme::ink_hint() }));
                        ui.add_space(12.0);
                    }
                    if waiting > 0 {
                        ui.label(RichText::new(format!("{waiting} held")).size(12.0).color(c(theme::WARN)));
                        ui.add_space(12.0);
                    }
                    ui.label(
                        RichText::new(format!("Proxy 127.0.0.1:{port} \u{00B7} intercept {}", if on { "on" } else { "off" }))
                            .size(12.0)
                            .color(if on { c(theme::ORANGE) } else { theme::ink_hint() }),
                    );
                });
            });
        });

    event_log_window(app, ctx);
    search_window(app, ctx);
    history_menu_windows(app, ctx);

    egui::CentralPanel::default()
        .frame(egui::Frame::default().fill(theme::surface()).inner_margin(egui::Margin::same(10.0)))
        .show(ctx, |ui| match app.tab {
            Tab::Dashboard => dashboard(app, ui),
            Tab::Target => target(app, ui),
            Tab::Proxy => proxy(app, ui),
            Tab::Scanner => scanner(app, ui),
            Tab::Intruder => intruder(app, ui),
            Tab::Repeater => repeater(app, ui),
            Tab::Sequencer => crate::tools::sequencer(app, ui),
            Tab::Comparer => comparer(app, ui),
            Tab::Logger => logger_view(app, ui),
            Tab::Organizer => organizer_view(app, ui),
            Tab::Sessions => crate::tools::sessions(app, ui),
            Tab::Decoder => decoder(app, ui),
            Tab::Search => crate::tools::search(app, ui),
            Tab::Collaborator => crate::collaborator_ui::show(&mut app.collab_state, ui),
            Tab::Extensions => crate::tools::extensions(app, ui),
            Tab::BurpAi => burp_ai(app, ui),
            Tab::Discover => discover(app, ui),
        });
}

/// Most matching history rows laid out in one go. Older rows stay in the model,
/// they are just not drawn (N-02).
const HISTORY_RENDER_LIMIT: usize = 1000;

/// The rows the history table shows: newest first, filtered, sorted, then capped.
/// The order of those steps is the contract: the filter and the sort see the
/// whole list and only the result is cut, otherwise an old match or the true
/// top of a sort would silently vanish behind the cap. Pure, so it is tested.
/// UTC time-of-day for a unix timestamp, for Burp's "Time requested" column
/// (build 52685 burp.Zxwu line 52).
pub(crate) fn time_of_day(ts: u64) -> String {
    let s = ts % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

/// Engagement tools > Generate CSRF PoC: an auto-submitting HTML form that
/// replays the request's parameters (URL-encoded body, or query for GET).
pub(crate) fn csrf_poc_html(e: &net::HistEntry) -> String {
    let url = history_url(e);
    let parts = util::parse_http(&e.req_raw);
    let body = String::from_utf8_lossy(&e.req_raw[parts.head_len.min(e.req_raw.len())..]).into_owned();
    let (action, params) = if e.method.eq_ignore_ascii_case("GET") {
        let (u, q) = url.split_once('?').unwrap_or((url.as_str(), ""));
        (u.to_string(), q.to_string())
    } else {
        (url.clone(), body)
    };
    let esc = |v: &str| v.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;");
    let mut inputs = String::new();
    for kv in params.split('&').filter(|x| !x.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        inputs.push_str(&format!("      <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n", esc(&util::url_decode(k)), esc(&util::url_decode(v))));
    }
    format!(
        "<html>\n  <!-- CSRF PoC - generated by WebProbe -->\n  <body>\n    <form action=\"{}\" method=\"{}\">\n{inputs}      <input type=\"submit\" value=\"Submit request\" />\n    </form>\n    <script>\n      history.pushState('', '', '/');\n      document.forms[0].submit();\n    </script>\n  </body>\n</html>\n",
        esc(&action),
        if e.method.eq_ignore_ascii_case("GET") { "GET" } else { "POST" }
    )
}

/// The dialogs the history context menu opens.
fn history_menu_windows(app: &mut App, ctx: &egui::Context) {
    if let Some((title, url)) = app.browser_url.clone() {
        let mut open = true;
        egui::Window::new(title).open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
            ui.label("To show this item in your browser, copy the URL below and paste it into a browser that is configured to use WebProbe as its proxy.");
            ui.add_space(6.0);
            let mut u = url.clone();
            ui.add(egui::TextEdit::singleline(&mut u).desired_width(420.0));
            ui.horizontal(|ui| {
                if ui.button("Copy").clicked() {
                    ui.output_mut(|o| o.copied_text = url.clone());
                }
                if ui.button("Close").clicked() {
                    app.browser_url = None;
                }
            });
        });
        if !open {
            app.browser_url = None;
        }
    }
    if let Some(html) = app.csrf_poc.clone() {
        let mut open = true;
        egui::Window::new("CSRF PoC generator").open(&mut open).default_size(egui::vec2(640.0, 420.0)).show(ctx, |ui| {
            ui.label(RichText::new("CSRF HTML:").strong());
            let mut h = html.clone();
            ui.add(egui::TextEdit::multiline(&mut h).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).desired_rows(16));
            ui.horizontal(|ui| {
                if ui.button("Copy HTML").clicked() {
                    ui.output_mut(|o| o.copied_text = html.clone());
                }
                if ui.button("Close").clicked() {
                    app.csrf_poc = None;
                }
            });
        });
        if !open {
            app.csrf_poc = None;
        }
    }
    if app.hist_window_open {
        let mut open = true;
        egui::Window::new("HTTP history").open(&mut open).default_size(egui::vec2(900.0, 420.0)).show(ctx, |ui| {
            ui.add(egui::TextEdit::singleline(&mut app.hist_window_filter).hint_text("Search").desired_width(260.0));
            let q = app.hist_window_filter.to_ascii_lowercase();
            let rows: Vec<net::HistEntry> = app.shared.history.lock().unwrap().iter().rev().filter(|e| q.is_empty() || history_url(e).to_ascii_lowercase().contains(&q)).cloned().collect();
            let cols = [table::Column::new("#", 50.0), table::Column::new("Host", 180.0), table::Column::new("Method", 60.0), table::Column::new("URL", 300.0), table::Column::new("Status code", 80.0), table::Column::new("Length", 70.0)];
            let mut st = app.hist_window_table.clone();
            let mut pick = None;
            let h = ui.available_height();
            table::table_body(ui, "hist_window", &cols, &rows, &mut st, 19.0, h, &mut |e, ui| {
                let row = ui.horizontal(|ui| {
                    table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                        (0, e.id.to_string(), None),
                        (1, history_host(e), None),
                        (2, e.method.clone(), None),
                        (3, e.path.clone(), None),
                        (4, e.status.clone(), None),
                        (5, e.resp_len.to_string(), None),
                    ]);
                }).response.interact(egui::Sense::click());
                if row.clicked() {
                    pick = Some(e.id);
                }
            });
            app.hist_window_table = st;
            if pick.is_some() {
                app.history_sel = pick;
            }
        });
        if !open {
            app.hist_window_open = false;
        }
    }
}

/// Burp's row highlight colours (ui.highlight.N.background in LightTheme.json).
const HIGHLIGHT_NAMES: [&str; 9] = ["Red", "Orange", "Yellow", "Green", "Cyan", "Blue", "Pink", "Magenta", "Gray"];
const HIGHLIGHT_CMDS: [&str; 9] = ["hl_0", "hl_1", "hl_2", "hl_3", "hl_4", "hl_5", "hl_6", "hl_7", "hl_8"];
pub(crate) fn highlight_colours(k: u8) -> (egui::Color32, egui::Color32) {
    let (bg, fg) = match k {
        0 => (0xFF6464, 0xFFFFFF),
        1 => (0xFFC864, 0x000000),
        2 => (0xFFFF64, 0x000000),
        3 => (0x64FF64, 0x000000),
        4 => (0x64FFFF, 0x000000),
        5 => (0x6464FF, 0xFFFFFF),
        6 => (0xFFC8C8, 0x000000),
        7 => (0xFF64FF, 0x000000),
        _ => (0xB4B4B4, 0x000000),
    };
    (c(bg), c(fg))
}

/// Burp's Host column: scheme://host, with the port only when it is not the
/// scheme default.
pub(crate) fn history_host(e: &net::HistEntry) -> String {
    let scheme = if e.https { "https" } else { "http" };
    let default = if e.https { 443 } else { 80 };
    if e.port == default || e.port == 0 {
        format!("{scheme}://{}", e.host)
    } else {
        format!("{scheme}://{}:{}", e.host, e.port)
    }
}

/// Burp's Time column ("22:05:18 15 Nov 2026").
pub(crate) fn history_time(ts: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(ts as i64) {
        Ok(t) => {
            const M: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            format!(
                "{:02}:{:02}:{:02} {} {} {}",
                t.hour(), t.minute(), t.second(), t.day(), M[(u8::from(t.month()) - 1) as usize], t.year()
            )
        }
        Err(_) => time_of_day(ts),
    }
}

fn history_view(
    history: &[net::HistEntry],
    keep: impl Fn(&net::HistEntry) -> bool,
    sort: &table::TableState,
) -> (Vec<net::HistEntry>, bool) {
    let mut rows: Vec<net::HistEntry> = history.iter().rev().filter(|e| keep(e)).cloned().collect();
    table::sort_rows(&mut rows, sort, |e, col| match col {
        0 => format!("{:020}", e.id),
        1 => history_host(e),
        2 => e.method.clone(),
        3 => e.path.clone(),
        4 => if e.params { "1".to_string() } else { String::new() },
        5 => if e.edited { "1".to_string() } else { String::new() },
        6 => e.status.clone(),
        7 => format!("{:010}", e.resp_len),
        8 => crate::history_filter::HistoryFilter::burp_mime_of(e).to_string(),
        9 => e.extension.clone(),
        10 => e.title.clone(),
        11 => e.note.clone().unwrap_or_default(),
        12 => if e.https { "1".to_string() } else { String::new() },
        13 => e.ip.clone(),
        14 => e.cookies.clone(),
        15 => format!("{:020}", e.ts),
        16 => format!("{:05}", e.listener_port),
        17 => format!("{:010}", e.diffs),
        _ => String::new(),
    });
    let truncated = rows.len() > HISTORY_RENDER_LIMIT;
    rows.truncate(HISTORY_RENDER_LIMIT);
    (rows, truncated)
}

/// Proxy > HTTP history (B-01).
///
/// The filter bar is text/regex plus method, status code, MIME type and "in scope
/// only"; every column is sortable and resizable, and the view is virtualized.
fn proxy_history(app: &mut App, ui: &mut Ui) {
    let total = app.shared.history.lock().map(|h| h.len()).unwrap_or(0);

    // N-02: the filtered view is recomputed only when an input changed, never
    // once per frame. The key covers every filter input plus the history size
    // and the sort column, so anything the user can change invalidates it.
    let key = format!(
        "{}|{}|{}|{}",
        total,
        app.hist_filter.key(),
        app.hist_table.sort_col,
        app.hist_table.sort_asc,
    );
    let (rows, truncated) = if key != app.hist_cache_key || total < app.hist_cache_len {
        let (rows, truncated) = {
            let history = app.shared.history.lock().unwrap();
            history_view(&history, |e| app.hist_filter.matches(e, &app.shared), &app.hist_table)
        };
        app.hist_cache_len = total;
        app.hist_cache = rows;
        app.hist_cache_truncated = truncated;
        app.hist_cache_key = key;
        (app.hist_cache.clone(), truncated)
    } else {
        (app.hist_cache.clone(), app.hist_cache_truncated)
    };

    // B-01 filter bar, between the sub-tabs and the table. An edit is picked up
    // by the cache key on the next frame (the app repaints continuously).
    let regex_broken = app.hist_filter.ui(ui, &app.shared, rows.len(), total);
    if regex_broken {
        ui.label(
            RichText::new("That is not a valid regular expression.")
                .size(12.0)
                .color(c(theme::BAD)),
        );
    }
    ui.add_space(2.0);

    // Burp's HTTP history columns, in Burp's order (live 52685 window).
    let columns = [
        table::Column::new("#", 38.0),
        table::Column::new("Host", 168.0),
        table::Column::new("Method", 56.0),
        table::Column::new("URL", 200.0),
        table::Column::new("Params", 54.0),
        table::Column::new("Edited", 54.0),
        table::Column::new("Status code", 80.0),
        table::Column::new("Length", 54.0),
        table::Column::new("MIME type", 66.0),
        table::Column::new("Extension", 66.0),
        table::Column::new("Title", 134.0),
        table::Column::new("Notes", 100.0),
        table::Column::new("TLS", 38.0),
        table::Column::new("IP", 108.0),
        table::Column::new("Cookies", 108.0),
        table::Column::new("Time", 80.0),
        table::Column::new("Listener port", 84.0),
        // "Diff count", Proxy history (build 52685 burp.Zxwu.java:56); off by default.
        table::Column::new("Diff count", 64.0),
    ];
    if app.hist_table.hidden.len() < columns.len() {
        let mut v = vec![true; columns.len()];
        v[17] = false;
        for (i, x) in app.hist_table.hidden.iter().enumerate() {
            v[i] = *x;
        }
        app.hist_table.hidden = v;
    }
    if truncated {
        ui.label(RichText::new("(most recent 1000 matching entries)").size(12.0).color(theme::ink_faint()));
    }

    // Burp: Up/Down move the selection when no text field has the keyboard.
    if !ui.ctx().wants_keyboard_input() && !rows.is_empty() {
        let (up, down) = ui.input(|i| (i.key_pressed(egui::Key::ArrowUp), i.key_pressed(egui::Key::ArrowDown)));
        if up || down {
            let pos = app.history_sel.and_then(|id| rows.iter().position(|r| r.id == id));
            let next = match (pos, down) {
                (None, _) => 0,
                (Some(p), true) => (p + 1).min(rows.len() - 1),
                (Some(p), false) => p.saturating_sub(1),
            };
            app.history_sel = Some(rows[next].id);
        }
    }

    let mut selected = app.history_sel;
    // Burp's JTable rows are ~16 px; keep a little air for egui's text.
    let row_height = 19.0;
    // Leave room for the message pane underneath, like Burp's split view; the
    // divider between the two is draggable (B-05).
    let pane_h = ui.available_height();
    // The split detail is the message pane; keep at least 40% of the space for it.
    // Burp gives the message area a bit more than half of the tab.
    if app.split_detail < 0.0 || app.split_detail == 260.0 {
        app.split_detail = (pane_h * 0.58).max(260.0);
    }
    let table_h = (pane_h - app.split_detail.min(pane_h * 0.75)).max(120.0);
    // The column visibility is read inside the row closure, so it is snapshotted
    // here rather than borrowed from the table state the body mutably holds.
    let visible = app.hist_table.hidden.clone();
    let widths = app.hist_table.widths.clone();
    let col_state = table::TableState { hidden: visible, widths, ..Default::default() };
    // Context-menu commands captured during the frame, applied right after
    // table_body returns (the row closure cannot borrow `app` mutably).
    let mut pending_menu: Option<(net::HistEntry, &'static str)> = None;
    table::table_body(ui, "proxy_history", &columns, &rows, &mut app.hist_table, row_height, table_h, &mut |e, ui| {
        let row_rect = egui::Rect::from_min_size(
            ui.cursor().min,
            egui::vec2(ui.available_width(), row_height),
        );
        if selected == Some(e.id) {
            // Burp's selectionBackground, so a selected row reads as selected
            // and not as a warning.
            ui.painter().rect_filled(row_rect, egui::Rounding::ZERO, theme::selection_bg());
            ui.painter().rect_stroke(row_rect.shrink(0.5), egui::Rounding::ZERO, egui::Stroke::new(1.0, c(0x5384B2)));
        } else if let Some(k) = e.highlight {
            ui.painter().rect_filled(row_rect, egui::Rounding::ZERO, highlight_colours(k).0);
        } else if e.id % 2 == 0 {
            ui.painter().rect_filled(row_rect, egui::Rounding::ZERO, theme::zebra());
        }
        let row = ui
            .horizontal(|ui| {
                let tick = |b: bool| if b { theme::icon::CHECK.to_string() } else { String::new() };
                let ink = Some(match e.highlight {
                    Some(k) if selected != Some(e.id) => highlight_colours(k).1,
                    _ => theme::ink_dim(),
                });
                let cells = [
                    (0, e.id.to_string(), ink),
                    (1, history_host(e), ink),
                    (2, e.method.clone(), ink),
                    (3, e.path.clone(), ink),
                    (4, tick(e.params), ink),
                    (5, tick(e.edited), ink),
                    (6, e.status.clone(), ink),
                    (7, e.resp_len.to_string(), ink),
                    (8, crate::history_filter::HistoryFilter::burp_mime_of(e).to_string(), ink),
                    (9, e.extension.clone(), ink),
                    (10, e.title.clone(), ink),
                    (11, e.note.clone().unwrap_or_default(), ink),
                    (12, tick(e.https), ink),
                    (13, e.ip.clone(), ink),
                    (14, e.cookies.clone(), ink),
                    (15, history_time(e.ts), ink),
                    (16, e.listener_port.to_string(), ink),
                    (17, e.diffs.to_string(), ink),
                ];
                table::cells(ui, &columns, &col_state, row_height, &cells);
            })
            .response
            .interact(egui::Sense::click());
        if row.clicked() {
            selected = Some(e.id);
        }
        // History context menu, items and order grounded in the live 52685
        // reference (right-click on a populated history row, 2026-11-15):
        // Add to scope / Scan / Passive scan selected message / Active scan
        // selected message / Send to Intruder / Send to Repeater / Send to
        // Sequencer / Send to Organizer / Send to Comparer (request|response)
        // / Open response in browser / Request in browser / Send to Burp AT /
        // Engagement tools / Show new history window / Add notes / Highlight
        // / Delete item / Clear history / Copy URL / Copy as curl command
        // (bash) / Copy links in response / Save item / Proxy history
        // documentation. Items without a WebProbe backend are disabled rather
        // than pretended away. App-touching commands are queued as
        // pending_menu and applied after table_body, because the row closure
        // must not capture `app` while `app.hist_table` is mutably borrowed.
        row.context_menu(|ui| {
            ui.set_min_width(260.0);
            // Swing menu density: ~22 px items.
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.spacing_mut().button_padding.y = 4.0;
            ui.label(RichText::new(history_url(e)).strong().size(12.5));
            ui.separator();
            if menu_action(ui, "Add to scope") {
                pending_menu = Some((e.clone(), "scope"));
            }
            if menu_action(ui, "Scan") {
                pending_menu = Some((e.clone(), "scan"));
            }
            if menu_action(ui, "Passive scan selected message") {
                pending_menu = Some((e.clone(), "passive"));
            }
            if menu_action(ui, "Active scan selected message") {
                pending_menu = Some((e.clone(), "scan"));
            }
            ui.separator();
            if menu_action(ui, "Send to Intruder\tCtrl+I") {
                pending_menu = Some((e.clone(), "intruder"));
            }
            if menu_action(ui, "Send to Repeater\tCtrl+R") {
                pending_menu = Some((e.clone(), "repeater"));
            }
            if menu_action(ui, "Send to Sequencer") {
                pending_menu = Some((e.clone(), "sequencer"));
            }
            if menu_action(ui, "Send to Organizer\tCtrl+O") {
                pending_menu = Some((e.clone(), "organizer"));
            }
            if menu_action(ui, "Send to Comparer (request)") {
                pending_menu = Some((e.clone(), "cmp_req"));
            }
            if menu_action(ui, "Send to Comparer (response)") {
                pending_menu = Some((e.clone(), "cmp_resp"));
            }
            if menu_action(ui, "Open response in browser") {
                pending_menu = Some((e.clone(), "show_browser"));
            }
            if menu_action(ui, "Request in browser") {
                pending_menu = Some((e.clone(), "req_browser"));
            }
            if menu_action(ui, "Send to WebProbe AI") {
                pending_menu = Some((e.clone(), "ai"));
            }
            ui.menu_button(RichText::new("Engagement tools").size(13.0), |ui| {
                if menu_action(ui, "Find references") {
                    pending_menu = Some((e.clone(), "find_refs"));
                }
                if menu_action(ui, "Generate CSRF PoC") {
                    pending_menu = Some((e.clone(), "csrf_poc"));
                }
            });
            ui.separator();
            if menu_action(ui, "Show new history window") {
                pending_menu = Some((e.clone(), "hist_window"));
            }
            if menu_action(ui, "Add notes") {
                pending_menu = Some((e.clone(), "notes"));
            }
            ui.menu_button(RichText::new("Highlight").size(13.0), |ui| {
                // ui.highlight.0..8 (LightTheme.json), Burp's menu order.
                for (k, name) in HIGHLIGHT_NAMES.iter().enumerate() {
                    let (bg, _) = highlight_colours(k as u8);
                    if ui.add(egui::Button::new(RichText::new(*name).size(13.0)).fill(bg)).clicked() {
                        pending_menu = Some((e.clone(), HIGHLIGHT_CMDS[k]));
                        ui.close_menu();
                    }
                }
                if ui.button("None").clicked() {
                    pending_menu = Some((e.clone(), "hl_none"));
                    ui.close_menu();
                }
            });
            if menu_action(ui, "Delete item") {
                pending_menu = Some((e.clone(), "delete"));
            }
            if menu_action(ui, "Clear history") {
                pending_menu = Some((e.clone(), "clear"));
            }
            ui.separator();
            if menu_action(ui, "Copy URL") {
                ui.output_mut(|o| o.copied_text = history_url(e));
            }
            if menu_action(ui, "Copy as curl command (bash)") {
                ui.output_mut(|o| o.copied_text = curl_command_of(e));
            }
            if menu_action(ui, "Copy links in response") {
                ui.output_mut(|o| o.copied_text = links_in_response(e));
            }
            if menu_action(ui, "Save item") {
                pending_menu = Some((e.clone(), "save_item"));
            }
            ui.separator();
            if menu_action(ui, "Proxy history documentation") {
                pending_menu = Some((e.clone(), "docs"));
            }
        });
    });
    if let Some((e, cmd)) = pending_menu {
        match cmd {
            "scope" => {
                let rule = format!("{}://{}", if e.https { "https" } else { "http" }, e.host);
                app.shared.scope.lock().unwrap().push(net::ScopeRule::include(rule, false));
                app.shared.log(&format!("Added {} to target scope", e.host));
            }
            "scan" => run_active_scan_on(app, &e),
            "intruder" => {
                app.history_sel = Some(e.id);
                send_history_to_intruder(app);
                app.tab = Tab::Intruder;
            }
            "repeater" => {
                app.history_sel = Some(e.id);
                send_history_to_repeater(app);
                app.tab = Tab::Repeater;
            }
            "organizer" => {
                let req_text = String::from_utf8_lossy(&e.req_raw).into_owned();
                let resp_text = e.resp_raw.as_ref().map(|r| String::from_utf8_lossy(r).into_owned()).unwrap_or_default();
                app.organizer.add(&format!("{} {}", e.method, e.path), "", &req_text, &resp_text, util::now_secs());
                app.shared.log(&format!("Sent {} {} to Organizer", e.method, e.path));
                feedback::toast(feedback::Level::Success, "Sent to Organizer");
            }
            "cmp_req" => {
                app.cmp_items.push(request_for_tools(&e.req_raw));
                app.tab = Tab::Comparer;
            }
            "cmp_resp" => {
                app.cmp_items.push(e.resp_raw.as_ref().map(|r| String::from_utf8_lossy(r).into_owned()).unwrap_or_default());
                app.tab = Tab::Comparer;
            }
            "ai" => {
                app.ai.input = crate::ai::explain_prompt(&request_for_tools(&e.req_raw).into_bytes(), e.resp_raw.as_deref());
                app.tab = Tab::BurpAi;
            }
            "passive" => {
                crate::scan::add_passive_issues(&app.shared, crate::scan::passive_check(&e));
                feedback::toast(feedback::Level::Info, "Passive scan of the selected message done");
            }
            "show_browser" => app.browser_url = Some(("Show response in browser".into(), format!("http://webprobe/show/{}", e.id))),
            "req_browser" => app.browser_url = Some(("Request in browser".into(), format!("http://webprobe/repeat/{}", e.id))),
            "hist_window" => app.hist_window_open = true,
            "docs" => app.tab = Tab::Discover,
            "save_item" => {
                let dir = std::env::current_dir().map(|d| d.join("saved-items")).unwrap_or_else(|_| "saved-items".into());
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join(format!("item-{}.http", e.id));
                let mut bytes = e.req_raw.clone();
                bytes.extend_from_slice(b"\r\n\r\n");
                if let Some(r) = &e.resp_raw {
                    bytes.extend_from_slice(r);
                }
                match std::fs::write(&path, bytes) {
                    Ok(()) => feedback::toast(feedback::Level::Success, format!("Saved to {}", path.display())),
                    Err(err) => feedback::toast(feedback::Level::Error, format!("Save failed: {err}")),
                }
            }
            "find_refs" => {
                app.search_query = history_url(&e);
                app.search_open = true;
            }
            "csrf_poc" => app.csrf_poc = Some(csrf_poc_html(&e)),
            "sequencer" => {
                app.history_sel = Some(e.id);
                app.seq_requests.push(e.clone());
                app.seq_req_sel = Some(app.seq_requests.len() - 1);
                app.tab = Tab::Sequencer;
            }
            "notes" => {
                app.history_sel = Some(e.id);
                app.dock_sel = 1;
            }
            cmd if cmd.starts_with("hl_") => {
                let k = HIGHLIGHT_CMDS.iter().position(|c| *c == cmd).map(|k| k as u8);
                if let Some(h) = app.shared.history.lock().unwrap().iter_mut().find(|h| h.id == e.id) {
                    h.highlight = k;
                }
                app.hist_cache_key.clear();
            }
            "delete" => {
                app.shared.history.lock().unwrap().retain(|h| h.id != e.id);
                selected = None;
                app.shared.log(&format!("Deleted history item {}", e.id));
            }
            "clear" => {
                app.shared.history.lock().unwrap().clear();
                selected = None;
            }
            _ => {}
        }
    }
    app.history_sel = selected;
    ui.add_space(2.0);
    splitter(ui, &mut app.split_detail, pane_h);
    detail(app, ui);
}

/// A draggable horizontal divider: `split` is the height of the pane below it.
/// Dragging it down shrinks the table, dragging it up grows the message pane.
fn splitter(ui: &mut Ui, split: &mut f32, total: f32) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 7.0),
        egui::Sense::hover(),
    );
    let drag = ui.interact(rect, ui.id().with("splitter"), egui::Sense::drag());
    if drag.dragged() {
        let next = *split - drag.drag_delta().y;
        *split = next.clamp(90.0, (total - 140.0).max(90.0));
    }
    let active = drag.dragged() || drag.hovered();
    let y = rect.center().y;
    ui.painter().rect_filled(
        egui::Rect::from_min_size(egui::pos2(rect.left(), y - 0.5), egui::vec2(rect.width(), 1.0)),
        egui::Rounding::ZERO,
        if active { c(theme::ORANGE) } else { theme::line() },
    );
    if active {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(egui::pos2(rect.center().x - 14.0, y - 1.5), egui::vec2(28.0, 3.0)),
            egui::Rounding::same(1.5),
            c(theme::ORANGE),
        );
    }
}

fn proxy_options(app: &mut App, ui: &mut Ui) {
    // Burp: the gear tab opens Settings > Tools > Proxy (listeners, interception
    // rules, WebSockets, response modification).
    ui.label(RichText::new("Connection and listeners").color(theme::ink()).size(14.0).strong());
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Listen on").size(13.0).color(theme::ink_dim()));
        ui.add(
            egui::TextEdit::singleline(&mut app.port_txt)
                .desired_width(90.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.label(RichText::new("(127.0.0.1, default 8080)").size(12.0).color(theme::ink_faint()));
        if ui.button("Restart listener").clicked() {
            if let Ok(p) = app.port_txt.trim().parse::<u16>() {
                app.shared.proxy_port.store(p, Ordering::SeqCst);
                app.shared.listener_restart.store(true, Ordering::SeqCst);
                app.shared.log(&format!("Restarting listener on 127.0.0.1:{p}"));
            }
        }
    });
    ui.add_space(8.0);
    listeners_panel(app, ui, true);
    ui.add_space(10.0);
    // Proxy settings > WebSockets: frame interception (Burp default: off).
    ui.label(RichText::new("WebSockets").color(theme::ink()).size(14.0).strong());
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        let mut client_flag = app.shared.ws_intercept_client.load(Ordering::SeqCst);
        if ui.checkbox(&mut client_flag, "Intercept client-to-server messages").changed() {
            app.shared.ws_intercept_client.store(client_flag, Ordering::SeqCst);
        }
        let mut server_flag = app.shared.ws_intercept_server.load(Ordering::SeqCst);
        if ui.checkbox(&mut server_flag, "Intercept server-to-client messages").changed() {
            app.shared.ws_intercept_server.store(server_flag, Ordering::SeqCst);
        }
    });
    ui.add_space(10.0);
    facts(ui, &[
        ("connect timeout", "120 s (ProjectDefaults.json)"),
        ("read timeout", "120 s (ProjectDefaults.json)"),
        ("open-ended response timeout", "10 s (ProjectDefaults.json)"),
        ("history cap", "none; all session entries retained"),
        ("HTTPS", "decrypted with per-host certificates signed by the local CA"),
    ]);
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui.button("Export CA certificate").clicked() {
            match std::env::current_dir() {
                Ok(dir) => {
                    let path = dir.join("webprobe-ca.pem");
                    match std::fs::write(&path, app.shared.mitm.ca_pem()) {
                        Ok(()) => app.shared.log(&format!("CA certificate exported to {}", path.display())),
                        Err(e) => app.shared.log(&format!("CA certificate export failed: {e}")),
                    }
                }
                Err(e) => app.shared.log(&format!("CA certificate export failed: {e}")),
            }
        }
    });
    hint(ui, "For HTTPS without browser warnings, export and trust this CA in your browser or test profile. Its private key stays in memory and is never written to disk.");
    ui.add_space(10.0);
    crate::tools::upstream_options(app, ui);

    ui.add_space(8.0);
    hint(ui, "New rules are enabled with an empty pattern, like the original.");
}

fn mr_table(ui: &mut Ui, app: &mut App, request_side: bool) {
    if request_side {
        let mut rules = app.shared.mr_request.lock().unwrap();
        crate::rules_ui::rules_editor(ui, &mut rules, request_side);
    } else {
        let mut rules = app.shared.mr_response.lock().unwrap();
        crate::rules_ui::rules_editor(ui, &mut rules, request_side);
    }
}

fn facts(ui: &mut Ui, rows: &[(&str, &str)]) {
    egui::Grid::new("facts").num_columns(2).striped(true).show(ui, |ui| {
        for (k, v) in rows {
            ui.label(RichText::new(*k).size(12.5).color(theme::ink_faint()));
            ui.label(RichText::new(*v).monospace().size(12.0).color(theme::ink_dim()));
            ui.end_row();
        }
    });
}

// ================= message detail =================

/// Burp's message area under the history table: Request over Response on the
/// left, the Inspector (or Notes) panel and the vertical dock on the right.
fn detail(app: &mut App, ui: &mut Ui) {
    let entry = app
        .history_sel
        .and_then(|id| app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned());
    // Burp shows the request in origin form even when the browser sent it to
    // the proxy in absolute form.
    let req = entry.as_ref().map(|e| util::origin_form(&e.req_raw));
    let resp = entry.as_ref().and_then(|e| e.resp_raw.clone());
    let dock_w = 32.0;
    let side_w = if app.dock_sel < 2 { 330.0 } else { 0.0 };
    // egui_extras strips give each region a hard size and clip rect, so a
    // wide message never pushes the Inspector off screen.
    let mut sb = egui_extras::StripBuilder::new(ui).size(egui_extras::Size::remainder().at_least(200.0));
    if side_w > 0.0 {
        sb = sb.size(egui_extras::Size::exact(side_w));
    }
    sb.size(egui_extras::Size::exact(dock_w)).horizontal(|mut strip| {
        strip.cell(|ui| {
            let full = ui.available_height();
            egui_extras::StripBuilder::new(ui)
                .size(egui_extras::Size::relative(0.5))
                .size(egui_extras::Size::remainder())
                .vertical(|mut col| {
                    col.cell(|ui| {
                        crate::msgpane::message_pane(ui, "hist_req", "Request", req.as_deref(), &mut app.req_pane, false, full / 2.0);
                    });
                    col.cell(|ui| {
                        let r = ui.max_rect();
                        ui.painter().hline(r.x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                        crate::msgpane::message_pane(ui, "hist_resp", "Response", resp.as_deref(), &mut app.resp_pane, true, ui.available_height());
                    });
                });
        });
        if side_w > 0.0 {
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                if app.dock_sel == 0 {
                    crate::msgpane::inspector(ui, "hist_insp", req.as_deref(), resp.as_deref(), &mut app.insp_state);
                } else {
                    ui.horizontal(|ui| {
                        ui.add_space(10.0);
                        ui.label(RichText::new("Notes").strong().size(15.0).color(theme::ink()));
                    });
                    if let Some(e) = &entry {
                        let mut note = e.note.clone().unwrap_or_default();
                        let w = ui.available_width() - 16.0;
                        if ui.add(egui::TextEdit::multiline(&mut note).desired_width(w).desired_rows(12)).changed() {
                            if let Some(h) = app.shared.history.lock().unwrap().iter_mut().find(|h| h.id == e.id) {
                                h.note = if note.is_empty() { None } else { Some(note) };
                            }
                        }
                    }
                }
            });
        }
        strip.cell(|ui| {
            let r = ui.max_rect();
            ui.painter().rect_filled(r, 0.0, theme::chrome());
            ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
            if let Some(i) = crate::msgpane::side_dock(ui, app.dock_sel) {
                app.dock_sel = if app.dock_sel == i { 2 } else { i };
            }
        });
    });
}

// ================= Scanner =================

fn scan_sev_color(sev: &str) -> egui::Color32 {
    match sev {
        "high" => c(theme::BAD),
        "medium" => c(theme::ORANGE),
        "low" => c(theme::METHOD_OTHER),
        _ => theme::ink_faint(),
    }
}

/// Burp's exact severity display names (build 52685, burp.Ze1r lines 12-22:
/// "High", "Medium", "Low", "Information", "False positive").
fn scan_sev_label(sev: &str) -> &'static str {
    match sev {
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Information",
    }
}

/// Match Collaborator interactions against the tokens the active scan
/// embedded (`Shared::oob_pending`). Runs on the UI thread each frame the
/// Scanner or Dashboard view is open; raises one issue per observed
/// interaction. Burp family: SCANNER_ACTIVE_CHECKS_EXTERNAL_INTERACTION.
fn sync_oob_issues(app: &mut App) {
    let interactions = app.collab_state.interactions();
    let Ok(mut pending) = app.shared.oob_pending.lock() else { return };
    if pending.is_empty() || interactions.is_empty() {
        return;
    }
    let mut issues = Vec::new();
    for it in &interactions {
        let Some(token) = &it.token else { continue };
        let kind = it.kind().label();
        if let Some(pos) = pending.iter().position(|(t, k, _)| t == token && k.is_none_or(|k| k == kind)) {
            let (_, _, mut issue) = pending.remove(pos);
            issue.detail = format!("Collaborator interaction observed: {} (source {})", it.headline(), it.source);
            issues.push(issue);
        }
    }
    drop(pending);
    crate::scan::add_issues(&app.shared, issues);
}

fn scanner(app: &mut App, ui: &mut Ui) {
    sync_oob_issues(app);
    ui.label(RichText::new("Scanner").color(theme::ink()).size(14.0).strong());
    ui.add_space(2.0);
    hint(ui, "Every proxied response is audited live (passive checks). Select a request in the history and press Run active scan to send light active probes (URL parameters, max 30).");
    // Scan configuration: audit speed / accuracy (AuditDefaults.json keys
    // scan_speed / scan_accuracy; values from burp.Zsv7 and burp.Zgnf).
    ui.horizontal(|ui| {
        let mut speed = app.shared.scan_speed.load(Ordering::SeqCst);
        ui.label(RichText::new("Scan speed").size(12.0).color(theme::ink_dim()));
        egui::ComboBox::from_id_salt("scan_speed")
            .selected_text(["Fast", "Normal", "Thorough"][speed.min(2) as usize])
            .show_ui(ui, |ui| {
                for (i, l) in ["Fast", "Normal", "Thorough"].iter().enumerate() {
                    ui.selectable_value(&mut speed, i as u8, *l);
                }
            });
        app.shared.scan_speed.store(speed, Ordering::SeqCst);
        let mut acc = app.shared.scan_accuracy.load(Ordering::SeqCst);
        ui.label(RichText::new("Scan accuracy").size(12.0).color(theme::ink_dim()));
        let accs = ["Minimize false negatives", "Normal", "Minimize false positives"];
        egui::ComboBox::from_id_salt("scan_accuracy")
            .selected_text(accs[acc.min(2) as usize])
            .show_ui(ui, |ui| {
                for (i, l) in accs.iter().enumerate() {
                    ui.selectable_value(&mut acc, i as u8, *l);
                }
            });
        app.shared.scan_accuracy.store(acc, Ordering::SeqCst);
        ui.add_space(16.0);
        let mut extra = app.shared.extra_checks.load(Ordering::SeqCst);
        if ui
            .checkbox(&mut extra, "WebProbe extra checks")
            .on_hover_text("Also report passive checks Burp does not have (missing CSP, Referrer-Policy, version banners, ...)")
            .changed()
        {
            app.shared.extra_checks.store(extra, Ordering::SeqCst);
        }
    });
    ui.add_space(2.0);

    let busy = app.shared.scan_busy.load(Ordering::SeqCst);
    let (done, total) = (
        app.shared.scan_done.load(Ordering::SeqCst),
        app.shared.scan_total.load(Ordering::SeqCst),
    );
    ui.horizontal(|ui| {
        let btn = RichText::new(if busy { "scanning..." } else { "Run active scan on selected request" })
            .color(if busy { theme::ink_faint() } else { c(theme::ORANGE) })
            .size(13.0);
        if !busy && ui.button(btn).clicked() {
            if let Some(id) = app.history_sel {
                let e = app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned();
                if let Some(e) = e {
                    run_active_scan_on(app, &e);
                }
            } else {
                feedback::toast(feedback::Level::Warn, "Select a request in Proxy history first");
            }
        }
        if total > 0 && feedback::progress(ui, done, total, busy) {
            app.shared.scan_stop.store(true, Ordering::SeqCst);
            feedback::toast(feedback::Level::Warn, "Active scan cancelled");
        }
        ui.separator();
        let mut on = app.shared.scan_enabled.load(Ordering::SeqCst);
        if ui.checkbox(&mut on, "live passive scan of proxied traffic").changed() {
            app.shared.scan_enabled.store(on, Ordering::SeqCst);
            app.shared.log(if on { "Live passive scan: on" } else { "Live passive scan: off" });
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Clear issues").clicked() {
                app.shared.issues.lock().unwrap().clear();
            }
            ui.label(
                RichText::new(format!("{} issues", app.shared.issues.lock().unwrap().len()))
                    .size(12.0)
                    .color(theme::ink_faint()),
            );
        });
    });

    ui.add_space(6.0);
    let issues = app.shared.issues.lock().unwrap().clone();
    let table_h = if app.scan_sel.is_some() { (ui.available_height() - 220.0).max(140.0) } else { ui.available_height() - 10.0 };
    let columns = [
        table::Column::new("Severity", 78.0),
        table::Column::new("Confidence", 78.0),
        table::Column::new("Issue", 280.0),
        table::Column::new("Host", 180.0),
        table::Column::new("Path", 260.0),
    ];
    let mut selected = app.scan_sel;
    let filtered = table::filter_rows(&issues, &app.scan_table, |i| {
        format!("{} {} {} {}", i.sev, i.name, i.host, i.path)
    });
    let mut sortable: Vec<(String, String, String, scan::ScanIssue)> = filtered
        .iter()
        .map(|i| (i.sev.clone(), i.name.clone(), i.host.clone(), i.clone()))
        .collect();
    table::sort_rows(&mut sortable, &app.scan_table, |row, col| match col {
        0 => row.0.clone(),
        1 => row.3.confidence.clone(),
        2 => row.1.clone(),
        3 => row.2.clone(),
        _ => row.3.path.clone(),
    });
    let rows: Vec<scan::ScanIssue> = sortable.into_iter().map(|r| r.3).collect();
    egui::ScrollArea::vertical().max_height(table_h.max(140.0)).show(ui, |ui| {
        let row_h = theme::appearance().1.row_height();
        table::data_table(ui, "scan_issues", &columns, &rows, &mut app.scan_table, row_h, |iss, ui| {
            let row = ui
                .horizontal(|ui| {
                    let sev_text = if iss.false_positive { "False positive" } else { scan_sev_label(&iss.sev) };
                    let sev_colour = if iss.false_positive { theme::ink_faint() } else { scan_sev_color(&iss.sev) };
                    table::cell(ui, &columns[0], sev_text, Some(sev_colour), row_h);
                    table::cell(ui, &columns[1], iss.confidence.clone(), Some(theme::ink_dim()), row_h);
                    table::cell(ui, &columns[2], iss.name.clone(), Some(theme::ink_dim()), row_h);
                    table::cell(ui, &columns[3], iss.host.clone(), Some(theme::ink_dim()), row_h);
                    table::cell(ui, &columns[4], iss.path.clone(), Some(theme::ink_faint()), row_h);
                })
                .response
                .interact(egui::Sense::click());
            if row.clicked() {
                selected = Some(iss.id);
            }
        });
        if rows.is_empty() {
            if issues.is_empty() {
                feedback::empty_state(ui, "No issues yet", "Browse sites through the proxy, or run an active scan on a request.");
            } else {
                feedback::empty_state(ui, "No issues match the filter", "Clear the filter box to see every issue.");
            }
        }
    });
    app.scan_sel = selected;

    if let Some(id) = app.scan_sel {
        if let Some(issue) = issues.iter().find(|i| i.id == id) {
            ui.add_space(4.0);
            let label = if issue.false_positive { "False positive" } else { scan_sev_label(&issue.sev) };
            let colour = if issue.false_positive { theme::ink_faint() } else { scan_sev_color(&issue.sev) };
            ui.label(RichText::new(format!("{label} - {}", issue.name)).size(13.0).strong().color(colour));
            hint(ui, &format!("{} {} - {}", issue.host, issue.path, issue.detail));
            // Burp's False positive classification (build 52685, burp.Ze1r line 12).
            if ui.button(if issue.false_positive { "Unmark false positive" } else { "Mark as false positive" }).clicked() {
                if let Some(mut it) = app.shared.issues.lock().unwrap().iter_mut().find(|i| i.id == id) {
                    it.false_positive = !it.false_positive;
                }
            }
        }
    }
}

// ================= Intruder =================

/// Wrap the char range `sel` of `text` in payload markers (Burp's Add §);
/// with an empty selection a pair is inserted at the cursor.
pub(crate) fn add_marker(text: &str, sel: (usize, usize)) -> String {
    let chars: Vec<char> = text.chars().collect();
    let (a, b) = (sel.0.min(chars.len()), sel.1.min(chars.len()));
    let mut out: String = chars[..a].iter().collect();
    out.push('\u{00A7}');
    out.extend(chars[a..b].iter());
    out.push('\u{00A7}');
    out.extend(chars[b..].iter());
    out
}

/// Set the Host header of `req` to the authority of `target` (Burp's
/// "Update Host header to match target").
fn with_target_host(req: &str, target: &str) -> String {
    let auth = target.split_once("://").map(|x| x.1).unwrap_or(target).trim_end_matches('/');
    let auth = auth
        .strip_suffix(":80")
        .filter(|_| target.starts_with("http://"))
        .or_else(|| auth.strip_suffix(":443").filter(|_| target.starts_with("https://")))
        .unwrap_or(auth);
    String::from_utf8_lossy(&net::replace_or_add_header(req.as_bytes(), "Host", auth)).into_owned()
}

fn intruder(app: &mut App, ui: &mut Ui) {
    let attack = app.shared.attack.lock().unwrap().clone();
    let running = attack.running.load(Ordering::SeqCst);
    if app.intr_req.trim().is_empty() {
        // Burp's empty state (live 52685): illustration + "To get started".
        egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::relative(0.5))
            .size(egui_extras::Size::remainder())
            .horizontal(|mut strip| {
                strip.cell(|ui| {
                    ui.painter().rect_filled(ui.max_rect(), 0.0, c(0xEBF1F6));
                    ui.add_space(ui.available_height() * 0.3);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("To get started, send a request to Intruder\nfrom anywhere in WebProbe.").size(18.0).color(theme::ink()));
                        ui.add_space(14.0);
                        ui.label(RichText::new("Right-click a request in Proxy, Target, Logger or Repeater and choose Send to Intruder (Ctrl+I).").size(12.5).color(theme::ink_dim()));
                    });
                });
                strip.cell(|ui| {
                    ui.add_space(ui.available_height() * 0.3);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(theme::icon::ROCKET_LAUNCH).size(56.0).color(c(0x26649D)));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Intruder").strong().size(16.0).color(theme::ink()));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Configure automated attacks that send the same request many times, substituting specific values with predetermined payloads each time.").size(12.5).color(theme::ink_dim()));
                        ui.add_space(10.0);
                        if ui.button("Learn more").clicked() {
                            app.tab = Tab::Discover;
                        }
                    });
                });
            });
        return;
    }
    if app.intr_target.is_empty() {
        let host = util::get_header(&util::parse_http(app.intr_req.as_bytes()).headers, "Host").unwrap_or_default();
        app.intr_target = format!("{}://{host}", if app.intr_https { "https" } else { "http" });
    }

    let positions = intruder::Template::parse(&app.intr_req).map(|t| t.positions()).unwrap_or(0);
    while app.intr_sets.len() < positions.max(1) {
        app.intr_sets.push(String::new());
    }
    let needed = app.intr_attack.sets_needed(positions).max(1);
    let sets: Vec<Vec<String>> = app
        .intr_sets
        .iter()
        .take(needed)
        .map(|text| text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .collect();

    let side_w = if app.intr_dock < 3 { 400.0 } else { 0.0 };
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::remainder().at_least(400.0))
        .size(egui_extras::Size::exact(side_w))
        .size(egui_extras::Size::exact(32.0))
        .horizontal(|mut strip| {
            // ---------------- attack configuration + positions ----------------
            strip.cell(|ui| {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false)).on_hover_text(
                        "Sniper: one set, each position in turn. Battering ram: one set, all positions at once. Pitchfork: one set per position, in step. Cluster bomb: every combination.",
                    );
                    let w = (ui.available_width() - 150.0).max(160.0);
                    egui::ComboBox::from_id_salt("intr_attack_type")
                        .width(w)
                        .selected_text(app.intr_attack.label())
                        .show_ui(ui, |ui| {
                            for kind in [intruder::AttackType::Sniper, intruder::AttackType::BatteringRam, intruder::AttackType::Pitchfork, intruder::AttackType::ClusterBomb] {
                                ui.selectable_value(&mut app.intr_attack, kind, kind.label());
                            }
                        });
                    let start = egui::Button::new(
                        RichText::new(if running { format!("{} Stop attack", theme::icon::STOP_CIRCLE) } else { format!("{} Start attack", theme::icon::PLAY_CIRCLE) })
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .fill(c(theme::ORANGE_1))
                    .min_size(egui::vec2(130.0, 24.0));
                    if ui.add(start).clicked() {
                        if running {
                            attack.stop.store(true, Ordering::SeqCst);
                        } else {
                            let req = if app.intr_update_host { with_target_host(&app.intr_req, &app.intr_target) } else { app.intr_req.clone() };
                            let https = app.intr_target.starts_with("https://");
                            match net::start_attack(app.shared.clone(), req, app.intr_attack, sets.clone(), https) {
                                Ok(()) => {
                                    app.intr_results_open = true;
                                    app.intr_attack_no += 1;
                                }
                                Err(e) => feedback::toast(feedback::Level::Error, e),
                            }
                        }
                    }
                });
                ui.add_space(6.0);
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Target").size(12.5).color(theme::ink()));
                    let w = (ui.available_width() - 260.0).max(160.0);
                    ui.add(egui::TextEdit::singleline(&mut app.intr_target).desired_width(w));
                    ui.checkbox(&mut app.intr_update_host, "Update Host header to match target");
                });
                ui.add_space(6.0);
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Positions").size(12.5).color(theme::ink()));
                    ui.add_space(6.0);
                    if ui.add(egui::Button::new(RichText::new("Add \u{00A7}").strong()).min_size(egui::vec2(70.0, 20.0))).clicked() {
                        let sel = app.intr_pane.sel.unwrap_or((app.intr_req.chars().count(), app.intr_req.chars().count()));
                        app.intr_req = add_marker(&app.intr_req, sel);
                        app.intr_pane.sel = None;
                    }
                    if ui.add(egui::Button::new(RichText::new("Clear \u{00A7}").strong()).min_size(egui::vec2(80.0, 20.0))).clicked() {
                        app.intr_req = intruder::clear_markers(&app.intr_req);
                    }
                    if ui.add(egui::Button::new(RichText::new("Auto \u{00A7}").strong()).min_size(egui::vec2(76.0, 20.0))).clicked() {
                        app.intr_req = intruder::auto_mark(&app.intr_req);
                    }
                });
                ui.add_space(4.0);
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                let h = (ui.available_height() - 30.0).max(120.0);
                crate::msgpane::editable_pane(ui, "intr_req", "", &mut app.intr_req, &mut app.intr_pane, h);
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        ui.label(RichText::new(format!("Length: {}", app.intr_req.len())).size(12.0).color(theme::ink_dim()));
                        ui.label(RichText::new("|").size(12.0).color(theme::line_strong()));
                        ui.label(RichText::new(format!("{positions} payload position{}", if positions == 1 { "" } else { "s" })).size(12.0).color(theme::ink_dim()));
                    });
                });
            });
            // ---------------- Payloads / Resource pool / Settings ----------------
            strip.cell(|ui| {
                if side_w == 0.0 {
                    return;
                }
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                let title = ["Payloads", "Resource pool", "Settings"][app.intr_dock.min(2)];
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new(title).strong().size(15.0).color(theme::ink()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui.add(egui::Button::new(RichText::new(theme::icon::X).size(14.0)).frame(false)).clicked() {
                            app.intr_dock = 3;
                        }
                    });
                });
                ui.add_space(6.0);
                match app.intr_dock {
                    0 if positions == 0 => {
                        ui.add_space(ui.available_height() * 0.25);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new(theme::icon::ROCKET_LAUNCH).size(48.0).color(c(0x26649D)));
                            ui.add_space(6.0);
                            ui.label(RichText::new("Payloads").strong().size(16.0).color(theme::ink()));
                            ui.add_space(6.0);
                            ui.label(RichText::new("To get started, highlight the part of the request or target you want to replace, then click Add \u{00A7} to set a payload position.").size(12.5).color(theme::ink_dim()));
                            ui.add_space(10.0);
                            if ui.button("Close").clicked() {
                                app.intr_dock = 3;
                            }
                        });
                    }
                    0 => {
                        egui::ScrollArea::vertical().id_salt("intr_payloads").auto_shrink([false, false]).show(ui, |ui| {
                            ui.add_space(4.0);
                            let set_n = app.intr_set_sel.min(needed - 1);
                            egui::Grid::new("intr_pl").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                                ui.label(RichText::new("Payload position:").size(12.5).color(theme::ink()));
                                egui::ComboBox::from_id_salt("intr_set").selected_text(if needed == 1 && matches!(app.intr_attack, intruder::AttackType::Sniper | intruder::AttackType::BatteringRam) { "All payload positions".to_string() } else { format!("{}", set_n + 1) }).show_ui(ui, |ui| {
                                    for k in 0..needed {
                                        ui.selectable_value(&mut app.intr_set_sel, k, format!("{}", k + 1));
                                    }
                                });
                                ui.end_row();
                                ui.label(RichText::new("Payload type:").size(12.5).color(theme::ink()));
                                ui.label(RichText::new("Simple list").size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                                let count = sets.get(set_n).map(Vec::len).unwrap_or(0);
                                let lens: Vec<usize> = sets.iter().map(Vec::len).collect();
                                let reqs = intruder::count(app.intr_attack, positions, &lens).map(|n| n.to_string()).unwrap_or_else(|| "too many".into());
                                ui.label(RichText::new("Payload count:").size(12.5).color(theme::ink()));
                                ui.label(RichText::new(count.to_string()).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                                ui.label(RichText::new("Request count:").size(12.5).color(theme::ink()));
                                ui.label(RichText::new(reqs).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                            });
                            ui.add_space(10.0);
                            ui.label(RichText::new("Payload configuration").strong().size(13.0).color(theme::ink()));
                            ui.label(RichText::new("This payload type lets you configure a simple list of strings that are used as payloads.").size(12.0).color(theme::ink_dim()));
                            ui.add_space(6.0);
                            ui.horizontal_top(|ui| {
                                ui.vertical(|ui| {
                                    ui.set_width(96.0);
                                    let set = &mut app.intr_sets[set_n];
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Paste")).clicked() {
                                        app.intr_paste_pending = true;
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Load ...")).on_hover_text("Load a newline-separated file (path below)").clicked() {
                                        if let Ok(t) = std::fs::read_to_string(app.intr_load_path.trim()) {
                                            if !set.is_empty() && !set.ends_with('\n') { set.push('\n'); }
                                            set.push_str(&t);
                                        } else {
                                            feedback::toast(feedback::Level::Error, "Could not read the payload file");
                                        }
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Remove")).on_hover_text("Remove the last payload").clicked() {
                                        let mut lines: Vec<&str> = set.lines().collect();
                                        lines.pop();
                                        *set = lines.join("\n");
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Clear")).clicked() {
                                        set.clear();
                                    }
                                    if ui.add_sized([90.0, 22.0], egui::Button::new("Deduplicate")).clicked() {
                                        let mut seen = std::collections::HashSet::new();
                                        let kept: Vec<&str> = set.lines().filter(|l| seen.insert(*l)).collect();
                                        *set = kept.join("\n");
                                    }
                                });
                                let set = &mut app.intr_sets[set_n];
                                egui::Frame::none().stroke(egui::Stroke::new(1.0, theme::line())).fill(theme::surface()).show(ui, |ui| {
                                    ui.add(egui::TextEdit::multiline(set).font(egui::TextStyle::Monospace).desired_rows(8).desired_width(ui.available_width() - 8.0).frame(false));
                                });
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(100.0);
                                if ui.add_sized([90.0, 22.0], egui::Button::new("Add")).clicked() && !app.intr_add.trim().is_empty() {
                                    let set = &mut app.intr_sets[set_n];
                                    if !set.is_empty() && !set.ends_with('\n') { set.push('\n'); }
                                    set.push_str(app.intr_add.trim());
                                    app.intr_add.clear();
                                }
                                ui.add(egui::TextEdit::singleline(&mut app.intr_add).hint_text("Enter a new item").desired_width(ui.available_width() - 8.0));
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(100.0);
                                ui.add(egui::TextEdit::singleline(&mut app.intr_load_path).hint_text("File to load (Load ...)").desired_width(ui.available_width() - 8.0));
                            });
                        });
                        if app.intr_paste_pending {
                            app.intr_paste_pending = false;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                        }
                        let pasted: Option<String> = ui.input(|i| i.events.iter().find_map(|e| if let egui::Event::Paste(t) = e { Some(t.clone()) } else { None }));
                        if let Some(t) = pasted {
                            if !ui.ctx().wants_keyboard_input() {
                                let set_n = app.intr_set_sel.min(needed - 1);
                                let set = &mut app.intr_sets[set_n];
                                if !set.is_empty() && !set.ends_with('\n') { set.push('\n'); }
                                set.push_str(&t);
                            }
                        }
                    }
                    1 => {
                        ui.label(RichText::new("Requests are sent one at a time with a 50 ms pause between them (WebProbe's single default resource pool).").size(12.5).color(theme::ink_dim()));
                    }
                    _ => {
                        ui.label(RichText::new("Attack results record status code, length and timing for every request; open the results window with Start attack.").size(12.5).color(theme::ink_dim()));
                        ui.add_space(6.0);
                        if ui.button("Show last attack results").clicked() {
                            app.intr_results_open = true;
                        }
                    }
                }
            });
            // ---------------- dock ----------------
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                for (i, label) in ["Payloads", "Resource pool", "Settings"].iter().enumerate() {
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(32.0, 130.0), egui::Sense::click());
                    if app.intr_dock == i {
                        ui.painter().rect_filled(rect, 0.0, c(0xCADAF0));
                    }
                    let g = ui.painter().layout_no_wrap(label.to_string(), egui::FontId::proportional(12.5), theme::ink_dim());
                    let pos = egui::pos2(rect.center().x + g.size().y / 2.0, rect.top() + 12.0);
                    ui.painter().add(egui::epaint::TextShape::new(pos, g, theme::ink_dim()).with_angle(std::f32::consts::FRAC_PI_2));
                    ui.painter().hline(rect.x_range(), rect.bottom(), egui::Stroke::new(1.0, theme::line()));
                    if resp.clicked() {
                        app.intr_dock = if app.intr_dock == i { 3 } else { i };
                    }
                }
            });
        });

    // Burp opens each attack in its own results window.
    if app.intr_results_open {
        let mut open = true;
        let target = app.intr_target.clone();
        egui::Window::new(format!("{}. Intruder attack of {target}", app.intr_attack_no.max(1)))
            .open(&mut open)
            .default_size(egui::vec2(980.0, 640.0))
            .show(ui.ctx(), |ui| {
                let (done, total) = (attack.done.load(Ordering::SeqCst), attack.total.load(Ordering::SeqCst));
                ui.horizontal(|ui| {
                    ui.label(RichText::new(if running { format!("Attack running: {done} of {total}") } else { format!("Finished: {done} of {total} requests") }).size(12.5).color(theme::ink_dim()));
                    if running && ui.button("Pause / Stop").clicked() {
                        attack.stop.store(true, Ordering::SeqCst);
                    }
                });
                let rows: Vec<(usize, net::AttackRow)> = attack.rows.lock().unwrap().clone().into_iter().enumerate().collect();
                let cols = [
                    table::Column::new("Request", 70.0),
                    table::Column::new("Payload", 260.0),
                    table::Column::new("Status code", 90.0),
                    table::Column::new("Response received", 130.0),
                    table::Column::new("Error", 60.0),
                    table::Column::new("Length", 80.0),
                ];
                let mut st = app.intr_table.clone();
                let mut pick = None;
                let sel = app.intr_row_sel;
                table::table_body(ui, "intr_results", &cols, &rows, &mut st, 19.0, 300.0, &mut |(i, r), ui| {
                    let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                    if sel == Some(*i) {
                        ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                    }
                    let row = ui.horizontal(|ui| {
                        table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                            (0, (i + 1).to_string(), None),
                            (1, r.payload.clone(), None),
                            (2, r.status.clone(), None),
                            (3, r.ms.to_string(), None),
                            (4, if r.ok { String::new() } else { theme::icon::CHECK.to_string() }, None),
                            (5, r.len.to_string(), None),
                        ]);
                    }).response.interact(egui::Sense::click());
                    if row.clicked() {
                        pick = Some(*i);
                    }
                });
                app.intr_table = st;
                if pick.is_some() {
                    app.intr_row_sel = pick;
                }
                let chosen = app.intr_row_sel.and_then(|i| rows.get(i).map(|x| x.1.clone()));
                let h = ui.available_height().max(200.0);
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::remainder())
                    .size(egui_extras::Size::remainder())
                    .horizontal(|mut s2| {
                        s2.cell(|ui| crate::msgpane::message_pane(ui, "intr_res_req", "Request", chosen.as_ref().map(|r| r.req.as_slice()), &mut app.intr_res_req_pane, false, h));
                        s2.cell(|ui| crate::msgpane::message_pane(ui, "intr_res_resp", "Response", chosen.as_ref().and_then(|r| r.resp.as_deref()), &mut app.intr_res_resp_pane, true, h));
                    });
            });
        if !open {
            app.intr_results_open = false;
        }
    }
}

// ================= Repeater =================

fn repeater(app: &mut App, ui: &mut Ui) {
    // Burp's Repeater: a strip of numbered tabs (close cross, "+"), a toolbar
    // (orange Send, settings, Cancel, history arrows ... Target on the
    // right), then Request | Response | Inspector with the vertical dock, and
    // a status line at the bottom (live 52685 reference).
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        let names: Vec<String> = app.shared.repeaters.lock().unwrap().iter().map(|r| r.name.clone()).collect();
        let reps_len = names.len();
        let mut close: Option<usize> = None;
        for (i, name) in names.iter().enumerate() {
            let sel = app.rep_sel == i;
            let label = if name.starts_with("Rep ") { format!("{}", i + 1) } else { name.clone() };
            let frame = egui::Frame::none()
                .fill(if sel { theme::surface() } else { theme::chrome() })
                .stroke(egui::Stroke::new(1.0, theme::line()))
                .inner_margin(egui::Margin::symmetric(8.0, 3.0));
            frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.add(egui::Label::new(RichText::new(label).size(12.5).color(theme::ink())).sense(egui::Sense::click())).clicked() {
                        app.rep_sel = i;
                    }
                    if reps_len > 1
                        && ui.add(egui::Label::new(RichText::new("\u{00d7}").size(12.0).color(theme::ink_faint())).sense(egui::Sense::click())).clicked()
                    {
                        close = Some(i);
                    }
                });
            });
            if sel {
                let r = ui.min_rect();
                let _ = r;
            }
        }
        if ui.add(egui::Button::new(RichText::new("+").size(14.0)).frame(false)).on_hover_text("New tab").clicked() {
            let mut reps = app.shared.repeaters.lock().unwrap();
            let n = reps.len() + 1;
            reps.push(net::RepTab {
                name: format!("Rep {n}"),
                host: String::new(),
                port: 80,
                https: false,
                request: String::new(),
                response: None,
                result_line: String::new(),
            history: Vec::new(),
            hist_pos: 0,
            });
            app.rep_sel = n - 1;
        }
        if let Some(i) = close {
            let mut reps = app.shared.repeaters.lock().unwrap();
            reps.remove(i);
            app.rep_sel = app.rep_sel.saturating_sub(1).min(reps.len().saturating_sub(1));
        }
    });
    ui.add_space(4.0);

    let busy = app.shared.rep_busy.load(Ordering::SeqCst);
    let (target, result_line, https) = {
        let reps = app.shared.repeaters.lock().unwrap();
        let i = app.rep_sel.min(reps.len().saturating_sub(1));
        let r = &reps[i];
        let host = util::get_header(&util::parse_http(r.request.as_bytes()).headers, "Host").unwrap_or_default();
        let t = if !r.host.is_empty() {
            let scheme = if r.https { "https" } else { "http" };
            let default = if r.https { 443 } else { 80 };
            if r.port == default { format!("{scheme}://{}", r.host) } else { format!("{scheme}://{}:{}", r.host, r.port) }
        } else if !host.is_empty() {
            format!("{}://{host}", if r.https { "https" } else { "http" })
        } else {
            "Not specified".to_string()
        };
        (t, r.result_line.clone(), r.https)
    };
    ui.horizontal(|ui| {
        ui.set_height(28.0);
        let send = egui::Button::new(RichText::new("Send").strong().color(egui::Color32::WHITE))
            .fill(c(theme::ORANGE_1))
            .min_size(egui::vec2(64.0, 24.0));
        if ui.add_enabled(!busy, send).on_hover_text("Send (Ctrl+Space)").clicked() {
            repeater_send(app);
        }
        ui.menu_button(RichText::new(theme::icon::GEAR).size(15.0), |ui| {
            // Burp's Repeater settings menu (the options WebProbe implements).
            ui.checkbox(&mut app.rep_update_cl, "Update Content-Length");
        })
        .response
        .on_hover_text("Repeater settings");
        if ui.add_enabled(busy, egui::Button::new("Cancel").min_size(egui::vec2(64.0, 24.0))).clicked() {
            app.shared.rep_cancel.store(true, Ordering::SeqCst);
        }
        // Burp's per-tab request history.
        let (pos, len) = {
            let reps = app.shared.repeaters.lock().unwrap();
            let i = app.rep_sel.min(reps.len().saturating_sub(1));
            (reps[i].hist_pos, reps[i].history.len())
        };
        let back = ui.add_enabled(!busy && pos > 0 && len > 0, egui::Button::new("<")).on_hover_text("Previous request");
        let fwd = ui.add_enabled(!busy && pos + 1 < len, egui::Button::new(">")).on_hover_text("Next request");
        if back.clicked() || fwd.clicked() {
            let mut reps = app.shared.repeaters.lock().unwrap();
            let i = app.rep_sel.min(reps.len().saturating_sub(1));
            let r = &mut reps[i];
            r.hist_pos = if back.clicked() { r.hist_pos - 1 } else { r.hist_pos + 1 };
            let (req, resp, line) = r.history[r.hist_pos].clone();
            r.request = req;
            r.response = resp;
            r.result_line = line;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(6.0);
            let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(15.0)).frame(false)).on_hover_text("Help");
            let edit = ui.add(egui::Button::new(RichText::new(theme::icon::PENCIL_SIMPLE).size(15.0)).frame(false)).on_hover_text("Configure target details");
            if edit.clicked() {
                app.rep_target_edit = !app.rep_target_edit;
            }
            ui.label(RichText::new(format!("Target: {target}")).strong().size(12.5).color(theme::ink()));
        });
    });
    if app.rep_target_edit {
        let mut open = true;
        egui::Window::new("Configure target details")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                let i = app.rep_sel.min(app.shared.repeaters.lock().unwrap().len().saturating_sub(1));
                let mut reps = app.shared.repeaters.lock().unwrap();
                let r = &mut reps[i];
                egui::Grid::new("rep_target").num_columns(2).show(ui, |ui| {
                    ui.label("Host:");
                    ui.text_edit_singleline(&mut r.host);
                    ui.end_row();
                    ui.label("Port:");
                    let mut p = r.port.to_string();
                    if ui.text_edit_singleline(&mut p).changed() {
                        if let Ok(v) = p.trim().parse() {
                            r.port = v;
                        }
                    }
                    ui.end_row();
                    ui.label("");
                    let mut h = r.https;
                    if ui.checkbox(&mut h, "Use HTTPS").changed() {
                        r.https = h;
                        if r.port == 80 || r.port == 443 {
                            r.port = if h { 443 } else { 80 };
                        }
                    }
                    ui.end_row();
                });
            });
        if !open {
            app.rep_target_edit = false;
        }
    }
    let _ = https;
    let r = ui.cursor();
    ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));

    let resp = {
        let reps = app.shared.repeaters.lock().unwrap();
        let i = app.rep_sel.min(reps.len().saturating_sub(1));
        reps[i].response.clone()
    };
    let status_h = 26.0;
    let body_h = (ui.available_height() - status_h).max(120.0);
    let dock_w = 32.0;
    let side_w = if app.dock_sel < 2 { 330.0 } else { 0.0 };
    ui.allocate_ui(egui::vec2(ui.available_width(), body_h), |ui| {
        let mut sb = egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::remainder().at_least(200.0))
            .size(egui_extras::Size::remainder().at_least(200.0));
        if side_w > 0.0 {
            sb = sb.size(egui_extras::Size::exact(side_w));
        }
        sb.size(egui_extras::Size::exact(dock_w)).horizontal(|mut strip| {
            strip.cell(|ui| {
                let i = app.rep_sel.min(app.shared.repeaters.lock().unwrap().len().saturating_sub(1));
                let mut text = app.shared.repeaters.lock().unwrap()[i].request.clone();
                if crate::msgpane::editable_pane(ui, "rep_req", "Request", &mut text, &mut app.rep_req_pane, body_h) {
                    app.shared.repeaters.lock().unwrap()[i].request = text;
                }
            });
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                crate::msgpane::message_pane(ui, "rep_resp", "Response", resp.as_deref(), &mut app.rep_resp_pane, true, body_h);
            });
            if side_w > 0.0 {
                strip.cell(|ui| {
                    let r = ui.max_rect();
                    ui.painter().rect_filled(r, 0.0, theme::chrome());
                    ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                    let req = {
                        let reps = app.shared.repeaters.lock().unwrap();
                        let i = app.rep_sel.min(reps.len().saturating_sub(1));
                        reps[i].request.clone()
                    };
                    let reqb = (!req.trim().is_empty()).then(|| req.into_bytes());
                    crate::msgpane::inspector(ui, "rep_insp", reqb.as_deref(), resp.as_deref(), &mut app.insp_state);
                });
            }
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                if let Some(i) = crate::msgpane::side_dock(ui, app.dock_sel) {
                    app.dock_sel = if app.dock_sel == i { 2 } else { i };
                }
            });
        });
    });
    let r = ui.cursor();
    ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
    ui.horizontal(|ui| {
        ui.add_space(4.0);
        let line = if busy { "Waiting for response...".to_string() } else if result_line.is_empty() { "Ready".to_string() } else { result_line };
        let (left, right) = line.split_once('\t').unwrap_or((line.as_str(), ""));
        ui.label(RichText::new(left).size(12.0).color(theme::ink_dim()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new(right).size(12.0).color(theme::ink_dim()));
        });
    });
}

/// Burp's "Update Content-Length": restamp the header to the body length.
pub(crate) fn update_content_length(req: &str) -> String {
    let (head, body) = match req.find("\r\n\r\n") {
        Some(i) => (&req[..i], &req[i + 4..]),
        None => return req.to_string(),
    };
    let has_cl = head.lines().any(|l| l.to_ascii_lowercase().starts_with("content-length:"));
    if !has_cl && body.is_empty() {
        return req.to_string();
    }
    let fixed = net::replace_or_add_header(req.as_bytes(), "Content-Length", &body.len().to_string());
    String::from_utf8_lossy(&fixed).into_owned()
}

fn repeater_send(app: &mut App) {
    if app.rep_update_cl {
        let mut reps = app.shared.repeaters.lock().unwrap();
        let i = app.rep_sel.min(reps.len().saturating_sub(1));
        let fixed = update_content_length(&reps[i].request);
        reps[i].request = fixed;
    }
    let reps_len = app.shared.repeaters.lock().unwrap().len();
    let i = app.rep_sel.min(reps_len.saturating_sub(1));
    let (idx, name, request, port, https) = {
        let reps = app.shared.repeaters.lock().unwrap();
        let r = &reps[i];
        let parts = util::parse_http(r.request.as_bytes());
        let host = util::get_header(&parts.headers, "Host").unwrap_or_default();
        (i, r.name.clone(), r.request.clone(), if host.contains(':') { split_port(&host).unwrap_or(r.port) } else { r.port }, r.https)
    };
    let host = {
        let reps = app.shared.repeaters.lock().unwrap();
        let parts = util::parse_http(reps[idx].request.as_bytes());
        util::get_header(&parts.headers, "Host").unwrap_or_default()
    };
    if host.is_empty() {
        *app.shared.rep_result.lock().unwrap() = "no Host header in request".into();
        return;
    }
    let (h, p) = net::split_h_p(&host, port);
    app.shared.rep_busy.store(true, Ordering::SeqCst);
    *app.shared.rep_result.lock().unwrap() = "sending...".into();
    let sh = app.shared.clone();
    std::thread::spawn(move || {
        let t0 = std::time::Instant::now();
        let up = if https {
            net::send_tls_raw(&sh, &h, p, request.as_bytes())
        } else {
            net::send_raw(&sh, &h, p, request.as_bytes())
        };
        let ms = t0.elapsed().as_millis();
        let mut reps = sh.repeaters.lock().unwrap();
        let target = reps.iter_mut().find(|r| r.name == name);
        if let Some(r) = target {
            r.response = up.resp.clone();
            let sent_req = request.clone();
            r.result_line = match &up.resp {
                Some(resp) => {
                    // Burp's Repeater status line: "Done" ... "1,976 bytes | 21 millis".
                    let n = resp.len().to_string();
                    let mut grouped = String::new();
                    for (k, ch) in n.chars().enumerate() {
                        if k > 0 && (n.len() - k) % 3 == 0 {
                            grouped.push(',');
                        }
                        grouped.push(ch);
                    }
                    format!("Done\t{grouped} bytes | {ms} millis")
                }
                None => format!("error: {}", up.error.clone().unwrap_or_default()),
            };
            r.history.push((sent_req, r.response.clone(), r.result_line.clone()));
            r.hist_pos = r.history.len() - 1;
        }
        sh.rep_busy.store(false, Ordering::SeqCst);
        let line = reps
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.result_line.clone())
            .unwrap_or_default();
        // Burp reports the outcome in the status line only; errors still toast.
        if let Some(err) = line.strip_prefix("error: ") {
            crate::feedback::toast(crate::feedback::Level::Error, format!("Repeater failed: {err}"));
        }
        *sh.rep_result.lock().unwrap() = line;
    });
}

fn split_port(host: &str) -> Option<u16> {
    host.rsplit(':').next()?.parse().ok()
}

// ================= Decoder =================

fn decoder(app: &mut App, ui: &mut Ui) {
    use crate::decoder_ops::Op;
    // Burp's Decoder (live 52685): a stack of stages; each is a text area
    // with Text/Hex, Decode as / Encode as / Hash and Smart decode on the
    // right. Applying an operation replaces every stage below with its result.
    let stages = 1 + app.dec_chain.len();
    let mut apply: Option<(usize, Op)> = None;
    egui::ScrollArea::vertical().id_salt("decoder_stages").auto_shrink([false, false]).show(ui, |ui| {
        for k in 0..stages {
            ui.horizontal_top(|ui| {
                let w = (ui.available_width() - 230.0).max(200.0);
                let hex = if k == 0 { app.dec_editor.hex } else { app.dec_chain[k - 1].1 };
                egui::Frame::none().stroke(egui::Stroke::new(1.0, theme::line())).fill(theme::surface()).show(ui, |ui| {
                    ui.set_width(w);
                    let text: &mut String = if k == 0 { &mut app.dec_input } else { &mut app.dec_chain[k - 1].0 };
                    if hex {
                        let mut shown = util::hex_view(text.as_bytes(), 65536);
                        ui.add(egui::TextEdit::multiline(&mut shown).font(egui::TextStyle::Monospace).desired_rows(6).desired_width(w - 8.0).frame(false).interactive(false));
                    } else {
                        ui.add(egui::TextEdit::multiline(text).font(egui::TextStyle::Monospace).desired_rows(6).desired_width(w - 8.0).frame(false));
                    }
                });
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.set_width(210.0);
                    ui.horizontal(|ui| {
                        let mut h = hex;
                        if ui.radio(!h, "Text").clicked() { h = false; }
                        if ui.radio(h, "Hex").clicked() { h = true; }
                        if k == 0 { app.dec_editor.hex = h; } else { app.dec_chain[k - 1].1 = h; }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(15.0)).frame(false)).on_hover_text("Transform the data with the menus below; each result opens a new panel underneath.");
                        });
                    });
                    for (label, ops) in [
                        ("Decode as ...", vec![Op::UrlDecode, Op::HtmlDecode, Op::Base64Decode, Op::AsciiHexDecode, Op::HexDecode]),
                        ("Encode as ...", vec![Op::UrlEncode, Op::HtmlEncode, Op::Base64Encode, Op::AsciiHexEncode, Op::HexEncode]),
                        ("Hash ...", vec![Op::Md5, Op::Sha1, Op::Sha256, Op::Sha512]),
                    ] {
                        egui::ComboBox::from_id_salt((label, k)).width(200.0).selected_text(label).show_ui(ui, |ui| {
                            for op in ops {
                                if ui.selectable_label(false, op_label(op)).clicked() {
                                    apply = Some((k, op));
                                }
                            }
                        });
                    }
                    if ui.add_sized([200.0, 22.0], egui::Button::new(RichText::new("Smart decode").strong())).clicked() {
                        apply = Some((k, Op::SmartDecode));
                    }
                });
            });
            ui.add_space(8.0);
        }
    });
    if let Some((k, op)) = apply {
        let src = if k == 0 { app.dec_input.clone() } else { app.dec_chain[k - 1].0.clone() };
        let out = crate::decoder_ops::apply(op, &src).unwrap_or_else(|e| format!("<error: {e}>"));
        app.dec_chain.truncate(k);
        app.dec_chain.push((out.clone(), false));
        app.dec_output = out;
    }
}

fn op_label(op: crate::decoder_ops::Op) -> &'static str {
    use crate::decoder_ops::Op::*;
    match op {
        UrlEncode => "URL encode",
        UrlDecode => "URL decode",
        HtmlEncode => "HTML encode",
        HtmlDecode => "HTML decode",
        Base64Encode => "Base64 encode",
        Base64Decode => "Base64 decode",
        AsciiHexEncode => "ASCII hex encode",
        AsciiHexDecode => "ASCII hex decode",
        HexEncode => "Hex encode",
        HexDecode => "Hex decode",
        Rot13 => "ROT13",
        Md5 => "MD5",
        Sha1 => "SHA-1",
        Sha256 => "SHA-256",
        Sha512 => "SHA-512",
        SmartDecode => "Smart decode",
    }
}

fn dec_add(app: &mut App, label: &str, value: String) {
    app.dec_results.insert(0, (label.to_string(), value));
    if app.dec_results.len() > 20 {
        app.dec_results.truncate(20);
    }
}

fn dec_result(app: &mut App, label: &str, r: Result<String, String>) {
    dec_add(app, label, r.unwrap_or_else(|e| format!("<error: {e}>")));
}

// ================= hotkeys =================

/// Run one command from the hotkey table. Ids are Burp's own
/// (`burp.Zmcg.ZB()`), so a shortcut can be traced back to the reference build.
fn run_shortcut(app: &mut App, idx: usize) {
    use crate::shortcuts::ACTIONS;
    let Some(def) = ACTIONS.get(idx) else { return };
    match def.id {
        "send_to_repeater" => {
            if app.history_sel.is_none() {
                feedback::toast(feedback::Level::Warn, "Select a history entry first");
            }
            send_history_to_repeater(app);
        }
        "send_to_intruder" => {
            if app.history_sel.is_none() {
                feedback::toast(feedback::Level::Warn, "Select a history entry first");
            }
            send_history_to_intruder(app);
        }
        "forward_intercepted_proxy_message" => net::intercept_forward(&app.shared, false),
        "toggle_proxy_interception" => {
            let now = !app.shared.intercept_on.load(Ordering::SeqCst);
            app.shared.intercept_on.store(now, Ordering::SeqCst);
            app.shared.log(if now {
                "Interception enabled (Ctrl+T)"
            } else {
                "Interception disabled (Ctrl+T)"
            });
        }
        "issue_repeater_request" => {
            if app.tab == Tab::Repeater {
                repeater_send(app);
            } else {
                app.tab = Tab::Repeater;
            }
        }
        "switch_to_dashboard" => app.tab = Tab::Dashboard,
        "switch_to_target" => app.tab = Tab::Target,
        "switch_to_proxy" => app.tab = Tab::Proxy,
        "switch_to_intruder" => app.tab = Tab::Intruder,
        "switch_to_repeater" => app.tab = Tab::Repeater,
        "go_to_previous_tab" => cycle_tab(app, -1),
        "go_to_next_tab" => cycle_tab(app, 1),
        "open_command_palette" => {
            app.palette.open = true;
            app.palette.query.clear();
            app.palette.sel = 0;
        }
        _ => feedback::toast(
            feedback::Level::Info,
            format!("{} is not available in WebProbe yet", def.label),
        ),
    }
}

/// Burp's Ctrl+Minus / Ctrl+Equals walk the tab strip in its own order.
fn cycle_tab(app: &mut App, delta: i32) {
    let Some(pos) = TABS.iter().position(|(_, t)| *t == app.tab) else { return };
    let n = TABS.len() as i32;
    let next = (pos as i32 + delta).rem_euclid(n) as usize;
    app.tab = TABS[next].1;
}

// ============ history -> tools ============

/// A context-menu item rendered as a full-width button: closes the menu on
/// click. egui 0.29 has no Ui::menu_item in this feature set, so the context
/// menu uses this; visually close to the native menu rows.
fn menu_action(ui: &mut Ui, label: &str) -> bool {
    if ui
        .add(egui::Button::new(RichText::new(label).size(13.0)).wrap_mode(egui::TextWrapMode::Extend))
        .clicked()
    {
        ui.close_menu();
        true
    } else {
        false
    }
}

/// Run the light active scan on one history entry (shared by the scanner
/// button and the history context menu): one Collaborator payload per URL
/// parameter for the OOB family, plus two per parameter for Burp's SMTP
/// header injection check when a public Collaborator is active (Burp runs
/// that check only with Collaborator enabled, burp.Zgcg).
fn run_active_scan_on(app: &mut App, e: &net::HistEntry) {
    let parts = util::parse_http(&e.req_raw);
    let names: Vec<String> = scan::query_params(&parts.path).into_iter().map(|(n, _)| n).collect();
    let oob: Vec<(String, String, String)> = names
        .iter()
        .map(|name| {
            let p = app.collab_state.generate_payload();
            (name.clone(), p.token, p.dns_name)
        })
        .collect();
    let smtp: Vec<scan::SmtpOob> = if app.collab_state.remote_server().is_some() {
        names
            .iter()
            .map(|name| {
                let a = app.collab_state.generate_payload();
                let b = app.collab_state.generate_payload();
                scan::SmtpOob { param: name.clone(), simple: (a.token, a.dns_name), enclosed: (b.token, b.dns_name) }
            })
            .collect()
    } else {
        Vec::new()
    };
    crate::scan::start_active_scan(app.shared.clone(), e.clone(), &oob, &smtp);
    feedback::toast(feedback::Level::Info, "Active scan started");
}

/// The absolute URL of a history entry, the way the "Copy URL" menu item
/// puts it on the clipboard.
fn history_url(e: &net::HistEntry) -> String {
    let parts = util::parse_http(&e.req_raw);
    if parts.path.starts_with("http://") || parts.path.starts_with("https://") {
        return parts.path.clone();
    }
    let host = util::get_header(&parts.headers, "Host").unwrap_or_else(|| format!("{}:{}", e.host, e.port));
    format!("{}://{}{}", if e.https { "https" } else { "http" }, host, parts.path)
}

/// "Copy as curl command (bash)": a bash curl line reproducing the request.
fn curl_command_of(e: &net::HistEntry) -> String {
    let parts = util::parse_http(&e.req_raw);
    let mut cmd = format!("curl -i -s -k -X {}", parts.method);
    for (k, v) in &parts.headers {
        if k.eq_ignore_ascii_case("Connection") || k.eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        cmd.push_str(&format!(" -H '{}'{}: {}'", k, "", v.replace('\'', "'\\''")));
    }
    let body = String::from_utf8_lossy(&e.req_raw[parts.head_len.min(e.req_raw.len())..]);
    if !body.trim().is_empty() {
        cmd.push_str(&format!(" --data-raw '{}'", body.replace('\'', "'\\''")));
    }
    format!("{} '{}'", cmd, history_url(e))
}

/// Links found in a response body (href/src/action attribute values and bare
/// absolute URLs), for "Copy links in response".
fn links_in_response(e: &net::HistEntry) -> String {
    let Some(resp) = &e.resp_raw else { return String::new() };
    let rp = util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
    let mut links = Vec::new();
    for attr in ["href", "src", "action"] {
        let mut rest = body.as_ref();
        while let Some(at) = rest.find(&format!("{attr}=\"")) {
            let start = at + attr.len() + 2;
            if let Some(end) = body[start..].find('"') {
                let link = &body[start..start + end];
                if link.starts_with("http://") || link.starts_with("https://") {
                    if !links.contains(&link) {
                        links.push(link);
                    }
                }
                rest = &body[start + end + 1..];
            } else {
                break;
            }
        }
    }
    links.join("\n")
}

/// The request as Burp hands it to Repeater/Intruder: origin form, without
/// the hop-by-hop Proxy-Connection header the browser sent to the proxy.
pub(crate) fn request_for_tools(raw: &[u8]) -> String {
    let req = String::from_utf8_lossy(&util::origin_form(raw)).into_owned();
    let (head, body) = match req.find("\r\n\r\n") {
        Some(i) => (&req[..i], &req[i..]),
        None => (req.as_str(), ""),
    };
    let kept: Vec<&str> = head
        .split("\r\n")
        .filter(|l| !l.to_ascii_lowercase().starts_with("proxy-connection:"))
        .collect();
    format!("{}{}", kept.join("\r\n"), body)
}

pub fn send_history_to_repeater(app: &mut App) {
    let Some(id) = app.history_sel else { return };
    let entry = app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned();
    if let Some(e) = entry {
        let mut reps = app.shared.repeaters.lock().unwrap();
        let n = reps.len() + 1;
        reps.push(net::RepTab {
            name: format!("Rep {n}"),
            host: e.host.clone(),
            port: e.port,
            https: e.https,
            request: request_for_tools(&e.req_raw),
            // Burp opens a new Repeater tab with no response until Send.
            response: None,
            result_line: String::new(),
            history: Vec::new(),
            hist_pos: 0,
        });
        app.rep_sel = n - 1;
        app.tab = Tab::Repeater;
    }
}

pub fn send_history_to_intruder(app: &mut App) {
    let Some(id) = app.history_sel else { return };
    let entry = app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned();
    if let Some(e) = entry {
        app.intr_req = request_for_tools(&e.req_raw);
        app.intr_https = e.https;
        app.tab = Tab::Intruder;
    }
}

/// A muted one-line explanation under a heading.
fn hint(ui: &mut Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .size(12.0)
            .color(theme::ink_hint()),
    );
}

// ================= Proxy =================

/// Small inline sub-tab strip. Returns the newly selected index, if any.
pub(crate) fn sub_tabs_pub(ui: &mut Ui, labels: &[&str], current: usize) -> Option<usize> {
    sub_tabs(ui, labels, current)
}

fn sub_tabs(ui: &mut Ui, labels: &[&str], current: usize) -> Option<usize> {
    // Burp's sub-tab strip: plain labels, orange underline on the active one,
    // a rule under the whole row.
    let r = ui.horizontal(|ui| crate::msgpane::underline_tabs(ui, labels, current, 13.0));
    let rect = r.response.rect;
    ui.painter().hline(
        ui.max_rect().x_range(),
        rect.bottom(),
        egui::Stroke::new(1.0, theme::line()),
    );
    r.inner
}

fn proxy(app: &mut App, ui: &mut Ui) {
    // Burp's Proxy sub-tab row: Intercept | HTTP history | WebSockets history |
    // Match and replace | (gear) Proxy settings. The intercept toggle lives on
    // the Intercept tab, not above the row.
    if let Some(sub) = sub_tabs(
        ui,
        &["Intercept", "HTTP history", "WebSockets history", "Match and replace", "\u{E270} Proxy settings"],
        app.proxy_sub,
    ) {
        if sub == 4 {
            app.settings_help = SettingsPane::Proxy;
            app.settings_open = true;
        } else {
            app.proxy_sub = sub;
        }
    }
    ui.add_space(4.0);
    match app.proxy_sub {
        0 => proxy_intercept(app, ui),
        1 => proxy_history(app, ui),
        2 => crate::tools::websocket_history(app, ui),
        3 => proxy_match_replace(app, ui),
        _ => proxy_options(app, ui),
    }
}

fn proxy_match_replace(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("HTTP match and replace rules").color(theme::ink()).size(15.0));
    ui.add_space(4.0);
    ui.label(RichText::new("Use these settings to automatically replace parts of HTTP requests and responses passing through the Proxy.").size(12.5).color(theme::ink_faint()));
    ui.add_space(6.0);
    mr_table(ui, app, true);
    ui.add_space(6.0);
    mr_table(ui, app, false);
}

fn proxy_intercept(app: &mut App, ui: &mut Ui) {
    // Burp's Intercept tab (live 52685): toolbar [Intercept on/off] [Forward]
    // [Drop] ... [Open browser], then either the held message or the
    // "Intercept is off/on" empty state. The held item is only peeked at: it
    // stays queued (and the proxy keeps waiting) until Forward or Drop.
    let on = app.shared.intercept_on.load(Ordering::SeqCst);
    let head = {
        let q = app.shared.queue.lock().unwrap();
        q.first().map(|i| (i.id, i.host.clone(), i.port, i.edited.clone(), q.len()))
    };
    let mut forward = false;
    let mut drop = false;
    ui.horizontal(|ui| {
        ui.add_space(14.0);
        let label = format!("{}  Intercept {}", if on { theme::icon::TOGGLE_RIGHT } else { theme::icon::TOGGLE_LEFT }, if on { "on" } else { "off" });
        let b = egui::Button::new(RichText::new(label).strong().color(if on { egui::Color32::WHITE } else { theme::ink() }))
            .fill(if on { c(0x26649D) } else { theme::header_bg() })
            .min_size(egui::vec2(160.0, 22.0));
        if ui.add(b).on_hover_text("Ctrl+T").clicked() {
            app.shared.intercept_on.store(!on, Ordering::SeqCst);
        }
        ui.add_space(8.0);
        let has = head.is_some();
        if ui.add_enabled(has, egui::Button::new(RichText::new(format!("{}  Forward", theme::icon::ARROW_RIGHT)).strong()).min_size(egui::vec2(160.0, 22.0))).clicked() {
            forward = true;
        }
        ui.add_space(8.0);
        if ui.add_enabled(has, egui::Button::new(RichText::new("Drop").strong()).min_size(egui::vec2(160.0, 22.0))).clicked() {
            drop = true;
        }
        if let Some((_, _, _, _, n)) = &head {
            ui.add_space(10.0);
            ui.label(RichText::new(format!("{n} held")).size(12.5).color(theme::ink_dim()));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(10.0);
            let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false)).on_hover_text("Held messages wait here until you forward or drop them.");
            if ui.add(egui::Button::new(RichText::new(format!("{}  Open browser", theme::icon::GLOBE)).strong()).min_size(egui::vec2(140.0, 22.0))).clicked() {
                match crate::tools::launch_preconfigured_browser(&app.shared) {
                    Ok(name) => feedback::toast(feedback::Level::Success, format!("Launched {name} with the proxy preconfigured")),
                    Err(e) => feedback::toast(feedback::Level::Error, e),
                }
            }
        });
    });
    ui.add_space(8.0);

    let Some((id, host, port, edited, _)) = head else {
        ui.add_space(ui.available_height() * 0.28);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::TRAFFIC_SIGNAL).size(56.0).color(c(0x26649D)));
            ui.add_space(8.0);
            ui.label(RichText::new(if on { "Intercept is on" } else { "Intercept is off" }).strong().size(18.0).color(theme::ink()));
            ui.add_space(8.0);
            ui.label(RichText::new(if on {
                "Requests passing through the proxy will be held here so you can analyze and modify them before you forward them."
            } else {
                "If you turn Intercept on, messages between WebProbe's browser and your target servers are held here. This enables you to analyze and modify these messages, before you forward them."
            }).size(12.5).color(theme::ink_dim()));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(ui.available_width() / 2.0 - 120.0);
                if ui.button("Learn more").clicked() {
                    app.tab = Tab::Discover;
                }
                let ob = egui::Button::new(RichText::new("Open browser").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1));
                if ui.add(ob).clicked() {
                    match crate::tools::launch_preconfigured_browser(&app.shared) {
                        Ok(name) => feedback::toast(feedback::Level::Success, format!("Launched {name} with the proxy preconfigured")),
                        Err(e) => feedback::toast(feedback::Level::Error, e),
                    }
                }
            });
        });
        return;
    };
    if app.intercept_cur != Some(id) {
        app.intercept_cur = Some(id);
        app.intercept_text = edited;
    }
    ui.horizontal(|ui| {
        ui.add_space(14.0);
        let scheme = if port == 443 { "https" } else { "http" };
        ui.label(RichText::new(format!("Request to {scheme}://{host}:{port}")).strong().size(13.0).color(theme::ink()));
    });
    let h = ui.available_height();
    crate::msgpane::editable_pane(ui, "intercept_edit", "Request", &mut app.intercept_text, &mut app.intercept_pane, h);
    if forward || drop {
        if forward {
            if let Some(item) = app.shared.queue.lock().unwrap().iter_mut().find(|i| i.id == id) {
                item.edited = app.intercept_text.clone();
            }
        }
        net::intercept_forward(&app.shared, drop);
        app.shared.log(&format!("{} {host} request", if drop { "dropped" } else { "forwarded" }));
        app.intercept_cur = None;
    }
}

// ================= Listeners (A-07) =================

/// Every proxy listener with its state. The first row is the primary listener
/// (the port box in Proxy > Options); the rest are extra bind:port pairs.
/// `editable` adds the add/remove controls. A failed bind shows its error here
/// instead of a quiet status dot.
fn listeners_panel(app: &mut App, ui: &mut Ui, editable: bool) {
    ui.label(RichText::new("Listeners").size(13.0).strong().color(theme::ink()));
    ui.add_space(2.0);
    let mut remove: Option<usize> = None;
    for (i, (addr, running, error)) in net::listener_status(&app.shared).iter().enumerate() {
        ui.horizontal(|ui| {
            let (word, colour) = if *running { ("running", c(theme::GOOD)) } else { ("stopped", c(theme::BAD)) };
            ui.label(RichText::new(word).size(12.0).color(colour));
            ui.label(RichText::new(addr.as_str()).monospace().size(12.0).color(theme::ink_dim()));
            if let Some(err) = error {
                ui.label(RichText::new(err.as_str()).size(12.0).color(c(theme::BAD)));
            }
            if editable && i > 0 && ui.small_button("Remove").clicked() {
                remove = Some(i - 1);
            }
        });
    }
    if let Some(index) = remove {
        let mut specs = net::listener_specs(&app.shared);
        specs.remove(index);
        if let Err(e) = net::set_listeners(&app.shared, specs) {
            feedback::toast(feedback::Level::Error, e);
        }
    }
    if !editable {
        return;
    }

    // The draft row lives in egui's temp memory, so it needs no App field.
    let id = ui.id().with("new_listener");
    let (mut bind, mut port): (String, String) = ui
        .data_mut(|d| d.get_temp(id))
        .unwrap_or_else(|| ("127.0.0.1".to_string(), String::new()));
    ui.horizontal(|ui| {
        ui.label(RichText::new("bind").size(12.0).color(theme::ink_faint()));
        ui.add(egui::TextEdit::singleline(&mut bind).desired_width(120.0).font(egui::TextStyle::Monospace));
        ui.label(RichText::new("port").size(12.0).color(theme::ink_faint()));
        ui.add(egui::TextEdit::singleline(&mut port).desired_width(60.0).font(egui::TextStyle::Monospace));
        if ui.button("Add listener").clicked() {
            match port.trim().parse::<u16>() {
                Ok(p) => {
                    let mut specs = net::listener_specs(&app.shared);
                    specs.push(net::ListenerSpec { bind: bind.trim().to_string(), port: p });
                    match net::set_listeners(&app.shared, specs) {
                        Ok(()) => {
                            feedback::toast(
                                feedback::Level::Success,
                                format!("Listener added on {}:{p}", bind.trim()),
                            );
                            port.clear();
                        }
                        Err(e) => feedback::toast(feedback::Level::Error, e),
                    }
                }
                Err(_) => feedback::toast(feedback::Level::Error, "Port must be 1-65535"),
            }
        }
    });
    ui.data_mut(|d| d.insert_temp(id, (bind, port)));
    hint(ui, "Extra listeners keep the history and every other setting; the primary port is set above.");
}

// ================= Settings window =================

/// Which page of the Settings window is showing (Burp: Settings is its own
/// window, not a tab).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingsPane {
    Appearance,
    Hotkeys,
    Proxy,
    Sessions,
}

fn settings_window(app: &mut App, ctx: &egui::Context) {
    if !app.settings_open {
        return;
    }
    let mut open = app.settings_open;
    let mut close = false;
    egui::Window::new("Settings")
        .open(&mut open)
        .default_pos(ctx.screen_rect().center() - egui::vec2(310.0, 260.0))
        .resizable(true)
        .default_width(900.0)
        .default_height(600.0)
        .show(ctx, |ui| {
            // Burp's Settings dialog: a navigation tree on the left (User /
            // Project groups), the selected page on the right.
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(180.0);
                    for (group, items) in [
                        ("User interface", vec![("Appearance", SettingsPane::Appearance), ("Hotkeys", SettingsPane::Hotkeys)]),
                        ("Tools", vec![("Proxy", SettingsPane::Proxy)]),
                        ("Project", vec![("Sessions", SettingsPane::Sessions)]),
                    ] {
                        ui.label(RichText::new(group).strong().size(12.5).color(theme::ink()));
                        for (name, pane) in items {
                            ui.horizontal(|ui| {
                                ui.add_space(12.0);
                                if ui.selectable_label(app.settings_help == pane, name).clicked() {
                                    app.settings_help = pane;
                                }
                            });
                        }
                        ui.add_space(6.0);
                    }
                    ui.add_space(12.0);
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                });
                ui.separator();
                ui.vertical(|ui| {
                    egui::ScrollArea::vertical().id_salt("settings_page").show(ui, |ui| match app.settings_help {
                        SettingsPane::Appearance => crate::tools::appearance_options(ui),
                        SettingsPane::Hotkeys => crate::shortcuts::settings_panel(app, ui),
                        SettingsPane::Proxy => proxy_options(app, ui),
                        SettingsPane::Sessions => crate::tools::sessions(app, ui),
                    });
                });
            });
        });
    if !open || close {
        app.settings_open = false;
    }
}

/// Process memory in MB and machine memory in MB (sysinfo), refreshed at most
/// every two seconds.
fn memory_usage(app: &mut App) -> (f64, f64) {
    let now = std::time::Instant::now();
    if app.mem_at.map(|t| now.duration_since(t).as_secs_f32() > 2.0).unwrap_or(true) {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let pid = sysinfo::Pid::from_u32(std::process::id());
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        let used = sys.process(pid).map(|p| p.memory() as f64 / 1_048_576.0).unwrap_or(0.0);
        app.mem = (used, sys.total_memory() as f64 / 1_048_576.0);
        app.mem_at = Some(now);
    }
    app.mem
}

/// Burp's Event log: a window listing the application log, newest first.
fn event_log_window(app: &mut App, ctx: &egui::Context) {
    if !app.event_log_open {
        return;
    }
    let mut open = true;
    egui::Window::new("Event log")
        .open(&mut open)
        .default_size(egui::vec2(760.0, 320.0))
        .show(ctx, |ui| {
            let lines: Vec<String> = app.shared.events.lock().map(|e| e.clone()).unwrap_or_default();
            let columns = [table::Column::new("Time", 90.0), table::Column::new("Type", 70.0), table::Column::new("Source", 90.0), table::Column::new("Message", 480.0)];
            let rows: Vec<(usize, String)> = lines.into_iter().rev().enumerate().collect();
            let mut st = app.event_log_table.clone();
            table::table_body(ui, "event_log", &columns, &rows, &mut st, 18.0, ui.available_height(), &mut |(_, l), ui| {
                let (ts, msg) = l.split_once("] ").unwrap_or(("", l.as_str()));
                let time = ts.trim_start_matches('[').parse::<u64>().map(time_of_day).unwrap_or_default();
                let kind = if msg.to_ascii_lowercase().contains("fail") || msg.to_ascii_lowercase().contains("error") { "Error" } else { "Info" };
                table::cells(ui, &columns, &table::TableState::default(), 18.0, &[
                    (0, time.to_string(), None),
                    (1, kind.to_string(), None),
                    (2, "WebProbe".to_string(), None),
                    (3, msg.to_string(), None),
                ]);
            });
            app.event_log_table = st;
        });
    if !open {
        app.event_log_open = false;
    }
}

/// Burp's Search (top-right magnifier / Burp > Search) opens in its own window.
fn search_window(app: &mut App, ctx: &egui::Context) {
    if !app.search_open {
        return;
    }
    let mut open = true;
    egui::Window::new("Search")
        .open(&mut open)
        .default_size(egui::vec2(820.0, 520.0))
        .show(ctx, |ui| crate::tools::search(app, ui));
    if !open {
        app.search_open = false;
    }
}

/// Discover: WebProbe's own learning page (Burp's Discover tab slot).
fn discover(app: &mut App, ui: &mut Ui) {
    let r = ui.available_rect_before_wrap();
    let hero = egui::Rect::from_min_size(r.min, egui::vec2(r.width(), 300.0_f32.min(r.height())));
    ui.painter().rect_filled(hero, 0.0, c(0x14102A));
    ui.allocate_ui_at_rect(hero.shrink2(egui::vec2(r.width() * 0.3, 80.0)), |ui| {
        ui.label(RichText::new("WebProbe").size(44.0).strong().color(egui::Color32::WHITE));
        ui.add_space(8.0);
        ui.label(RichText::new("Intercept, replay, fuzz and audit HTTP traffic from one window.").size(18.0).color(egui::Color32::WHITE));
    });
    ui.add_space(320.0);
    ui.horizontal(|ui| {
        for (glyph, title, sub) in [
            (theme::icon::BOOK_OPEN, "Documentation", "docs/ in the repository"),
            (theme::icon::KEYBOARD, "Keyboard shortcuts", "Help > Keyboard shortcuts"),
            (theme::icon::TERMINAL, "Command palette", "Ctrl+K"),
        ] {
            ui.add_space(40.0);
            ui.label(RichText::new(glyph).size(28.0).color(theme::ink_dim()));
            ui.vertical(|ui| {
                ui.label(RichText::new(title).strong().size(13.0).color(theme::ink()));
                ui.label(RichText::new(sub).size(12.0).color(theme::ink_faint()));
            });
            ui.add_space(60.0);
        }
    });
    // The first-run setup checklist lives here, under the learning cards
    // (Burp's Dashboard has none).
    ui.add_space(16.0);
    if !app.onboarding_hidden && crate::onboarding::panel(app, ui) {}
}

// ================= Dashboard =================

fn dashboard(app: &mut App, ui: &mut Ui) {
    sync_oob_issues(app);
    // Burp's Dashboard (live 52685 reference): optional "Task execution is
    // paused" banner, a Tasks rail on the left (New scan / New live task,
    // filter + search, one card per task) and the selected task on the right
    // with Summary | Audit items | Issues | Event log | Logger | Audit log.
    let live_on = app.shared.scan_enabled.load(Ordering::SeqCst);
    if !live_on {
        let r = ui.available_rect_before_wrap();
        let band = egui::Rect::from_min_size(r.min - egui::vec2(10.0, 10.0), egui::vec2(r.width() + 20.0, 28.0));
        ui.painter().rect_filled(band, 0.0, c(0xEBF1F6));
        ui.allocate_ui_at_rect(band, |ui| {
            ui.horizontal_centered(|ui| {
                ui.add_space(band.width() / 2.0 - 120.0);
                ui.label(RichText::new("Task execution is paused").size(13.5).color(theme::ink()));
                ui.add_space(14.0);
                if ui.button(RichText::new("Resume").strong()).clicked() {
                    app.shared.scan_enabled.store(true, Ordering::SeqCst);
                }
            });
        });
        ui.add_space(22.0);
    }

    let all_issues = app.shared.issues.lock().unwrap().clone();
    let counts = |pred: &dyn Fn(&crate::scan::ScanIssue) -> bool| -> [usize; 4] {
        let mut v = [0usize; 4];
        for i in all_issues.iter().filter(|i| !i.false_positive && pred(i)) {
            v[match i.sev.as_str() { "high" => 0, "medium" => 1, "low" => 2, _ => 3 }] += 1;
        }
        v
    };
    let scan_total = app.shared.scan_total.load(Ordering::SeqCst);
    let busy = app.shared.scan_busy.load(Ordering::SeqCst);
    let has_active = scan_total > 0 || busy;
    if app.dash_task > 1 && !has_active {
        app.dash_task = 1;
    }

    let rail_w = 390.0;
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::exact(rail_w))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            // ---------------- Tasks rail ----------------
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().vline(r.right(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Tasks").strong().size(15.0).color(theme::ink()));
                    ui.add_space(8.0);
                    let orange = |t: &str| egui::Button::new(RichText::new(t).strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1)).min_size(egui::vec2(90.0, 24.0));
                    if ui.add(orange("New scan")).clicked() {
                        app.new_scan_open = true;
                    }
                    if ui.add(orange("New live task")).on_hover_text("Live audit of proxy traffic").clicked() {
                        app.shared.scan_enabled.store(true, Ordering::SeqCst);
                        app.dash_task = 1;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false)).on_hover_text("Help: see Discover > Documentation");
                        if ui.add(egui::Button::new(RichText::new(theme::icon::GEAR).size(16.0)).frame(false)).on_hover_text("Scanner settings").clicked() {
                            app.tab = Tab::Scanner;
                        }
                        let glyph = if live_on { theme::icon::PAUSE_CIRCLE } else { theme::icon::PLAY_CIRCLE };
                        if ui.add(egui::Button::new(RichText::new(glyph).size(16.0)).frame(false)).on_hover_text(if live_on { "Pause task execution" } else { "Resume task execution" }).clicked() {
                            app.shared.scan_enabled.store(!live_on, Ordering::SeqCst);
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.label(RichText::new(format!("{}  Filter", theme::icon::FUNNEL)).size(12.5).color(theme::ink_dim()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        ui.add(egui::TextEdit::singleline(&mut app.dash_search).hint_text("Search").desired_width(140.0));
                    });
                });
                ui.add_space(8.0);
                // Task cards, newest first.
                let mut cards: Vec<(usize, String, String, bool)> = Vec::new();
                if has_active {
                    let done = app.shared.scan_done.load(Ordering::SeqCst);
                    cards.push((2, "3. Active scan".into(), if busy { format!("Auditing: {done} of {scan_total} requests") } else { format!("Finished: {done} requests") }, false));
                }
                cards.push((1, "2. Live audit from Proxy (all traffic)".into(), "Audit checks - passive".into(), true));
                cards.push((0, "1. Live passive crawl from Proxy (all traffic)".into(), "Add links. Add item itself, same domain and URLs in suite scope.".into(), true));
                let q = app.dash_search.to_ascii_lowercase();
                for (id, title, sub, capturing) in cards {
                    if !q.is_empty() && !title.to_ascii_lowercase().contains(&q) {
                        continue;
                    }
                    let sel = app.dash_task == id;
                    let frame = egui::Frame::none()
                        .fill(if sel { c(0xEBF1F6) } else { theme::surface() })
                        .stroke(egui::Stroke::new(1.0, theme::line()))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                        .outer_margin(egui::Margin::symmetric(8.0, 4.0));
                    let resp = frame
                        .show(ui, |ui| {
                            ui.set_width(rail_w - 46.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&title).strong().size(13.0).color(theme::ink()));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    // Per-task pause and menu (Burp: pause/resume, view details).
                                    let flag = match id {
                                        0 => Some(&app.shared.crawl_capture),
                                        1 => Some(&app.shared.scan_enabled),
                                        _ => None,
                                    };
                                    let running = flag.map(|f| f.load(Ordering::SeqCst)).unwrap_or(busy);
                                    ui.menu_button(RichText::new(theme::icon::DOTS_THREE_VERTICAL).size(14.0), |ui| {
                                        if let Some(f) = flag {
                                            if ui.button(if running { "Pause task" } else { "Resume task" }).clicked() {
                                                f.store(!running, Ordering::SeqCst);
                                                ui.close_menu();
                                            }
                                        } else if ui.add_enabled(busy, egui::Button::new("Stop scan")).clicked() {
                                            app.shared.scan_stop.store(true, Ordering::SeqCst);
                                            ui.close_menu();
                                        }
                                        if ui.button("View details").clicked() {
                                            app.dash_task = id;
                                            ui.close_menu();
                                        }
                                    });
                                    let glyph = if running { theme::icon::PAUSE_CIRCLE } else { theme::icon::PLAY_CIRCLE };
                                    if ui.add(egui::Button::new(RichText::new(glyph).size(14.0)).frame(false)).on_hover_text(if running { "Pause" } else { "Resume" }).clicked() {
                                        match flag {
                                            Some(f) => f.store(!running, Ordering::SeqCst),
                                            None => app.shared.scan_stop.store(true, Ordering::SeqCst),
                                        }
                                    }
                                });
                            });
                            ui.add_space(4.0);
                            ui.add(egui::Label::new(RichText::new(&sub).size(12.5).color(theme::ink_dim())).wrap());
                            if capturing {
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("Capturing").size(12.5).color(theme::ink_dim()));
                                    ui.add_space(10.0);
                                    if id == 1 {
                                        let mut on = app.shared.scan_enabled.load(Ordering::SeqCst);
                                        if ui.add(crate::history_filter::toggle(&mut on)).changed() {
                                            app.shared.scan_enabled.store(on, Ordering::SeqCst);
                                        }
                                    } else {
                                        let mut on = app.shared.crawl_capture.load(Ordering::SeqCst);
                                        if ui.add(crate::history_filter::toggle(&mut on)).changed() {
                                            app.shared.crawl_capture.store(on, Ordering::SeqCst);
                                        }
                                    }
                                });
                            }
                            if id != 0 {
                                ui.add_space(4.0);
                                let v = counts(&|_| true);
                                ui.horizontal(|ui| {
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        for (k, col) in [(3, 0xB0AFAF), (2, 0x26649D), (1, 0xFF6633), (0, 0xD6213F)] {
                                            egui::Frame::none().fill(c(col)).rounding(8.0).inner_margin(egui::Margin::symmetric(9.0, 1.0)).show(ui, |ui| {
                                                ui.label(RichText::new(v[k].to_string()).size(11.5).strong().color(egui::Color32::WHITE));
                                            });
                                        }
                                        ui.label(RichText::new("Issues:").size(12.5).color(theme::ink_dim()));
                                    });
                                });
                            }
                        })
                        .response;
                    if sel {
                        let rr = resp.rect;
                        ui.painter().vline(rr.right() - 2.0, rr.y_range(), egui::Stroke::new(4.0, c(0x26649D)));
                    }
                    if resp.interact(egui::Sense::click()).clicked() {
                        app.dash_task = id;
                    }
                }
            });
            // ---------------- Selected task ----------------
            strip.cell(|ui| {
                let title = match app.dash_task {
                    0 => "1. Live passive crawl from Proxy (all traffic)",
                    2 => "3. Active scan",
                    _ => "2. Live audit from Proxy (all traffic)",
                };
                ui.horizontal(|ui| {
                    ui.add_space(14.0);
                    ui.label(RichText::new(theme::icon::CARET_LEFT).size(16.0).color(theme::ink_dim()));
                    ui.add_space(8.0);
                    ui.label(RichText::new(title).strong().size(15.0).color(theme::ink()));
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    if let Some(v) = crate::msgpane::underline_tabs(ui, &["Summary", "Audit items", "Issues", "Event log", "Logger", "Audit log"], app.dash_sub, 13.0) {
                        app.dash_sub = v;
                    }
                });
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                ui.add_space(10.0);
                match app.dash_sub {
                    0 => dashboard_summary(app, ui, &all_issues),
                    1 => {
                        let rows: Vec<net::HistEntry> = app.shared.history.lock().unwrap().iter().rev().take(2000).cloned().collect();
                        let cols = [
                            table::Column::new("#", 50.0),
                            table::Column::new("Host", 200.0),
                            table::Column::new("Method", 70.0),
                            table::Column::new("URL", 320.0),
                            table::Column::new("Status", 80.0),
                            table::Column::new("Audited", 80.0),
                        ];
                        let mut st = app.dash_items_table.clone();
                        let h = ui.available_height();
                        table::table_body(ui, "dash_items", &cols, &rows, &mut st, 19.0, h, &mut |e, ui| {
                            table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                                (0, e.id.to_string(), None),
                                (1, history_host(e), None),
                                (2, e.method.clone(), None),
                                (3, e.path.clone(), None),
                                (4, e.status.clone(), None),
                                (5, if e.audited { theme::icon::CHECK.to_string() } else { String::new() }, None),
                            ]);
                        });
                        app.dash_items_table = st;
                    }
                    2 => scanner(app, ui),
                    3 | 5 => {
                        let events: Vec<String> = app.shared.events.lock().map(|e| e.iter().rev().cloned().collect()).unwrap_or_default();
                        let filt: Vec<&String> = events.iter().filter(|e| app.dash_sub == 3 || e.contains("Scanner")).collect();
                        egui::ScrollArea::vertical().id_salt("dash_events").auto_shrink([false, false]).show(ui, |ui| {
                            if filt.is_empty() {
                                hint(ui, "Nothing logged yet.");
                            }
                            for ev in filt {
                                let (ts, msg) = ev.split_once("] ").unwrap_or(("", ev.as_str()));
                                let t = ts.trim_start_matches('[').parse::<u64>().map(history_time).unwrap_or_default();
                                ui.horizontal(|ui| {
                                    ui.add_sized([150.0, 16.0], egui::Label::new(RichText::new(t).size(12.0).color(theme::ink_faint())));
                                    ui.label(RichText::new(msg).size(12.5).color(theme::ink_dim()));
                                });
                            }
                        });
                    }
                    _ => logger_view(app, ui),
                }
            });
        });

    if app.new_scan_open {
        let mut open = true;
        egui::Window::new("New scan")
            .open(&mut open)
            .collapsible(false)
            .default_width(560.0)
            .show(ui.ctx(), |ui| {
                ui.label(RichText::new("Scan details").strong().size(14.0));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Scan type").size(12.5).color(theme::ink()));
                    ui.radio_value(&mut app.new_scan_type, 0, "Crawl and audit");
                    ui.radio_value(&mut app.new_scan_type, 1, "Audit selected items");
                });
                ui.add_space(4.0);
                ui.label(RichText::new("URLs to scan").size(12.5).color(theme::ink_dim()));
                ui.add(egui::TextEdit::multiline(&mut app.new_scan_urls).desired_rows(4).desired_width(520.0).hint_text("https://example.com/"));
                ui.add_space(6.0);
                ui.label(RichText::new("Crawl and audit follows links, robots.txt and sitemap.xml from each URL on the same origin (link depth 4, 1500 locations), then audits every item found. Audit selected items audits only the URLs listed.").size(12.0).color(theme::ink_hint()));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ok = egui::Button::new(RichText::new("OK").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1)).min_size(egui::vec2(70.0, 24.0));
                    if ui.add(ok).clicked() {
                        let urls: Vec<String> = app.new_scan_urls.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
                        start_url_scan(app, urls);
                        app.new_scan_open = false;
                        app.dash_task = 2;
                    }
                    if ui.button("Cancel").clicked() {
                        app.new_scan_open = false;
                    }
                });
            });
        if !open {
            app.new_scan_open = false;
        }
    }
}

/// Dashboard > Summary: "Most serious vulnerabilities found" plus the Task
/// configuration / progress / log cards.
fn dashboard_summary(app: &mut App, ui: &mut Ui, issues: &[crate::scan::ScanIssue]) {
    let card = |ui: &mut Ui, title: &str, glyph: &str, add: &mut dyn FnMut(&mut Ui)| {
        egui::Frame::none()
            .fill(theme::chrome())
            .rounding(4.0)
            .inner_margin(egui::Margin::same(14.0))
            .outer_margin(egui::Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(glyph).size(14.0).color(theme::ink_dim()));
                    ui.label(RichText::new(title).strong().size(13.0).color(theme::ink()));
                });
                ui.add_space(6.0);
                add(ui);
            });
    };
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::relative(0.5))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                card(ui, "Most serious vulnerabilities found (live)", theme::icon::WARNING, &mut |ui| {
                    let mut v: Vec<&crate::scan::ScanIssue> = issues.iter().filter(|i| !i.false_positive).collect();
                    let rank = |s: &str| match s { "high" => 0, "medium" => 1, "low" => 2, _ => 3 };
                    v.sort_by_key(|i| (rank(&i.sev), std::cmp::Reverse(i.ts)));
                    egui::Frame::none().stroke(egui::Stroke::new(1.0, theme::line())).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.set_min_height((ui.available_height() - 20.0).max(200.0));
                        egui::Grid::new("dash_top").num_columns(3).striped(true).min_col_width(80.0).show(ui, |ui| {
                            for h in ["Issue type", "Host", "Time"] {
                                ui.label(RichText::new(h).size(12.5).color(theme::ink()));
                            }
                            ui.end_row();
                            for i in v.iter().take(30) {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("\u{25CF}").size(10.0).color(theme::issue_colour(&i.sev)));
                                    ui.label(RichText::new(&i.name).size(12.5).color(theme::ink_dim()));
                                });
                                ui.label(RichText::new(&i.host).size(12.5).color(theme::ink_dim()));
                                ui.label(RichText::new(if i.ts > 0 { time_of_day(i.ts) } else { String::new() }).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                            }
                        });
                        if v.is_empty() {
                            ui.add_space(60.0);
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new("No issues to show").strong().size(16.0).color(theme::ink()));
                                ui.add_space(8.0);
                                ui.label(RichText::new("Any issues found during the audit will be displayed here.").size(12.5).color(theme::ink_dim()));
                            });
                        }
                    });
                });
            });
            strip.cell(|ui| {
                let live = app.shared.scan_enabled.load(Ordering::SeqCst);
                card(ui, "Task configuration", theme::icon::GEAR, &mut |ui| {
                    egui::Grid::new("dash_cfg").num_columns(2).spacing([40.0, 8.0]).show(ui, |ui| {
                        for (k, v) in [("Task type:", "Live audit"), ("Scope:", "Proxy (all traffic)"), ("Configuration:", "Audit checks - passive")] {
                            ui.label(RichText::new(k).strong().size(12.5).color(theme::ink()));
                            ui.label(RichText::new(v).size(12.5).color(theme::ink_dim()));
                            ui.end_row();
                        }
                        ui.label(RichText::new("Capturing").strong().size(12.5).color(theme::ink()));
                        let mut on = live;
                        if ui.add(crate::history_filter::toggle(&mut on)).changed() {
                            app.shared.scan_enabled.store(on, Ordering::SeqCst);
                        }
                        ui.end_row();
                    });
                });
                let total = app.shared.history.lock().map(|h| h.len()).unwrap_or(0);
                let (done, all, busy) = (
                    app.shared.scan_done.load(Ordering::SeqCst),
                    app.shared.scan_total.load(Ordering::SeqCst),
                    app.shared.scan_busy.load(Ordering::SeqCst),
                );
                let msgs = app.shared.messages.load(Ordering::SeqCst);
                let (audited, net_errors) = {
                    let h = app.shared.history.lock().unwrap();
                    (h.iter().filter(|e| e.audited).count(), h.iter().filter(|e| e.resp_raw.is_none()).count())
                };
                card(ui, "Task progress", theme::icon::CLOCK, &mut |ui| {
                    egui::Grid::new("dash_prog").num_columns(4).spacing([30.0, 8.0]).show(ui, |ui| {
                        let row = |ui: &mut Ui, a: &str, av: String, b: &str, bv: String| {
                            ui.label(RichText::new(a).strong().size(12.5).color(theme::ink()));
                            ui.label(RichText::new(av).size(12.5).color(theme::ink_dim()));
                            ui.label(RichText::new(b).strong().size(12.5).color(theme::ink()));
                            ui.label(RichText::new(bv).size(12.5).color(theme::ink_dim()));
                            ui.end_row();
                        };
                        let _ = total;
                        row(ui, "Total audit items:", audited.to_string(), "Requests:", (msgs + done).to_string());
                        row(ui, "Audit items pending:", if busy { (all.saturating_sub(done)).to_string() } else { "0".into() }, "Network errors:", net_errors.to_string());
                        row(ui, "Audit items in progress:", if busy { "1".into() } else { "0".into() }, "", String::new());
                        row(ui, "Audit items completed:", audited.to_string(), "", String::new());
                    });
                });
                card(ui, "Task log", theme::icon::CLOCK, &mut |ui| {
                    let events: Vec<String> = app.shared.events.lock().map(|e| e.iter().rev().take(8).cloned().collect()).unwrap_or_default();
                    for ev in events {
                        let msg = ev.split_once("] ").map(|x| x.1.to_string()).unwrap_or(ev);
                        ui.label(RichText::new(msg).size(12.0).color(theme::ink_dim()));
                    }
                });
            });
        });
}

/// Dashboard > New scan: fetch each URL once and run the active audit on it,
/// one after the other (Burp: "Audit" scan type over the listed URLs).
fn start_url_scan(app: &mut App, urls: Vec<String>) {
    let shared = app.shared.clone();
    let audit_only = app.new_scan_type == 1;
    shared.scan_stop.store(false, Ordering::SeqCst);
    std::thread::spawn(move || crate::scan::crawl_and_audit(&shared, &urls, audit_only));
}

// ================= Target =================

/// One node of the site map tree.
#[derive(Default)]
struct MapNode {
    children: std::collections::BTreeMap<String, MapNode>,
    requested: bool,
}

impl MapNode {
    fn insert(&mut self, segs: &[&str], requested: bool) {
        let mut node = self;
        for seg in segs {
            node = node.children.entry(seg.to_string()).or_default();
        }
        node.requested |= requested;
    }
    fn any_requested(&self) -> bool {
        self.requested || self.children.values().any(|c| c.any_requested())
    }
}

fn path_segments(path: &str) -> Vec<String> {
    let (p, q) = match path.split_once('?') { Some((p, q)) => (p, Some(q)), None => (path, None) };
    let mut v: Vec<String> = Vec::new();
    let trimmed = p.trim_start_matches('/');
    if !trimmed.is_empty() {
        let parts: Vec<&str> = trimmed.split('/').collect();
        for (i, seg) in parts.iter().enumerate() {
            if seg.is_empty() {
                continue;
            }
            // Folders keep their trailing slash, as Burp's tree shows them.
            if i + 1 < parts.len() { v.push(format!("{seg}/")) } else { v.push(seg.to_string()) }
        }
    }
    if let Some(q) = q {
        let last = v.pop().unwrap_or_default();
        v.push(format!("{last}?{q}"));
    }
    v
}

fn target(app: &mut App, ui: &mut Ui) {
    // Burp's Target: Site map | Scope | Issues (live 52685 reference).
    if let Some(v) = sub_tabs(ui, &["Site map", "Scope", "Issues"], app.target_sub) {
        app.target_sub = v;
    }
    ui.add_space(6.0);
    match app.target_sub {
        1 => {
            egui::ScrollArea::vertical().id_salt("scope_page").show(ui, |ui| crate::tools::scope_editor(app, ui));
            return;
        }
        2 => {
            scanner(app, ui);
            return;
        }
        _ => {}
    }
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (i, label) in ["URL view", "Crawl paths view"].iter().enumerate() {
            let sel = app.target_view == i;
            let b = egui::Button::new(RichText::new(*label).size(12.0).color(if sel { egui::Color32::WHITE } else { theme::ink() }))
                .fill(if sel { c(0x26649D) } else { theme::header_bg() })
                .rounding(2.0);
            if ui.add(b).clicked() {
                app.target_view = i;
            }
        }
    });
    ui.add_space(6.0);

    let mut entries: Vec<net::HistEntry> = app.shared.history.lock().unwrap().clone();
    // Crawler requests are site-map contents too (Burp keeps them out of
    // Proxy history but in the site map).
    entries.extend(app.shared.crawl_items.lock().unwrap().iter().cloned());
    let links: Vec<(String, String)> = app.shared.site_links.lock().unwrap().iter().cloned().collect();
    if entries.is_empty() && links.is_empty() {
        ui.add_space(ui.available_height() * 0.25);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::TREE_STRUCTURE).size(56.0).color(c(0x26649D)));
            ui.add_space(8.0);
            ui.label(RichText::new("Site map URL view is empty").strong().size(18.0).color(theme::ink()));
            ui.add_space(8.0);
            ui.label(RichText::new("The site map displays information about the contents of your target applications, along with any issues that have been discovered. The URL view shows your targets as a tree of URLs, organized hierarchically by domain and directory. To populate the URL view, run a scan or browse using WebProbe's browser.").size(12.5).color(theme::ink_dim()));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(ui.available_width() / 2.0 - 110.0);
                if ui.button("Learn more").clicked() {
                    app.tab = Tab::Discover;
                }
                let open = egui::Button::new(RichText::new("Open browser").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1));
                if ui.add(open).clicked() {
                    match crate::tools::launch_preconfigured_browser(&app.shared) {
                        Ok(name) => feedback::toast(feedback::Level::Success, format!("Launched {name} with the proxy preconfigured")),
                        Err(e) => feedback::toast(feedback::Level::Error, e),
                    }
                }
            });
        });
        return;
    }

    // Build the tree: requested items from the history, unrequested ones from
    // the live passive crawl (shown grey, as in Burp).
    let mut roots: std::collections::BTreeMap<String, MapNode> = std::collections::BTreeMap::new();
    for e in &entries {
        let segs = path_segments(&e.path);
        let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
        let root = roots.entry(history_host(e)).or_default();
        if refs.is_empty() { root.requested = true; } else { root.insert(&refs, true); }
    }
    if app.target_view == 0 {
        for (origin, path) in &links {
            let segs = path_segments(path);
            let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
            roots.entry(origin.clone()).or_default().insert(&refs, false);
        }
    }

    let tree_w = 330.0;
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::exact(tree_w))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().vline(r.right(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                egui::ScrollArea::both().id_salt("site_tree").auto_shrink([false, false]).show(ui, |ui| {
                    // Swing-tree density: ~18 px rows.
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.spacing_mut().interact_size.y = 18.0;
                    if app.target_view == 1 {
                        ui.label(RichText::new("Crawl paths (links found by the live passive crawl)").size(12.0).color(theme::ink_hint()));
                        for (origin, path) in &links {
                            let label = format!("{origin}{path}");
                            let sel = app.target_node.as_ref() == Some(&(origin.clone(), path.clone()));
                            if ui.selectable_label(sel, RichText::new(label).size(12.5).color(theme::ink_faint())).clicked() {
                                app.target_node = Some((origin.clone(), path.clone()));
                            }
                        }
                        return;
                    }
                    fn draw(ui: &mut Ui, app: &mut App, origin: &str, prefix: &str, name: &str, node: &MapNode, depth: usize) {
                        let full = format!("{prefix}{name}");
                        let sel = app.target_node.as_ref().map(|(o, p)| o == origin && p == &full).unwrap_or(false);
                        let colour = if node.any_requested() { theme::ink() } else { theme::ink_hint() };
                        let icon = if node.children.is_empty() { theme::icon::FILE } else { theme::icon::FOLDER };
                        let text = RichText::new(format!("{icon} {}", if depth == 0 { origin } else { name })).size(12.5).color(colour);
                        if node.children.is_empty() {
                            ui.horizontal(|ui| {
                                ui.add_space(18.0);
                                if ui.selectable_label(sel, text).clicked() {
                                    app.target_node = Some((origin.to_string(), full.clone()));
                                }
                            });
                        } else {
                            let id = ui.make_persistent_id(("site", origin, &full));
                            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, depth == 0)
                                .show_header(ui, |ui| {
                                    if ui.selectable_label(sel, text).clicked() {
                                        app.target_node = Some((origin.to_string(), full.clone()));
                                    }
                                })
                                .body(|ui| {
                                    for (child, n) in &node.children {
                                        draw(ui, app, origin, &full, child, n, depth + 1);
                                    }
                                });
                        }
                    }
                    for (origin, node) in &roots {
                        draw(ui, app, origin, "/", "", node, 0);
                    }
                });
            });
            strip.cell(|ui| {
                let (origin, prefix) = app.target_node.clone().unwrap_or_default();
                let rows: Vec<net::HistEntry> = entries
                    .iter()
                    .filter(|e| origin.is_empty() || (history_host(e) == origin && e.path.starts_with(&prefix)))
                    .cloned()
                    .collect();
                let full_h = ui.available_height();
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::relative(0.45))
                    .size(egui_extras::Size::remainder())
                    .vertical(|mut col| {
                        col.cell(|ui| {
                            let cols = [
                                table::Column::new("Host", 170.0),
                                table::Column::new("Method", 56.0),
                                table::Column::new("URL", 260.0),
                                table::Column::new("Params", 54.0),
                                table::Column::new("Status code", 80.0),
                                table::Column::new("Length", 60.0),
                                table::Column::new("MIME type", 70.0),
                                table::Column::new("Title", 160.0),
                            ];
                            let mut st = app.target_table.clone();
                            let mut pick = None;
                            let h = ui.available_height();
                            let sel = app.target_entry;
                            table::table_body(ui, "site_contents", &cols, &rows, &mut st, 19.0, h, &mut |e, ui| {
                                let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                                if sel == Some(e.id) {
                                    ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                                }
                                let row = ui.horizontal(|ui| {
                                    table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                                        (0, history_host(e), None),
                                        (1, e.method.clone(), None),
                                        (2, e.path.clone(), None),
                                        (3, if e.params { theme::icon::CHECK.to_string() } else { String::new() }, None),
                                        (4, e.status.clone(), None),
                                        (5, e.resp_len.to_string(), None),
                                        (6, crate::history_filter::HistoryFilter::burp_mime_of(e).to_string(), None),
                                        (7, e.title.clone(), None),
                                    ]);
                                }).response.interact(egui::Sense::click());
                                if row.clicked() {
                                    pick = Some(e.id);
                                }
                            });
                            app.target_table = st;
                            if pick.is_some() {
                                app.target_entry = pick;
                            }
                        });
                        col.cell(|ui| {
                            let e = app.target_entry.and_then(|id| entries.iter().find(|e| e.id == id).cloned());
                            let req = e.as_ref().map(|e| util::origin_form(&e.req_raw));
                            let resp = e.as_ref().and_then(|e| e.resp_raw.clone());
                            let h = ui.available_height().max(full_h * 0.5);
                            egui_extras::StripBuilder::new(ui)
                                .size(egui_extras::Size::remainder())
                                .size(egui_extras::Size::remainder())
                                .horizontal(|mut s2| {
                                    s2.cell(|ui| crate::msgpane::message_pane(ui, "site_req", "Request", req.as_deref(), &mut app.site_req_pane, false, h));
                                    s2.cell(|ui| {
                                        let r = ui.max_rect();
                                        ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                                        crate::msgpane::message_pane(ui, "site_resp", "Response", resp.as_deref(), &mut app.site_resp_pane, true, h)
                                    });
                                });
                        });
                    });
            });
        });
}

// ================= Comparer =================

/// The two-sided editor and the exact line diff live in `analysis_ui`; this only
/// supplies the selected history entry for its "selected request/response" buttons.
fn comparer(app: &mut App, ui: &mut Ui) {
    // Burp's Comparer (live 52685): one item list shown twice ("Select item
    // 1" / "Select item 2"), Paste / Load / Remove / Clear on the right, and
    // "Compare ... Words / Bytes" opening a comparison window.
    ui.horizontal(|ui| {
        ui.add_space(4.0);
        ui.label(RichText::new("Comparer").strong().size(15.0).color(theme::ink()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false)).on_hover_text("Help: see Discover > Documentation");
        });
    });
    ui.label(RichText::new("This function lets you do a word- or byte-level comparison between different data. You can load, paste, or send data here from other tools and then select the comparison you want to perform.").size(12.5).color(theme::ink_dim()));
    ui.add_space(8.0);
    let items = app.cmp_items.clone();
    let cols = [table::Column::new("#", 70.0), table::Column::new("Length", 70.0), table::Column::new("Data", 900.0)];
    let full_h = ui.available_height();
    let btn_w = 96.0;
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::remainder())
        .size(egui_extras::Size::exact(btn_w + 12.0))
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                for (k, label) in ["Select item 1:", "Select item 2:"].iter().enumerate() {
                    ui.label(RichText::new(*label).size(12.5).color(theme::ink()));
                    let mut st = if k == 0 { app.cmp_table1.clone() } else { app.cmp_table2.clone() };
                    let sel = if k == 0 { app.cmp_sel1 } else { app.cmp_sel2 };
                    let mut pick = None;
                    let rows: Vec<(usize, String)> = items.iter().cloned().enumerate().collect();
                    let h = (full_h / 2.0 - 70.0).max(100.0);
                    ui.allocate_ui(egui::vec2(ui.available_width(), h + 28.0), |ui| {
                        table::table_body(ui, if k == 0 { "cmp1" } else { "cmp2" }, &cols, &rows, &mut st, 19.0, h, &mut |(i, d), ui| {
                            let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                            if sel == Some(*i) {
                                ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                            }
                            let preview: String = d.chars().take(200).map(|c| if c.is_control() { ' ' } else { c }).collect();
                            let row = ui.horizontal(|ui| {
                                table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                                    (0, (i + 1).to_string(), None),
                                    (1, d.len().to_string(), None),
                                    (2, preview, None),
                                ]);
                            }).response.interact(egui::Sense::click());
                            if row.clicked() {
                                pick = Some(*i);
                            }
                        });
                    });
                    if k == 0 {
                        app.cmp_table1 = st;
                        if pick.is_some() { app.cmp_sel1 = pick; }
                    } else {
                        app.cmp_table2 = st;
                        if pick.is_some() { app.cmp_sel2 = pick; }
                    }
                    ui.add_space(8.0);
                }
            });
            strip.cell(|ui| {
                ui.add_space(26.0);
                let b = |ui: &mut Ui, t: &str| ui.add_sized([btn_w, 22.0], egui::Button::new(RichText::new(t).strong())).clicked();
                if b(ui, "Paste") {
                    app.cmp_paste_pending = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
                if b(ui, "Load") {
                    if let Ok(t) = std::fs::read(app.cmp_load_path.trim()) {
                        app.cmp_items.push(String::from_utf8_lossy(&t).into_owned());
                    } else {
                        feedback::toast(feedback::Level::Error, "Could not read the file named below");
                    }
                }
                ui.add(egui::TextEdit::singleline(&mut app.cmp_load_path).hint_text("file path").desired_width(btn_w));
                if b(ui, "Remove") {
                    if let Some(i) = app.cmp_sel1.or(app.cmp_sel2) {
                        if i < app.cmp_items.len() {
                            app.cmp_items.remove(i);
                        }
                        app.cmp_sel1 = None;
                        app.cmp_sel2 = None;
                    }
                }
                if b(ui, "Clear") {
                    app.cmp_items.clear();
                    app.cmp_sel1 = None;
                    app.cmp_sel2 = None;
                }
                ui.add_space((ui.available_height() - 80.0).max(10.0));
                ui.label(RichText::new("Compare ...").size(12.5).color(theme::ink()));
                let ready = app.cmp_sel1.is_some() && app.cmp_sel2.is_some();
                for (label, bytes) in [("Words", false), ("Bytes", true)] {
                    if ui.add_enabled(ready, egui::Button::new(RichText::new(label).strong()).min_size(egui::vec2(btn_w, 22.0))).clicked() {
                        let (a, b) = (app.cmp_sel1.unwrap(), app.cmp_sel2.unwrap());
                        app.comparer_state.left = app.cmp_items.get(a).cloned().unwrap_or_default();
                        app.comparer_state.right = app.cmp_items.get(b).cloned().unwrap_or_default();
                        app.comparer_state.recompute();
                        app.cmp_window = Some((a, b, bytes));
                    }
                }
            });
        });
    if app.cmp_paste_pending {
        let pasted: Option<String> = ui.input(|i| i.events.iter().find_map(|e| if let egui::Event::Paste(t) = e { Some(t.clone()) } else { None }));
        if let Some(t) = pasted {
            app.cmp_items.push(t);
            app.cmp_paste_pending = false;
        }
    }
    if let Some((a, b, bytes)) = app.cmp_window {
        let mut open = true;
        let st = &app.comparer_state;
        let diffs = st.added + st.removed;
        egui::Window::new(format!("{} compare of #{} and #{} ({} differences)", if bytes { "Byte" } else { "Word" }, a + 1, b + 1, diffs))
            .open(&mut open)
            .default_size(egui::vec2(1000.0, 620.0))
            .show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Key:").size(12.5));
                    for (name, col) in [("Modified", 0x9FBBD4), ("Deleted", 0xEE95A1), ("Added", 0x9BCF88)] {
                        egui::Frame::none().fill(c(col)).inner_margin(egui::Margin::symmetric(6.0, 1.0)).show(ui, |ui| {
                            ui.label(RichText::new(name).size(12.0).color(egui::Color32::BLACK));
                        });
                    }
                });
                ui.add_space(6.0);
                ui.columns(2, |cols2| {
                    for (side, col) in cols2.iter_mut().enumerate() {
                        col.label(RichText::new(format!("#{}  Length: {}", if side == 0 { a + 1 } else { b + 1 }, if side == 0 { st.left.len() } else { st.right.len() })).size(12.5).strong());
                        egui::ScrollArea::both().id_salt(("cmpw", side)).auto_shrink([false, false]).show(col, |ui| {
                            for r in &st.rows {
                                let present = if side == 0 { r.left_line.is_some() } else { r.right_line.is_some() };
                                if !present {
                                    continue;
                                }
                                let bg = match (r.kind, side) {
                                    (crate::analysis::DiffKind::Removed, 0) => Some(c(0xEE95A1)),
                                    (crate::analysis::DiffKind::Added, 1) => Some(c(0x9BCF88)),
                                    (crate::analysis::DiffKind::Changed, _) => Some(c(0x9FBBD4)),
                                    _ => None,
                                };
                                let text = if bytes { util::hex_view(r.text.as_bytes(), 4096) } else { r.text.clone() };
                                let mut rt = RichText::new(text).monospace().size(12.5).color(theme::editor_colours().text);
                                if let Some(bg) = bg {
                                    rt = rt.background_color(bg).color(egui::Color32::BLACK);
                                }
                                ui.label(rt);
                            }
                        });
                    }
                });
            });
        if !open {
            app.cmp_window = None;
        }
    }
}

// ================= Burp AI =================

/// Burp's AI tab slot (build 52685 `burp.Zg4s.ZF` case 7, "Burp AI"). Burp's
/// assistant runs on PortSwigger's cloud; WebProbe AI chats with a
/// user-configured OpenAI-compatible endpoint (ai.rs). Verified against a live
/// model by `ai::tests::live_model_explains_an_exchange`.
fn burp_ai(app: &mut App, ui: &mut Ui) {
    // WebProbe AI: Burp's AI assistant slot, backed by an OpenAI-compatible
    // chat endpoint you configure (nothing is sent until one is set).
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{}  WebProbe AI", theme::icon::LIGHTNING)).strong().size(15.0).color(theme::ink()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("New chat").clicked() {
                app.ai.messages.lock().unwrap().clear();
            }
        });
    });
    ui.add_space(4.0);
    egui::CollapsingHeader::new(RichText::new("Model endpoint").size(12.5))
        .default_open(!app.ai.configured())
        .show(ui, |ui| {
            egui::Grid::new("ai_cfg").num_columns(2).show(ui, |ui| {
                ui.label("Endpoint (OpenAI-compatible):");
                ui.add(egui::TextEdit::singleline(&mut app.ai.endpoint).hint_text("http://127.0.0.1:8080").desired_width(360.0));
                ui.end_row();
                ui.label("Model:");
                ui.add(egui::TextEdit::singleline(&mut app.ai.model).desired_width(360.0));
                ui.end_row();
                ui.label("API key:");
                ui.add(egui::TextEdit::singleline(&mut app.ai.api_key).password(true).desired_width(360.0));
                ui.end_row();
            });
            hint(ui, "Requests and responses you send to WebProbe AI are transmitted to this endpoint. Use a local model server to keep traffic on your machine.");
        });
    ui.add_space(6.0);
    let msgs = app.ai.messages.lock().unwrap().clone();
    let busy = app.ai.busy.load(Ordering::SeqCst);
    let h = (ui.available_height() - 90.0).max(120.0);
    egui::ScrollArea::vertical().id_salt("ai_chat").max_height(h).auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
        if msgs.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("Ask about a request, or right-click any history item and choose Send to WebProbe AI.").size(12.5).color(theme::ink_dim()));
            });
        }
        for m in &msgs {
            let mine = m.role == "user";
            egui::Frame::none()
                .fill(if mine { c(0xEBF1F6) } else { theme::chrome() })
                .rounding(6.0)
                .inner_margin(egui::Margin::same(8.0))
                .outer_margin(egui::Margin::symmetric(4.0, 3.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(if mine { "You" } else { "WebProbe AI" }).strong().size(12.0).color(theme::ink()));
                    ui.add(egui::Label::new(RichText::new(&m.text).size(12.5).color(theme::ink_dim())).wrap());
                });
        }
        if busy {
            ui.label(RichText::new("Thinking...").italics().size(12.5).color(theme::ink_hint()));
        }
    });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 90.0).max(200.0);
        let r = ui.add(egui::TextEdit::multiline(&mut app.ai.input).desired_rows(3).desired_width(w).hint_text("Ask WebProbe AI"));
        let enter = r.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter) && i.modifiers.ctrl);
        let can = app.ai.configured() && !busy;
        if (ui.add_enabled(can, egui::Button::new(RichText::new("Send").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1)).min_size(egui::vec2(70.0, 26.0)))
            .on_disabled_hover_text("Set the model endpoint first")
            .clicked()
            || (enter && can))
        {
            let text = std::mem::take(&mut app.ai.input);
            app.ai.send(app.shared.clone(), text);
        }
    });
}

// ================= Logger =================

/// Burp-style HTTP Logger view over the bounded `logger` engine. The tab name
/// is jar-grounded: build 52685 `burp.Zi96` addTab("Logger", ...) (Zi96.java:16).
fn logger_view(app: &mut App, ui: &mut Ui) {
    // Burp's Logger (live 52685): a capture-filter bar with the "Logging on"
    // switch, then the log table and the message panes.
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 330.0).max(200.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 20.0), egui::Sense::hover());
        ui.painter().rect(rect, 2.0, theme::header_bg(), egui::Stroke::new(1.0, theme::line()));
        ui.painter().with_clip_rect(rect.shrink(2.0)).text(
            egui::pos2(rect.left() + 8.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            format!("{}  Capture filter: Logger memory limit set to {} entries | Capturing requests and responses in full", theme::icon::FUNNEL, app.logger.cap),
            egui::FontId::proportional(12.5),
            theme::ink_dim(),
        );
        ui.add_space(8.0);
        ui.add(egui::TextEdit::singleline(&mut app.log_filter.text).hint_text("Search").desired_width(180.0));
        ui.add_space(6.0);
        ui.add(crate::history_filter::toggle(&mut app.log_on));
        ui.label(RichText::new("Logging on").size(12.5).color(theme::ink_dim()));
        if ui.add(egui::Button::new(RichText::new(theme::icon::TRASH).size(14.0)).frame(false)).on_hover_text("Clear log").clicked() {
            app.logger.clear();
            app.log_sel = None;
        }
    });
    ui.add_space(6.0);
    let rows: Vec<crate::logger::LogEntry> = app.logger.filter(&app.log_filter).into_iter().rev().cloned().collect();
    if rows.is_empty() {
        ui.add_space(ui.available_height() * 0.25);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::LIST_BULLETS).size(52.0).color(c(0x26649D)));
            ui.add_space(6.0);
            ui.label(RichText::new("Logger is empty").strong().size(16.0).color(theme::ink()));
            ui.add_space(6.0);
            ui.label(RichText::new("Logger displays the history of all HTTP traffic sent between WebProbe's tools and your target applications.").size(12.5).color(theme::ink_dim()));
        });
        return;
    }
    let cols = [
        table::Column::new("#", 50.0),
        table::Column::new("Time", 150.0),
        table::Column::new("Tool", 70.0),
        table::Column::new("Method", 60.0),
        table::Column::new("Host", 170.0),
        table::Column::new("Path", 240.0),
        table::Column::new("Status code", 80.0),
        table::Column::new("Length", 70.0),
        table::Column::new("MIME type", 90.0),
    ];
    let full = ui.available_height();
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::relative(0.45))
        .size(egui_extras::Size::remainder())
        .vertical(|mut col| {
            col.cell(|ui| {
                let mut st = app.log_table.clone();
                let mut pick = None;
                let sel = app.log_sel;
                let h = ui.available_height();
                table::table_body(ui, "logger_rows", &cols, &rows, &mut st, 19.0, h, &mut |e, ui| {
                    let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                    if sel == Some(e.id) {
                        ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                    }
                    let row = ui.horizontal(|ui| {
                        table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                            (0, e.id.to_string(), None),
                            (1, history_time(e.ts), None),
                            (2, e.tool.clone(), None),
                            (3, e.method.clone(), None),
                            (4, e.host.clone(), None),
                            (5, e.path.clone(), None),
                            (6, e.status.clone(), None),
                            (7, e.resp_len.to_string(), None),
                            (8, e.mime.clone(), None),
                        ]);
                    }).response.interact(egui::Sense::click());
                    if row.clicked() {
                        pick = Some(e.id);
                    }
                });
                app.log_table = st;
                if pick.is_some() {
                    app.log_sel = pick;
                }
            });
            col.cell(|ui| {
                let e = app.log_sel.and_then(|id| app.shared.history.lock().unwrap().iter().find(|h| h.id == id).cloned());
                let req = e.as_ref().map(|e| util::origin_form(&e.req_raw));
                let resp = e.as_ref().and_then(|e| e.resp_raw.clone());
                let h = ui.available_height().max(full * 0.5);
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::remainder())
                    .size(egui_extras::Size::remainder())
                    .horizontal(|mut s2| {
                        s2.cell(|ui| crate::msgpane::message_pane(ui, "log_req", "Request", req.as_deref(), &mut app.log_req_pane, false, h));
                        s2.cell(|ui| crate::msgpane::message_pane(ui, "log_resp", "Response", resp.as_deref(), &mut app.log_resp_pane, true, h));
                    });
            });
        });
}

// ================= Organizer =================

/// Saved request/response collection view. The tab name is jar-grounded:
/// build 52685 `burp.Zr86` setText("Organizer") (Zr86.java:612).
fn organizer_view(app: &mut App, ui: &mut Ui) {
    // Burp's Organizer (live 52685): Collections rail (New, search, Inbox) and
    // the selected collection with its Contents tab.
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::exact(280.0))
        .size(egui_extras::Size::remainder())
        .horizontal(|mut strip| {
            strip.cell(|ui| {
                let r = ui.max_rect();
                ui.painter().rect_filled(r, 0.0, theme::chrome());
                ui.painter().vline(r.right(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Collections").strong().size(14.0).color(theme::ink()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui.button(format!("{} New", theme::icon::PLUS)).on_hover_text("New item in the Inbox").clicked() {
                            let id = app.organizer.add("New item", "", "", "", util::now_secs());
                            app.org_sel = Some(id);
                        }
                    });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(6.0);
                    ui.add(egui::TextEdit::singleline(&mut app.org_search).hint_text("Search").desired_width(250.0));
                });
                ui.add_space(6.0);
                let _ = ui.selectable_label(true, RichText::new(format!("{}  Inbox ({})", theme::icon::TRAY, app.organizer.len())).size(12.5));
            });
            strip.cell(|ui| {
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new(format!("{}  Inbox", theme::icon::TRAY)).strong().size(14.0).color(theme::ink()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui.add_enabled(app.org_sel.is_some(), egui::Button::new("Delete")).clicked() {
                            if let Some(id) = app.org_sel.take() {
                                app.organizer.remove(id);
                            }
                        }
                    });
                });
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    let _ = crate::msgpane::underline_tabs(ui, &["Contents"], 0, 13.0);
                });
                let r = ui.cursor();
                ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
                ui.add_space(6.0);
                let q = app.org_search.to_ascii_lowercase();
                let items: Vec<crate::organizer::OrganizerItem> = app
                    .organizer
                    .list()
                    .into_iter()
                    .filter(|i| q.is_empty() || i.name.to_ascii_lowercase().contains(&q) || i.note.to_ascii_lowercase().contains(&q))
                    .cloned()
                    .collect();
                if items.is_empty() {
                    ui.add_space(ui.available_height() * 0.25);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(theme::icon::CLIPBOARD_TEXT).size(52.0).color(c(0x26649D)));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Organizer inbox is empty").strong().size(16.0).color(theme::ink()));
                        ui.add_space(6.0);
                        ui.label(RichText::new("To get started, send a message to Organizer from anywhere in WebProbe (Ctrl+O).").size(12.5).color(theme::ink_dim()));
                    });
                    return;
                }
                let cols = [
                    table::Column::new("#", 50.0),
                    table::Column::new("Time", 150.0),
                    table::Column::new("Item", 300.0),
                    table::Column::new("Notes", 300.0),
                ];
                let full = ui.available_height();
                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::relative(0.4))
                    .size(egui_extras::Size::remainder())
                    .vertical(|mut col| {
                        col.cell(|ui| {
                            let mut st = app.org_table.clone();
                            let mut pick = None;
                            let sel = app.org_sel;
                            let h = ui.available_height();
                            table::table_body(ui, "org_rows", &cols, &items, &mut st, 19.0, h, &mut |it, ui| {
                                let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                                if sel == Some(it.id) {
                                    ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                                }
                                let row = ui.horizontal(|ui| {
                                    table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                                        (0, it.id.to_string(), None),
                                        (1, history_time(it.created), None),
                                        (2, it.name.clone(), None),
                                        (3, it.note.clone(), None),
                                    ]);
                                }).response.interact(egui::Sense::click());
                                if row.clicked() {
                                    pick = Some(it.id);
                                }
                            });
                            app.org_table = st;
                            if pick.is_some() {
                                app.org_sel = pick;
                            }
                        });
                        col.cell(|ui| {
                            let Some(id) = app.org_sel else { return };
                            let Some(mut item) = app.organizer.get(id).cloned() else { return };
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Notes").size(12.5).color(theme::ink()));
                                if ui.add(egui::TextEdit::singleline(&mut item.note).desired_width(ui.available_width() - 10.0)).changed() {
                                    app.organizer.set_note(id, &item.note);
                                }
                            });
                            let h = ui.available_height().max(full * 0.5);
                            egui_extras::StripBuilder::new(ui)
                                .size(egui_extras::Size::remainder())
                                .size(egui_extras::Size::remainder())
                                .horizontal(|mut s2| {
                                    let req = (!item.request.is_empty()).then(|| item.request.clone().into_bytes());
                                    let resp = (!item.response.is_empty()).then(|| item.response.clone().into_bytes());
                                    s2.cell(|ui| crate::msgpane::message_pane(ui, "org_req", "Request", req.as_deref(), &mut app.org_req_pane, false, h));
                                    s2.cell(|ui| crate::msgpane::message_pane(ui, "org_resp", "Response", resp.as_deref(), &mut app.org_resp_pane, true, h));
                                });
                        });
                    });
            });
        });
}

#[cfg(test)]
mod tests {
    use super::{history_view, HISTORY_RENDER_LIMIT};
    use crate::net::HistEntry;
    use crate::table::TableState;

    fn entry(id: u64, host: &str) -> HistEntry {
        HistEntry {
            id,
            ts: 0,
            method: "GET".to_string(),
            host: host.to_string(),
            port: 80,
            path: "/".to_string(),
            status: "200".to_string(),
            resp_len: 0,
            req_raw: Vec::new(),
            resp_raw: None,
            https: false,
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        }
    }

    #[test]
    fn history_filters_full_list_before_limiting_rendered_rows() {
        let history: Vec<_> = (1..=(HISTORY_RENDER_LIMIT as u64 + 1))
            .map(|id| entry(id, if id == 1 { "old.example" } else { "other.example" }))
            .collect();

        // The only match is the oldest entry, far behind the render cap.
        let (rows, truncated) =
            history_view(&history, |e| e.host.contains("old.example"), &TableState::new());
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), [1]);
        assert!(!truncated);

        let (rows, truncated) = history_view(&history, |_| true, &TableState::new());
        assert_eq!(rows.len(), HISTORY_RENDER_LIMIT);
        assert!(truncated);
        assert_eq!(rows.first().unwrap().id, HISTORY_RENDER_LIMIT as u64 + 1);
        assert_eq!(rows.last().unwrap().id, 2);
    }

    #[test]
    fn history_sorts_by_method_before_limiting() {
        let mut history: Vec<_> = (1..=5).map(|id| entry(id, "example.test")).collect();
        history[0].method = "POST".to_string();
        let mut state = TableState::new();
        state.sort_col = 2; // Method (Burp column order: #, Host, Method, ...)
        state.sort_asc = true;
        let (rows, _) = history_view(&history, |_| true, &state);
        // Ascending by method: GET rows keep newest-first order, POST sorts last.
        assert_eq!(rows[0].method, "GET");
        assert_eq!(rows[4].method, "POST");
    }

    #[test]
    fn csrf_poc_replays_the_body() {
        let mut e = crate::net::HistEntry::default();
        e.method = "POST".into();
        e.host = "h".into();
        e.port = 80;
        e.path = "/change".into();
        e.req_raw = b"POST /change HTTP/1.1\r\nHost: h\r\n\r\nemail=a%40b.c&x=1".to_vec();
        let html = crate::ui::csrf_poc_html(&e);
        assert!(html.contains("action=\"http://h/change\"") && html.contains("name=\"email\" value=\"a@b.c\""), "{html}");
    }

    #[test]
    fn add_marker_wraps_the_selection() {
        assert_eq!(crate::ui::add_marker("q=apple", (2, 7)), "q=\u{00A7}apple\u{00A7}");
        assert_eq!(crate::ui::add_marker("ab", (1, 1)), "a\u{00A7}\u{00A7}b");
    }

    #[test]
    fn tools_get_origin_form_without_proxy_connection() {
        let r = crate::ui::request_for_tools(b"GET http://h:1/a?b=1 HTTP/1.1\r\nHost: h:1\r\nProxy-Connection: Keep-Alive\r\nAccept: */*\r\n\r\n");
        assert_eq!(r, "GET /a?b=1 HTTP/1.1\r\nHost: h:1\r\nAccept: */*\r\n\r\n");
    }

    #[test]
    fn repeater_updates_content_length() {
        let r = crate::ui::update_content_length("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nabcd");
        assert!(r.contains("Content-Length: 4\r\n"), "{r}");
        let g = crate::ui::update_content_length("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(!g.contains("Content-Length"));
    }

    #[test]
    fn the_cap_applies_after_the_sort() {
        let mut history: Vec<_> = (1..=(HISTORY_RENDER_LIMIT as u64 + 1))
            .map(|id| entry(id, "example.test"))
            .collect();
        history[0].method = "POST".to_string(); // the oldest entry, behind the cap
        let mut state = TableState::new();
        state.sort_col = 2; // Method
        state.sort_asc = false; // POST first
        let (rows, truncated) = history_view(&history, |_| true, &state);
        assert!(truncated);
        assert_eq!(rows[0].id, 1, "the sort must see the whole list before the cap");
    }
}

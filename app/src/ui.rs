// UI panels: Dashboard, Target (site map), Proxy (intercept/history/options),
// Intruder, Repeater, Decoder. Styling per theme.rs (DarkTheme.json evidence).

use std::sync::atomic::Ordering;

use eframe::egui::{self, RichText, Ui};

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

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let ctx = &ui.ctx().clone();
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
    crate::menus::project_window(app, ctx);
    crate::project_start::window(app, ctx);
    // Toasts are drawn once, by App::ui after this function returns, so
    // they sit above everything (drawing them here too doubled every toast's
    // widget ids).

    // P-01: Burp's menu row sits above the tab row. Only items that do
    // something real are here; the rest of Burp's menus arrive with their
    // features (P-03 Settings, D-06 issues, K-03 extensions).
    egui::Panel::top("menu_bar")
        .exact_size(26.0)
        .frame(
            egui::Frame::default()
                .fill(theme::chrome_alt())
                .inner_margin(egui::Margin::symmetric(6, 2)),
        )
        .show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                // Menu contents follow build 52685: Burp (Zc6t), Project (Zpn_),
                // Intruder (Zcur), Repeater (Zcu0), View (Zupi), Help (Zup4).
                // Items WebProbe has no backend for are shown disabled, not
                // pretended away.
                let off = |ui: &mut Ui, label: &str| {
                    ui.add_enabled(false, egui::Button::new(label));
                };
                ui.menu_button("WebProbe", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("Search").clicked() {
                        app.search_open = true;
                        ui.close();
                    }
                    if ui.button("Settings").clicked() {
                        app.settings_open = true;
                        ui.close();
                    }
                    if ui.button("Configuration library").clicked() {
                        app.settings_open = true;
                        app.settings_help = SettingsPane::ConfigurationLibrary;
                        ui.close();
                    }
                    ui.separator();
                    off(ui, "WebProbe Infiltrator");
                    off(ui, "WebProbe Clickbandit");
                    if ui.button("WebProbe Collaborator client").clicked() {
                        app.tab = Tab::Collaborator;
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Project", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    if ui.button("New temporary project").clicked() {
                        if let Err(e) = crate::project_start::new_project(app, None) {
                            feedback::toast(feedback::Level::Error, e);
                        }
                        ui.close();
                    }
                    if ui.button("New or open project\u{2026}").clicked() {
                        app.chooser.open = true;
                        app.chooser.at_start = false;
                        ui.close();
                    }
                    let recent = webprobe_core::project_files::recent_file().map(|f| webprobe_core::project_files::load_recent(&f)).unwrap_or_default();
                    ui.add_enabled_ui(!recent.is_empty(), |ui| {
                        ui.menu_button("Open recent project", |ui| {
                            for p in recent {
                                let exists = std::path::Path::new(&p).is_file();
                                if ui.add_enabled(exists, egui::Button::new(p.clone())).clicked() {
                                    if let Err(e) = crate::project_start::open(app, &p) {
                                        feedback::toast(feedback::Level::Error, e);
                                    }
                                    ui.close();
                                }
                            }
                        });
                    });
                    ui.separator();
                    off(ui, "Rename");
                    if ui.button("Save copy").clicked() {
                        crate::menus::save_project_copy(app);
                        ui.close();
                    }
                    if ui.button("Import project file").clicked() {
                        ui.data_mut(|d| d.insert_temp(crate::menus::project_window_id(), true));
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Project file\u{2026}").clicked() {
                        ui.data_mut(|d| d.insert_temp(crate::menus::project_window_id(), true));
                        ui.close();
                    }
                });
                ui.menu_button("Intruder", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    crate::menus::intruder_menu(app, ui);
                });
                ui.menu_button("Repeater", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    crate::menus::repeater_menu(app, ui);
                });
                ui.menu_button("View", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    // Burp: "Restore default tab layout", then the tools
                    // alphabetically (theme lives in Settings > Appearance).
                    if ui.button("Restore default tab layout").clicked() {
                        app.tab = Tab::Dashboard;
                        ui.close();
                    }
                    ui.separator();
                    let mut names: Vec<(&str, Tab)> = TABS.to_vec();
                    names.sort_by_key(|(n, _)| *n);
                    for (name, tab) in names {
                        if ui.button(name).clicked() {
                            app.tab = tab;
                            ui.close();
                        }
                    }
                });
                let title = format!("WebProbe - {}", std::path::Path::new(&app.project_path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default());
                let full = ui.max_rect();
                ui.painter().text(full.center(), egui::Align2::CENTER_CENTER, title, egui::FontId::proportional(12.5), theme::ink_dim());
                ui.menu_button("Help", |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.spacing_mut().button_padding.y = 4.0;
                    crate::menus::help_menu(app, ui);
                });
            });
        });

    egui::Panel::top("main_bar")
        .exact_size(38.0)
        .frame(egui::Frame::default().fill(theme::surface()).inner_margin(egui::Margin::symmetric(0, 0)))
        .show(ui, |ui| {
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                // Burp's tool tabs: plain labels, orange[1] underline on the
                // active one, no branding in the row.
                for (name, tab) in &TABS {
                    let sel = app.tab == *tab;
                    let galley = ui.painter().layout_no_wrap(name.to_string(), egui::FontId::proportional(12.5), theme::ink());
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(galley.size().x + 22.0, 38.0), egui::Sense::click());
                    // Painted by hand, so name it for accessibility / UI automation.
                    resp.widget_info(|| egui::WidgetInfo::selected(egui::accesskit::Role::Tab, true, sel, *name));
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
                    .corner_radius(6.0)
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
    egui::Panel::bottom("status_bar")
        .exact_size(36.0)
        .frame(
            egui::Frame::default()
                .fill(theme::chrome())
                .inner_margin(egui::Margin::symmetric(8, 3)),
        )
        .show(ui, |ui| {
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
                    app.shared.scan.is_busy(),
                    app.shared.scan.done.load(Ordering::SeqCst),
                    app.shared.scan.total.load(Ordering::SeqCst),
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
        .frame(egui::Frame::default().fill(theme::surface()).inner_margin(egui::Margin::same(10)))
        .show(ui, |ui| match app.tab {
            Tab::Dashboard => dashboard(app, ui),
            Tab::Target => target(app, ui),
            Tab::Proxy => proxy(app, ui),
            Tab::Scanner => scanner(app, ui),
            Tab::Intruder => intruder(app, ui),
            Tab::Repeater => repeater(app, ui),
            // The analysis results run past one screen: the tab scrolls.
            Tab::Sequencer => {
                egui::ScrollArea::vertical().id_salt("sequencer_tab").auto_shrink([false, false]).show(ui, |ui| crate::tools::sequencer(app, ui));
            }
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

/// Rows appended to the history since the cached view was built, filtered and
/// newest first: what goes on top of the view while the default newest-first
/// order is in force, so streaming traffic never rebuilds the whole view.
fn history_new_rows(history: &[net::HistEntry], from: usize, keep: impl Fn(&net::HistEntry) -> bool) -> Vec<net::HistEntry> {
    history.get(from..).unwrap_or_default().iter().rev().filter(|e| keep(e)).cloned().collect()
}

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
        egui::Window::new(title).default_pos(crate::theme::window_pos(&ctx)).open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
            ui.label("To show this item in your browser, copy the URL below and paste it into a browser that is configured to use WebProbe as its proxy.");
            ui.add_space(6.0);
            let mut u = url.clone();
            ui.add(egui::TextEdit::singleline(&mut u).desired_width(420.0));
            ui.horizontal(|ui| {
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(url.clone());
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
        egui::Window::new("CSRF PoC generator").default_pos(crate::theme::window_pos(&ctx)).open(&mut open).default_size(egui::vec2(640.0, 420.0)).show(ctx, |ui| {
            ui.label(RichText::new("CSRF HTML:").strong());
            let mut h = html.clone();
            ui.add(egui::TextEdit::multiline(&mut h).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).desired_rows(16));
            ui.horizontal(|ui| {
                if ui.button("Copy HTML").clicked() {
                    ui.ctx().copy_text(html.clone());
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
        egui::Window::new("HTTP history").default_pos(crate::theme::window_pos(&ctx)).open(&mut open).default_size(egui::vec2(900.0, 420.0)).show(ctx, |ui| {
            ui.add(egui::TextEdit::singleline(&mut app.hist_window_filter).hint_text("Search").desired_width(260.0));
            let q = app.hist_window_filter.to_ascii_lowercase();
            // Rebuilt only when the history or the filter changes: filtering
            // and copying every entry under the history lock on every frame
            // held up the proxy threads that record traffic.
            thread_local! {
                static ROWS: std::cell::RefCell<((usize, u64, String), std::rc::Rc<Vec<net::HistEntry>>)> = std::cell::RefCell::new(((usize::MAX, 0, String::new()), Default::default()));
            }
            let stamp = {
                let (len, last) = app.shared.history.stamp();
                (len, last, q.clone())
            };
            let rows = ROWS.with(|c| {
                let mut c = c.borrow_mut();
                if c.0 != stamp {
                    let snapshot: Vec<net::HistEntry> = app.shared.history.snapshot().iter().rev().cloned().collect();
                    let rows: Vec<net::HistEntry> = snapshot.into_iter().filter(|e| q.is_empty() || history_url(e).to_ascii_lowercase().contains(&q)).collect();
                    *c = (stamp, std::rc::Rc::new(rows));
                }
                c.1.clone()
            });
            let cols = [table::Column::new("#", 50.0), table::Column::new("Host", 180.0), table::Column::new("Method", 60.0), table::Column::new("URL", 300.0), table::Column::new("Status code", 80.0), table::Column::new("Length", 70.0)];
            let mut st = app.hist_window_table.clone();
            let mut pick = None;
            let h = ui.available_height();
            table::table_body(ui, "hist_window", &cols, &rows[..], &mut st, 19.0, h, &mut |e, ui| {
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
pub(crate) use crate::net::history_host;

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
    // Every matching row is kept: the table body is virtualised, so only the
    // visible rows are laid out (Burp shows the whole history too).
    (rows, false)
}

/// A history menu command applied to several selected rows at once.
fn bulk_history_command(app: &mut App, entries: &[net::HistEntry], cmd: &str) {
    let n = entries.len();
    let ids: Vec<u64> = entries.iter().map(|e| e.id).collect();
    match cmd {
        "scope" => {
            let mut scope = app.shared.scope.lock().unwrap();
            let mut added = std::collections::BTreeSet::new();
            for e in entries {
                let rule = format!("{}://{}", if e.https { "https" } else { "http" }, e.host);
                if added.insert(rule.clone()) && !scope.iter().any(|r| r.include && r.pattern == rule) {
                    scope.push(net::ScopeRule::include(rule, false));
                }
            }
            feedback::toast(feedback::Level::Success, format!("Added {} host(s) to target scope", added.len()));
        }
        "scan" => {
            crate::scan::audit_entries(app.shared.clone(), entries.to_vec());
            feedback::toast(feedback::Level::Info, format!("Active scan of {n} item(s) started"));
        }
        "passive" => {
            for e in entries {
                crate::scan::add_passive_issues(&app.shared, crate::scan::passive_check_for(&app.shared, e));
            }
            feedback::toast(feedback::Level::Success, format!("Passive scan of {n} item(s) done"));
        }
        "repeater" => {
            for e in entries {
                app.history_sel = Some(e.id);
                send_history_to_repeater(app);
            }
            app.tab = Tab::Repeater;
        }
        "organizer" => {
            for e in entries {
                let req_text = String::from_utf8_lossy(&e.req_raw).into_owned();
                let resp_text = e.resp_raw.as_ref().map(|r| String::from_utf8_lossy(r).into_owned()).unwrap_or_default();
                app.shared.organizer.lock().unwrap().add(&format!("{} {}", e.method, e.path), "", &req_text, &resp_text, util::now_secs());
            }
            feedback::toast(feedback::Level::Success, format!("Sent {n} item(s) to Organizer"));
        }
        "cmp_req" | "cmp_resp" => {
            for e in entries {
                app.cmp_items.push(if cmd == "cmp_req" { request_for_tools(&e.req_raw) } else { e.resp_raw.as_ref().map(|r| String::from_utf8_lossy(r).into_owned()).unwrap_or_default() });
            }
            app.tab = Tab::Comparer;
        }
        "delete" => {
            app.shared.history.retain(|h| !ids.contains(&h.id));
            app.hist_cache_key.clear();
            feedback::toast(feedback::Level::Success, format!("Deleted {n} item(s)"));
        }
        "save_item" => {
            let dir = std::env::current_dir().map(|d| d.join("saved-items")).unwrap_or_else(|_| "saved-items".into());
            let _ = std::fs::create_dir_all(&dir);
            let mut saved = 0;
            for e in entries {
                let mut bytes = e.req_raw.to_vec();
                bytes.extend_from_slice(b"\r\n\r\n");
                if let Some(r) = &e.resp_raw {
                    bytes.extend_from_slice(r);
                }
                if std::fs::write(dir.join(format!("item-{}.http", e.id)), bytes).is_ok() {
                    saved += 1;
                }
            }
            feedback::toast(feedback::Level::Success, format!("Saved {saved} item(s) to {}", dir.display()));
        }
        hl if hl.starts_with("hl_") => {
            let k = HIGHLIGHT_CMDS.iter().position(|c| *c == hl).map(|k| k as u8);
            app.shared.history.update_where(|h| ids.contains(&h.id), |h| h.highlight = k);
            app.hist_cache_key.clear();
        }
        _ => {}
    }
}

/// Proxy > HTTP history (B-01).
///
/// The filter bar is text/regex plus method, status code, MIME type and "in scope
/// only"; every column is sortable and resizable, and the view is virtualized.
fn proxy_history(app: &mut App, ui: &mut Ui) {
    let total = app.shared.history.len();

    // N-02: the filtered view is rebuilt only when a filter or sort input
    // changed. New traffic in the default newest-first order is put on top
    // of the cached view instead, and frames share the view (an Arc), so a
    // frame never copies the history.
    let key = format!("{}|{}|{}", app.hist_filter.key(), app.hist_table.sort_col, app.hist_table.sort_asc);
    let newest_first = (app.hist_table.sort_col == 0 && !app.hist_table.sort_asc) || app.hist_table.sort_col == usize::MAX;
    if key != app.hist_cache_key || total < app.hist_cache_len || (total > app.hist_cache_len && !newest_first) {
        let (rows, truncated) = {
            app.shared.history.with_rows(|history| history_view(history, |e| app.hist_filter.matches(e, &app.shared), &app.hist_table))
        };
        app.hist_cache = std::sync::Arc::new(rows);
        app.hist_cache_truncated = truncated;
        app.hist_cache_key = key;
        app.hist_cache_len = total;
    } else if total > app.hist_cache_len {
        let fresh = {
            app.shared.history.with_rows(|history| history_new_rows(history, app.hist_cache_len, |e| app.hist_filter.matches(e, &app.shared)))
        };
        let old = std::mem::take(std::sync::Arc::make_mut(&mut app.hist_cache));
        let mut rows = fresh;
        rows.extend(old);
        app.hist_cache = std::sync::Arc::new(rows);
        app.hist_cache_len = total;
    }
    let (rows, truncated) = (app.hist_cache.clone(), app.hist_cache_truncated);

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
        table::Column::new("#", 54.0),
        table::Column::new("Host", 150.0),
        table::Column::new("Method", 56.0),
        table::Column::new("URL", 190.0),
        table::Column::new("Params", 54.0),
        table::Column::new("Edited", 54.0),
        table::Column::new("Status code", 80.0),
        table::Column::new("Length", 54.0),
        table::Column::new("MIME type", 66.0),
        table::Column::new("Extension", 66.0),
        table::Column::new("Title", 110.0),
        table::Column::new("Notes", 70.0),
        table::Column::new("TLS", 38.0),
        table::Column::new("IP", 96.0),
        table::Column::new("Cookies", 90.0),
        table::Column::new("Time", 140.0),
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
    if !ui.ctx().egui_wants_keyboard_input() && !rows.is_empty() {
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

    // A row the filter or search no longer shows cannot stay selected: its
    // messages would sit in the panes below with no row to account for them.
    if app.history_sel.is_some_and(|id| !rows.iter().any(|r| r.id == id)) {
        app.history_sel = None;
    }
    let order: Vec<u64> = rows.iter().map(|r| r.id).collect();
    app.history_multi.retain_visible(&order);
    // Ctrl+A selects every visible row while no text field has the keyboard.
    if !ui.ctx().egui_wants_keyboard_input() && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::A)) {
        app.history_multi.select_all(&order);
    }
    let multi = app.history_multi.clone();
    let mut click: Option<(u64, bool, bool)> = None;
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
    let ext_shared = app.shared.clone();
    table::table_body(ui, "proxy_history", &columns, &rows, &mut app.hist_table, row_height, table_h, &mut |e, ui| {
        let row_rect = egui::Rect::from_min_size(
            ui.cursor().min,
            egui::vec2(ui.available_width(), row_height),
        );
        if selected == Some(e.id) || multi.ids.contains(&e.id) {
            // Burp's selectionBackground, so a selected row reads as selected
            // and not as a warning.
            ui.painter().rect_filled(row_rect, egui::CornerRadius::ZERO, theme::selection_bg());
            ui.painter().rect_stroke(row_rect.shrink(0.5), egui::CornerRadius::ZERO, egui::Stroke::new(1.0, c(0x5384B2)), egui::StrokeKind::Outside);
        } else if let Some(k) = e.highlight {
            ui.painter().rect_filled(row_rect, egui::CornerRadius::ZERO, highlight_colours(k).0);
        } else if e.id % 2 == 0 {
            ui.painter().rect_filled(row_rect, egui::CornerRadius::ZERO, theme::zebra());
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
            let m = ui.input(|i| i.modifiers);
            click = Some((e.id, m.command, m.shift));
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
            let n = multi.targets(&order, e.id).len();
            if n > 1 {
                ui.label(RichText::new(format!("{n} items selected")).strong().size(12.5));
            } else {
                ui.label(RichText::new(history_url(e)).strong().size(12.5));
            }
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
                        ui.close();
                    }
                }
                if ui.button("None").clicked() {
                    pending_menu = Some((e.clone(), "hl_none"));
                    ui.close();
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
                ui.ctx().copy_text(history_url(e));
            }
            if menu_action(ui, "Copy as curl command (bash)") {
                ui.ctx().copy_text(curl_command_of(e));
            }
            if menu_action(ui, "Copy links in response") {
                ui.ctx().copy_text(links_in_response(e));
            }
            if menu_action(ui, "Save item") {
                pending_menu = Some((e.clone(), "save_item"));
            }
            ui.separator();
            if menu_action(ui, "Proxy history documentation") {
                pending_menu = Some((e.clone(), "docs"));
            }
            // Montoya extensions' items (the history is read-only: a
            // message an action sets is not applied here).
            let ctx = webprobe_core::ext_host::MenuContext {
                tool: "Proxy".into(),
                invocation: "PROXY_HISTORY".into(),
                messages: vec![crate::ext_menu::message_of(e)],
                editor: None,
            };
            crate::ext_menu::submenu(ui, &ext_shared, &ctx, None);
        });
    });
    if let Some((id, ctrl, shift)) = click {
        app.history_multi.click(&order, id, ctrl, shift);
    }
    // Commands that act on every selected row when the clicked row is part of
    // a multi-row selection (Burp applies them to the whole selection).
    if let Some((e, cmd)) = &pending_menu {
        let ids = app.history_multi.targets(&order, e.id);
        if ids.len() > 1 && matches!(*cmd, "scope" | "scan" | "passive" | "repeater" | "organizer" | "delete" | "save_item" | "cmp_req" | "cmp_resp") || (ids.len() > 1 && cmd.starts_with("hl_")) {
            let entries: Vec<net::HistEntry> = rows.iter().filter(|r| ids.contains(&r.id)).cloned().collect();
            bulk_history_command(app, &entries, cmd);
            if *cmd == "delete" {
                selected = None;
                app.history_multi = table::MultiSelect::default();
            }
            pending_menu = None;
        }
    }
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
                app.shared.organizer.lock().unwrap().add(&format!("{} {}", e.method, e.path), "", &req_text, &resp_text, util::now_secs());
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
                crate::scan::add_passive_issues(&app.shared, crate::scan::passive_check_for(&app.shared, &e));
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
                let mut bytes = e.req_raw.to_vec();
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
                app.shared.history.update(e.id, |h| h.highlight = k);
                app.hist_cache_key.clear();
            }
            "delete" => {
                app.shared.history.retain(|h| h.id != e.id);
                selected = None;
                app.shared.log(&format!("Deleted history item {}", e.id));
            }
            "clear" => {
                app.shared.history.clear();
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
/// A draggable vertical divider at `x` between two side-by-side panes;
/// `frac` is the left pane's share of `total` width (kept 0.15..0.85).
pub(crate) fn vsplit_handle(ui: &mut Ui, id: &str, x: f32, y: std::ops::RangeInclusive<f32>, frac: &mut f32, total: f32) {
    let rect = egui::Rect::from_x_y_ranges((x - 3.0)..=(x + 3.0), y);
    let drag = ui.interact(rect, egui::Id::unique(("vsplit", id)), egui::Sense::drag());
    if drag.dragged() && total > 0.0 {
        *frac = (*frac + drag.drag_delta().x / total).clamp(0.15, 0.85);
    }
    if drag.hovered() || drag.dragged() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
        ui.painter().vline(x, rect.y_range(), egui::Stroke::new(2.0, c(theme::ORANGE)));
    }
    drag.widget_info(|| egui::WidgetInfo::labeled(egui::accesskit::Role::Splitter, true, id));
}

fn splitter(ui: &mut Ui, split: &mut f32, total: f32) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 7.0),
        egui::Sense::hover(),
    );
    let drag = ui.interact(rect, ui.scope_id().with("splitter"), egui::Sense::drag());
    if drag.dragged() {
        let next = *split - drag.drag_delta().y;
        *split = next.clamp(90.0, (total - 140.0).max(90.0));
    }
    let active = drag.dragged() || drag.hovered();
    let y = rect.center().y;
    ui.painter().rect_filled(
        egui::Rect::from_min_size(egui::pos2(rect.left(), y - 0.5), egui::vec2(rect.width(), 1.0)),
        egui::CornerRadius::ZERO,
        if active { c(theme::ORANGE) } else { theme::line() },
    );
    if active {
        ui.painter().rect_filled(
            egui::Rect::from_min_size(egui::pos2(rect.center().x - 14.0, y - 1.5), egui::vec2(28.0, 3.0)),
            egui::CornerRadius::same(2),
            c(theme::ORANGE),
        );
    }
}

pub(crate) fn proxy_options(app: &mut App, ui: &mut Ui) {
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
    crate::proxy_settings::listeners_table(app, ui);
    ui.add_space(10.0);
    crate::proxy_settings::ca_buttons(app, ui);
    ui.add_space(10.0);
    crate::proxy_settings::intercept_rules_table(app, ui);
    ui.add_space(8.0);
    crate::proxy_settings::response_rules_and_pass_through(app, ui);
    ui.add_space(10.0);
    // Proxy settings > WebSockets: which directions are held while Intercept
    // is on (Burp default: both, ProjectDefaults intercept_web_sockets_messages).
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
    ui.horizontal(|ui| {
        let mut f = app.shared.ws_intercept_in_scope.load(Ordering::SeqCst);
        if ui.checkbox(&mut f, "Only intercept in-scope messages").changed() {
            app.shared.ws_intercept_in_scope.store(f, Ordering::SeqCst);
        }
        let mut f = app.shared.ws_strip_extensions.load(Ordering::SeqCst);
        if ui.checkbox(&mut f, "Strip Sec-WebSocket-Extensions headers in incoming requests").changed() {
            app.shared.ws_strip_extensions.store(f, Ordering::SeqCst);
        }
    });
    ui.add_space(10.0);
    crate::proxy_settings::ws_match_replace(app, ui);
    ui.add_space(10.0);
    crate::proxy_settings::streaming_responses(app, ui);
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
        .and_then(|id| app.shared.history.get(id));
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
            // Burp's default message layout here is request and response side
            // by side; stacked, each pane showed only four or five lines.
            let full = ui.available_height();
            egui_extras::StripBuilder::new(ui)
                .size(egui_extras::Size::relative(0.5))
                .size(egui_extras::Size::remainder())
                .horizontal(|mut col| {
                    col.cell(|ui| {
                        crate::msgpane::message_pane(ui, "hist_req", "Request", req.as_deref(), &mut app.req_pane, false, full);
                    });
                    col.cell(|ui| {
                        let r = ui.max_rect();
                        ui.painter().vline(r.left(), r.y_range(), egui::Stroke::new(1.0, theme::line()));
                        crate::msgpane::message_pane(ui, "hist_resp", "Response", resp.as_deref(), &mut app.resp_pane, true, full);
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
                            app.shared.history.update(e.id, |h| h.note = if note.is_empty() { None } else { Some(note) });
                            // The filtered rows are cached copies: refresh the Notes column now.
                            app.hist_cache_key.clear();
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

fn scanner(app: &mut App, ui: &mut Ui) {
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
            .on_hover_text("Also run checks Burp does not have: passive (missing CSP, Referrer-Policy, version banners, ...) and active (reflected DOM canary, stored echo, TRACE echo, OPTIONS methods, header reflection). Off: a scan sends and reports what Burp's would.")
            .changed()
        {
            app.shared.extra_checks.store(extra, Ordering::SeqCst);
        }
    });
    ui.add_space(2.0);

    // D-07: "Report issues" (the rows shown) / "Report selected issues".
    let mut report_ids: Option<Vec<u64>> = None;
    let mut issue_action: Option<(u64, crate::issue_view::IssueAction)> = None;
    let mut report_all = false;
    let busy = app.shared.scan.is_busy();
    let (done, total) = (
        app.shared.scan.done.load(Ordering::SeqCst),
        app.shared.scan.total.load(Ordering::SeqCst),
    );
    ui.horizontal(|ui| {
        let btn = RichText::new(if busy { "scanning..." } else { "Run active scan on selected request" })
            .color(if busy { theme::ink_faint() } else { c(theme::ORANGE) })
            .size(13.0);
        if !busy && ui.button(btn).clicked() {
            if let Some(id) = app.history_sel {
                let e = app.shared.history.get(id);
                if let Some(e) = e {
                    run_active_scan_on(app, &e);
                }
            } else {
                feedback::toast(feedback::Level::Warn, "Select a request in Proxy history first");
            }
        }
        if total > 0 && feedback::progress(ui, done, total, busy) {
            app.shared.scan.stop.store(true, Ordering::SeqCst);
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
            if ui.button("Report issues").on_hover_text("Report the issues shown in the table as HTML or XML").clicked() {
                report_all = true;
            }
            ui.label(
                RichText::new(format!("{} issues", app.shared.issues.lock().unwrap().len()))
                    .size(12.0)
                    .color(theme::ink_faint()),
            );
        });
    });

    ui.add_space(4.0);
    app.issue_filter.bar(ui);
    ui.add_space(4.0);
    let issues: Vec<scan::ScanIssue> = app.shared.issues.lock().unwrap().iter().filter(|i| app.issue_filter.matches(i)).cloned().collect();
    // With an issue selected the table keeps the upper part and the advisory
    // and evidence tabs get the rest, as in Burp's issue activity view.
    let table_h = if app.scan_sel.is_some() { (ui.available_height() * 0.4).max(140.0) } else { ui.available_height() - 10.0 };
    let columns = [
        table::Column::new("Severity", 78.0),
        table::Column::new("Confidence", 78.0),
        table::Column::new("Issue", 280.0),
        table::Column::new("Host", 180.0),
        table::Column::new("Path", 260.0),
    ];
    let mut selected = app.scan_sel;
    let filter_default = app.issue_filter.is_default();
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
    if report_all {
        report_ids = Some(rows.iter().map(|i| i.id).collect());
    }
    let grouping = app.issue_filter.grouping;
    if grouping != crate::issue_view::Grouping::None {
        egui::ScrollArea::vertical().id_salt("scan_issues_grouped").max_height(table_h.max(140.0)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            issue_action = crate::issue_view::grouped_list(
                ui,
                &rows,
                grouping,
                &mut selected,
                |i| if i.false_positive { "False positive".to_string() } else { scan_sev_label(&i.sev).to_string() },
                |i| if i.false_positive { theme::ink_faint() } else { scan_sev_color(&i.sev) },
            );
            if rows.is_empty() {
                feedback::empty_state(ui, "No issues to group", "Browse sites through the proxy, run an active scan, or widen the filter.");
            }
        });
    } else {
    egui::ScrollArea::vertical().max_height(table_h.max(140.0)).show(ui, |ui| {
        let row_h = theme::appearance().1.row_height();
        table::data_table(ui, "scan_issues", &columns, &rows, &mut app.scan_table, row_h, |iss, ui| {
            if selected == Some(iss.id) {
                let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), row_h));
                ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
            }
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
            row.context_menu(|ui| {
                if let Some(a) = crate::issue_view::issue_menu(ui, iss) {
                    issue_action = Some((iss.id, a));
                }
            });
        });
        if rows.is_empty() {
            if issues.is_empty() && filter_default {
                feedback::empty_state(ui, "No issues yet", "Browse sites through the proxy, or run an active scan on a request.");
            } else {
                feedback::empty_state(ui, "No issues match the filter", "Clear the filter box and tick every severity and confidence to see every issue.");
            }
        }
    });
    }
    app.scan_sel = selected;
    if let Some((id, action)) = issue_action {
        if action == crate::issue_view::IssueAction::CopyUrl {
            if let Some(i) = issues.iter().find(|i| i.id == id) {
                // Issues keep host and path; the scheme and port come from the
                // item they were found on.
                let entries = crate::engagement::site_entries(app);
                let url = entries
                    .iter()
                    .find(|e| e.host == i.host && e.path.split('?').next() == Some(i.path.as_str()))
                    .map(|e| format!("{}{}", crate::engagement::origin_of(e), i.path))
                    .unwrap_or_else(|| format!("http://{}{}", i.host, i.path));
                ui.ctx().copy_text(url);
            }
        } else if let Some(ids) = crate::issue_view::apply_issue_action(&mut app.shared.issues.lock().unwrap(), id, &action) {
            report_ids = Some(ids);
        }
        if action == crate::issue_view::IssueAction::Delete && app.scan_sel == Some(id) {
            app.scan_sel = None;
        }
    }
    if let Some(ids) = report_ids.take() {
        app.eng.report.open_for(ids);
    }

    if let Some(id) = app.scan_sel {
        if let Some(issue) = issues.iter().find(|i| i.id == id).cloned() {
            ui.add_space(4.0);
            let label = if issue.false_positive { "False positive" } else { scan_sev_label(&issue.sev) };
            let colour = if issue.false_positive { theme::ink_faint() } else { scan_sev_color(&issue.sev) };
            if crate::issue_view::issue_detail(app, ui, &issue, label, colour) {
                if let Some(it) = app.shared.issues.lock().unwrap().iter_mut().find(|i| i.id == id) {
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
    // Attacks run through intruder_run (pool, retries, grep, recursive grep).
    let running = crate::intruder_ui::is_running(app);
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
    while app.intr_sources.len() < app.intr_sets.len() {
        app.intr_sources.push(intruder::PayloadSource::SimpleList { items: Vec::new() });
    }
    let needed = app.intr_attack.sets_needed(positions).max(1);
    let bases: Vec<String> = intruder::Template::parse(&app.intr_req).map(|t| t.position_values().to_vec()).unwrap_or_default();
    let sets: Vec<Vec<String>> = app
        .intr_sets
        .iter()
        .zip(app.intr_sources.iter())
        .take(needed)
        .enumerate()
        .map(|(i, (text, source))| match source {
            intruder::PayloadSource::SimpleList { .. } => text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
            other => other.generate_for_base(bases.get(i).map(String::as_str).unwrap_or("")),
        })
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
                            crate::intruder_ui::stop(app);
                        } else {
                            let req = if app.intr_update_host { with_target_host(&app.intr_req, &app.intr_target) } else { app.intr_req.clone() };
                            match crate::intruder_ui::start_attack(app, &req) {
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
                                let current = app.intr_sources[set_n].label();
                                egui::ComboBox::from_id_salt("intr_ptype").selected_text(current).show_ui(ui, |ui| {
                                    for d in intruder::PayloadSource::defaults() {
                                        let l = d.label();
                                        if ui.selectable_label(current == l, l).clicked() && current != l {
                                            let mut d = d;
                                            // The frobber works on the position's base value.
                                            if let intruder::PayloadSource::CharacterFrobber { base } = &mut d {
                                                *base = intruder::Template::parse(&app.intr_req).ok().and_then(|t| t.position_values().get(set_n).cloned()).unwrap_or_default();
                                            }
                                            app.intr_sources[set_n] = d;
                                        }
                                    }
                                });
                                ui.end_row();
                                let count = sets.get(set_n).map(Vec::len).unwrap_or(0);
                                let reqs = crate::intruder_ui::request_count_text(app);
                                ui.label(RichText::new("Payload count:").size(12.5).color(theme::ink()));
                                ui.label(RichText::new(count.to_string()).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                                ui.label(RichText::new("Request count:").size(12.5).color(theme::ink()));
                                ui.label(RichText::new(reqs).size(12.5).color(theme::ink_dim()));
                                ui.end_row();
                                let procs: Vec<String> = app.shared.ext_host.lock().unwrap().active().iter().filter_map(|e| e.ui()).flat_map(|u| u.processors).collect();
                                if app.intr_ext_proc.len() <= set_n {
                                    app.intr_ext_proc.resize(set_n + 1, String::new());
                                }
                                if !procs.is_empty() || !app.intr_ext_proc[set_n].is_empty() {
                                    ui.label(RichText::new("Extension processor:").size(12.5).color(theme::ink()));
                                    let chosen = &mut app.intr_ext_proc[set_n];
                                    let shown = if chosen.is_empty() { "(none)".to_string() } else { chosen.clone() };
                                    egui::ComboBox::from_id_salt("intr_ext_proc").selected_text(shown).show_ui(ui, |ui| {
                                        ui.selectable_value(chosen, String::new(), "(none)");
                                        for n in &procs {
                                            ui.selectable_value(chosen, n.clone(), n);
                                        }
                                    });
                                    ui.end_row();
                                }
                            });
                            ui.add_space(10.0);
                            ui.label(RichText::new("Payload configuration").strong().size(13.0).color(theme::ink()));
                            if matches!(app.intr_sources[set_n], intruder::PayloadSource::Extension { .. }) {
                                let names = webprobe_core::ext_calls::payload_generators(&app.shared);
                                if let intruder::PayloadSource::Extension { provider, .. } = &mut app.intr_sources[set_n] {
                                    crate::intruder_ui::extension_source_config(ui, provider, &names);
                                }
                            } else if !matches!(app.intr_sources[set_n], intruder::PayloadSource::SimpleList { .. }) {
                                payload_source_config(ui, &mut app.intr_sources[set_n]);
                            } else {
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
                                egui::Frame::NONE.stroke(egui::Stroke::new(1.0, theme::line())).fill(theme::surface()).show(ui, |ui| {
                                    ui.add(egui::TextEdit::multiline(set).font(egui::TextStyle::Monospace).desired_rows(8).desired_width(ui.available_width() - 8.0).frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2))));
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
                            }
                        });
                        if app.intr_paste_pending {
                            app.intr_paste_pending = false;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                        }
                        let pasted: Option<String> = ui.input(|i| i.events.iter().find_map(|e| if let egui::Event::Paste(t) = e { Some(t.clone()) } else { None }));
                        if let Some(t) = pasted {
                            if !ui.ctx().egui_wants_keyboard_input() {
                                let set_n = app.intr_set_sel.min(needed - 1);
                                let set = &mut app.intr_sets[set_n];
                                if !set.is_empty() && !set.ends_with('\n') { set.push('\n'); }
                                set.push_str(&t);
                            }
                        }
                    }
                    1 => crate::intruder_ui::resource_pool_panel(ui, &mut app.intr_x),
                    _ => {
                        if crate::intruder_ui::settings_panel(ui, &mut app.intr_x) {
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
                    resp.widget_info(|| egui::WidgetInfo::selected(egui::accesskit::Role::Tab, true, app.intr_dock == i, *label));
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
    crate::intruder_ui::results_window(app, ui.ctx());
}

// ================= Repeater =================

fn repeater(app: &mut App, ui: &mut Ui) {
    // Burp's Repeater: a strip of numbered tabs (close cross, "+"), a toolbar
    // (orange Send, settings, Cancel, history arrows ... Target on the
    // right), then Request | Response | Inspector with the vertical dock, and
    // a status line at the bottom (live 52685 reference). E-04: the tab
    // strip (rename, close, duplicate, reorder) lives in repeater_ops.
    crate::repeater_ops::tab_strip(app, ui);
    crate::repeater_groups::dialog(app, ui.ctx());
    crate::repeater_groups::tick(app);
    ui.add_space(4.0);
    // A WebSocket Repeater tab has its own view.
    let ws_session = {
        let reps = app.shared.repeaters.lock().unwrap();
        reps.get(app.rep_sel.min(reps.len().saturating_sub(1))).and_then(|r| r.ws)
    };
    if let Some(id) = ws_session {
        crate::repeater_ops::ws_repeater_view(app, ui, id);
        return;
    }

    let busy = app.shared.rep.is_busy();
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
        egui::menu::MenuButton::new(RichText::new(theme::icon::GEAR).size(15.0)).config(egui::menu::MenuConfig::new().close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)).ui(ui, |ui| {
            // Burp's Repeater settings menu (the options WebProbe implements).
            crate::repeater_ops::settings_menu(ui, app);
        })
        .0
        .on_hover_text("Repeater settings");
        let group_busy = crate::repeater_groups::is_sending(app);
        if ui.add_enabled(busy || group_busy, egui::Button::new("Cancel").min_size(egui::vec2(64.0, 24.0))).clicked() {
            if busy {
                cancel_repeater_send(&app.shared);
            }
            if group_busy {
                crate::repeater_groups::cancel(app);
            }
        }
        // E-02: Burp's "Follow redirection" button, shown for a 3xx response.
        if crate::repeater_ops::can_follow(app)
            && ui
                .add_enabled(!busy, egui::Button::new("Follow redirection").min_size(egui::vec2(64.0, 24.0)))
                .on_hover_text("Follow the redirection in the current response")
                .clicked()
            && crate::repeater_ops::load_redirect(app)
        {
            repeater_send(app);
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
        egui::Window::new("Configure target details").default_pos(crate::theme::window_pos(ui.ctx()))
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
    let mut rep_action: Option<crate::repeater_ops::RepAction> = None;
    // Request | response divider: draggable (Burp's split pane), kept in
    // the project layout as a fraction of the two panes' width.
    let panes_w = (ui.available_width() - side_w - dock_w).max(400.0);
    let req_w = (panes_w * app.rep_split).clamp(200.0, panes_w - 200.0);
    let panes_top = ui.cursor().min;
    ui.allocate_ui(egui::vec2(ui.available_width(), body_h), |ui| {
        let mut sb = egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::exact(req_w))
            .size(egui_extras::Size::remainder().at_least(200.0));
        if side_w > 0.0 {
            sb = sb.size(egui_extras::Size::exact(side_w));
        }
        sb.size(egui_extras::Size::exact(dock_w)).horizontal(|mut strip| {
            strip.cell(|ui| {
                // E-06 "Paste URL as request" lands here before the editor
                // could take the paste.
                crate::repeater_ops::poll_paste_url(app, ui);
                let i = app.rep_sel.min(app.shared.repeaters.lock().unwrap().len().saturating_sub(1));
                let (mut text, has_resp) = {
                    let reps = app.shared.repeaters.lock().unwrap();
                    (reps[i].request.clone(), reps[i].response.is_some())
                };
                app.rep_req_pane.live_url_encode = app.rops.url_encode_live;
                // E-03: Burp's request-editor context menu.
                let rops = &mut app.rops;
                let ext_shared = app.shared.clone();
                let (rep_service, rep_text) = {
                    let reps = app.shared.repeaters.lock().unwrap();
                    (webprobe_core::ext_host::HttpService::new(&reps[i].host, reps[i].port, reps[i].https), reps[i].request.clone())
                };
                // Requests extension actions/editors gave back for this tab
                // (they run off the UI thread and arrive on a later frame).
                let ext_target = format!("Repeater:{}", app.shared.repeaters.lock().unwrap()[i].id);
                let ext_edit = crate::ext_menu::take_edit(&ext_target);
                let mut menu = |ui: &mut Ui, sel: Option<String>| {
                    if let Some(a) = crate::repeater_ops::request_menu(ui, rops, sel.is_some(), sel.as_deref(), has_resp) {
                        rep_action = Some(a);
                    }
                    // Montoya extensions' items, with the editor's selection
                    // (located by its first occurrence in the request).
                    let raw = rep_text.replace("\r\n", "\n").replace('\n', "\r\n").into_bytes();
                    let at = sel.as_deref().and_then(|s| String::from_utf8_lossy(&raw).find(&s.replace("\r\n", "\n").replace('\n', "\r\n")).map(|a| (a, a + s.len())));
                    let (start, end) = at.unwrap_or((0, 0));
                    let ctx = webprobe_core::ext_host::MenuContext {
                        tool: "Repeater".into(),
                        invocation: "MESSAGE_EDITOR_REQUEST".into(),
                        messages: vec![webprobe_core::ext_host::MenuMessage { request: raw, response: None, service: rep_service.clone() }],
                        editor: Some(("REQUEST".into(), start, end, start)),
                    };
                    crate::ext_menu::submenu(ui, &ext_shared, &ctx, Some(&ext_target));
                    crate::ext_menu::editor_items(ui, &ext_shared, &ctx.messages[0], "Repeater", &ext_target);
                };
                if crate::msgpane::editable_pane_ex(ui, "rep_req", "Request", &mut text, &mut app.rep_req_pane, body_h, Some(&mut menu)) {
                    app.shared.repeaters.lock().unwrap()[i].request = text;
                }
                // An extension action that set the editor's request.
                if let Some(raw) = ext_edit {
                    app.shared.repeaters.lock().unwrap()[i].request = String::from_utf8_lossy(&raw).into_owned();
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
                    if let Some(new) = crate::msgpane::inspector_ex(ui, "rep_insp", reqb.as_deref(), resp.as_deref(), &mut app.insp_state, true) {
                        let mut reps = app.shared.repeaters.lock().unwrap();
                        let i = app.rep_sel.min(reps.len().saturating_sub(1));
                        reps[i].request = String::from_utf8_lossy(&new).into_owned();
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
    });
    vsplit_handle(ui, "rep_split", panes_top.x + req_w, panes_top.y..=panes_top.y + body_h, &mut app.rep_split, panes_w);
    if let Some(action) = rep_action {
        use crate::repeater_ops::RepAction;
        match action {
            RepAction::ActiveScan => {
                if let Some(e) = crate::repeater_ops::tab_entry(app) {
                    run_active_scan_on(app, &e);
                }
            }
            RepAction::ToIntruder => repeater_tab_to_intruder(app),
            RepAction::ToRepeater => repeater_tab_to_new_tab(app),
            other => {
                let ctx = ui.ctx().clone();
                crate::repeater_ops::apply_action(app, &ctx, other);
            }
        }
    }
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

/// Burp's "Update Content-Length" (the engine's `util::update_content_length`).
pub(crate) fn update_content_length(req: &str) -> String {
    String::from_utf8_lossy(&util::update_content_length(req.as_bytes())).into_owned()
}

pub(crate) fn repeater_send(app: &mut App) {
    if app.rep_update_cl {
        let mut reps = app.shared.repeaters.lock().unwrap();
        let i = app.rep_sel.min(reps.len().saturating_sub(1));
        let fixed = update_content_length(&reps[i].request);
        reps[i].request = fixed;
    }
    let reps_len = app.shared.repeaters.lock().unwrap().len();
    let i = app.rep_sel.min(reps_len.saturating_sub(1));
    // Burp sends to the tab's Target; the Host header is just a header (so
    // Host header attacks reach the real server). Only a tab without a
    // target falls back to the Host header, which then becomes its target.
    let (tab_id, request, h, p, https) = {
        let mut reps = app.shared.repeaters.lock().unwrap();
        let r = &mut reps[i];
        if r.host.trim().is_empty() {
            let parts = util::parse_http(r.request.as_bytes());
            let host = util::get_header(&parts.headers, "Host").unwrap_or_default();
            if host.is_empty() {
                // Shown where the user looks: the tab's status line.
                r.result_line = "error: no target and no Host header in request".into();
                drop(reps);
                crate::feedback::toast(crate::feedback::Level::Error, "Repeater: set a target or a Host header first");
                return;
            }
            let default_port = if r.port == 0 { if r.https { 443 } else { 80 } } else { r.port };
            let (h, p) = net::split_h_p(&host, default_port);
            r.host = h;
            r.port = p;
        }
        (r.id, r.request.clone(), r.host.clone(), r.port, r.https)
    };
    let gen = app.shared.rep.begin(tab_id);
    let sh = app.shared.clone();
    // E-02: Repeater settings > Follow redirections / Process cookies.
    let (follow, cookies) = (app.rops.follow, app.rops.process_cookies);
    // HTTP/1 or HTTP/2 as the request says (Burp's protocol control).
    let h2 = crate::repeater_ops::http2_choice(&request, app.rops.h2_alpn_override, app.rops.h2_strip_connection);
    std::thread::spawn(move || {
        let _tool = net::tool_scope("Repeater");
        let _h2 = net::http2_scope(h2);
        let t0 = std::time::Instant::now();
        let service = crate::repeater_ops::Service::new(&h, p, https);
        let stale = || !sh.rep.is_current(gen);
        // A streaming response shows in the tab as it arrives.
        let progress = |bytes: &[u8], restart: bool| {
            sh.rep.finish_partial(gen, || {
                if let Some(r) = sh.repeaters.lock().unwrap().iter_mut().find(|r| r.id == tab_id) {
                    let shown = r.response.get_or_insert_with(Vec::new);
                    if restart {
                        shown.clear();
                    }
                    shown.extend_from_slice(bytes);
                    r.result_line = format!("Streaming...\t{} bytes", shown.len());
                }
            });
            sh.wake();
        };
        let fr = crate::repeater_ops::send_following(&sh, &request, &service, follow, cookies, &stale, &progress);
        let up = net::Upstream { resp: fr.response, error: fr.error };
        let followed = fr.followed;
        let protocol = net::last_protocol();
        // After followed redirections the tab shows the last request sent
        // and its target, as Burp's item does (Zrr5.ZA), so the history
        // entry and "Follow redirection" continue from the last hop.
        let last = (followed > 0).then_some((fr.request, fr.service));
        let ms = t0.elapsed().as_millis();
        // Cancelled (or superseded) while in flight: nothing is written. The
        // check and the tab write happen under one lock (finish_with), so a
        // Cancel cannot slip in between.
        let mut line = String::new();
        let finished = sh.rep.finish_with(gen, || {
            let mut reps = sh.repeaters.lock().unwrap();
            let target = reps.iter_mut().find(|r| r.id == tab_id);
            if let Some(r) = target {
                r.response = up.resp.clone();
                let mut sent_req = request.clone();
                if let Some((req, svc)) = last {
                    sent_req = req.clone();
                    r.request = req;
                    r.host = svc.host;
                    r.port = svc.port;
                    r.https = svc.https;
                }
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
                        match followed {
                            0 => format!("Done\t{grouped} bytes | {ms} millis | {protocol}"),
                            1 => format!("Done (followed 1 redirection)\t{grouped} bytes | {ms} millis | {protocol}"),
                            n => format!("Done (followed {n} redirections)\t{grouped} bytes | {ms} millis | {protocol}"),
                        }
                    }
                    None => format!("error: {}", up.error.clone().unwrap_or_default()),
                };
                r.history.push((sent_req, r.response.clone(), r.result_line.clone()));
                r.hist_pos = r.history.len() - 1;
            }
            line = reps.iter().find(|r| r.id == tab_id).map(|r| r.result_line.clone()).unwrap_or_default();
            line.clone()
        });
        // Burp reports the outcome in the status line only; errors still toast.
        if let Some(err) = line.strip_prefix("error: ").filter(|_| finished) {
            crate::feedback::toast(crate::feedback::Level::Error, format!("Repeater failed: {err}"));
        }
    });
}

/// Repeater Cancel: abandon the in-flight send. The tab is free at once and
/// the late response, if any, never lands (its generation is stale).
pub(crate) fn cancel_repeater_send(shared: &net::Shared) {
    if let Some(tab) = shared.rep.cancel() {
        // The status line the user sees is the tab's.
        if let Some(r) = shared.repeaters.lock().unwrap().iter_mut().find(|r| r.id == tab) {
            r.result_line = "Request cancelled".into();
        }
    }
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
                let hex = if k == 0 { app.dec_hex } else { app.dec_chain[k - 1].1 };
                egui::Frame::NONE.stroke(egui::Stroke::new(1.0, theme::line())).fill(theme::surface()).show(ui, |ui| {
                    ui.set_width(w);
                    let text: &mut String = if k == 0 { &mut app.dec_input } else { &mut app.dec_chain[k - 1].0 };
                    if hex {
                        let mut shown = util::hex_view(text.as_bytes(), 65536);
                        ui.add(egui::TextEdit::multiline(&mut shown).font(egui::TextStyle::Monospace).desired_rows(6).desired_width(w - 8.0).frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2))).interactive(false));
                    } else {
                        ui.add(egui::TextEdit::multiline(text).font(egui::TextStyle::Monospace).desired_rows(6).desired_width(w - 8.0).frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(4, 2))));
                    }
                });
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.set_width(210.0);
                    ui.horizontal(|ui| {
                        let mut h = hex;
                        if ui.radio(!h, "Text").clicked() { h = false; }
                        if ui.radio(h, "Hex").clicked() { h = true; }
                        if k == 0 { app.dec_hex = h; } else { app.dec_chain[k - 1].1 = h; }
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

// ================= hotkeys =================

/// Run one command from the hotkey table. Ids are Burp's own
/// (`burp.Zmcg.ZB()`), so a shortcut can be traced back to the reference build.
fn run_shortcut(app: &mut App, idx: usize) {
    use crate::shortcuts::ACTIONS;
    let Some(def) = ACTIONS.get(idx) else { return };
    match def.id {
        // In Repeater, Burp sends the current tab's request (Ctrl+R opens a
        // copy in a new tab, Ctrl+I loads it into Intruder); elsewhere the
        // selected history item.
        "send_to_repeater" if app.tab == Tab::Repeater => repeater_tab_to_new_tab(app),
        "send_to_intruder" if app.tab == Tab::Repeater => repeater_tab_to_intruder(app),
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
        "forward_intercepted_proxy_message" => {
            // The message on screen, with its edits (Burp forwards the selection).
            let done = app.intercept_cur.take().is_some_and(|id| net::intercept_release(&app.shared, id, false, Some(app.intercept_text.clone())));
            if !done {
                net::intercept_forward(&app.shared, false);
            }
        }
        "toggle_proxy_interception" => {
            let now = !app.shared.intercept_on.load(Ordering::SeqCst);
            set_intercept(app, now);
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
        ui.close();
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
    let oob: Vec<(String, String, String)> = scan::oob_slots(&app.shared, &e.req_raw)
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
    let name = format!("Active scan of {}", history_url(e));
    crate::tasks::enqueue(&app.shared, name, crate::tasks::TaskKind::Single { entry: e.clone(), oob, smtp });
    feedback::toast(feedback::Level::Info, "Active scan queued");
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

/// "Copy as curl command (bash)": Burp's curl line (Zc2z) for the request.
fn curl_command_of(e: &net::HistEntry) -> String {
    crate::repeater_ops::curl_command(&e.req_raw, &history_url(e))
}

/// Links found in a response body (href/src/action attribute values and bare
/// absolute URLs), for "Copy links in response".
fn links_in_response(e: &net::HistEntry) -> String {
    let Some(resp) = &e.resp_raw else { return String::new() };
    let rp = util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
    let mut links = Vec::new();
    for attr in ["href", "src", "action"] {
        // Every index is into `rest` and `rest` only moves forward: the old
        // loop indexed the whole body with an offset found in `rest`, which
        // looped forever (or panicked inside a multi-byte character) from
        // the second link on.
        let needle = format!("{attr}=\"");
        let mut rest = body.as_ref();
        while let Some(at) = rest.find(&needle) {
            rest = &rest[at + needle.len()..];
            let Some(end) = rest.find('"') else { break };
            let link = &rest[..end];
            if (link.starts_with("http://") || link.starts_with("https://")) && !links.contains(&link) {
                links.push(link);
            }
            rest = &rest[end + 1..];
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
    let entry = app.shared.history.get(id);
    if let Some(e) = entry {
        let mut reps = app.shared.repeaters.lock().unwrap();
        let id = app.shared.rep.new_tab_id();
        reps.push(net::RepTab {
            id,
            name: id.to_string(),
            host: e.host.clone(),
            port: e.port,
            https: e.https,
            request: request_for_tools(&e.req_raw),
            // Burp opens a new Repeater tab with no response until Send.
            response: None,
            result_line: String::new(),
            history: Vec::new(),
            hist_pos: 0,
        ws: None,
        });
        app.rep_sel = reps.len() - 1;
        app.tab = Tab::Repeater;
    }
}

/// The selected Repeater tab's (request, https, host, port).
fn current_repeater(app: &App) -> Option<(String, bool, String, u16)> {
    let reps = app.shared.repeaters.lock().unwrap();
    let r = reps.get(app.rep_sel.min(reps.len().saturating_sub(1)))?;
    Some((r.request.clone(), r.https, r.host.clone(), r.port))
}

fn repeater_tab_to_intruder(app: &mut App) {
    let Some((req, https, _, _)) = current_repeater(app) else { return };
    if req.trim().is_empty() {
        feedback::toast(feedback::Level::Warn, "The Repeater tab has no request");
        return;
    }
    app.intr_req = req;
    app.intr_https = https;
    app.tab = Tab::Intruder;
}

fn repeater_tab_to_new_tab(app: &mut App) {
    let Some((request, https, host, port)) = current_repeater(app) else { return };
    let mut reps = app.shared.repeaters.lock().unwrap();
    let id = app.shared.rep.new_tab_id();
    reps.push(net::RepTab {
        id,
        name: id.to_string(),
        host,
        port,
        https,
        request,
        response: None,
        result_line: String::new(),
        history: Vec::new(),
        hist_pos: 0,
    ws: None,
    });
    app.rep_sel = reps.len() - 1;
}

pub fn send_history_to_intruder(app: &mut App) {
    let Some(id) = app.history_sel else { return };
    let entry = app.shared.history.get(id);
    if let Some(e) = entry {
        app.intr_req = request_for_tools(&e.req_raw);
        app.intr_https = e.https;
        app.tab = Tab::Intruder;
    }
}

/// Burp's per-type payload configuration panels for the generated types.
fn payload_source_config(ui: &mut Ui, src: &mut intruder::PayloadSource) {
    use intruder::PayloadSource as P;
    fn note(ui: &mut Ui, t: &str) {
        ui.label(RichText::new(t).size(12.0).color(theme::ink_dim()));
        ui.add_space(6.0);
    }
    fn row(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
        ui.horizontal(|ui| {
            ui.add_sized([120.0, 20.0], egui::Label::new(RichText::new(label).size(12.5).color(theme::ink())));
            add(ui);
        });
    }
    match src {
        P::SimpleList { .. } => {}
        P::RuntimeFile { path } => {
            note(ui, "This payload type lets you configure a file from which to read payload strings at runtime.");
            row(ui, "Select file:", |ui| {
                ui.add(egui::TextEdit::singleline(path).hint_text("/path/to/payloads.txt").desired_width(230.0));
            });
        }
        P::Numbers { from, to, step, base, min_digits, .. } => {
            note(ui, "This payload type generates numeric payloads within a given range and in a specified format.");
            row(ui, "From:", |ui| { ui.add(egui::DragValue::new(from)); });
            row(ui, "To:", |ui| { ui.add(egui::DragValue::new(to)); });
            row(ui, "Step:", |ui| { ui.add(egui::DragValue::new(step).range(1..=i64::MAX)); });
            row(ui, "Base:", |ui| {
                ui.radio_value(base, intruder::NumberBase::Decimal, "Decimal");
                ui.radio_value(base, intruder::NumberBase::Hex, "Hex");
            });
            row(ui, "Min integer digits:", |ui| { ui.add(egui::DragValue::new(min_digits).range(0..=64)); });
        }
        P::Dates { from, to, step_secs, format } => {
            note(ui, "This payload type generates date payloads within a given range and in a specified format (UTC).");
            row(ui, "From (Unix time):", |ui| { ui.add(egui::DragValue::new(from)); });
            row(ui, "To (Unix time):", |ui| { ui.add(egui::DragValue::new(to)); });
            row(ui, "Step (seconds):", |ui| { ui.add(egui::DragValue::new(step_secs).range(1..=u64::MAX)); });
            row(ui, "Format:", |ui| { ui.add(egui::TextEdit::singleline(format).desired_width(160.0)); });
        }
        P::BruteForcer { charset, min_len, max_len } => {
            note(ui, "This payload type generates payloads of specified lengths that contain all permutations of a specified character set.");
            row(ui, "Character set:", |ui| { ui.add(egui::TextEdit::singleline(charset).desired_width(230.0)); });
            row(ui, "Min length:", |ui| { ui.add(egui::DragValue::new(min_len).range(0..=32)); });
            row(ui, "Max length:", |ui| { ui.add(egui::DragValue::new(max_len).range(0..=32)); });
        }
        P::NullPayloads { count } => {
            note(ui, "This payload type generates payloads whose value is an empty string. With no payload markers configured, this can be used to repeatedly issue the base request unmodified.");
            row(ui, "Generate:", |ui| { ui.add(egui::DragValue::new(count).range(1..=1_000_000)); ui.label("payloads"); });
        }
        P::CaseModification { items, no_change, lower, upper, propername, proper_name } => {
            note(ui, "This payload type lets you configure a list of strings and apply various case modifications to each item on the list.");
            let mut text = items.join("\n");
            // split('\n') keeps the trailing empty line so Enter starts a new item;
            // generate() skips blank items.
            if ui.add(egui::TextEdit::multiline(&mut text).desired_rows(5).desired_width(ui.available_width() - 8.0).font(egui::TextStyle::Monospace)).changed() {
                *items = text.split('\n').map(str::to_string).collect();
            }
            ui.checkbox(no_change, "No change");
            ui.checkbox(lower, "To lower case");
            ui.checkbox(upper, "To upper case");
            ui.checkbox(propername, "To Propername");
            ui.checkbox(proper_name, "To ProperName");
        }
        P::CharacterFrobber { base } => {
            note(ui, "This payload type operates on the base value of the payload position and modifies the value of each character position in turn by incrementing its ASCII code by one.");
            row(ui, "Base value:", |ui| { ui.add(egui::TextEdit::singleline(base).desired_width(230.0)); });
        }
        P::CharacterBlocks { base, min_len, max_len } => {
            note(ui, "This payload type generates blocks of a given input string, with specified lengths.");
            row(ui, "Base string:", |ui| { ui.add(egui::TextEdit::singleline(base).desired_width(230.0)); });
            row(ui, "Min length:", |ui| { ui.add(egui::DragValue::new(min_len).range(0..=100_000)); });
            row(ui, "Max length:", |ui| { ui.add(egui::DragValue::new(max_len).range(0..=100_000)); });
        }
        _ => crate::intruder_ui::source_config(ui, &mut *src),
    }
    ui.add_space(4.0);
    ui.label(RichText::new(crate::intruder_ui::generated_note(src)).size(12.0).color(theme::ink_hint()));
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
        // B-09: WebSockets history with direction/search filters.
        2 => crate::repeater_ops::ws_history_view(app, ui),
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
    // [Drop] ... [Open browser] (?) (Options), then the held-messages table
    // and the selected message, or the "Intercept is off/on" empty state.
    // Held items stay queued (the proxy keeps waiting) until Forward or Drop.
    // P-06/B-09: the table lists HTTP requests and WebSocket messages; the
    // Options button (Burp's Zube) picks its columns.
    let on = app.shared.intercept_on.load(Ordering::SeqCst);
    let rows = crate::repeater_ops::held_rows(&app.shared);
    // Keep the selected row while it is held; otherwise the oldest.
    if !rows.iter().any(|r| Some(r.id) == app.rops.intercept_sel) {
        app.rops.intercept_sel = rows.first().map(|r| r.id);
    }
    let head = {
        let q = app.shared.queue.lock().unwrap();
        app.rops
            .intercept_sel
            .and_then(|id| q.iter().find(|i| i.id == id))
            .map(|i| (i.id, i.host.clone(), i.port, i.edited.clone(), i.kind, q.len()))
    };
    let mut forward = false;
    let mut drop = false;
    ui.horizontal(|ui| {
        ui.add_space(14.0);
        let label = format!("{}  Intercept {}", if on { theme::icon::TOGGLE_RIGHT } else { theme::icon::TOGGLE_LEFT }, if on { "on" } else { "off" });
        let b = egui::Button::new(RichText::new(label).strong().color(if on { egui::Color32::WHITE } else { theme::ink() }))
            .fill(if on { c(0x26649D) } else { theme::header_bg() })
            .min_size(egui::vec2(160.0, 22.0));
        if ui.add(b).on_hover_text("Toggle message interception (Ctrl+T)").clicked() {
            set_intercept(app, !on);
        }
        ui.add_space(8.0);
        let has = head.is_some();
        // Burp's split buttons: the arrow picks the mode, the button runs it.
        let fwd_label = if app.intercept_fwd_all { "Forward all" } else { "Forward" };
        if ui.add_enabled(has, egui::Button::new(RichText::new(format!("{}  {fwd_label}", theme::icon::ARROW_RIGHT)).strong()).min_size(egui::vec2(140.0, 22.0))).clicked() {
            forward = true;
        }
        ui.menu_button(RichText::new("\u{25BE}").size(12.0), |ui| {
            if ui.selectable_label(!app.intercept_fwd_all, "Forward").clicked() {
                app.intercept_fwd_all = false;
                ui.close();
            }
            if ui.selectable_label(app.intercept_fwd_all, "Forward all").clicked() {
                app.intercept_fwd_all = true;
                ui.close();
            }
        });
        ui.add_space(8.0);
        let drop_label = if app.intercept_drop_all { "Drop all" } else { "Drop" };
        if ui.add_enabled(has, egui::Button::new(RichText::new(drop_label).strong()).min_size(egui::vec2(140.0, 22.0))).clicked() {
            drop = true;
        }
        ui.menu_button(RichText::new("\u{25BE}").size(12.0), |ui| {
            if ui.selectable_label(!app.intercept_drop_all, "Drop").clicked() {
                app.intercept_drop_all = false;
                ui.close();
            }
            if ui.selectable_label(app.intercept_drop_all, "Drop all").clicked() {
                app.intercept_drop_all = true;
                ui.close();
            }
        });
        if let Some((_, _, _, _, _, n)) = &head {
            ui.add_space(10.0);
            ui.label(RichText::new(format!("{n} held")).size(12.5).color(theme::ink_dim()));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(10.0);
            // P-06: Burp's overflow ("Options") button at the far right.
            egui::menu::MenuButton::new(RichText::new(theme::icon::DOTS_THREE_VERTICAL).size(14.0)).config(egui::menu::MenuConfig::new().close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)).ui(ui, |ui| {
                crate::repeater_ops::intercept_options_menu(ui, &mut app.rops);
            })
            .0
            .on_hover_text("Options");
            let _ = ui.add(egui::Button::new(RichText::new(theme::icon::QUESTION).size(16.0)).frame(false)).on_hover_text("Held messages wait here until you forward or drop them.");
            if ui.add(egui::Button::new(RichText::new(format!("{}  Open browser", theme::icon::GLOBE)).strong()).min_size(egui::vec2(140.0, 22.0))).on_hover_text("Open pre-configured browser").clicked() {
                match crate::tools::launch_preconfigured_browser(&app.shared) {
                    Ok(name) => feedback::toast(feedback::Level::Success, format!("Launched {name} with the proxy preconfigured")),
                    Err(e) => feedback::toast(feedback::Level::Error, e),
                }
            }
        });
    });
    ui.add_space(8.0);

    let Some((id, host, port, edited, kind, _)) = head else {
        ui.add_space(ui.available_height() * 0.28);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::TRAFFIC_SIGNAL).size(56.0).color(c(0x26649D)));
            ui.add_space(8.0);
            ui.label(RichText::new(if on { "Intercept is on" } else { "Intercept is off" }).strong().size(18.0).color(theme::ink()));
            ui.add_space(8.0);
            ui.label(RichText::new(if on {
                "Messages between WebProbe's browser and your target servers are held here. This enables you to analyze and modify these messages, before you forward them."
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
        // Switching rows keeps the edit made to the previous message.
        if let Some(prev) = app.intercept_cur {
            if let Some(item) = app.shared.queue.lock().unwrap().iter_mut().find(|i| i.id == prev) {
                item.edited = app.intercept_text.clone();
            }
        }
        app.intercept_cur = Some(id);
        app.intercept_text = edited;
    }
    let table_h = (rows.len() as f32 * 20.0 + 4.0).clamp(24.0, 140.0);
    crate::repeater_ops::intercept_table(ui, &mut app.rops, &rows, table_h);
    ui.add_space(6.0);
    let (heading, title) = match kind {
        net::InterceptKind::Request { https } => {
            let svc = crate::repeater_ops::Service::new(&host, port, https || port == 443);
            (format!("Request to {}", svc.origin()), "Request")
        }
        net::InterceptKind::Response { https } => {
            let svc = crate::repeater_ops::Service::new(&host, port, https || port == 443);
            (format!("Response from {}", svc.origin()), "Response")
        }
        net::InterceptKind::WebSocket { to_server: true } => (format!("WebSocket message to server {host}"), "Message"),
        net::InterceptKind::WebSocket { to_server: false } => (format!("WebSocket message to client from {host}"), "Message"),
    };
    ui.horizontal(|ui| {
        ui.add_space(14.0);
        ui.label(RichText::new(heading).strong().size(13.0).color(theme::ink()));
    });
    let h = ui.available_height();
    // A WebSocket payload is not an HTTP message: pasted LF stays LF.
    app.intercept_pane.crlf_paste = matches!(kind, net::InterceptKind::Request { .. } | net::InterceptKind::Response { .. });
    crate::msgpane::editable_pane(ui, "intercept_edit", title, &mut app.intercept_text, &mut app.intercept_pane, h);
    if forward || drop {
        let all = if drop { app.intercept_drop_all } else { app.intercept_fwd_all };
        if all {
            if let Some(item) = app.shared.queue.lock().unwrap().iter_mut().find(|i| i.id == id) {
                item.edited = app.intercept_text.clone();
            }
            let n = net::intercept_release_all(&app.shared, drop);
            app.shared.log(&format!("{} {n} held message(s)", if drop { "dropped" } else { "forwarded" }));
        } else {
            net::intercept_release(&app.shared, id, drop, (!drop).then(|| app.intercept_text.clone()));
            app.shared.log(&format!("{} {host} message", if drop { "dropped" } else { "forwarded" }));
        }
        app.intercept_cur = None;
        app.rops.intercept_sel = None;
    }
}

/// Intercept on/off. Turning it off releases every held message unchanged
/// except for edits already made, as Burp forwards automatically while off.
fn set_intercept(app: &mut App, on: bool) {
    if !on {
        if let Some(id) = app.intercept_cur.take() {
            if let Some(item) = app.shared.queue.lock().unwrap().iter_mut().find(|i| i.id == id) {
                item.edited = app.intercept_text.clone();
            }
        }
    }
    net::set_intercept(&app.shared, on);
}

// ================= Listeners (A-07) =================

// ================= Settings window =================

/// Which page of the Settings window is showing (Burp: Settings is its own
/// window, not a tab).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingsPane {
    Appearance,
    Hotkeys,
    Proxy,
    Sessions,
    Intruder,
    Repeater,
    Sequencer,
    Comparer,
    Scope,
    Collaborator,
    Tasks,
    Network,
    Suite,
    Extensions,
    ConfigurationLibrary,
}

fn settings_window(app: &mut App, ctx: &egui::Context) {
    // Report, Find results, Discover content and crash-recovery windows
    // (engagement.rs); drawn here because this runs every frame on any tab.
    crate::engagement::windows(app, ctx);
    crate::settings_dialog::window(app, ctx);
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
    egui::Window::new("Event log").default_pos(crate::theme::window_pos(&ctx))
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
    egui::Window::new("Search").default_pos(crate::theme::window_pos(&ctx))
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
    ui.scope_builder(egui::UiBuilder::new().max_rect(hero.shrink2(egui::vec2(r.width() * 0.3, 80.0))), |ui| {
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
    if !app.onboarding_hidden && crate::onboarding::panel(app, ui) {
        app.onboarding_hidden = true;
    }
}

// ================= Dashboard =================

fn dashboard(app: &mut App, ui: &mut Ui) {
    // Burp's Dashboard (live 52685 reference): optional "Task execution is
    // paused" banner, a Tasks rail on the left (New scan / New live task,
    // filter + search, one card per task) and the selected task on the right
    // with Summary | Audit items | Issues | Event log | Logger | Audit log.
    let live_on = app.shared.scan_enabled.load(Ordering::SeqCst);
    if !live_on {
        let r = ui.available_rect_before_wrap();
        let band = egui::Rect::from_min_size(r.min - egui::vec2(10.0, 10.0), egui::vec2(r.width() + 20.0, 28.0));
        ui.painter().rect_filled(band, 0.0, c(0xEBF1F6));
        ui.scope_builder(egui::UiBuilder::new().max_rect(band), |ui| {
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
    let scan_total = app.shared.scan.total.load(Ordering::SeqCst);
    let busy = app.shared.scan.is_busy();
    let has_active = scan_total > 0 || busy;
    // Scan tasks have card ids 1000 + task id (0 and 1 are the live tasks).
    let task_list: Vec<crate::tasks::ScanTask> = app.shared.tasks.lock().unwrap().clone();
    let card_task = |id: usize| -> Option<&crate::tasks::ScanTask> { id.checked_sub(1000).and_then(|t| task_list.iter().find(|x| x.id as usize == t)) };
    if (app.dash_task == 2 && !(has_active && app.shared.scan.direct.load(Ordering::SeqCst))) || (app.dash_task >= 1000 && card_task(app.dash_task).is_none()) {
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
                for t in task_list.iter().rev() {
                    let progress = match (t.state, t.total) {
                        (crate::tasks::TaskState::Running, Some(n)) => format!("Auditing: {} of {n} items", t.done),
                        (crate::tasks::TaskState::Running, None) => format!("Crawling and auditing: request {} of {}", app.shared.scan.done.load(Ordering::SeqCst), scan_total),
                        (s, Some(n)) => format!("{}: {} of {n} items", s.label(), t.done),
                        (s, None) => s.label().to_string(),
                    };
                    cards.push((1000 + t.id as usize, format!("{}. {}", t.id + 2, t.name), progress, false));
                }
                if has_active && app.shared.scan.direct.load(Ordering::SeqCst) {
                    let done = app.shared.scan.done.load(Ordering::SeqCst);
                    cards.push((2, format!("{}. Active scan", app.shared.next_task_id.load(Ordering::SeqCst) + 2), if busy { format!("Auditing: {done} of {scan_total} requests") } else { format!("Finished: {done} requests") }, false));
                }
                cards.push((1, "2. Live audit from Proxy (all traffic)".into(), "Audit checks - passive".into(), true));
                cards.push((0, "1. Live passive crawl from Proxy (all traffic)".into(), "Add links. Add item itself, same domain and URLs in suite scope.".into(), true));
                let q = app.dash_search.to_ascii_lowercase();
                for (id, title, sub, capturing) in cards {
                    if !q.is_empty() && !title.to_ascii_lowercase().contains(&q) {
                        continue;
                    }
                    let sel = app.dash_task == id;
                    // The card's click area goes in before its contents, so
                    // the menu and pause buttons stay on top of it (egui hit-
                    // tests the last widget first). Its size is last frame's.
                    let rect_key = egui::Id::unique(("dash-card-rect", id));
                    let card_click = ui
                        .data(|d| d.get_temp::<egui::Rect>(rect_key))
                        .map(|r| ui.interact(r, egui::Id::unique(("dash-card", id)), egui::Sense::click()));
                    let frame = egui::Frame::NONE
                        .fill(if sel { c(0xEBF1F6) } else { theme::surface() })
                        .stroke(egui::Stroke::new(1.0, theme::line()))
                        .corner_radius(4.0)
                        .inner_margin(egui::Margin::symmetric(14, 10))
                        .outer_margin(egui::Margin::symmetric(8, 4));
                    let resp = frame
                        .show(ui, |ui| {
                            ui.set_width(rail_w - 46.0);
                            ui.horizontal(|ui| {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    // Buttons first (right to left), then the title in what
                                    // is left, truncated, so a long URL never runs under them.
                                    let title_label = |ui: &mut Ui| {
                                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                            ui.add(egui::Label::new(RichText::new(&title).strong().size(13.0).color(theme::ink())).truncate().selectable(false));
                                        });
                                    };
                                    // Per-task pause and menu (Burp: pause/resume, view details).
                                    let flag = match id {
                                        0 => Some(&app.shared.crawl_capture),
                                        1 => Some(&app.shared.scan_enabled),
                                        _ => None,
                                    };
                                    if let Some(t) = card_task(id) {
                                        // A scan task: pause/resume, cancel, remove.
                                        let (tid, state) = (t.id, t.state);
                                        ui.menu_button(RichText::new(theme::icon::DOTS_THREE_VERTICAL).size(14.0), |ui| {
                                            if state == crate::tasks::TaskState::Paused {
                                                if ui.button("Resume task").clicked() {
                                                    crate::tasks::resume(&app.shared, tid);
                                                    ui.close();
                                                }
                                            } else if ui.add_enabled(state.is_open(), egui::Button::new("Pause task")).clicked() {
                                                crate::tasks::pause(&app.shared, tid);
                                                ui.close();
                                            }
                                            if ui.add_enabled(state.is_open(), egui::Button::new("Cancel task")).clicked() {
                                                crate::tasks::cancel(&app.shared, tid);
                                                ui.close();
                                            }
                                            if ui.add_enabled(!state.is_open(), egui::Button::new("Delete task")).clicked() {
                                                crate::tasks::remove(&app.shared, tid);
                                                ui.close();
                                            }
                                        });
                                        if state.is_open() {
                                            let paused = state == crate::tasks::TaskState::Paused;
                                            let glyph = if paused { theme::icon::PLAY_CIRCLE } else { theme::icon::PAUSE_CIRCLE };
                                            if ui.add(egui::Button::new(RichText::new(glyph).size(14.0)).frame(false)).on_hover_text(if paused { "Resume" } else { "Pause" }).clicked() {
                                                if paused {
                                                    crate::tasks::resume(&app.shared, tid);
                                                } else {
                                                    crate::tasks::pause(&app.shared, tid);
                                                }
                                            }
                                        }
                                        title_label(ui);
                                        return;
                                    }
                                    let running = flag.map(|f| f.load(Ordering::SeqCst)).unwrap_or(busy);
                                    ui.menu_button(RichText::new(theme::icon::DOTS_THREE_VERTICAL).size(14.0), |ui| {
                                        if let Some(f) = flag {
                                            if ui.button(if running { "Pause task" } else { "Resume task" }).clicked() {
                                                f.store(!running, Ordering::SeqCst);
                                                ui.close();
                                            }
                                        } else if ui.add_enabled(busy, egui::Button::new("Stop scan")).clicked() {
                                            app.shared.scan.stop.store(true, Ordering::SeqCst);
                                            ui.close();
                                        }
                                        if ui.button("View details").clicked() {
                                            app.dash_task = id;
                                            ui.close();
                                        }
                                    });
                                    let glyph = if running { theme::icon::PAUSE_CIRCLE } else { theme::icon::PLAY_CIRCLE };
                                    if ui.add(egui::Button::new(RichText::new(glyph).size(14.0)).frame(false)).on_hover_text(if running { "Pause" } else { "Resume" }).clicked() {
                                        match flag {
                                            Some(f) => f.store(!running, Ordering::SeqCst),
                                            None => app.shared.scan.stop.store(true, Ordering::SeqCst),
                                        }
                                    }
                                    title_label(ui);
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
                                            egui::Frame::NONE.fill(c(col)).corner_radius(8.0).inner_margin(egui::Margin::symmetric(9, 1)).show(ui, |ui| {
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
                    ui.data_mut(|d| d.insert_temp(rect_key, resp.rect));
                    if card_click.is_some_and(|r| r.clicked()) {
                        app.dash_task = id;
                    }
                }
            });
            // ---------------- Selected task ----------------
            strip.cell(|ui| {
                let task_title;
                let title = match app.dash_task {
                    0 => "1. Live passive crawl from Proxy (all traffic)",
                    2 => {
                        task_title = format!("{}. Active scan", app.shared.next_task_id.load(Ordering::SeqCst) + 2);
                        task_title.as_str()
                    }
                    id if id >= 1000 => {
                        task_title = card_task(id).map(|t| format!("{}. {} \u{2014} {}, {} issue(s)", t.id + 2, t.name, t.state.label(), t.issues_found)).unwrap_or_default();
                        task_title.as_str()
                    }
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
                        let rows: Vec<net::HistEntry> = app.shared.history.with_rows(|h| h.iter().rev().take(2000).cloned().collect());
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
        egui::Window::new("New scan").default_pos(crate::theme::window_pos(ui.ctx()))
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
                ui.label(RichText::new("Crawl and audit follows links, robots.txt and sitemap.xml from each URL on the same origin within the scan configuration's crawl limits, then audits every item found. Audit selected items audits only the URLs listed.").size(12.0).color(theme::ink_hint()));
                ui.add_space(8.0);
                crate::scan_library_ui::launch_picker(app, ui);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ok = egui::Button::new(RichText::new("OK").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1)).min_size(egui::vec2(70.0, 24.0));
                    if ui.add(ok).clicked() {
                        let urls: Vec<String> = app.new_scan_urls.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
                        let applied = crate::scan_library_ui::apply_launch(app);
                        if !applied.is_empty() {
                            app.shared.log(&format!("Scan configuration from library: {}", applied.join(", ")));
                        }
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
        egui::Frame::NONE
            .fill(theme::chrome())
            .corner_radius(4.0)
            .inner_margin(egui::Margin::same(14))
            .outer_margin(egui::Margin::symmetric(10, 6))
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
                    egui::Frame::NONE.stroke(egui::Stroke::new(1.0, theme::line())).show(ui, |ui| {
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
                let total = app.shared.history.len();
                let (done, all, busy) = (
                    app.shared.scan.done.load(Ordering::SeqCst),
                    app.shared.scan.total.load(Ordering::SeqCst),
                    app.shared.scan.is_busy(),
                );
                let msgs = app.shared.messages.load(Ordering::SeqCst);
                let (audited, net_errors) = {
                    app.shared.history.with_rows(|h| (h.iter().filter(|e| e.audited).count(), h.iter().filter(|e| e.resp_raw.is_none()).count()))
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
    let audit_only = app.new_scan_type == 1;
    let name = format!("{} of {}", if audit_only { "Audit" } else { "Crawl and audit" }, urls.first().cloned().unwrap_or_default());
    crate::tasks::enqueue(&app.shared, name, crate::tasks::TaskKind::CrawlAudit { urls, audit_only });
}

// ================= Target =================

/// One node of the site map tree.
#[derive(Default)]
pub(crate) struct MapNode {
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
                .corner_radius(2.0);
            if ui.add(b).clicked() {
                app.target_view = i;
            }
        }
    });
    ui.add_space(4.0);
    // Burp's site map filter: text, in-scope only, unrequested items.
    ui.horizontal(|ui| {
        ui.label(RichText::new(theme::icon::FUNNEL).size(13.0).color(theme::ink_dim()));
        ui.add(egui::TextEdit::singleline(&mut app.site_filter.text).hint_text("Filter by host or path").desired_width(220.0));
        ui.checkbox(&mut app.site_filter.in_scope_only, "Show only in-scope items");
        ui.checkbox(&mut app.site_filter.hide_unrequested, "Hide unrequested items");
    });
    ui.add_space(4.0);

    // The site contents are rebuilt only when the history, the crawl, the
    // scope or the filter changed, not on every frame.
    let (hist_len, crawl_len) = (app.shared.history.len(), app.shared.crawl_items.len());
    let scope_key = app.shared.scope.lock().unwrap().iter().map(|r| format!("{}{}{}{}", r.enabled, r.include, r.is_regex, r.pattern)).collect::<Vec<_>>().join("|");
    let key = format!("{hist_len}|{crawl_len}|{}|{}|{}|{scope_key}", app.site_filter.text, app.site_filter.in_scope_only, app.site_filter.hide_unrequested);
    if key != app.site_cache_key {
        let mut all: Vec<net::HistEntry> = app.shared.history.snapshot();
        // Crawler requests are site-map contents too (Burp keeps them out of
        // Proxy history but in the site map).
        all.extend(app.shared.crawl_items.snapshot().iter().cloned());
        let shared = app.shared.clone();
        let filter = app.site_filter.clone();
        let kept: Vec<net::HistEntry> = all.into_iter().filter(|e| filter.keeps(&history_host(e), &e.path, || net::in_scope(&shared, &history_url(e)))).collect();
        let links: Vec<(String, String)> = if filter.hide_unrequested {
            Vec::new()
        } else {
            app.shared.site_links.lock().unwrap().iter().filter(|(o, p)| filter.keeps(o, p, || net::in_scope(&shared, &format!("{o}{p}")))).cloned().collect()
        };
        app.site_cache = std::sync::Arc::new((kept, links));
        app.site_cache_key = key;
    }
    let cache = app.site_cache.clone();
    let entries: &Vec<net::HistEntry> = &cache.0;
    let links: &Vec<(String, String)> = &cache.1;
    // Issue markers: the most severe issue under each node gets a dot.
    let issue_marks: Vec<(String, String, usize)> = app
        .shared
        .issues
        .lock()
        .unwrap()
        .iter()
        .filter(|i| !i.false_positive)
        .map(|i| (i.host.clone(), i.path.clone(), crate::report::severity_index(&i.sev)))
        .collect();
    let scope_set = app.shared.scope.lock().unwrap().iter().any(|r| r.enabled && r.include);
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
    // the live passive crawl (shown grey, as in Burp). Rebuilt only when the
    // contents or the view change: rebuilding it every frame cost ~100 ms a
    // frame with 10k items.
    let tree_key = format!("{}|{}", app.site_cache_key, app.target_view);
    if tree_key != app.site_tree_key {
        let mut roots: std::collections::BTreeMap<String, MapNode> = std::collections::BTreeMap::new();
        for e in entries.iter() {
            let segs = path_segments(&e.path);
            let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
            let root = roots.entry(history_host(e)).or_default();
            if refs.is_empty() { root.requested = true; } else { root.insert(&refs, true); }
        }
        if app.target_view == 0 {
            for (origin, path) in links.iter() {
                let segs = path_segments(path);
                let refs: Vec<&str> = segs.iter().map(String::as_str).collect();
                roots.entry(origin.clone()).or_default().insert(&refs, false);
            }
        }
        app.site_tree = std::sync::Arc::new(roots);
        app.site_tree_key = tree_key;
    }
    let roots_arc = app.site_tree.clone();
    let roots = &*roots_arc;

    // Tree | contents divider: draggable, kept in the project layout.
    let map_w = ui.available_width().max(500.0);
    let tree_w = (map_w * app.map_split).clamp(180.0, map_w - 300.0);
    let map_top = ui.cursor().min;
    let map_h = ui.available_height();
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
                        for (origin, path) in links.iter() {
                            let label = format!("{origin}{path}");
                            let sel = app.target_node.as_ref() == Some(&(origin.clone(), path.clone()));
                            if ui.selectable_label(sel, RichText::new(label).size(12.5).color(theme::ink_faint())).clicked() {
                                app.target_node = Some((origin.clone(), path.clone()));
                            }
                        }
                        return;
                    }
                    struct Marks<'a> {
                        issues: &'a [(String, String, usize)],
                        scope_set: bool,
                    }
                    fn draw(ui: &mut Ui, app: &mut App, marks: &Marks, origin: &str, prefix: &str, name: &str, node: &MapNode, depth: usize) {
                        let full = format!("{prefix}{name}");
                        let sel = app.target_node.as_ref().map(|(o, p)| o == origin && p == &full).unwrap_or(false);
                        // Burp: unrequested items grey; with a scope defined,
                        // hosts outside it grey and in-scope hosts in bold.
                        let in_scope = depth > 0 || !marks.scope_set || net::in_scope(&app.shared, origin);
                        let colour = if node.any_requested() && in_scope { theme::ink() } else { theme::ink_hint() };
                        let icon = if node.children.is_empty() { theme::icon::FILE } else { theme::icon::FOLDER };
                        let mut text = RichText::new(format!("{icon} {}", if depth == 0 { origin } else { name })).size(12.5).color(colour);
                        if depth == 0 && marks.scope_set && in_scope {
                            text = text.strong();
                        }
                        let host = crate::engagement::origin_host(origin);
                        let worst = crate::site_map::worst_issue(marks.issues, host, &full);
                        let dot = |ui: &mut Ui| {
                            if let Some(rank) = worst {
                                let sev = ["high", "medium", "low", "info"][rank.min(3)];
                                ui.label(RichText::new("\u{25cf}").size(10.0).color(scan_sev_color(sev))).on_hover_text(format!("{} issue(s) here", crate::report::SEVERITIES[rank.min(3)]));
                            }
                        };
                        if node.children.is_empty() {
                            ui.horizontal(|ui| {
                                ui.add_space(18.0);
                                let r = ui.selectable_label(sel, text);
                                dot(ui);
                                if r.clicked() {
                                    app.target_node = Some((origin.to_string(), full.clone()));
                                }
                                // L-02: copy URLs / Engagement tools.
                                r.context_menu(|ui| crate::engagement::site_map_menu(ui, app, origin, &full));
                            });
                        } else {
                            let id = ui.make_persistent_id(("site", origin, &full));
                            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, depth == 0)
                                .show_header(ui, |ui| {
                                    let r = ui.selectable_label(sel, text);
                                    dot(ui);
                                    if r.clicked() {
                                        app.target_node = Some((origin.to_string(), full.clone()));
                                    }
                                    r.context_menu(|ui| crate::engagement::site_map_menu(ui, app, origin, &full));
                                })
                                .body(|ui| {
                                    for (child, n) in &node.children {
                                        draw(ui, app, marks, origin, &full, child, n, depth + 1);
                                    }
                                });
                        }
                    }
                    let marks = Marks { issues: &issue_marks, scope_set };
                    for (origin, node) in roots {
                        draw(ui, app, &marks, origin, "/", "", node, 0);
                    }
                });
            });
            strip.cell(|ui| {
                // The selected node's items, as indices into the cached
                // contents, recomputed only when the contents or the node
                // change (cloning every entry each frame cost ~40 ms at 10k).
                let (origin, prefix) = app.target_node.clone().unwrap_or_default();
                let rows_key = format!("{}|{origin}|{prefix}", app.site_tree_key);
                if rows_key != app.site_rows_key {
                    app.site_rows = std::sync::Arc::new(
                        entries
                            .iter()
                            .enumerate()
                            .filter(|(_, e)| origin.is_empty() || (e.path.starts_with(&prefix) && history_host(e) == origin))
                            .map(|(i, _)| i)
                            .collect(),
                    );
                    app.site_rows_key = rows_key;
                }
                let row_idx = app.site_rows.clone();
                let rows: Vec<&net::HistEntry> = row_idx.iter().filter_map(|&i| entries.get(i)).collect();
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
                                table::Column::new("Comment", 140.0),
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
                                        (8, e.note.clone().unwrap_or_default(), None),
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
    vsplit_handle(ui, "map_split", map_top.x + tree_w, map_top.y..=map_top.y + map_h, &mut app.map_split, map_w);
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
                            // The row's click area is registered before its
                            // cells, under an id unique to this table and row,
                            // so a click lands even when press and release come
                            // in one frame (automation) and the two tables'
                            // rows never share an id.
                            let row = ui.interact(rr, egui::Id::unique(("comparer-row", k, *i)), egui::Sense::click());
                            ui.horizontal(|ui| {
                                table::cells(ui, &cols, &table::TableState::default(), 19.0, &[
                                    (0, (i + 1).to_string(), None),
                                    (1, d.len().to_string(), None),
                                    (2, preview, None),
                                ]);
                            });
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
                ui.add_space((ui.available_height() - 108.0).max(10.0));
                ui.label(RichText::new("Compare ...").size(12.5).color(theme::ink()));
                let ready = app.cmp_sel1.is_some() && app.cmp_sel2.is_some();
                for (label, bytes) in [("Words", false), ("Bytes", true), ("Characters", false)] {
                    if ui.add_enabled(ready, egui::Button::new(RichText::new(label).strong()).min_size(egui::vec2(btn_w, 22.0))).clicked() {
                        let (a, b) = (app.cmp_sel1.unwrap(), app.cmp_sel2.unwrap());
                        app.comparer_state.left = app.cmp_items.get(a).cloned().unwrap_or_default();
                        app.comparer_state.right = app.cmp_items.get(b).cloned().unwrap_or_default();
                        app.comparer_state.recompute();
                        let unit = match label {
                            "Bytes" => crate::compare::Unit::Bytes,
                            "Characters" => crate::compare::Unit::Chars,
                            _ => crate::compare::Unit::Words,
                        };
                        app.cmp_unit_label = label;
                        app.cmp_result = Some(crate::compare::compare(app.comparer_state.left.as_bytes(), app.comparer_state.right.as_bytes(), unit));
                        app.cmp_window = Some((a, b, bytes));
                        app.cmp_hex = bytes;
                        app.cmp_scroll = egui::Vec2::ZERO;
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
        let Some(result) = app.cmp_result.clone() else {
            app.cmp_window = None;
            return;
        };
        let unit_name = match app.cmp_unit_label {
            "Bytes" => "Byte",
            "Characters" => "Character",
            _ => "Word",
        };
        let title = format!("{unit_name} compare of #{} and #{} ({} differences)", a + 1, b + 1, result.differences);
        egui::Window::new(title.clone()).default_pos(crate::theme::window_pos(ui.ctx()))
            .open(&mut open)
            .default_size(egui::vec2(1000.0, 620.0))
            .show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Key:").size(12.5));
                    for (name, col) in [("Modified", 0x9FBBD4), ("Deleted", 0xEE95A1), ("Added", 0x9BCF88)] {
                        egui::Frame::NONE.fill(c(col)).inner_margin(egui::Margin::symmetric(6, 1)).show(ui, |ui| {
                            ui.label(RichText::new(name).size(12.0).color(egui::Color32::BLACK));
                        });
                    }
                    if result.capped {
                        ui.label(RichText::new("(very different: the middle is shown as one block)").size(12.0).color(theme::ink_faint()));
                    }
                    // Burp's result window: Text | Hex view and Sync views.
                    ui.add_space(16.0);
                    ui.radio_value(&mut app.cmp_hex, false, "Text");
                    ui.radio_value(&mut app.cmp_hex, true, "Hex");
                    ui.add_space(8.0);
                    ui.checkbox(&mut app.cmp_sync, "Sync views");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Export").on_hover_text("Write both sides with the differences highlighted as an HTML page").clicked() {
                            let path = app.cmp_export_path.trim().to_string();
                            match std::fs::write(&path, crate::compare::export_html(&result, &title)) {
                                Ok(()) => feedback::toast(feedback::Level::Success, format!("Comparison written to {path}")),
                                Err(e) => feedback::toast(feedback::Level::Error, format!("Could not write {path}: {e}")),
                            }
                        }
                        ui.add(egui::TextEdit::singleline(&mut app.cmp_export_path).desired_width(220.0));
                    });
                });
                ui.add_space(6.0);
                // Byte compares show unprintable bytes as dots so the
                // highlighted runs keep their position.
                let shown = |t: &str| -> String {
                    if bytes {
                        t.chars().map(|ch| if ch == '\n' || ch == '\r' || ch == '\t' || !ch.is_control() { ch } else { '\u{b7}' }).collect()
                    } else {
                        t.to_string()
                    }
                };
                let (hex, sync) = (app.cmp_hex, app.cmp_sync);
                let mut scroll = app.cmp_scroll;
                ui.columns(2, |cols2| {
                    for (side, col) in cols2.iter_mut().enumerate() {
                        let raw = if side == 0 { &result.left } else { &result.right };
                        let len: usize = raw.iter().map(|s| s.text.len()).sum();
                        let hexed;
                        let spans = if hex {
                            hexed = crate::compare::hex_spans(raw);
                            &hexed
                        } else {
                            raw
                        };
                        col.label(RichText::new(format!("#{}  Length: {len}", if side == 0 { a + 1 } else { b + 1 })).size(12.5).color(theme::ink_dim()));
                        let mut area = egui::ScrollArea::both().id_salt(("cmpw", side)).auto_shrink([false, false]);
                        if sync {
                            area = area.vertical_scroll_offset(scroll.y).horizontal_scroll_offset(scroll.x);
                        }
                        let shown_area = area.show(col, |ui| {
                            let font = egui::FontId::monospace(12.5);
                            let mut job = egui::text::LayoutJob::default();
                            for sp in spans {
                                let bg = match sp.kind {
                                    crate::compare::Kind::Same => egui::Color32::TRANSPARENT,
                                    crate::compare::Kind::Modified => c(0x9FBBD4),
                                    crate::compare::Kind::Deleted => c(0xEE95A1),
                                    crate::compare::Kind::Added => c(0x9BCF88),
                                };
                                let fg = if sp.kind == crate::compare::Kind::Same { theme::editor_colours().text } else { egui::Color32::BLACK };
                                let text = if hex { sp.text.clone() } else { shown(&sp.text) };
                                job.append(&text, 0.0, egui::TextFormat { font_id: font.clone(), color: fg, background: bg, ..Default::default() });
                            }
                            job.wrap.max_width = if hex { f32::INFINITY } else { ui.available_width() };
                            ui.label(job);
                        });
                        // With Sync views, whichever side moved leads both.
                        if sync && shown_area.state.unclamped_offset() != scroll {
                            scroll = shown_area.state.unclamped_offset();
                        }
                    }
                });
                app.cmp_scroll = scroll;
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
            egui::Frame::NONE
                .fill(if mine { c(0xEBF1F6) } else { theme::chrome() })
                .corner_radius(6.0)
                .inner_margin(egui::Margin::same(8))
                .outer_margin(egui::Margin::symmetric(4, 3))
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
        if ui.add_enabled(can, egui::Button::new(RichText::new("Send").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1)).min_size(egui::vec2(70.0, 26.0)))
            .on_disabled_hover_text("Set the model endpoint first")
            .clicked()
            || (enter && can)
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
        let w = (ui.available_width() - 395.0).max(200.0);
        let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 20.0), egui::Sense::hover());
        ui.painter().rect(rect, 2.0, theme::header_bg(), egui::Stroke::new(1.0, theme::line()), egui::StrokeKind::Outside);
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
        // L-04: export the rows the table shows (filtered, newest first).
        egui::menu::MenuButton::new("Export").config(egui::menu::MenuConfig::new().close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)).ui(ui, |ui| {
            if app.eng.log_export_path.is_empty() {
                app.eng.log_export_path = std::env::current_dir()
                    .map(|d| d.join("webprobe-logger.csv").display().to_string())
                    .unwrap_or_else(|_| "webprobe-logger.csv".into());
            }
            ui.label("Save to");
            ui.add(egui::TextEdit::singleline(&mut app.eng.log_export_path).desired_width(320.0));
            if ui.button("Export as CSV").clicked() {
                let rows: Vec<crate::logger::LogEntry> = app.logger.filter(&app.log_filter).into_iter().rev().cloned().collect();
                let csv = crate::logger::to_csv(&rows, history_time);
                match std::fs::write(&app.eng.log_export_path, csv) {
                    Ok(()) => feedback::toast(feedback::Level::Success, format!("Exported {} row(s) to {}", rows.len(), app.eng.log_export_path)),
                    Err(e) => feedback::toast(feedback::Level::Error, format!("Export failed: {e}")),
                }
                ui.close();
            }
        });
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
                // A proxy row shows the history item it mirrors; a tool row
                // (Repeater, Intruder, Scanner, ...) carries its own messages.
                let row = app.log_sel.and_then(|id| app.logger.get(id).cloned());
                let (req, resp) = match &row {
                    Some(r) if r.hist_id.is_some() => {
                        let e = r.hist_id.and_then(|id| app.shared.history.get(id));
                        (e.as_ref().map(|e| util::origin_form(&e.req_raw)), e.and_then(|e| e.resp_raw).map(|b| b.to_vec()))
                    }
                    Some(r) => (r.request.as_ref().map(|b| b.to_vec()), r.response.as_ref().map(|b| b.to_vec())),
                    None => (None, None),
                };
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
                            let id = app.shared.organizer.lock().unwrap().add("New item", "", "", "", util::now_secs());
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
                let _ = ui.selectable_label(true, RichText::new(format!("{}  Inbox ({})", theme::icon::TRAY, app.shared.organizer.lock().unwrap().len())).size(12.5));
            });
            strip.cell(|ui| {
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(RichText::new(format!("{}  Inbox", theme::icon::TRAY)).strong().size(14.0).color(theme::ink()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui.add_enabled(app.org_sel.is_some(), egui::Button::new("Delete")).clicked() {
                            if let Some(id) = app.org_sel.take() {
                                app.shared.organizer.lock().unwrap().remove(id);
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
                    .shared
                    .organizer
                    .lock()
                    .unwrap()
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
                            let Some(mut item) = app.shared.organizer.lock().unwrap().get(id).cloned() else { return };
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Notes").size(12.5).color(theme::ink()));
                                if ui.add(egui::TextEdit::singleline(&mut item.note).desired_width(ui.available_width() - 10.0)).changed() {
                                    app.shared.organizer.lock().unwrap().set_note(id, &item.note);
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
mod repeater_fix_tests {
    use super::*;

    /// Second review, finding 3: several links (and non-ASCII text) neither
    /// hang nor panic.
    #[test]
    fn links_in_response_walks_every_link() {
        let body = "<a href=\"http://a\"> x <a href=\"http://b\"> é <img src=\"https://c/ü\"> <a href=\"/rel\">";
        let e = net::HistEntry { resp_raw: Some(format!("HTTP/1.1 200 OK\r\n\r\n{body}").into()), ..Default::default() };
        assert_eq!(links_in_response(&e), "http://a\nhttp://b\nhttps://c/ü");
    }

    /// Issue #2 item 2: Cancel frees the tab at once and a late response
    /// is dropped (its generation is stale).
    #[test]
    fn cancel_abandons_the_in_flight_send() {
        let sh = net::Shared::new();
        let tab = sh.repeaters.lock().unwrap()[0].id;
        let gen = sh.rep.begin(tab);
        cancel_repeater_send(&sh);
        assert_eq!(sh.repeaters.lock().unwrap()[0].result_line, "Request cancelled", "shown in the tab's status line");
        assert!(!sh.rep.is_busy());
        assert_eq!(sh.rep.result(), "Request cancelled");
        assert!(!sh.rep.is_current(gen), "the worker sees a stale generation");
        // Cancel with nothing in flight changes nothing.
        cancel_repeater_send(&sh);
        assert_eq!(sh.rep.result(), "Request cancelled");
    }

    /// Issue #2 item 1: tab numbers are never reused, so routing by id can
    /// not hit a different tab after a close.
    #[test]
    fn repeater_tab_ids_are_never_reused() {
        let sh = net::Shared::new();
        let first = sh.repeaters.lock().unwrap()[0].id;
        let a = sh.rep.new_tab_id();
        let b = sh.rep.new_tab_id();
        assert!(a != first && b != a && b != first);
    }
}

#[cfg(test)]
mod tests {
    use super::{history_new_rows, history_view};
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
            req_raw: Vec::new().into(),
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
    fn history_view_keeps_every_match_and_new_rows_go_on_top() {
        let history: Vec<_> = (1..=1500u64).map(|id| entry(id, if id == 1 { "old.example" } else { "other.example" })).collect();
        // The only match is the oldest entry.
        let (rows, truncated) = history_view(&history, |e| e.host.contains("old.example"), &TableState::new());
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), [1]);
        assert!(!truncated);
        // No cap: all 1500 rows, newest first.
        let (rows, truncated) = history_view(&history, |_| true, &TableState::new());
        assert_eq!(rows.len(), 1500);
        assert!(!truncated);
        assert_eq!((rows.first().unwrap().id, rows.last().unwrap().id), (1500, 1));
        // Appended rows, filtered and newest first, are what an incremental
        // update puts on top: the result equals a full rebuild.
        let mut grown = history.clone();
        grown.extend((1501..=1505u64).map(|id| entry(id, if id % 2 == 0 { "old.example" } else { "x" })));
        let keep = |e: &crate::net::HistEntry| e.host.contains("old.example");
        let mut incremental = history_new_rows(&grown, history.len(), keep);
        incremental.extend(history_view(&history, keep, &TableState::new()).0);
        let full = history_view(&grown, keep, &TableState::new()).0;
        assert_eq!(incremental.iter().map(|r| r.id).collect::<Vec<_>>(), full.iter().map(|r| r.id).collect::<Vec<_>>());
        assert_eq!(full.iter().map(|r| r.id).collect::<Vec<_>>(), [1504, 1502, 1]);
        assert!(history_new_rows(&history, 9999, keep).is_empty());
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
        e.req_raw = b"POST /change HTTP/1.1\r\nHost: h\r\n\r\nemail=a%40b.c&x=1".to_vec().into();
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
    fn a_sort_sees_the_whole_history() {
        let mut history: Vec<_> = (1..=1500u64).map(|id| entry(id, "example.test")).collect();
        history[0].method = "POST".to_string(); // the oldest entry
        let mut state = TableState::new();
        state.sort_col = 2; // Method
        state.sort_asc = false; // POST first
        let (rows, truncated) = history_view(&history, |_| true, &state);
        assert!(!truncated);
        assert_eq!(rows.len(), 1500);
        assert_eq!(rows[0].id, 1, "the sort must see the whole list");
    }
}

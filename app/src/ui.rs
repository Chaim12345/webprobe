// UI panels: Dashboard, Target (site map), Proxy (intercept/history/options),
// Intruder, Repeater, Decoder. Styling per theme.rs (DarkTheme.json evidence).

use std::sync::atomic::Ordering;

use eframe::egui::{self, RichText, Ui};

use crate::editor;
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
    Sessions,
    Decoder,
    Search,
    Collaborator,
    Extensions,
}

const TABS: [(&str, Tab); 13] = [
    ("Dashboard", Tab::Dashboard),
    ("Target", Tab::Target),
    ("Proxy", Tab::Proxy),
    ("Scanner", Tab::Scanner),
    ("Intruder", Tab::Intruder),
    ("Repeater", Tab::Repeater),
    ("Sequencer", Tab::Sequencer),
    ("Comparer", Tab::Comparer),
    ("Sessions", Tab::Sessions),
    ("Decoder", Tab::Decoder),
    ("Search", Tab::Search),
    ("Collaborator", Tab::Collaborator),
    ("Extensions", Tab::Extensions),
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

    egui::TopBottomPanel::top("main_bar")
        .exact_height(30.0)
        .frame(egui::Frame::default().fill(c(theme::MONO1)).inner_margin(egui::Margin::symmetric(8.0, 4.0)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                // neutral placeholder mark (no copied logo)
                let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, theme::RADIUS_S, c(theme::SELECTION_SUBTLE));
                let r = rect.shrink2(egui::vec2(4.0, 3.5));
                ui.painter().line_segment(
                    [r.center() + egui::vec2(-4.0, 6.0), r.center() + egui::vec2(1.0, -6.0)],
                    egui::Stroke::new(2.4, c(theme::ORANGE)),
                );
                ui.add_space(6.0);
                ui.label(RichText::new("WebProbe").strong().color(c(theme::ORANGE)).size(15.0));
                ui.add_space(16.0);
                for (name, tab) in &TABS[..6] {
                    let sel = app.tab == *tab;
                    let text = RichText::new(*name).size(13.5).color(if sel { c(theme::ORANGE) } else { c(theme::MONO6) });
                    if ui.selectable_label(sel, text).clicked() {
                        app.tab = *tab;
                    }
                    ui.add_space(6.0);
                }
                let active_extra = TABS[6..].iter().find(|(_, tab)| app.tab == *tab).map(|(name, _)| *name);
                let more_label = active_extra.unwrap_or("More tools");
                ui.menu_button(RichText::new(format!("{more_label} ▾")).size(13.5).color(if active_extra.is_some() { c(theme::ORANGE) } else { c(theme::MONO6) }), |ui| {
                    for (name, tab) in &TABS[6..] {
                        if ui.selectable_label(app.tab == *tab, *name).clicked() {
                            app.tab = *tab;
                            ui.close_menu();
                        }
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Burp: Settings is its own window (Settings > User
                    // interface > Hotkeys), not a dashboard panel. Plain text:
                    // the default egui font has no gear glyph.
                    if ui
                        .small_button("Settings")
                        .on_hover_text("Appearance and hotkeys")
                        .clicked()
                    {
                        app.settings_open = true;
                    }
                    ui.add_space(10.0);
                    let on = app.shared.intercept_on.load(Ordering::SeqCst);
                    ui.label(
                        RichText::new(format!("127.0.0.1:{}", app.shared.proxy_port.load(Ordering::SeqCst)))
                            .size(11.5)
                            .color(c(theme::MONO6)),
                    );
                    ui.add_space(10.0);
                    let dot = if on {
                        RichText::new("INTERCEPT ON").color(c(theme::ORANGE)).size(12.0)
                    } else {
                        RichText::new("intercept off").color(c(theme::MONO6)).size(12.0)
                    };
                    ui.label(dot);
                });
            });
        });

    // Status bar (B-05): what Burp keeps along the bottom edge — listener,
    // intercept state, the interception queue, the history size, the last
    // message and any scan progress. It is always visible, whatever the tab.
    egui::TopBottomPanel::bottom("status_bar")
        .exact_height(24.0)
        .frame(
            egui::Frame::default()
                .fill(c(theme::MONO1))
                .inner_margin(egui::Margin::symmetric(8.0, 3.0)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                let on = app.shared.intercept_on.load(Ordering::SeqCst);
                let waiting = app.shared.count_waiting();
                let total = app.shared.history.lock().map(|h| h.len()).unwrap_or(0);
                let messages = app.shared.messages.load(Ordering::SeqCst);
                let port = app.shared.proxy_port.load(Ordering::SeqCst);

                let dot = if on { c(theme::ORANGE) } else { c(theme::GOOD) };
                ui.label(RichText::new("\u{25cf}").color(dot).size(11.0));
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("127.0.0.1:{port}"))
                        .monospace()
                        .size(11.5)
                        .color(c(theme::MONO6)),
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new(if on { "intercept on" } else { "intercept off" })
                        .size(11.5)
                        .color(c(if on { theme::ORANGE } else { theme::MONO6 })),
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new(format!("held: {waiting}"))
                        .size(11.5)
                        .color(c(if waiting > 0 { theme::WARN } else { theme::MONO4 })),
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new(format!("history: {total}"))
                        .size(11.5)
                        .color(c(theme::MONO4)),
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new(format!("messages: {messages}"))
                        .size(11.5)
                        .color(c(theme::MONO4)),
                );

                let (busy, done, scan_total) = (
                    app.shared.scan_busy.load(Ordering::SeqCst),
                    app.shared.scan_done.load(Ordering::SeqCst),
                    app.shared.scan_total.load(Ordering::SeqCst),
                );
                if busy || scan_total > 0 {
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(format!("scan {done}/{scan_total}"))
                            .size(11.5)
                            .color(c(if busy { theme::ORANGE } else { theme::MONO4 })),
                    );
                }

                let last = app
                    .shared
                    .history
                    .lock()
                    .ok()
                    .and_then(|h| {
                        h.last()
                            .map(|e| (e.method.clone(), e.host.clone(), e.path.clone(), e.status.clone()))
                    });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some((method, host, path, status)) = last {
                        ui.label(
                            RichText::new(format!("{method} {host}{path} \u{2192} {status}"))
                                .monospace()
                                .size(11.0)
                                .color(c(theme::MONO6)),
                        );
                        ui.add_space(10.0);
                    }
                });
            });
        });

    egui::CentralPanel::default()
        .frame(egui::Frame::default().fill(c(theme::MONO1X)).inner_margin(egui::Margin::same(10.0)))
        .show(ctx, |ui| match app.tab {
            Tab::Dashboard => dashboard(app, ui),
            Tab::Target => target(app, ui),
            Tab::Proxy => proxy(app, ui),
            Tab::Scanner => scanner(app, ui),
            Tab::Intruder => intruder(app, ui),
            Tab::Repeater => repeater(app, ui),
            Tab::Sequencer => sequencer(app, ui),
            Tab::Comparer => comparer(app, ui),
            Tab::Sessions => sessions(app, ui),
            Tab::Decoder => decoder(app, ui),
            Tab::Search => search(app, ui),
            Tab::Collaborator => crate::collaborator_ui::collaborator(app, ui),
            Tab::Extensions => extensions(app, ui),
        });
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
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        total,
        app.hist_filter.text.trim(),
        app.hist_filter.regex,
        app.hist_filter.method.trim(),
        app.hist_filter.status.trim(),
        app.hist_filter.mime.trim(),
        app.hist_filter.in_scope_only,
        app.hist_table.sort_col,
        app.hist_table.sort_asc,
    );
    let (rows, truncated) = if key != app.hist_cache_key || total < app.hist_cache_len {
        let mut rows: Vec<net::HistEntry> = {
            let history = app.shared.history.lock().unwrap();
            let filter = &app.hist_filter;
            let shared = &app.shared;
            history
                .iter()
                .rev()
                .filter(|e| filter.matches(e, shared))
                .cloned()
                .collect()
        };
        table::sort_rows(&mut rows, &app.hist_table, |e, col| match col {
            0 => format!("{:020}", e.id),
            1 => e.method.clone(),
            2 => format!("{}:{:05}", e.host, e.port),
            3 => e.path.clone(),
            4 => e.status.clone(),
            5 => format!("{:010}", e.resp_len),
            6 => crate::history_filter::HistoryFilter::mime_of(e),
            7 => if e.https { "https".to_string() } else { "http".to_string() },
            _ => String::new(),
        });
        let truncated = rows.len() > HISTORY_RENDER_LIMIT;
        rows.truncate(HISTORY_RENDER_LIMIT);
        app.hist_cache_len = total;
        app.hist_cache = rows;
        app.hist_cache_truncated = truncated;
        app.hist_cache_key = key;
        (app.hist_cache.clone(), truncated)
    } else {
        (app.hist_cache.clone(), app.hist_cache_truncated)
    };

    let columns = [
        table::Column::right("#", 46.0),
        table::Column::new("Method", 62.0),
        table::Column::new("Host", 190.0),
        table::Column::new("URL", 260.0),
        table::Column::right("Status", 54.0),
        table::Column::right("Length", 70.0),
        table::Column::new("MIME", 150.0),
        table::Column::new("TLS", 52.0),
    ];

    table::column_chooser(ui, &columns, &mut app.hist_table);
    ui.add_space(4.0);

    // Toolbar: the actions Burp keeps above its HTTP history table.
    ui.horizontal(|ui| {
        if ui.button(RichText::new("Send to Repeater (Ctrl+R)")).clicked() {
            send_history_to_repeater(app);
            app.tab = crate::ui::Tab::Repeater;
        }
        if ui.button(RichText::new("Send to Intruder (Ctrl+I)")).clicked() {
            send_history_to_intruder(app);
            app.tab = crate::ui::Tab::Intruder;
        }
        if ui
            .button(RichText::new("Clear history").color(c(theme::MONO6)))
            .on_hover_text("Remove every recorded entry from the history")
            .clicked()
        {
            if let Ok(mut h) = app.shared.history.lock() {
                h.clear();
            }
            app.history_sel = None;
        }
        if truncated {
            ui.label(
                RichText::new("(most recent 1000 matching entries)")
                    .size(11.0)
                    .color(c(theme::MONO6)),
            );
        }
    });
    ui.add_space(4.0);

    let mut selected = app.history_sel;
    let row_height = theme::appearance().1.row_height();
    // Leave room for the message pane underneath, like Burp's split view; the
    // divider between the two is draggable (B-05).
    let pane_h = ui.available_height();
    let table_h = (pane_h - app.split_detail).max(100.0);
    // The column visibility is read inside the row closure, so it is snapshotted
    // here rather than borrowed from the table state the body mutably holds.
    let visible = app.hist_table.hidden.clone();
    let widths = app.hist_table.widths.clone();
    let col_state = table::TableState { hidden: visible, widths, ..Default::default() };
    table::table_body(ui, "proxy_history", &columns, &rows, &mut app.hist_table, row_height, table_h, &mut |e, ui| {
        let row_rect = egui::Rect::from_min_size(
            ui.cursor().min,
            egui::vec2(ui.available_width(), row_height),
        );
        if selected == Some(e.id) {
            // Burp's selectionBackground, so a selected row reads as selected
            // and not as a warning.
            ui.painter().rect_filled(row_rect, egui::Rounding::ZERO, c(theme::SEL_BG));
        } else if e.id % 2 == 0 {
            ui.painter().rect_filled(row_rect, egui::Rounding::ZERO, c(theme::ZEBRA));
        }
        let row = ui
            .horizontal(|ui| {
                let cells = [
                    (0, e.id.to_string(), Some(c(theme::EDITOR_TEXT))),
                    (1, e.method.clone(), Some(theme::method_color(&e.method))),
                    (2, format!("{}:{}", e.host, e.port), Some(c(theme::EDITOR_TEXT))),
                    (3, e.path.clone(), Some(c(theme::EDITOR_TEXT))),
                    (4, e.status.clone(), Some(theme::status_color(&e.status))),
                    (5, e.resp_len.to_string(), Some(c(theme::EDITOR_TEXT))),
                    (6, crate::history_filter::HistoryFilter::mime_of(e), Some(c(theme::MONO6))),
                    (7, if e.https { "https" } else { "http" }.to_string(), Some(c(theme::MONO6))),
                ];
                table::cells(ui, &columns, &col_state, row_height, &cells);
            })
            .response
            .interact(egui::Sense::click());
        if row.clicked() {
            selected = Some(e.id);
        }
    });
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
        if active { c(theme::ORANGE) } else { c(theme::MONO2) },
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
    ui.heading(RichText::new("Proxy options").color(c(theme::MONO7)).size(15.0));
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Listen on").size(13.0).color(c(theme::EDITOR_TEXT)));
        ui.add(
            egui::TextEdit::singleline(&mut app.port_txt)
                .desired_width(90.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.label(RichText::new("(127.0.0.1, default 8080)").size(12.0).color(c(theme::MONO6)));
        if ui.button("Restart listener").clicked() {
            if let Ok(p) = app.port_txt.trim().parse::<u16>() {
                app.shared.proxy_port.store(p, Ordering::SeqCst);
                app.shared.listener_restart.store(true, Ordering::SeqCst);
                app.shared.log(&format!("Restarting listener on 127.0.0.1:{p}"));
            }
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

    ui.add_space(12.0);
    ui.label(RichText::new("Match and replace").color(c(theme::MONO7)).size(14.0).strong());
    ui.label(RichText::new("Rules run as messages pass through: request rules before sending upstream, response rules before delivery.").size(12.0).color(c(theme::MONO6)));
    ui.add_space(4.0);
    mr_table(ui, app, true);
    ui.add_space(6.0);
    mr_table(ui, app, false);
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
            ui.label(RichText::new(*k).size(12.5).color(c(theme::MONO6)));
            ui.label(RichText::new(*v).monospace().size(12.0).color(c(theme::EDITOR_TEXT)));
            ui.end_row();
        }
    });
}

// ================= message detail =================

fn detail(app: &mut App, ui: &mut Ui) {
    let Some(id) = app.history_sel else {
        ui.label(RichText::new("select a request to inspect it").size(12.0).color(c(theme::MONO6)));
        return;
    };
    let entry = app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned();
    let Some(e) = entry else { return };

    ui.horizontal(|ui| {
        if let Some(s) = sub_tabs(ui, &["Request", "Response"], app.detail_sub) {
            app.detail_sub = s;
        }
        ui.add_space(14.0);
        if let Some(s) = sub_tabs(ui, &["Raw", "Hex", "Headers", "Params"], app.detail_view) {
            app.detail_view = s;
        }
    });

    let show_req = app.detail_sub == 0;
    if !show_req && e.resp_raw.is_none() {
        hint(ui, &e.note.clone().unwrap_or_else(|| "no response stored".to_string()));
        return;
    }
    let bytes = if show_req { e.req_raw.clone() } else { e.resp_raw.clone().unwrap_or_default() };
    let parts = util::parse_http(&bytes);
    ui.label(RichText::new(parts.first.clone()).monospace().size(12.5).color(c(theme::HEADER_BLUE)));
    ui.add_space(2.0);

    match app.detail_view {
        0 => {
            // Shared message view (M-03): tinted head, cheap body rendering.
            let text = String::from_utf8_lossy(&bytes).into_owned();
            editor::message_view(ui, "detail_raw", &text, &mut app.detail_editor);
        }
        1 => {
            egui::ScrollArea::vertical().min_scrolled_height(70.0).show(ui, |ui| {
                ui.monospace(RichText::new(util::hex_view(&bytes, 16384)).size(11.5).color(c(theme::EDITOR_TEXT)));
            });
        }
        2 => {
            egui::ScrollArea::vertical().min_scrolled_height(70.0).show(ui, |ui| {
                egui::Grid::new("hdrgrid").striped(true).num_columns(2).show(ui, |ui| {
                    for (k, v) in &parts.headers {
                        ui.label(RichText::new(k.clone()).monospace().size(12.0).color(c(theme::HEADER_BLUE)));
                        ui.label(RichText::new(v.clone()).monospace().size(12.0).color(c(theme::EDITOR_TEXT)));
                        ui.end_row();
                    }
                });
            });
        }
        _ => {
            egui::ScrollArea::vertical().min_scrolled_height(70.0).show(ui, |ui| {
                egui::Grid::new("pgrid").striped(true).num_columns(2).show(ui, |ui| {
                    let q = parts.path.split('?').nth(1).unwrap_or("");
                    for kv in q.split('&').filter(|s| !s.is_empty()) {
                        let mut it = kv.splitn(2, '=');
                        let k = it.next().unwrap_or("");
                        let v = it.next().unwrap_or("");
                        ui.label(RichText::new(util::url_decode(k)).monospace().size(12.0).color(c(theme::URL_KEY)));
                        ui.label(RichText::new(util::url_decode(v)).monospace().size(12.0).color(c(theme::URL_VALUE)));
                        ui.end_row();
                    }
                });
            });
        }
    }
}

// ================= Scanner =================

fn scan_sev_color(sev: &str) -> egui::Color32 {
    match sev {
        "high" => c(theme::BAD),
        "medium" => c(theme::ORANGE),
        "low" => c(theme::METHOD_OTHER),
        _ => c(theme::MONO6),
    }
}

fn scanner(app: &mut App, ui: &mut Ui) {
    ui.label(RichText::new("Scanner").color(c(theme::MONO7)).size(14.0).strong());
    ui.add_space(2.0);
    hint(ui, "Every proxied response is audited live (passive checks). Select a request in the history and press Run active scan to send light active probes (URL parameters, max 30).");
    ui.add_space(2.0);

    let busy = app.shared.scan_busy.load(Ordering::SeqCst);
    let (done, total) = (
        app.shared.scan_done.load(Ordering::SeqCst),
        app.shared.scan_total.load(Ordering::SeqCst),
    );
    ui.horizontal(|ui| {
        let btn = RichText::new(if busy { "scanning..." } else { "Run active scan on selected request" })
            .color(if busy { c(theme::MONO6) } else { c(theme::ORANGE) })
            .size(13.0);
        if !busy && ui.button(btn).clicked() {
            if let Some(id) = app.history_sel {
                if let Some(e) = app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned() {
                    crate::scan::start_active_scan(app.shared.clone(), e);
                    feedback::toast(feedback::Level::Info, "Active scan started");
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
                    .color(c(theme::MONO6)),
            );
        });
    });

    ui.add_space(6.0);
    let issues = app.shared.issues.lock().unwrap().clone();
    let table_h = if app.scan_sel.is_some() { (ui.available_height() - 220.0).max(140.0) } else { ui.available_height() - 10.0 };
    let columns = [
        table::Column::new("Severity", 78.0),
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
        1 => row.1.clone(),
        2 => row.2.clone(),
        _ => row.3.path.clone(),
    });
    let rows: Vec<scan::ScanIssue> = sortable.into_iter().map(|r| r.3).collect();
    egui::ScrollArea::vertical().max_height(table_h.max(140.0)).show(ui, |ui| {
        let row_h = theme::appearance().1.row_height();
        table::data_table(ui, "scan_issues", &columns, &rows, &mut app.scan_table, row_h, |iss, ui| {
            let row = ui
                .horizontal(|ui| {
                    table::cell(ui, &columns[0], iss.sev.clone(), Some(scan_sev_color(&iss.sev)), row_h);
                    table::cell(ui, &columns[1], iss.name.clone(), Some(c(theme::EDITOR_TEXT)), row_h);
                    table::cell(ui, &columns[2], iss.host.clone(), Some(c(theme::EDITOR_TEXT)), row_h);
                    table::cell(ui, &columns[3], iss.path.clone(), Some(c(theme::MONO6)), row_h);
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
            ui.label(RichText::new(issue.name.clone()).size(13.0).strong().color(scan_sev_color(&issue.sev)));
            hint(ui, &format!("{} {} - {}", issue.host, issue.path, issue.detail));
        }
    }
}

// ================= Intruder =================

fn intruder(app: &mut App, ui: &mut Ui) {
    let attack = app.shared.attack.lock().unwrap().clone();
    ui.heading(RichText::new("Intruder").color(c(theme::MONO7)).size(15.0));
    ui.add_space(2.0);
    hint(ui, "Wrap the attack point in § markers (type them into the request text). Each run attacks one marked position with every payload; results appear below.");
    ui.add_space(4.0);

    let running = attack.running.load(Ordering::SeqCst);
    ui.horizontal(|ui| {
        let run_text = RichText::new(if running { "Attack running..." } else { "Start attack" }).color(c(theme::ORANGE)).size(13.0);
        if !running && ui.button(run_text).clicked() {
            net::start_attack(app.shared.clone(), app.intr_req.clone(), app.intr_payloads.clone(), app.intr_https);
        }
        if running && ui.button("Stop").clicked() {
            attack.stop.store(true, Ordering::SeqCst);
        }
        ui.add_enabled_ui(!running, |ui| {
            ui.checkbox(&mut app.intr_https, "HTTPS");
        });
        let (done, total) = (attack.done.load(Ordering::SeqCst), attack.total.load(Ordering::SeqCst));
        if total > 0 {
            if feedback::progress(ui, done, total, running) {
                attack.stop.store(true, Ordering::SeqCst);
                feedback::toast(feedback::Level::Warn, "Attack cancelled");
            }
        } else {
            ui.label(RichText::new("no attack yet").size(12.5).color(c(theme::MONO6)));
        }
        if ui.button("Clear results").clicked() {
            attack.rows.lock().unwrap().clear();
            attack.total.store(0, Ordering::SeqCst);
            attack.done.store(0, Ordering::SeqCst);
        }
    });
    ui.add_space(4.0);

    let half = (ui.available_height() - 220.0).max(100.0) / 2.0;
    egui::ScrollArea::vertical().max_height(half).show(ui, |ui| {
        ui.label(RichText::new("Request with positions").size(12.0).color(c(theme::MONO6)));
        editor::message_editor(ui, "intruder_request", &mut app.intr_req, 8, &mut app.intr_editor);
    });
    egui::ScrollArea::vertical().max_height(half).show(ui, |ui| {
        ui.label(RichText::new("Payload list (one per line)").size(12.0).color(c(theme::MONO6)));
        egui::TextEdit::multiline(&mut app.intr_payloads)
            .font(egui::TextStyle::Monospace)
            .code_editor()
            .desired_rows(6)
            .desired_width(400.0)
            .show(ui);
    });

    ui.add_space(4.0);
    ui.label(RichText::new("Results").size(12.0).color(c(theme::MONO6)));
    let rows: Vec<(usize, net::AttackRow)> = attack.rows.lock().unwrap().clone().into_iter().enumerate().collect();
    if rows.is_empty() {
        feedback::empty_state(ui, "No attack results yet", "Mark a position with § and press Start attack.");
        return;
    }
    let rows = table::filter_rows(&rows, &app.intr_table, |(i, r)| {
        format!("{i} {} {} {} {}", r.payload, r.status, r.len, r.ms)
    });
    let columns = [
        table::Column::right("#", 44.0),
        table::Column::new("Payload", 260.0),
        table::Column::right("Status", 60.0),
        table::Column::right("Length", 72.0),
        table::Column::right("Time", 80.0),
    ];
    egui::ScrollArea::vertical().show(ui, |ui| {
        let row_h = theme::appearance().1.row_height();
        table::data_table(ui, "intruder_results", &columns, &rows, &mut app.intr_table, row_h, |(i, r), ui| {
            ui.horizontal(|ui| {
                table::cell(ui, &columns[0], i.to_string(), Some(c(theme::MONO6)), row_h);
                table::cell(ui, &columns[1], r.payload.clone(), Some(c(theme::EDITOR_TEXT)), row_h);
                table::cell(ui, &columns[2], r.status.clone(), Some(theme::status_color(&r.status)), row_h);
                table::cell(ui, &columns[3], r.len.to_string(), Some(c(theme::EDITOR_TEXT)), row_h);
                table::cell(ui, &columns[4], format!("{} ms", r.ms), Some(c(theme::MONO6)), row_h);
            });
        });
    });
}

// ================= Repeater =================

fn repeater(app: &mut App, ui: &mut Ui) {
    {
        let reps = app.shared.repeaters.lock().unwrap().len();
        for i in 0..reps {
            let name = format!("{} ", {
                let r = app.shared.repeaters.lock().unwrap();
                r[i].name.clone()
            });
            let sel = app.rep_sel == i;
            if ui.selectable_label(sel, RichText::new(name).color(if sel { c(theme::MONO7) } else { c(theme::MONO6) })).clicked() {
                app.rep_sel = i;
            }
        }
        if ui.button("+").clicked() {
            let mut reps = app.shared.repeaters.lock().unwrap();
            let n = reps.len() + 1;
            let name = format!("Rep {n}");
            reps.push(net::RepTab {
                name: name.clone(),
                host: String::new(),
                port: 80,
                https: false,
                request: String::new(),
                response: None,
                result_line: String::new(),
            });
            app.rep_sel = n - 1;
        }
    }
    ui.add_space(4.0);

    let busy = app.shared.rep_busy.load(Ordering::SeqCst);
    ui.horizontal(|ui| {
        let btn = if busy {
            RichText::new("sending...").color(c(theme::MONO6)).size(13.0)
        } else {
            RichText::new("Send (Ctrl+Space)").color(c(theme::ORANGE)).size(13.0)
        };
        if ui.button(btn).clicked() && !busy {
            repeater_send(app);
        }
        let i = app.rep_sel.min(app.shared.repeaters.lock().unwrap().len().saturating_sub(1));
        let mut https = app.shared.repeaters.lock().unwrap()[i].https;
        if ui.add_enabled(!busy, egui::Checkbox::new(&mut https, "HTTPS")).changed() {
            let mut reps = app.shared.repeaters.lock().unwrap();
            reps[i].https = https;
            if !reps[i].host.contains(':') {
                reps[i].port = if https { 443 } else { 80 };
            }
        }
        let res = app.shared.rep_result.lock().unwrap().clone();
        if let Some(err) = res.strip_prefix("error: ") {
            if feedback::inline_error(ui, err, !busy) {
                repeater_send(app);
            }
        } else if !res.is_empty() {
            ui.label(RichText::new(res).size(12.0).color(c(theme::EDITOR_TEXT)));
        }
    });
    ui.add_space(4.0);

    let half = (ui.available_height() - 220.0).max(120.0) / 2.0;
    egui::ScrollArea::vertical().max_height(half).show(ui, |ui| {
        ui.label(RichText::new("Request (edit then Send - keep the Host header, e.g. example.com:80)").size(12.0).color(c(theme::MONO6)));
        {
            let reps_len = app.shared.repeaters.lock().unwrap().len();
            let i = app.rep_sel.min(reps_len.saturating_sub(1));
            let mut reps = app.shared.repeaters.lock().unwrap();
            editor::message_editor(ui, "repeater_request", &mut reps[i].request, 10, &mut app.rep_editor);
        }
    });
    ui.add_space(4.0);
    ui.label(RichText::new("Response").size(12.0).color(c(theme::MONO6)));
    let resp = {
        let reps = app.shared.repeaters.lock().unwrap();
        let i = app.rep_sel.min(reps.len().saturating_sub(1));
        reps[i].response.clone()
    };
    match resp {
        Some(r) => {
            egui::ScrollArea::vertical().show(ui, |ui| {
                let parts = util::parse_http(&r);
                ui.label(RichText::new(parts.first.clone()).monospace().size(12.5).color(c(theme::HEADER_BLUE)));
                ui.monospace(RichText::new(String::from_utf8_lossy(&r).into_owned()).size(12.0).color(c(theme::EDITOR_TEXT)));
            });
        }
        None => hint(ui, "no response yet"),
    }
}

fn repeater_send(app: &mut App) {
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
            r.result_line = match &up.resp {
                Some(resp) => {
                    let st = util::parse_http(resp).first.split_whitespace().nth(1).unwrap_or("").to_string();
                    format!("{} | {} bytes | {} ms", st, resp.len(), ms)
                }
                None => format!("error: {}", up.error.clone().unwrap_or_default()),
            };
        }
        sh.rep_busy.store(false, Ordering::SeqCst);
        let line = reps
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.result_line.clone())
            .unwrap_or_default();
        if let Some(err) = line.strip_prefix("error: ") {
            crate::feedback::toast(crate::feedback::Level::Error, format!("Repeater failed: {err}"));
        } else {
            crate::feedback::toast(crate::feedback::Level::Success, format!("Repeater: {line}"));
        }
        *sh.rep_result.lock().unwrap() = line;
    });
}

fn split_port(host: &str) -> Option<u16> {
    host.rsplit(':').next()?.parse().ok()
}

// ================= Decoder =================

fn decoder(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Decoder").color(c(theme::MONO7)).size(15.0));
    ui.add_space(4.0);
    egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
        editor::message_editor(ui, "decoder_input", &mut app.dec_input, 5, &mut app.dec_editor);
    });
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        if ui.button("Encode as Base64").clicked() {
            dec_add(app, "Base64", util::b64_encode(app.dec_input.as_bytes()));
        }
        if ui.button("URL encode (key)").clicked() {
            dec_add(app, "URL", util::url_encode_key(&app.dec_input));
        }
        if ui.button("Hex").clicked() {
            dec_add(app, "Hex", util::hex_encode(app.dec_input.as_bytes()));
        }
        if ui.button("HTML encode").clicked() {
            dec_add(app, "HTML", util::html_encode(&app.dec_input));
        }
        if ui.button("Decode as Base64").clicked() {
            dec_result(app, "Base64 <-", util::b64_decode(app.dec_input.trim()).map(|b| String::from_utf8_lossy(&b).into_owned()));
        }
        if ui.button("URL decode").clicked() {
            dec_result(app, "URL <-", Ok(util::url_decode(&app.dec_input)));
        }
        if ui.button("Hex decode").clicked() {
            dec_result(app, "Hex <-", util::hex_decode(app.dec_input.trim()).map(|b| String::from_utf8_lossy(&b).into_owned()));
        }
        if ui.button("HTML decode").clicked() {
            dec_result(app, "HTML <-", Ok(util::html_decode(&app.dec_input)));
        }
    });
    ui.add_space(8.0);
    let results = app.dec_results.clone();
    for (i, (label, text)) in results.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(label.clone()).size(12.0).color(c(theme::ORANGE)));
            if ui.button("copy to input").clicked() {
                app.dec_input = text.clone();
            }
            if ui.button("x").clicked() {
                app.dec_results.remove(i);
            }
        });
        ui.monospace(RichText::new(text.clone()).size(12.0).color(c(theme::EDITOR_TEXT)));
        ui.add_space(6.0);
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
        "forward_intercepted_proxy_message" => intercept_forward(app),
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
            request: String::from_utf8_lossy(&e.req_raw).into_owned(),
            response: e.resp_raw.clone(),
            result_line: String::new(),
        });
        app.rep_sel = n - 1;
        app.tab = Tab::Repeater;
    }
}

pub fn send_history_to_intruder(app: &mut App) {
    let Some(id) = app.history_sel else { return };
    let entry = app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned();
    if let Some(e) = entry {
        app.intr_req = String::from_utf8_lossy(&e.req_raw).into_owned();
        app.intr_https = e.https;
        app.tab = Tab::Intruder;
    }
}

#[cfg(test)]
mod tests {
    use super::{history_rows, HISTORY_RENDER_LIMIT};

    fn entry(id: u64, host: &str) -> crate::net::HistEntry {
        crate::net::HistEntry {
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
        }
    }

    #[test]
    fn history_filters_full_list_before_limiting_rendered_rows() {
        let history: Vec<_> = (1..=(HISTORY_RENDER_LIMIT as u64 + 1))
            .map(|id| entry(id, if id == 1 { "old.example" } else { "other.example" }))
            .collect();

        let mut state = crate::table::TableState::new();
        state.filter = "OLD.EXAMPLE".to_string();
        let (rows, truncated) = history_rows(&history, &state);
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), [1]);
        assert!(!truncated);

        let state = crate::table::TableState::new();
        let (rows, truncated) = history_rows(&history, &state);
        assert_eq!(rows.len(), HISTORY_RENDER_LIMIT);
        assert!(truncated);
        assert_eq!(rows.first().unwrap().id, HISTORY_RENDER_LIMIT as u64 + 1);
        assert_eq!(rows.last().unwrap().id, 2);
    }

    #[test]
    fn history_sorts_by_method_before_limiting() {
        let mut history: Vec<_> = (1..=5).map(|id| entry(id, "example.test")).collect();
        history[0].method = "POST".to_string();
        let mut state = crate::table::TableState::new();
        state.sort_col = 1;
        state.sort_asc = true;
        let (rows, _) = history_rows(&history, &state);
        // Ascending by method: GET rows keep newest-first order, POST sorts last.
        assert_eq!(rows[0].method, "GET");
        assert_eq!(rows[4].method, "POST");
    }
}

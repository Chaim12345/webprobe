// Additional Burp-parity tools: scope, upstream routing, Sequencer,
// Comparer, session rules/macros, WebSocket history, cross-tool search,
// local Collaborator, project persistence, and the extension blocker.

use eframe::egui::{self, RichText, Ui};

use crate::analysis;
use crate::net;
use crate::project;
use crate::theme::{self, c};
use crate::upstream::UpstreamKind;
use crate::App;

const SEQUENCER_MAX_LENGTH_DEVIATION: usize = 5; // ProjectDefaults.json sequencer.live_capture

fn hint(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Label::new(RichText::new(text).size(12.0).color(theme::ink_faint()))
            .wrap_mode(egui::TextWrapMode::Wrap),
    );
}

fn selected_history(app: &App) -> Option<net::HistEntry> {
    let id = app.history_sel?;
    app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned()
}

// ================= Target scope =================

pub fn scope_editor(app: &mut App, ui: &mut Ui) {
    ui.label(RichText::new("Scope").size(12.5).color(theme::ink_faint()));
    let mut rules = app.shared.scope.lock().unwrap().clone();
    let mut remove = None;
    egui::Grid::new("scope_grid").striped(true).num_columns(5).show(ui, |ui| {
        for (i, rule) in rules.iter_mut().enumerate() {
            ui.checkbox(&mut rule.enabled, "");
            let mode = if rule.include { "include" } else { "exclude" };
            if ui.selectable_label(false, RichText::new(mode).size(12.0).color(theme::ink_faint())).clicked() {
                rule.include = !rule.include;
            }
            ui.add(
                egui::TextEdit::singleline(&mut rule.pattern)
                    .desired_width(150.0)
                    .hint_text("host/path")
                    .font(egui::TextStyle::Monospace),
            );
            if ui.selectable_label(rule.is_regex, RichText::new("regex").size(12.0).color(if rule.is_regex { c(theme::ORANGE) } else { theme::ink_faint() })).clicked() {
                rule.is_regex = !rule.is_regex;
            }
            if ui.button("x").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        rules.remove(i);
    }
    if ui.button("+ scope rule").clicked() {
        rules.push(net::ScopeRule::include("", false));
    }
    *app.shared.scope.lock().unwrap() = rules;
    hint(ui, "With no include rules everything is in scope. A matching exclude rule always wins.");
}

// ================= Upstream routing =================

pub fn upstream_options(app: &mut App, ui: &mut Ui) {
    ui.label(RichText::new("Upstream routing").color(theme::ink()).size(14.0).strong());
    let mut config = app.shared.upstream.lock().unwrap().clone();
    ui.horizontal(|ui| {
        let kinds = [
            ("direct", UpstreamKind::None),
            ("HTTP proxy", UpstreamKind::Http),
            ("SOCKS5", UpstreamKind::Socks5),
        ];
        for (name, kind) in kinds {
            let sel = config.kind == kind;
            if ui.selectable_label(sel, RichText::new(name).size(12.5).color(if sel { c(theme::ORANGE) } else { theme::ink_faint() })).clicked() {
                config.kind = kind;
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("host").size(12.0).color(theme::ink_faint()));
        ui.add(egui::TextEdit::singleline(&mut config.host).desired_width(180.0).font(egui::TextStyle::Monospace));
        ui.label(RichText::new("port").size(12.0).color(theme::ink_faint()));
        ui.add(egui::TextEdit::singleline(&mut config.port).desired_width(70.0).font(egui::TextStyle::Monospace));
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("username").size(12.0).color(theme::ink_faint()));
        ui.add(egui::TextEdit::singleline(&mut config.username).desired_width(130.0).font(egui::TextStyle::Monospace));
        ui.label(RichText::new("password").size(12.0).color(theme::ink_faint()));
        ui.add(egui::TextEdit::singleline(&mut config.password).desired_width(130.0).font(egui::TextStyle::Monospace));
    });
    *app.shared.upstream.lock().unwrap() = config;
    hint(ui, "HTTP routing uses absolute-form requests and CONNECT for TLS; SOCKS5 supports username/password authentication.");
}

// ================= Sequencer =================

fn extract_token(response: &[u8], mode: usize, selector: &str) -> Option<Vec<u8>> {
    let parts = crate::util::parse_http(response);
    match mode {
        0 => crate::util::get_header(&parts.headers, selector).map(|v| v.into_bytes()),
        1 => parts
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .find_map(|(_, cookie)| {
                let first = cookie.split(';').next().unwrap_or("");
                let (name, value) = first.split_once('=')?;
                name.trim().eq_ignore_ascii_case(selector).then(|| value.trim().as_bytes().to_vec())
            }),
        _ => {
            let body = String::from_utf8_lossy(&response[parts.head_len.min(response.len())..]).into_owned();
            // The first capture group is the token (whole match when the
            // expression has no group).
            let re = regex::Regex::new(selector).ok()?;
            let caps = re.captures(&body)?;
            caps.get(1).or_else(|| caps.get(0)).map(|m| m.as_str().as_bytes().to_vec())
        }
    }
}

fn add_sequencer_sample(app: &mut App, sample: Vec<u8>) {
    if app.seq_ignore_abnormal {
        if let Some(first) = app.seq_samples.first() {
            let deviation = sample.len().abs_diff(first.len());
            if deviation > SEQUENCER_MAX_LENGTH_DEVIATION {
                app.seq_status = format!("ignored token with length deviation {deviation} (> {SEQUENCER_MAX_LENGTH_DEVIATION})");
                return;
            }
        }
    }
    app.seq_samples.push(sample);
}

/// Cookie names set by a response (Sequencer's "Cookie:" token locations).
fn set_cookie_names(resp: &[u8]) -> Vec<String> {
    let parts = crate::util::parse_http(resp);
    let mut v: Vec<String> = parts
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, val)| val.split('=').next().map(|n| n.trim().to_string()))
        .filter(|n| !n.is_empty())
        .collect();
    v.dedup();
    v
}

/// Hidden/form input names in an HTML response (Sequencer's "Form field:").
fn form_field_names(resp: &[u8]) -> Vec<String> {
    let parts = crate::util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[parts.head_len.min(resp.len())..]).to_string();
    let re = regex::Regex::new(r#"(?i)<input[^>]*\bname=["']?([^"' >]+)"#).unwrap();
    let mut v: Vec<String> = re.captures_iter(&body).map(|c| c[1].to_string()).collect();
    v.dedup();
    v
}

pub fn sequencer(app: &mut App, ui: &mut Ui) {
    // Burp's Sequencer (live 52685): Live capture | Manual load | Sequencer
    // settings. Live capture lists requests sent here, then the token
    // location (Cookie / Form field / Custom location) and Start live capture.
    // Drain samples gathered by a running live capture.
    if let Some(buf) = &app.seq_live_buf {
        let got: Vec<Vec<u8>> = std::mem::take(&mut *buf.lock().unwrap());
        for t in got {
            add_sequencer_sample(app, t);
        }
    }
    let live_running = app.seq_live_stop.as_ref().map(|f| !f.load(std::sync::atomic::Ordering::SeqCst)).unwrap_or(false);
    if let Some(v) = crate::ui::sub_tabs_pub(ui, &["Live capture", "Manual load", "\u{E270} Sequencer settings"], app.seq_sub) {
        app.seq_sub = v;
    }
    ui.add_space(8.0);
    let section = |ui: &mut Ui, title: &str, sub: &str| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(crate::theme::icon::QUESTION).size(16.0).color(theme::ink_dim()));
            ui.label(RichText::new(title).strong().size(14.0).color(theme::ink()));
        });
        ui.horizontal(|ui| {
            ui.add_space(28.0);
            ui.label(RichText::new(sub).size(12.5).color(theme::ink_dim()));
        });
        ui.add_space(6.0);
    };
    match app.seq_sub {
        0 => {
            section(ui, "Select live capture request", "Send requests here from other tools to configure a live capture. Select the request to use, configure the other options below, then click \"Start live capture\".");
            ui.horizontal_top(|ui| {
                ui.add_space(28.0);
                ui.vertical(|ui| {
                    ui.set_width(96.0);
                    if ui.add_sized([92.0, 22.0], egui::Button::new(RichText::new("Remove").strong())).clicked() {
                        if let Some(i) = app.seq_req_sel.take() {
                            if i < app.seq_requests.len() {
                                app.seq_requests.remove(i);
                            }
                        }
                    }
                    if ui.add_sized([92.0, 22.0], egui::Button::new(RichText::new("Clear").strong())).clicked() {
                        app.seq_requests.clear();
                        app.seq_req_sel = None;
                    }
                });
                let cols = [crate::table::Column::new("#", 70.0), crate::table::Column::new("Host", 150.0), crate::table::Column::new("Request", 260.0)];
                let rows: Vec<(usize, net::HistEntry)> = app.seq_requests.iter().cloned().enumerate().collect();
                let mut st = app.seq_table.clone();
                let mut pick = None;
                let sel = app.seq_req_sel;
                ui.allocate_ui(egui::vec2(500.0, 150.0), |ui| {
                    crate::table::table_body(ui, "seq_reqs", &cols, &rows, &mut st, 19.0, 120.0, &mut |(i, e), ui| {
                        let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                        if sel == Some(*i) {
                            ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                        }
                        let row = ui.horizontal(|ui| {
                            crate::table::cells(ui, &cols, &crate::table::TableState::default(), 19.0, &[
                                (0, (i + 1).to_string(), None),
                                (1, crate::ui::history_host(e), None),
                                (2, format!("{} {}", e.method, e.path), None),
                            ]);
                        }).response.interact(egui::Sense::click());
                        if row.clicked() {
                            pick = Some(*i);
                        }
                    });
                });
                app.seq_table = st;
                if pick.is_some() {
                    app.seq_req_sel = pick;
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                let chosen = app.seq_req_sel.and_then(|i| app.seq_requests.get(i).cloned());
                if live_running {
                    if ui.add(egui::Button::new(RichText::new(format!("Stop live capture ({} tokens)", app.seq_samples.len())).strong())).clicked() {
                        if let Some(f) = &app.seq_live_stop {
                            f.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                } else if ui.add_enabled(chosen.is_some(), egui::Button::new(RichText::new("Start live capture").strong())).clicked() {
                    if let Some(e) = chosen {
                        start_live_capture(app, e);
                    }
                }
                if !app.seq_samples.is_empty() {
                    ui.add_space(10.0);
                    if ui.button(format!("Analyze now ({} tokens)", app.seq_samples.len())).clicked() {
                        app.seq_stats = Some(analysis::analyze_tokens(&app.seq_samples));
                        let tokens: Vec<String> = app.seq_samples.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect();
                        app.seq_report = Some(analysis::analyze_sequence(&tokens));
                        app.seq_status = format!("analyzed {} sample(s)", app.seq_samples.len());
                    }
                    if ui.button("Clear tokens").clicked() {
                        app.seq_samples.clear();
                        app.seq_stats = None;
                        app.seq_report = None;
                    }
                }
            });
            ui.add_space(10.0);
            let r = ui.cursor();
            ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
            ui.add_space(10.0);
            section(ui, "Token location within response", "Select the location in the response where the token appears.");
            let resp = app.seq_req_sel.and_then(|i| app.seq_requests.get(i)).and_then(|e| e.resp_raw.clone()).unwrap_or_default();
            let cookies = set_cookie_names(&resp);
            let fields = form_field_names(&resp);
            egui::Grid::new("seq_loc").num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(28.0);
                    if ui.radio(app.seq_loc == 0, "Cookie:").clicked() { app.seq_loc = 0; }
                });
                egui::ComboBox::from_id_salt("seq_cookie").width(340.0).selected_text(if app.seq_loc == 0 { app.seq_selector.clone() } else { String::new() }).show_ui(ui, |ui| {
                    for n in &cookies {
                        if ui.selectable_label(false, n).clicked() { app.seq_loc = 0; app.seq_selector = n.clone(); }
                    }
                });
                ui.label("");
                ui.end_row();
                ui.horizontal(|ui| {
                    ui.add_space(28.0);
                    if ui.radio(app.seq_loc == 1, "Form field:").clicked() { app.seq_loc = 1; }
                });
                egui::ComboBox::from_id_salt("seq_field").width(340.0).selected_text(if app.seq_loc == 1 { app.seq_field.clone() } else { String::new() }).show_ui(ui, |ui| {
                    for n in &fields {
                        if ui.selectable_label(false, n).clicked() { app.seq_loc = 1; app.seq_field = n.clone(); }
                    }
                });
                ui.label("");
                ui.end_row();
                ui.horizontal(|ui| {
                    ui.add_space(28.0);
                    if ui.radio(app.seq_loc == 2, "Custom location:").clicked() { app.seq_loc = 2; }
                });
                if ui.add(egui::TextEdit::singleline(&mut app.seq_custom).hint_text("regex with one capture group").desired_width(340.0)).changed() {
                    app.seq_loc = 2;
                }
                if ui.button(RichText::new("Configure").strong()).on_hover_text("The first capture group of this regular expression is the token").clicked() {
                    app.seq_loc = 2;
                }
                ui.end_row();
            });
            if !app.seq_status.is_empty() {
                ui.add_space(6.0);
                hint(ui, &app.seq_status);
            }
        }
        1 => {
            section(ui, "Manual load", "Paste or load a list of tokens (one per line), then click \"Analyze now\".");
            ui.horizontal_top(|ui| {
                ui.add_space(28.0);
                ui.vertical(|ui| {
                    if ui.add_sized([92.0, 22.0], egui::Button::new(RichText::new("Load ...").strong())).clicked() {
                        match std::fs::read_to_string(app.seq_load_path.trim()) {
                            Ok(t) => app.seq_manual.push_str(&t),
                            Err(_) => crate::feedback::toast(crate::feedback::Level::Error, "Could not read the token file"),
                        }
                    }
                    ui.add(egui::TextEdit::singleline(&mut app.seq_load_path).hint_text("file").desired_width(92.0));
                    if ui.add_sized([92.0, 22.0], egui::Button::new(RichText::new("Clear").strong())).clicked() {
                        app.seq_manual.clear();
                    }
                });
                ui.add(egui::TextEdit::multiline(&mut app.seq_manual).font(egui::TextStyle::Monospace).desired_rows(10).desired_width(500.0));
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                if ui.add_enabled(!app.seq_manual.trim().is_empty(), egui::Button::new(RichText::new("Analyze now").strong())).clicked() {
                    app.seq_samples.clear();
                    for line in app.seq_manual.clone().lines().filter(|l| !l.trim().is_empty()) {
                        add_sequencer_sample(app, line.trim().as_bytes().to_vec());
                    }
                    app.seq_stats = Some(analysis::analyze_tokens(&app.seq_samples));
                    let tokens: Vec<String> = app.seq_samples.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect();
                    app.seq_report = Some(analysis::analyze_sequence(&tokens));
                }
                ui.label(RichText::new(format!("{} tokens", app.seq_manual.lines().filter(|l| !l.trim().is_empty()).count())).size(12.5).color(theme::ink_dim()));
            });
        }
        _ => {
            section(ui, "Token handling", "Settings applied to captured tokens.");
            ui.horizontal(|ui| {
                ui.add_space(28.0);
                ui.checkbox(&mut app.seq_ignore_abnormal, "Ignore tokens whose length deviates by more than 5 characters");
            });
        }
    }
    if let Some(stats) = &app.seq_stats {
        ui.add_space(10.0);
        ui.label(RichText::new("Summary").strong().size(14.0).color(theme::ink()));
        egui::Grid::new("seq_stats").striped(true).num_columns(2).show(ui, |ui| {
            for (k, v) in [
                ("Samples", stats.sample_count.to_string()),
                ("Token length", stats.token_length.to_string()),
                ("Bits per character", format!("{:.4}", stats.bits_per_character)),
                ("Total entropy (bits)", format!("{:.2}", stats.total_entropy_bits)),
            ] {
                ui.label(RichText::new(k).size(12.5).color(theme::ink()));
                ui.label(RichText::new(v).size(12.5).color(theme::ink_dim()));
                ui.end_row();
            }
        });
    }
    if let Some(report) = &app.seq_report {
        ui.add_space(8.0);
        crate::analysis_ui::show_sequencer_report(ui, report);
    }
}

/// Burp's live capture: re-issue the request in the background and collect
/// the token from each response until stopped (or 20,000 tokens).
fn start_live_capture(app: &mut App, e: net::HistEntry) {
    let (mode, selector) = match app.seq_loc {
        0 => (1, app.seq_selector.clone()),
        1 => (2, format!(r#"(?i)name=["']?{}["']?[^>]*value=["']?([^"' >]*)"#, regex::escape(&app.seq_field))),
        _ => (2, app.seq_custom.clone()),
    };
    if selector.trim().is_empty() {
        app.seq_status = "choose where the token is (cookie, form field or custom location)".into();
        return;
    }
    let parts = crate::util::parse_http(&e.req_raw);
    let host = crate::util::get_header(&parts.headers, "Host").unwrap_or_default();
    if host.is_empty() {
        app.seq_status = "request has no Host header".into();
        return;
    }
    let (h, p) = net::split_h_p(&host, e.port);
    let req = crate::util::origin_form(&e.req_raw);
    let https = e.https;
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    app.seq_live_buf = Some(buf.clone());
    app.seq_live_stop = Some(stop.clone());
    app.seq_samples.clear();
    app.seq_status = "live capture running".into();
    let shared = app.shared.clone();
    std::thread::spawn(move || {
        let mut n = 0;
        let mut misses = 0;
        while !stop.load(std::sync::atomic::Ordering::SeqCst) && n < 20_000 {
            let up = if https { net::send_tls_raw(&shared, &h, p, &req) } else { net::send_raw(&shared, &h, p, &req) };
            if let Some(t) = up.resp.and_then(|r| extract_token(&r, mode, &selector)) {
                buf.lock().unwrap().push(t);
                n += 1;
                misses = 0;
            } else {
                // A token location that never matches must not hammer the
                // target: give up after 20 consecutive misses.
                misses += 1;
                if up.error.is_some() || misses >= 20 {
                    shared.log("Sequencer live capture stopped: token not found in the responses");
                    break;
                }
            }
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    });
}

#[cfg(test)]
mod seq_tests {
    #[test]
    fn regex_token_uses_the_first_capture_group() {
        let r = b"HTTP/1.1 200 OK\r\n\r\n{\"answer\":\"16\"}";
        assert_eq!(super::extract_token(r, 2, r#""answer":"([0-9]+)""#), Some(b"16".to_vec()));
        assert_eq!(super::extract_token(r, 2, r#"[0-9]+"#), Some(b"16".to_vec()));
    }
}

// ================= Sessions and macros =================

pub fn sessions(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Session handling").color(theme::ink()).size(15.0));
    ui.add_space(4.0);
    hint(ui, "Rules run before match-and-replace. Set-header takes 'Name: value'; use-cookie names a captured cookie; run-macro executes a stored request first.");
    let mut rules = app.shared.session_rules.lock().unwrap().clone();
    let mut remove = None;
    egui::Grid::new("session_rules").striped(true).num_columns(6).show(ui, |ui| {
        for (i, rule) in rules.iter_mut().enumerate() {
            ui.checkbox(&mut rule.enabled, "");
            ui.add(egui::TextEdit::singleline(&mut rule.name).desired_width(140.0).font(egui::TextStyle::Monospace));
            ui.horizontal(|ui| {
                for action in ["set header", "use cookie", "run macro"] {
                    if ui.selectable_label(rule.action == action, RichText::new(action).size(12.0).color(if rule.action == action { c(theme::ORANGE) } else { theme::ink_faint() })).clicked() {
                        rule.action = action.into();
                    }
                }
            });
            ui.add(egui::TextEdit::singleline(&mut rule.host_match).desired_width(120.0).hint_text("host contains").font(egui::TextStyle::Monospace));
            ui.add(egui::TextEdit::singleline(&mut rule.value).desired_width(190.0).hint_text("value").font(egui::TextStyle::Monospace));
            if ui.button("x").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        rules.remove(i);
    }
    if ui.button("+ session rule").clicked() {
        rules.push(net::SessionRule::new());
    }
    *app.shared.session_rules.lock().unwrap() = rules;

    ui.add_space(10.0);
    ui.label(RichText::new("Macros").color(theme::ink()).size(14.0).strong());
    let macros = app.shared.macros.lock().unwrap().clone();
    egui::Grid::new("macros").striped(true).num_columns(3).show(ui, |ui| {
        for (i, m) in macros.iter().enumerate() {
            ui.label(RichText::new(m.name.clone()).size(12.0).color(theme::ink_dim()));
            if ui.button("run").clicked() {
                let parts = crate::util::parse_http(m.request.as_bytes());
                let host = crate::util::get_header(&parts.headers, "Host").unwrap_or_default();
                if host.is_empty() {
                    app.shared.log("Macro has no Host header");
                } else {
                    let (h, p) = net::split_h_p(&host, 80);
                    let up = net::send_raw(&app.shared, &h, p, m.request.as_bytes());
                    app.shared.log(&format!(
                        "Macro {} {}",
                        m.name,
                        if up.resp.is_some() { "completed" } else { "failed" }
                    ));
                }
            }
            if ui.button("load into editor").clicked() {
                app.macro_name = m.name.clone();
                app.macro_request = m.request.clone();
            }
            if ui.button("x").clicked() {
                app.shared.macros.lock().unwrap().remove(i);
            }
            ui.end_row();
        }
    });
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.macro_name).desired_width(130.0).font(egui::TextStyle::Monospace));
        if ui.button("Save macro").clicked() && !app.macro_name.trim().is_empty() {
            let mut macros = app.shared.macros.lock().unwrap();
            if let Some(existing) = macros.iter_mut().find(|m| m.name == app.macro_name) {
                existing.request = app.macro_request.clone();
            } else {
                macros.push(net::Macro { name: app.macro_name.clone(), request: app.macro_request.clone() });
            }
        }
    });
    egui::ScrollArea::vertical().id_salt("macro_scroll").max_height(180.0).show(ui, |ui| {
        egui::TextEdit::multiline(&mut app.macro_request)
            .font(egui::TextStyle::Monospace)
            .code_editor()
            .desired_rows(7)
            .desired_width(ui.available_width())
            .show(ui);
    });
}

// ================= WebSocket history =================

pub fn websocket_history(app: &mut App, ui: &mut Ui) {
    ui.label(RichText::new("WebSocket history").color(theme::ink()).size(14.0).strong());
    ui.add_space(4.0);
    hint(ui, "Plain-HTTP upgrades are relayed and every frame is captured. TLS handshakes are recorded; encrypted frame relay is not supported yet.");
    ui.add_space(2.0);
    let entries = app.shared.ws_history.lock().unwrap().clone();
    let mut selected = app.ws_sel;
    egui::ScrollArea::vertical().id_salt("ws_scroll").show(ui, |ui| {
        egui::Grid::new("ws_grid").striped(true).num_columns(7).show(ui, |ui| {
            for e in entries.iter().rev() {
                let is_sel = selected == Some(e.id);
                let row = ui
                    .horizontal(|ui| {
                        ui.monospace(RichText::new(e.id.to_string()).size(12.0).color(theme::ink_faint()));
                        ui.monospace(RichText::new(crate::ui::time_of_day(e.ts)).size(12.0).color(theme::ink_faint()));
                        ui.monospace(RichText::new(e.host.clone()).size(12.0).color(theme::ink_dim()));
                        ui.monospace(RichText::new(e.direction.clone()).size(12.0).color(theme::ink_faint()));
                        ui.monospace(RichText::new(e.opcode.clone()).size(12.0).color(c(theme::ORANGE)));
                        ui.monospace(RichText::new(e.payload.len().to_string()).size(12.0).color(theme::ink_faint()));
                        ui.monospace(RichText::new(e.payload.clone()).size(12.0).color(theme::ink_dim()));
                    })
                    .response
                    .interact(egui::Sense::click());
                if row.clicked() {
                    selected = if is_sel { None } else { Some(e.id) };
                }
                ui.end_row();
            }
        });
        if entries.is_empty() {
            ui.label(RichText::new("no WebSocket traffic yet").size(12.0).color(theme::ink_faint()));
        }
    });
    app.ws_sel = selected;

    // Frame inspector: the selected frame's payload, editable for replay prep.
    if let Some(id) = app.ws_sel {
        if let Some(e) = entries.iter().find(|e| e.id == id) {
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!("#{} {} {} {} ({} B)", e.id, e.direction, e.host, e.opcode, e.payload.len()))
                    .monospace()
                    .size(12.0)
                    .color(theme::header_ink()),
            );
            let mut text = e.payload.clone();
            egui::ScrollArea::vertical().id_salt("ws_payload_scroll").max_height(160.0).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text)
                        .font(egui::TextStyle::Monospace)
                        .code_editor()
                        .desired_rows(6)
                        .desired_width(ui.available_width()),
                );
            });
        }
    }
}

// ================= Cross-tool search =================

pub fn search(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Search").color(theme::ink()).size(15.0));
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.search_query).desired_width(360.0).font(egui::TextStyle::Monospace));
        ui.checkbox(&mut app.search_case, "case sensitive");
        if ui.button("Search all tools").clicked() && !app.search_query.trim().is_empty() {
            let mut records = Vec::new();
            for e in app.shared.history.lock().unwrap().iter() {
                records.push(analysis::SearchRecord {
                    id: e.id.to_string(),
                    tool: "Proxy".into(),
                    title: format!("{} {}:{}{}", e.method, e.host, e.port, e.path),
                    body: format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&e.req_raw),
                        e.resp_raw.as_deref().map(|r| String::from_utf8_lossy(r).into_owned()).unwrap_or_default()
                    ),
                });
            }
            for r in app.shared.repeaters.lock().unwrap().iter() {
                records.push(analysis::SearchRecord {
                    id: format!("repeater-{}", r.name),
                    tool: "Repeater".into(),
                    title: r.name.clone(),
                    body: format!(
                        "{}\n{}",
                        r.request,
                        r.response.as_deref().map(|x| String::from_utf8_lossy(x).into_owned()).unwrap_or_default()
                    ),
                });
            }
            for i in app.shared.issues.lock().unwrap().iter() {
                records.push(analysis::SearchRecord {
                    id: i.id.to_string(),
                    tool: "Scanner".into(),
                    title: format!("{} {}", i.name, i.host),
                    body: format!("{} {}\n{}", i.host, i.path, i.detail),
                });
            }
            for w in app.shared.ws_history.lock().unwrap().iter() {
                records.push(analysis::SearchRecord {
                    id: w.id.to_string(),
                    tool: "WebSocket".into(),
                    title: format!("{} {}", w.direction, w.opcode),
                    body: w.payload.clone(),
                });
            }
            app.search_results = analysis::search_records(app.search_case, &app.search_query, &records);
        }
    });
    ui.add_space(6.0);
    egui::ScrollArea::vertical().id_salt("search_results_scroll").show(ui, |ui| {
        for hit in &app.search_results {
            ui.horizontal(|ui| {
                ui.label(RichText::new(hit.tool.clone()).size(12.0).color(c(theme::ORANGE)));
                ui.label(RichText::new(hit.title.clone()).size(12.5).color(theme::ink_dim()));
            });
            ui.monospace(RichText::new(hit.excerpt.clone()).size(12.0).color(theme::ink_faint()));
            ui.add_space(4.0);
        }
        if app.search_results.is_empty() {
            ui.label(RichText::new("no results yet").size(12.0).color(theme::ink_faint()));
        }
    });
}

// ================= Extensions =================

// ================= Embedded browser (M-parity, wave 28) =================

/// Where Burp's own embedded Chromium lives, if the Burp installation is
/// present on this machine. build 52685 ships a versioned Chromium directory
/// next to burpsuite.jar (/opt/BurpSuite/burpbrowser/<version>/chrome); the
/// reference install has 150.0.7871.186. Returned newest-first when several
/// versions are installed.
fn burp_bundled_browsers() -> Vec<std::path::PathBuf> {
    let mut out: Vec<(u64, std::path::PathBuf)> = Vec::new();
    for root in ["/opt/BurpSuite/burpbrowser", "/usr/lib/burpbrowser"] {
        let Ok(entries) = std::fs::read_dir(root) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            let chrome = p.join("chrome");
            if !chrome.is_file() {
                continue;
            }
            // Version directories sort numerically; a non-numeric name sorts 0.
            let ver: u64 = e
                .file_name()
                .to_string_lossy()
                .split('.')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            out.push((ver, chrome));
        }
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out.into_iter().map(|(_, p)| p).collect()
}

/// A launcher script that pins its own `--user-data-dir` (e.g. an xrdp
/// wrapper in /usr/local/bin) hands every launch to the desktop browser that
/// is already open, dropping our proxy flags. Distro launchers (/usr/bin/
/// chromium, google-chrome) are scripts too but pass the profile through.
fn pins_profile(path: &std::path::Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else { return false };
    bytes.starts_with(b"#!") && bytes.len() < 64 * 1024 && String::from_utf8_lossy(&bytes).contains("--user-data-dir")
}

/// The browser candidates as absolute paths, in preference order: Burp's own
/// bundled Chromium first (the real embedded browser of build 52685), then the
/// system Chrome/Chromium found on PATH (build 52685 also drives
/// chrome/chromium by name: Zrg5.java:38 / Zrgu.java:28), skipping
/// profile-pinning wrappers.
fn browser_candidates() -> Vec<String> {
    let mut v: Vec<String> = burp_bundled_browsers().into_iter().map(|p| p.to_string_lossy().into_owned()).collect();
    let path = std::env::var_os("PATH").unwrap_or_default();
    for name in ["google-chrome-stable", "google-chrome", "chromium-browser", "chromium"] {
        for dir in std::env::split_paths(&path) {
            let p = dir.join(name);
            if p.is_file() && !pins_profile(&p) {
                let canon = |x: &str| std::fs::canonicalize(x).unwrap_or_else(|_| x.into());
                let s = p.to_string_lossy().into_owned();
                if !v.iter().any(|x| canon(x) == canon(&s)) {
                    v.push(s);
                }
            }
        }
    }
    for p in ["/opt/google/chrome/chrome", "/usr/lib/chromium/chromium"] {
        if std::path::Path::new(p).is_file() && !v.iter().any(|x| x == p) {
            v.push(p.into());
        }
    }
    v
}

/// True when WebProbe runs as root: Chromium refuses to start as root unless
/// its sandbox is off (Burp's equivalent is Settings > Burp's browser >
/// "Allow Burp's browser to run without a sandbox").
fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The profile for the browser of the listener on `port` (the private browser
/// listener, random per WebProbe run, as Burp uses a fresh profile per
/// browser session). A second launch in the same run opens a window in the
/// running instance; another WebProbe gets its own instance instead of
/// borrowing one wired to the wrong proxy.
fn browser_profile(port: u16) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("webprobe-browser-{port}"))
}

/// Close the browsers WebProbe opened (whole process trees). Burp's browser
/// closes when Burp exits; leaving them would keep tens of processes running.
pub fn close_launched_browsers(shared: &crate::net::Shared) {
    for (pid, profile) in shared.browsers.lock().unwrap().drain(..) {
        crate::util::kill_process_tree(pid, Some(&profile), std::time::Duration::from_secs(2));
    }
}

/// A private HOME for the browser whose NSS database (~/.pki/nssdb, where
/// Chromium on Linux reads user-added roots) trusts WebProbe's CA, so HTTPS
/// through the proxy loads with no warning, the way Burp's browser trusts
/// Burp's CA. Only this browser sees it: the user's own browsers and the
/// system trust store are untouched. None when certutil (libnss3-tools) is
/// missing; --ignore-certificate-errors still lets pages load then.
fn browser_home_with_ca(profile: &std::path::Path, ca_pem: &str) -> Option<std::path::PathBuf> {
    let home = profile.join("home");
    let db = home.join(".pki").join("nssdb");
    let marker = db.join("webprobe-ca.pem");
    if std::fs::read_to_string(&marker).ok().as_deref() == Some(ca_pem) {
        return Some(home);
    }
    std::fs::create_dir_all(&db).ok()?;
    let dbarg = format!("sql:{}", db.display());
    let certutil = |args: &[&str]| std::process::Command::new("certutil").args(args).output().ok().filter(|o| o.status.success());
    if !db.join("cert9.db").exists() {
        certutil(&["-N", "-d", &dbarg, "--empty-password"])?;
    }
    std::fs::write(&marker, ca_pem).ok()?;
    let _ = certutil(&["-D", "-d", &dbarg, "-n", "WebProbe Local CA"]);
    certutil(&["-A", "-d", &dbarg, "-n", "WebProbe Local CA", "-t", "C,,", "-i", &marker.to_string_lossy()])?;
    Some(home)
}

/// First-run preferences that keep the browser's own traffic out of the
/// proxy and the history: no omnibox search suggestions (every keystroke in
/// the address bar would go to the search engine), no sign-in, no Safe
/// Browsing lookups, no network prediction, no alternate error pages.
fn seed_browser_prefs(profile: &std::path::Path) {
    let file = profile.join("Default").join("Preferences");
    if file.exists() {
        return;
    }
    let prefs = serde_json::json!({
        "search": {"suggest_enabled": false},
        "signin": {"allowed": false},
        "safebrowsing": {"enabled": false},
        "net": {"network_prediction_options": 2},
        "alternate_error_pages": {"enabled": false},
        "browser": {"has_seen_welcome_page": true},
        "url_keyed_anonymized_data_collection": {"enabled": false},
        "translate": {"enabled": false},
    });
    if std::fs::create_dir_all(file.parent().unwrap()).is_ok() {
        let _ = std::fs::write(&file, prefs.to_string());
    }
}

/// Delete browser profiles left by earlier WebProbe runs whose browser is no
/// longer running (each run gets a new random listener port, so they pile up).
fn clear_old_profiles(current: u16) {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(port) = name.strip_prefix("webprobe-browser-").and_then(|p| p.parse::<u16>().ok()) else { continue };
        if port == current || !e.path().is_dir() {
            continue;
        }
        clear_stale_lock(&e.path());
        if std::fs::symlink_metadata(e.path().join("SingletonLock")).is_err() {
            let _ = std::fs::remove_dir_all(e.path());
            let _ = std::fs::remove_file(std::env::temp_dir().join(format!("webprobe-browser-{port}.log")));
        }
    }
}

/// Remove Chromium's singleton lock when the process that holds it is gone
/// (a crashed or killed browser leaves it behind and blocks the next start).
/// The lock is a symlink to "<host>-<pid>".
fn clear_stale_lock(profile: &std::path::Path) {
    let lock = profile.join("SingletonLock");
    let Ok(target) = std::fs::read_link(&lock) else { return };
    let t = target.to_string_lossy();
    let Some((host, pid)) = t.rsplit_once('-') else { return };
    let this_host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let alive = pid.parse::<u32>().is_ok_and(|p| std::path::Path::new(&format!("/proc/{p}")).exists());
    if host == this_host.trim() && !alive {
        for f in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
            let _ = std::fs::remove_file(profile.join(f));
        }
    }
}

/// The launch arguments: proxy preconfigured, the per-port profile, Burp's own
/// embedded-browser flags (burp.Zi9a.java:57 passes `--class=burp-browser`
/// and `--ignore-certificate-errors`, so HTTPS through the proxy's MITM CA
/// works without installing the CA), `--no-sandbox` when running as root,
/// and the onboarding page (served at http://webprobe through the proxy) as
/// start URL.
fn browser_args(port: u16, root: bool) -> Vec<String> {
    let mut v = vec![
        format!("--proxy-server=http://127.0.0.1:{port}"),
        // Chromium sends localhost / 127.0.0.1 direct unless told otherwise;
        // Burp's browser passes this so local targets go through the proxy.
        "--proxy-bypass-list=<-loopback>".into(),
        format!("--user-data-dir={}", browser_profile(port).display()),
        "--class=burp-browser".into(),
        "--ignore-certificate-errors".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        // Burp's browser flags that keep the browser's own background traffic
        // (Safe Browsing, component updates, pings) out of the proxy.
        "--disable-background-networking".into(),
        "--no-pings".into(),
        "--disable-default-apps".into(),
        "--disable-breakpad".into(),
        "--disable-crash-reporter".into(),
        "--no-service-autorun".into(),
        "--disable-features=ChromeWhatsNewUI,HttpsUpgrades,LensOverlay,TrackingProtection3pcd".into(),
    ];
    if root {
        v.push("--no-sandbox".into());
    }
    v.push("http://webprobe/".into());
    v
}

/// "Open browser" (build 52685 Zw5t.java:63, Zrxt.java:217): launch a
/// proxy-configured Chromium. Burp embeds its own Chromium; when the Burp
/// installation is present WebProbe launches that exact binary, so the
/// browsing surface is Burp's own — otherwise the system Chrome/Chromium.
/// The launch is checked: a browser that exits with an error within 1.5
/// seconds is reported (with its last log line) and the next candidate is
/// tried; a quick clean exit means the window opened in this proxy's running
/// instance.
pub fn launch_preconfigured_browser(shared: &std::sync::Arc<crate::net::Shared>) -> Result<String, String> {
    let port = crate::net::browser_listener(shared)?;
    clear_old_profiles(port);
    let args = browser_args(port, running_as_root());
    let profile = browser_profile(port);
    let _ = std::fs::create_dir_all(&profile);
    clear_stale_lock(&profile);
    let log_path = std::env::temp_dir().join(format!("webprobe-browser-{port}.log"));
    seed_browser_prefs(&profile);
    let home = browser_home_with_ca(&profile, shared.mitm.ca_pem());
    if home.is_none() {
        shared.log("certutil not found: the browser will load HTTPS through the proxy but mark it Not secure (install libnss3-tools)");
    }
    let mut tried = Vec::new();
    for name in browser_candidates() {
        let log = std::fs::File::create(&log_path).ok();
        let mut cmd = std::process::Command::new(&name);
        crate::util::own_process_group(&mut cmd);
        cmd.args(&args).stdout(std::process::Stdio::null());
        if let Some(h) = &home {
            // The X server cookie is found through HOME by default; keep it.
            if std::env::var_os("XAUTHORITY").is_none() {
                if let Some(real) = std::env::var_os("HOME") {
                    let xa = std::path::PathBuf::from(real).join(".Xauthority");
                    if xa.exists() {
                        cmd.env("XAUTHORITY", xa);
                    }
                }
            }
            cmd.env("HOME", h);
        }
        match log {
            Some(f) => cmd.stderr(f),
            None => cmd.stderr(std::process::Stdio::null()),
        };
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tried.push(format!("{name}: spawn failed ({e})"));
                continue;
            }
        };
        let t0 = std::time::Instant::now();
        let mut exit = None;
        while t0.elapsed() < std::time::Duration::from_millis(1500) {
            if let Ok(Some(st)) = child.try_wait() {
                exit = Some(st);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let is_burp = name.contains("burpbrowser");
        match exit {
            Some(st) if !st.success() => {
                let last = std::fs::read_to_string(&log_path)
                    .unwrap_or_default()
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .map(|l| l.trim().chars().take(200).collect::<String>())
                    .unwrap_or_else(|| format!("exit {st}"));
                tried.push(format!("{name}: exited ({last})"));
                continue;
            }
            Some(_) => {
                shared.log(&format!("Opened a new window in the browser already running for proxy 127.0.0.1:{port}"));
            }
            None => {
                // Closed with WebProbe, like Burp's browser (App::on_exit).
                shared.browsers.lock().unwrap().push((child.id(), profile.display().to_string()));
                // Reap it when it closes, so no zombie is left behind.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                shared.log(&format!(
                    "Launched {name} with the proxy preconfigured (127.0.0.1:{port}){}",
                    if is_burp { " — Burp's own bundled Chromium" } else { "" }
                ));
            }
        }
        return Ok(if is_burp { format!("{name} (Burp embedded Chromium)") } else { name });
    }
    Err(if tried.is_empty() {
        "no Chromium found. Install Burp (which ships its own embedded Chromium) or Google Chrome.".into()
    } else {
        format!("the browser did not start: {}", tried.join("; "))
    })
}

pub fn extensions(app: &mut App, ui: &mut Ui) {
    use crate::ext_host::ProxyHooks as _;
    // Burp's Extensions (live 52685): Installed | BApp Store | APIs | Custom
    // scan checks | Bambda library | Extensions settings. Installed shows the
    // system-impact bar, the extension table with Add / Remove / Up / Down,
    // and Details / Output / Errors for the selection.
    if let Some(v) = crate::ui::sub_tabs_pub(ui, &["Installed", "BApp Store", "APIs", "Custom scan checks", "Bambda library", "\u{E270} Extensions settings"], app.ext_sub) {
        app.ext_sub = v;
    }
    ui.add_space(6.0);
    match app.ext_sub {
        0 => {
            let n = app.shared.ext_host.lock().unwrap().extensions.len();
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("Total estimated system impact:").size(12.5).color(theme::ink()));
                ui.label(RichText::new(if n == 0 { "None" } else { "Low" }).strong().size(12.5).color(theme::ink()));
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("WebProbe extensions").strong().size(14.0).color(theme::ink()));
            });
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("Extensions let you customize WebProbe's behavior using your own or third-party code (Rust hooks in-process, Montoya .jar extensions through the sidecar JVM).").size(12.5).color(theme::ink_dim()));
            });
            ui.add_space(6.0);
            let mut action: Option<&str> = None;
            ui.horizontal_top(|ui| {
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    for label in ["Add", "Remove", "Up", "Down"] {
                        if ui.add_sized([90.0, 22.0], egui::Button::new(RichText::new(label).strong())).clicked() {
                            action = Some(label);
                        }
                    }
                });
                let cols = [
                    crate::table::Column::new("Loaded", 60.0),
                    crate::table::Column::new("Type", 70.0),
                    crate::table::Column::new("Name", 360.0),
                    crate::table::Column::new("Hooks", 360.0),
                ];
                let rows: Vec<(usize, bool, String, String)> = app
                    .shared
                    .ext_host
                    .lock()
                    .unwrap()
                    .extensions
                    .iter()
                    .enumerate()
                    .map(|(i, e)| (i, e.enabled, e.hooks.extension_name().to_string(), e.hooks.hooks_registered().to_string()))
                    .collect();
                let mut st = app.ext_table.clone();
                let mut pick = None;
                let mut toggle = None;
                let sel = app.ext_sel;
                ui.allocate_ui_with_layout(egui::vec2(ui.available_width() - 16.0, 160.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                    crate::table::table_body(ui, "ext_rows", &cols, &rows, &mut st, 19.0, 130.0, &mut |(i, en, name, hooks), ui| {
                        let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                        if sel == Some(*i) {
                            ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                        }
                        let row = ui.horizontal(|ui| {
                            let mut on = *en;
                            ui.allocate_ui(egui::vec2(60.0 + crate::table::DIVIDER, 19.0), |ui| {
                                if ui.checkbox(&mut on, "").changed() {
                                    toggle = Some(*i);
                                }
                            });
                            let ty = if hooks.contains("sidecar") || name.ends_with(".jar") { "Java" } else { "Rust" };
                            crate::table::cell_w(ui, &cols[1], 70.0, ty, None, 19.0);
                            ui.add_space(crate::table::DIVIDER);
                            crate::table::cell_w(ui, &cols[2], 360.0, name.clone(), None, 19.0);
                            ui.add_space(crate::table::DIVIDER);
                            crate::table::cell_w(ui, &cols[3], 360.0, hooks.clone(), None, 19.0);
                        }).response.interact(egui::Sense::click());
                        if row.clicked() {
                            pick = Some(*i);
                        }
                    });
                });
                app.ext_table = st;
                if pick.is_some() {
                    app.ext_sel = pick;
                }
                if let Some(i) = toggle {
                    let mut host = app.shared.ext_host.lock().unwrap();
                    if let Some(e) = host.extensions.get_mut(i) {
                        e.enabled = !e.enabled;
                        app.shared.log(&format!("Extension {} {}", e.hooks.extension_name(), if e.enabled { "enabled" } else { "disabled" }));
                    }
                }
            });
            match action {
                Some("Add") => app.ext_add_open = true,
                Some("Remove") => {
                    if let Some(i) = app.ext_sel.take() {
                        let mut host = app.shared.ext_host.lock().unwrap();
                        if i < host.extensions.len() {
                            let e = host.extensions.remove(i);
                            app.shared.log(&format!("Removed extension {}", e.hooks.extension_name()));
                        }
                    }
                }
                Some(dir @ ("Up" | "Down")) => {
                    if let Some(i) = app.ext_sel {
                        let mut host = app.shared.ext_host.lock().unwrap();
                        let j = if dir == "Up" { i.checked_sub(1) } else { (i + 1 < host.extensions.len()).then_some(i + 1) };
                        if let Some(j) = j {
                            host.extensions.swap(i, j);
                            app.ext_sel = Some(j);
                        }
                    }
                }
                _ => {}
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                if let Some(v) = crate::msgpane::underline_tabs(ui, &["Details", "Output", "Errors"], app.ext_detail, 13.0) {
                    app.ext_detail = v;
                }
            });
            let r = ui.cursor();
            ui.painter().hline(ui.max_rect().x_range(), r.top(), egui::Stroke::new(1.0, theme::line()));
            ui.add_space(6.0);
            let sel = app.ext_sel.and_then(|i| {
                let host = app.shared.ext_host.lock().unwrap();
                host.extensions.get(i).map(|e| (e.enabled, e.hooks.extension_name().to_string(), e.hooks.hooks_registered().to_string()))
            });
            let events: Vec<String> = app.shared.events.lock().map(|e| e.clone()).unwrap_or_default();
            egui::ScrollArea::vertical().id_salt("ext_detail").auto_shrink([false, false]).show(ui, |ui| match (app.ext_detail, &sel) {
                (_, None) => {
                    ui.label(RichText::new("Select an extension to see its details, output and errors.").size(12.5).color(theme::ink_dim()));
                }
                (0, Some((en, name, hooks))) => {
                    egui::Grid::new("ext_det").num_columns(2).spacing([20.0, 6.0]).show(ui, |ui| {
                        for (k, v) in [("Extension loaded", if *en { "Yes".to_string() } else { "No".to_string() }), ("Name", name.clone()), ("Hooks registered", hooks.clone())] {
                            ui.label(RichText::new(k).size(12.5).color(theme::ink()));
                            ui.label(RichText::new(v).size(12.5).color(theme::ink_dim()));
                            ui.end_row();
                        }
                    });
                }
                (k, Some((_, name, _))) => {
                    let want_err = k == 2;
                    for ev in events.iter().filter(|e| e.contains(name.as_str()) || e.contains("Sidecar") || e.contains("Extension")) {
                        let is_err = ev.to_ascii_lowercase().contains("fail") || ev.to_ascii_lowercase().contains("error");
                        if is_err == want_err {
                            ui.label(RichText::new(ev).monospace().size(12.0).color(theme::ink_dim()));
                        }
                    }
                }
            });
            if app.ext_add_open {
                let mut open = true;
                egui::Window::new("Load extension").open(&mut open).collapsible(false).default_width(520.0).show(ui.ctx(), |ui| {
                    ui.label(RichText::new("Extension details").strong().size(13.0));
                    ui.horizontal(|ui| {
                        ui.label("Extension type:");
                        ui.label(RichText::new("Java (Montoya API, sidecar JVM)").color(theme::ink_dim()));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Extension file (.jar):");
                        ui.add(egui::TextEdit::singleline(&mut app.ext_add_path).desired_width(300.0));
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let next = egui::Button::new(RichText::new("Next").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1));
                        if ui.add(next).clicked() {
                            let path = app.ext_add_path.trim().to_string();
                            match crate::ext_host::JavaSidecar::spawn(&path) {
                                Ok(sidecar) => {
                                    app.shared.log(&format!("Sidecar JVM loaded Montoya extension: {} ({})", sidecar.extension_name(), sidecar.hooks_registered()));
                                    app.shared.ext_host.lock().unwrap().extensions.push(crate::ext_host::LoadedExtension { enabled: true, hooks: Box::new(sidecar) });
                                    app.ext_add_open = false;
                                }
                                Err(e) => {
                                    app.shared.log(&format!("Sidecar JVM failed to load {path}: {e}"));
                                    crate::feedback::toast(crate::feedback::Level::Error, format!("Could not load the extension: {e}"));
                                }
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            app.ext_add_open = false;
                        }
                    });
                });
                if !open {
                    app.ext_add_open = false;
                }
            }
        }
        1 => {
            ui.label(RichText::new("Customize WebProbe with extensions").strong().size(14.0).color(theme::ink()));
            ui.label(RichText::new("The BApp Store is not fetched (offline); these well-known BApps are Java jars you can load with Installed > Add.").size(12.5).color(theme::ink_dim()));
            ui.add_space(6.0);
            const CATALOG: &[(&str, &str)] = &[
                ("Active Scan++", "Additional active scan checks for common and unusual server misconfigurations."),
                ("Autorize", "Repeats requests with a low-privileged session to detect broken access control."),
                ("Collaborator Everywhere", "Injects Collaborator payloads into headers to surface out-of-band blind vulnerabilities."),
                ("JWT*", "Decodes, manipulates and attacks JSON Web Tokens."),
                ("Logger++", "Logs all requests and responses with a rich search and filter language."),
                ("Param Miner", "Discovers hidden parameters by fuzzing and observes their effect on responses."),
                ("Turbo Intruder", "High-speed HTTP brute-forcing for large-scale attacks."),
                ("Upload Scanner", "Uploads files with payload injection to test file-handling endpoints."),
            ];
            egui::Grid::new("bapps").striped(true).num_columns(2).spacing([24.0, 6.0]).show(ui, |ui| {
                ui.label(RichText::new("Name").strong());
                ui.label(RichText::new("Detail").strong());
                ui.end_row();
                for (name, desc) in CATALOG {
                    ui.label(RichText::new(*name).size(12.5).color(theme::ink()));
                    ui.label(RichText::new(*desc).size(12.5).color(theme::ink_dim()));
                    ui.end_row();
                }
            });
        }
        2 => {
            ui.label(RichText::new("APIs").strong().size(14.0).color(theme::ink()));
            ui.label(RichText::new("Montoya API: Java extensions run against Burp's own Montoya classes through the sidecar JVM (initialize, logging, request/response continue-or-drop). Rust extensions implement ProxyHooks in-process.").size(12.5).color(theme::ink_dim()));
        }
        3 => {
            ui.label(RichText::new("Custom scan checks").strong().size(14.0).color(theme::ink()));
            ui.label(RichText::new("WebProbe's scan checks are built in (Dashboard > New scan, context menu > Scan). BCheck files are not supported.").size(12.5).color(theme::ink_dim()));
        }
        4 => {
            ui.label(RichText::new("Bambda library").strong().size(14.0).color(theme::ink()));
            ui.label(RichText::new("Bambdas (Java filter snippets) are not supported; use the HTTP history filter settings and Logger search.").size(12.5).color(theme::ink_dim()));
        }
        _ => {
            ui.label(RichText::new("Extensions settings").strong().size(14.0).color(theme::ink()));
            ui.label(RichText::new(format!("Java runtime for extensions: sidecar JVM against {}", crate::ext_host::JavaSidecar::burp_jar())).size(12.5).color(theme::ink_dim()));
        }
    }
}

// ================= Appearance (M-05) =================

/// Appearance editor: palette, density and font scale. Changes apply live and
/// persist with the project file.
pub fn appearance_options(ui: &mut Ui) {
    ui.label(RichText::new("Appearance").size(12.5).color(theme::ink_faint()));
    let (palette, density, scale) = crate::theme::appearance();
    let mut changed = false;
    ui.horizontal(|ui| {
        for p in [crate::theme::Palette::Dark, crate::theme::Palette::Light, crate::theme::Palette::HighContrast] {
            if ui.selectable_label(palette == p, p.label()).clicked() {
                crate::theme::set_appearance(p, density, scale);
                changed = true;
            }
        }
    });
    ui.horizontal(|ui| {
        for d in [crate::theme::Density::Compact, crate::theme::Density::Comfortable] {
            if ui.selectable_label(density == d, d.label()).clicked() {
                crate::theme::set_appearance(palette, d, scale);
                changed = true;
            }
        }
    });
    let mut font_scale = scale;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Font size").size(12.0).color(theme::ink_faint()));
        if ui.add(egui::DragValue::new(&mut font_scale).speed(0.05).range(0.85..=1.4).suffix("×")).changed() {
            crate::theme::set_appearance(palette, density, font_scale);
            changed = true;
        }
    });
    let _ = changed;
}

// ================= Project persistence =================

/// Project options panel: the project file path, save/restore, and the JSON
/// export/import round-trip — all state mapping lives in `project::*`.
pub fn project_controls(app: &mut App, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Project file").size(12.0).color(theme::ink_faint()));
        ui.add(egui::TextEdit::singleline(&mut app.project_path).desired_width(330.0).font(egui::TextStyle::Monospace));
        if ui.button("Save project").clicked() {
            match project::save(std::path::Path::new(&app.project_path), &project::snapshot(app)) {
                Ok(()) => {
                    app.project_status = format!("saved {}", app.project_path);
                    crate::feedback::toast(crate::feedback::Level::Success, format!("Project saved to {}", app.project_path));
                }
                Err(e) => {
                    app.project_status = format!("save failed: {e}");
                    crate::feedback::toast(crate::feedback::Level::Error, format!("Save failed: {e}"));
                }
            }
        }
        if ui.button("Restore project").clicked() {
            restore_from_file(app);
        }
    });
    ui.horizontal(|ui| {
        if ui.button("Export JSON").clicked() {
            match project::export_json(&project::snapshot(app)) {
                Ok(text) => export_text(app, &text),
                Err(e) => project_action_failed(app, "export", e),
            }
        }
        if ui.button("Import JSON").clicked() {
            match std::fs::read_to_string(&app.project_path) {
                Ok(text) => match project::import_json(&text) {
                    Ok(data) => {
                        project::restore(&data, app);
                        keep_history_selection(app);
                        app.project_status = format!("imported {}", app.project_path);
                        crate::feedback::toast(crate::feedback::Level::Success, format!("Project imported from {}", app.project_path));
                    }
                    Err(e) => project_action_failed(app, "import", e),
                },
                Err(e) => project_action_failed(app, "import", e.to_string()),
            }
        }
    });
    if !app.project_status.is_empty() {
        hint(ui, &app.project_status);
    }
}

fn export_text(app: &mut App, text: &str) {
    match std::fs::write(&app.project_path, text) {
        Ok(()) => {
            app.project_status = format!("exported {}", app.project_path);
            crate::feedback::toast(crate::feedback::Level::Success, format!("Project exported to {}", app.project_path));
        }
        Err(e) => project_action_failed(app, "export", e.to_string()),
    }
}

fn project_action_failed(app: &mut App, action: &str, e: String) {
    app.project_status = format!("{action} failed: {e}");
    crate::feedback::toast(crate::feedback::Level::Error, format!("{} failed: {e}", capitalize(action)));
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn restore_from_file(app: &mut App) {
    match project::load(std::path::Path::new(&app.project_path)) {
        Ok(data) => {
            project::restore(&data, app);
            keep_history_selection(app);
            app.project_status = format!("restored {}", app.project_path);
            crate::feedback::toast(crate::feedback::Level::Success, format!("Project restored from {}", app.project_path));
        }
        Err(e) => project_action_failed(app, "restore", e),
    }
}

/// Clear the history selection when the selected entry is gone after a
/// restore (ids may shift between saves).
fn keep_history_selection(app: &mut App) {
    let kept = selected_history(app)
        .is_some_and(|e| app.shared.history.lock().unwrap().iter().any(|h| h.id == e.id));
    if !kept {
        app.history_sel = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_launch_configuration_is_grounded() {
        // Burp's own bundled Chromium leads the preference order when the Burp
        // installation is present (that is the real embedded browser); the
        // system names follow (Zrg5.java:38 / Zrgu.java:28 mention "chrome",
        // "chromium").
        let cands = browser_candidates();
        let burp: Vec<&String> = cands.iter().filter(|c| c.contains("burpbrowser")).collect();
        if !burp.is_empty() {
            // Newest bundled version first, and always ahead of the system ones.
            if let Some(sys) = cands.iter().position(|c| !c.contains("burpbrowser")) {
                assert!(cands.iter().position(|c| c.contains("burpbrowser")).unwrap() < sys);
            }
            let v: Vec<u64> = burp
                .iter()
                .map(|p| {
                    std::path::Path::new(p)
                        .parent()
                        .and_then(|d| d.file_name())
                        .and_then(|n| n.to_string_lossy().split('.').next().map(|s| s.to_string()))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0)
                })
                .collect();
            assert!(v.windows(2).all(|w| w[0] >= w[1]), "bundled versions must sort newest-first: {v:?}");
        }
        // Candidates are absolute paths, never a launcher that pins its own
        // profile (an xrdp wrapper would hand the launch to the desktop
        // browser and drop the proxy flags).
        assert!(cands.iter().all(|c| c.starts_with('/')), "{cands:?}");
        assert!(cands.iter().all(|c| !pins_profile(std::path::Path::new(c))), "{cands:?}");
        // The arguments preconfigure the proxy, use the per-port profile, and
        // start on the onboarding page served at http://webprobe.
        let args = browser_args(8080, false);
        assert_eq!(args[0], "--proxy-server=http://127.0.0.1:8080", "proxy preconfigured");
        assert!(args.iter().any(|a| a == &format!("--user-data-dir={}", browser_profile(8080).display())), "per-port profile");
        assert_ne!(browser_profile(8080), browser_profile(8081), "one instance per proxy port");
        assert!(!args.iter().any(|a| a == "--no-sandbox"));
        // Loopback targets must not bypass the proxy (Burp passes the same).
        assert!(args.iter().any(|a| a == "--proxy-bypass-list=<-loopback>"));
        assert!(args.iter().any(|a| a == "--disable-background-networking"));
        assert!(browser_args(8080, true).iter().any(|a| a == "--no-sandbox"), "root needs --no-sandbox");
        // Burp's own embedded-browser flags (burp.Zi9a.java:57).
        assert!(args.iter().any(|a| a == "--class=burp-browser"));
        assert!(args.iter().any(|a| a == "--ignore-certificate-errors"));
        assert!(args.last().is_some_and(|a| a == "http://webprobe/"), "onboarding start URL");
    }

    #[test]
    fn profile_pinning_wrappers_and_stale_locks() {
        let d = std::env::temp_dir().join(format!("wp-browser-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let wrapper = d.join("chromium");
        std::fs::write(&wrapper, "#!/bin/sh\nexec /usr/bin/chromium --user-data-dir=\"$HOME/x\" \"$@\"\n").unwrap();
        assert!(pins_profile(&wrapper));
        let launcher = d.join("chromium2");
        std::fs::write(&launcher, "#!/bin/sh\nexec /usr/lib/chromium/chromium \"$@\"\n").unwrap();
        assert!(!pins_profile(&launcher));
        // A lock held by a dead pid on this host is removed; a live one stays.
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim().to_string();
        let lock = d.join("SingletonLock");
        std::os::unix::fs::symlink(format!("{host}-999999999"), &lock).unwrap();
        clear_stale_lock(&d);
        assert!(std::fs::symlink_metadata(&lock).is_err(), "stale lock removed");
        std::os::unix::fs::symlink(format!("{host}-{}", std::process::id()), &lock).unwrap();
        clear_stale_lock(&d);
        assert!(std::fs::symlink_metadata(&lock).is_ok(), "live lock kept");
        let _ = std::fs::remove_dir_all(&d);
    }
}

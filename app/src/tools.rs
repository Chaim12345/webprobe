// Additional Burp-parity tools: scope, upstream routing, Sequencer,
// Comparer, session rules/macros, WebSocket history, cross-tool search,
// local Collaborator, project persistence, and the extension blocker.

use std::sync::atomic::Ordering;

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
        egui::Label::new(RichText::new(text).size(12.0).color(c(theme::MONO6)))
            .wrap_mode(egui::TextWrapMode::Wrap),
    );
}

fn selected_history(app: &App) -> Option<net::HistEntry> {
    let id = app.history_sel?;
    app.shared.history.lock().unwrap().iter().find(|e| e.id == id).cloned()
}

// ================= Target scope =================

pub fn scope_editor(app: &mut App, ui: &mut Ui) {
    ui.label(RichText::new("Scope").size(12.5).color(c(theme::MONO6)));
    let mut rules = app.shared.scope.lock().unwrap().clone();
    let mut remove = None;
    egui::Grid::new("scope_grid").striped(true).num_columns(5).show(ui, |ui| {
        for (i, rule) in rules.iter_mut().enumerate() {
            ui.checkbox(&mut rule.enabled, "");
            let mode = if rule.include { "include" } else { "exclude" };
            if ui.selectable_label(false, RichText::new(mode).size(12.0).color(c(theme::MONO6))).clicked() {
                rule.include = !rule.include;
            }
            ui.add(
                egui::TextEdit::singleline(&mut rule.pattern)
                    .desired_width(150.0)
                    .hint_text("host/path")
                    .font(egui::TextStyle::Monospace),
            );
            if ui.selectable_label(rule.is_regex, RichText::new("regex").size(12.0).color(if rule.is_regex { c(theme::ORANGE) } else { c(theme::MONO6) })).clicked() {
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
    ui.label(RichText::new("Upstream routing").color(c(theme::MONO7)).size(14.0).strong());
    let mut config = app.shared.upstream.lock().unwrap().clone();
    ui.horizontal(|ui| {
        let kinds = [
            ("direct", UpstreamKind::None),
            ("HTTP proxy", UpstreamKind::Http),
            ("SOCKS5", UpstreamKind::Socks5),
        ];
        for (name, kind) in kinds {
            let sel = config.kind == kind;
            if ui.selectable_label(sel, RichText::new(name).size(12.5).color(if sel { c(theme::ORANGE) } else { c(theme::MONO6) })).clicked() {
                config.kind = kind;
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("host").size(12.0).color(c(theme::MONO6)));
        ui.add(egui::TextEdit::singleline(&mut config.host).desired_width(180.0).font(egui::TextStyle::Monospace));
        ui.label(RichText::new("port").size(12.0).color(c(theme::MONO6)));
        ui.add(egui::TextEdit::singleline(&mut config.port).desired_width(70.0).font(egui::TextStyle::Monospace));
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("username").size(12.0).color(c(theme::MONO6)));
        ui.add(egui::TextEdit::singleline(&mut config.username).desired_width(130.0).font(egui::TextStyle::Monospace));
        ui.label(RichText::new("password").size(12.0).color(c(theme::MONO6)));
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
            regex::Regex::new(selector).ok()?.find(&body).map(|m| m.as_str().as_bytes().to_vec())
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

pub fn sequencer(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Sequencer").color(c(theme::MONO7)).size(15.0));
    ui.add_space(4.0);
    let entry = selected_history(app);
    if entry.is_none() {
        hint(ui, "Select a request in Proxy history or Target first.");
    }
    ui.horizontal(|ui| {
        for (i, name) in ["response header", "cookie", "body regex"].iter().enumerate() {
            let sel = app.seq_mode == i;
            if ui.selectable_label(sel, RichText::new(*name).size(12.5).color(if sel { c(theme::ORANGE) } else { c(theme::MONO6) })).clicked() {
                app.seq_mode = i;
            }
        }
        ui.checkbox(&mut app.seq_ignore_abnormal, "ignore abnormal lengths");
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new(if app.seq_mode == 0 { "header" } else if app.seq_mode == 1 { "cookie" } else { "regex" }).size(12.0).color(c(theme::MONO6)));
        ui.add(egui::TextEdit::singleline(&mut app.seq_selector).desired_width(260.0).font(egui::TextStyle::Monospace));
    });
    ui.horizontal(|ui| {
        if ui.button("Capture stored response").clicked() {
            if let Some(e) = selected_history(app) {
                if let Some(response) = &e.resp_raw {
                    match extract_token(response, app.seq_mode, &app.seq_selector) {
                        Some(token) => add_sequencer_sample(app, token),
                        None => app.seq_status = "token not found in stored response".into(),
                    }
                } else {
                    app.seq_status = "selected request has no response".into();
                }
            }
        }
        if ui.button("Capture live").clicked() {
            if let Some(e) = selected_history(app) {
                let parts = crate::util::parse_http(&e.req_raw);
                let host = crate::util::get_header(&parts.headers, "Host").unwrap_or_default();
                if host.is_empty() {
                    app.seq_status = "request has no Host header".into();
                } else {
                    let (h, p) = net::split_h_p(&host, e.port);
                    let up = net::send_raw(&app.shared, &h, p, &e.req_raw);
                    match up.resp.and_then(|r| extract_token(&r, app.seq_mode, &app.seq_selector)) {
                        Some(token) => add_sequencer_sample(app, token),
                        None => app.seq_status = format!("live capture failed: {}", up.error.unwrap_or_else(|| "token not found".into())),
                    }
                }
            }
        }
        if ui.button("Analyze").clicked() && !app.seq_samples.is_empty() {
            app.seq_stats = Some(analysis::analyze_tokens(&app.seq_samples));
            let tokens: Vec<String> = app.seq_samples.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect();
            app.seq_report = Some(analysis::analyze_sequence(&tokens));
            app.seq_status = format!("analyzed {} sample(s)", app.seq_samples.len());
        }
        if ui.button("Clear").clicked() {
            app.seq_samples.clear();
            app.seq_stats = None;
            app.seq_report = None;
            app.seq_status.clear();
        }
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("manual samples (one per line)").size(12.0).color(c(theme::MONO6)));
        if ui.button("Add lines").clicked() {
            for line in app.seq_manual.clone().lines().filter(|l| !l.is_empty()) {
                add_sequencer_sample(app, line.as_bytes().to_vec());
            }
            app.seq_manual.clear();
        }
    });
    egui::ScrollArea::vertical().max_height(90.0).show(ui, |ui| {
        crate::editor::message_editor(ui, "sequencer_manual", &mut app.seq_manual, 3, &mut app.seq_editor);
    });
    if !app.seq_status.is_empty() {
        hint(ui, &app.seq_status);
    }
    if let Some(stats) = &app.seq_stats {
        ui.add_space(6.0);
        egui::Grid::new("seq_stats").striped(true).num_columns(2).show(ui, |ui| {
            ui.label(RichText::new("samples").size(12.0).color(c(theme::MONO6)));
            ui.monospace(stats.sample_count.to_string());
            ui.end_row();
            ui.label(RichText::new("token length").size(12.0).color(c(theme::MONO6)));
            ui.monospace(stats.token_length.to_string());
            ui.end_row();
            ui.label(RichText::new("bits/character").size(12.0).color(c(theme::MONO6)));
            ui.monospace(format!("{:.4}", stats.bits_per_character));
            ui.end_row();
            ui.label(RichText::new("total entropy bits").size(12.0).color(c(theme::MONO6)));
            ui.monospace(format!("{:.2}", stats.total_entropy_bits));
            ui.end_row();
        });
        ui.add_space(4.0);
        ui.label(RichText::new("Character distribution").size(12.0).color(c(theme::MONO6)));
        egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
            egui::Grid::new("seq_dist").num_columns(4).show(ui, |ui| {
                for row in stats.char_distribution.chunks(4) {
                    for (ch, count) in row {
                        ui.monospace(RichText::new(format!("{:02x}: {}", *ch as u32, count)).size(12.0).color(c(theme::EDITOR_TEXT)));
                    }
                    ui.end_row();
                }
            });
        });
    }
    if let Some(report) = &app.seq_report {
        ui.add_space(8.0);
        ui.label(RichText::new("Statistical analysis").size(12.5).color(c(theme::MONO6)));
        crate::analysis_ui::show_sequencer_report(ui, report);
    }
}

// ================= Sessions and macros =================

pub fn sessions(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Session handling").color(c(theme::MONO7)).size(15.0));
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
                    if ui.selectable_label(rule.action == action, RichText::new(action).size(12.0).color(if rule.action == action { c(theme::ORANGE) } else { c(theme::MONO6) })).clicked() {
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
    ui.label(RichText::new("Macros").color(c(theme::MONO7)).size(14.0).strong());
    let macros = app.shared.macros.lock().unwrap().clone();
    egui::Grid::new("macros").striped(true).num_columns(3).show(ui, |ui| {
        for (i, m) in macros.iter().enumerate() {
            ui.label(RichText::new(m.name.clone()).size(12.0).color(c(theme::EDITOR_TEXT)));
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
    egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
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
    ui.label(RichText::new("WebSocket history").color(c(theme::MONO7)).size(14.0).strong());
    ui.add_space(4.0);
    hint(ui, "Plain-HTTP upgrades are relayed and every frame is captured. TLS handshakes are recorded; encrypted frame relay is not supported yet.");
    let entries = app.shared.ws_history.lock().unwrap().clone();
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("ws_grid").striped(true).num_columns(5).show(ui, |ui| {
            for e in entries.iter().rev() {
                ui.monospace(RichText::new(e.id.to_string()).size(12.0).color(c(theme::MONO6)));
                ui.monospace(RichText::new(e.host.clone()).size(12.0).color(c(theme::EDITOR_TEXT)));
                ui.monospace(RichText::new(e.direction.clone()).size(12.0).color(c(theme::MONO6)));
                ui.monospace(RichText::new(e.opcode.clone()).size(12.0).color(c(theme::ORANGE)));
                ui.monospace(RichText::new(e.payload.clone()).size(12.0).color(c(theme::EDITOR_TEXT)));
                ui.end_row();
            }
        });
        if entries.is_empty() {
            ui.label(RichText::new("no WebSocket traffic yet").size(12.0).color(c(theme::MONO6)));
        }
    });
}

// ================= Cross-tool search =================

pub fn search(app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Search").color(c(theme::MONO7)).size(15.0));
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
    egui::ScrollArea::vertical().show(ui, |ui| {
        for hit in &app.search_results {
            ui.horizontal(|ui| {
                ui.label(RichText::new(hit.tool.clone()).size(12.0).color(c(theme::ORANGE)));
                ui.label(RichText::new(hit.title.clone()).size(12.5).color(c(theme::EDITOR_TEXT)));
            });
            ui.monospace(RichText::new(hit.excerpt.clone()).size(12.0).color(c(theme::MONO6)));
            ui.add_space(4.0);
        }
        if app.search_results.is_empty() {
            ui.label(RichText::new("no results yet").size(12.0).color(c(theme::MONO6)));
        }
    });
}

// ================= Extensions =================

pub fn extensions(_app: &mut App, ui: &mut Ui) {
    ui.heading(RichText::new("Extensions").color(c(theme::MONO7)).size(15.0));
    ui.add_space(6.0);
    hint(ui, "Burp extensions are in-process Java plugins using the legacy extender callbacks or the Montoya Extension API. WebProbe is a Rust process, so it cannot execute those Java classes without embedding a JVM. This is a concrete runtime blocker, not a paid-service dependency.");
    ui.add_space(6.0);
    ui.label(RichText::new("No extension is silently loaded or pretended to run.").size(12.5).color(c(theme::EDITOR_TEXT)));
}

// ================= Appearance (M-05) =================

/// Appearance editor: palette, density and font scale. Changes apply live and
/// persist with the project file.
pub fn appearance_options(ui: &mut Ui) {
    ui.label(RichText::new("Appearance").size(12.5).color(c(theme::MONO6)));
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
        ui.label(RichText::new("Font size").size(12.0).color(c(theme::MONO6)));
        if ui.add(egui::DragValue::new(&mut font_scale).speed(0.05).range(0.85..=1.4).suffix("×")).changed() {
            crate::theme::set_appearance(palette, density, font_scale);
            changed = true;
        }
    });
    let _ = changed;
}

// ================= Project persistence =================

fn project_rule(kind: &str, rule: &crate::rules::MrRule) -> project::ProjectRule {
    project::ProjectRule {
        enabled: rule.enabled,
        kind: kind.into(),
        match_text: rule.match_.clone(),
        replacement: rule.replacement.clone(),
        comment: rule.comment.clone(),
        is_regex: rule.is_regex,
    }
}

fn net_rule(rule: &project::ProjectRule) -> crate::rules::MrRule {
    crate::rules::MrRule {
        enabled: rule.enabled,
        match_: rule.match_text.clone(),
        replacement: rule.replacement.clone(),
        comment: rule.comment.clone(),
        is_regex: rule.is_regex,
        scope: crate::rules::MrScope::default_for(rule.kind != "response"),
    }
}

pub fn project_controls(app: &mut App, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Project file").size(12.0).color(c(theme::MONO6)));
        ui.add(egui::TextEdit::singleline(&mut app.project_path).desired_width(330.0).font(egui::TextStyle::Monospace));
        if ui.button("Save project").clicked() {
            let history = app.shared.history.lock().unwrap().iter().map(|e| project::ProjectHistory {
                id: e.id,
                timestamp: e.ts,
                method: e.method.clone(),
                host: e.host.clone(),
                port: e.port,
                https: e.https,
                path: e.path.clone(),
                status: e.status.clone(),
                request: String::from_utf8_lossy(&e.req_raw).into_owned(),
                response: e.resp_raw.as_ref().map(|r| String::from_utf8_lossy(r).into_owned()),
                note: e.note.clone(),
            }).collect();
            let data = project::ProjectData {
                version: project::PROJECT_VERSION,
                saved_at: crate::util::now_secs(),
                history,
                match_request: app.shared.mr_request.lock().unwrap().iter().map(|r| project_rule("request", r)).collect(),
                match_response: app.shared.mr_response.lock().unwrap().iter().map(|r| project_rule("response", r)).collect(),
                scope: app.shared.scope.lock().unwrap().iter().map(|s| project::ProjectScope {
                    enabled: s.enabled,
                    include: s.include,
                    pattern: s.pattern.clone(),
                    is_regex: s.is_regex,
                }).collect(),
                session_rules: app.shared.session_rules.lock().unwrap().iter().map(|s| project::ProjectSessionRule {
                    enabled: s.enabled,
                    name: s.name.clone(),
                    action: s.action.clone(),
                    match_text: s.host_match.clone(),
                    value: s.value.clone(),
                }).collect(),
                macros: app.shared.macros.lock().unwrap().iter().map(|m| project::ProjectMacro {
                    name: m.name.clone(),
                    request: m.request.clone(),
                }).collect(),
                repeaters: app.shared.repeaters.lock().unwrap().iter().map(|r| project::ProjectRepeater {
                    name: r.name.clone(),
                    host: r.host.clone(),
                    port: r.port,
                    https: r.https,
                    request: r.request.clone(),
                    response: r.response.as_ref().map(|v| String::from_utf8_lossy(v).into_owned()),
                    result_line: r.result_line.clone(),
                }).collect(),
                issues: app.shared.issues.lock().unwrap().iter().map(|i| project::ProjectIssue {
                    id: i.id,
                    severity: i.sev.clone(),
                    name: i.name.clone(),
                    host: i.host.clone(),
                    path: i.path.clone(),
                    detail: i.detail.clone(),
                }).collect(),
                websockets: app.shared.ws_history.lock().unwrap().iter().map(|w| project::ProjectWebsocket {
                    id: w.id,
                    timestamp: w.ts,
                    host: w.host.clone(),
                    direction: w.direction.clone(),
                    opcode: w.opcode.clone(),
                    payload: w.payload.clone(),
                }).collect(),
                upstream: app.shared.upstream.lock().unwrap().clone(),
                listener_port: app.shared.proxy_port.load(Ordering::SeqCst),
                appearance: {
                    let (palette, density, font_scale) = crate::theme::appearance();
                    project::Appearance {
                        palette: palette.label().into(),
                        density: density.label().into(),
                        font_scale,
                    }
                },
            };
            match project::save(std::path::Path::new(&app.project_path), &data) {
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
            match project::load(std::path::Path::new(&app.project_path)) {
                Ok(data) => {
                    *app.shared.history.lock().unwrap() = data.history.iter().map(|h| net::HistEntry {
                        id: h.id,
                        ts: h.timestamp,
                        method: h.method.clone(),
                        host: h.host.clone(),
                        port: h.port,
                        https: h.https,
                        path: h.path.clone(),
                        status: h.status.clone(),
                        resp_len: h.response.as_deref().map(|r| r.len()).unwrap_or(0),
                        req_raw: h.request.clone().into_bytes(),
                        resp_raw: h.response.clone().map(|r| r.into_bytes()),
                        note: h.note.clone(),
                    }).collect();
                    *app.shared.mr_request.lock().unwrap() = data.match_request.iter().filter(|r| r.kind == "request").map(net_rule).collect();
                    *app.shared.mr_response.lock().unwrap() = data.match_response.iter().filter(|r| r.kind == "response").map(net_rule).collect();
                    *app.shared.scope.lock().unwrap() = data.scope.iter().map(|s| net::ScopeRule {
                        enabled: s.enabled,
                        include: s.include,
                        pattern: s.pattern.clone(),
                        is_regex: s.is_regex,
                    }).collect();
                    *app.shared.session_rules.lock().unwrap() = data.session_rules.iter().map(|s| net::SessionRule {
                        enabled: s.enabled,
                        name: s.name.clone(),
                        action: s.action.clone(),
                        host_match: s.match_text.clone(),
                        value: s.value.clone(),
                    }).collect();
                    *app.shared.macros.lock().unwrap() = data.macros.iter().map(|m| net::Macro {
                        name: m.name.clone(),
                        request: m.request.clone(),
                    }).collect();
                    *app.shared.repeaters.lock().unwrap() = data.repeaters.iter().map(|r| net::RepTab {
                        name: r.name.clone(),
                        host: r.host.clone(),
                        port: r.port,
                        https: r.https,
                        request: r.request.clone(),
                        response: r.response.as_ref().map(|v| v.as_bytes().to_vec()),
                        result_line: r.result_line.clone(),
                    }).collect();
                    *app.shared.issues.lock().unwrap() = data.issues.iter().map(|i| crate::scan::ScanIssue {
                        id: i.id,
                        sev: i.severity.clone(),
                        name: i.name.clone(),
                        host: i.host.clone(),
                        path: i.path.clone(),
                        detail: i.detail.clone(),
                    }).collect();
                    *app.shared.ws_history.lock().unwrap() = data.websockets.iter().map(|w| net::WsEntry {
                        id: w.id,
                        ts: w.timestamp,
                        host: w.host.clone(),
                        direction: w.direction.clone(),
                        opcode: w.opcode.clone(),
                        payload: w.payload.clone(),
                    }).collect();
                    *app.shared.upstream.lock().unwrap() = data.upstream.clone();
                    app.shared.proxy_port.store(data.listener_port, Ordering::SeqCst);
                    app.shared.listener_restart.store(true, Ordering::SeqCst);
                    // M-05: apply the persisted appearance.
                    crate::theme::set_appearance(
                        crate::theme::Palette::parse(&data.appearance.palette),
                        crate::theme::Density::parse(&data.appearance.density),
                        data.appearance.font_scale,
                    );
                    app.map_cache_len = usize::MAX;
                    app.project_status = format!("restored {}", app.project_path);
                    crate::feedback::toast(crate::feedback::Level::Success, format!("Project restored from {}", app.project_path));
                }
                Err(e) => app.project_status = format!("restore failed: {e}"),
            }
        }
    });
    if !app.project_status.is_empty() {
        hint(ui, &app.project_status);
    }
}

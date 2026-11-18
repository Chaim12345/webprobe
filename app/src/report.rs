//! The "Report issues" options window. The report generators are engine
//! code (`webprobe_core::report`).

use eframe::egui;

pub use webprobe_core::report::*;

use std::path::Path;

use crate::scan::ScanIssue;

/// State of the report dialog.
#[derive(Clone, Debug)]
pub struct ReportDialog {
    pub open: bool,
    pub options: ReportOptions,
    /// Issue ids chosen in the issues view (empty = report nothing).
    pub issue_ids: Vec<u64>,
    pub path: String,
    pub limit_req: String,
    pub limit_resp: String,
    pub status: String,
}

impl Default for ReportDialog {
    fn default() -> Self {
        Self {
            open: false,
            options: ReportOptions::default(),
            issue_ids: Vec::new(),
            path: String::new(),
            limit_req: String::new(),
            limit_resp: String::new(),
            status: String::new(),
        }
    }
}

impl ReportDialog {
    /// Open the dialog for these issue ids.
    pub fn open_for(&mut self, ids: Vec<u64>) {
        self.issue_ids = ids;
        self.open = true;
        self.status.clear();
        if self.path.is_empty() {
            self.path = default_report_path(self.options.format);
        }
    }
}

/// `<cwd>/webprobe-report.html|xml`.
pub fn default_report_path(fmt: ReportFormat) -> String {
    let ext = if fmt == ReportFormat::Html { "html" } else { "xml" };
    std::env::current_dir()
        .map(|d| d.join(format!("webprobe-report.{ext}")).display().to_string())
        .unwrap_or_else(|_| format!("webprobe-report.{ext}"))
}

fn swap_extension(path: &str, fmt: ReportFormat) -> String {
    let ext = if fmt == ReportFormat::Html { "html" } else { "xml" };
    let p = Path::new(path);
    match p.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") | Some("xml") => p.with_extension(ext).display().to_string(),
        _ => path.to_string(),
    }
}

fn mode_radio(ui: &mut egui::Ui, mode: &mut MessageMode, limit: &mut String, noun: &str, xml: bool) {
    ui.radio_value(mode, MessageMode::Omit, format!("Do not include {noun}"));
    ui.add_enabled_ui(!xml, |ui| {
        ui.radio_value(mode, MessageMode::Extract, "Include relevant extract");
    });
    ui.radio_value(mode, MessageMode::Full, format!("Include full {noun}"));
    ui.horizontal(|ui| {
        ui.label("Limit to");
        ui.add(egui::TextEdit::singleline(limit).desired_width(70.0));
        ui.label("bytes");
    });
}

fn parse_limit(s: &str) -> Option<usize> {
    s.trim().parse::<usize>().ok().filter(|n| *n >= 1)
}

/// The report dialog window. Collects the chosen issues, their history
/// evidence and the knowledge base, renders and writes the file.
pub fn report_window(app: &mut crate::App, ctx: &egui::Context) {
    if !app.eng.report.open {
        return;
    }
    let mut open = true;
    let mut generate = false;
    let n = app.eng.report.issue_ids.len();
    egui::Window::new("Report issues")
        .open(&mut open)
        .resizable(true)
        .default_width(560.0)
        .default_pos(ctx.content_rect().center() - egui::vec2(280.0, 300.0))
        .show(ctx, |ui| {
            let d = &mut app.eng.report;
            let o = &mut d.options;
            egui::ScrollArea::vertical().max_height(560.0).show(ui, |ui| {
                ui.label(format!("{n} issue(s) selected for the report."));
                ui.separator();
                ui.strong("Choose the format:");
                let before = o.format;
                ui.radio_value(&mut o.format, ReportFormat::Html, "Generate report (HTML)");
                ui.radio_value(&mut o.format, ReportFormat::Xml, "Export issue data (XML)");
                ui.add_enabled(o.format == ReportFormat::Xml, egui::Checkbox::new(&mut o.base64, "Base64-encode requests and responses"));
                if o.format != before {
                    d.path = swap_extension(&d.path, o.format);
                }
                let xml = o.format == ReportFormat::Xml;
                if xml {
                    // Zrac.ZX: XML has no "relevant extract".
                    if o.requests == MessageMode::Extract {
                        o.requests = MessageMode::Full;
                    }
                    if o.responses == MessageMode::Extract {
                        o.responses = MessageMode::Full;
                    }
                }
                ui.separator();
                ui.add_enabled_ui(!xml, |ui| {
                    egui::Grid::new("report_layout").num_columns(2).show(ui, |ui| {
                        ui.label("Report title");
                        ui.text_edit_singleline(&mut o.title);
                        ui.end_row();
                        ui.label("Issue organization");
                        egui::ComboBox::from_id_salt("report_org").selected_text(o.organization.label()).show_ui(ui, |ui| {
                            for org in Organization::ALL {
                                ui.selectable_value(&mut o.organization, org, org.label());
                            }
                        });
                        ui.end_row();
                        ui.label("Table of contents levels");
                        egui::ComboBox::from_id_salt("report_toc").selected_text(o.toc_levels.to_string()).show_ui(ui, |ui| {
                            for l in 1..=3u8 {
                                ui.selectable_value(&mut o.toc_levels, l, l.to_string());
                            }
                        });
                        ui.end_row();
                    });
                    ui.checkbox(&mut o.summary_table, "Summary table");
                    ui.checkbox(&mut o.bar_chart, "Summary bar chart");
                });
                ui.separator();
                ui.strong("Select the severities and confidences to include in the report.");
                ui.horizontal(|ui| {
                    for (s, l) in SEVERITIES.iter().enumerate() {
                        ui.checkbox(&mut o.severities[s], *l);
                    }
                });
                ui.horizontal(|ui| {
                    for (c, l) in CONFIDENCES.iter().enumerate() {
                        ui.checkbox(&mut o.confidences[c], *l);
                    }
                });
                ui.checkbox(&mut o.include_false_positives, "Include false positives");
                ui.separator();
                ui.strong("Select the types of details to include in the report.");
                ui.checkbox(&mut o.issue_background, "Issue background");
                ui.checkbox(&mut o.remediation_background, "Remediation background");
                ui.checkbox(&mut o.issue_detail, "Issue detail [where applicable]");
                ui.checkbox(&mut o.remediation_detail, "Remediation detail [where applicable]");
                ui.checkbox(&mut o.references, "References");
                ui.checkbox(&mut o.classifications, "Vulnerability classifications [where applicable]");
                ui.separator();
                ui.columns(2, |cols| {
                    cols[0].strong("Requests");
                    mode_radio(&mut cols[0], &mut o.requests, &mut d.limit_req, "requests", xml);
                    cols[1].strong("Responses");
                    mode_radio(&mut cols[1], &mut o.responses, &mut d.limit_resp, "responses", xml);
                });
                o.request_limit = parse_limit(&d.limit_req);
                o.response_limit = parse_limit(&d.limit_resp);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Save to");
                    ui.add(egui::TextEdit::singleline(&mut d.path).desired_width(360.0).font(egui::TextStyle::Monospace));
                });
                if ui.button("Save report").clicked() {
                    generate = true;
                }
                if !d.status.is_empty() {
                    ui.label(egui::RichText::new(&d.status).size(12.0).color(crate::theme::ink_dim()));
                }
            });
        });
    if generate {
        let ids = app.eng.report.issue_ids.clone();
        let all = app.shared.issues.lock().unwrap().clone();
        let chosen: Vec<ScanIssue> = ids.iter().filter_map(|id| all.iter().find(|i| i.id == *id).cloned()).collect();
        let selected = select_issues(&chosen, &app.eng.report.options);
        let history = app.shared.history.snapshot();
        if app.eng.kb.is_none() {
            app.eng.kb = Some(match KnowledgeBase::discover_checked() {
                Ok(kb) => kb,
                Err(missing) => {
                    crate::feedback::toast(crate::feedback::Level::Warn, missing.to_string());
                    KnowledgeBase::default()
                }
            });
        }
        let kb = app.eng.kb.as_ref().unwrap();
        let ris = build_report_issues(&selected, &history, kb);
        let text = render(&ris, &app.eng.report.options, crate::util::now_secs());
        let path = app.eng.report.path.clone();
        match std::fs::write(&path, text.as_bytes()) {
            Ok(()) => {
                let kb_note = if kb.entries.is_empty() { " (no knowledge base found: backgrounds omitted)" } else { "" };
                app.eng.report.status = format!("Wrote {} issue(s), {} bytes, to {path}{kb_note}", ris.len(), text.len());
                crate::feedback::toast(crate::feedback::Level::Success, format!("Report saved to {path}"));
            }
            Err(e) => {
                app.eng.report.status = format!("Could not write {path}: {e}");
                crate::feedback::toast(crate::feedback::Level::Error, app.eng.report.status.clone());
            }
        }
    }
    if !open {
        app.eng.report.open = false;
    }
}


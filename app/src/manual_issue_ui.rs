//! Issues the user raises by hand: the "Record an issue" submenu of
//! WebProbe's message editors, the "Create an issue" dialog and the "Add to
//! an issue" picker.
//!
//! Ported from the reference build:
//! - burp.Zgmp.getContextMenuItems puts a "Record an issue" submenu after
//!   "Open response in browser" and before "Request in browser", with
//!   "Create an issue" (burp.Zipf.MANUALLY_CREATE_ISSUE, 133392) and "Add to
//!   manually created issue" (ADD_TO_MANUALLY_CREATED_ISSUE, 133397). It is
//!   offered when the editor's message has a request and a response.
//! - burp.Zudh.Zu handles both: the dialog gets the message's service and the
//!   request-line target (burp.Zudh.Zc); nothing opens when the request line
//!   has no target.
//! - burp.Zgwg (dialog) and burp.Zr7j (its fields, defaults and validation),
//!   burp.Zsl_ (the "Invalid: ..." line and the button state), burp.Zp_6
//!   (the issue it records).
//! - burp.Zgwd / burp.Zr7e (the picker), burp.Zxwl (its columns), burp.Zm81
//!   (the manual issues it lists) and burp.Zchl (what "Add to issue" does).
//!
//! The engine side (issue construction, validation, appending evidence) is
//! in webprobe-core's scan::issue_types.

use eframe::egui::{self, RichText, Ui};

use crate::scan::{self, ManualIssueForm};
use crate::theme;

/// The message a dialog was opened on.
#[derive(Clone, Debug, Default)]
struct Message {
    request: Vec<u8>,
    response: Option<Vec<u8>>,
}

/// "Create an issue" (burp.Zgwg).
#[derive(Clone, Debug, Default)]
struct CreateDialog {
    form: ManualIssueForm,
    message: Message,
    /// Burp validates on the first edit of the name, service or path
    /// (burp.Zr7j adds its document listener to those three, after setting
    /// the defaults): until then the button is disabled and no error shows.
    edited: bool,
    /// Focus the Name field on the first frame (burp.Zr7j lambda$new$0).
    focus_name: bool,
}

/// "Add to an issue" (burp.Zgwd).
#[derive(Clone, Debug, Default)]
struct AddDialog {
    message: Message,
    /// The selected manual issue (burp.Zr7e.Zr takes the first selected row).
    selected: Option<u64>,
    /// Burp enables "Add to issue" on the first selection and never disables
    /// it again (burp.Zr7e lambda$new$1).
    enabled: bool,
}

/// Both dialogs; one field of [`crate::engagement::State`].
#[derive(Clone, Debug, Default)]
pub struct State {
    create: Option<CreateDialog>,
    add: Option<AddDialog>,
}

/// The item picked in the "Record an issue" submenu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    Create,
    AddTo,
}

/// Burp's "Record an issue" submenu (burp.Zgmp, Pro labels). Drawn only for
/// a message with a request and a response.
pub fn record_menu(ui: &mut Ui, has_request: bool, has_response: bool) -> Option<Pick> {
    if !(has_request && has_response) {
        return None;
    }
    let mut out = None;
    ui.menu_button(RichText::new("Record an issue").size(13.0), |ui| {
        ui.set_min_width(220.0);
        for (label, pick) in [
            ("Create an issue", Pick::Create),
            ("Add to manually created issue", Pick::AddTo),
        ] {
            if ui
                .add(
                    egui::Button::new(RichText::new(label).size(13.0))
                        .wrap_mode(egui::TextWrapMode::Extend),
                )
                .clicked()
            {
                out = Some(pick);
                ui.close();
            }
        }
    });
    out
}

impl State {
    /// Open the dialog `pick` for a message (burp.Zudh.Zu, cases 133392 and
    /// 133397). Returns false, and opens nothing, when the request line has
    /// no target (Burp's Zudh.Zc returns null and the action does nothing).
    pub fn open(
        &mut self,
        pick: Pick,
        host: &str,
        port: u16,
        https: bool,
        request: &[u8],
        response: Option<&[u8]>,
    ) -> bool {
        if scan::request_target(request).is_none() || host.is_empty() {
            return false;
        }
        let message = Message {
            request: request.to_vec(),
            response: response.map(<[u8]>::to_vec),
        };
        match pick {
            Pick::Create => {
                self.create = Some(CreateDialog {
                    form: ManualIssueForm::for_message(host, port, https, request),
                    message,
                    edited: false,
                    focus_name: true,
                })
            }
            Pick::AddTo => {
                self.add = Some(AddDialog {
                    message,
                    ..Default::default()
                })
            }
        }
        true
    }
}

/// Open `pick` on a history-style message, with a toast when Burp would do
/// nothing.
pub fn open_for_entry(app: &mut crate::App, pick: Pick, e: &crate::net::HistEntry, request: &[u8]) {
    let response = e.resp_raw.as_ref().map(|b| b.to_vec());
    if !app
        .eng
        .manual_issue
        .open(pick, &e.host, e.port, e.https, request, response.as_deref())
    {
        crate::feedback::toast(
            crate::feedback::Level::Warn,
            "The request has no request line target",
        );
    }
}

/// Draw whichever dialog is open. Called every frame from
/// `engagement::windows`.
pub fn windows(app: &mut crate::App, ctx: &egui::Context) {
    create_window(app, ctx);
    add_window(app, ctx);
}

fn label(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(13.0).color(theme::ink()));
}

/// burp.Zgwg + burp.Zr7j: Name, HTTP service, Path, Issue severity | Issue
/// confidence, Issue detail (optional), Remediation (optional); the error
/// line left of Cancel / Create issue.
fn create_window(app: &mut crate::App, ctx: &egui::Context) {
    let Some(d) = app.eng.manual_issue.create.as_mut() else {
        return;
    };
    let mut open = true;
    let mut close = false;
    let mut create = false;
    egui::Window::new("Create an issue")
        .id(egui::Id::unique("manual_issue_create"))
        .default_pos(theme::window_pos(ctx))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .min_width(400.0)
        .min_height(400.0)
        .default_width(520.0)
        .show(ctx, |ui| {
            let f = &mut d.form;
            let mut changed = false;
            let full = ui.available_width();
            label(ui, "Name");
            let name = ui.add(
                egui::TextEdit::singleline(&mut f.name)
                    .id_salt("manualIssueCreationName")
                    .desired_width(full),
            );
            if d.focus_name {
                name.request_focus();
                d.focus_name = false;
            }
            changed |= name.changed();
            ui.add_space(10.0);
            label(ui, "HTTP service");
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut f.service)
                        .id_salt("manualIssueCreationService")
                        .desired_width(full),
                )
                .changed();
            ui.add_space(10.0);
            label(ui, "Path");
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut f.path)
                        .id_salt("manualIssueCreationPath")
                        .desired_width(full),
                )
                .changed();
            ui.add_space(10.0);
            let half = (full - 15.0) / 2.0;
            ui.horizontal(|ui| {
                ui.allocate_ui(egui::vec2(half, 20.0), |ui| {
                    ui.set_width(half);
                    label(ui, "Issue severity");
                });
                ui.add_space(15.0);
                label(ui, "Issue confidence");
            });
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("manualIssueCreationSeverity")
                    .width(half - 8.0)
                    .selected_text(f.severity.clone())
                    .show_ui(ui, |ui| {
                        for s in scan::MANUAL_SEVERITIES {
                            ui.selectable_value(&mut f.severity, s.to_string(), s);
                        }
                    });
                ui.add_space(15.0);
                egui::ComboBox::from_id_salt("manualIssueCreationConfidence")
                    .width(half - 8.0)
                    .selected_text(f.confidence.clone())
                    .show_ui(ui, |ui| {
                        for c in scan::MANUAL_CONFIDENCES {
                            ui.selectable_value(&mut f.confidence, c.to_string(), c);
                        }
                    });
            });
            ui.add_space(10.0);
            // Burp validates on edits of these three only (burp.Zr7j listens
            // to the name, service and path documents).
            d.edited |= changed;
            label(ui, "Issue detail (optional)");
            ui.add(
                egui::TextEdit::multiline(&mut f.detail)
                    .id_salt("manualIssueCreationDetail")
                    .desired_rows(5)
                    .desired_width(full),
            );
            ui.add_space(10.0);
            label(ui, "Remediation (optional)");
            ui.add(
                egui::TextEdit::multiline(&mut f.remediation)
                    .id_salt("manualIssueCreationRemediation")
                    .desired_rows(5)
                    .desired_width(full),
            );
            ui.add_space(8.0);
            ui.separator();
            let error = if d.edited { f.error_text() } else { None };
            let can_create = d.edited && error.is_none();
            ui.horizontal(|ui| {
                if let Some(e) = &error {
                    ui.label(RichText::new(e).size(12.5).color(theme::ink_dim()));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(can_create, egui::Button::new("Create issue"))
                        .clicked()
                    {
                        create = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        });
    if create {
        let d = app.eng.manual_issue.create.take();
        if let Some(d) = d
            && let Some(issue) =
                scan::mk_manual_issue(&d.form, &d.message.request, d.message.response.as_deref())
        {
            scan::add_issues(&app.shared, vec![issue]);
            crate::feedback::toast(
                crate::feedback::Level::Success,
                format!("Issue created: {}", d.form.name),
            );
        }
    } else if close || !open {
        app.eng.manual_issue.create = None;
    }
}

/// The severity text Burp shows for an issue (burp.Ze1r.ZX).
fn severity_text(i: &scan::ScanIssue) -> &'static str {
    if i.false_positive {
        return "False positive";
    }
    match i.sev.to_ascii_lowercase().as_str() {
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Information",
    }
}

/// burp.Zgwd + burp.Zr7e: "Manual issues" / "All issues raised manually.",
/// the table of manual issues (burp.Zxwl: Name, Host, Path, Severity,
/// Confidence) and Cancel / Add to issue.
fn add_window(app: &mut crate::App, ctx: &egui::Context) {
    let Some(d) = app.eng.manual_issue.add.as_mut() else {
        return;
    };
    let issues: Vec<scan::ScanIssue> = app
        .shared
        .issues
        .lock()
        .iter()
        .filter(|i| scan::is_manual_issue(i))
        .cloned()
        .collect();
    let mut open = true;
    let mut close = false;
    let mut add = false;
    egui::Window::new("Add to an issue")
        .id(egui::Id::unique("manual_issue_add"))
        .default_pos(theme::window_pos(ctx))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .min_width(400.0)
        .min_height(400.0)
        .default_width(640.0)
        .show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Manual issues")
                        .strong()
                        .size(15.0)
                        .color(theme::ink()),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new("All issues raised manually.")
                        .size(12.5)
                        .color(theme::ink_dim()),
                );
            });
            ui.add_space(8.0);
            let widths = [0.30, 0.18, 0.26, 0.13, 0.13];
            // Room for the scroll bar and the gaps between cells, so the
            // rows never widen the window.
            let full = ui.available_width() - 40.0;
            let row = |ui: &mut Ui, cells: [&str; 5], strong: bool| {
                ui.horizontal(|ui| {
                    for (c, w) in cells.iter().zip(widths) {
                        let t = RichText::new(*c).size(12.5);
                        let t = if strong {
                            t.strong()
                        } else {
                            t.color(theme::ink_dim())
                        };
                        ui.allocate_ui_with_layout(
                            egui::vec2(full * w, 20.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_width(full * w);
                                ui.add(egui::Label::new(t).truncate().selectable(false));
                            },
                        );
                    }
                })
                .response
            };
            row(ui, ["Name", "Host", "Path", "Severity", "Confidence"], true);
            ui.separator();
            let table_h = (ui.available_height() - 44.0).max(160.0);
            egui::ScrollArea::vertical()
                .id_salt("manualIssueAddIssueTable")
                .max_height(table_h)
                .min_scrolled_height(table_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for i in &issues {
                        let top = ui.cursor().min;
                        if d.selected == Some(i.id) {
                            ui.painter().rect_filled(
                                egui::Rect::from_min_size(top, egui::vec2(full, 22.0)),
                                0.0,
                                theme::selection_bg(),
                            );
                        }
                        let r = row(
                            ui,
                            [&i.name, &i.host, &i.path, severity_text(i), &i.confidence],
                            false,
                        )
                        .interact(egui::Sense::click());
                        if r.clicked() {
                            d.selected = Some(i.id);
                            d.enabled = true;
                        }
                    }
                    if issues.is_empty() {
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("No issue has been raised manually yet.")
                                .size(12.5)
                                .color(theme::ink_faint()),
                        );
                    }
                });
            ui.separator();
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(d.enabled, egui::Button::new("Add to issue"))
                        .clicked()
                    {
                        add = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        });
    if add {
        if let Some(d) = app.eng.manual_issue.add.take()
            && let Some(id) = d.selected
        {
            let added = app
                .shared
                .issues
                .lock()
                .iter_mut()
                .find(|i| i.id == id)
                .is_some_and(|i| {
                    scan::add_manual_evidence(i, &d.message.request, d.message.response.as_deref())
                });
            if added {
                crate::feedback::toast(crate::feedback::Level::Success, "Added to the issue");
            }
        }
    } else if close || !open {
        app.eng.manual_issue.add = None;
    }
}

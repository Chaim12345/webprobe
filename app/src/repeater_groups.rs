//! Repeater tab groups in the desktop app (R-12): the tab context menu's
//! group items, the create/edit group dialog, the group colour chips in
//! the tab strip, and the background "Send group" worker with Burp's
//! three modes (groups.html, send-group.html). The model — membership,
//! colours, ordering, validation, the senders — is core's `send_group`;
//! this module only wires it to widgets and to the shared tab list.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui::{self, RichText, Ui};

use webprobe_core::net;
use webprobe_core::send_group::{self, GroupItem, GroupMode, RepGroup};

use crate::feedback;
use crate::theme::{self, c};

/// The 15 group colours (burp.Zxpb GROUP_0..GROUP_14), as RGB.
pub const GROUP_RGB: [(u8, u8, u8); 15] = [
    (229, 57, 53),   // red
    (251, 140, 0),   // orange
    (253, 216, 53),  // yellow
    (175, 180, 43),  // lime
    (67, 160, 71),   // green
    (0, 137, 123),   // teal
    (0, 172, 193),   // cyan
    (30, 136, 229),  // blue
    (57, 73, 171),   // indigo
    (94, 53, 177),   // deep purple
    (142, 36, 170),  // purple
    (216, 27, 96),   // pink
    (109, 76, 65),   // brown
    (117, 117, 117), // gray
    (84, 110, 122),  // blue gray
];

fn colour(i: u8) -> egui::Color32 {
    let (r, g, b) = GROUP_RGB[(i as usize) % GROUP_RGB.len()];
    egui::Color32::from_rgb(r, g, b)
}

/// The create/edit group dialog's state (`App::rep_group_dialog`).
pub struct GroupDialog {
    /// None: creating a group around `tab`; Some(id): editing group id.
    pub group: Option<u64>,
    pub tab: u64,
    pub name: String,
    pub colour: u8,
}

/// A running group send: the cancel flag the worker checks and the
/// running flag it lowers at the end (the UI clears the slot then).
pub struct GroupSend {
    pub cancel: Arc<AtomicBool>,
    pub running: Arc<AtomicBool>,
    pub name: String,
}

/// The tab bar as tab ids, in order.
fn bar_order(app: &crate::App) -> Vec<u64> {
    app.shared
        .repeaters
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect()
}

/// Reorder the shared tab list to `order` (the model's `gather` works on
/// an id list; this applies it to the tabs themselves).
fn apply_order(app: &crate::App, order: &[u64]) {
    let mut reps = app.shared.repeaters.lock().unwrap();
    let mut sorted = Vec::with_capacity(reps.len());
    for id in order {
        if let Some(pos) = reps.iter().position(|r| r.id == *id) {
            sorted.push(reps.remove(pos));
        }
    }
    sorted.append(&mut reps);
    *reps = sorted;
}

/// Drop groups whose tabs are gone (after tab closes); member lists
/// follow the tab bar. Call after any close/reorder.
pub fn prune(app: &mut crate::App) {
    let order = bar_order(app);
    send_group::prune(&mut app.rep_groups, &order);
}

/// The group chip in the tab strip: a small square of the group's colour
/// before the tab's label, tooltip naming the group.
pub fn chip(ui: &mut Ui, groups: &[RepGroup], tab: u64) {
    let Some(g) = send_group::group_of(groups, tab) else {
        return;
    };
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 2.0, colour(g.colour));
    resp.on_hover_text(format!("Group: {}", g.name));
}

/// The group items of a tab's context menu (Burp's "Add tab to group",
/// "Remove tab from group", the group submenu with edit/ungroup/delete
/// and the three "Send group" modes). Returns true when it changed the
/// tab bar (the caller refreshes its selection).
pub fn menu_section(ui: &mut Ui, app: &mut crate::App, idx: usize) {
    let Some(tab) = app.shared.repeaters.lock().unwrap().get(idx).map(|r| r.id) else {
        return;
    };
    let item = |ui: &mut Ui, label: &str, enabled: bool| -> bool {
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(label).size(13.0))
                .wrap_mode(egui::TextWrapMode::Extend),
        )
        .clicked()
    };
    ui.separator();
    match send_group::group_of(&app.rep_groups, tab).map(|g| (g.id, g.name.clone())) {
        None => {
            if item(ui, "Add tab to new group...", true) {
                ui.close();
                let colour = send_group::next_colour(&app.rep_groups);
                app.rep_group_dialog = Some(GroupDialog {
                    group: None,
                    tab,
                    name: String::new(),
                    colour,
                });
            }
            if !app.rep_groups.is_empty() {
                ui.menu_button(RichText::new("Add tab to group").size(13.0), |ui| {
                    for g in app.rep_groups.clone() {
                        if item(ui, &g.name, true) {
                            ui.close();
                            let mut order = bar_order(app);
                            send_group::add_to_group(&mut app.rep_groups, &mut order, g.id, tab);
                            apply_order(app, &order);
                        }
                    }
                });
            }
        }
        Some((gid, gname)) => {
            if item(ui, "Remove tab from group", true) {
                ui.close();
                send_group::remove_from_group(&mut app.rep_groups, tab);
            }
            if item(ui, &format!("Edit group \"{gname}\"..."), true) {
                ui.close();
                let (name, col) = app
                    .rep_groups
                    .iter()
                    .find(|g| g.id == gid)
                    .map(|g| (g.name.clone(), g.colour))
                    .unwrap_or_default();
                app.rep_group_dialog = Some(GroupDialog {
                    group: Some(gid),
                    tab,
                    name,
                    colour: col,
                });
            }
            if item(ui, "Ungroup tabs", true) {
                ui.close();
                send_group::ungroup(&mut app.rep_groups, gid);
            }
            if item(ui, "Close all tabs in group", true) {
                ui.close();
                close_group_tabs(app, gid);
            }
            ui.separator();
            ui.label(
                RichText::new(format!("Send group \"{gname}\""))
                    .size(12.0)
                    .color(theme::ink_dim()),
            );
            let busy = app
                .rep_group_send
                .as_ref()
                .is_some_and(|s| s.running.load(Ordering::SeqCst));
            for (label, mode) in [
                (
                    "in sequence (single connection)",
                    GroupMode::SingleConnection,
                ),
                ("in sequence (separate connections)", GroupMode::Separate),
                ("in parallel", GroupMode::Parallel),
            ] {
                if item(ui, label, !busy) {
                    ui.close();
                    send(app, gid, mode);
                }
            }
        }
    }
}

/// "Close all tabs in group" (burp.Zio9): the tabs go the way of any
/// closed tab (reopenable), the group goes.
fn close_group_tabs(app: &mut crate::App, group: u64) {
    let ids = send_group::delete_group(&mut app.rep_groups, group);
    let mut reps = app.shared.repeaters.lock().unwrap();
    for id in ids {
        if let Some(pos) = reps.iter().position(|r| r.id == id) {
            crate::repeater_ops::close_tabs(
                &mut reps,
                pos,
                crate::repeater_ops::CloseWhich::This,
                &mut app.rops.closed,
                || app.shared.rep.new_tab_id(),
            );
        }
    }
    drop(reps);
    if app.repeater.sel >= app.shared.repeaters.lock().unwrap().len() {
        app.repeater.sel = app.shared.repeaters.lock().unwrap().len().saturating_sub(1);
    }
}

/// The create/edit group dialog window; call once per frame.
pub fn dialog(app: &mut crate::App, ctx: &egui::Context) {
    let Some(d) = &mut app.rep_group_dialog else {
        return;
    };
    let creating = d.group.is_none();
    let title = if creating {
        "Create Repeater tab group"
    } else {
        "Edit Repeater tab group"
    };
    let mut open = true;
    let mut done = false;
    let mut cancelled = false;
    egui::Window::new(title)
        .default_pos(crate::theme::window_pos(ctx))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            let Some(d) = app.rep_group_dialog.as_mut() else {
                return;
            };
            egui::Grid::new("rep_group").num_columns(2).show(ui, |ui| {
                ui.label("Name:");
                ui.text_edit_singleline(&mut d.name);
                ui.end_row();
                ui.label("Colour:");
                ui.horizontal_wrapped(|ui| {
                    for i in 0..send_group::GROUP_COLOURS {
                        let (rect, resp) =
                            ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::click());
                        ui.painter().rect_filled(rect, 3.0, colour(i as u8));
                        if d.colour == i as u8 {
                            ui.painter().rect_stroke(
                                rect,
                                3.0,
                                egui::Stroke::new(2.0, c(theme::ORANGE_1)),
                                egui::StrokeKind::Outside,
                            );
                        }
                        if resp.clicked() {
                            d.colour = i as u8;
                        }
                    }
                });
                ui.end_row();
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let Some(d) = app.rep_group_dialog.as_ref() else {
                    return;
                };
                let valid = !d.name.trim().is_empty();
                if ui
                    .add_enabled(
                        valid,
                        egui::Button::new(if creating { "Create group" } else { "Save" }),
                    )
                    .clicked()
                {
                    done = true;
                }
                if ui.button("Cancel").clicked() {
                    cancelled = true;
                }
            });
        });
    if done {
        let Some(d) = app.rep_group_dialog.take() else {
            return;
        };
        match d.group {
            None => {
                let mut order = bar_order(app);
                let id = app.shared.rep.new_tab_id();
                send_group::create_group(
                    &mut app.rep_groups,
                    &mut order,
                    id,
                    &d.name,
                    d.colour,
                    &[d.tab],
                );
                apply_order(app, &order);
            }
            Some(gid) => {
                send_group::edit_group(&mut app.rep_groups, gid, &d.name, d.colour);
            }
        }
    } else if !open || cancelled {
        app.rep_group_dialog = None;
    }
}

/// "Send group": validate the group's items for the mode (burp.Zr4d), then
/// run the matching sender on a worker thread, updating each tab with its
/// result as it lands. Problems refuse the send with a toast naming them.
pub fn send(app: &mut crate::App, group: u64, mode: GroupMode) {
    let keep_alive = app.shared.keep_alive.load(Ordering::SeqCst);
    // The group's items in tab-bar order, targets filled from the Host
    // header for tabs without one (what a plain Send does).
    let items: Vec<GroupItem> = {
        let reps = app.shared.repeaters.lock().unwrap();
        reps.iter()
            .filter(|r| send_group::group_of(&app.rep_groups, r.id).is_some_and(|g| g.id == group))
            .map(|r| {
                let mut host = r.host.clone();
                let mut port = r.port;
                if host.trim().is_empty() {
                    let parts = crate::util::parse_http(r.request.as_bytes());
                    let h = crate::util::get_header(&parts.headers, "Host").unwrap_or_default();
                    let (h, p) = net::split_h_p(&h, if r.https { 443 } else { 80 });
                    host = h;
                    port = p;
                }
                GroupItem {
                    tab: r.id,
                    host,
                    port,
                    https: r.https,
                    request: r.request.clone().into_bytes(),
                    http2: crate::repeater_ops::is_http2(&r.request),
                    websocket: r.ws.is_some(),
                }
            })
            .collect()
    };
    let problems = send_group::validate(mode, &items, keep_alive);
    if !problems.is_empty() {
        let mut msg = problems[0].text().to_string();
        if problems.len() > 1 {
            msg.push_str(&format!(" ({} problems)", problems.len()));
        }
        feedback::toast(feedback::Level::Error, format!("Send group refused: {msg}"));
        return;
    }
    let name = app
        .rep_groups
        .iter()
        .find(|g| g.id == group)
        .map(|g| g.name.clone())
        .unwrap_or_default();
    let tabs: Vec<u64> = items.iter().map(|i| i.tab).collect();
    let cancel = Arc::new(AtomicBool::new(false));
    let running = Arc::new(AtomicBool::new(true));
    app.rep_group_send = Some(GroupSend {
        cancel: cancel.clone(),
        running: running.clone(),
        name: name.clone(),
    });
    let sh = app.shared.clone();
    feedback::toast(
        feedback::Level::Info,
        format!("Sending group \"{name}\" ({} requests)", items.len()),
    );
    std::thread::spawn(move || {
        let _tool = net::tool_scope("Repeater");
        let sh_report = sh.clone();
        let report = move |n: usize, r: send_group::GroupResult| {
            {
                let mut reps = sh_report.repeaters.lock().unwrap();
                if let Some(t) = reps.iter_mut().find(|t| Some(t.id) == tabs.get(n).copied()) {
                    t.response = r.response.clone();
                    t.result_line = match &r.error {
                        Some(e) => format!("error: {e}"),
                        None => {
                            let arrival = r
                                .arrival
                                .map(|(a, total)| format!(" | arrival {a}/{total}"))
                                .unwrap_or_default();
                            format!(
                                "Done\t{} bytes | {} millis | {}{arrival}",
                                r.response.as_ref().map_or(0, Vec::len),
                                r.elapsed_ms,
                                r.protocol
                            )
                        }
                    };
                    // response_sources stays parallel to history (a group
                    // send has no follow-redirect source).
                    t.response_sources.resize_with(t.history.len(), || None);
                    t.response_sources.push(None);
                    t.history.push((
                        String::from_utf8_lossy(&r.sent).into_owned(),
                        t.response.clone(),
                        t.result_line.clone(),
                    ));
                    t.hist_pos = t.history.len() - 1;
                }
            }
            sh_report.wake();
        };
        let end = match mode {
            GroupMode::SingleConnection => {
                send_group::run_sequence(&sh, &items, true, &cancel, report)
            }
            GroupMode::Separate => send_group::run_sequence(&sh, &items, false, &cancel, report),
            GroupMode::Parallel => send_group::run_parallel(&sh, &items, &cancel, report),
        };
        running.store(false, Ordering::SeqCst);
        if let send_group::SequenceEnd::UnknownHost(n) = end {
            feedback::toast(
                feedback::Level::Error,
                format!(
                    "Group \"{name}\": unknown host stopped the sequence at request {}",
                    n + 1
                ),
            );
        }
        sh.wake();
    });
}

/// Cancel the running group send, if any (the toolbar's Cancel button).
pub fn cancel(app: &mut crate::App) {
    if let Some(s) = &app.rep_group_send {
        s.cancel.store(true, Ordering::SeqCst);
    }
}

/// The group send in flight, if it is still running.
pub fn is_sending(app: &crate::App) -> bool {
    app.rep_group_send
        .as_ref()
        .is_some_and(|s| s.running.load(Ordering::SeqCst))
}

/// Clear the slot of a finished send; call once per frame.
pub fn tick(app: &mut crate::App) {
    if app
        .rep_group_send
        .as_ref()
        .is_some_and(|s| !s.running.load(Ordering::SeqCst))
    {
        app.rep_group_send = None;
    }
}

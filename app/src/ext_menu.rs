//! "Extensions" in WebProbe's context menus: the items Montoya extensions
//! add (`registerContextMenuItemsProvider`), asked for once when the menu
//! opens and run in the extension's JVM when chosen. Also the "Extension
//! editors" hand-off of a message to extension-provided editors.

use std::cell::RefCell;
use std::sync::Arc;

use eframe::egui;
use webprobe_core::ext_host::{MenuContext, MenuItem, MenuMessage, MenuOutcome, ProxyHooks};
use webprobe_core::net::{HistEntry, Shared};

thread_local! {
    /// The items of the menu now open: its key and, per extension, the items.
    static CACHE: RefCell<Option<(String, Vec<(Arc<dyn ProxyHooks>, Vec<MenuItem>)>)>> = const { RefCell::new(None) };
}

/// A history entry as a menu message.
pub fn message_of(e: &HistEntry) -> MenuMessage {
    MenuMessage {
        request: e.req_raw.to_vec(),
        response: e.resp_raw.as_ref().map(|r| r.to_vec()),
        service: webprobe_core::ext_host::HttpService::new(&e.host, e.port, e.https),
    }
}

fn key(ctx: &MenuContext) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for m in &ctx.messages {
        m.request.hash(&mut h);
        m.response.hash(&mut h);
    }
    format!("{}|{}|{:?}|{}", ctx.tool, ctx.invocation, ctx.editor, h.finish())
}

/// The extensions' items for this menu (asked once per opened menu).
fn items(shared: &Shared, ctx: &MenuContext) -> Vec<(Arc<dyn ProxyHooks>, Vec<MenuItem>)> {
    let k = key(ctx);
    if let Some(hit) = CACHE.with(|c| c.borrow().as_ref().filter(|(ck, _)| *ck == k).map(|(_, v)| v.clone())) {
        return hit;
    }
    let exts = shared.ext_host.lock().unwrap().active();
    let found: Vec<(Arc<dyn ProxyHooks>, Vec<MenuItem>)> = exts
        .into_iter()
        .filter(|e| e.ui().is_some_and(|u| u.menu_providers > 0))
        .map(|e| {
            let items = e.menu_items(ctx);
            (e, items)
        })
        .filter(|(_, items)| !items.is_empty())
        .collect();
    CACHE.with(|c| *c.borrow_mut() = Some((k, found.clone())));
    found
}

/// Draw "Extensions > <extension> > items"; returns what a chosen item
/// did. Nothing is drawn when no extension adds items.
pub fn submenu(ui: &mut egui::Ui, shared: &Shared, ctx: &MenuContext) -> Option<MenuOutcome> {
    let found = items(shared, ctx);
    if found.is_empty() {
        return None;
    }
    let mut outcome = None;
    ui.separator();
    ui.menu_button("Extensions", |ui| {
        for (ext, items) in &found {
            ui.menu_button(ext.extension_name(), |ui| {
                for it in items {
                    if ui.button(&it.label).clicked() {
                        outcome = Some(ext.invoke_menu_item(&it.id));
                        CACHE.with(|c| *c.borrow_mut() = None);
                        ui.close();
                    }
                }
            });
        }
    });
    outcome
}

/// "Extension editors" items of a request editor's menu, when a loaded
/// extension provides editors: send the message to them (they show in the
/// extension's window), or take back the request one changed.
pub fn editor_items(ui: &mut egui::Ui, shared: &Shared, msg: &MenuMessage, tool: &str) -> Option<Vec<u8>> {
    let any = shared.ext_host.lock().unwrap().active().iter().any(|e| e.ui().is_some_and(|u| u.request_editors + u.response_editors > 0));
    if !any {
        return None;
    }
    let mut out = None;
    ui.menu_button("Extension editors", |ui| {
        if ui.button("Open this message in extension editors").clicked() {
            crate::feedback::toast(crate::feedback::Level::Info, open_in_editors(shared, msg, tool));
            ui.close();
        }
        if ui.button("Use the request edited in an extension editor").clicked() {
            match edited_request(shared) {
                Some(r) => out = Some(r),
                None => crate::feedback::toast(crate::feedback::Level::Info, "No extension editor has changed the request."),
            }
            ui.close();
        }
    });
    out
}

/// Offer a message to every extension editor; a summary for a toast.
pub fn open_in_editors(shared: &Shared, msg: &MenuMessage, tool: &str) -> String {
    let exts = shared.ext_host.lock().unwrap().active();
    let mut shown = Vec::new();
    let mut idle = 0;
    for e in exts {
        if let Some(u) = e.ui() {
            if u.request_editors + u.response_editors == 0 {
                continue;
            }
            for t in e.open_in_editors(msg, tool) {
                if t.enabled {
                    shown.push(format!("{} ({})", t.caption, e.extension_name()));
                } else {
                    idle += 1;
                }
            }
            if u.headless {
                return "The extension editors cannot be shown: its JVM runs without a display.".into();
            }
        }
    }
    match (shown.is_empty(), idle) {
        (true, 0) => "No loaded extension provides message editors.".into(),
        (true, _) => "No extension editor handles this message.".into(),
        (false, _) => format!("Opened in the extension window: {}", shown.join(", ")),
    }
}

/// The first request an extension editor changed.
pub fn edited_request(shared: &Shared) -> Option<Vec<u8>> {
    let exts = shared.ext_host.lock().unwrap().active();
    exts.iter().filter(|e| e.ui().is_some_and(|u| u.request_editors > 0)).find_map(|e| e.edited_request())
}

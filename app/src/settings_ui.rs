//! Editors for the target scope and the upstream proxy.
//!
//! Layout and labels follow the Burp 51467 reference surfaces: include /
//! exclude rule tables with per-row enable toggles (`target.scope`), and the
//! project-level proxy form (HTTP proxy servers, SOCKS5 with optional
//! username/password). Reference defaults are empty lists and a disabled,
//! port-0 proxy.

use eframe::egui::{self, RichText, Ui};

use crate::settings::{
    ScopeRule, ScopeState, ScopeTarget, UpstreamKind, UpstreamState,
};
use crate::theme::{self, c};

fn muted(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).size(size).color(c(theme::MONO6))
}

fn section_heading(ui: &mut Ui, text: &str) {
    ui.heading(RichText::new(text).color(c(theme::MONO7)).size(15.0));
}

fn hint(ui: &mut Ui, text: impl Into<String>) {
    ui.label(RichText::new(text).size(11.5).color(c(theme::MONO6)));
}

/// Target-scope editor for include/exclude host and path regex rules.
pub fn show_scope(ui: &mut Ui, state: &mut ScopeState) {
    section_heading(ui, "Target scope");
    hint(
        ui,
        "Enabled exclude rules always win; include host and include path rules both apply when present.",
    );
    ui.add_space(6.0);

    scope_group(ui, "Include", &mut state.include, false);
    ui.add_space(8.0);
    scope_group(ui, "Exclude", &mut state.exclude, true);
    ui.add_space(6.0);

    let matcher = state.matcher();
    if matcher.is_unrestricted() {
        hint(ui, "No valid enabled include rules: every host and path is in scope.");
    } else {
        hint(
            ui,
            "A location is in scope when its host and path satisfy the include rules and no exclude rule matches.",
        );
    }
}

fn scope_group(ui: &mut Ui, title: &str, rules: &mut Vec<ScopeRule>, exclude: bool) {
    ui.horizontal(|ui| {
        let color = if exclude {
            c(theme::BAD)
        } else {
            c(theme::GOOD)
        };
        ui.label(RichText::new(title).size(13.0).strong().color(color));
        hint(
            ui,
            if exclude {
                "matching host or path removes a location from scope"
            } else {
                "host and path patterns are combined"
            },
        );
    });

    if rules.is_empty() {
        hint(
            ui,
            if exclude {
                "No exclude rules."
            } else {
                "No include rules; everything is in scope."
            },
        );
    }

    let mut remove: Option<usize> = None;
    if !rules.is_empty() {
        egui::Grid::new(if exclude {
            "scope_exclude_grid"
        } else {
            "scope_include_grid"
        })
        .striped(true)
        .num_columns(5)
        .spacing([8.0, 4.0])
        .show(ui, |grid| {
            grid.label(muted("on", 11.0));
            grid.label(muted("matches", 11.0));
            grid.label(muted("regex", 11.0));
            grid.label(muted("state", 11.0));
            grid.label("");
            grid.end_row();

            for (index, rule) in rules.iter_mut().enumerate() {
                grid.checkbox(&mut rule.enabled, "");
                grid.horizontal(|ui| {
                    ui.selectable_value(&mut rule.target, ScopeTarget::Host, "host");
                    ui.selectable_value(&mut rule.target, ScopeTarget::Path, "path");
                });
                grid.add(
                    egui::TextEdit::singleline(&mut rule.pattern)
                        .desired_width(260.0)
                        .hint_text("regular expression")
                        .font(egui::TextStyle::Monospace),
                );
                match rule.error() {
                    Some(problem) => {
                        grid.label(RichText::new(problem).size(11.0).color(c(theme::BAD)));
                    }
                    None => {
                        grid.label(RichText::new("valid").size(11.0).color(c(theme::GOOD)));
                    }
                }
                if grid
                    .button("remove")
                    .on_hover_text("Delete this rule")
                    .clicked()
                {
                    remove = Some(index);
                }
                grid.end_row();
            }
        });
    }

    if let Some(index) = remove {
        rules.remove(index);
    }

    ui.horizontal(|ui| {
        if ui
            .button("+ host")
            .on_hover_text("Add a host regex rule")
            .clicked()
        {
            rules.push(ScopeRule::new(ScopeTarget::Host));
        }
        if ui
            .button("+ path")
            .on_hover_text("Add a path regex rule")
            .clicked()
        {
            rules.push(ScopeRule::new(ScopeTarget::Path));
        }
    });
}

/// Upstream-proxy editor (HTTP or SOCKS5, optional credentials).
pub fn show_upstream(ui: &mut Ui, state: &mut UpstreamState) {
    section_heading(ui, "Upstream proxy");
    hint(
        ui,
        "Routes outbound HTTP and HTTPS through an HTTP or SOCKS5 proxy. Credentials are optional.",
    );
    ui.add_space(6.0);

    ui.checkbox(
        &mut state.enabled,
        RichText::new("Use an upstream proxy").size(13.0),
    );
    ui.add_space(4.0);

    egui::Grid::new("upstream_proxy_grid")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |grid| {
            grid.label(muted("Type", 12.0));
            grid.horizontal(|ui| {
                ui.radio_value(&mut state.kind, UpstreamKind::Http, "HTTP");
                ui.radio_value(&mut state.kind, UpstreamKind::Socks5, "SOCKS5");
            });
            grid.end_row();

            grid.label(muted("Host", 12.0));
            grid.add(
                egui::TextEdit::singleline(&mut state.host)
                    .desired_width(220.0)
                    .hint_text("proxy hostname or IP")
                    .font(egui::TextStyle::Monospace),
            );
            grid.end_row();

            grid.label(muted("Port", 12.0));
            grid.horizontal(|ui| {
                ui.add(
                    egui::DragValue::new(&mut state.port)
                        .speed(1.0)
                        .range(0..=65535),
                );
                if state.port == 0 {
                    hint(ui, "0 = unset");
                }
            });
            grid.end_row();

            grid.label(muted("Username", 12.0));
            grid.add(
                egui::TextEdit::singleline(&mut state.username)
                    .desired_width(220.0)
                    .hint_text("optional")
                    .font(egui::TextStyle::Monospace),
            );
            grid.end_row();

            grid.label(muted("Password", 12.0));
            grid.add(
                egui::TextEdit::singleline(&mut state.password)
                    .desired_width(220.0)
                    .password(true)
                    .hint_text("optional")
                    .font(egui::TextStyle::Monospace),
            );
            grid.end_row();
        });

    ui.add_space(4.0);
    if state.enabled {
        match state.validation_error() {
            Some(error) => {
                ui.label(RichText::new(error).size(11.5).color(c(theme::BAD)));
            }
            None => {
                ui.label(
                    RichText::new("Proxy settings are complete.")
                        .size(11.5)
                        .color(c(theme::GOOD)),
                );
            }
        }
        if let Some(endpoint) = state.endpoint() {
            hint(ui, format!("Endpoint: {endpoint}"));
        }
    } else {
        hint(ui, "Disabled: connections go directly to the destination server.");
    }
    hint(ui, match state.kind {
        UpstreamKind::Http => "HTTP proxies receive absolute-form requests; TLS tunnels use CONNECT.",
        UpstreamKind::Socks5 => "SOCKS5 carries TCP and supports optional username/password authentication.",
    });
}

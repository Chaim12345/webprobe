//! UI panel for the loopback-only Collaborator replacement.
//!
//! The required entry point is [`show`]. It exposes explicit start/stop
//! controls for the loopback HTTP and DNS listeners, the current configured
//! ports, visible status and last errors, generated payload tokens/URLs, and
//! the captured interaction list. No cloud payload transport, public DNS
//! resolver, or external service is displayed anywhere in this panel.

use eframe::egui::{self, RichText, Ui};

use crate::collaborator::{
    CollaboratorState, InteractionDetail, InteractionKind, Interaction, MAX_INTERACTIONS,
    MAX_PAYLOADS,
};
use crate::theme::{self, c};

fn hint(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Label::new(RichText::new(text).size(12.0).color(c(theme::MONO6)))
            .wrap_mode(egui::TextWrapMode::Wrap),
    );
}

fn status_label(ui: &mut Ui, running: bool, description: &str, bound: Option<String>) {
    let (text, color) = if running {
        (
            match bound {
                Some(addr) => format!("listening on {addr}"),
                None => format!("starting on {description}"),
            },
            theme::GOOD,
        )
    } else {
        ("stopped".to_string(), theme::MONO6)
    };
    ui.label(RichText::new(text).size(12.0).color(c(color)));
}

fn error_label(ui: &mut Ui, error: Option<String>) {
    if let Some(error) = error {
        ui.add(
            egui::Label::new(
                RichText::new(format!("last error: {error}"))
                    .size(12.0)
                    .color(c(theme::BAD)),
            )
            .wrap_mode(egui::TextWrapMode::Wrap),
        );
    }
}

fn listener_notes(ui: &mut Ui, protocol: &str) {
    if protocol == "HTTP" {
        hint(
            ui,
            "Loopback-only HTTP capture. Sends the request to the local listener and records method, path, headers and body.",
        );
    } else {
        hint(
            ui,
            "Loopback-only DNS capture. Point a local resolver/client at this port; A and ANY queries are answered with 127.0.0.1.",
        );
    }
}

pub fn show(state: &mut CollaboratorState, ui: &mut egui::Ui) {
    ui.heading(
        RichText::new("Collaborator (local)")
            .size(15.0)
            .color(c(theme::MONO7)),
    );
    hint(
        ui,
        "Loopback-only local Collaborator replacement. It records HTTP and DNS interactions that reach these local listeners; it does not use or contact any public DNS/cloud service.",
    );
    ui.add_space(6.0);

    // ------------------------- HTTP listener -------------------------
    ui.group(|ui| {
        ui.label(
            RichText::new("HTTP listener")
                .size(13.0)
                .strong()
                .color(c(theme::ORANGE)),
        );
        let running = state.http.is_running();
        let mut want_start = false;
        let mut want_stop = false;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("port")
                    .size(12.0)
                    .color(c(theme::MONO6)),
            );
            let port_response = ui
                .add_enabled(!running, egui::DragValue::new(&mut state.http.port).range(1..=65535));
            if port_response.changed() {
                state.refresh_payload_urls();
            }
            if running {
                if ui.button("Stop HTTP").clicked() {
                    want_stop = true;
                }
            } else if ui.button("Start HTTP").clicked() {
                want_start = true;
            }
        });
        if want_stop {
            state.stop_http();
        }
        if want_start {
            match state.start_http() {
                Ok(_) => {}
                Err(_) => {}
            }
        }
        let running_now = state.http.is_running();
        status_label(
            ui,
            running_now,
            "127.0.0.1",
            state.http.bound_addr().map(|addr| addr.to_string()),
        );
        error_label(ui, state.http.last_error());
        listener_notes(ui, "HTTP");
    });

    ui.add_space(4.0);

    // -------------------------- DNS listener -------------------------
    ui.group(|ui| {
        ui.label(
            RichText::new("DNS listener")
                .size(13.0)
                .strong()
                .color(c(theme::ORANGE)),
        );
        let running = state.dns.is_running();
        let mut want_start = false;
        let mut want_stop = false;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("port")
                    .size(12.0)
                    .color(c(theme::MONO6)),
            );
            ui.add_enabled(!running, egui::DragValue::new(&mut state.dns.port).range(1..=65535));
            if running {
                if ui.button("Stop DNS").clicked() {
                    want_stop = true;
                }
            } else if ui.button("Start DNS").clicked() {
                want_start = true;
            }
        });
        if want_stop {
            state.stop_dns();
        }
        if want_start {
            match state.start_dns() {
                Ok(_) => {}
                Err(_) => {}
            }
        }
        let running_now = state.dns.is_running();
        status_label(
            ui,
            running_now,
            "127.0.0.1",
            state.dns.bound_addr().map(|addr| addr.to_string()),
        );
        error_label(ui, state.dns.last_error());
        listener_notes(ui, "DNS");
    });

    ui.add_space(6.0);

    // ------------------------- Generated tokens ----------------------
    ui.group(|ui| {
        ui.label(
            RichText::new("Generated payloads")
                .size(13.0)
                .strong()
                .color(c(theme::MONO7)),
        );
        ui.horizontal(|ui| {
            if ui.button("Generate payload").clicked() {
                let _ = state.generate_payload();
            }
            let count = state.payloads().len();
            ui.label(
                RichText::new(format!("{count} retained (max {MAX_PAYLOADS})"))
                    .size(12.0)
                    .color(c(theme::MONO6)),
            );
        });
        let payloads = state.payloads().to_vec();
        if payloads.is_empty() {
            hint(ui, "No payloads generated yet.");
        } else {
            egui::ScrollArea::vertical()
                .id_salt("collab_payload_list")
                .max_height(120.0)
                .show(ui, |ui| {
                    for payload in payloads.iter().rev() {
                        ui.horizontal(|ui| {
                            ui.monospace(
                                RichText::new(payload.http_url.clone())
                                    .size(12.0)
                                    .color(c(theme::ORANGE_5)),
                            );
                            if ui.small_button("copy HTTP").clicked() {
                                ui.ctx().copy_text(payload.http_url.clone());
                            }
                            let dns_text = format!(
                                "{} (query 127.0.0.1:{})",
                                payload.dns_name, state.dns.port
                            );
                            if ui.small_button("copy DNS").clicked() {
                                ui.ctx().copy_text(dns_text);
                            }
                        });
                        ui.label(
                            RichText::new(format!(
                                "token: {}",
                                payload.token
                            ))
                            .size(12.0)
                            .color(c(theme::MONO6)),
                        );
                    }
                });
        }
        hint(ui, "Payload URLs are local-only. They are meaningful only when the corresponding listeners are running on 127.0.0.1.");
    });

    ui.add_space(6.0);

    // -------------------- Observed interactions ----------------------
    ui.group(|ui| {
        let interactions: Vec<Interaction> = state.interactions();
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "Interactions ({}/{MAX_INTERACTIONS})",
                    interactions.len()
                ))
                .size(13.0)
                .strong()
                .color(c(theme::MONO7)),
            );
            if !interactions.is_empty() && ui.small_button("Clear all").clicked() {
                state.clear_interactions();
            }
        });
        if interactions.is_empty() {
            hint(ui, "No HTTP or DNS interactions captured on these local listeners yet.");
        } else {
            let columns = [
                crate::table::Column::new("Time", 92.0),
                crate::table::Column::new("Type", 60.0),
                crate::table::Column::new("Target", 340.0),
            ];
            let mut rows: Vec<(String, String, String, Interaction)> = interactions
                .iter()
                .map(|i| {
                    (
                        format_clock(i.at),
                        i.kind().label().to_string(),
                        i.headline(),
                        i.clone(),
                    )
                })
                .collect();
            crate::table::sort_rows(&mut rows, &state.table, |row, col| match col {
                0 => row.0.clone(),
                1 => row.1.clone(),
                _ => row.2.clone(),
            });
            let mut selected = state.selected;
            egui::ScrollArea::vertical()
                .id_salt("collab_interactions")
                .max_height(280.0)
                .show(ui, |ui| {
                    crate::table::data_table(
                        ui,
                        "collab_interactions_table",
                        &columns,
                        &rows,
                        &mut state.table,
                        theme::appearance().1.row_height(),
                        |(clock, kind, headline, interaction), ui| {
                            let color = match interaction.kind() {
                                InteractionKind::Http => c(theme::METHOD_OTHER),
                                InteractionKind::Dns => c(theme::ORANGE_5),
                            };
                            let row_h = theme::appearance().1.row_height();
                            let row = ui
                                .horizontal(|ui| {
                                    crate::table::cell(ui, &columns[0], clock.clone(), Some(c(theme::MONO6)), row_h);
                                    crate::table::cell(ui, &columns[1], kind.clone(), Some(color), row_h);
                                    crate::table::cell(ui, &columns[2], headline.clone(), Some(color), row_h);
                                })
                                .response
                                .interact(egui::Sense::click());
                            if row.clicked() {
                                selected = Some(interaction.id);
                            }
                        },
                    );
                });
            state.selected = selected;
            // Detail for the selected interaction (falls back to the newest).
            let detail = state
                .selected
                .and_then(|id| interactions.iter().find(|i| i.id == id))
                .or_else(|| interactions.last());
            if let Some(interaction) = detail {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!(
                        "id {}  source {}  token {}",
                        interaction.id,
                        interaction.source,
                        interaction.token.as_deref().unwrap_or("(none)")
                    ))
                    .size(12.0)
                    .color(c(theme::MONO6)),
                );
                match &interaction.detail {
                    InteractionDetail::Http(http) => http_details(ui, http),
                    InteractionDetail::Dns(dns) => dns_details(ui, dns),
                }
            }
        }
    });
}

fn http_details(ui: &mut Ui, http: &crate::collaborator::HttpInteraction) {
    ui.label(
        RichText::new(format!(
            "{} {} {}",
            http.method, http.target, http.version
        ))
        .monospace()
        .size(12.0)
        .color(theme::method_color(&http.method)),
    );
    egui::Grid::new("collab_http_headers").num_columns(2).show(
        ui,
        |ui| {
            for (name, value) in &http.headers {
                ui.label(
                    RichText::new(name.clone())
                        .monospace()
                        .size(12.0)
                        .color(c(theme::HEADER_BLUE)),
                );
                ui.label(
                    RichText::new(value.clone())
                        .monospace()
                        .size(12.0)
                        .color(c(theme::EDITOR_TEXT)),
                );
                ui.end_row();
            }
        },
    );
    if !http.body.is_empty() {
        ui.label(
            RichText::new(format!("body ({} bytes)", http.body.len()))
                .size(12.0)
                .color(c(theme::MONO6)),
        );
        ui.monospace(
            RichText::new(String::from_utf8_lossy(&http.body).into_owned())
                .size(12.0)
                .color(c(theme::EDITOR_TEXT)),
        );
    }
}

fn dns_details(ui: &mut Ui, dns: &crate::collaborator::DnsInteraction) {
    ui.label(
        RichText::new(format!("query: {}", dns.qname))
            .monospace()
            .size(12.0)
            .color(c(theme::EDITOR_TEXT)),
    );
    ui.label(
        RichText::new(format!(
            "type: {} ({})  class IN  raw {} bytes",
            dns.qtype_label(),
            dns.qtype,
            dns.raw_query.len()
        ))
        .size(12.0)
        .color(c(theme::MONO6)),
    );
    ui.label(
        RichText::new("reply: A 127.0.0.1")
            .size(12.0)
            .color(c(theme::GOOD)),
    );
}

fn format_clock(unix_secs: u64) -> String {
    let day_secs = unix_secs % 86_400;
    format!(
        "{:02}:{:02}:{:02}Z",
        day_secs / 3600,
        (day_secs / 60) % 60,
        day_secs % 60
    )
}

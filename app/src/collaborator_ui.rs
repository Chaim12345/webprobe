//! UI panel for the loopback-only Collaborator replacement.
//!
//! The required entry point is [`show`]. It exposes explicit start/stop
//! controls for the loopback HTTP and DNS listeners, the current configured
//! ports, visible status and last errors, generated payload tokens/URLs, and
//! the captured interaction list. No cloud payload transport, public DNS
//! resolver, or external service is displayed anywhere in this panel.

use eframe::egui::{self, RichText, Ui};

use crate::collaborator::{
    CollaboratorState, InteractionDetail, InteractionKind, Interaction,
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

/// Burp's Collaborator tab (live 52685): onboarding until "Get started",
/// then the client: Copy to clipboard / Poll now / "Include Collaborator
/// server location", the interactions table and Description / Request to
/// Collaborator / Response from Collaborator. Server and listener settings
/// sit behind the gear.
pub fn show(state: &mut CollaboratorState, ui: &mut egui::Ui) {
    if !state.ui_started {
        ui.add_space(ui.available_height() * 0.25);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(theme::icon::BROADCAST).size(56.0).color(c(0x26649D)));
            ui.add_space(8.0);
            ui.label(RichText::new("WebProbe Collaborator").strong().size(16.0).color(theme::ink()));
            ui.add_space(8.0);
            ui.label(RichText::new("Collaborator enables you to test whether you can induce an application to interact with an external service via DNS, HTTP, or SMTP. This type of testing makes it easier to discover blind or asynchronous vulnerabilities.").size(12.5).color(theme::ink_dim()));
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(ui.available_width() / 2.0 - 100.0);
                if ui.button("Learn more").on_hover_text("Payloads come from a public interactsh server or the loopback listeners").clicked() {
                    state.ui_settings = true;
                    state.ui_started = true;
                }
                let gs = egui::Button::new(RichText::new("Get started").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1));
                if ui.add(gs).clicked() {
                    state.ui_started = true;
                }
            });
        });
        return;
    }
    let interactions: Vec<Interaction> = state.interactions();
    ui.horizontal(|ui| {
        let copy = egui::Button::new(RichText::new("Copy to clipboard").strong().color(egui::Color32::WHITE)).fill(c(theme::ORANGE_1)).min_size(egui::vec2(140.0, 24.0));
        if ui.add(copy).on_hover_text("Generate a new payload and copy it").clicked() {
            let p = state.generate_payload();
            let text = if state.include_server { p.dns_name.clone() } else { p.dns_name.split('.').next().unwrap_or("").to_string() };
            ui.ctx().copy_text(text.clone());
            crate::feedback::toast(crate::feedback::Level::Success, format!("Copied {text}"));
        }
        ui.checkbox(&mut state.include_server, "Include Collaborator server location");
        if ui.button("Poll now").clicked() {
            state.poll_now();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            if ui.add(egui::Button::new(RichText::new(theme::icon::GEAR).size(16.0)).frame(false)).on_hover_text("Collaborator server and listeners").clicked() {
                state.ui_settings = !state.ui_settings;
            }
            let server = state.remote_server().map(|d| format!("*.{d}")).unwrap_or_else(|| {
                if state.http.is_running() || state.dns.is_running() { "loopback listeners (127.0.0.1)".to_string() } else { "not configured".to_string() }
            });
            ui.label(RichText::new(format!("Collaborator server: {server}")).size(12.5).color(theme::ink_dim()));
        });
    });
    ui.add_space(6.0);
    if state.ui_settings {
        egui::Frame::NONE.fill(theme::chrome()).stroke(egui::Stroke::new(1.0, theme::line())).inner_margin(egui::Margin::same(8)).show(ui, |ui| {
            settings_panel(state, ui);
        });
        ui.add_space(6.0);
    }
    let cols = [
        crate::table::Column::new("#", 50.0),
        crate::table::Column::new("Time", 150.0),
        crate::table::Column::new("Type", 70.0),
        crate::table::Column::new("Payload", 220.0),
        crate::table::Column::new("Source IP address", 140.0),
        crate::table::Column::new("Comment", 300.0),
    ];
    let mut selected = state.selected;
    let full = ui.available_height();
    let mut tbl = state.table.clone();
    egui_extras::StripBuilder::new(ui)
        .size(egui_extras::Size::relative(0.45))
        .size(egui_extras::Size::remainder())
        .vertical(|mut col| {
            col.cell(|ui| {
                let rows: Vec<Interaction> = interactions.iter().rev().cloned().collect();
                let h = ui.available_height();
                crate::table::table_body(ui, "collab_rows", &cols, &rows, &mut tbl, 19.0, h, &mut |i, ui| {
                    let rr = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 19.0));
                    if selected == Some(i.id) {
                        ui.painter().rect_filled(rr, 0.0, theme::selection_bg());
                    }
                    let row = ui.horizontal(|ui| {
                        crate::table::cells(ui, &cols, &crate::table::TableState::default(), 19.0, &[
                            (0, i.id.to_string(), None),
                            (1, format_clock(i.at), None),
                            (2, i.kind().label().to_string(), None),
                            (3, i.token.clone().unwrap_or_default(), None),
                            (4, i.source.clone(), None),
                            (5, i.headline(), None),
                        ]);
                    }).response.interact(egui::Sense::click());
                    if row.clicked() {
                        selected = Some(i.id);
                    }
                });
            });
            col.cell(|ui| {
                let Some(i) = selected.and_then(|id| interactions.iter().find(|x| x.id == id)) else {
                    if interactions.is_empty() {
                        ui.add_space(10.0);
                        ui.label(RichText::new(if state.remote_server().is_some() { "No interactions yet. Payloads are polled every 3 seconds; click Poll now to check immediately." } else { "No interactions yet. Copy a payload, use it in a request, then poll. Configure a server with the gear." }).size(12.5).color(theme::ink_dim()));
                    }
                    return;
                };
                ui.horizontal(|ui| {
                    if let Some(v) = crate::msgpane::underline_tabs(ui, &["Description", "Request to Collaborator", "Response from Collaborator"], state.detail_tab, 13.0) {
                        state.detail_tab = v;
                    }
                });
                let _ = full;
                egui::ScrollArea::vertical().id_salt("collab_detail").auto_shrink([false, false]).show(ui, |ui| match state.detail_tab {
                    0 => {
                        let what = match i.kind() {
                            InteractionKind::Http => "an HTTP request",
                            InteractionKind::Dns => "a DNS lookup",
                            InteractionKind::Smtp => "an SMTP connection",
                        };
                        ui.label(RichText::new(format!(
                            "The Collaborator server received {what} for the payload {}. The request was received from IP address {} at {}.",
                            i.token.clone().unwrap_or_default(), i.source, format_clock(i.at)
                        )).size(12.5).color(theme::ink_dim()));
                    }
                    1 => match &i.detail {
                        InteractionDetail::Http(http) => http_details(ui, http),
                        InteractionDetail::Dns(dns) => dns_details(ui, dns),
                        InteractionDetail::Smtp(smtp) => smtp_details(ui, smtp),
                    },
                    _ => {
                        ui.label(RichText::new("The server's reply is a fixed acknowledgement (HTTP 200 with an empty body, or an A record of 127.0.0.1 for DNS).").size(12.5).color(theme::ink_dim()));
                    }
                });
            });
        });
    state.table = tbl;
    state.selected = selected;
}

/// Server and listener configuration (the gear in Burp's client).
fn settings_panel(state: &mut CollaboratorState, ui: &mut egui::Ui) {
    hint(
        ui,
        "Use a public interactsh server so targets on the internet can reach the payloads (DNS, HTTP and SMTP, polled every 3 s); the loopback listeners only see traffic from this machine.",
    );
    ui.add_space(6.0);

    // ------------------------- Public server (interactsh) -------------
    ui.group(|ui| {
        ui.label(RichText::new("Public server (interactsh)").size(13.0).strong().color(c(theme::ORANGE)));
        let active = state.remote_server();
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("collab_remote_server")
                .selected_text(state.remote_choice.clone())
                .show_ui(ui, |ui| {
                    for srv in crate::interactsh::DEFAULT_SERVERS {
                        ui.selectable_value(&mut state.remote_choice, srv.to_string(), srv);
                    }
                });
            if active.is_some() {
                if ui.button("Stop").clicked() {
                    state.stop_remote();
                }
            } else if ui.button("Use public server").clicked() {
                let choice = state.remote_choice.clone();
                match state.start_remote(&choice) {
                    Ok(d) => crate::feedback::toast(crate::feedback::Level::Info, &format!("Collaborator registered on {d}")),
                    Err(e) => crate::feedback::toast(crate::feedback::Level::Error, &e),
                }
            }
        });
        status_label(ui, active.is_some(), "public payloads", active.map(|d| format!("*.{d}")));
        error_label(ui, state.remote_error());
    });
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
        match state.remote_server() {
            Some(d) => hint(ui, &format!("Payloads resolve publicly under *.{d}: any DNS lookup, HTTP request or mail to user@<payload> is reported here.")),
            None => hint(ui, "Payload URLs are local-only. They are meaningful only when the corresponding listeners are running on 127.0.0.1."),
        }
    });

    ui.add_space(6.0);

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

fn smtp_details(ui: &mut Ui, smtp: &crate::collaborator::SmtpInteraction) {
    ui.label(RichText::new(format!("MAIL FROM: {}", smtp.from)).monospace().size(12.0).color(c(theme::EDITOR_TEXT)));
    ui.label(RichText::new(&smtp.conversation).monospace().size(12.0).color(c(theme::MONO6)));
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

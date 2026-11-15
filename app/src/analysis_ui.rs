//! UI for the integrated Sequencer report and Comparer workspaces.

use eframe::egui::{self, RichText, Ui};

use crate::analysis::{self, ComparerState, DiffKind};
use crate::net::HistEntry;
use crate::theme::{self, c};

fn hint(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Label::new(RichText::new(text).size(12.0).color(c(theme::MONO6)))
            .wrap_mode(egui::TextWrapMode::Wrap),
    );
}

fn workspace_heading(ui: &mut Ui, title: &str) {
    ui.heading(RichText::new(title).color(c(theme::MONO7)).size(15.0));
    ui.add_space(4.0);
}

fn stat_row(ui: &mut Ui, key: &str, value: String) {
    ui.label(RichText::new(key).size(12.5).color(c(theme::MONO6)));
    ui.monospace(value);
    ui.end_row();
}

fn number(value: f64) -> String {
    if !value.is_finite() {
        "n/a".into()
    } else if (value.abs() >= 1e9) || (value != 0.0 && value.abs() < 1e-4) {
        format!("{value:.6e}")
    } else {
        format!("{value:.4}")
    }
}

fn optional_number(value: Option<f64>) -> String {
    value.map(number).unwrap_or_else(|| "n/a".into())
}

pub fn show_sequencer_report(ui: &mut Ui, report: &analysis::SequencerReport) {
    egui::Grid::new("sequencer_workspace_stats")
        .striped(true)
        .num_columns(2)
        .show(ui, |ui| {
            stat_row(ui, "tokens", report.token_count.to_string());
            stat_row(ui, "unique tokens", report.unique_tokens.to_string());
            stat_row(ui, "total characters", report.total_characters.to_string());
            stat_row(
                ui,
                "entropy (bits/char)",
                format!(
                    "{:.4} (effective alphabet {:.2})",
                    report.entropy_bits_per_character, report.effective_alphabet
                ),
            );
            stat_row(
                ui,
                "chi-square",
                match &report.chi_square {
                    Some(chi) => format!(
                        "{:.4} (df {}, p = {})",
                        chi.statistic,
                        chi.degrees_of_freedom,
                        optional_number(chi.p_value)
                    ),
                    None => "n/a (needs 2+ distinct characters)".into(),
                },
            );
        });

    if let Some(numeric) = &report.numeric {
        ui.add_space(4.0);
        egui::Grid::new("sequencer_workspace_numeric")
            .striped(true)
            .num_columns(2)
            .show(ui, |ui| {
                stat_row(ui, "numeric tokens", numeric.count.to_string());
                stat_row(ui, "minimum", number(numeric.min));
                stat_row(ui, "maximum", number(numeric.max));
                stat_row(ui, "mean", number(numeric.mean));
                stat_row(ui, "std dev (population)", number(numeric.std_dev));
            });
    } else {
        ui.add_space(4.0);
        hint(ui, "no decimal tokens; numeric statistics unavailable");
    }
}

// ================= Comparer =================

fn line_label(number: Option<usize>) -> String {
    number.map(|value| value.to_string()).unwrap_or_else(|| "-".into())
}

fn byte_label(row: &analysis::CompareRow) -> String {
    match row.kind {
        DiffKind::Same => format!("{}", row.left_bytes),
        DiffKind::Added => format!("+{}", row.right_bytes),
        DiffKind::Removed => format!("-{}", row.left_bytes),
        DiffKind::Changed => format!("{} / {}", row.left_bytes, row.right_bytes),
    }
}

fn compare_row_colors(kind: DiffKind) -> (char, egui::Color32) {
    match kind {
        DiffKind::Same => (' ', c(theme::MONO6)),
        DiffKind::Added => ('+', c(theme::GOOD)),
        DiffKind::Removed => ('-', c(theme::BAD)),
        DiffKind::Changed => ('~', c(theme::WARN)),
    }
}

pub fn show_comparer(
    state: &mut ComparerState,
    selected: Option<HistEntry>,
    ui: &mut Ui,
) {
    workspace_heading(ui, "Comparer");
    hint(
        ui,
        "Edit the two inputs and Compare. The diff is an exact line-level LCS; line numbers \
         are 1-based per side and byte lengths cover the displayed line text (terminators \
         excluded).",
    );
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        if ui.button("Selected request → A").clicked() {
            if let Some(entry) = selected.as_ref() {
                state.left = String::from_utf8_lossy(&entry.req_raw).into_owned();
            }
        }
        if ui.button("Selected response → A").clicked() {
            if let Some(response) = selected.as_ref().and_then(|entry| entry.resp_raw.as_ref()) {
                state.left = String::from_utf8_lossy(response).into_owned();
            }
        }
        if ui.button("Selected request → B").clicked() {
            if let Some(entry) = selected.as_ref() {
                state.right = String::from_utf8_lossy(&entry.req_raw).into_owned();
            }
        }
        if ui.button("Selected response → B").clicked() {
            if let Some(response) = selected.as_ref().and_then(|entry| entry.resp_raw.as_ref()) {
                state.right = String::from_utf8_lossy(response).into_owned();
            }
        }
    });
    ui.columns(2, |columns| {
        columns[0].label(RichText::new("A").size(12.0).color(c(theme::MONO6)));
        columns[0].add(
            egui::TextEdit::multiline(&mut state.left)
                .font(egui::TextStyle::Monospace)
                .code_editor()
                .desired_rows(8)
                .hint_text("left side"),
        );
        columns[1].label(RichText::new("B").size(12.0).color(c(theme::MONO6)));
        columns[1].add(
            egui::TextEdit::multiline(&mut state.right)
                .font(egui::TextStyle::Monospace)
                .code_editor()
                .desired_rows(8)
                .hint_text("right side"),
        );
    });
    ui.horizontal(|ui| {
        if ui.button("Compare").clicked() {
            state.recompute();
        }
        if ui.button("Clear").clicked() {
            state.clear();
        }
    });
    if !state.status.is_empty() {
        hint(ui, &state.status);
    }
    if state.rows.is_empty() {
        if state.status.is_empty() {
            hint(ui, "no diff yet; press Compare to produce row(s)");
        }
        return;
    }
    ui.add_space(4.0);
    let available_height = (ui.available_height() - 16.0).max(160.0);
    egui::ScrollArea::both().max_height(available_height).show(ui, |ui| {
        egui::Grid::new("comparer_workspace_rows")
            .striped(true)
            .num_columns(5)
            .show(ui, |ui| {
                for value in [
                    RichText::new("sign").size(12.0).color(c(theme::MONO6)),
                    RichText::new("A line").size(12.0).color(c(theme::MONO6)),
                    RichText::new("B line").size(12.0).color(c(theme::MONO6)),
                    RichText::new("text").size(12.0).color(c(theme::MONO6)),
                    RichText::new("bytes").size(12.0).color(c(theme::MONO6)),
                ] {
                    ui.monospace(value);
                }
                ui.end_row();

                for row in &state.rows {
                    let (marker, color) = compare_row_colors(row.kind);
                    ui.monospace(RichText::new(marker).color(color));
                    ui.monospace(RichText::new(line_label(row.left_line)).color(c(theme::MONO6)));
                    ui.monospace(RichText::new(line_label(row.right_line)).color(c(theme::MONO6)));
                    ui.monospace(RichText::new(row.text.clone()).color(color));
                    ui.monospace(RichText::new(byte_label(row)).color(c(theme::MONO6)));
                    ui.end_row();
                }
            });
    });
}


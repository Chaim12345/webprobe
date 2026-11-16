//! UI for the integrated Sequencer report and Comparer workspaces.

use eframe::egui::{self, RichText, Ui};

use crate::analysis;
use crate::theme::{self, c};

/// Faint tinted panel for status and empty-state notes (design token consumer
/// for theme::subtle_bg / RADIUS_M).
fn banner(ui: &mut Ui, text: &str) {
    egui::Frame::NONE
        .fill(theme::subtle_bg())
        .corner_radius(theme::RADIUS_M)
        .inner_margin(egui::Margin::symmetric(theme::SPACE_M as i8, theme::SPACE_S as i8))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.0).color(theme::ink_dim()));
        });
}

/// Section heading for a workspace tab. Uses the H2 size token so both
/// workspaces scale together (Burp's pane titles are 15 px).
pub fn workspace_heading(ui: &mut Ui, title: &str) {
    ui.heading(RichText::new(title).color(theme::ink()).size(theme::FONT_H2));
    ui.add_space(theme::SPACE_XS);
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
    workspace_heading(ui, "Sequencer report");
    // Density drives the row gap; the key/value column gap is the design
    // token's wide step so long numbers stay readable.
    let spacing = egui::vec2(theme::SPACE_L, theme::appearance().1.item_spacing());
    egui::Grid::new("sequencer_workspace_stats")
        .striped(true)
        .num_columns(2)
        .spacing(spacing)
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
        ui.add_space(theme::SPACE_XL);
        egui::Grid::new("sequencer_workspace_numeric")
            .striped(true)
            .num_columns(2)
            .spacing(spacing)
            .show(ui, |ui| {
                stat_row(ui, "numeric tokens", numeric.count.to_string());
                stat_row(ui, "minimum", number(numeric.min));
                stat_row(ui, "maximum", number(numeric.max));
                stat_row(ui, "mean", number(numeric.mean));
                stat_row(ui, "std dev (population)", number(numeric.std_dev));
            });
    } else {
        banner(ui, "no decimal tokens; numeric statistics unavailable");
    }
}

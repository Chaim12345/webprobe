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

/// Bit-level results (Burp's Sequencer summary): the overall rating, the
/// effective entropy at each significance level, a bar per bit position and
/// the export buttons. `export_path` is the file the buttons write to.
pub fn show_bit_report(ui: &mut egui::Ui, report: &crate::seq_bits::BitReport, samples: &[Vec<u8>], export_path: &mut String) {
    use crate::seq_bits as sb;
    ui.add_space(10.0);
    ui.label(egui::RichText::new("Overall result").strong().size(14.0).color(theme::ink()));
    ui.label(egui::RichText::new(sb::summary(report)).size(12.5).color(theme::ink_dim()));
    ui.add_space(6.0);
    ui.label(egui::RichText::new("Effective entropy").strong().size(13.0).color(theme::ink()));
    egui::Grid::new("seq_effective_entropy").striped(true).num_columns(2).spacing([24.0, 3.0]).show(ui, |ui| {
        ui.label(egui::RichText::new("Significance level").size(12.5).color(theme::ink_faint()));
        ui.label(egui::RichText::new("Bits").size(12.5).color(theme::ink_faint()));
        ui.end_row();
        for (label, bits) in sb::LEVEL_LABELS.iter().zip(report.effective_entropy) {
            ui.label(egui::RichText::new(*label).size(12.5).color(theme::ink()));
            ui.label(egui::RichText::new(format!("{bits} of {}", report.token_bits)).size(12.5).color(theme::ink_dim()));
            ui.end_row();
        }
    });
    ui.add_space(6.0);
    ui.label(egui::RichText::new("Bit-level results (one bar per bit position; taller is more random, red fails at 1%)").size(12.5).color(theme::ink()));
    // One bar per bit: height is the combined p-value on a log scale from
    // 0.001% (empty) to 100% (full), as in Burp's bit-level chart.
    let width = ui.available_width().min(report.bits.len() as f32 * 6.0 + 2.0).max(60.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 90.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, theme::chrome());
    let step = rect.width() / report.bits.len().max(1) as f32;
    for (i, bit) in report.bits.iter().enumerate() {
        let frac = ((bit.combined.max(1e-5).log10() + 5.0) / 5.0).clamp(0.0, 1.0) as f32;
        let x0 = rect.left() + i as f32 * step;
        let bar = egui::Rect::from_min_max(egui::pos2(x0 + 0.5, rect.bottom() - 2.0 - frac * (rect.height() - 4.0)), egui::pos2(x0 + step - 0.5, rect.bottom()));
        painter.rect_filled(bar, 0.0, if bit.combined >= 0.01 { c(theme::GOOD) } else { c(theme::BAD) });
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(export_path).hint_text("file").desired_width(260.0));
        let write = |what: &str, bytes: Vec<u8>, path: &str| {
            if path.trim().is_empty() {
                crate::feedback::toast(crate::feedback::Level::Warn, "Enter a file path first");
                return;
            }
            match std::fs::write(path.trim(), bytes) {
                Ok(()) => crate::feedback::toast(crate::feedback::Level::Success, format!("{what} saved to {}", path.trim())),
                Err(e) => crate::feedback::toast(crate::feedback::Level::Error, format!("Could not save {what}: {e}")),
            }
        };
        if ui.button("Save tokens").clicked() {
            write("Tokens", sb::tokens_text(samples), export_path);
        }
        if ui.button("Export analysis (CSV)").clicked() {
            write("Analysis", sb::report_csv(report).into_bytes(), export_path);
        }
        if ui.button("Export analysis (JSON)").clicked() {
            write("Analysis", sb::report_json(report).into_bytes(), export_path);
        }
    });
}

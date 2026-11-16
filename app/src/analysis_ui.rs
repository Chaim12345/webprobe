//! UI for the integrated Sequencer report and Comparer workspaces.

use eframe::egui::{self, RichText, Ui};

use crate::analysis::{self, ComparerState, DiffKind};
use crate::net::HistEntry;
use crate::theme::{self, c};
use crate::util;

fn hint(ui: &mut Ui, text: &str) {
    ui.add(
        egui::Label::new(RichText::new(text).size(12.0).color(c(theme::MONO6)))
            .wrap_mode(egui::TextWrapMode::Wrap),
    );
}

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

// ================= Comparer =================

/// Side label for a line number that may be absent.
pub fn line_label(number: Option<usize>) -> String {
    number.map(|value| value.to_string()).unwrap_or_else(|| "-".into())
}

/// Byte-count cell for one diff row ("12", "+30", "-8", "5 / 7").
pub fn byte_label(row: &analysis::CompareRow) -> String {
    match row.kind {
        DiffKind::Same => format!("{}", row.left_bytes),
        DiffKind::Added => format!("+{}", row.right_bytes),
        DiffKind::Removed => format!("-{}", row.left_bytes),
        DiffKind::Changed => format!("{} / {}", row.left_bytes, row.right_bytes),
    }
}

/// Sign marker and text colour for one diff row.
pub fn compare_row_colors(kind: DiffKind) -> (char, egui::Color32) {
    match kind {
        DiffKind::Same => (' ', c(theme::MONO6)),
        DiffKind::Added => ('+', c(theme::GOOD)),
        DiffKind::Removed => ('-', c(theme::BAD)),
        DiffKind::Changed => ('~', c(theme::WARN)),
    }
}

/// Row background in Burp's comparison window: the side that lost or gained the
/// line is tinted (Modified / Deleted / Added). Shared by the tab renderer and
/// the window renderer so both paint the same palette.
pub fn compare_row_background(kind: DiffKind, side: usize) -> Option<egui::Color32> {
    match (kind, side) {
        (DiffKind::Removed, 0) => Some(c(0xEE95A1)),
        (DiffKind::Added, 1) => Some(c(0x9BCF88)),
        (DiffKind::Changed, _) => Some(c(0x9FBBD4)),
        _ => None,
    }
}

/// The striped diff table under the A/B editors (tab renderer).
pub fn compare_table_ui(ui: &mut Ui, st: &ComparerState) {
    let spacing = theme::appearance().1.item_spacing();
    egui::Grid::new("comparer_workspace_rows")
        .striped(true)
        .num_columns(5)
        .spacing(egui::vec2(spacing, spacing))
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

            for row in &st.rows {
                let (marker, color) = compare_row_colors(row.kind);
                ui.monospace(RichText::new(marker).color(color));
                ui.monospace(RichText::new(line_label(row.left_line)).color(c(theme::MONO6)));
                ui.monospace(RichText::new(line_label(row.right_line)).color(c(theme::MONO6)));
                ui.monospace(RichText::new(row.text.clone()).color(color));
                ui.monospace(RichText::new(byte_label(row)).color(c(theme::MONO6)));
                ui.end_row();
            }
        });
}

/// Body of Burp's comparison window: the colour key and the two scrollable
/// sides, numbered `#a` / `#b` as in the window title. `bytes_mode` shows each
/// row's hex view. This is the canonical renderer — the window drawn inline in
/// ui.rs (cmp_window branch) should call this instead of its private copy.
pub fn comparer_columns_ui(ui: &mut Ui, st: &ComparerState, a_no: usize, b_no: usize, bytes_mode: bool) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Key:").size(12.5));
        for (name, col) in [("Modified", 0x9FBBD4), ("Deleted", 0xEE95A1), ("Added", 0x9BCF88)] {
            egui::Frame::NONE.fill(c(col)).inner_margin(egui::Margin::symmetric(6, 1)).show(ui, |ui| {
                ui.label(RichText::new(name).size(12.0).color(egui::Color32::BLACK));
            });
        }
    });
    ui.add_space(theme::SPACE_XS);
    ui.columns(2, |cols| {
        for (side, col) in cols.iter_mut().enumerate() {
            let len = if side == 0 { st.left.len() } else { st.right.len() };
            col.label(RichText::new(format!("#{}  Length: {}", if side == 0 { a_no } else { b_no }, len)).size(12.5).strong());
            egui::ScrollArea::both().id_salt(("cmpw", side)).auto_shrink([false, false]).show(col, |ui| {
                for r in &st.rows {
                    let present = if side == 0 { r.left_line.is_some() } else { r.right_line.is_some() };
                    if !present {
                        continue;
                    }
                    let text = if bytes_mode { util::hex_view(r.text.as_bytes(), 4096) } else { r.text.clone() };
                    let mut rt = RichText::new(text).monospace().size(12.5).color(theme::editor_colours().text);
                    if let Some(bg) = compare_row_background(r.kind, side) {
                        rt = rt.background_color(bg).color(egui::Color32::BLACK);
                    }
                    ui.label(rt);
                }
            });
        }
    });
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
    ui.add_space(theme::SPACE_L);
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = theme::appearance().1.item_spacing();
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
        banner(ui, &state.status);
    }
    if state.rows.is_empty() {
        if state.status.is_empty() {
            banner(ui, "no diff yet; press Compare to produce row(s)");
        }
        return;
    }
    ui.add_space(theme::SPACE_L);
    let available_height = (ui.available_height() - theme::SPACE_L).max(160.0);
    egui::ScrollArea::both().max_height(available_height).show(ui, |ui| {
        compare_table_ui(ui, state);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_colours_follow_the_diff_kind() {
        assert_eq!(line_label(None), "-");
        assert_eq!(line_label(Some(7)), "7");
        let row = analysis::CompareRow {
            kind: DiffKind::Added,
            left_line: None,
            right_line: Some(3),
            text: "x".into(),
            left_bytes: 0,
            right_bytes: 30,
        };
        assert_eq!(byte_label(&row), "+30");
        assert_eq!(compare_row_colors(DiffKind::Changed), ('~', c(theme::WARN)));
        assert_eq!(compare_row_background(DiffKind::Removed, 0), Some(c(0xEE95A1)));
        assert_eq!(compare_row_background(DiffKind::Removed, 1), None);
        assert_eq!(compare_row_background(DiffKind::Same, 0), None);
    }
}


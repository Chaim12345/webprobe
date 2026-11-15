//! Match-and-replace rules table.
//!
//! Widget labels and tooltips follow the Burp Suite 51467 rule editor
//! (`Zg5h`): "Direction", "Match:", "Replace:", "Comment:", and "Regex match"
//! tooltip. The scope list is the seven HTTP scopes from `MrScope::ALL`.

use eframe::egui;

use crate::rules::{MrRule, MrScope};
use crate::theme;

/// Edit one list of match-and-replace rules. `request_side` controls the
/// heading, the default scope that new rules get, and the add button label.
pub fn rules_editor(ui: &mut egui::Ui, rules: &mut Vec<MrRule>, request_side: bool) {
    let title = if request_side {
        "Request rules"
    } else {
        "Response rules"
    };
    ui.label(grey(title, 12.5));

    if rules.is_empty() {
        ui.label(grey("(no rules)", 12.0));
    }

    let count = rules.len();
    egui::ScrollArea::horizontal().id_salt(("mr_scroll", request_side)).show(ui, |scroll_ui| {
        egui::Grid::new(("mr_rules", request_side))
            .striped(true)
            .num_columns(8)
            .show(scroll_ui, |grid_ui| {
                for text in [
                    "On",
                    "Direction",
                    "Match / regex",
                    "",
                    "Replace",
                    "Comment",
                    "Regex",
                    "",
                ] {
                    if text.is_empty() {
                        grid_ui.label("");
                    } else {
                        grid_ui.label(grey(text, 11.0));
                    }
                }
                grid_ui.end_row();

                let mut remove: Option<usize> = None;
                let mut swap: Option<(usize, usize)> = None;

                for (index, rule) in rules.iter_mut().enumerate() {
                    grid_ui.push_id(("mr_rule", index), |row_ui| {
                        row_ui
                            .checkbox(&mut rule.enabled, "")
                            .on_hover_text("Enable or disable this rule");

                        egui::ComboBox::from_id_salt(("mr_scope", index))
                            .width(145.0)
                            .selected_text(rule.scope.label())
                            .show_ui(row_ui, |combo_ui| {
                                for scope in MrScope::ALL {
                                    combo_ui.selectable_value(
                                        &mut rule.scope,
                                        scope,
                                        scope.label(),
                                    );
                                }
                            });

                        row_ui.add(
                            egui::TextEdit::singleline(&mut rule.match_)
                                .desired_width(200.0)
                                .hint_text("Regex / text to match")
                                .font(egui::TextStyle::Monospace),
                        );

                        row_ui.label(
                            egui::RichText::new("→").color(theme::c(theme::ORANGE)),
                        );

                        row_ui.add(
                            egui::TextEdit::singleline(&mut rule.replacement)
                                .desired_width(160.0)
                                .hint_text("Literal string to replace")
                                .font(egui::TextStyle::Monospace),
                        );

                        row_ui.add(
                            egui::TextEdit::singleline(&mut rule.comment)
                                .desired_width(160.0)
                                .hint_text("Comment")
                                .font(egui::TextStyle::Monospace),
                        );

                        row_ui.horizontal(|regex_ui| {
                            regex_ui
                                .checkbox(
                                    &mut rule.is_regex,
                                    egui::RichText::new("Regex").size(12.0),
                                )
                                .on_hover_text(
                                    "Select to use regular expression matching. \
                                     Deselect to make matches literal.",
                                );
                            if rule.is_regex
                                && !rule.match_.is_empty()
                                && !rule.pattern_is_valid()
                            {
                                regex_ui
                                    .label(
                                        egui::RichText::new("invalid regex")
                                            .size(12.0)
                                            .color(theme::c(theme::BAD)),
                                    );
                            }
                        });

                        row_ui.horizontal(|actions_ui| {
                            if actions_ui
                                .add_enabled(index > 0, egui::Button::new("↑"))
                                .on_hover_text("Move this rule up")
                                .clicked()
                            {
                                swap = Some((index, index - 1));
                            }
                            if actions_ui
                                .add_enabled(index + 1 < count, egui::Button::new("↓"))
                                .on_hover_text("Move this rule down")
                                .clicked()
                            {
                                swap = Some((index, index + 1));
                            }
                            if actions_ui
                                .button("Remove")
                                .on_hover_text("Delete this rule")
                                .clicked()
                            {
                                remove = Some(index);
                            }
                        });
                    });
                    grid_ui.end_row();
                }

                if let Some((from, to)) = swap {
                    if from < count && to < count {
                        rules.swap(from, to);
                    }
                }
                if let Some(index) = remove {
                    if index < count {
                        rules.remove(index);
                    }
                }
            });
    });

    ui.add_space(4.0);
    let add_label = if request_side { "+ request rule" } else { "+ response rule" };
    if ui.button(add_label).on_hover_text(
        "Add an enabled rule with an empty match, replacement, and comment.",
    ).clicked() {
        rules.push(MrRule::new(MrScope::default_for(request_side)));
    }
}

fn grey(text: impl Into<String>, size: f32) -> egui::RichText {
    egui::RichText::new(text)
        .size(size)
        .color(theme::c(theme::MONO6))
}

// Shared data table (M-02): sortable, filterable and virtualized, used by the
// Proxy, Target, Scanner, Intruder and Collaborator tabs.
//
// Rows are rendered lazily through `egui::ScrollArea::show_rows`, so a 10k-row
// history costs only the visible window.

use eframe::egui::{self, RichText, Ui};

use crate::theme::{self, c};

/// One column description.
pub struct Column {
    pub label: &'static str,
    pub width: f32,
    pub align_right: bool,
}

impl Column {
    pub fn new(label: &'static str, width: f32) -> Self {
        Self { label, width, align_right: false }
    }
    pub fn right(label: &'static str, width: f32) -> Self {
        Self { label, width, align_right: true }
    }
}

/// Per-table UI state (sort column/direction, filter text). Owned by the caller
/// so it survives frames.
#[derive(Clone)]
pub struct TableState {
    pub sort_col: usize,
    pub sort_asc: bool,
    pub filter: String,
    /// Per-column widths, overriding `Column::width` once the user has dragged a
    /// divider. Empty means "use the defaults".
    pub widths: Vec<f32>,
    /// Columns the user switched off in the column chooser.
    pub hidden: Vec<bool>,
    /// Whether the column chooser is expanded.
    pub chooser_open: bool,
}

impl Default for TableState {
    fn default() -> Self {
        Self {
            sort_col: usize::MAX,
            sort_asc: false,
            filter: String::new(),
            widths: Vec::new(),
            hidden: Vec::new(),
            chooser_open: false,
        }
    }
}

impl TableState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn width_of(&self, columns: &[Column], idx: usize) -> f32 {
        self.widths.get(idx).copied().unwrap_or_else(|| columns[idx].width)
    }

    pub fn is_visible(&self, idx: usize) -> bool {
        self.hidden.get(idx).copied().unwrap_or(true)
    }

    pub fn visible_indices(&self, columns: &[Column]) -> Vec<usize> {
        (0..columns.len()).filter(|&i| self.is_visible(i)).collect()
    }
}

/// Column chooser: a button that expands into one checkbox per column, like
/// Burp's table header menu. The open/closed state lives in `TableState` so it
/// survives frames, and the whole control is one horizontal row so it never
/// claims vertical space it does not use.
pub fn column_chooser(ui: &mut Ui, columns: &[Column], state: &mut TableState) {
    ui.horizontal(|ui| {
        let open = state.chooser_open;
        if ui.small_button(if open { "Hide columns" } else { "Columns" }).clicked() {
            state.chooser_open = !open;
        }
        if state.chooser_open {
            ui.add_space(6.0);
            ui.label(RichText::new("show:").size(12.0).color(theme::ink_hint()));
            for (i, col) in columns.iter().enumerate() {
                let mut on = state.is_visible(i);
                if ui.checkbox(&mut on, col.label).changed() {
                    // `hidden` stores visibility per column (true = shown).
                    if state.hidden.len() < columns.len() {
                        state.hidden.resize(columns.len(), true);
                    }
                    state.hidden[i] = on;
                }
            }
        }
    });
}

/// Sort rows by `col` (already filtered). Ascending/descending per `asc`.
pub fn sort_rows<R>(rows: &mut Vec<R>, state: &TableState, key: impl Fn(&R, usize) -> String) {
    if state.sort_col == usize::MAX || rows.len() < 2 {
        return;
    }
    rows.sort_by(|a, b| {
        let ka = key(a, state.sort_col);
        let kb = key(b, state.sort_col);
        let ord = ka.cmp(&kb);
        if state.sort_asc { ord } else { ord.reverse() }
    });
}

/// Filter rows by a case-insensitive substring over `text`.
pub fn filter_rows<R: Clone>(rows: &[R], state: &TableState, text: impl Fn(&R) -> String) -> Vec<R> {
    let needle = state.filter.trim().to_lowercase();
    if needle.is_empty() {
        return rows.to_vec();
    }
    rows.iter().filter(|r| text(r).to_lowercase().contains(&needle)).cloned().collect()
}

/// Table with a header, a filter box and a virtualized body.
pub fn data_table<R, F>(
    ui: &mut Ui,
    id: &str,
    columns: &[Column],
    rows: &[R],
    state: &mut TableState,
    row_height: f32,
    mut render: F,
) where
    F: FnMut(&R, &mut Ui),
{
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.filter)
                .desired_width(240.0)
                .hint_text("Filter...")
                .font(egui::TextStyle::Monospace),
        );
        if !state.filter.is_empty() && ui.small_button("Clear").clicked() {
            state.filter.clear();
        }
        ui.label(RichText::new(format!("{} rows", rows.len())).size(12.0).color(theme::ink_faint()));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            column_chooser(ui, columns, state);
        });
    });
    ui.add_space(theme::SPACE_XS);
    let body_height = (ui.available_height() - 4.0).max(60.0);
    table_body(ui, id, columns, rows, state, row_height, body_height, &mut render);
}

/// Draw only the header + virtualized body (no filter box). Callers that own
/// their filter UI use this.
pub fn table_body<R, F>(
    ui: &mut Ui,
    id: &str,
    columns: &[Column],
    rows: &[R],
    state: &mut TableState,
    row_height: f32,
    body_height: f32,
    render: &mut F,
) where
    F: FnMut(&R, &mut Ui),
{
    // Burp's tables scroll sideways when the columns are wider than the
    // view; the scroll area also stops a wide header from widening the parent.
    let view_w = ui.available_width();
    let total: f32 = state
        .visible_indices(columns)
        .iter()
        .map(|&i| state.width_of(columns, i) + DIVIDER)
        .sum();
    let content_w = total.max(view_w - 14.0);
    let outer_h = body_height.min(ui.available_height()) + row_height + 8.0;
    // Every widget id inside the table is scoped by the table id, so two
    // tables in one parent (Comparer's item lists) never collide.
    ui.push_id(("table_scope", id), |ui| {
        egui::ScrollArea::horizontal()
            .id_salt(("hscroll", id))
            .max_height(outer_h)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.set_width(content_w);
                // Header above body even when the caller's layout is horizontal.
                ui.vertical(|ui| {
                    table_body_inner(ui, id, columns, rows, state, row_height, body_height, render);
                });
            });
    });
}

fn table_body_inner<R, F>(
    ui: &mut Ui,
    id: &str,
    columns: &[Column],
    rows: &[R],
    state: &mut TableState,
    row_height: f32,
    body_height: f32,
    render: &mut F,
) where
    F: FnMut(&R, &mut Ui),
{
    // Header (Burp's JTable header): left-aligned labels, the sort arrow only on
    // the sorted column, 1px dividers you can drag, and a right-click menu that
    // switches columns on and off.
    let visible = state.visible_indices(columns);
    let header = egui::Frame::none()
        .fill(theme::header_bg())
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for i in visible {
                    let col = &columns[i];
                    let width = state.width_of(columns, i);
                    let label = if state.sort_col == i {
                        let arrow = if state.sort_asc { " \u{2191}" } else { " \u{2193}" };
                        format!("{}{arrow}", col.label)
                    } else {
                        col.label.to_string()
                    };
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(width, row_height), egui::Sense::click());
                    if resp.hovered() {
                        ui.painter().rect_filled(rect, 0.0, theme::line());
                    }
                    ui.painter().with_clip_rect(rect).text(
                        egui::pos2(rect.left() + 5.0, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        label,
                        egui::FontId::proportional(12.5),
                        theme::ink(),
                    );
                    if resp.clicked() {
                        if state.sort_col == i {
                            state.sort_asc = !state.sort_asc;
                        } else {
                            state.sort_col = i;
                            state.sort_asc = true;
                        }
                    }
                    // Divider: drag to resize.
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(DIVIDER, row_height), egui::Sense::hover());
                    let drag = ui.interact(rect.expand2(egui::vec2(2.0, 0.0)), ui.id().with(("resize", i)), egui::Sense::drag());
                    if drag.hovered() || drag.dragged() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeColumn);
                    }
                    if drag.dragged() {
                        let new_width = (width + drag.drag_delta().x).max(28.0);
                        if state.widths.len() < columns.len() {
                            state.widths.resize(columns.len(), 0.0);
                        }
                        for (j, slot) in state.widths.iter_mut().enumerate() {
                            if *slot == 0.0 {
                                *slot = columns[j].width;
                            }
                        }
                        state.widths[i] = new_width;
                    }
                    let active = drag.dragged() || drag.hovered();
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(egui::pos2(rect.center().x, rect.top() + 2.0), egui::vec2(1.0, (row_height - 4.0).max(1.0))),
                        egui::Rounding::ZERO,
                        if active { c(theme::ORANGE) } else { theme::line_strong() },
                    );
                }
            });
        })
        .response;
    header.interact(egui::Sense::click()).context_menu(|ui| {
        for (i, col) in columns.iter().enumerate() {
            let mut on = state.is_visible(i);
            if ui.checkbox(&mut on, col.label).changed() {
                if state.hidden.len() < columns.len() {
                    state.hidden.resize(columns.len(), true);
                }
                state.hidden[i] = on;
            }
        }
    });

    // `body_height` is what the caller could spare (it may have reserved room for
    // an action row); the pane's own remainder is the other bound.
    let pane_height = ui.available_height();
    // Virtualized with a manual window: `show_rows` positions the content in
    // layout space, which on this egui build put the rows outside the clip rect
    // (the header drew, the body did not). Windowing off the viewport is explicit
    // and keeps 10k-row tables at a fixed per-frame cost.
    egui::ScrollArea::vertical()
        .id_salt(("table", id))
        .auto_shrink([false, false])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
        .max_height(body_height.min(pane_height))
        .show_viewport(ui, |ui, viewport| {
            // Rows sit flush, like a Swing JTable.
            ui.spacing_mut().item_spacing.y = 0.0;
            let stride = row_height;
            ui.set_min_height(stride * rows.len() as f32);
            if rows.is_empty() {
                ui.add_space(8.0);
                ui.label(
                    RichText::new("no matching entries")
                        .size(12.0)
                        .color(theme::ink_faint()),
                );
                return;
            }
            // Virtualization: only the rows that intersect the viewport (plus one
            // row of slack at each end) are laid out. `viewport` is the visible
            // slice in content coordinates, so scrolling changes `first`/`last`
            // without changing the geometry of the content above the window.
            let first = (viewport.top() / stride).floor().max(0.0) as usize;
            let last = (((viewport.bottom() / stride).ceil() as usize) + 1).min(rows.len());
            if first > 0 {
                ui.add_space(stride * first as f32);
            }
            for i in first..last {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), row_height), egui::Sense::hover());
                let mut row_ui = ui.new_child(
                    egui::UiBuilder::new().max_rect(rect).layout(egui::Layout::left_to_right(egui::Align::Center)),
                );
                row_ui.set_clip_rect(rect.intersect(ui.clip_rect()));
                render(&rows[i], &mut row_ui);
            }
            if last < rows.len() {
                ui.add_space(stride * (rows.len() - last) as f32);
            }
        });
}

/// Width of the draggable divider after each header cell; body rows leave the
/// same gap so cells stay under their headers.
pub const DIVIDER: f32 = 3.0;

/// Render one fixed-width cell inside a row (elided with an ellipsis).
///
/// The height is passed in rather than read from `available_height()`: inside a
/// row's horizontal layout that value is the leftover of the row, which is zero
/// once a cell has been placed, and a zero-height label paints nothing.
pub fn cell(
    ui: &mut Ui,
    col: &Column,
    text: impl Into<String>,
    color: Option<eframe::egui::Color32>,
    row_height: f32,
) {
    cell_w(ui, col, col.width, text, color, row_height)
}

/// `cell` at an explicit width (the user may have resized the column).
pub fn cell_w(
    ui: &mut Ui,
    col: &Column,
    width: f32,
    text: impl Into<String>,
    color: Option<eframe::egui::Color32>,
    row_height: f32,
) {
    let rich = RichText::new(text.into())
        .size(12.5)
        .color(color.unwrap_or_else(|| theme::ink_dim()));
    let label = egui::Label::new(rich).truncate();
    let rect = ui
        .allocate_exact_size(egui::vec2(width, row_height), egui::Sense::hover())
        .0
        .shrink2(egui::vec2(5.0, 0.0));
    let layout = if col.align_right {
        egui::Layout::right_to_left(egui::Align::Center)
    } else {
        egui::Layout::left_to_right(egui::Align::Center)
    };
    let mut inner = ui.new_child(egui::UiBuilder::new().max_rect(rect).layout(layout));
    inner.add(label);
}

/// Draw one row of cells, skipping hidden columns. Callers keep their column
/// indices; only the visible ones are rendered.
pub fn cells(
    ui: &mut Ui,
    columns: &[Column],
    state: &TableState,
    row_height: f32,
    cells: &[(usize, String, Option<eframe::egui::Color32>)],
) {
    ui.spacing_mut().item_spacing.x = 0.0;
    for (idx, text, colour) in cells {
        if !state.is_visible(*idx) {
            continue;
        }
        cell_w(ui, &columns[*idx], state.width_of(columns, *idx), text.clone(), *colour, row_height);
        ui.add_space(DIVIDER);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<(u64, String, String)> {
        vec![
            (3, "GET".into(), "/c".into()),
            (1, "POST".into(), "/a".into()),
            (2, "GET".into(), "/b".into()),
        ]
    }

    #[test]
    fn sort_rows_by_column_asc_and_desc() {
        let mut data = rows();
        let mut state = TableState::new();
        state.sort_col = 0;
        state.sort_asc = true;
        sort_rows(&mut data, &state, |r, _| format!("{:020}", r.0));
        assert_eq!(data.iter().map(|r| r.0).collect::<Vec<_>>(), vec![1, 2, 3]);
        state.sort_asc = false;
        sort_rows(&mut data, &state, |r, _| format!("{:020}", r.0));
        assert_eq!(data.iter().map(|r| r.0).collect::<Vec<_>>(), vec![3, 2, 1]);
    }

    #[test]
    fn sort_rows_by_method_then_path() {
        let mut data = rows();
        let mut state = TableState::new();
        state.sort_col = 1;
        state.sort_asc = true;
        sort_rows(&mut data, &state, |r, _| r.1.clone());
        assert_eq!(data[0].1, "GET");
        assert_eq!(data[2].1, "POST");
    }

    #[test]
    fn unsorted_state_keeps_input_order() {
        let mut data = rows();
        let state = TableState::new();
        sort_rows(&mut data, &state, |r, _| r.2.clone());
        assert_eq!(data.iter().map(|r| r.0).collect::<Vec<_>>(), vec![3, 1, 2]);
    }

    #[test]
    fn filter_rows_is_case_insensitive() {
        let data = rows();
        let mut state = TableState::new();
        state.filter = "get".into();
        let filtered = filter_rows(&data, &state, |r| format!("{} {}", r.1, r.2));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.1 == "GET"));
        state.filter = "  /a ".into();
        let filtered = filter_rows(&data, &state, |r| format!("{} {}", r.1, r.2));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, 1);
    }

    #[test]
    fn empty_filter_returns_every_row() {
        let data = rows();
        let state = TableState::new();
        assert_eq!(filter_rows(&data, &state, |r| r.2.clone()).len(), data.len());
    }
}

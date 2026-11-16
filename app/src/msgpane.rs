// Burp's HTTP message pane and Inspector, as drawn by build 52685 in the
// Proxy history, Logger and Repeater (live reference window, 2026-11-16):
//
//   Request                                      [layout buttons]
//   Pretty   Raw   Hex   (Render on responses)        [\n] [menu]
//   1 GET / HTTP/1.1                       <- httpFirstLine
//   2 Host: example.com                    <- headerName / headerValue
//   ...
//   (?) (gear) (<) (>) [Search..................] 0 highlights
//
// Colours come from ui.editor.message.* in burp/theme/LightTheme.json and
// DarkTheme.json via theme::editor_colours(). Search matches are painted with
// editor.message.highlight.search and counted in the "N highlights" label.

use eframe::egui::{self, text::LayoutJob, Color32, FontId, RichText, TextFormat, Ui};

use crate::theme::{self, c};
use crate::util;

/// Most lines a pane lays out per frame; the rest is summarised.
const MAX_LINES: usize = 4000;

#[derive(Clone, Debug)]
pub struct PaneState {
    /// 0 Pretty, 1 Raw, 2 Hex, 3 Render (responses only).
    pub view: usize,
    pub search: String,
    pub wrap: bool,
    /// Show non-printable characters (Burp's "\n" toggle).
    pub show_np: bool,
    /// Current search match (the < > buttons step through the highlights).
    pub cur: usize,
    /// Scroll the current match into view on the next frame.
    pub jump: bool,
    /// Search options (gear): case sensitive.
    pub case_sensitive: bool,
    /// Last text selection in an editable pane, as char indices.
    pub sel: Option<(usize, usize)>,
}

impl Default for PaneState {
    fn default() -> Self {
        Self { view: 0, search: String::new(), wrap: true, show_np: false, cur: 0, jump: false, case_sensitive: false, sel: None }
    }
}

/// Burp's tab strip: plain labels, the selected one underlined in orange[1].
pub fn underline_tabs(ui: &mut Ui, labels: &[&str], current: usize, size: f32) -> Option<usize> {
    let mut picked = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for (i, label) in labels.iter().enumerate() {
            let sel = i == current;
            let galley = ui.painter().layout_no_wrap(
                label.to_string(),
                FontId::proportional(size),
                if sel { theme::ink() } else { theme::ink_dim() },
            );
            let w = galley.size().x + 30.0;
            let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, size + 16.0), egui::Sense::click());
            if resp.hovered() && !sel {
                ui.painter().rect_filled(rect, 0.0, theme::zebra());
            }
            let pos = egui::pos2(rect.left() + 15.0, rect.center().y - galley.size().y / 2.0);
            ui.painter().galley(pos, galley, theme::ink());
            if sel {
                let y = rect.bottom() - 1.5;
                ui.painter().line_segment(
                    [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                    egui::Stroke::new(3.0, c(theme::ORANGE_1)),
                );
            }
            if resp.clicked() {
                picked = Some(i);
            }
        }
    });
    picked
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineKind {
    First,
    Header,
    Body,
}

/// Pretty view body: indented JSON when the body parses as JSON, otherwise the
/// raw body. Burp's Pretty tab reformats JSON/XML/HTML; JSON is the common case.
pub fn pretty_body(body: &str) -> String {
    let t = body.trim();
    if (t.starts_with('{') || t.starts_with('[')) && t.len() < 2_000_000 {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if let Ok(s) = serde_json::to_string_pretty(&v) {
                return s;
            }
        }
    }
    body.to_string()
}

/// Lines of a message for the text views, each tagged with its syntax role.
pub fn message_lines(bytes: &[u8], pretty: bool) -> Vec<(LineKind, String)> {
    let text = String::from_utf8_lossy(bytes);
    let (head, body, has_body) = if let Some(i) = text.find("\r\n\r\n") {
        (&text[..i], &text[i + 4..], true)
    } else if let Some(i) = text.find("\n\n") {
        (&text[..i], &text[i + 2..], true)
    } else {
        (&text[..], "", false)
    };
    let mut out = Vec::new();
    for (i, l) in head.split('\n').enumerate() {
        let l = l.trim_end_matches('\r').to_string();
        out.push((if i == 0 { LineKind::First } else { LineKind::Header }, l));
    }
    if has_body {
        out.push((LineKind::Body, String::new()));
        let b = if pretty { pretty_body(body) } else { body.to_string() };
        for l in b.split('\n') {
            out.push((LineKind::Body, l.trim_end_matches('\r').to_string()));
        }
    }
    out
}

/// Byte ranges of case-insensitive matches of `needle` in `hay` (ASCII folding,
/// so ranges stay on char boundaries).
pub fn match_ranges(hay: &str, needle: &str) -> Vec<(usize, usize)> {
    match_ranges_cs(hay, needle, false)
}

/// `match_ranges` with an explicit case-sensitivity switch.
pub fn match_ranges_cs(hay: &str, needle: &str, case_sensitive: bool) -> Vec<(usize, usize)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let (h, n) = if case_sensitive {
        (hay.to_string(), needle.to_string())
    } else {
        (hay.to_ascii_lowercase(), needle.to_ascii_lowercase())
    };
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = h[from..].find(&n) {
        let s = from + i;
        out.push((s, s + n.len()));
        from = s + n.len().max(1);
        if from >= h.len() {
            break;
        }
    }
    out
}

fn line_job(kind: LineKind, line: &str, font: &FontId, search: &str, wrap_w: Option<f32>, cs: bool) -> LayoutJob {
    let ec = theme::editor_colours();
    // Colour spans as (start, end, colour).
    let mut spans: Vec<(usize, usize, Color32)> = Vec::new();
    match kind {
        LineKind::First => spans.push((0, line.len(), ec.first_line)),
        LineKind::Header => match line.find(':') {
            Some(i) => {
                spans.push((0, i, ec.header_name));
                spans.push((i, line.len(), ec.header_value));
            }
            None => spans.push((0, line.len(), ec.header_value)),
        },
        LineKind::Body => spans.push((0, line.len(), ec.text)),
    }
    let hits = match_ranges_cs(line, search, cs);
    let mut cuts: Vec<usize> = vec![0, line.len()];
    for (s, e, _) in &spans {
        cuts.push(*s);
        cuts.push(*e);
    }
    for (s, e) in &hits {
        cuts.push(*s);
        cuts.push(*e);
    }
    cuts.sort_unstable();
    cuts.dedup();
    let mut job = LayoutJob::default();
    if let Some(w) = wrap_w {
        job.wrap.max_width = w;
    }
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        if a >= b || !line.is_char_boundary(a) || !line.is_char_boundary(b) {
            continue;
        }
        let colour = spans.iter().find(|(s, e, _)| a >= *s && a < *e).map(|x| x.2).unwrap_or(ec.text);
        let hit = hits.iter().any(|(s, e)| a >= *s && a < *e);
        let mut fmt = TextFormat::simple(font.clone(), colour);
        if hit {
            fmt.background = ec.search_highlight;
            if theme::appearance().0 == theme::Palette::Light {
                fmt.color = Color32::BLACK;
            }
        }
        job.append(&line[a..b], 0.0, fmt);
    }
    if line.is_empty() {
        job.append(" ", 0.0, TextFormat::simple(font.clone(), ec.text));
    }
    job
}

/// A line holding Intruder payload markers: the markers and the text between
/// each pair are painted with Burp's payload-position highlight.
fn marker_line_job(kind: LineKind, line: &str, font: &FontId) -> LayoutJob {
    let ec = theme::editor_colours();
    let base = match kind {
        LineKind::First => ec.first_line,
        LineKind::Header => ec.header_value,
        LineKind::Body => ec.text,
    };
    let hl = if theme::appearance().0 == theme::Palette::Light { c(0xFFD9C7) } else { c(0x6B3A22) };
    let mut job = LayoutJob::default();
    let mut inside = false;
    let mut buf = String::new();
    let flush = |job: &mut LayoutJob, buf: &mut String, inside: bool| {
        if buf.is_empty() {
            return;
        }
        let mut f = TextFormat::simple(font.clone(), if inside { theme::ink() } else { base });
        if inside {
            f.background = hl;
        }
        job.append(buf, 0.0, f);
        buf.clear();
    };
    for ch in line.chars() {
        if ch == '\u{00A7}' {
            flush(&mut job, &mut buf, inside);
            let mut f = TextFormat::simple(font.clone(), c(theme::ORANGE_1));
            f.background = hl;
            job.append("\u{00A7}", 0.0, f);
            inside = !inside;
        } else {
            buf.push(ch);
        }
    }
    flush(&mut job, &mut buf, inside);
    if line.is_empty() {
        job.append(" ", 0.0, TextFormat::simple(font.clone(), base));
    }
    job
}

/// Render tab: the visible text of an HTML response (html2text crate).
pub fn render_text(body: &str) -> String {
    html2text::from_read(body.as_bytes(), 100)
}

/// One message pane. `height` is the full height including title and search row.
pub fn message_pane(
    ui: &mut Ui,
    id: &str,
    title: &str,
    bytes: Option<&[u8]>,
    st: &mut PaneState,
    response: bool,
    height: f32,
) {
    let width = ui.available_width();
    ui.allocate_ui_with_layout(egui::vec2(width, height), egui::Layout::top_down(egui::Align::Min), |ui| {
        ui.set_min_size(egui::vec2(width, height));
        ui.set_max_width(width);
        ui.horizontal(|ui| {
            ui.set_height(26.0);
            ui.add_space(14.0);
            ui.label(RichText::new(title).strong().size(14.0).color(theme::ink()));
        });
        let labels: &[&str] = if response { &["Pretty", "Raw", "Hex", "Render"] } else { &["Pretty", "Raw", "Hex"] };
        if st.view >= labels.len() {
            st.view = 0;
        }
        let tabs_rect = ui
            .horizontal(|ui| {
                if let Some(v) = underline_tabs(ui, labels, st.view, 13.0) {
                    st.view = v;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    ui.toggle_value(&mut st.show_np, RichText::new("\\n").size(12.0))
                        .on_hover_text("Show non-printable characters");
                    ui.toggle_value(&mut st.wrap, RichText::new("wrap").size(11.0))
                        .on_hover_text("Wrap lines");
                });
            })
            .response
            .rect;
        ui.painter().hline(
            tabs_rect.x_range(),
            tabs_rect.bottom() + 1.0,
            egui::Stroke::new(1.0, theme::line()),
        );
        ui.add_space(3.0);

        let search_h = 30.0;
        let body_h = (ui.available_height() - search_h).max(40.0);
        let font = FontId::monospace(theme::FONT_MONO);
        let mut highlights = 0usize;
        let Some(bytes) = bytes else {
            ui.allocate_ui(egui::vec2(width, body_h), |ui| {
                ui.set_min_height(body_h);
            });
            search_row(ui, id, st, 0);
            return;
        };
        egui::ScrollArea::both()
            .id_salt(id)
            .max_height(body_h)
            .min_scrolled_height(body_h)
            .auto_shrink([false, false])
            .show(ui, |ui| match st.view {
                2 => {
                    let hex = util::hex_view(bytes, 65536);
                    highlights = match_ranges(&hex, &st.search).len();
                    ui.label(RichText::new(hex).font(font.clone()).color(theme::editor_colours().text));
                }
                3 => {
                    let text = String::from_utf8_lossy(bytes);
                    let body = text.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
                    let shown = render_text(body);
                    highlights = match_ranges(&shown, &st.search).len();
                    ui.add(egui::Label::new(RichText::new(shown).size(13.0).color(theme::ink_dim())).wrap());
                }
                v => {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let lines = message_lines(bytes, v == 0);
                    let ec = theme::editor_colours();
                    let gutter = 12.0 + 8.0 * (lines.len().max(1).to_string().len() as f32);
                    let text_w = (ui.available_width() - gutter - 8.0).max(80.0);
                    for (n, (kind, line)) in lines.iter().take(MAX_LINES).enumerate() {
                        let shown: std::borrow::Cow<str> = if st.show_np {
                            std::borrow::Cow::Owned(format!("{line}\\r\\n"))
                        } else {
                            std::borrow::Cow::Borrowed(line.as_str())
                        };
                        let here = match_ranges_cs(&shown, &st.search, st.case_sensitive).len();
                        let has_cur = here > 0 && st.cur >= highlights && st.cur < highlights + here;
                        highlights += here;
                        let job = line_job(*kind, &shown, &font, &st.search, st.wrap.then_some(text_w), st.case_sensitive);
                        let galley = ui.painter().layout_job(job);
                        let row_h = galley.size().y.max(14.0) + 1.0;
                        let (rect, _) = ui.allocate_exact_size(
                            egui::vec2(gutter + 6.0 + galley.size().x.max(text_w), row_h),
                            egui::Sense::hover(),
                        );
                        let num = ui.painter().layout_no_wrap(
                            (n + 1).to_string(),
                            FontId::monospace(theme::FONT_MONO - 1.0),
                            ec.line_numbers,
                        );
                        ui.painter().galley(
                            egui::pos2(rect.left() + gutter - num.size().x - 4.0, rect.top() + 1.0),
                            num,
                            ec.line_numbers,
                        );
                        if has_cur {
                            // Burp marks the current match's line.
                            ui.painter().rect_filled(
                                egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())),
                                0.0,
                                c(theme::ORANGE),
                            );
                            if st.jump {
                                ui.scroll_to_rect(rect, Some(egui::Align::Center));
                                st.jump = false;
                            }
                        }
                        ui.painter().galley(egui::pos2(rect.left() + gutter + 6.0, rect.top()), galley, ec.text);
                    }
                    if lines.len() > MAX_LINES {
                        ui.label(
                            RichText::new(format!("\u{2026} {} more lines", lines.len() - MAX_LINES))
                                .size(12.0)
                                .color(theme::ink_hint()),
                        );
                    }
                    let gx = ui.min_rect().left() + gutter + 1.0;
                    ui.painter().vline(gx, ui.min_rect().y_range(), egui::Stroke::new(1.0, ec.gutter_border));
                }
            });
        search_row(ui, id, st, highlights);
    });
}

fn search_row(ui: &mut Ui, id: &str, st: &mut PaneState, highlights: usize) {
    let r = ui
        .horizontal(|ui| {
            ui.set_height(28.0);
            ui.add_space(6.0);
            let small = |g: &str| egui::Button::new(RichText::new(g).size(13.0)).min_size(egui::vec2(22.0, 22.0));
            let _ = ui.add(small("?")).on_hover_text(
                "Type to highlight matches in this message. Use the arrows to step through them; the gear sets search options.",
            );
            ui.add_space(2.0);
            ui.menu_button(RichText::new(crate::theme::icon::GEAR).size(13.0), |ui| {
                ui.checkbox(&mut st.case_sensitive, "Case sensitive");
            });
            ui.add_space(2.0);
            if ui.add_enabled(highlights > 0, small("\u{2190}")).on_hover_text("Previous match").clicked() {
                st.cur = if st.cur == 0 { highlights - 1 } else { st.cur - 1 };
                st.jump = true;
            }
            ui.add_space(2.0);
            if ui.add_enabled(highlights > 0, small("\u{2192}")).on_hover_text("Next match").clicked() {
                st.cur = (st.cur + 1) % highlights.max(1);
                st.jump = true;
            }
            ui.add_space(6.0);
            let w = (ui.available_width() - 110.0).max(80.0);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut st.search)
                    .id_salt((id, "search"))
                    .hint_text("Search")
                    .desired_width(w),
            );
            if resp.changed() {
                st.cur = 0;
                st.jump = true;
            }
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && highlights > 0 {
                st.cur = (st.cur + 1) % highlights;
                st.jump = true;
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("{highlights} highlight{}", if highlights == 1 { "" } else { "s" }))
                    .size(12.0)
                    .color(theme::ink_dim()),
            );
        })
        .response
        .rect;
    if st.cur >= highlights.max(1) {
        st.cur = 0;
    }
    ui.painter().rect_filled(
        egui::Rect::from_min_size(egui::pos2(r.left(), r.top() - 2.0), egui::vec2(r.width(), 1.0)),
        0.0,
        theme::line(),
    );
}

/// Burp's editable request pane (Repeater, Intruder): the same title, tabs and
/// search row as `message_pane`, with an editable, syntax-coloured body and a
/// line-number gutter. Returns true when the text changed.
pub fn editable_pane(ui: &mut Ui, id: &str, title: &str, text: &mut String, st: &mut PaneState, height: f32) -> bool {
    let width = ui.available_width();
    let mut changed = false;
    ui.allocate_ui_with_layout(egui::vec2(width, height), egui::Layout::top_down(egui::Align::Min), |ui| {
        ui.set_min_size(egui::vec2(width, height));
        ui.set_max_width(width);
        if title.is_empty() {
            // Intruder's positions editor: no title and no view tabs.
            st.view = 1;
        } else {
            ui.horizontal(|ui| {
                ui.set_height(26.0);
                ui.add_space(14.0);
                ui.label(RichText::new(title).strong().size(14.0).color(theme::ink()));
            });
            let labels: &[&str] = &["Pretty", "Raw", "Hex"];
            if st.view >= labels.len() {
                st.view = 1;
            }
            let tabs_rect = ui
                .horizontal(|ui| {
                    if let Some(v) = underline_tabs(ui, labels, st.view, 13.0) {
                        st.view = v;
                    }
                })
                .response
                .rect;
            ui.painter().hline(tabs_rect.x_range(), tabs_rect.bottom() + 1.0, egui::Stroke::new(1.0, theme::line()));
        }
        ui.add_space(3.0);
        let search_h = 30.0;
        let body_h = (ui.available_height() - search_h).max(40.0);
        let font = FontId::monospace(theme::FONT_MONO);
        let highlights = match_ranges_cs(text, &st.search, st.case_sensitive).len();
        egui::ScrollArea::both()
            .id_salt((id, "edit"))
            .max_height(body_h)
            .min_scrolled_height(body_h)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if st.view == 2 {
                    ui.label(RichText::new(util::hex_view(text.as_bytes(), 65536)).font(font.clone()).color(theme::editor_colours().text));
                    return;
                }
                let ec = theme::editor_colours();
                let lines = text.split('\n').count().max(1);
                let gutter = 12.0 + 8.0 * (lines.to_string().len() as f32);
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    let (g, _) = ui.allocate_exact_size(egui::vec2(gutter + 6.0, body_h.max(20.0)), egui::Sense::hover());
                    let search = st.search.clone();
                    let cs = st.case_sensitive;
                    let font2 = font.clone();
                    let mut layouter = move |ui: &egui::Ui, s: &dyn egui::TextBuffer, _wrap: f32| {
                        let mut job = LayoutJob::default();
                        let mut in_body = false;
                        for (i, line) in s.as_str().split('\n').enumerate() {
                            let l = line.trim_end_matches('\r');
                            let kind = if i == 0 {
                                LineKind::First
                            } else if in_body {
                                LineKind::Body
                            } else if l.is_empty() {
                                in_body = true;
                                LineKind::Body
                            } else {
                                LineKind::Header
                            };
                            let mut lj = if line.contains('\u{00A7}') {
                                marker_line_job(kind, line, &font2)
                            } else {
                                line_job(kind, line, &font2, &search, None, cs)
                            };
                            if i > 0 {
                                job.append("\n", 0.0, TextFormat::simple(font2.clone(), ec.text));
                            }
                            job.sections.extend(lj.sections.drain(..).map(|mut sec| {
                                let off = job.text.len();
                                sec.byte_range = (sec.byte_range.start + off)..(sec.byte_range.end + off);
                                sec
                            }));
                            job.text.push_str(&lj.text);
                        }
                        ui.painter().layout_job(job)
                    };
                    let out = egui::TextEdit::multiline(text)
                        .id_salt((id, "text"))
                        .font(font.clone())
                        .code_editor()
                        .frame(egui::Frame::default())
                        .desired_width(f32::INFINITY.min(4000.0))
                        .desired_rows(((body_h / 16.0) as usize).max(4))
                        .layouter(&mut layouter)
                        .show(ui);
                    if out.response.changed() {
                        changed = true;
                    }
                    if out.response.has_focus() {
                        if let Some(cr) = out.cursor_range {
                            let [a, b] = cr.sorted_cursors();
                            st.sel = Some((a.index.into(), b.index.into()));
                        }
                    }
                    // Line numbers: one per logical line, at the row it starts on.
                    let mut n = 1;
                    let mut new_line = true;
                    for row in &out.galley.rows {
                        if new_line {
                            let y = out.galley_pos.y + row.pos.y;
                            ui.painter().text(
                                egui::pos2(g.left() + gutter - 2.0, y + 1.0),
                                egui::Align2::RIGHT_TOP,
                                n.to_string(),
                                FontId::monospace(theme::FONT_MONO - 1.0),
                                ec.line_numbers,
                            );
                            n += 1;
                        }
                        new_line = row.ends_with_newline;
                    }
                    ui.painter().vline(g.left() + gutter + 2.0, g.y_range(), egui::Stroke::new(1.0, ec.gutter_border));
                });
            });
        search_row(ui, id, st, highlights);
    });
    changed
}

/// Inspector state: which sections are expanded.
#[derive(Clone, Debug, Default)]
pub struct InspectorState {
    pub open: [bool; 8],
}

fn query_params(path: &str) -> Vec<(String, String)> {
    path.split_once('?')
        .map(|(_, q)| q.split('&').filter(|s| !s.is_empty()).map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (util::url_decode(k), util::url_decode(v))
        }).collect())
        .unwrap_or_default()
}

fn cookies(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';').map(|p| {
            let p = p.trim();
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.to_string(), v.to_string())
        }).collect::<Vec<_>>())
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// The Inspector sections Burp lists for a request/response pair, with counts.
/// Sections with nothing to show are omitted, as in Burp.
pub fn inspector_sections(req: &[u8], resp: Option<&[u8]>) -> Vec<(&'static str, Vec<(String, String)>)> {
    let rp = util::parse_http(req);
    let mut out = Vec::new();
    // Live 52685: "Request attributes 2" = Method and Path; the protocol is a
    // separate HTTP/1 | HTTP/2 toggle above the Name/Value table.
    out.push((
        "Request attributes",
        vec![("Method".to_string(), rp.method.clone()), ("Path".to_string(), rp.path.split('?').next().unwrap_or("").to_string())],
    ));
    let q = query_params(&rp.path);
    if !q.is_empty() {
        out.push(("Request query parameters", q));
    }
    let body = &req[rp.head_len.min(req.len())..];
    let ct = rp.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|x| x.1.to_ascii_lowercase()).unwrap_or_default();
    if !body.is_empty() && ct.contains("x-www-form-urlencoded") {
        let b = String::from_utf8_lossy(body);
        let p = query_params(&format!("?{b}"));
        if !p.is_empty() {
            out.push(("Request body parameters", p));
        }
    }
    let ck = cookies(&rp.headers);
    if !ck.is_empty() {
        out.push(("Request cookies", ck));
    }
    out.push(("Request headers", rp.headers.clone()));
    if let Some(r) = resp {
        let sp = util::parse_http(r);
        out.push(("Response headers", sp.headers));
    }
    out
}

/// Burp's Inspector panel: title row and one collapsible row per section with a
/// count lozenge.
pub fn inspector(ui: &mut Ui, id: &str, req: Option<&[u8]>, resp: Option<&[u8]>, st: &mut InspectorState) {
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.label(RichText::new("Inspector").strong().size(15.0).color(theme::ink()));
    });
    ui.add_space(6.0);
    let Some(req) = req else {
        ui.label(RichText::new("Select a message to inspect it.").size(12.0).color(theme::ink_hint()));
        return;
    };
    let ec = theme::editor_colours();
    egui::ScrollArea::vertical().id_salt(id).auto_shrink([false, false]).show(ui, |ui| {
        for (i, (name, rows)) in inspector_sections(req, resp).into_iter().enumerate() {
            let i = i.min(st.open.len() - 1);
            let (rect, resp_) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), egui::Sense::click());
            if resp_.hovered() {
                ui.painter().rect_filled(rect, 0.0, theme::zebra());
            }
            ui.painter().hline(rect.x_range(), rect.bottom(), egui::Stroke::new(1.0, theme::line()));
            ui.painter().text(
                egui::pos2(rect.left() + 10.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                name,
                FontId::proportional(13.0),
                theme::ink_dim(),
            );
            let count = rows.len().to_string();
            let lz = egui::Rect::from_center_size(egui::pos2(rect.right() - 50.0, rect.center().y), egui::vec2(24.0, 18.0));
            ui.painter().rect_filled(lz, 9.0, theme::header_bg());
            ui.painter().text(lz.center(), egui::Align2::CENTER_CENTER, count, FontId::proportional(12.0), theme::ink_dim());
            ui.painter().text(
                egui::pos2(rect.right() - 18.0, rect.center().y),
                egui::Align2::CENTER_CENTER,
                if st.open[i] { "\u{25B4}" } else { "\u{25BE}" },
                FontId::proportional(13.0),
                theme::ink_dim(),
            );
            if resp_.clicked() {
                st.open[i] = !st.open[i];
            }
            if st.open[i] {
                if name == "Request attributes" {
                    let h2 = req.windows(8).take(64).any(|w| w == b"HTTP/2\r\n" || w == b"HTTP/2.0") ;
                    ui.horizontal(|ui| {
                        ui.add_space(10.0);
                        ui.label(RichText::new("Protocol").size(12.5).color(theme::ink_dim()));
                        ui.add_space(12.0);
                        let _ = ui.selectable_label(!h2, "HTTP/1");
                        let _ = ui.selectable_label(h2, "HTTP/2");
                    });
                    ui.add_space(6.0);
                }
                let full = ui.available_width() - 20.0;
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.set_width(full);
                        let (hr, _) = ui.allocate_exact_size(egui::vec2(full, 22.0), egui::Sense::hover());
                        ui.painter().rect_filled(hr, 0.0, theme::header_bg());
                        let half = full * 0.5;
                        ui.painter().text(egui::pos2(hr.left() + 4.0, hr.center().y), egui::Align2::LEFT_CENTER, "Name", FontId::proportional(12.5), theme::ink());
                        ui.painter().text(egui::pos2(hr.left() + half + 4.0, hr.center().y), egui::Align2::LEFT_CENTER, "Value", FontId::proportional(12.5), theme::ink());
                        for (k, v) in rows {
                            let (rr, _) = ui.allocate_exact_size(egui::vec2(full, 22.0), egui::Sense::hover());
                            ui.painter().text(egui::pos2(rr.left() + 4.0, rr.center().y), egui::Align2::LEFT_CENTER, k, FontId::proportional(12.5), ec.header_name);
                            let clip = ui.painter().with_clip_rect(egui::Rect::from_min_max(egui::pos2(rr.left() + half, rr.top()), egui::pos2(rr.right() - 16.0, rr.bottom())));
                            clip.text(egui::pos2(rr.left() + half + 4.0, rr.center().y), egui::Align2::LEFT_CENTER, v, FontId::proportional(12.5), ec.header_value);
                            ui.painter().text(egui::pos2(rr.right() - 8.0, rr.center().y), egui::Align2::CENTER_CENTER, "\u{203A}", FontId::proportional(14.0), theme::ink_dim());
                        }
                    });
                });
                ui.add_space(8.0);
            }
        }
    });
}

/// The narrow right-hand dock with vertical "Inspector" / "Notes" labels.
pub fn side_dock(ui: &mut Ui, active: usize) -> Option<usize> {
    let mut picked = None;
    let w = ui.available_width();
    for (i, label) in ["Inspector", "Notes"].iter().enumerate() {
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 120.0), egui::Sense::click());
        if i == active {
            ui.painter().rect_filled(rect, 0.0, c(0xCADAF0).linear_multiply(if theme::appearance().0 == theme::Palette::Light { 1.0 } else { 0.25 }));
        }
        let galley = ui.painter().layout_no_wrap(label.to_string(), FontId::proportional(12.5), theme::ink_dim());
        let pos = egui::pos2(rect.center().x + galley.size().y / 2.0, rect.top() + 14.0);
        ui.painter().add(egui::epaint::TextShape::new(pos, galley, theme::ink_dim()).with_angle(std::f32::consts::FRAC_PI_2));
        ui.painter().hline(rect.x_range(), rect.bottom(), egui::Stroke::new(1.0, theme::line()));
        if resp.clicked() {
            picked = Some(i);
        }
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_tagged_first_header_body() {
        let l = message_lines(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n{\"a\":1}", true);
        assert_eq!(l[0], (LineKind::First, "GET / HTTP/1.1".into()));
        assert_eq!(l[1], (LineKind::Header, "Host: a".into()));
        assert_eq!(l[2], (LineKind::Body, String::new()));
        // Pretty view indents JSON.
        assert_eq!(l[3].1, "{");
        assert!(l[4].1.contains("\"a\": 1"));
        let raw = message_lines(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n{\"a\":1}", false);
        assert_eq!(raw.last().unwrap().1, "{\"a\":1}");
    }

    #[test]
    fn search_ranges_are_case_insensitive() {
        assert_eq!(match_ranges("Host: HOST host", "host"), vec![(0, 4), (6, 10), (11, 15)]);
        assert!(match_ranges("abc", "").is_empty());
    }

    #[test]
    fn inspector_counts_match_the_message() {
        let req = b"GET /a?x=1&y=2 HTTP/1.1\r\nHost: h\r\nCookie: s=1; t=2\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\nbody";
        let s = inspector_sections(req, Some(resp));
        let names: Vec<_> = s.iter().map(|x| (x.0, x.1.len())).collect();
        assert_eq!(
            names,
            vec![
                ("Request attributes", 2),
                ("Request query parameters", 2),
                ("Request cookies", 2),
                ("Request headers", 2),
                ("Response headers", 3),
            ]
        );
    }

    #[test]
    fn render_drops_tags_and_scripts() {
        let r = render_text("<html><body><h1>Hi</h1><p>there</p></body></html>");
        assert!(r.contains("Hi") && r.contains("there") && !r.contains("<p>"), "{r}");
    }
}

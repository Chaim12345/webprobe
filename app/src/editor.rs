// Shared HTTP message editor and read-only viewer (M-03, B-02).
//
// One place owns the monospace look, the wrap/search controls and the
// header-vs-body tinting, so Proxy, Repeater, Intruder, Sequencer and Decoder
// all behave the same. The viewer renders the head line by line (bounded) and
// the body as one block, so multi-megabyte bodies stay cheap.
//
// B-02 adds what Burp's message editor shows: line numbers, a font-size
// control, a hex view, and syntax colouring for the request/status line,
// header names and JSON/XML bodies.

use eframe::egui::{self, RichText, Ui};

use crate::theme::{self, c};

/// Per-editor UI state. Owned by the caller so it survives frames.
#[derive(Clone)]
pub struct EditorState {
    /// Soft-wrap long lines.
    pub wrap: bool,
    /// Search text (highlighted count in views, plain filter aid in editors).
    pub search: String,
    /// Show a line-number gutter.
    pub line_numbers: bool,
    /// Message font size in points (Burp's `display.http_message_display`).
    pub font_size: f32,
    /// Hex view instead of text.
    pub hex: bool,
}

impl Default for EditorState {
    fn default() -> Self {
        Self {
            wrap: true,
            search: String::new(),
            line_numbers: true,
            // UserDefaults.json display.http_message_display = 13.
            font_size: 13.0,
            hex: false,
        }
    }
}

/// Number of case-insensitive occurrences of `needle` in `haystack`.
pub fn match_count(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let hay = haystack.to_lowercase();
    let nee = needle.to_lowercase();
    hay.match_indices(&nee).count()
}

/// Split a raw HTTP message into head (request/status line + headers) and body.
/// Accepts CRLF and bare LF line endings.
pub fn split_message(text: &str) -> (&str, &str) {
    if let Some(i) = text.find("\r\n\r\n") {
        (&text[..i], &text[i + 4..])
    } else if let Some(i) = text.find("\n\n") {
        (&text[..i], &text[i + 2..])
    } else {
        (text, "")
    }
}

/// Lowercase hex, no separators: the form the hex editor round-trips.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse hex text back to bytes. Whitespace, `0x` prefixes and the separators a
/// pasted dump carries (commas, colons, dashes) are ignored; an odd number of
/// digits is an error because it cannot be a whole number of bytes.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let lowered = text.to_lowercase();
    let mut digits = String::with_capacity(lowered.len());
    let mut chars = lowered.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '0' && matches!(chars.peek(), Some('x')) {
            // `0x` prefix of a pasted hex dump.
            chars.next();
        } else if ch.is_ascii_hexdigit() {
            digits.push(ch);
        } else if ch.is_whitespace() || matches!(ch, ',' | ':' | '-' | '_') {
            continue;
        } else {
            return Err(format!("unexpected character {ch:?}"));
        }
    }
    if digits.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Classic hex dump: offset, 16 bytes, ASCII gutter.
pub fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|b| {
                let ch = *b as char;
                if ch.is_ascii_graphic() || ch == ' ' {
                    ch
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{:08x}  {:<47}  |{ascii}|\n", i * 16, hex.join(" ")));
    }
    out
}

/// Colour for one rendered line: request/status line, header name, header value,
/// punctuation, or body text.
pub fn line_colour(line: &str, first: bool) -> eframe::egui::Color32 {
    if first {
        return c(theme::HEADER_BLUE);
    }
    if let Some((name, _)) = line.split_once(':') {
        if !name.is_empty() && !name.contains(' ') {
            return c(theme::ORANGE_5);
        }
    }
    theme::editor_ink()
}

/// Body colouring for the common structured types.
pub fn body_colour(body: &str) -> eframe::egui::Color32 {
    let t = body.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        return c(theme::GOOD);
    }
    if t.starts_with('<') {
        return c(theme::HEADER_BLUE);
    }
    theme::editor_ink()
}

/// The request/status line split into coloured spans: everything before the
/// query string and the trailing protocol token keep the first-line colour,
/// query keys and values get Burp's url_key/url_value tokens (its Params view
/// colours, applied to the raw line).
pub fn first_line_spans(line: &str) -> Vec<(String, eframe::egui::Color32)> {
    let accent = c(theme::HEADER_BLUE);
    let mut out: Vec<(String, eframe::egui::Color32)> = Vec::new();
    let (pre, q) = match line.split_once('?') {
        Some((pre, q)) => (pre, Some(q)),
        None => (line, None),
    };
    out.push((pre.to_owned(), accent));
    let Some(q) = q else { return out };
    let (pairs, tail) = match q.rsplit_once(' ') {
        Some((pairs, tail)) => (pairs, Some(tail)),
        None => (q, None),
    };
    for (i, pair) in pairs.split('&').enumerate() {
        if i > 0 {
            out.push(("&".to_owned(), accent));
        }
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => {
                out.push((k.to_owned(), theme::url_key()));
                out.push((format!("={v}"), theme::url_value()));
            }
            None => out.push((pair.to_owned(), theme::url_key())),
        }
    }
    if let Some(tail) = tail {
        out.push((format!(" {tail}"), accent));
    }
    out
}

/// egui has no per-widget font size, so the monospace text style of this `Ui`
/// (and everything drawn inside it) is set to the chosen size.
pub fn apply_font_size(ui: &mut Ui, size: f32) {
    let mut style = egui::Style::clone(ui.style());
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(size));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::monospace(size));
    ui.set_style(style);
}

/// Editable message editor used by Repeater, Intruder, Sequencer and Decoder.
///
/// When `state.hex` is on, the buffer is shown as hex and edits are decoded back
/// into the message as they are made, so the two views never disagree.
/// The "N matches" counter, drawn as a chip on the subtle tint (design token
/// consumer for theme::subtle_bg / RADIUS_S).
fn match_count_chip(ui: &mut Ui, n: usize) {
    egui::Frame::NONE
        .fill(theme::subtle_bg())
        .corner_radius(theme::RADIUS_S)
        .inner_margin(egui::Margin::symmetric(6, 1))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{n} match{}", if n == 1 { "" } else { "es" }))
                    .size(12.0)
                    .color(c(if n == 0 { theme::MONO6 } else { theme::ORANGE_5 })),
            );
        });
}

pub fn message_editor(
    ui: &mut Ui,
    id: &str,
    text: &mut String,
    rows: usize,
    state: &mut EditorState,
) -> egui::Response {
    ui.horizontal(|ui| {
        if ui.checkbox(&mut state.wrap, "wrap").changed() {}
        if ui.checkbox(&mut state.hex, "hex").changed() {
            if state.hex {
                *text = hex_encode(text.as_bytes());
            } else if let Ok(bytes) = hex_decode(text) {
                *text = String::from_utf8_lossy(&bytes).into_owned();
            } else {
                // Not valid hex: keep the text and leave the view.
                state.hex = false;
            }
        }
        ui.checkbox(&mut state.line_numbers, "lines");
        ui.add(
            egui::TextEdit::singleline(&mut state.search)
                .desired_width(150.0)
                .hint_text("find in message…")
                .font(egui::TextStyle::Monospace),
        );
        if !state.search.is_empty() {
            let n = match_count(text, &state.search);
            match_count_chip(ui, n);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let mut size = state.font_size;
            if ui
                .add(
                    egui::DragValue::new(&mut size)
                        .speed(0.5)
                        .range(8.0..=22.0)
                        .prefix("Aa ")
                        .suffix(" pt"),
                )
                .changed()
            {
                state.font_size = size;
            }
        });
    });

    // Never ask for an unbounded width: inside a scroll area egui then hands the
    // text a near-zero wrap width and every character lands on its own line.
    let text_w = ui.available_width().max(120.0);
    let mut edit = egui::TextEdit::multiline(text)
        .font(egui::TextStyle::Monospace)
        .code_editor()
        .desired_rows(rows)
        .desired_width(text_w)
        .id_salt(id);
    if !state.wrap {
        edit = edit.desired_width(text_w);
    }
    apply_font_size(ui, state.font_size);
    ui.add(edit)
}

/// Read-only message view used by the Proxy detail pane and other previews.
/// Head lines are tinted and numbered; the body is one block.
pub fn message_view(ui: &mut Ui, id: &str, text: &str, state: &mut EditorState) {
    message_view_inner(ui, id, text, state, None);
}

/// Same view, with an optional "annotate search matches" callback.
pub fn message_view_inner(
    ui: &mut Ui,
    id: &str,
    text: &str,
    state: &mut EditorState,
    _annotate: Option<&dyn Fn(&str) -> String>,
) {
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.line_numbers, "lines");
        ui.add(
            egui::TextEdit::singleline(&mut state.search)
                .desired_width(160.0)
                .hint_text("find in message…")
                .font(egui::TextStyle::Monospace),
        );
        if !state.search.is_empty() {
            let n = match_count(text, &state.search);
            match_count_chip(ui, n);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let mut size = state.font_size;
            if ui
                .add(
                    egui::DragValue::new(&mut size)
                        .speed(0.5)
                        .range(8.0..=22.0)
                        .prefix("Aa ")
                        .suffix(" pt"),
                )
                .changed()
            {
                state.font_size = size;
            }
        });
    });

    let size = state.font_size;
    let gutter = if state.line_numbers { 46.0 } else { 0.0 };
    let (head, body) = split_message(text);
    egui::ScrollArea::vertical()
        .id_salt(id)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if state.hex {
                ui.monospace(RichText::new(hex_dump(text.as_bytes())).size(size).color(c(theme::EDITOR_TEXT)));
                return;
            }
            for (i, line) in head.split('\n').enumerate() {
                let line = line.trim_end_matches('\r');
                ui.horizontal(|ui| {
                    if gutter > 0.0 {
                        ui.add_sized(
                            [gutter, 0.0],
                            egui::Label::new(
                                RichText::new(format!("{}", i + 1))
                                    .monospace()
                                    .size(size - 1.5)
                                    .color(c(theme::MONO4)),
                            ),
                        );
                    }
                    if i == 0 {
                        for (seg, colour) in first_line_spans(line) {
                            ui.label(RichText::new(seg).monospace().size(size).color(colour));
                        }
                    } else {
                        ui.label(
                            RichText::new(line)
                                .monospace()
                                .size(size)
                                .color(line_colour(line, false)),
                        );
                    }
                });
            }
            if !body.is_empty() {
                // One blank line at the message font (~16 px) separates the
                // headers from the body, as the raw CRLFCRLF does.
                ui.add_space(theme::SPACE_L);
                ui.horizontal(|ui| {
                    if gutter > 0.0 {
                        ui.add_sized(
                            [gutter, 0.0],
                            egui::Label::new(
                                RichText::new("·")
                                    .monospace()
                                    .size(size - 1.5)
                                    .color(c(theme::MONO4)),
                            ),
                        );
                    }
                    ui.label(
                        RichText::new(body)
                            .monospace()
                            .size(size)
                            .color(body_colour(body)),
                    );
                });
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_message_handles_crlf_and_lf() {
        let (head, body) = split_message("GET / HTTP/1.1\r\nHost: a\r\n\r\nbody");
        assert_eq!(head, "GET / HTTP/1.1\r\nHost: a");
        assert_eq!(body, "body");
        let (head, body) = split_message("GET / HTTP/1.1\nHost: a\n\nbody");
        assert_eq!(head, "GET / HTTP/1.1\nHost: a");
        assert_eq!(body, "body");
    }

    #[test]
    fn split_message_without_body_returns_empty_body() {
        let (head, body) = split_message("GET / HTTP/1.1\r\nHost: a\r\n");
        assert_eq!(head, "GET / HTTP/1.1\r\nHost: a\r\n");
        assert!(body.is_empty());
    }

    #[test]
    fn match_count_is_case_insensitive() {
        assert_eq!(match_count("Host: a\r\nhost: b", "HOST"), 2);
        assert_eq!(match_count("abc", ""), 0);
        assert_eq!(match_count("abc", "zz"), 0);
    }

    #[test]
    fn hex_round_trips_through_the_editor_buffer() {
        let msg = "GET / HTTP/1.1\r\nHost: a\r\n\r\nbody";
        let encoded = hex_encode(msg.as_bytes());
        assert_eq!(encoded.len(), msg.len() * 2);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), msg);
    }

    #[test]
    fn hex_decode_tolerates_a_pasted_dump_but_not_junk() {
        assert_eq!(hex_decode("41 42\n43").unwrap(), b"ABC".to_vec());
        assert_eq!(hex_decode("0x41,0x42").unwrap(), b"AB".to_vec());
        assert!(hex_decode("41 4").is_err(), "odd digit count");
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn hex_dump_shows_offsets_and_ascii() {
        let dump = hex_dump(b"AB");
        assert!(dump.starts_with("00000000"), "{dump}");
        assert!(dump.contains("41 42"), "{dump}");
        assert!(dump.contains("|AB|"), "{dump}");
    }

    #[test]
    fn line_colours_follow_the_message_shape() {
        assert_eq!(line_colour("GET / HTTP/1.1", true), c(theme::HEADER_BLUE));
        assert_eq!(line_colour("Host: a", false), c(theme::ORANGE_5));
        assert_eq!(line_colour("  folded", false), theme::editor_ink());
        assert_eq!(body_colour("{\"a\":1}"), c(theme::GOOD));
        assert_eq!(body_colour("<html>"), c(theme::HEADER_BLUE));
        assert_eq!(body_colour("plain"), theme::editor_ink());
    }

    #[test]
    fn first_line_spans_colour_the_query() {
        let spans = first_line_spans("GET /p?a=1&b HTTP/1.1");
        assert_eq!(spans[0], ("GET /".to_owned(), c(theme::HEADER_BLUE)));
        assert_eq!(spans[1], ("a".to_owned(), theme::url_key()));
        assert_eq!(spans[2], ("=1".to_owned(), theme::url_value()));
        assert_eq!(spans[3], ("&".to_owned(), c(theme::HEADER_BLUE)));
        assert_eq!(spans[4], ("b".to_owned(), theme::url_key()));
        assert_eq!(spans[5], (" HTTP/1.1".to_owned(), c(theme::HEADER_BLUE)));
        // A status line without a query stays one span.
        assert_eq!(first_line_spans("HTTP/1.1 200 OK").len(), 1);
    }
}
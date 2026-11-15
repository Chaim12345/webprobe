// Theme constants transcribed from burp/theme/DarkTheme.json (MECHANICS.md).
// Greys come from the `black` swatch shades, accent from the `orange` swatch.

use eframe::egui::{self, Color32};

pub const ORANGE: u32 = 0xFF6633; // accent
pub const ORANGE_1: u32 = 0xDB612F; // orange[1]
pub const ORANGE_5: u32 = 0xFFB090; // links
pub const MONO1: u32 = 0x2B2B2B; // panel dark
pub const ZEBRA: u32 = 0x3A3D3F; // alternating table row (a clear step above mono[1])
pub const MONO1X: u32 = 0x323334; // message editor background (mono[1])
pub const MONO2: u32 = 0x424244; // mono[2]
pub const MONO3: u32 = 0x525255;
pub const MONO4: u32 = 0x9AA0A6; // secondary text: >= 4.5:1 on MONO1/MONO1X
pub const MONO6: u32 = 0xC5C7C8; // disabled / unknown
pub const MONO7: u32 = 0xFFFFFF;
pub const EDITOR_TEXT: u32 = 0xCECECE;
pub const EDITOR_CUR_LINE: u32 = 0x35383A;
pub const SEL_BG: u32 = 0x2C5175; // selectionBackground (secondary[2])
pub const METHOD_GET: u32 = 0xD37FA4; // magenta[3]
pub const METHOD_POST: u32 = 0x9189FE; // purple[3]
pub const METHOD_OTHER: u32 = 0x83CDD1; // teal[3]
pub const GOOD: u32 = 0x7DC164; // green[4]
pub const WARN: u32 = 0xE1B156; // yellow[3]
pub const BAD: u32 = 0xDF4C63; // red[3]
pub const HEADER_BLUE: u32 = 0xD1E8F9;

pub const fn c(v: u32) -> Color32 {
    Color32::from_rgb(((v >> 16) & 0xFF) as u8, ((v >> 8) & 0xFF) as u8, (v & 0xFF) as u8)
}

pub fn method_color(m: &str) -> Color32 {
    let m = m.to_ascii_uppercase();
    match m.as_str() {
        "GET" | "OPTIONS" => c(METHOD_GET),
        "POST" => c(METHOD_POST),
        "" => c(MONO6),
        _ => c(METHOD_OTHER),
    }
}

#[allow(dead_code)]
pub fn status_color(s: &str) -> Color32 {
    if s.is_empty() {
        return c(MONO6);
    }
    if s.starts_with('2') {
        c(GOOD)
    } else if s.starts_with('3') {
        c(WARN)
    } else if s.starts_with('4') || s.starts_with('5') {
        c(BAD)
    } else {
        c(MONO6)
    }
}

pub fn apply(ctx: &egui::Context) {
    install_fonts(ctx);
    apply_as(ctx, Palette::Dark, Density::Comfortable, 1.0);
}

/// egui's proportional faces lack some arrows and symbols the UI prints, and a
/// missing glyph draws as a box. Hack (the bundled monospace face) has them, so
/// it joins the proportional family as a last-resort fallback. Call once at
/// start-up: replacing the fonts rebuilds the glyph atlas.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        if !family.iter().any(|name| name == "Hack") {
            family.push("Hack".to_owned());
        }
    }
    ctx.set_fonts(fonts);
}

// ---------- design tokens (M-01) ----------

/// Spacing scale (logical pixels).
pub const SPACE_XS: f32 = 4.0;
pub const SPACE_S: f32 = 8.0;
pub const SPACE_M: f32 = 12.0;
pub const SPACE_L: f32 = 16.0;
pub const SPACE_XL: f32 = 24.0;

/// Corner radii.
pub const RADIUS_S: f32 = 2.0;
pub const RADIUS_M: f32 = 4.0;

/// Typography scale.
pub const FONT_H1: f32 = 18.0;
pub const FONT_H2: f32 = 15.0;
pub const FONT_BODY: f32 = 13.0;
pub const FONT_SMALL: f32 = 11.0;
/// `display.http_message_display.font_size` (UserDefaults.json) = 13.
pub const FONT_MONO: f32 = 13.0;

/// Named colours that had no token (kept here so widgets never inline hex).
pub const URL_KEY: u32 = 0xBBCDFF;
pub const URL_VALUE: u32 = 0xA5C35B;
pub const SELECTION_SUBTLE: u32 = 0x1A2250;

/// UI density.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Density {
    Compact,
    Comfortable,
}

impl Density {
    pub fn parse(s: &str) -> Self {
        match s {
            "compact" => Density::Compact,
            _ => Density::Comfortable,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Density::Compact => "compact",
            Density::Comfortable => "comfortable",
        }
    }
    /// Height of one table row / list item.
    pub fn row_height(self) -> f32 {
        match self {
            Density::Compact => 20.0,
            Density::Comfortable => 26.0,
        }
    }
    /// Spacing between items.
    pub fn item_spacing(self) -> f32 {
        match self {
            Density::Compact => SPACE_XS,
            Density::Comfortable => SPACE_S,
        }
    }
}

/// Colour palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Palette {
    Dark,
    Light,
    HighContrast,
}

impl Palette {
    pub fn parse(s: &str) -> Self {
        match s {
            "light" => Palette::Light,
            "high_contrast" => Palette::HighContrast,
            _ => Palette::Dark,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Palette::Dark => "dark",
            Palette::Light => "light",
            Palette::HighContrast => "high contrast",
        }
    }
    fn panel_fill(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO1),
            Palette::Light => Color32::from_rgb(0xF6, 0xF7, 0xF8),
            Palette::HighContrast => Color32::from_rgb(0x00, 0x00, 0x00),
        }
    }
    fn editor_bg(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO1X),
            Palette::Light => Color32::from_rgb(0xFF, 0xFF, 0xFF),
            Palette::HighContrast => Color32::from_rgb(0x00, 0x00, 0x00),
        }
    }
    fn text(self) -> Color32 {
        match self {
            Palette::Dark => c(EDITOR_TEXT),
            Palette::Light => Color32::from_rgb(0x1A, 0x1C, 0x1F),
            Palette::HighContrast => Color32::from_rgb(0xFF, 0xFF, 0xFF),
        }
    }
    fn faint_bg(self) -> Color32 {
        match self {
            Palette::Dark => c(EDITOR_CUR_LINE),
            Palette::Light => Color32::from_rgb(0xEC, 0xEE, 0xF1),
            Palette::HighContrast => Color32::from_rgb(0x1A, 0x1A, 0x1A),
        }
    }
    fn widget_bg(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO3),
            Palette::Light => Color32::from_rgb(0xE4, 0xE7, 0xEB),
            Palette::HighContrast => Color32::from_rgb(0x3A, 0x3A, 0x3A),
        }
    }
    fn border(self) -> Color32 {
        match self {
            Palette::Dark => c(MONO2),
            Palette::Light => Color32::from_rgb(0xC9, 0xCE, 0xD4),
            Palette::HighContrast => Color32::from_rgb(0xFF, 0xFF, 0xFF),
        }
    }
}

/// Apply the full appearance (M-01/M-05): palette, density and font scale.
pub fn apply_as(ctx: &egui::Context, palette: Palette, density: Density, font_scale: f32) {
    let mut sty = (*ctx.style()).clone();
    sty.spacing.item_spacing = egui::vec2(SPACE_S, SPACE_S);
    // A scroll bar you can actually see: egui's default floats over the content
    // and is nearly invisible on a dark palette. Ours allocates its own gutter.
    sty.spacing.scroll.floating = false;
    sty.spacing.scroll.bar_width = 12.0;
    sty.spacing.scroll.handle_min_length = 32.0;
    sty.spacing.scroll.bar_inner_margin = 2.0;
    sty.spacing.scroll.bar_outer_margin = 2.0;
    sty.spacing.button_padding = egui::vec2(SPACE_S, SPACE_XS);
    sty.spacing.window_margin = egui::Margin::symmetric(SPACE_M, SPACE_M);
    if palette == Palette::Dark {
        // The dark palette keeps the original Burp-derived styling.
        let mut dark = (*ctx.style()).clone();
        let v = &mut dark.visuals;
        *v = egui::Visuals::dark();
        v.panel_fill = c(MONO1);
        v.window_fill = c(MONO1);
        v.extreme_bg_color = c(MONO1);
        v.faint_bg_color = c(EDITOR_CUR_LINE);
        v.selection.bg_fill = c(SEL_BG);
        v.selection.stroke.color = c(MONO7);
        v.override_text_color = Some(c(EDITOR_TEXT));
        v.window_stroke = egui::Stroke::new(1.0, c(MONO2));
        v.widgets.noninteractive.bg_fill = c(MONO2);
        v.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5, c(MONO3));
        v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, c(EDITOR_TEXT));
        v.widgets.inactive.bg_fill = c(MONO3);
        v.widgets.inactive.bg_stroke = egui::Stroke::new(0.5, c(MONO4));
        v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, c(MONO6));
        v.widgets.hovered.bg_fill = c(MONO4);
        v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, c(MONO7));
        v.widgets.active.bg_fill = c(ORANGE_1);
        v.widgets.active.fg_stroke = egui::Stroke::new(1.0, c(MONO7));
        v.hyperlink_color = c(ORANGE_5);
        dark.text_styles = base_text_styles(font_scale);
        sty = dark;
    } else {
        let v = &mut sty.visuals;
        *v = if palette == Palette::HighContrast {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        v.panel_fill = palette.panel_fill();
        v.window_fill = palette.panel_fill();
        v.extreme_bg_color = palette.editor_bg();
        v.faint_bg_color = palette.faint_bg();
        v.override_text_color = Some(palette.text());
        v.window_stroke = egui::Stroke::new(1.0, palette.border());
        v.widgets.noninteractive.bg_fill = palette.faint_bg();
        v.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5, palette.border());
        v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, palette.text());
        v.widgets.inactive.bg_fill = palette.widget_bg();
        v.widgets.inactive.bg_stroke = egui::Stroke::new(0.5, palette.border());
        v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, palette.text());
        v.widgets.hovered.bg_fill = palette.faint_bg();
        v.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, palette.text());
        v.widgets.active.bg_fill = c(ORANGE_1);
        v.widgets.active.fg_stroke = egui::Stroke::new(1.0, c(MONO7));
        v.hyperlink_color = c(ORANGE_5);
        sty.text_styles = base_text_styles(font_scale);
    }
    // Density applies in every palette.
    let row = density.row_height();
    sty.spacing.interact_size = egui::vec2(row, row);
    ctx.set_style(sty);
}

fn base_text_styles(font_scale: f32) -> std::collections::BTreeMap<egui::TextStyle, egui::FontId> {
    [
        (egui::TextStyle::Heading, egui::FontId::proportional(FONT_H1 * font_scale)),
        (egui::TextStyle::Body, egui::FontId::proportional(FONT_BODY * font_scale)),
        (egui::TextStyle::Button, egui::FontId::proportional(FONT_BODY * font_scale)),
        (egui::TextStyle::Small, egui::FontId::proportional(FONT_SMALL * font_scale)),
        (egui::TextStyle::Monospace, egui::FontId::monospace(FONT_MONO * font_scale)),
    ]
    .into()
}

// ---------- live appearance state (M-05) ----------

use std::sync::atomic::{AtomicU32, AtomicU8};

static PALETTE: AtomicU8 = AtomicU8::new(0); // 0 dark, 1 light, 2 high contrast
static DENSITY: AtomicU8 = AtomicU8::new(1); // 0 compact, 1 comfortable
static FONT_SCALE_BITS: AtomicU32 = AtomicU32::new(1.0f32.to_bits());

pub fn appearance() -> (Palette, Density, f32) {
    let palette = match PALETTE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => Palette::Light,
        2 => Palette::HighContrast,
        _ => Palette::Dark,
    };
    let density = match DENSITY.load(std::sync::atomic::Ordering::Relaxed) {
        0 => Density::Compact,
        _ => Density::Comfortable,
    };
    let scale = f32::from_bits(FONT_SCALE_BITS.load(std::sync::atomic::Ordering::Relaxed)).clamp(0.7, 2.0);
    (palette, density, scale)
}

pub fn set_appearance(palette: Palette, density: Density, font_scale: f32) {
    PALETTE.store(
        match palette {
            Palette::Dark => 0,
            Palette::Light => 1,
            Palette::HighContrast => 2,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
    DENSITY.store(
        match density {
            Density::Compact => 0,
            Density::Comfortable => 1,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
    FONT_SCALE_BITS.store(font_scale.clamp(0.7, 2.0).to_bits(), std::sync::atomic::Ordering::Relaxed);
}

/// Apply the live appearance (call once per frame; cheap).
pub fn apply_current(ctx: &egui::Context) {
    let (palette, density, scale) = appearance();
    apply_as(ctx, palette, density, scale);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every non-ASCII character the UI prints. Add one here when you print a new one.
    const UI_GLYPHS: &[char] = &[
        '\u{2192}', // right arrow
        '\u{2014}', // em dash
        '\u{2026}', // ellipsis
        '\u{00B7}', // middle dot
        '\u{00D7}', // multiplication sign
        '\u{2191}', // up arrow
        '\u{2193}', // down arrow
        '\u{25BE}', // small down triangle
        '\u{2195}', // up-down arrow (table sort hint)
        '\u{25BC}', // down triangle (table sort arrow)
    ];

    fn missing(ctx: &egui::Context) -> Vec<char> {
        // Fonts are (re)built at the start of a pass.
        let _ = ctx.run(egui::RawInput::default(), |_| {});
        let font = egui::FontId::proportional(13.0);
        ctx.fonts(|f| UI_GLYPHS.iter().copied().filter(|&c| !f.has_glyph(&font, c)).collect())
    }

    #[test]
    fn every_glyph_the_ui_prints_can_be_drawn() {
        let stock = egui::Context::default();
        eprintln!("missing with egui's stock fonts: {:?}", missing(&stock));
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let missing = missing(&ctx);
        assert!(missing.is_empty(), "these would draw as boxes: {missing:?}");
    }
}

//! Suspicious input transformation (burp.Zeo6, APIP_SuspiciousInputTransformation):
//! the reflection probes of burp.Zed7.Zp (Zp9c / Zp9y / Zp9q / Zp9d / Zp9g on
//! the Zp9v base), the matchers they search the response with (burp.Zpfn,
//! burp.Zh_1) and the issue text of burp.Zwvh. Pure functions over a send
//! closure; the reflected check (`SuspiciousInputTransformation`) and the
//! stored one (`SuspiciousInputTransformationStored`) wrap them.
//!
//! Strings are Burp's ISO-8859-1 view of bytes: a char U+0000..U+00FF is
//! one byte (net.portswigger.Zhs.Zq / ZA).

/// net.portswigger.Zel.ZG, the named entities net.portswigger.Zg0 decodes:
/// Zel.ZP registers every upper/lower-case spelling of each name, so a
/// name matches in any case, and of two names that differ only in case the
/// one registered last wins (`eacute` over `Eacute`). `nbsp` is a plain
/// space there. Values are ISO-8859-1 bytes.
const NAMED_ENTITIES: &[(&str, u8)] = &[
    ("quot", 0x22),
    ("amp", 0x26),
    ("lt", 0x3c),
    ("gt", 0x3e),
    ("apos", 0x27),
    ("nbsp", 0x20),
    ("iexcl", 0xa1),
    ("cent", 0xa2),
    ("pound", 0xa3),
    ("curren", 0xa4),
    ("yen", 0xa5),
    ("brvbar", 0xa6),
    ("sect", 0xa7),
    ("uml", 0xa8),
    ("copy", 0xa9),
    ("ordf", 0xaa),
    ("laquo", 0xab),
    ("not", 0xac),
    ("shy", 0xad),
    ("reg", 0xae),
    ("macr", 0xaf),
    ("deg", 0xb0),
    ("plusmn", 0xb1),
    ("sup2", 0xb2),
    ("sup3", 0xb3),
    ("acute", 0xb4),
    ("micro", 0xb5),
    ("para", 0xb6),
    ("middot", 0xb7),
    ("cedil", 0xb8),
    ("sup1", 0xb9),
    ("ordm", 0xba),
    ("raquo", 0xbb),
    ("frac14", 0xbc),
    ("frac12", 0xbd),
    ("frac34", 0xbe),
    ("iquest", 0xbf),
    ("agrave", 0xe0),
    ("aacute", 0xe1),
    ("acirc", 0xe2),
    ("atilde", 0xe3),
    ("auml", 0xe4),
    ("aring", 0xe5),
    ("aelig", 0xe6),
    ("ccedil", 0xe7),
    ("egrave", 0xe8),
    ("eacute", 0xe9),
    ("ecirc", 0xea),
    ("euml", 0xeb),
    ("igrave", 0xec),
    ("iacute", 0xed),
    ("icirc", 0xee),
    ("iuml", 0xef),
    ("eth", 0xf0),
    ("ntilde", 0xf1),
    ("ograve", 0xf2),
    ("oacute", 0xf3),
    ("ocirc", 0xf4),
    ("otilde", 0xf5),
    ("ouml", 0xf6),
    ("times", 0xd7),
    ("oslash", 0xf8),
    ("ugrave", 0xf9),
    ("uacute", 0xfa),
    ("ucirc", 0xfb),
    ("uuml", 0xfc),
    ("yacute", 0xfd),
    ("thorn", 0xfe),
    ("szlig", 0xdf),
    ("divide", 0xf7),
    ("yuml", 0xff),
];

/// net.portswigger.Zg0.Ze over the bytes between `&` and `;`
/// (net.portswigger.Zrl): `#` then decimal digits, `#x` / `#X` then hex
/// digits (an int that wraps, cut to a byte; no digits is 0), otherwise a
/// named entity. None when a digit is invalid or the name is unknown.
fn entity_byte(name: &[u8]) -> Option<u8> {
    if name.first() == Some(&b'#') {
        let (radix, digits) = if name.len() >= 2 && matches!(name[1], b'x' | b'X') {
            (16u32, &name[2..])
        } else {
            (10u32, &name[1..])
        };
        let mut n: i32 = 0;
        for &b in digits {
            let d = (b as char).to_digit(radix)?;
            n = n.wrapping_mul(radix as i32).wrapping_add(d as i32);
        }
        return Some(n as u8);
    }
    NAMED_ENTITIES
        .iter()
        .find(|(k, _)| k.as_bytes().eq_ignore_ascii_case(name))
        .map(|&(_, v)| v)
}

/// net.portswigger.Zyn.ZK / Zru.Zz: ASCII upper case to lower case.
fn lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// net.portswigger.Zsh.Zy(bytes, false), the decoding burp.Zh_1 applies to
/// the bytes between prefix and suffix: each `&name;` (the next `;`, with
/// no `&` before it) that net.portswigger.Zg0 decodes becomes that byte.
fn decode_entities(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let mut c = b[i];
        if c == b'&' {
            // Zsh.ZE: the next ';' unless an '&' comes first.
            let end = b[i + 1..]
                .iter()
                .position(|&x| x == b'&' || x == b';')
                .map(|k| i + 1 + k)
                .filter(|&k| b[k] == b';');
            if let Some(end) = end
                && let Some(v) = entity_byte(&b[i + 1..end])
            {
                c = v;
                i = end;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// burp.Zpfn, the matcher the reflection probes search with, without the
/// quote-escape mode (Zpfn.Zv) no probe here uses. Matching is ASCII
/// case-insensitive; with `entities` (Zpfn.Zl) an entity in the response
/// counts as the character it stands for, without it (Zpfn.Zj) bytes are
/// compared as they are.
#[derive(Clone, Debug)]
pub(crate) struct Needle {
    bytes: Vec<u8>,
    entities: bool,
}

impl Needle {
    pub(crate) fn new(bytes: &[u8], entities: bool) -> Self {
        Needle {
            bytes: bytes.to_vec(),
            entities,
        }
    }

    /// burp.Zpfn.Zn: the first match inside `from..to` as (start, end).
    /// With entities, a failed entity-aware scan falls back to a plain
    /// case-insensitive search (Zpfn.ZW: net.portswigger.Zyn.ZB with
    /// case sensitivity off, burp's Boyer-Moore net.portswigger.Zek).
    pub(crate) fn find(&self, hay: &[u8], from: usize, to: usize) -> Option<(usize, usize)> {
        let to = to.min(hay.len());
        if self.bytes.is_empty() || from >= hay.len() {
            return None;
        }
        if let Some(m) = self.scan(hay, from, to) {
            return Some(m);
        }
        if !self.entities || from > to {
            return None;
        }
        hay[from..to]
            .windows(self.bytes.len())
            .position(|w| w.eq_ignore_ascii_case(&self.bytes))
            .map(|p| (from + p, from + p + self.bytes.len()))
    }

    /// burp.Zpfn.Zm: a byte-at-a-time scan that restarts one byte after
    /// the start of a failed partial match. An entity whose decoded byte
    /// would end past the last possible match aborts the whole scan.
    fn scan(&self, hay: &[u8], from: usize, to: usize) -> Option<(usize, usize)> {
        let len = self.bytes.len() as isize;
        let to = to as isize;
        let mut pos = from as isize;
        let mut matched: isize = 0;
        let mut start: isize = -1;
        while pos <= to - len + matched {
            if start < 0 {
                start = pos;
            }
            let b = if self.entities {
                let (next, b) = self.next_byte(hay, pos as usize, to, matched)?;
                pos = next as isize;
                b
            } else {
                pos += 1;
                hay[pos as usize - 1]
            };
            if lower(b) == lower(self.bytes[matched as usize]) {
                matched += 1;
            } else {
                if start >= 0 {
                    pos = start + 1;
                }
                matched = 0;
                start = -1;
            }
            if matched == len {
                return Some((start as usize, pos as usize));
            }
        }
        None
    }

    /// burp.Zpfn.Zd: the byte at `pos`, or the byte an entity starting
    /// there stands for (Zpfn.Z_: only a decoded byte below 0x80 counts).
    fn next_byte(&self, hay: &[u8], pos: usize, to: isize, matched: isize) -> Option<(usize, u8)> {
        let mut b = hay[pos];
        let mut next = pos + 1;
        if b == b'&' {
            // Zyn.Zv(hay, ';', next + 1, hay.length).
            let semi = hay
                .get(next + 1..)
                .and_then(|r| r.iter().position(|&c| c == b';'))
                .map(|k| next + 1 + k);
            if let Some(semi) = semi
                && let Some(v) = entity_byte(&hay[pos + 1..semi]).filter(|v| *v < 0x80)
            {
                b = v;
                next = semi + 1;
                if next as isize > to - self.bytes.len() as isize + matched + 1 {
                    return None;
                }
            }
        }
        Some((next, b))
    }
}

/// burp.Zh_1, the "transformed in some unexpected way" matcher: the first
/// match of the prefix, then within 25 + 5 x (suffix length) bytes after it
/// the suffix. With the whole suffix found, the entity-decoded bytes
/// between must be one byte that is not the expected character (any case);
/// otherwise there is no match. Without it, the suffix minus its first two
/// characters must follow with at most three entity-decoded bytes between.
/// The match runs from the prefix's start to the suffix's end.
pub(crate) fn transformed_span(
    hay: &[u8],
    prefix: &Needle,
    suffix: &Needle,
    short: &Needle,
    suffix_len: usize,
    expected: u8,
) -> Option<(usize, usize)> {
    let (p_start, p_end) = prefix.find(hay, 0, hay.len())?;
    let window = hay.len().min(p_end + 25 + suffix_len * 5);
    if let Some((s_start, s_end)) = suffix.find(hay, p_end, window) {
        let between = decode_entities(&hay[p_end..s_start]);
        return (between.len() == 1 && lower(between[0]) != expected).then_some((p_start, s_end));
    }
    let (s_start, s_end) = short.find(hay, p_end, window)?;
    (decode_entities(&hay[p_end..s_start]).len() <= 3).then_some((p_start, s_end))
}

/// One probe of burp.Zed7.Zp, on burp.Zp9v.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    /// burp.Zp9c: the overlong UTF-8 sequence [0xc1][0x81] for 'A'.
    Overlong,
    /// burp.Zp9y: the invalid UTF-8 sequence [0xc1][0x01] for 'A'; run only
    /// after the overlong sequence was decoded (Zp9c's follower).
    Invalid,
    /// burp.Zp9q: `%41` (its static string, decoded by hand: "\u0001R\u0000"
    /// XOR 118 ^ 82/16/71).
    Url,
    /// burp.Zp9d: two backslashes ("}m" XOR 31 ^ 62/46), the suffix
    /// starting with `l` (Zp9d.ZE).
    Backslash,
    /// burp.Zp9g: `&#65;` ("texUc" XOR 83 ^ 1/21/29/51/11), searched
    /// without entity decoding (Zp9g.ZS: Zpfn.Zj).
    Html,
}

impl Probe {
    /// The bytes between prefix and suffix (Zp9v.Zd).
    fn sequence(self) -> &'static str {
        match self {
            Probe::Overlong => "\u{c1}\u{81}",
            Probe::Invalid => "\u{c1}\u{1}",
            Probe::Url => "%41",
            Probe::Backslash => "\\\\",
            Probe::Html => "&#65;",
        }
    }

    /// The character the sequence decodes to (Zp9v.Zj).
    fn decoded(self) -> u8 {
        match self {
            Probe::Backslash => b'\\',
            Probe::Overlong | Probe::Invalid | Probe::Url | Probe::Html => b'a',
        }
    }

    /// The issue variant of a decoding hit (burp.Zm26); the unexpected
    /// transformation is the next one.
    fn variant(self) -> usize {
        match self {
            Probe::Overlong => 0,
            Probe::Invalid => 2,
            Probe::Url => 4,
            Probe::Backslash => 6,
            Probe::Html => 8,
        }
    }

    fn needle(self, s: &str) -> Needle {
        Needle::new(&latin1_bytes(s), self != Probe::Html)
    }
}

/// A suspicious input transformation found: the variant byte of burp.Zwvh
/// (0..=9), the payload sent and the reflection it matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransformHit {
    pub variant: u8,
    pub payload: String,
    pub reflection: String,
    pub append: bool,
}

/// Burp's byte view of a string (net.portswigger.Zhs.Zq).
fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}

/// Burp's string view of bytes (net.portswigger.Zhs.ZA).
fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

type Found = [[Option<(String, String)>; 2]; 10];

/// burp.Zp9v.Zs: prefix (10 random a-z0-9), sequence, suffix (10 random,
/// or `l` + 9 for the backslash). The one response is searched for the
/// decoded form; only when it is absent is it searched with burp.Zh_1. True
/// when the sequence was decoded.
fn probe<R, S>(p: Probe, append: bool, rnd: &mut R, send: &mut S, found: &mut Found) -> bool
where
    R: FnMut(usize) -> String,
    S: FnMut(&str, bool) -> Option<Vec<u8>>,
{
    let prefix = rnd(10);
    let suffix = if p == Probe::Backslash {
        format!("l{}", rnd(9))
    } else {
        rnd(10)
    };
    let payload = format!("{prefix}{}{suffix}", p.sequence());
    let Some(resp) = send(&payload, append) else {
        return false;
    };
    let slot = usize::from(append);
    let decoded = format!("{prefix}{}{suffix}", p.decoded() as char);
    if let Some((a, b)) = p.needle(&decoded).find(&resp, 0, resp.len()) {
        found[p.variant()][slot] = Some((payload, latin1(&resp[a..b])));
        return true;
    }
    let span = transformed_span(
        &resp,
        &p.needle(&prefix),
        &p.needle(&suffix),
        &p.needle(&suffix[2..]),
        suffix.len(),
        p.decoded(),
    );
    if let Some((a, b)) = span {
        found[p.variant() + 1][slot] = Some((payload, latin1(&resp[a..b])));
    }
    false
}

/// burp.Zeo6.Zw over burp.Zm3o.Zg / Zr5j: the value is replaced (and, when
/// `append` allows it, appended to: burp.Zm3o.ZK). Each placement first
/// needs a plain reflection of a random 10-character a-z0-9 marker
/// (burp.Zp1_, matched like the probes with entity decoding); then the
/// overlong probe (and, when it was decoded, the invalid one), the URL,
/// backslash and HTML probes go out. Reported: invalid UTF-8 decoding, or
/// else overlong decoding (searched append first), then each other variant
/// in burp.Zm26 order, at most one issue per variant.
/// `send(payload, append)` returns the response the payload produced.
pub(crate) fn run_input_transformation_check<R, S>(
    append: bool,
    mut rnd: R,
    mut send: S,
) -> Vec<TransformHit>
where
    R: FnMut(usize) -> String,
    S: FnMut(&str, bool) -> Option<Vec<u8>>,
{
    let mut found: Found = Default::default();
    let placements: &[bool] = if append { &[false, true] } else { &[false] };
    for &app in placements {
        let marker = rnd(10);
        let Some(resp) = send(&marker, app) else {
            continue;
        };
        if Needle::new(marker.as_bytes(), true)
            .find(&resp, 0, resp.len())
            .is_none()
        {
            continue;
        }
        if probe(Probe::Overlong, app, &mut rnd, &mut send, &mut found) {
            probe(Probe::Invalid, app, &mut rnd, &mut send, &mut found);
        }
        for p in [Probe::Url, Probe::Backslash, Probe::Html] {
            probe(p, app, &mut rnd, &mut send, &mut found);
        }
    }
    let mut hits = Vec::new();
    let mut take = |variant: usize| -> bool {
        // Zwe8: OVERLONG_UTF8_DECODING_REFLECTION_TYPES lists APPEND first.
        let order: [bool; 2] = if variant == 0 {
            [true, false]
        } else {
            [false, true]
        };
        for app in order {
            if let Some((payload, reflection)) = found[variant][usize::from(app)].take() {
                hits.push(TransformHit {
                    variant: variant as u8,
                    payload,
                    reflection,
                    append: app,
                });
                return true;
            }
        }
        false
    };
    if !take(2) {
        take(0);
    }
    for variant in [1, 3, 4, 5, 6, 7, 8, 9] {
        take(variant);
    }
    hits
}

/// net.portswigger.Zucz.ZW(…, true): line breaks as `<br>`, a tab as
/// " &nbsp;&nbsp;&nbsp;", `<`, `>` and `&` escaped and any other
/// character outside 0x20..=0x7f shown as `.`.
pub(crate) fn burp_html(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '\n' => {
                out.push_str("<br>");
                i += 1;
            }
            '\r' if c.get(i + 1) == Some(&'\n') => {
                out.push_str("<br>");
                i += 2;
            }
            '\r' => i += 1,
            '\t' => {
                out.push_str(" &nbsp;&nbsp;&nbsp;");
                i += 1;
            }
            ' ' => {
                out.push(' ');
                i += 1;
            }
            _ => {
                while i < c.len() && !matches!(c[i], ' ' | '\r' | '\n' | '\t') {
                    match c[i] {
                        '<' => out.push_str("&lt;"),
                        '>' => out.push_str("&gt;"),
                        '&' => out.push_str("&amp;"),
                        ch if (ch as u32) < 0x20 || (ch as u32) > 127 => out.push('.'),
                        ch => out.push(ch),
                    }
                    i += 1;
                }
            }
        }
    }
    out
}

/// burp.Zwvh.ZB: net.portswigger.Zevt.ZM (the bytes Burp's payloads use
/// shown as `[0xNN]`) then Zucz.ZG.
fn burp_display(s: &str) -> String {
    let mut shown = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\u{0}' => shown.push_str("[0x00]"),
            '\r' => shown.push_str("[0x0d]"),
            '\n' => shown.push_str("[0x0a]"),
            '\u{9c}' => shown.push_str("[0x9c]"),
            '\u{ae}' => shown.push_str("[0xae]"),
            '\u{af}' => shown.push_str("[0xaf]"),
            '\u{c0}' => shown.push_str("[0xc0]"),
            '\u{c1}' => shown.push_str("[0xc1]"),
            '\u{81}' => shown.push_str("[0x81]"),
            '\u{1}' => shown.push_str("[0x01]"),
            c => shown.push(c),
        }
    }
    burp_html(&shown)
}

/// burp.Zwvh.Zs: the variants that report an unexpected transformation.
fn unexpected(variant: u8) -> bool {
    matches!(variant, 1 | 3 | 5 | 7 | 9)
}

/// burp.Zwvh.buildIssueDetail for `variant`: `point_bold` is the point in
/// burp.Zsg0.ZD(…, true, true) wording, `point_short` in Zsg0.Zj(…, true,
/// false) wording; `stored` holds the injection and retrieval URLs of the
/// stored type (the lambdas of Zwvh), None for the reflected one.
pub(crate) fn transformation_detail(
    variant: u8,
    point_bold: &str,
    point_short: &str,
    stored: Option<(&str, &str)>,
    payload: &str,
    reflection: &str,
) -> String {
    let mut s = String::from("The application ");
    if unexpected(variant) {
        s.push_str("appears to process the ");
        s.push_str(point_bold);
        s.push_str(", transform ");
        s.push_str(match variant {
            1 => "overlong UTF-8 sequences",
            3 => "invalid UTF-8 sequences",
            7 => "backslash escape sequences",
            5 => "URL-encoded data",
            _ => "HTML-encoded data",
        });
        s.push_str(if stored.is_some() {
            " in an unexpected way, and echo the result in a later response."
        } else {
            " in an unexpected way, and echo the result in the response."
        });
    } else {
        s.push_str("appears to ");
        s.push_str(match variant {
            0 => "decode overlong UTF-8 sequences when processing the",
            2 => "decode invalid UTF-8 sequences when processing the",
            6 => "unescape backslash escape sequences when processing the",
            4 => "URL-decode the",
            _ => "HTML-decode the",
        });
        s.push(' ');
        s.push_str(point_bold);
        s.push_str(if stored.is_some() {
            ", and echo the result in a later response."
        } else {
            ", and echo the result in the response."
        });
    }
    s.push_str("<br><br>The payload <strong>");
    s.push_str(&burp_display(payload));
    s.push_str("</strong>");
    match stored {
        None => {
            s.push_str(" was submitted in the ");
            s.push_str(point_short);
        }
        Some((injection, retrieval)) => {
            s.push_str(" submitted to the URL ");
            s.push_str(&burp_html(injection));
            s.push_str(" is copied into the response for the URL ");
            s.push_str(&burp_html(retrieval));
        }
    }
    let copied = format!(
        " The input was copied into the application's response as <strong>{}</strong>",
        burp_display(reflection)
    );
    let unexpectedly =
        ". This indicates that the application transformed the sequence in some unexpected way.";
    let concatenated = "<br><br>It might be possible to use this behavior to cause the application to differently interpret characters from the start of any data that is concatenated onto the input, by finishing the payload with the start of the multi-character sequence.";
    const OVERLONG: &str = ". This payload contains the overlong UTF-8 sequence [0xc1][0x81] corresponding to the character 'A'.";
    const INVALID: &str = ". This payload contains the invalid UTF-8 sequence [0xc1][0x01] corresponding to the character 'A'. The first byte [0xc1] indicates the start of a two-byte sequence, however the following byte [0x01] is not a valid continuation byte according to the UTF-8 specification.";
    const BACKSLASH: &str = ". This payload contains the '\\\\' sequence, which commonly represents an escaped backslash.";
    const BACKSLASH_TAIL: &str = "<br><br>This behavior indicates that the application might be evaluating the input within some interpreted context, which might give rise to code injection or other issues. It might also be possible to cause the application to differently interpret characters from the start of any data that is concatenated onto the input, by finishing the payload with a single backslash character.";
    const URL: &str =
        ". This payload contains the %41 sequence, corresponding to the character 'A'.";
    const HTML: &str =
        ". This payload contains the HTML entity '&amp#65;' corresponding to the character 'A'.";
    let parts: [&str; 3] = match variant {
        0 => [
            OVERLONG,
            " indicating that the application decoded the overlong UTF-8 sequence as the character 'A'.",
            "<br><br>It might be possible to use this behavior to bypass input validation by submitting overlong UTF-8 encodings of any filtered characters.",
        ],
        1 => [OVERLONG, unexpectedly, concatenated],
        2 => [
            INVALID,
            " indicating that the application decoded the invalid UTF-8 sequence as the character 'A'.",
            "<br><br>It might be possible to use this behavior to bypass input validation by submitting invalid UTF-8 encodings of any filtered characters. It might also be possible to cause the application to differently interpret characters from the start of any data that is concatenated onto the input, by finishing the payload with the start of the multi-character sequence.",
        ],
        3 => [INVALID, unexpectedly, concatenated],
        6 => [
            BACKSLASH,
            " indicating that the application unescaped the '\\\\' sequence as '\\'.",
            BACKSLASH_TAIL,
        ],
        7 => [BACKSLASH, unexpectedly, BACKSLASH_TAIL],
        4 => [
            URL,
            " indicating that the application URL-decoded the sequence.",
            "<br><br>It might be possible to use this behavior to bypass input validation by submitting superfluous URL-encodings of any filtered characters.",
        ],
        5 => [URL, unexpectedly, concatenated],
        8 => [
            HTML,
            " indicating that the application HTML-decoded the entity.",
            "<br><br>It might be possible to use this behavior to bypass input validation by submitting HTML-encodings of any filtered characters.",
        ],
        _ => [HTML, unexpectedly, concatenated],
    };
    s.push_str(parts[0]);
    s.push_str(&copied);
    s.push_str(parts[1]);
    s.push_str(parts[2]);
    if stored.is_some() {
        s.push_str("<br><br>WebProbe has captured the first observed location where this stored input is returned. There might be other locations within the application where the same input is returned. To identify all such locations, perform a full crawl of the application and then do a global search for the highlighted value.");
    }
    s
}

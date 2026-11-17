//! Intruder engine core: payload positions (C-02), the request matrix of the four
//! attack types (C-01), payload sources (C-03) and payload processing (C-04).
//!
//! Pure and independent of the UI and the network, so the matrix is tested on its
//! own; a runner only has to walk what `requests` returns. Positions are written
//! as `§original§` in the request text, exactly like Burp, and the markers never
//! reach the wire: `Template::render` strips them.
//!
//! Sources turn into plain `Vec<String>` sets (`resolve_sets`), which is exactly
//! what the UI stores and what `requests` consumes, so the new types sit beside
//! the existing API instead of replacing it.

use std::collections::HashSet;

use crate::decoder_ops::{self, Op};
use crate::net::parse_markers;
use crate::util;

pub const MARK: char = '§';

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackType {
    /// One set; each position in turn, the others keep their original text.
    Sniper,
    /// One set; the same payload goes into every position at once.
    BatteringRam,
    /// One set per position, walked in lock step; stops at the shortest set.
    Pitchfork,
    /// One set per position; every combination, the last position varying fastest.
    ClusterBomb,
}

impl AttackType {
    pub fn label(self) -> &'static str {
        // Runtime-grounded display strings: burp.Zgu5 enum constants decode to
        // "Sniper attack" / "Battering ram attack" / "Pitchfork attack" /
        // "Cluster bomb attack" (runtime_enums.tsv, runtime.enumConstant:Zgu5).
        match self {
            AttackType::Sniper => "Sniper attack",
            AttackType::BatteringRam => "Battering ram attack",
            AttackType::Pitchfork => "Pitchfork attack",
            AttackType::ClusterBomb => "Cluster bomb attack",
        }
    }

    /// How many payload sets the attack consumes for `positions` positions.
    pub fn sets_needed(self, positions: usize) -> usize {
        match self {
            AttackType::Sniper | AttackType::BatteringRam => 1,
            AttackType::Pitchfork | AttackType::ClusterBomb => positions,
        }
    }
}

/// A request template split at its payload positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// Text between positions; always one more entry than `defaults`.
    literals: Vec<String>,
    /// The original text inside each marker pair.
    defaults: Vec<String>,
}

impl Template {
    pub fn parse(text: &str) -> Result<Self, String> {
        let segments = parse_markers(text);
        if segments.last().map_or(false, |s| s.is_marker) {
            return Err("unbalanced § marker: a position is never closed".into());
        }
        let mut literals = Vec::new();
        let mut defaults = Vec::new();
        for segment in segments {
            if segment.is_marker {
                defaults.push(segment.text);
            } else {
                literals.push(segment.text);
            }
        }
        Ok(Self { literals, defaults })
    }

    pub fn positions(&self) -> usize {
        self.defaults.len()
    }

    /// The request with `values[i]` in position `i`; `None` keeps the original text.
    pub fn render(&self, values: &[Option<&str>]) -> String {
        let mut out = String::new();
        for (i, literal) in self.literals.iter().enumerate() {
            out.push_str(literal);
            if let Some(default) = self.defaults.get(i) {
                out.push_str(values.get(i).copied().flatten().unwrap_or(default));
            }
        }
        out
    }
}

/// One request of an attack and the payload used in each position (`None` where
/// the position kept its original text, which only happens for Sniper).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attack {
    pub payloads: Vec<Option<String>>,
    pub request: String,
}

/// How many requests the attack will make, or `None` when it overflows.
pub fn count(kind: AttackType, positions: usize, set_lens: &[usize]) -> Option<usize> {
    match kind {
        AttackType::Sniper => positions.checked_mul(*set_lens.first()?),
        AttackType::BatteringRam => set_lens.first().copied(),
        AttackType::Pitchfork => set_lens.iter().take(positions).copied().min(),
        AttackType::ClusterBomb => set_lens
            .iter()
            .take(positions)
            .try_fold(1usize, |acc, &n| acc.checked_mul(n)),
    }
}

fn attack(template: &Template, values: &[Option<&str>]) -> Attack {
    Attack {
        payloads: values.iter().map(|v| v.map(str::to_string)).collect(),
        request: template.render(values),
    }
}

/// The full request matrix. `limit` guards against a cluster bomb that would
/// allocate millions of requests before the first one is sent.
pub fn requests(
    template: &Template,
    kind: AttackType,
    sets: &[Vec<String>],
    limit: usize,
) -> Result<Vec<Attack>, String> {
    let n = template.positions();
    if n == 0 {
        return Err("no payload positions: mark at least one with §".into());
    }
    let needed = kind.sets_needed(n);
    if sets.len() < needed {
        return Err(format!(
            "{} needs {needed} payload set(s) for {n} position(s), got {}",
            kind.label(),
            sets.len()
        ));
    }
    if let Some(empty) = sets[..needed].iter().position(|s| s.is_empty()) {
        return Err(format!("payload set {} is empty", empty + 1));
    }
    let lens: Vec<usize> = sets[..needed].iter().map(Vec::len).collect();
    let total = count(kind, n, &lens).ok_or_else(|| "the attack is too large to count".to_string())?;
    if total > limit {
        return Err(format!("{} would send {total} requests, over the limit of {limit}", kind.label()));
    }

    let mut out = Vec::with_capacity(total);
    match kind {
        AttackType::Sniper => {
            for pos in 0..n {
                for payload in &sets[0] {
                    let mut values: Vec<Option<&str>> = vec![None; n];
                    values[pos] = Some(payload.as_str());
                    out.push(attack(template, &values));
                }
            }
        }
        AttackType::BatteringRam => {
            for payload in &sets[0] {
                out.push(attack(template, &vec![Some(payload.as_str()); n]));
            }
        }
        AttackType::Pitchfork => {
            for i in 0..total {
                let values: Vec<Option<&str>> = (0..n).map(|j| Some(sets[j][i].as_str())).collect();
                out.push(attack(template, &values));
            }
        }
        AttackType::ClusterBomb => {
            let mut index = vec![0usize; n];
            for _ in 0..total {
                let values: Vec<Option<&str>> = (0..n).map(|j| Some(sets[j][index[j]].as_str())).collect();
                out.push(attack(template, &values));
                // Odometer: the last position varies fastest.
                for j in (0..n).rev() {
                    index[j] += 1;
                    if index[j] < lens[j] {
                        break;
                    }
                    index[j] = 0;
                }
            }
        }
    }
    Ok(out)
}

// ---------- positions (C-02) ----------

/// Remove every position marker, keeping the original text.
pub fn clear_markers(text: &str) -> String {
    text.chars().filter(|&c| c != MARK).collect()
}

/// Wrap the byte range `start..end` in a position (the editor's selection).
pub fn add_marker(text: &str, start: usize, end: usize) -> Result<String, String> {
    if start > end || end > text.len() || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return Err("the selection is outside the request".into());
    }
    let selected = &text[start..end];
    if selected.contains(MARK) {
        return Err("the selection already contains a position marker".into());
    }
    if text[..start].chars().filter(|&c| c == MARK).count() % 2 == 1 {
        return Err("the selection is inside an existing position".into());
    }
    Ok(format!("{}{MARK}{selected}{MARK}{}", &text[..start], &text[end..]))
}

fn mark_pairs(s: &str, sep: char) -> String {
    s.split(sep)
        .map(|piece| match piece.split_once('=') {
            Some((name, value)) => format!("{name}={MARK}{value}{MARK}"),
            None => piece.to_string(),
        })
        .collect::<Vec<_>>()
        .join(&sep.to_string())
}

fn split_eol(line: &str) -> (&str, &str) {
    if let Some(content) = line.strip_suffix("\r\n") {
        (content, "\r\n")
    } else if let Some(content) = line.strip_suffix('\n') {
        (content, "\n")
    } else {
        (line, "")
    }
}

/// Burp's "Auto §": mark the value of every query parameter, cookie, form body
/// parameter and JSON scalar. Existing markers are cleared first.
pub fn auto_mark(request: &str) -> String {
    let request = clear_markers(request);
    let split = request
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| request.find("\n\n").map(|i| i + 2))
        .unwrap_or(request.len());
    let (head, body) = request.split_at(split);
    let head_lower = head.to_ascii_lowercase();

    let mut out = String::new();
    for (i, line) in head.split_inclusive('\n').enumerate() {
        let (content, eol) = split_eol(line);
        if i == 0 {
            let mut parts = content.splitn(3, ' ');
            let (method, target, rest) = (parts.next(), parts.next(), parts.next());
            match (method, target, rest) {
                (Some(method), Some(target), Some(rest)) if target.contains('?') => {
                    let (path, query) = target.split_once('?').unwrap_or((target, ""));
                    out.push_str(&format!("{method} {path}?{} {rest}{eol}", mark_pairs(query, '&')));
                }
                _ => out.push_str(line),
            }
        } else if content.get(..7).map_or(false, |p| p.eq_ignore_ascii_case("cookie:")) {
            out.push_str(&format!("{}{}{eol}", &content[..7], mark_pairs(&content[7..], ';')));
        } else {
            out.push_str(line);
        }
    }

    let trimmed = body.trim_end_matches(|c| c == '\r' || c == '\n');
    let tail = &body[trimmed.len()..];
    if head_lower.contains("application/x-www-form-urlencoded") {
        out.push_str(&mark_pairs(trimmed, '&'));
        out.push_str(tail);
    } else if head_lower.contains("json") {
        let re = regex::Regex::new(
            r#"("(?:[^"\\]|\\.)*"\s*:\s*)(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?|true|false|null))"#,
        )
        .expect("static pattern");
        let marked = re.replace_all(trimmed, |caps: &regex::Captures| match caps.get(2) {
            Some(text) => format!("{}\"{MARK}{}{MARK}\"", &caps[1], text.as_str()),
            None => format!("{}{MARK}{}{MARK}", &caps[1], &caps[3]),
        });
        out.push_str(&marked);
        out.push_str(tail);
    } else {
        out.push_str(body);
    }
    out
}

// ---------- payload sources (C-03) ----------

/// Hard cap on a generated set, so a brute forcer or an open-ended number range
/// cannot exhaust memory before the request limit ever sees it.
pub const MAX_PAYLOADS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberBase {
    Decimal,
    Hex,
}

impl NumberBase {
    fn render(self, magnitude: u64) -> String {
        match self {
            NumberBase::Decimal => magnitude.to_string(),
            NumberBase::Hex => format!("{magnitude:x}"),
        }
    }
}

/// Where a payload set comes from. `generate` is deterministic: the same source
/// always yields the same list, in the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadSource {
    /// The list as typed, one payload per entry.
    SimpleList { items: Vec<String> },
    /// Lines of a file, read when the set is generated (not when it is edited).
    RuntimeFile { path: String },
    /// An arithmetic run in base 10 or 16, zero-padded to `min_digits`.
    Numbers {
        from: i64,
        to: i64,
        step: i64,
        base: NumberBase,
        min_digits: usize,
        fraction_digits: usize,
    },
    /// Every combination over `charset`, shortest first, charset order preserved.
    BruteForcer { charset: String, min_len: usize, max_len: usize },
    /// Unix timestamps rendered with a strftime subset, UTC only.
    Dates { from: u64, to: u64, step_secs: u64, format: String },
    /// The base string repeated and truncated to each length in the range.
    CharacterBlocks { base: String, min_len: usize, max_len: usize },
}

impl PayloadSource {
    /// The payloads this source produces. Unreadable files and empty alphabets
    /// yield an empty set; nothing here panics or blocks.
    pub fn generate(&self) -> Vec<String> {
        match self {
            PayloadSource::SimpleList { items } => items.clone(),
            PayloadSource::RuntimeFile { path } => match std::fs::read_to_string(path) {
                Ok(text) => read_payload_lines(&text),
                Err(_) => Vec::new(),
            },
            PayloadSource::Numbers { from, to, step, base, min_digits, fraction_digits } => {
                let step = if *step == 0 { 1 } else { *step };
                number_run(*from, *to, step)
                    .map(|v| format_number(v, *base, *min_digits, *fraction_digits))
                    .collect()
            }
            PayloadSource::BruteForcer { charset, min_len, max_len } => {
                let alphabet: Vec<char> = charset.chars().collect();
                if alphabet.is_empty() || min_len > max_len {
                    return Vec::new();
                }
                let mut out = Vec::new();
                for len in *min_len..=*max_len {
                    let mut index = vec![0usize; len];
                    loop {
                        if out.len() >= MAX_PAYLOADS {
                            return out;
                        }
                        out.push(index.iter().map(|&i| alphabet[i]).collect());
                        // Odometer: the last character varies fastest.
                        let mut j = len;
                        let mut carry = true;
                        while j > 0 && carry {
                            j -= 1;
                            index[j] += 1;
                            if index[j] < alphabet.len() {
                                carry = false;
                            } else {
                                index[j] = 0;
                            }
                        }
                        if carry {
                            break;
                        }
                    }
                }
                out
            }
            PayloadSource::Dates { from, to, step_secs, format } => {
                let step = if *step_secs == 0 { 1 } else { *step_secs };
                date_run(*from, *to, step)
                    .map(|t| format_date(t, format))
                    .collect()
            }
            PayloadSource::CharacterBlocks { base, min_len, max_len } => {
                let chars: Vec<char> = base.chars().collect();
                if chars.is_empty() || min_len > max_len {
                    return Vec::new();
                }
                (*min_len..=*max_len)
                    .take(MAX_PAYLOADS)
                    .map(|len| chars.iter().copied().cycle().take(len).collect())
                    .collect()
            }
        }
    }

    /// How many payloads `generate` would return. Cheap except for `RuntimeFile`,
    /// which has to read the file to count its lines.
    pub fn len(&self) -> usize {
        match self {
            PayloadSource::SimpleList { items } => items.len(),
            PayloadSource::RuntimeFile { path } => std::fs::read_to_string(path)
                .map(|text| read_payload_lines(&text).len())
                .unwrap_or(0),
            PayloadSource::Numbers { from, to, step, .. } => {
                number_run(*from, *to, if *step == 0 { 1 } else { *step }).count()
            }
            PayloadSource::BruteForcer { charset, min_len, max_len } => {
                let n = charset.chars().count();
                if n == 0 || min_len > max_len {
                    return 0;
                }
                let mut total = 0usize;
                for len in *min_len..=*max_len {
                    total = total.saturating_add(n.saturating_pow(len as u32)).min(MAX_PAYLOADS);
                }
                total
            }
            PayloadSource::Dates { from, to, step_secs, .. } => {
                date_run(*from, *to, if *step_secs == 0 { 1 } else { *step_secs }).count()
            }
            PayloadSource::CharacterBlocks { base, min_len, max_len } => {
                if base.is_empty() || min_len > max_len {
                    0
                } else {
                    (max_len - min_len + 1).min(MAX_PAYLOADS)
                }
            }
        }
    }
}

/// `generate` for every source, in order — the payload sets an attack consumes.
pub fn resolve_sets(sources: &[PayloadSource]) -> Vec<Vec<String>> {
    sources.iter().map(PayloadSource::generate).collect()
}

/// Payload lines: trailing CR stripped, empty lines dropped.
fn read_payload_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

/// The numbers of a run, capped at `MAX_PAYLOADS`; an empty or inverted range
/// yields nothing. Iterates without materialising, so `len` stays cheap.
fn number_run(from: i64, to: i64, step: i64) -> impl Iterator<Item = i64> {
    let step = step.abs();
    let mut current = from;
    std::iter::from_fn(move || {
        if (step > 0 && current > to) || (step == 0) {
            return None;
        }
        let value = current;
        current = current.saturating_add(step);
        Some(value)
    })
    .take(MAX_PAYLOADS)
}

fn format_number(value: i64, base: NumberBase, min_digits: usize, fraction_digits: usize) -> String {
    let magnitude = value.unsigned_abs();
    let digits = base.render(magnitude);
    let padded = format!("{digits:0>min_digits$}");
    let mut out = String::new();
    if value < 0 {
        out.push('-');
    }
    out.push_str(&padded);
    if fraction_digits > 0 {
        out.push('.');
        out.extend(std::iter::repeat('0').take(fraction_digits));
    }
    out
}

fn date_run(from: u64, to: u64, step: u64) -> impl Iterator<Item = u64> {
    let mut current = from;
    std::iter::from_fn(move || {
        if current > to {
            return None;
        }
        let value = current;
        current = current.saturating_add(step);
        Some(value)
    })
    .take(MAX_PAYLOADS)
}

/// Days since the Unix epoch to a (year, month, day) civil date (UTC), after
/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// strftime subset for Intruder dates: `%Y %m %d %H %M %S %s`, plus `%%`.
/// Anything else is copied through untouched.
fn format_date(secs: u64, format: &str) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let mut out = String::with_capacity(format.len() + 8);
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{year:04}")),
            Some('m') => out.push_str(&format!("{month:02}")),
            Some('d') => out.push_str(&format!("{day:02}")),
            Some('H') => out.push_str(&format!("{hour:02}")),
            Some('M') => out.push_str(&format!("{minute:02}")),
            Some('S') => out.push_str(&format!("{second:02}")),
            Some('s') => out.push_str(&secs.to_string()),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

// ---------- payload processing (C-04) ----------

/// One rule in an ordered payload-processing pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processor {
    AddPrefix(String),
    AddSuffix(String),
    /// `regex` is a Rust `regex` pattern; `$1`-style group references work.
    MatchReplace { regex: String, replacement: String },
    /// Character offsets, `-1` = last character, both ends clamped; `end` is
    /// exclusive, so `-3..-1` keeps the last two characters.
    Substring { start: i64, end: i64 },
    Reverse,
    Lowercase,
    Uppercase,
    Base64Encode,
    Base64Decode,
    /// Percent-encode every byte, including unreserved characters.
    UrlEncodeAll,
    /// Percent-encode only the characters that are unsafe in a URL key.
    UrlEncodeKey,
    HtmlEncode,
    HexEncode,
    Md5,
    Sha1,
    Sha256,
    /// Drop the payload from the set when the pattern matches.
    SkipIfMatches { regex: String },
    /// Dedupe the set; `max` 0 means unlimited. A set-level rule, so `process`
    /// passes the payload through and `process_set` does the work.
    MakeUnique { max: usize },
}

/// Apply `rules` in order to one payload. `None` means a skip rule matched.
/// Invalid regexes and undecodable Base64 leave the payload unchanged instead
/// of failing the whole attack.
pub fn process(payload: &str, rules: &[Processor]) -> Option<String> {
    let mut current = payload.to_string();
    for rule in rules {
        match rule {
            Processor::AddPrefix(prefix) => current = format!("{prefix}{current}"),
            Processor::AddSuffix(suffix) => current = format!("{current}{suffix}"),
            Processor::MatchReplace { regex, replacement } => {
                if let Ok(re) = regex::Regex::new(regex) {
                    current = re.replace_all(&current, replacement.as_str()).into_owned();
                }
            }
            Processor::Substring { start, end } => current = substring(&current, *start, *end),
            Processor::Reverse => current = current.chars().rev().collect(),
            Processor::Lowercase => current = current.to_lowercase(),
            Processor::Uppercase => current = current.to_uppercase(),
            Processor::Base64Encode => current = util::b64_encode(current.as_bytes()),
            Processor::Base64Decode => {
                if let Ok(decoded) = decoder_ops::apply(Op::Base64Decode, &current) {
                    current = decoded;
                }
            }
            Processor::UrlEncodeAll => current = url_encode_all(&current),
            Processor::UrlEncodeKey => current = util::url_encode_key(&current),
            Processor::HtmlEncode => current = util::html_encode(&current),
            Processor::HexEncode => current = util::hex_encode(current.as_bytes()),
            Processor::Md5 => current = digest(Op::Md5, &current),
            Processor::Sha1 => current = digest(Op::Sha1, &current),
            Processor::Sha256 => current = digest(Op::Sha256, &current),
            Processor::SkipIfMatches { regex } => {
                if regex::Regex::new(regex).map_or(false, |re| re.is_match(&current)) {
                    return None;
                }
            }
            Processor::MakeUnique { .. } => {}
        }
    }
    Some(current)
}

/// Apply the pipeline to a whole set: skip rules drop payloads, and any
/// `MakeUnique` rule dedupes the result (capped by its `max`, 0 = unlimited).
pub fn process_set(set: &[String], rules: &[Processor]) -> Vec<String> {
    let unique = rules.iter().find_map(|rule| match rule {
        Processor::MakeUnique { max } => Some(*max),
        _ => None,
    });
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(set.len());
    for payload in set {
        let Some(value) = process(payload, rules) else { continue };
        if unique.is_some() {
            if !seen.insert(value.clone()) {
                continue;
            }
            if let Some(max) = unique.filter(|max| *max > 0) {
                if out.len() >= max {
                    continue;
                }
            }
        }
        out.push(value);
    }
    out
}

fn digest(op: Op, input: &str) -> String {
    decoder_ops::apply(op, input).unwrap_or_else(|_| input.to_string())
}

fn url_encode_all(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        out.push_str(&format!("%{byte:02X}"));
    }
    out
}

fn substring(input: &str, start: i64, end: i64) -> String {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len() as i64;
    let clamp = |index: i64| {
        if index < 0 {
            (len + index).max(0)
        } else {
            index.min(len)
        }
    };
    let (from, to) = (clamp(start), clamp(end));
    if from >= to {
        String::new()
    } else {
        chars[from as usize..to as usize].iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn reqs(attacks: &[Attack]) -> Vec<&str> {
        attacks.iter().map(|a| a.request.as_str()).collect()
    }

    #[test]
    fn parse_splits_positions_and_render_strips_markers() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        assert_eq!(t.positions(), 2);
        assert_eq!(t.render(&[None, None]), "a1b2c");
        assert_eq!(t.render(&[Some("x"), None]), "axb2c");
        assert!(!t.render(&[None, None]).contains(MARK));
    }

    #[test]
    fn unbalanced_marker_is_rejected() {
        assert!(Template::parse("a§1§b§2c").is_err());
    }

    #[test]
    fn sniper_walks_each_position_with_the_others_untouched() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(&t, AttackType::Sniper, &[set(&["x", "y"])], 100).unwrap();
        assert_eq!(reqs(&out), ["axb2c", "ayb2c", "a1bxc", "a1byc"]);
        assert_eq!(out[0].payloads, vec![Some("x".to_string()), None]);
        assert_eq!(count(AttackType::Sniper, 2, &[2]), Some(4));
    }

    #[test]
    fn battering_ram_puts_one_payload_everywhere() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(&t, AttackType::BatteringRam, &[set(&["x", "y"])], 100).unwrap();
        assert_eq!(reqs(&out), ["axbxc", "aybyc"]);
    }

    #[test]
    fn pitchfork_walks_in_lock_step_and_stops_at_the_shortest_set() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(&t, AttackType::Pitchfork, &[set(&["x", "y", "z"]), set(&["1", "2"])], 100).unwrap();
        assert_eq!(reqs(&out), ["axb1c", "ayb2c"]);
    }

    #[test]
    fn cluster_bomb_tries_every_combination_last_position_fastest() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        let out = requests(&t, AttackType::ClusterBomb, &[set(&["A", "B"]), set(&["1", "2"])], 100).unwrap();
        assert_eq!(reqs(&out), ["aAb1c", "aAb2c", "aBb1c", "aBb2c"]);

        let t3 = Template::parse("§a§§b§§c§").unwrap();
        let sets = [set(&["1", "2"]), set(&["3", "4"]), set(&["5", "6"])];
        assert_eq!(requests(&t3, AttackType::ClusterBomb, &sets, 100).unwrap().len(), 8);
    }

    #[test]
    fn bad_input_is_reported_not_swallowed() {
        let t = Template::parse("a§1§b§2§c").unwrap();
        assert!(requests(&t, AttackType::Pitchfork, &[set(&["x"])], 100).is_err(), "needs two sets");
        assert!(requests(&t, AttackType::Sniper, &[set(&[])], 100).is_err(), "empty set");
        assert!(requests(&t, AttackType::ClusterBomb, &[set(&["a", "b"]), set(&["c", "d"])], 3).is_err(), "over the limit");
        assert!(requests(&Template::parse("no positions").unwrap(), AttackType::Sniper, &[set(&["x"])], 100).is_err());
        assert_eq!(count(AttackType::ClusterBomb, 2, &[usize::MAX, 2]), None, "overflow");
    }

    #[test]
    fn add_and_clear_markers() {
        let text = "GET /a?b=1 HTTP/1.1";
        let marked = add_marker(text, 9, 10).unwrap();
        assert_eq!(marked, "GET /a?b=§1§ HTTP/1.1");
        assert_eq!(clear_markers(&marked), text);
        assert!(add_marker(&marked, 9, 12).is_err(), "selection contains a marker");
        assert!(add_marker(&marked, 11, 12).is_err(), "selection sits inside a position");
        assert!(add_marker(text, 5, 99).is_err(), "out of range");
    }

    #[test]
    fn auto_mark_covers_query_cookie_form_and_json() {
        let get = "GET /p?a=1&b=2 HTTP/1.1\r\nHost: h\r\nCookie: s=abc; t=9\r\n\r\n";
        assert_eq!(
            auto_mark(get),
            "GET /p?a=§1§&b=§2§ HTTP/1.1\r\nHost: h\r\nCookie: s=§abc§; t=§9§\r\n\r\n"
        );

        let form = "POST /l HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nu=bob&p=pw";
        assert!(auto_mark(form).ends_with("\r\n\r\nu=§bob§&p=§pw§"));

        let json = "POST /l HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"u\":\"bob\",\"n\":5,\"ok\":true}";
        assert!(auto_mark(json).ends_with("{\"u\":\"§bob§\",\"n\":§5§,\"ok\":§true§}"));

        // Existing markers are replaced, not nested.
        assert_eq!(auto_mark("GET /p?a=§1§ HTTP/1.1\r\n\r\n"), "GET /p?a=§1§ HTTP/1.1\r\n\r\n");
    }

    // ---------- payload sources (C-03) ----------

    fn temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("webprobe-intruder-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn simple_list_generates_verbatim_in_order() {
        let source = PayloadSource::SimpleList { items: set(&["admin", "root", ""]) };
        assert_eq!(source.generate(), ["admin", "root", ""]);
        assert_eq!(source.len(), 3);
    }

    #[test]
    fn runtime_file_reads_lines_skips_blanks_and_trims_cr() {
        let path = temp_file("payloads.txt", "one\r\ntwo\n\nthree\n");
        let source = PayloadSource::RuntimeFile { path: path.to_string_lossy().into_owned() };
        assert_eq!(source.generate(), ["one", "two", "three"]);
        assert_eq!(source.len(), 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn runtime_file_missing_is_empty_not_a_panic() {
        let path = std::env::temp_dir().join(format!("webprobe-intruder-{}-missing.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let source = PayloadSource::RuntimeFile { path: path.to_string_lossy().into_owned() };
        assert!(source.generate().is_empty());
        assert_eq!(source.len(), 0);
    }

    #[test]
    fn numbers_pad_in_decimal_and_hex() {
        let decimal = PayloadSource::Numbers {
            from: 8,
            to: 10,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 3,
            fraction_digits: 0,
        };
        assert_eq!(decimal.generate(), ["008", "009", "010"]);
        assert_eq!(decimal.len(), 3);

        let hex = PayloadSource::Numbers {
            from: 10,
            to: 12,
            step: 1,
            base: NumberBase::Hex,
            min_digits: 2,
            fraction_digits: 0,
        };
        assert_eq!(hex.generate(), ["0a", "0b", "0c"]);
    }

    #[test]
    fn numbers_handle_fractions_negatives_and_zero_step() {
        let fractional = PayloadSource::Numbers {
            from: 1,
            to: 2,
            step: 0, // rejected, treated as 1
            base: NumberBase::Decimal,
            min_digits: 3,
            fraction_digits: 2,
        };
        assert_eq!(fractional.generate(), ["001.00", "002.00"]);

        let negative = PayloadSource::Numbers {
            from: -2,
            to: 0,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 1,
            fraction_digits: 0,
        };
        assert_eq!(negative.generate(), ["-2", "-1", "0"]);

        let inverted = PayloadSource::Numbers {
            from: 5,
            to: 1,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 1,
            fraction_digits: 0,
        };
        assert!(inverted.generate().is_empty());
    }

    #[test]
    fn brute_forcer_is_lexicographic_with_the_charset_as_given() {
        let source = PayloadSource::BruteForcer { charset: "ba".into(), min_len: 1, max_len: 2 };
        assert_eq!(source.generate(), ["b", "a", "bb", "ba", "ab", "aa"]);
        assert_eq!(source.len(), 6);
        assert!(PayloadSource::BruteForcer { charset: String::new(), min_len: 1, max_len: 2 }
            .generate()
            .is_empty());
    }

    #[test]
    fn brute_forcer_caps_total_payloads() {
        let source = PayloadSource::BruteForcer { charset: "abcdefghij".into(), min_len: 1, max_len: 7 };
        assert_eq!(source.len(), MAX_PAYLOADS);
        assert_eq!(source.generate().len(), MAX_PAYLOADS);
    }

    #[test]
    fn dates_use_the_strftime_subset_in_utc() {
        let source = PayloadSource::Dates {
            from: 0,
            to: 86_400,
            step_secs: 86_400,
            format: "%Y-%m-%d %H:%M:%S %s".into(),
        };
        assert_eq!(source.generate(), ["1970-01-01 00:00:00 0", "1970-01-02 00:00:00 86400"]);
        assert_eq!(source.len(), 2);

        assert_eq!(
            format_date(1_700_000_000, "%Y/%m/%d %H:%M"),
            "2023/11/14 22:13"
        );
        assert_eq!(format_date(1_700_000_000, "%d%%%q"), "14%%q");
        // A zero step still advances one second instead of looping forever.
        assert_eq!(
            PayloadSource::Dates { from: 5, to: 6, step_secs: 0, format: "%s".into() }.generate(),
            ["5", "6"]
        );
    }

    #[test]
    fn character_blocks_repeat_and_truncate_the_base() {
        let source = PayloadSource::CharacterBlocks { base: "ab".into(), min_len: 1, max_len: 3 };
        assert_eq!(source.generate(), ["a", "ab", "aba"]);
        assert_eq!(source.len(), 3);
        assert!(PayloadSource::CharacterBlocks { base: String::new(), min_len: 1, max_len: 3 }
            .generate()
            .is_empty());
    }

    #[test]
    fn resolve_sets_turns_each_source_into_its_list() {
        let sources = [
            PayloadSource::SimpleList { items: set(&["x", "y"]) },
            PayloadSource::Numbers {
                from: 1,
                to: 2,
                step: 1,
                base: NumberBase::Decimal,
                min_digits: 1,
                fraction_digits: 0,
            },
        ];
        assert_eq!(resolve_sets(&sources), vec![set(&["x", "y"]), set(&["1", "2"])]);
    }

    // ---------- payload processing (C-04) ----------

    #[test]
    fn prefix_and_suffix_wrap_the_payload() {
        let rules = [Processor::AddPrefix("pre".into()), Processor::AddSuffix("post".into())];
        assert_eq!(process("x", &rules).unwrap(), "prexpost");
    }

    #[test]
    fn match_replace_uses_capture_groups() {
        let rules = [Processor::MatchReplace { regex: r"(\w+)=(\d+)".into(), replacement: "$2=$1".into() }];
        assert_eq!(process("user=123", &rules).unwrap(), "123=user");
        assert_eq!(process("nothing", &rules).unwrap(), "nothing");
    }

    #[test]
    fn invalid_regex_is_skipped_not_fatal() {
        let rules = [
            Processor::MatchReplace { regex: "(".into(), replacement: "x".into() },
            Processor::SkipIfMatches { regex: "[".into() },
        ];
        assert_eq!(process("keep", &rules).unwrap(), "keep");
    }

    #[test]
    fn substring_counts_from_the_end_and_clamps() {
        assert_eq!(substring("abcdef", -3, -1), "de");
        assert_eq!(substring("abcdef", 0, 3), "abc");
        assert_eq!(substring("abcdef", 2, -1), "cde");
        assert_eq!(substring("abcdef", -100, 2), "ab");
        assert_eq!(substring("abcdef", 10, 20), "");
        assert_eq!(process("abcdef", &[Processor::Substring { start: -1, end: 6 }]).unwrap(), "f");
    }

    #[test]
    fn case_and_reverse_transform_the_whole_payload() {
        assert_eq!(process("aBc", &[Processor::Reverse]).unwrap(), "cBa");
        assert_eq!(process("aBc", &[Processor::Lowercase]).unwrap(), "abc");
        assert_eq!(process("aBc", &[Processor::Uppercase]).unwrap(), "ABC");
    }

    #[test]
    fn base64_encodes_and_decodes_and_survives_bad_input() {
        assert_eq!(process("hi", &[Processor::Base64Encode]).unwrap(), "aGk=");
        assert_eq!(
            process("aGk=", &[Processor::Base64Decode]).unwrap(),
            "hi"
        );
        assert_eq!(process("!!!", &[Processor::Base64Decode]).unwrap(), "!!!");
    }

    #[test]
    fn url_encode_all_differs_from_key_encoding() {
        assert_eq!(process("a b", &[Processor::UrlEncodeAll]).unwrap(), "%61%20%62");
        assert_eq!(process("a b", &[Processor::UrlEncodeKey]).unwrap(), "a%20b");
    }

    #[test]
    fn html_and_hex_encoding() {
        assert_eq!(process("<a&b>", &[Processor::HtmlEncode]).unwrap(), "&lt;a&amp;b&gt;");
        assert_eq!(process("hi", &[Processor::HexEncode]).unwrap(), "6869");
    }

    #[test]
    fn hashes_match_known_vectors() {
        assert_eq!(process("abc", &[Processor::Md5]).unwrap(), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            process("abc", &[Processor::Sha1]).unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            process("abc", &[Processor::Sha256]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn skip_rule_drops_the_payload() {
        let rules = [Processor::SkipIfMatches { regex: r"\d+".into() }];
        assert_eq!(process("abc123", &rules), None);
        assert_eq!(process("abc", &rules).as_deref(), Some("abc"));
    }

    #[test]
    fn pipeline_order_is_respected() {
        let encode_then_prefix = [Processor::Base64Encode, Processor::AddPrefix("x".into())];
        let prefix_then_encode = [Processor::AddPrefix("x".into()), Processor::Base64Encode];
        assert_eq!(process("hi", &encode_then_prefix).unwrap(), "xaGk=");
        assert_eq!(process("hi", &prefix_then_encode).unwrap(), "eGhp");
        assert_ne!(
            process("hi", &encode_then_prefix).unwrap(),
            process("hi", &prefix_then_encode).unwrap()
        );
    }

    #[test]
    fn make_unique_dedupes_and_caps_the_set() {
        let set = set(&["a", "a", "b", "a", "c"]);
        assert_eq!(process_set(&set, &[Processor::MakeUnique { max: 0 }]), ["a", "b", "c"]);
        assert_eq!(process_set(&set, &[Processor::MakeUnique { max: 2 }]), ["a", "b"]);
    }

    #[test]
    fn process_set_without_make_unique_keeps_duplicates() {
        assert_eq!(process_set(&set(&["a", "a", "b"]), &[]), ["a", "a", "b"]);
    }

    #[test]
    fn process_set_drops_skipped_payloads() {
        let rules = [
            Processor::SkipIfMatches { regex: r"^\d".into() },
            Processor::AddPrefix("u_".into()),
        ];
        assert_eq!(process_set(&set(&["bob", "1eve", "eve"]), &rules), ["u_bob", "u_eve"]);
    }

    #[test]
    fn open_ended_number_ranges_stop_at_the_cap() {
        let source = PayloadSource::Numbers {
            from: 0,
            to: i64::MAX,
            step: 1,
            base: NumberBase::Decimal,
            min_digits: 1,
            fraction_digits: 0,
        };
        assert_eq!(source.len(), MAX_PAYLOADS);
    }

    #[test]
    fn skip_rules_see_the_value_after_earlier_rules() {
        let rules = [
            Processor::Base64Encode,
            Processor::SkipIfMatches { regex: "^aG".into() },
        ];
        assert_eq!(process("hi", &rules), None, "skipped after encoding");
        assert_eq!(
            process("hi", &[Processor::SkipIfMatches { regex: "^aG".into() }, Processor::Base64Encode])
                .as_deref(),
            Some("aGk="),
            "skip runs before the encoding when listed first"
        );
    }

    #[test]
    fn processed_sets_feed_the_attack_matrix() {
        let template = Template::parse("u=§a§&p=§b§").unwrap();
        let sources = [
            PayloadSource::Numbers {
                from: 1,
                to: 3,
                step: 1,
                base: NumberBase::Decimal,
                min_digits: 2,
                fraction_digits: 0,
            },
            PayloadSource::SimpleList { items: set(&["x", "y"]) },
        ];
        let rules = [Processor::AddPrefix("v".into())];
        let sets: Vec<Vec<String>> = resolve_sets(&sources)
            .iter()
            .map(|set| process_set(set, &rules))
            .collect();
        assert_eq!(sets, vec![set(&["v01", "v02", "v03"]), set(&["vx", "vy"])]);

        let attacks = requests(&template, AttackType::ClusterBomb, &sets, 100).unwrap();
        assert_eq!(attacks.len(), 6);
        assert_eq!(attacks[0].request, "u=v01&p=vx");
        assert_eq!(attacks[5].request, "u=v03&p=vy");
        assert_eq!(count(AttackType::ClusterBomb, 2, &[3, 2]), Some(6));
    }
}

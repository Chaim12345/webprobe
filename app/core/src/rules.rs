//! Match-and-replace rules for HTTP messages.
//!
//! The scope names and order come from the Burp Suite reference tree; the rule
//! defaults are verified in live build 52685 `burp.Zmo7.<init>` (`0007`–`0016`).
//! Matching is literal byte matching
//! unless the rule is marked as a regular expression. Literal replacements
//! operate directly on bytes, so non-UTF-8 bodies and other binary data are
//! preserved outside the replaced spans.

use std::borrow::Cow;
use std::ops::Range;

use regex::bytes::Regex;

/// The part of an HTTP message a rule edits.
///
/// Header scopes cover the header lines after the first line. Parameter
/// scopes cover the names or values of query-string parameters and of
/// `application/x-www-form-urlencoded` request-body parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MrScope {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
    RequestParamName,
    RequestParamValue,
    RequestFirstLine,
}

impl MrScope {
    /// Scopes in the order used by Burp's HTTP match/replace editor.
    pub const ALL: [MrScope; 7] = [
        MrScope::RequestHeader,
        MrScope::RequestBody,
        MrScope::ResponseHeader,
        MrScope::ResponseBody,
        MrScope::RequestParamName,
        MrScope::RequestParamValue,
        MrScope::RequestFirstLine,
    ];

    /// Display name used by Burp's direction selector.
    pub const fn label(self) -> &'static str {
        match self {
            MrScope::RequestHeader => "Request header",
            MrScope::RequestBody => "Request body",
            MrScope::ResponseHeader => "Response header",
            MrScope::ResponseBody => "Response body",
            MrScope::RequestParamName => "Request param name",
            MrScope::RequestParamValue => "Request param value",
            MrScope::RequestFirstLine => "Request first line",
        }
    }

    /// True for scopes that edit requests rather than responses.
    pub const fn is_request(self) -> bool {
        match self {
            MrScope::RequestHeader
            | MrScope::RequestBody
            | MrScope::RequestParamName
            | MrScope::RequestParamValue
            | MrScope::RequestFirstLine => true,
            MrScope::ResponseHeader | MrScope::ResponseBody => false,
        }
    }

    /// Default scope for a newly added request or response rule.
    pub const fn default_for(request_side: bool) -> Self {
        if request_side {
            MrScope::RequestHeader
        } else {
            MrScope::ResponseHeader
        }
    }
}

/// One match-and-replace rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MrRule {
    pub enabled: bool,
    pub match_: String,
    pub replacement: String,
    pub is_regex: bool,
    pub comment: String,
    pub scope: MrScope,
}

impl MrRule {
    /// New enabled literal rule with empty match, replacement, and comment.
    pub fn new(scope: MrScope) -> Self {
        Self {
            enabled: true,
            match_: String::new(),
            replacement: String::new(),
            is_regex: false,
            comment: String::new(),
            scope,
        }
    }

    /// New enabled literal rule with the default scope for one message side.
    pub fn default_for(request_side: bool) -> Self {
        Self::new(MrScope::default_for(request_side))
    }

    /// True when the rule will be considered by [`apply_rules`].
    pub fn is_active(&self) -> bool {
        self.enabled && !self.match_.is_empty() && self.pattern_is_valid()
    }

    /// Empty patterns are valid but inactive. Invalid regexes are rejected.
    pub fn pattern_is_valid(&self) -> bool {
        !self.is_regex || Regex::new(&self.match_).is_ok()
    }
}

impl Default for MrRule {
    fn default() -> Self {
        Self::new(MrScope::RequestHeader)
    }
}

/// Apply every enabled rule to `bytes`, in order, each rule seeing the result
/// of the previous one. Empty patterns, invalid regexes, and rules whose scope
/// belongs to the other side of the message are skipped.
pub fn apply_rules(bytes: &[u8], rules: &[MrRule]) -> Vec<u8> {
    let mut current: Option<Vec<u8>> = None;
    for rule in rules {
        let input = current.as_deref().unwrap_or(bytes);
        if let Some(next) = apply_rule(input, rule) {
            current = Some(next);
        }
    }
    current.unwrap_or_else(|| bytes.to_vec())
}

struct HttpParts {
    first_line_end: usize,
    header_start: usize,
    header_end: usize,
    body_start: usize,
    is_response: bool,
}

struct Edit {
    start: usize,
    end: usize,
    replacement: Vec<u8>,
}

enum MatchEngine<'a> {
    Literal(&'a [u8]),
    Regex(Regex),
}

impl<'a> MatchEngine<'a> {
    fn new(rule: &'a MrRule) -> Option<Self> {
        if rule.match_.is_empty() {
            return None;
        }
        if rule.is_regex {
            Regex::new(&rule.match_)
                .ok()
                .map(MatchEngine::Regex)
        } else {
            Some(MatchEngine::Literal(rule.match_.as_bytes()))
        }
    }
}

fn apply_rule(bytes: &[u8], rule: &MrRule) -> Option<Vec<u8>> {
    if !rule.enabled || rule.match_.is_empty() {
        return None;
    }
    let engine = MatchEngine::new(rule)?;
    let parts = parse_http(bytes);
    if rule.scope.is_request() == parts.is_response {
        return None;
    }

    match rule.scope {
        MrScope::RequestFirstLine => {
            let replaced = replace_target(
                &bytes[..parts.first_line_end],
                &engine,
                rule.replacement.as_bytes(),
            )?;
            Some(replace_span(
                bytes,
                0,
                parts.first_line_end,
                &replaced,
            ))
        }
        MrScope::RequestHeader | MrScope::ResponseHeader => {
            apply_header(bytes, &parts, &engine, rule.replacement.as_bytes())
        }
        MrScope::RequestBody | MrScope::ResponseBody => {
            if parts.body_start >= bytes.len() {
                return None;
            }
            let replaced = replace_target(
                &bytes[parts.body_start..],
                &engine,
                rule.replacement.as_bytes(),
            )?;
            Some(replace_span(
                bytes,
                parts.body_start,
                bytes.len(),
                &replaced,
            ))
        }
        MrScope::RequestParamName | MrScope::RequestParamValue => {
            apply_params(
                bytes,
                &parts,
                rule.scope == MrScope::RequestParamName,
                &engine,
                rule.replacement.as_bytes(),
            )
        }
    }
}

fn replace_target(
    target: &[u8],
    engine: &MatchEngine<'_>,
    replacement: &[u8],
) -> Option<Vec<u8>> {
    match engine {
        MatchEngine::Literal(needle) => {
            replace_literal_all(target, needle, replacement)
        }
        MatchEngine::Regex(regex) => match regex.replace_all(target, replacement) {
            Cow::Owned(bytes) => Some(bytes),
            Cow::Borrowed(_) => None,
        },
    }
}

fn replace_literal_all(
    haystack: &[u8],
    needle: &[u8],
    replacement: &[u8],
) -> Option<Vec<u8>> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }

    let mut out: Option<Vec<u8>> = None;
    let mut last = 0;
    let mut search = 0;

    while search + needle.len() <= haystack.len() {
        let Some(relative) = find_subslice(&haystack[search..], needle) else {
            break;
        };
        let at = search + relative;
        let out = out.get_or_insert_with(|| {
            Vec::with_capacity(
                haystack
                    .len()
                    .saturating_add(replacement.len().saturating_sub(needle.len())),
            )
        });
        out.extend_from_slice(&haystack[last..at]);
        out.extend_from_slice(replacement);
        last = at + needle.len();
        search = last;
    }

    let mut out = out?;
    out.extend_from_slice(&haystack[last..]);
    Some(out)
}

fn apply_header(
    bytes: &[u8],
    parts: &HttpParts,
    engine: &MatchEngine<'_>,
    replacement: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..parts.header_start]);

    let mut changed = false;
    let mut pos = parts.header_start;
    while pos < parts.header_end {
        let (content_end, next) = line_bounds(bytes, pos, parts.header_end);
        let line = &bytes[pos..content_end];

        match replace_target(line, engine, replacement) {
            Some(replaced) if replaced.is_empty() => {
                // As in Burp, replacing a whole header line with an empty
                // string removes that header line, including its line ending.
                changed = true;
            }
            Some(replaced) => {
                out.extend_from_slice(&replaced);
                out.extend_from_slice(&bytes[content_end..next]);
                changed = true;
            }
            None => {
                out.extend_from_slice(line);
                out.extend_from_slice(&bytes[content_end..next]);
            }
        }
        pos = next;
    }

    out.extend_from_slice(&bytes[parts.header_end..]);
    if changed {
        Some(out)
    } else {
        None
    }
}

fn apply_params(
    bytes: &[u8],
    parts: &HttpParts,
    want_name: bool,
    engine: &MatchEngine<'_>,
    replacement: &[u8],
) -> Option<Vec<u8>> {
    if parts.is_response {
        return None;
    }

    let mut edits: Vec<Edit> = Vec::new();
    let first_line = &bytes[..parts.first_line_end];

    if let Some(target_range) = request_target_range(first_line) {
        let target = &first_line[target_range.clone()];
        if let Some(query_mark) = target.iter().position(|&b| b == b'?') {
            collect_param_edits(
                &target[query_mark + 1..],
                target_range.start + query_mark + 1,
                want_name,
                engine,
                replacement,
                &mut edits,
            );
        }
    }

    if header_is_form_urlencoded(bytes, parts) && parts.body_start < bytes.len() {
        collect_param_edits(
            &bytes[parts.body_start..],
            parts.body_start,
            want_name,
            engine,
            replacement,
            &mut edits,
        );
    }

    if edits.is_empty() {
        return None;
    }
    edits.sort_by_key(|edit| edit.start);
    Some(apply_edits(bytes, &edits))
}

fn collect_param_edits(
    pairs: &[u8],
    base_offset: usize,
    want_name: bool,
    engine: &MatchEngine<'_>,
    replacement: &[u8],
    edits: &mut Vec<Edit>,
) {
    let mut start = 0;
    loop {
        let end = pairs[start..]
            .iter()
            .position(|&b| b == b'&')
            .map(|offset| start + offset)
            .unwrap_or(pairs.len());

        if end > start {
            let equals = pairs[start..end].iter().position(|&b| b == b'=');
            let range = if want_name {
                match equals {
                    Some(offset) => start..start + offset,
                    None => start..end,
                }
            } else {
                match equals {
                    Some(offset) => start + offset + 1..end,
                    None => end..end,
                }
            };

            if range.end > range.start {
                if let Some(replaced) =
                    replace_target(&pairs[range.clone()], engine, replacement)
                {
                    edits.push(Edit {
                        start: base_offset + range.start,
                        end: base_offset + range.end,
                        replacement: replaced,
                    });
                }
            }
        }

        if end >= pairs.len() {
            break;
        }
        start = end + 1;
    }
}

fn apply_edits(bytes: &[u8], edits: &[Edit]) -> Vec<u8> {
    let extra: usize = edits
        .iter()
        .map(|edit| edit.replacement.len())
        .sum();
    let mut out = Vec::with_capacity(bytes.len().saturating_add(extra));
    let mut pos = 0;

    for edit in edits {
        if edit.start < pos || edit.end < edit.start || edit.end > bytes.len() {
            continue;
        }
        out.extend_from_slice(&bytes[pos..edit.start]);
        out.extend_from_slice(&edit.replacement);
        pos = edit.end;
    }

    out.extend_from_slice(&bytes[pos..]);
    out
}

fn replace_span(
    bytes: &[u8],
    start: usize,
    end: usize,
    replacement: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        bytes
            .len()
            .saturating_sub(end.saturating_sub(start))
            .saturating_add(replacement.len()),
    );
    out.extend_from_slice(&bytes[..start]);
    out.extend_from_slice(replacement);
    out.extend_from_slice(&bytes[end..]);
    out
}

fn parse_http(bytes: &[u8]) -> HttpParts {
    let first_line_end = match bytes.iter().position(|&b| b == b'\n') {
        Some(newline) => {
            if newline > 0 && bytes[newline - 1] == b'\r' {
                newline - 1
            } else {
                newline
            }
        }
        None => bytes.len(),
    };

    let header_start = {
        let mut after = first_line_end;
        if after < bytes.len() && bytes[after] == b'\r' {
            if after + 1 < bytes.len() && bytes[after + 1] == b'\n' {
                after += 2;
            }
        } else if after < bytes.len() && bytes[after] == b'\n' {
            after += 1;
        }
        after
    };

    let (header_end, body_start) = if header_start < bytes.len() {
        match (bytes[header_start], bytes.get(header_start + 1)) {
            (b'\r', Some(b'\n')) => (header_start, header_start + 2),
            (b'\n', _) => (header_start, header_start + 1),
            _ => {
                let rest = &bytes[header_start..];
                if let Some(offset) = find_subslice(rest, b"\r\n\r\n") {
                    (header_start + offset, header_start + offset + 4)
                } else if let Some(offset) = find_subslice(rest, b"\n\n") {
                    (header_start + offset, header_start + offset + 2)
                } else {
                    (bytes.len(), bytes.len())
                }
            }
        }
    } else {
        (bytes.len(), bytes.len())
    };

    HttpParts {
        first_line_end,
        header_start,
        header_end,
        body_start,
        is_response: starts_with_ignore_ascii_case(
            &bytes[..first_line_end],
            b"HTTP/",
        ),
    }
}

fn line_bounds(bytes: &[u8], start: usize, limit: usize) -> (usize, usize) {
    if start >= limit {
        return (limit, limit);
    }
    match bytes[start..limit].iter().position(|&b| b == b'\n') {
        Some(offset) => {
            let newline = start + offset;
            let content_end =
                if newline > start && bytes[newline - 1] == b'\r' {
                    newline - 1
                } else {
                    newline
                };
            (content_end, newline + 1)
        }
        None => (limit, limit),
    }
}

fn header_is_form_urlencoded(bytes: &[u8], parts: &HttpParts) -> bool {
    let Some(value) = header_value(bytes, parts, b"content-type") else {
        return false;
    };
    let media_type = value.split(|&b| b == b';').next().unwrap_or(value);
    trim_ascii_ws(media_type)
        .eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
}

fn header_value<'a>(
    bytes: &'a [u8],
    parts: &HttpParts,
    name: &[u8],
) -> Option<&'a [u8]> {
    let mut pos = parts.header_start;
    while pos < parts.header_end {
        let (content_end, next) = line_bounds(bytes, pos, parts.header_end);
        let line = &bytes[pos..content_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if trim_ascii_ws(&line[..colon]).eq_ignore_ascii_case(name) {
                return Some(trim_ascii_ws(&line[colon + 1..]));
            }
        }
        pos = next;
    }
    None
}

fn request_target_range(first_line: &[u8]) -> Option<Range<usize>> {
    let mut pos = 0;
    while pos < first_line.len() && is_http_space(first_line[pos]) {
        pos += 1;
    }
    while pos < first_line.len() && !is_http_space(first_line[pos]) {
        pos += 1;
    }
    while pos < first_line.len() && is_http_space(first_line[pos]) {
        pos += 1;
    }

    let start = pos;
    while pos < first_line.len() && !is_http_space(first_line[pos]) {
        pos += 1;
    }
    if start == pos {
        None
    } else {
        Some(start..pos)
    }
}

fn trim_ascii_ws(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if first.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = value.split_last() {
        if last.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    value
}

fn is_http_space(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len()
        && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut at = 0;
    while at <= last_start {
        if haystack[at] == first
            && &haystack[at..at + needle.len()] == needle
        {
            return Some(at);
        }
        at += 1;
    }
    None
}

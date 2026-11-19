// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Literal or regex scope/session pattern match. Invalid regexes never match.
pub fn pattern_matches(pattern: &str, is_regex: bool, text: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if is_regex {
        regex::Regex::new(pattern)
            .map(|re| re.is_match(text))
            .unwrap_or(false)
    } else {
        text.contains(pattern)
    }
}

/// True when the URL is in target scope. With no include entries every URL is
/// in scope; an enabled matching exclude entry always removes it.
pub fn in_scope(shared: &Shared, url: &str) -> bool {
    let rules = shared.scope.lock().unwrap().clone();
    let active: Vec<&ScopeRule> = rules.iter().filter(|r| r.enabled).collect();
    if active
        .iter()
        .any(|r| !r.include && pattern_matches(&r.pattern, r.is_regex, url))
    {
        return false;
    }
    let includes: Vec<&ScopeRule> = active.iter().copied().filter(|r| r.include).collect();
    includes.is_empty()
        || includes
            .iter()
            .any(|r| pattern_matches(&r.pattern, r.is_regex, url))
}

/// Insert or replace a header in a raw HTTP message, keeping head order and
/// the body intact. Public: the scanner's header-manipulation probe reuses it.
pub fn replace_or_add_header(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let p = util::parse_http(raw);
    let body = &raw[p.head_len.min(raw.len())..];
    let mut out = String::with_capacity(raw.len() + name.len() + value.len() + 4);
    out.push_str(&p.first);
    out.push_str("\r\n");
    let mut replaced = false;
    for (k, v) in &p.headers {
        if k.eq_ignore_ascii_case(name) {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            replaced = true;
        } else {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
        }
        out.push_str("\r\n");
    }
    if !replaced {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

pub fn append_cookie(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let p = util::parse_http(raw);
    if let Some(existing) = util::get_header(&p.headers, "Cookie") {
        let merged = format!("{existing}; {name}={value}");
        replace_or_add_header(raw, "Cookie", &merged)
    } else {
        replace_or_add_header(raw, "Cookie", &format!("{name}={value}"))
    }
}

pub fn latest_cookie(shared: &Shared, name: &str) -> Option<String> {
    let history = shared.history.snapshot();
    for entry in history.iter().rev() {
        let Some(resp) = &entry.resp_raw else {
            continue;
        };
        let p = util::parse_http(resp);
        for (key, set_cookie) in &p.headers {
            if !key.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            let first = set_cookie.split(';').next().unwrap_or("");
            let (cookie_name, cookie_value) = first.split_once('=').unwrap_or(("", ""));
            if cookie_name.trim().eq_ignore_ascii_case(name) {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    None
}

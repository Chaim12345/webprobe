//! Intruder engine core: payload positions (C-02) and the request matrix of the
//! four attack types (C-01).
//!
//! Pure and independent of the UI and the network, so the matrix is tested on its
//! own; a runner only has to walk what `requests` returns. Positions are written
//! as `§original§` in the request text, exactly like Burp, and the markers never
//! reach the wire: `Template::render` strips them.

use crate::net::parse_markers;

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
        match self {
            AttackType::Sniper => "Sniper",
            AttackType::BatteringRam => "Battering ram",
            AttackType::Pitchfork => "Pitchfork",
            AttackType::ClusterBomb => "Cluster bomb",
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
}

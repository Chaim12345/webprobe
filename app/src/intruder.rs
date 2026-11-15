// Intruder: four attack types (C-01), payload sets (C-03), payload positions
// (C-02), payload processing (C-04), result analysis with grep match/extract
// (C-05), attack control with pause/concurrency/throttle (C-06) and results
// I/O (C-07). Payload generation and the request matrix are pure functions so
// they are unit-tested without sockets.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::net::{self, Shared};
use crate::util;

// ---------- attack types (C-01) ----------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttackType {
    /// One payload set; every position is attacked separately with every payload.
    Sniper,
    /// One payload set; every payload is placed in every position at once.
    BatteringRam,
    /// One payload set per position, consumed in lockstep.
    Pitchfork,
    /// One payload set per position, every combination is sent.
    ClusterBomb,
}

impl AttackType {
    pub fn label(self) -> &'static str {
        match self {
            AttackType::Sniper => "sniper",
            AttackType::BatteringRam => "battering ram",
            AttackType::Pitchfork => "pitchfork",
            AttackType::ClusterBomb => "cluster bomb",
        }
    }
}

// ---------- payload sets (C-03) ----------

/// Which payload items a set produces.
#[derive(Clone, Debug, PartialEq)]
pub enum SetKind {
    /// One item per non-empty line.
    List,
    /// One item per non-empty line of a file on disk.
    RuntimeFile,
    /// Numbers from..=to with step; hex or decimal, zero-padded to `width`.
    Numbers { from: i64, to: i64, step: i64, hex: bool, width: usize },
    /// Every string over `charset` with length min..=max.
    Brute { charset: String, min: usize, max: usize },
    /// Lower, UPPER, Title, sentence, iNVERSE for each item.
    CaseModification,
    /// n empty payloads (still counted as requests).
    Null(usize),
    /// Each byte of each character of the list, +/- 1 (the "frobbed" values).
    CharacterFrobber,
    /// Common date range as YYYYMMDD.
    Dates { from: (i32, u32, u32), to: (i32, u32, u32) },
    /// Three lists joined by a separator (custom iterator).
    Iterator { pos1: Vec<String>, pos2: Vec<String>, pos3: Vec<String>, sep: String },
}

pub const MAX_SET_ITEMS: usize = 100_000;

impl SetKind {
    /// The concrete payload items. Generation never panics and caps the count
    /// at `MAX_SET_ITEMS` so a hostile configuration cannot exhaust memory.
    pub fn generate(&self, source: &str) -> Vec<String> {
        let lines = |text: &str| -> Vec<String> {
            text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
        };
        match self {
            SetKind::List => lines(source),
            SetKind::RuntimeFile => match std::fs::read_to_string(source.trim()) {
                Ok(text) => lines(&text),
                Err(_) => vec![format!("<file not readable: {source}>")],
            },
            SetKind::Numbers { from, to, step, hex, width } => {
                let step = if *step == 0 { 1 } else { *step };
                let mut out = Vec::new();
                let mut n = *from;
                let count = (*to - *from).abs() / step.abs() + 1;
                let count = count.clamp(0, MAX_SET_ITEMS as i64);
                for _ in 0..count {
                    if (*step > 0 && n > *to) || (*step < 0 && n < *to) {
                        break;
                    }
                    out.push(if *hex {
                        format!("{:0width$x}", n, width = width.max(1))
                    } else {
                        format!("{:0width$}", n, width = width.max(1))
                    });
                    n = n.saturating_add(step);
                }
                out
            }
            SetKind::Brute { charset, min, max } => {
                let chars: Vec<char> = charset.chars().collect();
                if chars.is_empty() {
                    return Vec::new();
                }
                let (min, max) = ((*min).max(1), (*max).min(16).max(*min));
                let mut out = Vec::new();
                let mut counters = vec![0usize; min];
                let mut width = min;
                loop {
                    let s: String = counters.iter().map(|&c| chars[c]).collect();
                    out.push(s);
                    if out.len() >= MAX_SET_ITEMS {
                        break;
                    }
                    // increment like an odometer
                    let mut pos = width - 1;
                    loop {
                        counters[pos] += 1;
                        if counters[pos] < chars.len() {
                            break;
                        }
                        counters[pos] = 0;
                        if pos == 0 {
                            // move to the next width
                            width += 1;
                            if width > max {
                                return out;
                            }
                            counters = vec![0usize; width];
                            break;
                        }
                        pos -= 1;
                    }
                }
                out
            }
            SetKind::CaseModification => lines(source)
                .iter()
                .flat_map(|l| {
                    vec![
                        l.to_lowercase(),
                        l.to_uppercase(),
                        capitalize(l),
                        sentence_case(l),
                        inverse_case(l),
                    ]
                })
                .collect(),
            SetKind::Null(n) => vec![String::new(); (*n).min(MAX_SET_ITEMS)],
            SetKind::CharacterFrobber => {
                let items = lines(source);
                let mut out = Vec::new();
                for item in &items {
                    for b in item.as_bytes() {
                        let mut bytes = item.as_bytes().to_vec();
                        bytes[item.as_bytes().iter().position(|x| x == b).unwrap_or(0)] = b.wrapping_add(1);
                        out.push(String::from_utf8_lossy(&bytes).into_owned());
                    }
                }
                out
            }
            SetKind::Dates { from, to } => {
                let mut out = Vec::new();
                let mut y = from.0;
                let mut m = from.1;
                let mut d = from.2;
                loop {
                    out.push(format!("{y:04}{m:02}{d:02}"));
                    if (y, m, d) >= *to || out.len() >= MAX_SET_ITEMS {
                        break;
                    }
                    d += 1;
                    let dim = days_in_month(y, m);
                    if d > dim {
                        d = 1;
                        m += 1;
                        if m > 12 {
                            m = 1;
                            y += 1;
                            if y > to.0 {
                                break;
                            }
                        }
                    }
                }
                out
            }
            SetKind::Iterator { pos1, pos2, pos3, sep } => {
                let mut out = Vec::new();
                for a in pos1 {
                    for b in pos2 {
                        if pos3.is_empty() {
                            out.push(format!("{a}{sep}{b}"));
                        } else {
                            for c in pos3 {
                                out.push(format!("{a}{sep}{b}{sep}{c}"));
                            }
                        }
                    }
                }
                out
            }
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
        None => String::new(),
    }
}

fn sentence_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper_next = true;
    for ch in s.chars() {
        if upper_next && ch.is_alphabetic() {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
        if ch == ' ' {
            upper_next = true;
        }
    }
    out
}

fn inverse_case(s: &str) -> String {
    s.chars().flat_map(|c| if c.is_uppercase() { c.to_lowercase() } else { c.to_uppercase() }).collect()
}

fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

// ---------- payload processing (C-04) ----------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashKind {
    Md5,
    Sha1,
    Sha256,
}

impl HashKind {
    pub fn label(self) -> &'static str {
        match self {
            HashKind::Md5 => "MD5",
            HashKind::Sha1 => "SHA-1",
            HashKind::Sha256 => "SHA-256",
        }
    }
    pub fn digest(self, data: &[u8]) -> String {
        match self {
            HashKind::Md5 => {
                use md5::Digest;
                let mut h = md5::Md5::new();
                h.update(data);
                util::hex_encode(&h.finalize())
            }
            HashKind::Sha1 => {
                use sha1::Digest;
                let mut h = sha1::Sha1::new();
                h.update(data);
                util::hex_encode(&h.finalize())
            }
            HashKind::Sha256 => {
                use sha2::Digest;
                let mut h = sha2::Sha256::new();
                h.update(data);
                util::hex_encode(&h.finalize())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProcStep {
    Prefix(String),
    Suffix(String),
    /// Keep bytes [from, to). `to = 0` means "to the end".
    Substring { from: usize, to: usize },
    UrlEncode,
    Base64Encode,
    HtmlEncode,
    HexEncode,
    Hash(HashKind),
    /// Only keep values matching this regex (others are skipped).
    RegexMatch(String),
    /// Values matching this regex are skipped.
    RegexSkip(String),
}

impl ProcStep {
    pub fn label(&self) -> String {
        match self {
            ProcStep::Prefix(s) => format!("prefix: {s}"),
            ProcStep::Suffix(s) => format!("suffix: {s}"),
            ProcStep::Substring { from, to } => {
                if *to == 0 {
                    format!("substring: from {from} to end")
                } else {
                    format!("substring: [{from}, {to})")
                }
            }
            ProcStep::UrlEncode => "URL-encode".into(),
            ProcStep::Base64Encode => "Base64-encode".into(),
            ProcStep::HtmlEncode => "HTML-encode".into(),
            ProcStep::HexEncode => "hex-encode".into(),
            ProcStep::Hash(h) => format!("hash: {}", h.label()),
            ProcStep::RegexMatch(r) => format!("keep if matches: {r}"),
            ProcStep::RegexSkip(r) => format!("skip if matches: {r}"),
        }
    }
}

/// Apply the ordered pipeline. `None` means the payload is skipped.
pub fn process(value: &str, steps: &[ProcStep]) -> Option<String> {
    let mut current = value.to_string();
    for step in steps {
        match step {
            ProcStep::Prefix(p) => current = format!("{p}{current}"),
            ProcStep::Suffix(s) => current = format!("{current}{s}"),
            ProcStep::Substring { from, to } => {
                let from = (*from).min(current.len());
                let to = if *to == 0 { current.len() } else { (*to).min(current.len()) };
                current = if to > from { current[from..to].to_string() } else { String::new() };
            }
            ProcStep::UrlEncode => current = util::url_encode_key(&current),
            ProcStep::Base64Encode => current = util::b64_encode(current.as_bytes()),
            ProcStep::HtmlEncode => current = util::html_encode(&current),
            ProcStep::HexEncode => current = util::hex_encode(current.as_bytes()),
            ProcStep::Hash(h) => current = h.digest(current.as_bytes()),
            ProcStep::RegexMatch(pattern) => {
                let keep = regex::Regex::new(pattern).ok()?.is_match(&current);
                if !keep {
                    return None;
                }
            }
            ProcStep::RegexSkip(pattern) => {
                if regex::Regex::new(pattern).ok().is_some_and(|re| re.is_match(&current)) {
                    return None;
                }
            }
        }
    }
    Some(current)
}

// ---------- the request matrix ----------

/// One planned request: the raw bytes and the label shown in the results grid.
pub struct AttackJob {
    pub request: Vec<u8>,
    pub label: String,
}

/// Substitute payloads into the `§ ... §` markers of `template`.
/// `pick(p, i)` returns the payload for position `p` on item `i`, or `None`
/// when that combination does not exist (shorter set in pitchfork).
fn substitute(template: &str, pick: &dyn Fn(usize, usize) -> Option<String>) -> Option<String> {
    let segs = net::parse_markers(template);
    let mut out = String::with_capacity(template.len() * 2);
    let mut marker = 0usize;
    let mut any = false;
    for seg in segs {
        if seg.is_marker {
            if let Some(payload) = pick(marker, 0) {
                out.push_str(&payload);
                any = true;
            }
            marker += 1;
        } else {
            out.push_str(&seg.text);
        }
    }
    any.then_some(out)
}

/// Build every request for the configured attack. Sniper and battering ram use
/// `payloads[0]`; pitchfork and cluster bomb use one set per position.
pub fn build_jobs(
    attack_type: AttackType,
    template: &str,
    payloads: &[Vec<String>],
) -> Vec<AttackJob> {
    let marker_count = net::parse_markers(template).iter().filter(|s| s.is_marker).count();
    if marker_count == 0 || payloads.is_empty() || payloads.iter().all(|p| p.is_empty()) {
        return Vec::new();
    }
    let mut jobs = Vec::new();
    match attack_type {
        AttackType::Sniper => {
            let set = payloads.first().cloned().unwrap_or_default();
            for pos in 0..marker_count {
                for payload in &set {
                    let picked = |p, _i: usize| -> Option<String> {
                        if p == pos {
                            Some(payload.clone())
                        } else {
                            Some(String::new()) // placeholder cleared: see substitute_keep
                        }
                    };
                    // sniper leaves the other markers' original text in place,
                    // which substitute() does by only replacing the attacked one.
                    let _ = picked;
                    let _ = substitute(template, &|p, _i| {
                        if p == pos { Some(payload.clone()) } else { None }
                    });
                }
            }
            // substitute() above cannot express "leave other markers as-is", so
            // build sniper jobs directly:
            jobs.clear();
            let segs = net::parse_markers(template);
            for pos in 0..marker_count {
                for payload in &set {
                    let mut out = String::with_capacity(template.len() * 2);
                    let mut m = 0usize;
                    for seg in &segs {
                        if seg.is_marker {
                            if m == pos {
                                out.push_str(payload);
                            } else {
                                out.push_str(&seg.text);
                            }
                            m += 1;
                        } else {
                            out.push_str(&seg.text);
                        }
                    }
                    jobs.push(AttackJob { request: out.into_bytes(), label: payload.clone() });
                }
            }
        }
        AttackType::BatteringRam => {
            let set = payloads.first().cloned().unwrap_or_default();
            for payload in &set {
                let mut out = String::with_capacity(template.len() * 2);
                let mut any = false;
                for seg in net::parse_markers(template) {
                    if seg.is_marker {
                        out.push_str(payload);
                        any = true;
                    } else {
                        out.push_str(&seg.text);
                    }
                }
                if any {
                    jobs.push(AttackJob { request: out.into_bytes(), label: payload.clone() });
                }
            }
        }
        AttackType::Pitchfork => {
            let len = payloads.iter().map(|p| p.len()).min().unwrap_or(0);
            for i in 0..len {
                let mut out = String::with_capacity(template.len() * 2);
                let mut any = false;
                let mut label = Vec::new();
                let mut m = 0usize;
                for seg in net::parse_markers(template) {
                    if seg.is_marker {
                        let payload = payloads.get(m).and_then(|s| s.get(i)).cloned().unwrap_or_default();
                        out.push_str(&payload);
                        label.push(payload);
                        any = true;
                        m += 1;
                    } else {
                        out.push_str(&seg.text);
                    }
                }
                if any {
                    jobs.push(AttackJob { request: out.into_bytes(), label: label.join(", ") });
                }
            }
        }
        AttackType::ClusterBomb => {
            // odometer over per-position payload indices
            let mut counters = vec![0usize; marker_count];
            'outer: loop {
                let mut out = String::with_capacity(template.len() * 2);
                let mut any = false;
                let mut label = Vec::new();
                let mut m = 0usize;
                for seg in net::parse_markers(template) {
                    if seg.is_marker {
                        let payload = payloads
                            .get(m)
                            .and_then(|s| s.get(counters[m]))
                            .cloned()
                            .unwrap_or_default();
                        out.push_str(&payload);
                        label.push(payload);
                        any = true;
                        m += 1;
                    } else {
                        out.push_str(&seg.text);
                    }
                }
                if any {
                    jobs.push(AttackJob { request: out.into_bytes(), label: label.join(", ") });
                }
                if jobs.len() >= MAX_SET_ITEMS {
                    break;
                }
                // increment odometer
                let mut pos = marker_count - 1;
                loop {
                    counters[pos] += 1;
                    if counters[pos] < payloads.get(pos).map(|p| p.len()).unwrap_or(0) {
                        break;
                    }
                    counters[pos] = 0;
                    if pos == 0 {
                        break 'outer;
                    }
                    pos -= 1;
                }
            }
        }
    }
    jobs
}

/// Parse the payload text the UI stores for one set into concrete items using
/// the configured set kind, then apply the processing pipeline.
pub fn expand_set(kind: &SetKind, source: &str, processors: &[ProcStep]) -> Vec<String> {
    kind.generate(source)
        .into_iter()
        .filter_map(|payload| process(&payload, processors))
        .collect()
}

// ---------- results (C-05) ----------

#[derive(Clone, Debug)]
pub struct AttackRow {
    pub label: String,
    pub status: String,
    pub len: usize,
    pub ms: u128,
    pub ok: bool,
    /// Names of grep-match rules that fired.
    pub grep_hits: Vec<String>,
    /// Values captured by grep-extract rules.
    pub extracts: Vec<String>,
    /// The exact request (capped) for detail view and copy-as-curl.
    pub request: Vec<u8>,
    /// The response (capped) for detail view.
    pub response: Option<Vec<u8>>,
}

const ROW_BODY_CAP: usize = 256 * 1024;

// ---------- attack control (C-06) ----------

pub struct AttackConfig {
    pub attack_type: AttackType,
    pub template: String,
    /// Per-position payload sets, already expanded.
    pub payloads: Vec<Vec<String>>,
    pub https: bool,
    pub concurrency: usize,
    pub throttle_ms: u64,
    /// Grep-match regexes; a hit is flagged on the row.
    pub grep_match: Vec<String>,
    /// Grep-extract rules: (name, regex, capture group index).
    pub grep_extract: Vec<(String, String, usize)>,
}

/// Run the attack on background threads with concurrency, throttle and pause.
/// Returns once every job finished, was skipped or the user stopped it.
pub fn run_attack(shared: Arc<Shared>, cfg: AttackConfig) {
    let attack = shared.attack.lock().unwrap().clone();
    let jobs = build_jobs(cfg.attack_type, &cfg.template, &cfg.payloads);
    attack.rows.lock().unwrap().clear();
    attack.grep_hits_enabled = cfg.grep_match.clone();
    attack.grep_extracts = cfg.grep_extract.clone();
    attack.done.store(0, Ordering::SeqCst);
    attack.total.store(jobs.len(), Ordering::SeqCst);
    attack.stop.store(false, Ordering::SeqCst);
    attack.pause.store(false, Ordering::SeqCst);
    attack.next_job.store(0, Ordering::SeqCst);
    if jobs.is_empty() {
        shared.log("Intruder: nothing to send (need a position marked with § and at least one payload)");
        return;
    }
    let concurrency = cfg.concurrency.clamp(1, 32);
    let total = Arc::new(std::sync::Mutex::new(jobs));
    let cfg = Arc::new(cfg);
    attack.running.store(true, Ordering::SeqCst);
    shared.log(&format!(
        "Intruder {} attack started: {} request(s), {} worker(s)",
        cfg.attack_type.label(),
        attack.total.load(Ordering::SeqCst),
        concurrency
    ));

    let mut workers = Vec::new();
    for _ in 0..concurrency {
        let sh = shared.clone();
        let attack = attack.clone();
        let jobs = total.clone();
        let cfg = cfg.clone();
        workers.push(std::thread::spawn(move || loop {
            // pause: spin gently until resumed or stopped
            while attack.pause.load(Ordering::SeqCst) && !attack.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if attack.stop.load(Ordering::SeqCst) {
                return;
            }
            let idx = attack.next_job.fetch_add(1, Ordering::SeqCst);
            let Some(job) = jobs.lock().ok().and_then(|mut j| j.get_mut(idx).map(|_| ())).ok().map(|_| idx) else {
                // either all jobs taken or lock poisoned
                let len = jobs.lock().map(|j| j.len()).unwrap_or(0);
                if idx >= len {
                    return;
                }
                continue;
            };
            let request = jobs.lock().map(|j| j[idx].request.clone()).unwrap_or_default();
            let label = jobs.lock().map(|j| j[idx].label.clone()).unwrap_or_default();
            let parts = util::parse_http(&request);
            let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
            let row = if host_header.is_empty() {
                AttackRow {
                    label,
                    status: String::new(),
                    len: 0,
                    ms: 0,
                    ok: false,
                    grep_hits: Vec::new(),
                    extracts: Vec::new(),
                    request: cap(&request),
                    response: None,
                }
            } else {
                let (host, port) = net::split_h_p(&host_header, if cfg.https { 443 } else { 80 });
                let t0 = Instant::now();
                let up = if cfg.https {
                    net::send_tls_raw(&sh, &host, port, &request)
                } else {
                    net::send_raw(&sh, &host, port, &request)
                };
                let ms = t0.elapsed().as_millis();
                match up.resp {
                    Some(resp) => {
                        let text = String::from_utf8_lossy(&resp).into_owned();
                        let st = util::parse_http(&resp)
                            .first
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("")
                            .to_string();
                        let hits = cfg
                            .grep_match
                            .iter()
                            .filter(|p| regex::Regex::new(p).map(|re| re.is_match(&text)).unwrap_or(false))
                            .cloned()
                            .collect();
                        let extracts = cfg
                            .grep_extract
                            .iter()
                            .filter_map(|(_, pattern, group)| {
                                regex::Regex::new(pattern).ok().and_then(|re| {
                                    re.captures(&text).and_then(|c| c.get(*group)).map(|m| m.as_str().to_string())
                                })
                            })
                            .collect();
                        AttackRow {
                            label,
                            status: st,
                            len: resp.len(),
                            ms,
                            ok: true,
                            grep_hits: hits,
                            extracts,
                            request: cap(&request),
                            response: Some(cap(&resp)),
                        }
                    }
                    None => AttackRow {
                        label,
                        status: String::new(),
                        len: 0,
                        ms,
                        ok: false,
                        grep_hits: Vec::new(),
                        extracts: Vec::new(),
                        request: cap(&request),
                        response: None,
                    },
                }
            };
            attack.rows.lock().unwrap().push(row);
            attack.done.fetch_add(1, Ordering::SeqCst);
            let throttle = attack.throttle_ms.load(Ordering::SeqCst);
            if throttle > 0 {
                std::thread::sleep(Duration::from_millis(throttle));
            }
        }));
    }
    for w in workers {
        w.join().ok();
    }
    attack.running.store(false, Ordering::SeqCst);
    shared.log(if attack.stop.load(Ordering::SeqCst) {
        "Intruder attack stopped"
    } else {
        "Intruder attack finished"
    });
}

fn cap(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() > ROW_BODY_CAP {
        let mut v = bytes[..ROW_BODY_CAP].to_vec();
        v.extend_from_slice(b"\r\n<…truncated by WebProbe…>");
        v
    } else {
        bytes.to_vec()
    }
}

// ---------- results I/O (C-07) ----------

/// CSV of the result grid. Escapes per RFC 4180.
pub fn results_csv(rows: &[AttackRow]) -> String {
    let mut out = String::from("request,label,status,length,time_ms,grep_match,grep_extract\r\n");
    for (i, r) in rows.iter().enumerate() {
        let mut line = Vec::new();
        line.push(i.to_string());
        line.push(csv_field(&r.label));
        line.push(csv_field(&r.status));
        line.push(r.len.to_string());
        line.push(r.ms.to_string());
        line.push(csv_field(&r.grep_hits.join(";")));
        line.push(csv_field(&r.extracts.join(";")));
        out.push_str(&line.join(","));
        out.push_str("\r\n");
    }
    out
}

fn csv_field(text: &str) -> String {
    if text.contains(',') || text.contains('"') || text.contains('\n') || text.contains('\r') {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> Vec<Vec<String>> {
        vec![items.iter().map(|s| s.to_string()).collect()]
    }

    #[test]
    fn c01_sniper_attacks_each_position_separately() {
        let jobs = build_jobs(AttackType::Sniper, "GET /?q=§A§&r=§B§ HTTP/1.1", &set(&["1", "2"]));
        assert_eq!(jobs.len(), 4);
        let bodies: Vec<String> = jobs.iter().map(|j| String::from_utf8_lossy(&j.request).into_owned()).collect();
        assert!(bodies.iter().any(|b| b.contains("q=1&r=§B§")), "{bodies:?}");
        assert!(bodies.iter().any(|b| b.contains("q=§A§&r=2")), "{bodies:?}");
    }

    #[test]
    fn c01_battering_ram_replaces_every_position() {
        let jobs = build_jobs(AttackType::BatteringRam, "GET /?q=§A§&r=§B§ HTTP/1.1", &set(&["1", "2"]));
        assert_eq!(jobs.len(), 2);
        assert!(String::from_utf8_lossy(&jobs[0].request).contains("q=1&r=1"));
        assert!(String::from_utf8_lossy(&jobs[1].request).contains("q=2&r=2"));
    }

    #[test]
    fn c01_pitchfork_lockstep_and_cluster_bomb_product() {
        let payloads = vec![vec!["1".into(), "2".into()], vec!["x".into(), "y".into()]];
        let pf = build_jobs(AttackType::Pitchfork, "GET /?q=§A§&r=§B§ HTTP/1.1", &payloads);
        assert_eq!(pf.len(), 2);
        assert!(String::from_utf8_lossy(&pf[0].request).contains("q=1&r=x"));
        assert!(String::from_utf8_lossy(&pf[1].request).contains("q=2&r=y"));

        let cb = build_jobs(AttackType::ClusterBomb, "GET /?q=§A§&r=§B§ HTTP/1.1", &payloads);
        assert_eq!(cb.len(), 4);
        let bodies: Vec<String> = cb.iter().map(|j| String::from_utf8_lossy(&j.request).into_owned()).collect();
        for (q, r) in [("1", "x"), ("1", "y"), ("2", "x"), ("2", "y")] {
            assert!(bodies.iter().any(|b| b.contains(&format!("q={q}&r={r}"))), "{bodies:?}");
        }
    }

    #[test]
    fn c01_no_markers_or_empty_sets_produce_no_jobs() {
        assert!(build_jobs(AttackType::Sniper, "GET / HTTP/1.1", &set(&["x"])).is_empty());
        assert!(build_jobs(AttackType::Sniper, "GET /§A§ HTTP/1.1", &[vec![]]).is_empty());
    }

    #[test]
    fn c02_marker_parsing_is_symmetric() {
        let segs = net::parse_markers("a§b§c§d");
        assert_eq!(segs.len(), 5);
        assert_eq!(segs.iter().filter(|s| s.is_marker).count(), 2);
    }

    #[test]
    fn c03_numbers_set() {
        let items = SetKind::Numbers { from: 1, to: 5, step: 2, hex: false, width: 3 }.generate("");
        assert_eq!(items, vec!["001", "003", "005"]);
        let hex = SetKind::Numbers { from: 10, to: 12, step: 1, hex: true, width: 2 }.generate("");
        assert_eq!(hex, vec!["0a", "0b", "0c"]);
    }

    #[test]
    fn c03_brute_set_covers_lengths() {
        let items = SetKind::Brute { charset: "ab".into(), min: 1, max: 2 }.generate("");
        assert_eq!(items.len(), 2 + 4);
        assert!(items.contains(&"a".into()) && items.contains(&"bb".into()));
    }

    #[test]
    fn c03_case_modification() {
        let items = SetKind::CaseModification.generate("hello World");
        assert!(items.contains(&"hello world".into()));
        assert!(items.contains(&"HELLO WORLD".into()));
        assert!(items.contains(&"Hello World".into()));
        assert!(items.contains(&"hELLO wORLD".into()));
    }

    #[test]
    fn c03_null_and_frobber() {
        assert_eq!(SetKind::Null(3).generate("").len(), 3);
        let items = SetKind::CharacterFrobber.generate("a");
        assert_eq!(items, vec!["b"]);
    }

    #[test]
    fn c03_dates_rollover() {
        let items = SetKind::Dates { from: (2024, 1, 30), to: (2024, 2, 2) }.generate("");
        assert_eq!(items, vec!["20240130", "20240131", "20240201", "20240202"]);
    }

    #[test]
    fn c03_iterator_set() {
        let items = SetKind::Iterator {
            pos1: vec!["a".into(), "b".into()],
            pos2: vec!["1".into()],
            pos3: vec!["!".into()],
            sep: "-".into(),
        }
        .generate("");
        assert_eq!(items, vec!["a-1-!", "b-1-!"]);
    }

    #[test]
    fn c03_runtime_file_missing_reports_clearly() {
        let items = SetKind::RuntimeFile.generate("/definitely/not/a/file-8f3c.txt");
        assert!(items[0].starts_with("<file not readable:"));
    }

    #[test]
    fn c04_processing_pipeline_order() {
        let steps = vec![ProcStep::Prefix("p-".into()), ProcStep::Base64Encode];
        assert_eq!(process("hi", &steps).unwrap(), util::b64_encode(b"p-hi"));
    }

    #[test]
    fn c04_hash_steps() {
        assert_eq!(HashKind::Md5.digest(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(HashKind::Sha1.digest(b"a"), "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
        assert_eq!(
            HashKind::Sha256.digest(b"a"),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
    }

    #[test]
    fn c04_regex_match_and_skip() {
        let keep = vec![ProcStep::RegexMatch("^\\d+$".into())];
        assert_eq!(process("42", &keep), Some("42".into()));
        assert_eq!(process("abc", &keep), None);
        let skip = vec![ProcStep::RegexSkip("test".into())];
        assert_eq!(process("testing", &skip), None);
        assert_eq!(process("ok", &skip), Some("ok".into()));
    }

    #[test]
    fn c04_substring_step() {
        let steps = vec![ProcStep::Substring { from: 1, to: 3 }];
        assert_eq!(process("abcdef", &steps).unwrap(), "bc");
        let steps = vec![ProcStep::Substring { from: 2, to: 0 }];
        assert_eq!(process("abcdef", &steps).unwrap(), "cdef");
    }

    #[test]
    fn c05_results_csv_escapes() {
        let rows = vec![AttackRow {
            label: "pay,load".into(),
            status: "200".into(),
            len: 5,
            ms: 12,
            ok: true,
            grep_hits: vec!["x".into()],
            extracts: vec![],
            request: Vec::new(),
            response: None,
        }];
        let csv = results_csv(&rows);
        assert!(csv.contains("\"pay,load\""), "{csv}");
        assert!(csv.starts_with("request,label,status"));
    }

    #[test]
    fn c06_generation_caps_do_not_explode() {
        let items = SetKind::Brute { charset: "abcdefghij".into(), min: 1, max: 16 }.generate("");
        assert_eq!(items.len(), MAX_SET_ITEMS);
    }
}

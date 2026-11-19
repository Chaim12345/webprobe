// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

pub struct LinkManipHit {
    pub payload: String,
    pub target: String,
}

/// Link-attribute targets in a response: href/src/action/formaction values
/// plus redirect targets (burp.Zpyp injects a URL and checks it becomes a
/// link/redirect target the page points at).
pub fn link_targets(resp: &[u8]) -> Vec<String> {
    let mut out = redirect_targets(resp);
    let p = crate::util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let low = body.to_ascii_lowercase();
    for attr in ["href=", "src=", "action=", "formaction="] {
        let mut i = 0;
        while let Some(a) = low[i..].find(attr).map(|x| x + i) {
            let vs = a + attr.len();
            let rest = &body[vs.min(body.len())..];
            let val = if rest.starts_with('"') || rest.starts_with('\'') {
                let q = rest.as_bytes()[0] as char;
                rest[1..].split(q).next().unwrap_or("").to_string()
            } else {
                rest.split([' ', '>', '\t', '\n'])
                    .next()
                    .unwrap_or("")
                    .to_string()
            };
            if !val.is_empty() {
                out.push(val);
            }
            i = vs;
        }
    }
    out
}

/// Live passive crawl: same-origin link paths found in a response, resolved
/// against the request path (query kept, fragment dropped).
pub fn crawl_links(origin: &str, req_path: &str, resp: &[u8]) -> Vec<String> {
    let base = req_path.split('?').next().unwrap_or("/");
    let base = match base.split_once("://") {
        Some((_, r)) => r
            .find('/')
            .map(|i| r[i..].to_string())
            .unwrap_or_else(|| "/".into()),
        None => base.to_string(),
    };
    let dir = &base[..=base.rfind('/').unwrap_or(0)];
    let mut out = Vec::new();
    // Links come from HTML documents (and redirects), as a browser sees them:
    // href/src strings inside script bundles are not navigations.
    let ct = util::get_header(&util::parse_http(resp).headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let targets = if ct.contains("html") {
        link_targets(resp)
    } else {
        redirect_targets(resp)
    };
    for l in targets {
        let l = l.split('#').next().unwrap_or("").trim().to_string();
        if l.is_empty()
            || l.starts_with("javascript:")
            || l.starts_with("mailto:")
            || l.starts_with("data:")
        {
            continue;
        }
        if l.chars()
            .any(|c| c.is_whitespace() || "`{}()<>;$\"'\\".contains(c))
        {
            continue;
        }
        let path = if let Some(rest) = l.strip_prefix(origin) {
            if rest.is_empty() {
                "/".to_string()
            } else if rest.starts_with('/') {
                rest.to_string()
            } else {
                continue;
            }
        } else if l.contains("://") || l.starts_with("//") {
            continue;
        } else if l.starts_with('/') {
            l
        } else {
            format!("{dir}{l}")
        };
        // Collapse ./ and ../ segments.
        let (p, q) = match path.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (path.clone(), None),
        };
        let mut segs: Vec<&str> = Vec::new();
        let ends_dir = p.ends_with('/') || p.ends_with("/.") || p.ends_with("/..");
        for seg in p.split('/') {
            match seg {
                "." => {}
                ".." => {
                    segs.pop();
                }
                s => segs.push(s),
            }
        }
        let mut joined = segs.join("/");
        if ends_dir && !joined.ends_with('/') {
            joined.push('/');
        }
        if !joined.starts_with('/') {
            joined.insert(0, '/');
        }
        if let Some(q) = q {
            joined = format!("{joined}?{q}");
        }
        if !out.contains(&joined) {
            out.push(joined);
        }
    }
    out
}

/// burp.Zb_5 reflected link manipulation: inject an absolute URL and report
/// when it becomes a link or redirect target the page points at (value
/// replaced then appended, burp.Zw7s REPLACE/APPEND).
pub fn run_link_manip_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    _value: &str,
    mut send: F,
) -> Option<LinkManipHit> {
    // burp.Zb_5 (LINK_MANIPULATION_REFLECTED): the value is replaced by a
    // random 10-character token, which must come back unmodified inside a
    // URL: a link in the page or the Location / Refresh target (Burp, lab
    // /redirect: "echoed unmodified within the response header Location").
    // Nothing is appended to the original value, so allowlisting redirectors
    // (Juice Shop /redirect) reject the probe as they do Burp's.
    let token: String = {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10)
            .map(|i| {
                if i == 8 {
                    (b'0' + g.gen_range(0..10)) as char
                } else {
                    (b'a' + g.gen_range(0..26)) as char
                }
            })
            .collect()
    };
    let resp = send(&token)?;
    let target = link_targets(&resp)
        .into_iter()
        .chain(redirect_targets(&resp))
        .find(|t| t.contains(&token))?;
    Some(LinkManipHit {
        payload: token,
        target,
    })
}

/// burp.Zulm: valid (same-file) and invalid path variants of a path-like
/// value. Templates decoded from Zulm.ZV/Zb (%1=sep, %2=file, %3=random).
pub fn file_path_variants(value: &str) -> Option<(String, Vec<String>, Vec<String>)> {
    let sep = if !value.contains('/') && value.contains('\\') {
        "\\"
    } else {
        "/"
    };
    let cut = value.rfind(['/', '\\']);
    let (dir, file) = match cut {
        Some(i) => (&value[..i + 1], &value[i + 1..]),
        None => ("", value),
    };
    if file.is_empty() {
        return None;
    }
    let r = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..3)
            .map(|_| (b'a' + g.gen_range(0..26)) as char)
            .collect::<String>()
    };
    // Zulm.ZV: redundant paths to the same file (should return the same file).
    let valid = vec![
        format!("{dir}.{sep}{file}"),
        format!("{dir}.{sep}.{sep}{file}"),
        format!("{dir}.{sep}.{sep}.{sep}{file}"),
    ];
    // Zulm.Zb: bogus variants (should not return the same file).
    let invalid = vec![
        format!("{dir}...{sep}{file}"),
        format!("{dir}{}{sep}{file}", r()),
        format!("{dir}{file}{}", r()),
    ];
    Some((dir.to_string(), valid, invalid))
}

pub struct FilePathManipHit {
    pub valid: String,
    pub invalid: String,
    pub attributes: Vec<crate::variations::Attr>,
}

/// burp.Zsl1: for a path-like value, the redundant-path variants (same file)
/// must respond consistently differently from the bogus variants, proving the
/// parameter selects a file. Runs Burp's differential engine (Zmaq).
pub fn run_file_path_manip_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    accuracy: crate::variations::Accuracy,
    mut send: F,
) -> Option<FilePathManipHit> {
    // Only applies to a value that looks like a path (burp.Zsl1 gate).
    if !value.contains(['/', '\\', '.']) || value.len() < 3 {
        return None;
    }
    let (_, valid, invalid) = file_path_variants(value)?;
    let (vi, ii) = (std::cell::Cell::new(0usize), std::cell::Cell::new(0usize));
    let sent = std::cell::RefCell::new(&mut send);
    let attrs = crate::variations::differential(
        Some(baseline),
        accuracy,
        || {
            let p = &valid[vi.get() % valid.len()];
            vi.set(vi.get() + 1);
            (sent.borrow_mut())(p)
        },
        || {
            let p = &invalid[ii.get() % invalid.len()];
            ii.set(ii.get() + 1);
            (sent.borrow_mut())(p)
        },
    )?;
    Some(FilePathManipHit {
        valid: valid[0].clone(),
        invalid: invalid[0].clone(),
        attributes: attrs,
    })
}

pub struct KnownFileHit {
    pub payload: String,
    pub control: String,
    pub file: &'static str,
    pub marker: &'static str,
}

/// burp.Zsl1.java:111-128: known files tried in the selected directory once
/// the parameter is shown to select a file, each with the marker(s) that
/// prove retrieval (`.htaccess` hits on any of its three).
const KNOWN_FILES: &[(&str, &[&str])] = &[
    ("Web.config", &["<system.web"]),
    ("WEB-INF/web.xml", &["<web-app"]),
    (".htaccess", &["Options ", "AddHandler", "RewriteRule"]),
];

/// burp.Zsl1.java:179-203: known-file follow-up to the path-manipulation
/// differential. A file counts as retrieved when a marker appears that is in
/// neither the baseline nor the `X`-suffixed negative control (the same
/// control shape as `traversal_control`).
pub fn known_file_follow_up<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    mut send: F,
) -> Option<KnownFileHit> {
    let cut = value.rfind(['/', '\\']);
    let dir = match cut {
        Some(i) => &value[..i + 1],
        None => "",
    };
    let base = String::from_utf8_lossy(baseline);
    for (name, markers) in KNOWN_FILES {
        let payload = format!("{dir}{name}");
        let raw = send(&payload)?;
        let body = String::from_utf8_lossy(&raw);
        let Some(&marker) = markers
            .iter()
            .find(|m| body.contains(**m) && !base.contains(**m))
        else {
            continue;
        };
        let control = format!("{payload}X");
        // A failed control aborts the follow-up like a failed probe:
        // without the control there is no evidence the marker is specific
        // to the filename, so an empty answer must not confirm.
        let cbody = send(&control)?;
        if String::from_utf8_lossy(&cbody).contains(marker) {
            continue; // the marker shows regardless of the filename
        }
        return Some(KnownFileHit {
            payload,
            control,
            file: name,
            marker,
        });
    }
    None
}

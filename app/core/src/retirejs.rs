// Vulnerable JavaScript dependency (R-04): a port of Burp's retire.js
// check (burp.Zply, matching burp.Zmwd, repository burp.Zc_o, versions
// burp.Zp_1, issue burp.Zujw, text burp.Zcu3). The repository itself is
// not part of WebProbe: `paths::retirejs_repository` finds Burp's
// `RetireJS/retirejs_repository.json` or a retire.js `jsrepository.json`.

use super::*;
use super::passive_checks::PassiveCtx;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

/// burp.Zujw.ZC (VULNERABLE_JAVASCRIPT_DEPENDENCY): Tentative, Low (Zrh
/// bytes 1 / 2).
pub(crate) const CH_VULNERABLE_JS: CheckDef = CheckDef { id: "passive.vulnerable-js-dependency", name: "Vulnerable JavaScript dependency", sev: "low", confidence: "Tentative" };

/// One `vulnerabilities[]` entry (burp.Zxpi).
pub(crate) struct Vuln {
    at_or_above: Option<String>,
    below: Option<String>,
    info: Vec<String>,
    identifiers: BTreeMap<String, Vec<String>>,
}

/// One library (burp.Zcmc) with its compiled extractors.
pub(crate) struct Library {
    name: String,
    uri: Vec<regex::Regex>,
    filename: Vec<regex::Regex>,
    filecontent: Vec<regex::Regex>,
    vulns: Vec<Vuln>,
}

pub(crate) struct Repository {
    libs: Vec<Library>,
    /// Links Burp knows to be dead (`RetireJS/deadlinks.txt` next to the
    /// repository, when present).
    dead: BTreeSet<String>,
    /// Extractors Java accepts but the `regex` crate does not (look-around,
    /// back-references): "library kind: pattern".
    pub skipped: Vec<String>,
}

/// burp.Zcv2.ZE: the `§§version§§` placeholder, `{}` and newlines.
fn java_pattern(p: &str) -> String {
    let mut p = p.replace("§§version§§", r"[0-9][0-9.a-z_\\\\-]+");
    if p.contains('{') {
        p = p.replace("{}", r"\{\}");
    }
    p.replace('\n', r"\n")
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(a) => a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

impl Repository {
    /// burp.Zc_o.Zf: libraries without vulnerabilities are left out; a
    /// library without extractors makes the repository invalid.
    pub(crate) fn parse(json: &str, dead: BTreeSet<String>) -> Result<Self, String> {
        let root: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("Unable to parse JSON: {e}"))?;
        let obj = root.as_object().ok_or("Unable to parse JSON: not an object")?;
        let mut libs = Vec::new();
        let mut skipped = Vec::new();
        for (name, lib) in obj {
            let Some(vulns) = lib.get("vulnerabilities").and_then(|v| v.as_array()).filter(|v| !v.is_empty()) else { continue };
            let vulns = vulns
                .iter()
                .map(|v| Vuln {
                    at_or_above: v.get("atOrAbove").and_then(|x| x.as_str()).map(str::to_string),
                    below: v.get("below").and_then(|x| x.as_str()).map(str::to_string),
                    info: v.get("info").map(strings).unwrap_or_default(),
                    identifiers: v.get("identifiers").and_then(|x| x.as_object()).map(|m| m.iter().map(|(k, x)| (k.clone(), strings(x))).collect()).unwrap_or_default(),
                })
                .collect();
            let ex = lib.get("extractors").and_then(|x| x.as_object()).ok_or_else(|| format!("No extractors found in library {name}: each library should have at least one extractor"))?;
            let mut compiled = |kind: &str| -> Vec<regex::Regex> {
                ex.get(kind).map(strings).unwrap_or_default().iter().filter_map(|p| match regex::Regex::new(&java_pattern(p)) {
                    Ok(r) => Some(r),
                    Err(_) => {
                        skipped.push(format!("{name} {kind}: {p}"));
                        None
                    }
                }).collect()
            };
            let (uri, filename, filecontent) = (compiled("uri"), compiled("filename"), compiled("filecontent"));
            libs.push(Library { name: name.clone(), uri, filename, filecontent, vulns });
        }
        Ok(Repository { libs, dead, skipped })
    }

    pub(crate) fn load(path: &std::path::Path) -> Result<Self, String> {
        let json = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let dead = path.parent().map(|d| d.join("deadlinks.txt")).and_then(|f| std::fs::read_to_string(f).ok()).map(|s| s.lines().map(str::to_string).collect()).unwrap_or_default();
        Self::parse(&json, dead).map_err(|e| format!("{}: {e}", path.display()))
    }
}

static REPOSITORY: RwLock<Option<Result<Arc<Repository>, String>>> = RwLock::new(None);

/// The repository, loaded once through the resource resolver. The error
/// says what is missing (or what is wrong with the file).
pub(crate) fn repository() -> Result<Arc<Repository>, String> {
    if let Some(r) = REPOSITORY.read().unwrap().as_ref() {
        return r.clone();
    }
    let loaded = crate::paths::retirejs_repository().map_err(|m| m.to_string()).and_then(|p| Repository::load(&p)).map(Arc::new);
    if let Err(e) = &loaded {
        eprintln!("webprobe: {e}");
    }
    REPOSITORY.write().unwrap().get_or_insert(loaded).clone()
}

#[cfg(test)]
pub(crate) fn set_repository(r: Repository) {
    *REPOSITORY.write().unwrap() = Some(Ok(Arc::new(r)));
}

/// burp.Zp_1.Z_: `a` is below `b`, comparing the numeric parts of `b`
/// (split on `.` and `-`; `*` matches anything; non-numbers count as 0).
fn below(a: &str, b: &str) -> bool {
    let pa: Vec<&str> = a.split(['.', '-']).collect();
    let pb: Vec<&str> = b.split(['.', '-']).collect();
    let num = |p: &[&str], i: usize| p.get(i).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
    for i in 0..pb.len() {
        if pb[i] == "*" {
            continue;
        }
        let (x, y) = (num(&pa, i), num(&pb, i));
        if x != y {
            return x < y;
        }
    }
    false
}

/// burp.Zmwd.Zr: the library's vulnerabilities that cover `version`
/// (below `below`, at or above `atOrAbove`).
fn vulnerable<'a>(lib: &'a Library, version: &str) -> Vec<&'a Vuln> {
    lib.vulns.iter().filter(|v| v.below.as_deref().is_none_or(|b| below(version, b)) && v.at_or_above.as_deref().is_none_or(|a| !below(version, a))).collect()
}

fn version_of(r: &regex::Regex, s: &str) -> Option<String> {
    r.captures(s).and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
}

/// A library found at a version that has known vulnerabilities.
#[derive(Clone, PartialEq)]
struct Hit {
    lib: usize,
    version: String,
}

/// burp.Zmwd.ZQ / Zr (uri, filename extractors): per library, the first
/// pattern that yields a version decides.
fn by_name(repo: &Repository, s: &str, which: fn(&Library) -> &Vec<regex::Regex>) -> Vec<Hit> {
    let mut out = Vec::new();
    for (i, lib) in repo.libs.iter().enumerate() {
        if let Some(version) = which(lib).iter().find_map(|r| version_of(r, s)) {
            if !vulnerable(lib, &version).is_empty() {
                out.push(Hit { lib: i, version });
            }
        }
    }
    out
}

/// burp.Zply.Zy: the part after the last `/`.
fn file_name(url: &str) -> &str {
    match url.rfind('/') {
        Some(i) => &url[i + 1..],
        None if url.is_empty() => "",
        None => &url[1..],
    }
}

/// burp.Zply.Zf / ZX: the URL extractors, else the file-name ones.
fn by_url(repo: &Repository, url: &str) -> Vec<Hit> {
    let hits = by_name(repo, url, |l| &l.uri);
    if hits.is_empty() {
        by_name(repo, file_name(url), |l| &l.filename)
    } else {
        hits
    }
}

/// burp.Zmwd.ZU: per library, the first content pattern that yields a
/// version decides; a version without vulnerabilities ends that library.
fn by_content(repo: &Repository, body: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for (i, lib) in repo.libs.iter().enumerate() {
        if let Some(version) = lib.filecontent.iter().find_map(|r| version_of(r, body)) {
            if !vulnerable(lib, &version).is_empty() {
                out.push(Hit { lib: i, version });
            }
        }
    }
    out
}

/// burp.Zcu3.ZH: the summary, if the vulnerability has that key.
fn summary(v: &Vuln, t: &mut String, prefix: bool) -> bool {
    let Some(s) = v.identifiers.get("summary") else { return false };
    if !s.is_empty() {
        t.push_str(if prefix { ": " } else { "" });
        t.push_str(&s.join(", "));
        t.push_str("<br/>\n");
    }
    true
}

/// burp.Zcu3.Zd: the detail text for the libraries found.
fn detail(repo: &Repository, hits: &[Hit]) -> String {
    let mut t = String::new();
    for (n, h) in hits.iter().enumerate() {
        let lib = &repo.libs[h.lib];
        let vulns = vulnerable(lib, &h.version);
        let noun = if vulns.len() > 1 { "vulnerabilities" } else { "vulnerability" };
        t.push_str(&format!("<p>We{} detected <strong>{}</strong> version <strong>{}</strong>, which has the following {noun}:</p>\n<ul>\n", if n == 0 { "" } else { " also" }, lib.name, h.version));
        for v in vulns {
            t.push_str("<li>\n");
            if let Some(cves) = v.identifiers.get("CVE") {
                t.push_str(&cves.iter().map(|c| format!("<a href='https://nvd.nist.gov/vuln/detail/{c}'>{c}</a>")).collect::<Vec<_>>().join(", "));
                summary(v, &mut t, true);
            } else {
                let has_summary = summary(v, &mut t, false);
                if !v.info.is_empty() {
                    let live: Vec<&String> = v.info.iter().filter(|u| !repo.dead.contains(*u)).collect();
                    let links: Vec<&String> = if live.is_empty() {
                        t.push_str(if has_summary { "All " } else { "Vulnerability found, all " });
                        t.push_str("provided links appear to be broken but have been provided for reference:<br/>");
                        v.info.iter().collect()
                    } else {
                        if !has_summary {
                            t.push_str("Vulnerability with no summary found:<br/>");
                        }
                        live
                    };
                    t.push_str(&links.iter().map(|u| format!("<a href='{u}'>{u}</a><br/>")).collect::<Vec<_>>().join("\n"));
                    t.push('\n');
                }
            }
            t.push_str("</li>\n");
        }
        t.push_str("</ul><br/>\n");
    }
    let head = if hits.len() == 1 { "<p>We observed a vulnerable JavaScript library.</p>\n".to_string() } else { format!("<p>We observed {} vulnerable JavaScript libraries.</p>\n", hits.len()) };
    head + &t
}

/// The `src` of every `<script>` tag, first occurrence of each.
fn script_srcs(text: &str, low: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while let Some(o) = low[i..].find("<script") {
        let s = i + o;
        let e = low[s..].find('>').map(|x| s + x + 1).unwrap_or(low.len());
        if let Some(src) = super::passive_checks::attr(&low[s..e], &text[s..e], "src") {
            if !out.contains(&src) {
                out.push(src);
            }
        }
        i = e;
    }
    out
}

/// The libraries one exchange shows (burp.Zply.ZT): a script (path ends
/// in `.js` or a JavaScript content type) by its URL, else by its content;
/// an HTML page by the `src` of its script tags.
fn scan(repo: &Repository, cx: &PassiveCtx) -> Vec<Hit> {
    let ct = cx.ct.to_ascii_lowercase();
    let mut hits: Vec<Hit> = Vec::new();
    if cx.e.path.ends_with(".js") || ct.contains("javascript") || ct.contains("ecmascript") {
        hits = by_url(repo, &super::passive_checks::page_url(cx.e));
        if hits.is_empty() {
            let head = cx.p.head_len.min(cx.resp.len());
            let body = &cx.resp[head..cx.resp.len().min(head + 1_000_000)];
            hits = by_content(repo, &String::from_utf8_lossy(body));
        }
    } else if cx.e.path.ends_with(".html") || cx.e.path.ends_with(".htm") || cx.html {
        for src in script_srcs(&cx.text, &cx.low) {
            if let Some(h) = by_url(repo, &src).into_iter().next() {
                if !hits.contains(&h) {
                    hits.push(h);
                }
            }
        }
    }
    hits.dedup();
    hits
}

/// Vulnerable JavaScript dependency. Burp raises one issue per library and
/// version; here one issue per response names them all, in Burp's text for
/// several libraries.
pub(crate) fn run(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Ok(repo) = repository() else { return };
    run_with(&repo, cx, v);
}

pub(crate) fn run_with(repo: &Repository, cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let hits = scan(repo, cx);
    if !hits.is_empty() {
        v.push(mk_check(CH_VULNERABLE_JS, cx.e, detail(repo, &hits)));
    }
}

#[cfg(test)]
impl Repository {
    pub(crate) fn libs_len(&self) -> usize {
        self.libs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_order_follows_burp() {
        assert!(below("1.2.3", "1.3"));
        assert!(!below("1.3", "1.3.0"));
        assert!(below("1.12.0-beta", "1.12.1"));
        assert!(!below("2.0.0", "1.*.9"));
        assert!(below("1.5", "1.*.9"));
        assert!(!below("1.2.3", "1.2.3"));
        assert_eq!(file_name("/a/b/jquery-1.2.js"), "jquery-1.2.js");
        assert_eq!(java_pattern("x-(§§version§§)\\.js{}"), r"x-([0-9][0-9.a-z_\\\\-]+)\.js\{\}");
    }
}

// Content security policy issues (R-04), ported from burp.Zxr9 (the check,
// PPR_ContentSecurityPolicy), burp.Zupz (the policy model and parser) and
// burp.Zifp (the issue texts). Seven issue types, one registered unit each;
// all Information, Certain, except the Tentative clickjacking variant
// (burp.Zxr9.ZT: Zhcs byte 1). Zupz's sets were read from the running
// classes (Zq: directive names, ZY: valueless directives, ZR: sandbox may
// have no value, ZT: sandbox keywords); Zxr9.Zd() is non-zero at run time
// (111), which decides every obfuscated loop/flag below.

use super::passive_checks::PassiveCtx;
use super::*;

pub(crate) const CSP_NOT_ENFORCED: CheckDef = CheckDef { id: "passive.csp-not-enforced", name: "Content security policy: not enforced", sev: "info", confidence: "Certain" };
pub(crate) const CSP_UNTRUSTED_SCRIPTS: CheckDef = CheckDef { id: "passive.csp-untrusted-scripts", name: "Content security policy: allows untrusted script execution", sev: "info", confidence: "Certain" };
pub(crate) const CSP_UNTRUSTED_STYLES: CheckDef = CheckDef { id: "passive.csp-untrusted-styles", name: "Content security policy: allows untrusted style execution", sev: "info", confidence: "Certain" };
pub(crate) const CSP_ALLOWLISTED_SCRIPTS: CheckDef = CheckDef { id: "passive.csp-allowlisted-scripts", name: "Content security policy: allowlisted script resources", sev: "info", confidence: "Certain" };
pub(crate) const CSP_CLICKJACKING: CheckDef = CheckDef { id: "passive.csp-allows-clickjacking", name: "Content security policy: allows clickjacking", sev: "info", confidence: "Certain" };
pub(crate) const CSP_FORM_HIJACKING: CheckDef = CheckDef { id: "passive.csp-allows-form-hijacking", name: "Content security policy: allows form hijacking", sev: "info", confidence: "Certain" };
pub(crate) const CSP_MALFORMED: CheckDef = CheckDef { id: "passive.csp-malformed-syntax", name: "Content security policy: malformed syntax", sev: "info", confidence: "Certain" };

/// burp.Zupz.Zq.
const DIRECTIVES: [&str; 30] = [
    "manifest-src", "worker-src", "report-uri", "style-src-attr", "report-to", "frame-ancestors", "default-src", "script-src-elem", "object-src", "img-src",
    "script-src-attr", "navigate-to", "font-src", "upgrade-insecure-requests", "require-sri-for", "connect-src", "style-src", "script-src", "frame-src", "trusted-types",
    "require-trusted-types-for", "form-action", "prefetch-src", "style-src-elem", "sandbox", "child-src", "plugin-types", "media-src", "base-uri", "block-all-mixed-content",
];
/// burp.Zupz.ZY: directives that take no value.
const NO_VALUE: [&str; 2] = ["upgrade-insecure-requests", "block-all-mixed-content"];
/// burp.Zupz.ZR: directives that may have no value.
const MAY_BE_EMPTY: [&str; 1] = ["sandbox"];
/// burp.Zupz.ZT.
const SANDBOX: [&str; 11] = [
    "allow-presentation", "allow-downloads", "allow-top-navigations", "allow-orientation-lock", "allow-same-origin", "allow-scripts", "allow-modals", "allow-popups",
    "allow-forms", "allow-popups-to-escape-sandbox", "allow-pointer-lock",
];

/// The policies of one response (burp.Zupz).
#[derive(Default, Debug)]
pub(crate) struct Csp {
    /// One map per enforced policy (header or meta tag), directive -> value.
    policies: Vec<Vec<(String, String)>>,
    /// Violations of the CSP grammar (burp.Zbqw messages).
    errors: Vec<String>,
    /// X-Frame-Options present (Zupz.Zm).
    xfo: bool,
    /// frame-ancestors in a Content-Security-Policy header (Zupz.Zf).
    frame_ancestors_in_header: bool,
    /// A Content-Security-Policy-Report-Only header (Zupz.ZE).
    report_only: bool,
    /// A blank Content-Security-Policy header (Zupz.ZX).
    blank: bool,
}

/// Java's String.split: trailing empty strings dropped.
fn java_split<'a>(s: &'a str, sep: char) -> Vec<&'a str> {
    let mut v: Vec<&str> = s.split(sep).collect();
    while v.len() > 1 && v.last() == Some(&"") {
        v.pop();
    }
    if v == [""] && !s.is_empty() {
        v.clear();
    }
    v
}

fn tokens(v: &str) -> impl Iterator<Item = &str> {
    v.split_whitespace()
}

fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("CSP pattern")
}

/// burp.Zupz.ZW: a host source.
fn host_source(t: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let r = RE.get_or_init(|| re(r"^((http|ws)s?://)?(\*|(?:\*\.)?[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+)(?::\d+|:\*)?(?:/[A-Za-z0-9_\-._~:/?#@!$&'()*+=]*)?$"));
    t == "*" || r.is_match(t)
}

/// burp.Zupz.ZB: a scheme source.
fn scheme_source(t: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let t = t.replace("//*", "");
    RE.get_or_init(|| re(r"^[a-z][a-z0-9+\-.]{4,}:$")).is_match(&t) || ["http:", "https:", "data:", "blob:", "filesystem:", "ws:", "wss:", "about:", "tel:"].contains(&t.as_str())
}

/// java.net.URI's acceptance, approximated: no whitespace or characters
/// URIs never carry raw.
fn uri_ok(v: &str) -> bool {
    !v.chars().any(|c| c.is_whitespace() || "\"<>\\^`{|}".contains(c))
}

impl Csp {
    /// Parse the CSP meta tags of an HTML body, then the response headers
    /// (burp.Zupz.<init>).
    pub(crate) fn of(headers: &[(String, String)], html: Option<(&str, &str)>) -> Csp {
        let mut c = Csp::default();
        // `html` is (body, body lowercased): tags are found in the lowercase
        // copy and their values read, with their case, from the body.
        if let Some((text, low)) = html {
            let base = low.as_ptr() as usize;
            for tag_low in tags(low, "meta") {
                let at = tag_low.as_ptr() as usize - base;
                let tag = &text[at..at + tag_low.len()];
                let attr = |name: &str| {
                    let i = tag_low.find(&format!("{name}="))? + name.len() + 1;
                    let rest = &tag[i..];
                    let q = rest.chars().next()?;
                    if q == '"' || q == '\'' {
                        rest[1..].find(q).map(|e| rest[1..1 + e].to_string())
                    } else {
                        Some(rest.split(|ch: char| ch.is_whitespace() || ch == '>').next().unwrap_or("").to_string())
                    }
                };
                if attr("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("content-security-policy")) {
                    if let Some(content) = attr("content") {
                        c.parse(content.trim());
                    }
                }
            }
        }
        for (k, v) in headers {
            let name = k.trim();
            if name.eq_ignore_ascii_case("x-frame-options") {
                c.xfo = true;
            }
            if name.eq_ignore_ascii_case("content-security-policy-report-only") {
                c.report_only = true;
            } else if name.eq_ignore_ascii_case("content-security-policy") {
                let value = v.trim();
                c.frame_ancestors_in_header |= value.to_lowercase().contains("frame-ancestors");
                c.parse(value);
            }
        }
        c
    }

    fn err(&mut self, m: String) {
        self.errors.push(m);
    }

    /// burp.Zupz.Zv.
    fn parse(&mut self, policy: &str) {
        if policy.trim().is_empty() {
            self.blank = true;
            return;
        }
        let mut map: Vec<(String, String)> = Vec::new();
        for part in java_split(policy, ';') {
            let part = part.trim();
            let (name, value) = match part.split_once(' ') {
                Some((n, v)) => (n.trim().to_lowercase(), Some(v.trim().to_string())),
                None => (part.trim().to_lowercase(), None),
            };
            if !DIRECTIVES.contains(&name.as_str()) {
                self.err(format!("Invalid directive name: {name}"));
                continue;
            }
            if self.valid(&name, value.as_deref()) {
                if let Some(v) = value {
                    if !map.iter().any(|(k, _)| *k == name) {
                        map.push((name, v));
                    } else if let Some(slot) = map.iter_mut().find(|(k, _)| *k == name) {
                        slot.1 = v;
                    }
                }
            }
        }
        self.policies.push(map);
    }

    /// burp.Zupz.ZX.
    fn valid(&mut self, name: &str, value: Option<&str>) -> bool {
        if NO_VALUE.contains(&name) {
            if value.is_some() {
                self.err(format!("Directive {name} should have no value"));
                return false;
            }
            return true;
        }
        let Some(value) = value else {
            if MAY_BE_EMPTY.contains(&name) {
                return true;
            }
            self.err(format!("Directive {name} has no value"));
            return false;
        };
        match name {
            "report-uri" => {
                if uri_ok(value) {
                    true
                } else {
                    self.err(format!("Directive report-uri has invalid value: {value}"));
                    false
                }
            }
            "require-trusted-types-for" => {
                if value == "'script'" {
                    true
                } else {
                    self.err(format!("Directive {name} has invalid value: {value}"));
                    false
                }
            }
            "report-to" => {
                if value.chars().all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)) && !value.is_empty() {
                    true
                } else {
                    self.err(format!("Directive {name} has invalid value: {value}"));
                    false
                }
            }
            "sandbox" => {
                for t in tokens(value) {
                    if !SANDBOX.contains(&t) {
                        self.err(format!("Directive sandbox has unrecognised value: {t}"));
                        return false;
                    }
                }
                true
            }
            _ => {
                let mut ok = true;
                for t in tokens(value) {
                    let mut t = t.to_string();
                    let mut quoted = false;
                    if t.contains('\'') {
                        let well = t.len() >= 3 && t.starts_with('\'') && t.ends_with('\'') && !t[1..t.len() - 1].contains(['\'', ' ', '\t']);
                        if !well {
                            self.err(format!("Directive {name} has incorrectly quoted value: {t}"));
                            ok = false;
                        }
                        t = t.replace('\'', "").trim().to_string();
                        quoted = true;
                    }
                    self.component(name, &t.to_lowercase(), quoted);
                }
                ok
            }
        }
    }

    /// burp.Zupz.ZG: keyword, scheme, host, nonce or hash, else illegal.
    fn component(&mut self, name: &str, t: &str, quoted: bool) {
        let should_quote = |me: &mut Csp, hit: bool| -> bool {
            if hit && !quoted {
                me.err(format!("Directive {name} has value component: {t} which should be quoted"));
            }
            hit && quoted
        };
        let keyword = ["self", "none", "unsafe-inline", "unsafe-eval", "wasm-unsafe-eval", "unsafe-hashes", "strict-dynamic", "report-sample"].contains(&t);
        if should_quote(self, keyword) || scheme_source(t) || host_source(t) {
            return;
        }
        let nonce = t.starts_with("nonce-");
        if should_quote(self, nonce) {
            return;
        }
        static HASH: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let hash = HASH.get_or_init(|| re(r"^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$")).is_match(t);
        if should_quote(self, hash) {
            return;
        }
        self.err(format!("Directive {name} has illegal value component: {t}"));
    }

    /// burp.Zupz.Zw: `dir`, or default-src, of every policy.
    fn with_default(&self, dir: &str) -> Vec<&str> {
        self.policies.iter().filter_map(|m| m.iter().find(|(k, _)| k == dir).or_else(|| m.iter().find(|(k, _)| k == "default-src")).map(|(_, v)| v.as_str())).collect()
    }

    /// burp.Zupz.Za: `dir` only.
    fn only(&self, dir: &str) -> Vec<&str> {
        self.policies.iter().filter_map(|m| m.iter().find(|(k, _)| k == dir).map(|(_, v)| v.as_str())).collect()
    }

    fn none(&self) -> bool {
        self.policies.is_empty()
    }

    fn unsafe_kw(values: &[&str], kw: &str) -> bool {
        let mitigated = |v: &str| v.contains("'nonce-") || v.contains("'sha256-") || v.contains("'sha384-") || v.contains("'sha512-");
        values.iter().any(|v| tokens(v).any(|t| t.replace('\'', "").trim().eq_ignore_ascii_case(kw)) && !mitigated(v))
    }

    fn wildcard(v: &str) -> bool {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let r = RE.get_or_init(|| re(r"^(((http|ws)s?)://)?\*$"));
        tokens(v).any(|t| r.is_match(&t.replace('\'', "")))
    }

    fn data(v: &str) -> bool {
        tokens(v).any(|t| t.replace('\'', "").starts_with("data:"))
    }

    fn allowlist(v: &str) -> bool {
        tokens(v).any(|t| host_source(&t.replace('\'', "")))
    }

    /// burp.Zupz.isAnyHost(Predicate) / Zo: the script (or style) source
    /// lists, with the -attr / -elem variants.
    fn sources(&self, kind: &str, pred: fn(&str) -> bool) -> bool {
        if self.none() {
            return false;
        }
        let all = |l: &[&str]| l.iter().all(|v| pred(v));
        let main = self.with_default(&format!("{kind}-src"));
        let attr = self.with_default(&format!("{kind}-src-attr"));
        let elem = self.with_default(&format!("{kind}-src-elem"));
        let has = !main.is_empty();
        if has && all(&main) {
            return true;
        }
        (!has && (attr.is_empty() || elem.is_empty())) || (!attr.is_empty() && all(&attr)) || (!elem.is_empty() && all(&elem))
    }

    /// burp.Zupz.ZJ / ZK: a `nonce-` shorter than 8 characters in
    /// script-src (style-src).
    fn short_nonce(&self, dir: &str) -> bool {
        self.policies.iter().flat_map(|m| m.iter()).filter(|(k, _)| k.eq_ignore_ascii_case(dir)).any(|(_, v)| tokens(v).any(|t| {
            let t = t.replace('\'', "");
            t.starts_with("nonce-") && t.len() < 14
        }))
    }

    fn scripts_inline(&self) -> bool {
        ["script-src", "script-src-elem", "script-src-attr"].iter().any(|d| Self::unsafe_kw(&self.with_default(d), "unsafe-inline"))
    }
    fn scripts_eval(&self) -> bool {
        ["script-src", "script-src-elem", "script-src-attr"].iter().any(|d| Self::unsafe_kw(&self.with_default(d), "unsafe-eval"))
    }
    fn scripts_wildcard(&self) -> bool {
        self.sources("script", Self::wildcard)
    }
    fn scripts_data(&self) -> bool {
        self.sources("script", Self::data)
    }
    fn scripts_allowlist(&self) -> bool {
        self.scripts_wildcard() || self.sources("script", Self::allowlist)
    }
    fn styles_inline(&self) -> bool {
        ["style-src", "style-src-elem", "style-src-attr"].iter().any(|d| Self::unsafe_kw(&self.with_default(d), "unsafe-inline"))
    }
    fn styles_wildcard(&self) -> bool {
        self.sources("style", Self::wildcard)
    }
    fn styles_data(&self) -> bool {
        self.sources("style", Self::data)
    }
    fn frame_ancestors_present(&self) -> bool {
        !self.only("frame-ancestors").is_empty()
    }
    fn frame_ancestors_wildcard(&self) -> bool {
        self.with_default("frame-ancestors").iter().all(|v| Self::wildcard(v))
    }
    fn frame_ancestors_loose(&self) -> bool {
        self.frame_ancestors_wildcard() || self.with_default("frame-ancestors").iter().all(|v| Self::allowlist(v))
    }
    fn form_action_present(&self) -> bool {
        !self.with_default("form-action").is_empty()
    }
    fn form_action_wildcard(&self) -> bool {
        self.with_default("form-action").iter().all(|v| Self::wildcard(v))
    }
}

/// burp.Zxr9.ZT gate: a response Burp classes as HTML or plain text,
/// stated or sniffed, or one with no stated type (Zmlg 256 / 257 / 0).
/// WebProbe's MIME families stand in for Burp's sniffer.
fn applies(cx: &PassiveCtx) -> bool {
    if cx.binary {
        return false;
    }
    let stated = if cx.ct.trim().is_empty() { "" } else { crate::mime::burp_mime(&cx.ct, &[]) };
    let sniffed = crate::mime::burp_mime("", cx.body);
    stated.is_empty() || matches!(stated, "HTML" | "text") || sniffed == "HTML"
}

fn policy(cx: &PassiveCtx) -> Option<Csp> {
    applies(cx).then(|| Csp::of(&cx.p.headers, cx.html.then_some((cx.text.as_str(), cx.low.as_str()))))
}

fn issue(cx: &PassiveCtx, c: CheckDef, confidence: &str, detail: String) -> ScanIssue {
    let mut i = mk(c.sev, c.name, cx.e, detail);
    i.confidence = confidence.into();
    i
}

/// NOT_ENFORCED: no enforced policy, and a Report-Only header or a blank
/// Content-Security-Policy header (Zifp.ZH). Without either, Burp reports
/// no CSP issue at all.
pub(crate) fn run_not_enforced(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = policy(cx) else { return };
    if p.none() && (p.report_only || p.blank) {
        let text = if p.report_only {
            "<p>The content security policy is not currently enforced because the policy is served with the Content-Security-Policy-Report-Only header. This header will report any CSP violations but does not prevent any resources from being loaded.</p>"
        } else {
            "<p>The absence of a Content Security Policy (CSP) elevates a website's vulnerability risk, particularly to cross-site scripting (XSS) attacks, as it enables attackers to load unrestricted resources. Without CSP, there is no control over inline scripts and styles that are commonly exploited in XSS attacks. Additionally, not having a CSP hinders the ability to monitor and report security policy violations, compromising the website's overall security posture.</p>"
        };
        v.push(issue(cx, CSP_NOT_ENFORCED, "Certain", text.into()));
    }
}

/// The other six issues need at least one enforced policy (Zxr9 leaves
/// label105 when there is none).
fn enforced(cx: &PassiveCtx) -> Option<Csp> {
    policy(cx).filter(|p| !p.none())
}

pub(crate) fn run_untrusted_scripts(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    let (inline, eval, wild, data, nonce) = (p.scripts_inline(), p.scripts_eval(), p.scripts_wildcard(), p.scripts_data(), p.short_nonce("script-src"));
    if inline || eval || wild || data || nonce {
        let mut t = String::from("<p>The content security policy fails to prevent untrusted JavaScript from being executed. As a result, it may fail to mitigate cross-site scripting attacks.</p><p>The policy has the following issues:</p>");
        if inline {
            t.push_str("<p>The policy contains unsafe-inline which can allow arbitrary scripts to be executed.</p>");
        }
        if eval {
            t.push_str("<p>Allowing dynamic JavaScript execution through unsafe-eval in the policy fails to mitigate some DOM-based cross-site scripting vulnerabilities.</p>");
        }
        if wild {
            t.push_str("<p>The policy allows global wildcard URLs which allows arbitrary scripts to be executed.</p>");
        }
        if data {
            t.push_str("<p>The policy allows data: URLs which allows arbitrary scripts to be executed.</p>");
        }
        if nonce {
            t.push_str("<p>The nonce is under 8 characters long, which may expose it to brute-force attacks that enable an attacker to brute-force the nonce value and bypass the restrictions set out by the policy which could result in an attacker being able to execute arbitrary scripts.</p>");
        }
        v.push(issue(cx, CSP_UNTRUSTED_SCRIPTS, "Certain", t));
    }
}

pub(crate) fn run_untrusted_styles(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    let (inline, wild, data, nonce) = (p.styles_inline(), p.styles_wildcard(), p.styles_data(), p.short_nonce("style-src"));
    if inline || wild || data || nonce {
        let mut t = String::from("<p>The content security policy fails to prevent untrusted style execution. As a result, it may fail to mitigate style based data exfiltration.</p>");
        if inline {
            t.push_str("<p>The policy contains unsafe-inline which can allow arbitrary styles to be executed.</p>");
        }
        if wild {
            t.push_str("<p>The policy allows global wildcard URLs which allows arbitrary styles to be executed.</p>");
        }
        if data {
            t.push_str("<p>The policy allows data: URLs which allows arbitrary styles to be executed.</p>");
        }
        if nonce {
            t.push_str("<p>The nonce is under 8 characters long, which may expose it to brute-force attacks. That could enable an attacker to brute-force the nonce value and bypass the restrictions set out by the policy which could result in an attacker being able to execute arbitrary styles.</p>");
        }
        v.push(issue(cx, CSP_UNTRUSTED_STYLES, "Certain", t));
    }
}

pub(crate) fn run_allowlisted_scripts(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if !p.scripts_wildcard() && p.scripts_allowlist() {
        v.push(issue(cx, CSP_ALLOWLISTED_SCRIPTS, "Certain", "<p>The Content Security Policy relies on an allowlist to control script-based resource loading. However, this approach is vulnerable if allowlisted domains host scripts susceptible to reflected or DOM-based XSS attacks. Additionally, JSONP-based endpoints can be abused too. These vulnerabilities could enable attackers to bypass the CSP, leading to untrusted JavaScript execution.</p>".into()));
    }
}

/// Zifp.Zb's text.
fn clickjacking_text(p: &Csp) -> String {
    let mut t = String::from("<p>The content security policy does not mitigate clickjacking attacks:</p>");
    if !p.frame_ancestors_present() {
        t.push_str("<p>The frame-ancestors directive is not present in this content security policy.</p>");
    } else if p.frame_ancestors_wildcard() {
        t.push_str("<p>The frame-ancestors directive uses a global wildcard which will allow any site to frame the target application.</p>");
    }
    if p.frame_ancestors_present() && !p.frame_ancestors_in_header {
        t.push_str("<p>The frame-ancestors directive is present in the meta tag but not the response header.<br/>This directive will not be enforced and will not mitigate clickjacking attacks.</p>");
    }
    t
}

pub(crate) fn run_clickjacking(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if p.xfo {
        return;
    }
    if !p.frame_ancestors_in_header || p.frame_ancestors_wildcard() {
        v.push(issue(cx, CSP_CLICKJACKING, "Certain", clickjacking_text(&p)));
    } else if p.frame_ancestors_loose() {
        v.push(issue(cx, CSP_CLICKJACKING, "Tentative", clickjacking_text(&p)));
    }
}

pub(crate) fn run_form_hijacking(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if !p.form_action_present() || p.form_action_wildcard() {
        v.push(issue(cx, CSP_FORM_HIJACKING, "Certain", "<p>The content security policy doesn't prevent form hijacking, where attackers with HTML injection hijack forms using action attributes. This can lead to credential theft by autofilling passwords from a manager and sending them to an attacker's server upon form submission.</p>".into()));
    }
}

pub(crate) fn run_malformed(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let Some(p) = enforced(cx) else { return };
    if !p.errors.is_empty() {
        let mut t = String::from("<p>Malformed syntax in the policy means the following directives, which do not conform to the CSP specification, will not be enforced:</p>");
        for e in &p.errors {
            t.push_str(&format!("<p>{}</p>", util::html_encode(e)));
        }
        v.push(issue(cx, CSP_MALFORMED, "Certain", t));
    }
}

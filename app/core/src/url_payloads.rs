//! The URL-shaped Collaborator payloads of Burp's external-interaction
//! check (D-12): burp.Zpgu splits an insertion point's base value into URL
//! parts (burp.Zbvs), and burp.Zbxl builds one payload per variant from
//! them: the bare domain, the value's own scheme, `http://`, `Http://` and
//! `https://`, each keeping the value's userinfo, path and query around the
//! Collaborator domain.
//!
//! Opaque predicates in the decompiled code (`Zunv.Zj()` = 97 after its
//! static initialiser, `Z_e.ZY()` = null) never break the loops, so every
//! separator list is walked in full.

/// burp.Zbvs: a value split into URL parts. `None` where Burp holds null.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UrlParts {
    /// Zz: the scheme before the separator ("" becomes None).
    pub scheme: Option<String>,
    /// Zf: the separator as written ("://", "//", "\\\\", ":").
    pub sep: Option<String>,
    /// ZL: userinfo including its "@".
    pub userinfo: Option<String>,
    /// ZO: the host (and port).
    pub host: Option<String>,
    /// Zs: the path.
    pub path: Option<String>,
    /// Zk: the query as split off (see [`UrlParts::query`]).
    query_raw: Option<String>,
}

impl UrlParts {
    /// Zbvs.Zb: the query, with "?" put in front unless it starts with
    /// "?" or ";".
    pub(crate) fn query(&self) -> Option<String> {
        self.query_raw.as_ref().map(|q| {
            if q.starts_with('?') || q.starts_with(';') {
                q.clone()
            } else {
                format!("?{q}")
            }
        })
    }
}

/// Java's Character.isLetter || isDigit, close enough for URL text.
fn letter_or_digit(c: char) -> bool {
    c.is_alphabetic() || c.is_numeric()
}

/// Zpgu.ZG (lambda$static$0): letters and digits only (empty passes).
fn scheme_ok(s: &str) -> bool {
    s.chars().all(letter_or_digit)
}

/// Zpgu.ZF (lambda$static$1): userinfo: letters, digits, '%', at most one ':'.
fn userinfo_ok(s: &str) -> bool {
    let mut colon = false;
    for c in s.chars() {
        if c == ':' {
            if colon {
                return false;
            }
            colon = true;
        } else if !letter_or_digit(c) && c != '%' {
            return false;
        }
    }
    true
}

/// Zpgu.ZP (lambda$static$2): a host: letters, digits, '.', '-', one ':'
/// not first; not empty; ends in a letter or digit.
fn host_ok(s: &str) -> bool {
    let mut colon = false;
    for (i, c) in s.chars().enumerate() {
        if c == ':' {
            if i == 0 || colon {
                return false;
            }
            colon = true;
        } else if !letter_or_digit(c) && c != '.' && c != '-' {
            return false;
        }
    }
    s.chars().last().is_some_and(letter_or_digit)
}

/// Zpgu.ZO: empty is null.
fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Zpgu.Zx: the scheme separators in the order Burp tries them, with the
/// most characters a repeating one may run to (Zua8; None = Zuap, taken as
/// written).
const SCHEME_SEPS: [(&str, Option<usize>); 4] = [
    ("://", Some(7)),
    ("//", Some(6)),
    ("\\\\", Some(6)),
    (":", None),
];

/// Zpgu.ZL: (scheme, separator, rest) at the first separator of the list
/// found anywhere (list order, not position); `Ok(None)`: no separator;
/// `Err(())`: the value is not a URL (Burp returns null).
fn split_scheme(v: &str) -> Result<Option<(String, String, String)>, ()> {
    for (sep, max) in SCHEME_SEPS {
        let Some(idx) = v.find(sep) else { continue };
        let prefix = &v[..idx];
        if !scheme_ok(prefix) {
            return Err(());
        }
        let mut end = idx + sep.len();
        if let Some(max) = max {
            // Zua8.ZO: the separator's last character may repeat, up to
            // `max` characters in all.
            let last = sep.as_bytes()[sep.len() - 1];
            while end < v.len() && v.as_bytes()[end] == last {
                end += 1;
                if end - idx > max {
                    return Err(());
                }
            }
        }
        return Ok(Some((
            prefix.to_string(),
            v[idx..end].to_string(),
            v[end..].to_string(),
        )));
    }
    Ok(None)
}

/// Zpgu.ZS: (userinfo with its "@", rest) at the first "@"; `Err(())`
/// when what precedes it is not userinfo.
fn split_userinfo(v: &str) -> Result<Option<(String, String)>, ()> {
    match v.find('@') {
        None => Ok(None),
        Some(i) if userinfo_ok(&v[..i]) => Ok(Some((v[..=i].to_string(), v[i + 1..].to_string()))),
        Some(_) => Err(()),
    }
}

/// Zpgu.Zp: (host, rest) at the first of "/", "\", "./", "?", ";" found
/// (list order); the rest keeps its separator.
fn split_host(v: &str) -> Option<(&str, &str)> {
    ["/", "\\", "./", "?", ";"]
        .iter()
        .find_map(|sep| v.find(sep))
        .map(|i| (&v[..i], &v[i..]))
}

/// Zpgu.Zv: path and query out of what follows the host.
fn finish(
    scheme: Option<String>,
    sep: Option<String>,
    userinfo: Option<String>,
    host: Option<String>,
    rest: Option<String>,
) -> UrlParts {
    let mut p = UrlParts {
        scheme,
        sep,
        userinfo,
        host,
        path: None,
        query_raw: None,
    };
    let Some(rest) = rest else { return p };
    // Zpgu.Zh: the first '?', else the first ';'.
    match rest.find('?').or_else(|| rest.find(';')) {
        Some(i) => {
            p.path = non_empty(&rest[..i]);
            p.query_raw = Some(rest[i..].to_string());
        }
        None if !rest.starts_with('/') && !rest.starts_with("./") && !rest.starts_with('\\') => {
            p.query_raw = Some(rest)
        }
        None => p.path = Some(rest),
    }
    p
}

/// burp.Zpgu.Z_: split `v` into URL parts.
pub(crate) fn parse(v: &str) -> UrlParts {
    let (mut scheme, mut sep, mut userinfo, mut host, mut path) = (None, None, None, None, None);
    let mut rest = v.to_string();
    match split_scheme(&rest) {
        Err(()) => return finish(None, None, None, None, non_empty(&rest)),
        // Zpgu.Z_: a prefix starting with ':' is not a scheme (the scheme
        // check already rules ':' out).
        Ok(Some((s, se, r))) => {
            scheme = non_empty(&s);
            sep = Some(se);
            rest = r;
        }
        Ok(None) => {}
    }
    match split_userinfo(&rest) {
        Err(()) => return finish(scheme, sep, None, None, non_empty(&rest)),
        Ok(Some((u, r))) => {
            // Zpgu.Zm: "user:pass@host" read as scheme "user" + ":" is
            // userinfo after all.
            if sep.as_deref() == Some(":") && scheme.is_some() && !u.contains(':') {
                userinfo = Some(format!(
                    "{}{}{u}",
                    scheme.take().unwrap_or_default(),
                    sep.take().unwrap_or_default()
                ));
            } else {
                userinfo = Some(u);
            }
            rest = r;
        }
        Ok(None) => {}
    }
    match split_host(&rest) {
        Some((h, p)) if host_ok(h) => {
            host = Some(h.to_string());
            path = Some(p.to_string());
        }
        Some(_) => path = non_empty(&rest),
        None if host_ok(&rest) => host = Some(rest),
        None => path = non_empty(&rest),
    }
    finish(scheme, sep, userinfo, host, path)
}

/// burp.Zpu2's URL payload kinds, as Zbxl.Zu lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UrlVariant {
    /// NON_SCHEMA_URL_PAYLOAD: the bare domain.
    NonSchema,
    /// OWN_SCHEMA_URL_PAYLOAD: the value's own scheme and separator.
    OwnSchema,
    /// HTTP_PREFIXED_URL_PAYLOAD.
    Http,
    /// HTTP_MIXED_CASE_PREFIXED_URL_PAYLOAD ("Http://").
    HttpMixedCase,
    /// HTTPS_PREFIXED_URL_PAYLOAD.
    Https,
}

/// burp.Zbxl.Zu: the variants for base value `value`; `thorough`: the
/// audit thoroughness is Thorough (burp.Zxfo forces it when the value
/// looks like a URL, [`looks_like_url`]).
pub(crate) fn variants(value: &str, thorough: bool) -> Vec<UrlVariant> {
    let p = parse(value);
    let mut out = Vec::new();
    if p.sep.is_none() && !is_email(value) {
        out.push(UrlVariant::NonSchema);
    }
    if p.sep.is_some() {
        out.push(UrlVariant::OwnSchema);
    }
    let is = |s: &str| {
        p.scheme
            .as_deref()
            .is_some_and(|x| x.eq_ignore_ascii_case(s))
    };
    if !is("http") {
        out.push(UrlVariant::Http);
    }
    if thorough {
        out.push(UrlVariant::HttpMixedCase);
        if !is("https") {
            out.push(UrlVariant::Https);
        }
    }
    out
}

/// burp.Zbxl.ZT / ZY: the payload of `variant` for base value `value`
/// with the Collaborator domain `domain` (Zuxr.Zk: `<id>.<server>`). A
/// prefixed payload keeps the value's userinfo, path and query; a value
/// with none of those and no separator gets "/?<host>". Burp appends the
/// host with StringBuilder.append, so a missing host reads "null" (an
/// empty value gives `http://<domain>/?null`); ported as is.
pub(crate) fn payload(value: &str, variant: UrlVariant, domain: &str) -> String {
    let p = parse(value);
    // Zbxl.Zn: the scheme with the value's separator, "://" when it has none.
    let with = |scheme: &str| format!("{scheme}{}", p.sep.as_deref().unwrap_or("://"));
    let prefix = match variant {
        UrlVariant::OwnSchema => Some(format!(
            "{}{}",
            p.scheme.as_deref().unwrap_or(""),
            p.sep.as_deref().unwrap_or("")
        )),
        UrlVariant::Http => Some(with("http")),
        UrlVariant::HttpMixedCase => Some("Http://".to_string()),
        UrlVariant::Https => Some(with("https")),
        UrlVariant::NonSchema => None,
    };
    let mut out = String::new();
    if let Some(pre) = &prefix {
        out.push_str(pre);
    }
    if let Some(u) = &p.userinfo {
        out.push_str(u);
    }
    out.push_str(domain);
    if prefix.is_some() {
        let query = p.query();
        if let Some(path) = &p.path {
            out.push_str(path);
        }
        if let Some(q) = &query {
            out.push_str(q);
        }
        if p.path.is_none() && query.is_none() && p.sep.is_none() {
            out.push_str("/?");
            out.push_str(p.host.as_deref().unwrap_or("null"));
        }
    }
    out
}

/// burp.Zc4x.Z_: `v` reads as an e-mail address.
pub(crate) fn is_email(v: &str) -> bool {
    let c: Vec<char> = v.chars().collect();
    let Some(at) = c.iter().position(|&x| x == '@') else {
        return false;
    };
    let ascii_an = |x: char| x.is_ascii_alphanumeric();
    if at < 1
        || c.len() < 5
        || c[0] == '.'
        || c[c.len() - 1] == '.'
        || c[at - 1] == '.'
        || v.contains("..")
    {
        return false;
    }
    c.iter().enumerate().all(|(i, &x)| {
        if i < at {
            ascii_an(x) || ".@!#$%&'*+-/=?^_`{|}~".contains(x)
        } else if i > at {
            ascii_an(x) || x == '.' || x == '-'
        } else {
            true
        }
    })
}

/// burp.Zibp.ZN (baseValueLooksLikeUrl): `scheme:...`, or a dotted host
/// name (optionally after "/", "//", "\\" or "\") with an optional path.
pub(crate) fn looks_like_url(v: &str) -> bool {
    use std::sync::OnceLock;
    static RES: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    let res = RES.get_or_init(|| {
        let host = r"([A-Za-z0-9-]+\.[A-Za-z0-9-]+)+\.?(/.*)*";
        std::iter::once(r"^[A-z0-9]+:.*$".to_string())
            .chain(
                ["", "/", "//", r"\\\\", r"\\"]
                    .iter()
                    .map(|pre| format!("^(?:{pre}{host})$")),
            )
            .map(|r| regex::Regex::new(&r).expect("static regex"))
            .collect()
    });
    res.iter().any(|r| r.is_match(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    type PartsFields = (
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<String>,
    );

    fn parts(v: &str) -> PartsFields {
        // Leaked for terse assertions in tests only.
        let p: &'static UrlParts = Box::leak(Box::new(parse(v)));
        (
            p.scheme.as_deref(),
            p.sep.as_deref(),
            p.userinfo.as_deref(),
            p.host.as_deref(),
            p.path.as_deref(),
            p.query(),
        )
    }

    #[test]
    fn zpgu_splits_values_like_burp() {
        let q = |s: &str| Some(s.to_string());
        assert_eq!(
            parts("https://user:pw@shop.test:8443/a/b?x=1"),
            (
                Some("https"),
                Some("://"),
                Some("user:pw@"),
                Some("shop.test:8443"),
                Some("/a/b"),
                q("?x=1")
            )
        );
        assert_eq!(
            parts("shop.test"),
            (None, None, None, Some("shop.test"), None, None)
        );
        assert_eq!(
            parts("//cdn.test/x.js"),
            (
                None,
                Some("//"),
                None,
                Some("cdn.test"),
                Some("/x.js"),
                None
            )
        );
        assert_eq!(
            parts("\\\\files\\share"),
            (
                None,
                Some("\\\\"),
                None,
                Some("files"),
                Some("\\share"),
                None
            )
        );
        // Zua8: the separator's last character repeats.
        assert_eq!(
            parts("http:///x.test"),
            (Some("http"), Some(":///"), None, Some("x.test"), None, None)
        );
        // ... but not past its limit: then the whole value is a query.
        assert_eq!(
            parts("a:////////b"),
            (None, None, None, None, None, q("?a:////////b"))
        );
        // Zpgu.Zm: "user:pw@host" is userinfo, not scheme "user" (so is
        // "mailto:me@" for the same reason).
        assert_eq!(
            parts("user:pw@host.test"),
            (None, None, Some("user:pw@"), Some("host.test"), None, None)
        );
        assert_eq!(
            parts("user@host.test/p"),
            (
                None,
                None,
                Some("user@"),
                Some("host.test"),
                Some("/p"),
                None
            )
        );
        assert_eq!(
            parts("mailto:me@x.test"),
            (None, None, Some("mailto:me@"), Some("x.test"), None, None)
        );
        // A non-host value lands in the query slot (Zpgu.Zv), a path stays a path.
        assert_eq!(
            parts("hello world"),
            (None, None, None, None, None, q("?hello world"))
        );
        assert_eq!(
            parts("/a/b?c"),
            (None, None, None, None, Some("/a/b"), q("?c"))
        );
        assert_eq!(parts("12"), (None, None, None, Some("12"), None, None));
        assert_eq!(parts(""), (None, None, None, None, None, None));
        // Separator list order, not position: "://" is tried before ":".
        assert_eq!(
            parts("a:b://c.test"),
            (None, None, None, None, None, q("?a:b://c.test"))
        );
    }

    #[test]
    fn zbxl_variants_and_payloads() {
        use UrlVariant::*;
        let d = "abc.oast.test";
        // A plain value: bare domain, then http:// with "/?<host>".
        assert_eq!(variants("12", false), vec![NonSchema, Http]);
        assert_eq!(payload("12", NonSchema, d), "abc.oast.test");
        assert_eq!(payload("12", Http, d), "http://abc.oast.test/?12");
        // A URL: its own scheme with path and query kept; no http:// for http.
        let u = "http://shop.test/img?id=4";
        assert_eq!(variants(u, false), vec![OwnSchema]);
        assert_eq!(variants(u, true), vec![OwnSchema, HttpMixedCase, Https]);
        assert_eq!(payload(u, OwnSchema, d), "http://abc.oast.test/img?id=4");
        assert_eq!(
            payload(u, HttpMixedCase, d),
            "Http://abc.oast.test/img?id=4"
        );
        assert_eq!(payload(u, Https, d), "https://abc.oast.test/img?id=4");
        // Another scheme: own scheme, then http with the value's separator.
        let f = "ftp://user@files.test/a";
        assert_eq!(
            variants(f, true),
            vec![OwnSchema, Http, HttpMixedCase, Https]
        );
        assert_eq!(payload(f, OwnSchema, d), "ftp://user@abc.oast.test/a");
        assert_eq!(payload(f, Http, d), "http://user@abc.oast.test/a");
        // An HTTPS URL at Thorough: no https:// variant.
        assert_eq!(
            variants("HTTPS://x.test/", true),
            vec![OwnSchema, Http, HttpMixedCase]
        );
        // An e-mail address gets no bare-domain variant.
        assert_eq!(variants("me@mail.test", false), vec![Http]);
        assert_eq!(
            payload("me@mail.test", Http, d),
            "http://me@abc.oast.test/?mail.test"
        );
        // A protocol-relative URL: own "scheme" is the separator alone.
        assert_eq!(
            payload("//cdn.test/x.js", OwnSchema, d),
            "//abc.oast.test/x.js"
        );
        assert_eq!(
            payload("//cdn.test/x.js", Http, d),
            "http//abc.oast.test/x.js"
        );
        // Free text: the query slot follows the domain.
        assert_eq!(payload("hello", Http, d), "http://abc.oast.test/?hello");
        // Java's append(null): an empty value.
        assert_eq!(payload("", Http, d), "http://abc.oast.test/?null");
    }

    #[test]
    fn email_and_url_shapes() {
        assert!(is_email("me@mail.test") && is_email("a.b+c@x-y.test"));
        for v in [
            "@a.test",
            "me@x",
            ".me@x.test",
            "me.@x.test",
            "me@x.test.",
            "me@x..test",
            "me@x_y.test",
            "nope",
        ] {
            assert!(!is_email(v), "{v}");
        }
        for v in [
            "http://x",
            "x.test",
            "/x.test/a",
            "//cdn.test",
            "\\\\srv.test",
            "\\srv.test",
            "a1:b",
            "x.test.",
        ] {
            assert!(looks_like_url(v), "{v}");
        }
        for v in ["hello", "12", "/path", "x .test", ":x"] {
            assert!(!looks_like_url(v), "{v}");
        }
    }
}

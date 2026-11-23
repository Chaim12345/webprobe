//! BCheck execution support: value resolution against a request/response
//! context, the documented functions, request-modification application and
//! condition evaluation. The scan runner that drives definitions over
//! audited traffic lands in a follow-up slice.

use std::collections::HashMap;

use base64::Engine;
use rand::Rng;
use sha2::Digest;

use super::{Condition, Expr, InteractionKind, Interpol, ModMode, Part, RequestMod, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct RequestData {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponseData {
    pub status_code: u16,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Exchange {
    pub request: RequestData,
    pub response: ResponseData,
}

impl RequestData {
    /// Serialized request text (start line, headers, body) for `{x.request}`.
    pub fn raw(&self) -> String {
        let (path, query) = url_path_query(&self.url);
        let mut out = format!("{} {}", self.method, path);
        if !query.is_empty() {
            out.push('?');
            out.push_str(&query);
        }
        out.push(' ');
        out.push_str(if self.http_version.is_empty() {
            "HTTP/1.1"
        } else {
            &self.http_version
        });
        out.push_str("\r\n");
        for (k, v) in &self.headers {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        // A send-payload or replacing op may have changed the body after the
        // headers were captured: the length on the wire must match it.
        let mut wrote_len = false;
        let mut head = String::new();
        for line in out.lines() {
            if line.to_ascii_lowercase().starts_with("content-length:") {
                head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
                wrote_len = true;
            } else if line.is_empty() {
                break;
            } else {
                head.push_str(line);
                head.push_str("\r\n");
            }
        }
        if !wrote_len {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        head.push_str("\r\n");
        head.push_str(&self.body);
        head
    }
}

impl ResponseData {
    /// Serialized response text for `{x.response}` / `differs from`.
    pub fn raw(&self) -> String {
        let mut out = format!(
            "{} {}\r\n",
            if self.http_version.is_empty() {
                "HTTP/1.1"
            } else {
                &self.http_version
            },
            self.status_code
        );
        for (k, v) in &self.headers {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(&self.body);
        out
    }
}

impl ResponseData {
    /// The response minus headers that change on every identical answer
    /// (Date, Set-Cookie, ...): `differs from` on live traffic compares
    /// this, or no two responses ever compare equal.
    pub fn comparable(&self) -> String {
        const VOLATILE: &[&str] = &[
            "date",
            "set-cookie",
            "expires",
            "last-modified",
            "etag",
            "age",
            "cf-ray",
            "x-request-id",
            "x-amzn-trace-id",
            "x-amz-cf-id",
            "x-amz-cf-pop",
            "server-timing",
            "report-to",
            "nel",
        ];
        let mut out = format!(
            "{} {}\r\n",
            if self.http_version.is_empty() {
                "HTTP/1.1"
            } else {
                &self.http_version
            },
            self.status_code
        );
        for (k, v) in &self.headers {
            if VOLATILE.contains(&k.to_ascii_lowercase().as_str()) {
                continue;
            }
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(&self.body);
        out
    }
}

/// Split a URL into (path, query); path defaults to `/`.
fn url_path_query(url: &str) -> (String, String) {
    let after_authority = match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            match rest.find('/') {
                Some(j) => &rest[j..],
                None => "/",
            }
        }
        None => url,
    };
    match after_authority.find('?') {
        Some(i) => (
            after_authority[..i].to_string(),
            after_authority[i + 1..].to_string(),
        ),
        None => (after_authority.to_string(), String::new()),
    }
}

fn url_protocol(url: &str) -> String {
    url.split_once("://")
        .map(|(p, _)| p.to_string())
        .unwrap_or_default()
}

fn url_host_port(url: &str) -> (String, String) {
    let authority = match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            match rest.find('/') {
                Some(j) => &rest[..j],
                None => rest,
            }
        }
        None => url.split('/').next().unwrap_or(""),
    };
    // strip any userinfo
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.to_string())
        }
        _ => {
            let default_port = match url_protocol(url).as_str() {
                "https" => "443",
                "http" => "80",
                _ => "",
            };
            (authority.to_string(), default_port.to_string())
        }
    }
}

/// Collaborator handles the interpreter needs: address generation and the
/// set of interaction kinds observed so far.
pub trait Collaborator {
    fn generate_address(&mut self) -> Result<String, String>;
    /// True when an interaction of the kind has arrived. Implementations
    /// may consume observations (a later condition does not re-see them),
    /// which Burp's Log4Shell worked example relies on.
    fn has_interaction(&mut self, kind: InteractionKind) -> bool;
}

/// Evaluation context for one check run: variables, named exchanges and
/// optional collaborator / insertion-point state.
pub struct Context {
    pub vars: HashMap<String, String>,
    pub exchanges: HashMap<String, Exchange>,
    pub collaborator: Option<Box<dyn Collaborator>>,
    pub insertion_point_base_value: Option<String>,
    /// User-Agent value returned by the `user_agent` reserved variable.
    pub user_agent: String,
    /// Requests sent so far in this definition run; a runaway definition
    /// is cut off at [`MAX_REQUESTS_PER_RUN`] rather than scanning forever.
    pub requests_sent: usize,
}

/// Defensive ceiling on requests one definition run may send (Burp's own
/// checks send a handful; the run-for-each cap is separate).
pub const MAX_REQUESTS_PER_RUN: usize = 250;

impl Context {
    pub fn new(base: Exchange) -> Self {
        let mut exchanges = HashMap::new();
        exchanges.insert("base".to_string(), base.clone());
        exchanges.insert("latest".to_string(), base);
        Context {
            vars: HashMap::new(),
            exchanges,
            collaborator: None,
            insertion_point_base_value: None,
            user_agent: "Mozilla/5.0 (compatible; WebProbe)".to_string(),
            requests_sent: 0,
        }
    }

    /// Record a sent exchange under its `called` name and as `latest`.
    pub fn record(&mut self, name: Option<&str>, exchange: Exchange) {
        if let Some(n) = name {
            self.exchanges.insert(n.to_string(), exchange.clone());
        }
        self.exchanges.insert("latest".to_string(), exchange);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecError(pub String);

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ExecError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ExecError> {
    Err(ExecError(msg.into()))
}

/// Resolve a parsed value to a string.
pub fn resolve_value(cx: &mut Context, v: &Value) -> Result<String, ExecError> {
    match v {
        Value::Hole(e) => eval_expr(cx, e),
        Value::Str(s) => resolve_interpol(cx, s),
        Value::Ident(s) => Ok(s.clone()),
        Value::Null => Ok(String::new()),
    }
}

/// Resolve an interpolated string: literal parts verbatim, holes evaluated.
/// Non-interpolatable (double-quoted) strings hold no holes by construction.
pub fn resolve_interpol(cx: &mut Context, s: &Interpol) -> Result<String, ExecError> {
    let mut out = String::new();
    for part in &s.parts {
        match part {
            Part::Text(t) => out.push_str(t),
            Part::Hole(e) => out.push_str(&eval_expr(cx, e)?),
        }
    }
    Ok(out)
}

pub fn eval_expr(cx: &mut Context, e: &Expr) -> Result<String, ExecError> {
    match e {
        Expr::Int(n) => Ok(n.to_string()),
        Expr::Null => Ok(String::new()),
        Expr::Str(s) => resolve_interpol(cx, s),
        Expr::Var(name) => match name.as_str() {
            "user_agent" => Ok(cx.user_agent.clone()),
            "insertion_point_base_value" => {
                cx.insertion_point_base_value.clone().ok_or_else(|| {
                    ExecError("insertion_point_base_value outside an insertion-point check".into())
                })
            }
            other => {
                if let Some(v) = cx.vars.get(other) {
                    Ok(v.clone())
                } else if let Some(ex) = cx.exchanges.get(other) {
                    // a bare request name stringifies to its raw response
                    Ok(ex.response.raw())
                } else {
                    err(format!("undefined variable `{other}`"))
                }
            }
        },
        Expr::Path(segs) => eval_path(cx, segs),
        Expr::Call { name, args } => eval_call(cx, name, args),
    }
}

fn eval_path(cx: &mut Context, segs: &[String]) -> Result<String, ExecError> {
    if segs.is_empty() {
        return err("empty path");
    }
    // reserved single-word variables may arrive as paths of length 1
    if segs.len() == 1 {
        return match segs[0].as_str() {
            "user_agent" => Ok(cx.user_agent.clone()),
            "insertion_point_base_value" => {
                cx.insertion_point_base_value.clone().ok_or_else(|| {
                    ExecError("insertion_point_base_value outside an insertion-point check".into())
                })
            }
            name => {
                // a named exchange stringifies to its raw response
                if let Some(ex) = cx.exchanges.get(name) {
                    Ok(ex.response.raw())
                } else if let Some(v) = cx.vars.get(name) {
                    Ok(v.clone())
                } else {
                    err(format!("unknown reference `{name}`"))
                }
            }
        };
    }
    let name = segs[0].as_str();
    let ex = cx
        .exchanges
        .get(name)
        .ok_or_else(|| ExecError(format!("unknown request `{name}`")))?;
    match segs[1].as_str() {
        "response" => response_property(ex, &segs[2..]),
        "request" => request_property(ex, &segs[2..]),
        other => err(format!(
            "expected `request` or `response` after `{name}`, got `{other}`"
        )),
    }
}

/// A `differs from` operand: a bare `{x.response}` compares without its
/// volatile headers; everything else evaluates as usual.
fn eval_diff_operand(cx: &mut Context, e: &Expr) -> Result<String, ExecError> {
    if let Expr::Path(segs) = e
        && segs.len() == 2 && segs[1] == "response" {
            let ex = cx
                .exchanges
                .get(&segs[0])
                .ok_or_else(|| ExecError(format!("unknown request `{}`", segs[0])))?;
            return Ok(ex.response.comparable());
        }
    eval_expr(cx, e)
}

fn response_property(ex: &Exchange, rest: &[String]) -> Result<String, ExecError> {
    let r = &ex.response;
    match rest {
        [] => Ok(r.raw()),
        [p] => match p.as_str() {
            "status_code" => Ok(r.status_code.to_string()),
            "headers" => Ok(r
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\r\n")),
            "body" => Ok(r.body.clone()),
            "http_version" => Ok(r.http_version.clone()),
            // Burp's examples use both {base.response.url} and
            // {base.response.url.path}; a response's url is its request's.
            "url" => Ok(ex.request.url.clone()),
            other => err(format!("unknown response property `{other}`")),
        },
        [p, sub] if p == "url" => request_property(ex, &["url".to_string(), sub.clone()]),
        [p, more @ ..] => err(format!("unknown response path `{p}.{}`", more.join("."))),
    }
}

fn request_property(ex: &Exchange, rest: &[String]) -> Result<String, ExecError> {
    let q = &ex.request;
    match rest {
        [] => Ok(q.raw()),
        [p] => match p.as_str() {
            "method" => Ok(q.method.clone()),
            "url" => Ok(q.url.clone()),
            "http_version" => Ok(q.http_version.clone()),
            "headers" => Ok(q
                .headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\r\n")),
            "body" => Ok(q.body.clone()),
            other => err(format!("unknown request property `{other}`")),
        },
        [p, sub] if p == "url" => {
            let (host, port) = url_host_port(&q.url);
            let (path, query) = url_path_query(&q.url);
            match sub.as_str() {
                "protocol" => Ok(url_protocol(&q.url)),
                "host" => Ok(host),
                "port" => Ok(port),
                "path" => Ok(path),
                "file" => Ok(if query.is_empty() {
                    path
                } else {
                    format!("{path}?{query}")
                }),
                "query" => Ok(query),
                other => err(format!("unknown url property `{other}`")),
            }
        }
        [p, more @ ..] => err(format!("unknown request path `{p}.{}`", more.join("."))),
    }
}

fn eval_call(cx: &mut Context, name: &str, args: &[Expr]) -> Result<String, ExecError> {
    let argc = |want: usize| -> Result<(), ExecError> {
        if args.len() == want {
            Ok(())
        } else {
            err(format!(
                "{name} takes {want} argument(s), got {}",
                args.len()
            ))
        }
    };
    match name {
        "random_str" => {
            argc(1)?;
            let n = match eval_expr(cx, &args[0])?.parse::<usize>() {
                Ok(n) if n <= 9_999_999 => n,
                _ => return err("random_str length must be 0..=9999999"),
            };
            const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
            let mut rng = rand::thread_rng();
            Ok((0..n)
                .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
                .collect())
        }
        "regex_replace" => {
            argc(3)?;
            let source = eval_expr(cx, &args[0])?;
            let pattern = eval_expr(cx, &args[1])?;
            let replacement = eval_expr(cx, &args[2])?;
            let re = regex::Regex::new(&pattern)
                .map_err(|e| ExecError(format!("bad regex in regex_replace: {e}")))?;
            Ok(re.replace_all(&source, replacement.as_str()).into_owned())
        }
        "to_lower" => {
            argc(1)?;
            Ok(eval_expr(cx, &args[0])?.to_lowercase())
        }
        "to_upper" => {
            argc(1)?;
            Ok(eval_expr(cx, &args[0])?.to_uppercase())
        }
        "base64_encode" => {
            argc(1)?;
            Ok(base64::engine::general_purpose::STANDARD.encode(eval_expr(cx, &args[0])?))
        }
        "base64_decode" => {
            argc(1)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(eval_expr(cx, &args[0])?)
                .map_err(|e| ExecError(format!("bad base64 in base64_decode: {e}")))?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
        "generate_collaborator_address" => {
            argc(0)?;
            match cx.collaborator.as_deref_mut() {
                Some(c) => c.generate_address().map_err(ExecError),
                None => err("generate_collaborator_address needs a Collaborator"),
            }
        }
        "sha1" => {
            argc(1)?;
            crate::decoder_ops::apply(crate::decoder_ops::Op::Sha1, &eval_expr(cx, &args[0])?)
                .map_err(ExecError)
        }
        "sha256" => {
            argc(1)?;
            let mut h = sha2::Sha256::new();
            h.update(eval_expr(cx, &args[0])?.as_bytes());
            Ok(format!("{:x}", h.finalize()))
        }
        "md5" => {
            argc(1)?;
            crate::decoder_ops::apply(crate::decoder_ops::Op::Md5, &eval_expr(cx, &args[0])?)
                .map_err(ExecError)
        }
        other => err(format!("unknown function `{other}`")),
    }
}

/// Apply one request modification to an in-progress request.
pub fn apply_mod(cx: &mut Context, req: &mut RequestData, m: &RequestMod) -> Result<(), ExecError> {
    match m {
        RequestMod::Headers { mode, pairs } => {
            for (k, v) in pairs {
                let key = resolve_value(cx, k)?;
                let val = resolve_value(cx, v)?;
                match mode {
                    ModMode::Append => req.headers.push((key, val)),
                    ModMode::Replace => {
                        if let Some(h) = req
                            .headers
                            .iter_mut()
                            .find(|(k2, _)| k2.eq_ignore_ascii_case(&key))
                        {
                            h.1 = val;
                        } else {
                            req.headers.push((key, val));
                        }
                    }
                    ModMode::Remove => unreachable!(),
                }
            }
        }
        RequestMod::RemoveHeaders(names) => {
            for n in names {
                let name = resolve_value(cx, n)?;
                req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
            }
        }
        RequestMod::Queries { mode, entries } => {
            let (path, query) = url_path_query(&req.url);
            let mut pairs: Vec<(String, String)> = if query.is_empty() {
                Vec::new()
            } else {
                query
                    .split('&')
                    .map(|p| match p.split_once('=') {
                        Some((k, v)) => (k.to_string(), v.to_string()),
                        None => (p.to_string(), String::new()),
                    })
                    .collect()
            };
            for e in entries {
                let entry = resolve_value(cx, e)?;
                let (k, v) = match entry.split_once('=') {
                    Some((k, v)) => (k.to_string(), v.to_string()),
                    None => (entry, String::new()),
                };
                match mode {
                    ModMode::Append => pairs.push((k, v)),
                    ModMode::Replace => {
                        if let Some(p) = pairs.iter_mut().find(|(k2, _)| *k2 == k) {
                            p.1 = v;
                        } else {
                            pairs.push((k, v));
                        }
                    }
                    ModMode::Remove => unreachable!(),
                }
            }
            let new_query = pairs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            req.url = replace_path_query(&req.url, &path, &new_query);
        }
        RequestMod::RemoveQueries(names) => {
            let (path, query) = url_path_query(&req.url);
            let mut names_resolved = Vec::new();
            for n in names {
                names_resolved.push(resolve_value(cx, n)?);
            }
            let kept: Vec<&str> = query
                .split('&')
                .filter(|p| {
                    let k = p.split('=').next().unwrap_or("");
                    !names_resolved.iter().any(|n| n == k)
                })
                .filter(|p| !p.is_empty())
                .collect();
            req.url = replace_path_query(&req.url, &path, &kept.join("&"));
        }
        RequestMod::QueryString { mode, value } => {
            let (path, query) = url_path_query(&req.url);
            let v = resolve_value(cx, value)?;
            let new_query = match mode {
                ModMode::Append => {
                    if query.is_empty() {
                        v
                    } else {
                        format!("{query}&{v}")
                    }
                }
                ModMode::Replace => v,
                ModMode::Remove => unreachable!(),
            };
            req.url = replace_path_query(&req.url, &path, &new_query);
        }
        RequestMod::RemoveQueryString => {
            let (path, _) = url_path_query(&req.url);
            req.url = replace_path_query(&req.url, &path, "");
        }
        RequestMod::Path { mode, value } => {
            let (path, query) = url_path_query(&req.url);
            let v = resolve_value(cx, value)?;
            let new_path = match mode {
                ModMode::Append => format!("{path}{v}"),
                ModMode::Replace => v,
                ModMode::Remove => unreachable!(),
            };
            req.url = replace_path_query(&req.url, &new_path, &query);
        }
        RequestMod::RemovePath => {
            let (_, query) = url_path_query(&req.url);
            req.url = replace_path_query(&req.url, "/", &query);
        }
        RequestMod::Method { mode, value } => {
            let v = resolve_value(cx, value)?;
            match mode {
                ModMode::Replace | ModMode::Append => req.method = v,
                ModMode::Remove => unreachable!(),
            }
        }
        RequestMod::RemoveMethod => req.method.clear(),
        RequestMod::Body { mode, value } => {
            let v = resolve_value(cx, value)?;
            match mode {
                ModMode::Replace => req.body = v,
                ModMode::Append => req.body.push_str(&v),
                ModMode::Remove => unreachable!(),
            }
        }
        RequestMod::RemoveBody => req.body.clear(),
    }
    Ok(())
}

/// Rebuild a URL with a new path and query, preserving scheme/authority.
fn replace_path_query(url: &str, path: &str, query: &str) -> String {
    let prefix = match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            match rest.find('/') {
                Some(j) => &url[..i + 3 + j],
                None => url,
            }
        }
        None => "",
    };
    let mut out = format!("{prefix}{path}");
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    out
}

/// Evaluate a condition against the context.
pub fn eval_condition(cx: &mut Context, c: &Condition) -> Result<bool, ExecError> {
    match c {
        Condition::Matches(e, re_interpol) => {
            let value = eval_expr(cx, e)?;
            let pattern = resolve_interpol(cx, re_interpol)?;
            let re = regex::Regex::new(&pattern)
                .map_err(|e2| ExecError(format!("bad matches regex: {e2}")))?;
            Ok(re.is_match(&value))
        }
        // Burp's `differs from` is a weighted response diff; exact inequality
        // of the serialized responses is the conservative equivalent and is
        // what the documented examples rely on (garbage vs check).
        Condition::Differs(a, b) => Ok(eval_diff_operand(cx, a)? != eval_diff_operand(cx, b)?),
        Condition::In(needle, haystack) => {
            Ok(eval_expr(cx, haystack)?.contains(&eval_expr(cx, needle)?))
        }
        Condition::Is(a, b) => Ok(eval_expr(cx, a)? == eval_expr(cx, b)?),
        Condition::Interactions(kind) => match cx.collaborator.as_deref_mut() {
            Some(c) => Ok(c.has_interaction(*kind)),
            None => Ok(false),
        },
        Condition::And(a, b) => Ok(eval_condition(cx, a)? && eval_condition(cx, b)?),
        Condition::Or(a, b) => Ok(eval_condition(cx, a)? || eval_condition(cx, b)?),
        Condition::Not(inner) => Ok(!eval_condition(cx, inner)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bcheck::{parse, GivenMode, Stmt};

    struct FakeCollaborator {
        next: u32,
        kinds: std::collections::HashSet<InteractionKind>,
    }
    impl Collaborator for FakeCollaborator {
        fn generate_address(&mut self) -> Result<String, String> {
            self.next += 1;
            Ok(format!("{}.oast.test", self.next))
        }
        fn has_interaction(&mut self, kind: InteractionKind) -> bool {
            match kind {
                InteractionKind::Any => !self.kinds.is_empty(),
                other => self.kinds.contains(&other),
            }
        }
    }

    fn base_exchange() -> Exchange {
        Exchange {
            request: RequestData {
                method: "GET".into(),
                url: "https://example.com:8443/catalog/product?productId=1".into(),
                http_version: "HTTP/2".into(),
                headers: vec![
                    ("Host".into(), "example.com:8443".into()),
                    ("Cookie".into(), "session=abc".into()),
                ],
                body: String::new(),
            },
            response: ResponseData {
                status_code: 200,
                http_version: "HTTP/2".into(),
                headers: vec![("Content-Type".into(), "text/html".into())],
                body: "<html>hello</html>".into(),
            },
        }
    }

    #[test]
    fn differs_ignores_volatile_headers() {
        let mut a = super::ResponseData {
            status_code: 200,
            http_version: "HTTP/1.1".into(),
            headers: vec![
                ("Date".into(), "Tue".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: "same".into(),
        };
        let mut b = super::ResponseData {
            status_code: 200,
            http_version: "HTTP/1.1".into(),
            headers: vec![
                ("Date".into(), "Wed".into()),
                ("Set-Cookie".into(), "s=1".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body: "same".into(),
        };
        assert_eq!(a.comparable(), b.comparable());
        b.body = "different".into();
        assert_ne!(a.comparable(), b.comparable());
        a.headers.clear();
        b.headers.clear();
        // ...and through the condition itself
        let mut cx = cx();
        let base_req = cx.exchanges["base"].request.clone();
        let ex = |r: super::ResponseData| super::Exchange {
            request: base_req.clone(),
            response: r,
        };
        cx.exchanges.insert(
            "a".into(),
            ex(super::ResponseData {
                status_code: 200,
                http_version: "HTTP/1.1".into(),
                headers: vec![("Date".into(), "Tue".into())],
                body: "same".into(),
            }),
        );
        cx.exchanges.insert(
            "b".into(),
            ex(super::ResponseData {
                status_code: 200,
                http_version: "HTTP/1.1".into(),
                headers: vec![("Date".into(), "Wed".into())],
                body: "same".into(),
            }),
        );
        let path = |n: &str| Expr::Path(vec![n.to_string(), "response".to_string()]);
        assert!(!eval_condition(&mut cx, &Condition::Differs(path("a"), path("b"))).unwrap());
        cx.exchanges.get_mut("b").unwrap().response.body = "changed".into();
        assert!(eval_condition(&mut cx, &Condition::Differs(path("a"), path("b"))).unwrap());
    }

    #[test]
    fn raw_request_recomputes_content_length() {
        let r = super::RequestData {
            method: "POST".into(),
            url: "http://h/x".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![("Content-Length".into(), "3".into())],
            body: "longer-body".into(),
        };
        assert!(r.raw().contains("Content-Length: 11"), "{}", r.raw());
        let r = super::RequestData {
            method: "POST".into(),
            url: "http://h/x".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![],
            body: "abc".into(),
        };
        assert!(r.raw().contains("Content-Length: 3"), "{}", r.raw());
    }

    fn cx() -> Context {
        Context::new(base_exchange())
    }

    fn parse_body_stmt(src: &str, idx: usize) -> Stmt {
        let d = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("parse failed: {e:?}"),
        };
        d.body.into_iter().nth(idx).expect("stmt index")
    }

    #[test]
    fn reserved_paths_resolve() {
        let mut cx = cx();
        let path = |s: &str| Expr::Path(s.split('.').map(|x| x.to_string()).collect());
        assert_eq!(
            eval_expr(&mut cx, &path("base.response.status_code")).unwrap(),
            "200"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.response.body")).unwrap(),
            "<html>hello</html>"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.request.method")).unwrap(),
            "GET"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.request.url.protocol")).unwrap(),
            "https"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.request.url.host")).unwrap(),
            "example.com"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.request.url.port")).unwrap(),
            "8443"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.request.url.path")).unwrap(),
            "/catalog/product"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.request.url.file")).unwrap(),
            "/catalog/product?productId=1"
        );
        assert_eq!(
            eval_expr(&mut cx, &path("base.request.url.query")).unwrap(),
            "productId=1"
        );
        assert!(eval_expr(&mut cx, &path("base.request.url"))
            .unwrap()
            .starts_with("https://"));
        // whole request / response serialize
        assert!(eval_expr(&mut cx, &path("base.request"))
            .unwrap()
            .contains("GET /catalog/product?productId=1 HTTP/2"));
        assert!(eval_expr(&mut cx, &path("base.response"))
            .unwrap()
            .contains("200"));
        assert!(eval_expr(&mut cx, &path("latest.response.body"))
            .unwrap()
            .contains("hello"));
        assert!(eval_expr(&mut cx, &Expr::Var("user_agent".into()))
            .unwrap()
            .contains("WebProbe"));
    }

    #[test]
    fn functions_match_the_reference_examples() {
        let mut cx = cx();
        let call = |name: &str, args: Vec<Expr>| Expr::Call {
            name: name.into(),
            args,
        };
        let s = |v: &str| {
            Expr::Str(Interpol {
                parts: vec![Part::Text(v.into())],
                interpolatable: true,
            })
        };
        assert_eq!(
            eval_expr(&mut cx, &call("to_lower", vec![s("Carlos MONTOYA")])).unwrap(),
            "carlos montoya"
        );
        assert_eq!(
            eval_expr(&mut cx, &call("to_upper", vec![s("Peter weiner")])).unwrap(),
            "PETER WEINER"
        );
        assert_eq!(
            eval_expr(&mut cx, &call("base64_encode", vec![s("hello world")])).unwrap(),
            "aGVsbG8gd29ybGQ="
        );
        assert_eq!(
            eval_expr(&mut cx, &call("base64_decode", vec![s("aGVsbG8gd29ybGQ=")])).unwrap(),
            "hello world"
        );
        assert_eq!(
            eval_expr(&mut cx, &call("sha1", vec![s("Hello")])).unwrap(),
            "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0"
        );
        assert_eq!(
            eval_expr(&mut cx, &call("sha256", vec![s("Hello")])).unwrap(),
            "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
        );
        assert_eq!(
            eval_expr(&mut cx, &call("md5", vec![s("Hello")])).unwrap(),
            "8b1a9953c4611296a827abf8c47804d7"
        );
        // regex_replace from the reference: xyz@portswigger.net -> abc@portswigger.net
        assert_eq!(
            eval_expr(
                &mut cx,
                &call(
                    "regex_replace",
                    vec![s("xyz@portswigger.net"), s("[a-z]*@"), s("abc@")]
                )
            )
            .unwrap(),
            "abc@portswigger.net"
        );
        // $1 backreference, from the path-check example
        assert_eq!(
            eval_expr(
                &mut cx,
                &call(
                    "regex_replace",
                    vec![s("/catalog/product"), s("(.)/?$"), s("$1.bak")]
                )
            )
            .unwrap(),
            "/catalog/product.bak"
        );
        // random_str length and charset
        let r = eval_expr(&mut cx, &call("random_str", vec![Expr::Int(13)])).unwrap();
        assert_eq!(r.len(), 13);
        assert!(r
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(
            eval_expr(&mut cx, &call("random_str", vec![Expr::Int(0)])).unwrap(),
            ""
        );
        // nesting: base64_encode(to_lower("ABC"))
        assert_eq!(
            eval_expr(
                &mut cx,
                &call("base64_encode", vec![call("to_lower", vec![s("ABC")])])
            )
            .unwrap(),
            "YWJj"
        );
    }

    #[test]
    fn collaborator_function_uses_the_context() {
        let collab = FakeCollaborator {
            next: 0,
            kinds: std::collections::HashSet::new(),
        };
        let mut cx = cx();
        cx.collaborator = Some(Box::new(collab));
        let addr = eval_expr(
            &mut cx,
            &Expr::Call {
                name: "generate_collaborator_address".into(),
                args: vec![],
            },
        )
        .unwrap();
        assert_eq!(addr, "1.oast.test");
        let addr2 = eval_expr(
            &mut cx,
            &Expr::Call {
                name: "generate_collaborator_address".into(),
                args: vec![],
            },
        )
        .unwrap();
        assert_eq!(addr2, "2.oast.test");
    }

    #[test]
    fn variables_and_interpolation_resolve() {
        let mut cx = cx();
        cx.vars.insert("extension".into(), ".bak".into());
        cx.vars.insert("answer".into(), "1787569".into());
        assert_eq!(
            eval_expr(&mut cx, &Expr::Var("extension".into())).unwrap(),
            ".bak"
        );
        // interpolated backtick string `$1{extension}`
        let s = Interpol {
            parts: vec![
                Part::Text("$1".into()),
                Part::Hole(Expr::Var("extension".into())),
            ],
            interpolatable: true,
        };
        assert_eq!(resolve_interpol(&mut cx, &s).unwrap(), "$1.bak");
        assert!(eval_expr(&mut cx, &Expr::Var("missing".into())).is_err());
    }

    #[test]
    fn host_example_mods_build_the_git_probe_request() {
        let src = include_str!("../../tests/fixtures/bchecks/host.bcheck");
        let d = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let mut cx = cx();
        // run-for-each value in scope
        cx.vars
            .insert("potential_path".into(), "/.git/config".into());
        let Stmt::SendRequest { mods, .. } = &d.body[0] else {
            panic!()
        };
        let mut req = base_exchange().request;
        for m in mods {
            apply_mod(&mut cx, &mut req, m).unwrap();
        }
        assert_eq!(req.method, "GET");
        let (path, query) = url_path_query(&req.url);
        assert_eq!(path, "/.git/config");
        // Burp preserves the query string when replacing the path
        assert_eq!(query, "productId=1");
    }

    #[test]
    fn collaborator_example_adds_the_referer_header() {
        let src = include_str!("../../tests/fixtures/bchecks/collaborator.bcheck");
        let d = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let collab = FakeCollaborator {
            next: 0,
            kinds: std::collections::HashSet::new(),
        };
        let mut cx = cx();
        cx.collaborator = Some(Box::new(collab));
        let Stmt::SendRequest { mods, .. } = &d.body[0] else {
            panic!()
        };
        let mut req = base_exchange().request;
        for m in mods {
            apply_mod(&mut cx, &mut req, m).unwrap();
        }
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Referer" && v == "1.oast.test"));
    }

    #[test]
    fn log4shell_example_mods_apply() {
        let src = include_str!("../../tests/fixtures/bchecks/log4shell.bcheck");
        let d = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let collab = FakeCollaborator {
            next: 0,
            kinds: std::collections::HashSet::new(),
        };
        let mut cx = cx();
        cx.collaborator = Some(Box::new(collab));
        // define block values resolve first
        for decl in &d.define {
            let v = resolve_value(&mut cx, &decl.values[0]).unwrap();
            cx.vars.insert(decl.name.clone(), v);
        }
        assert!(cx.vars["log4shell"].contains("${jndi:ldap://1.oast.test/a}"));
        let Stmt::SendRequest { mods, .. } = &d.body[0] else {
            panic!()
        };
        let mut req = base_exchange().request;
        for m in mods {
            apply_mod(&mut cx, &mut req, m).unwrap();
        }
        assert_eq!(req.method, "GET");
        let (_, query) = url_path_query(&req.url);
        assert!(query.contains("x=${jndi:ldap://"), "query: {query}");
        // replacing headers: Cookie/Location/Origin/Referer added or replaced
        let cookie = req.headers.iter().find(|(k, _)| k == "Cookie").unwrap();
        assert!(cookie.1.contains("${jndi:ldap://"));
        assert!(req.headers.iter().any(|(k, _)| k == "Referer"));
    }

    #[test]
    fn conditions_evaluate() {
        let mut cx = cx();
        let interp = |s: &str| Interpol {
            parts: vec![Part::Text(s.into())],
            interpolatable: false,
        };
        let path = |s: &str| Expr::Path(s.split('.').map(|x| x.to_string()).collect());
        // matches
        assert!(eval_condition(
            &mut cx,
            &Condition::Matches(path("base.response.body"), interp("h.llo"))
        )
        .unwrap());
        assert!(!eval_condition(
            &mut cx,
            &Condition::Matches(path("base.response.body"), interp("^h.llo$"))
        )
        .unwrap());
        // in
        assert!(eval_condition(
            &mut cx,
            &Condition::In(
                Expr::Str(interp("[core]")),
                Expr::Str(interp("a [core] section"))
            )
        )
        .unwrap());
        // is
        assert!(eval_condition(
            &mut cx,
            &Condition::Is(path("base.response.status_code"), Expr::Str(interp("200")))
        )
        .unwrap());
        // differs
        assert!(eval_condition(
            &mut cx,
            &Condition::Differs(Expr::Str(interp("a")), Expr::Str(interp("b")))
        )
        .unwrap());
        // combinators + not
        let c = Condition::Or(
            Box::new(Condition::Is(
                Expr::Str(interp("x")),
                Expr::Str(interp("y")),
            )),
            Box::new(Condition::And(
                Box::new(Condition::Is(
                    Expr::Str(interp("a")),
                    Expr::Str(interp("a")),
                )),
                Box::new(Condition::Not(Box::new(Condition::Is(
                    Expr::Str(interp("b")),
                    Expr::Str(interp("c")),
                )))),
            )),
        );
        assert!(eval_condition(&mut cx, &c).unwrap());
    }

    #[test]
    fn interactions_conditions_read_the_collaborator() {
        let collab = FakeCollaborator {
            next: 0,
            kinds: [InteractionKind::Dns].into_iter().collect(),
        };
        let mut cx = cx();
        cx.collaborator = Some(Box::new(collab));
        assert!(eval_condition(&mut cx, &Condition::Interactions(InteractionKind::Dns)).unwrap());
        assert!(eval_condition(&mut cx, &Condition::Interactions(InteractionKind::Any)).unwrap());
        assert!(!eval_condition(&mut cx, &Condition::Interactions(InteractionKind::Http)).unwrap());
    }

    #[test]
    fn any_interaction_is_not_implied_by_nothing() {
        // Any must only be true when something arrived
        let collab = FakeCollaborator {
            next: 0,
            kinds: [InteractionKind::Dns].into_iter().collect(),
        };
        let mut cx = cx();
        cx.collaborator = Some(Box::new(collab));
        assert!(eval_condition(&mut cx, &Condition::Interactions(InteractionKind::Any)).unwrap());
    }

    #[test]
    fn path_example_first_condition_uses_base_status() {
        let src = include_str!("../../tests/fixtures/bchecks/path.bcheck");
        let stmt = parse_body_stmt(src, 0);
        let mut cx = cx();
        let Stmt::If { arms } = &stmt else { panic!() };
        // base status 200 != 404 -> not(...) is true
        assert!(eval_condition(&mut cx, arms[0].0.as_ref().unwrap()).unwrap());
        let mut cx404 = Context::new(Exchange {
            response: ResponseData {
                status_code: 404,
                ..base_exchange().response
            },
            ..base_exchange()
        });
        assert!(!eval_condition(&mut cx404, arms[0].0.as_ref().unwrap()).unwrap());
    }

    #[test]
    fn insertion_point_example_flow() {
        let src = include_str!("../../tests/fixtures/bchecks/insertion-point.bcheck");
        let d = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        assert_eq!(
            d.given,
            GivenMode::InsertionPoints(vec![super::super::InsertionPointKind::Any])
        );
        let mut cx = cx();
        for decl in &d.define {
            let v = resolve_value(&mut cx, &decl.values[0]).unwrap();
            cx.vars.insert(decl.name.clone(), v);
        }
        assert_eq!(cx.vars["calculation"], "{{1337*1337}}");
        assert_eq!(cx.vars["answer"], "1787569");
        // first if: answer not in base response -> true here
        let Stmt::If { arms } = &d.body[0] else {
            panic!()
        };
        assert!(eval_condition(&mut cx, arms[0].0.as_ref().unwrap()).unwrap());
        // send payload appends the calculation to the base value
        let Stmt::SendPayload { ops, .. } = &arms[0].1[0] else {
            panic!()
        };
        cx.insertion_point_base_value = Some("1".into());
        let (mode, value) = &ops[0];
        assert_eq!(*mode, ModMode::Append);
        let payload = resolve_value(&mut cx, value).unwrap();
        assert_eq!(payload, "{{1337*1337}}");
    }
}

use crate::diagnostics::Field;
// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

pub use webprobe_support::issues::{EVIDENCE_MAX_BYTES, ScanEvidence, ScanIssue};

/// Burp's numeric issue type for `name` (resources/KnowledgeBase/Issues
/// `typeIndex`, the names in kb_issue_names.txt), or 0 when Burp has no such
/// issue (WebProbe's own checks).
pub fn issue_type_id(name: &str) -> u64 {
    webprobe_support::issues::issue_type_id(name)
}

pub fn mk(sev: &str, name: &str, e: &HistEntry, detail: impl Into<String>) -> ScanIssue {
    ScanIssue {
        id: 0, // assigned by add_issues
        sev: sev.to_string(),
        name: name.into(),
        host: e.host.clone(),
        // Burp keys issues by URL path without the query string.
        path: e.path.split('?').next().unwrap_or("").to_string(),
        detail: detail.into(),
        false_positive: false,
        confidence: "Firm".into(),
        ts: util::now_secs(),
        type_id: issue_type_id(name),
        evidence: Vec::new(),
        ident: String::new(),
    }
}

/// An issue for a check ported from Burp: `kb_name` is the exact issue name
/// in Burp's KnowledgeBase (resources/KnowledgeBase/Issues/*.json), so the
/// Issues table matches Burp's; severity and confidence are what the live
/// Burp scanner reported for the same finding (parity lab, fnd_54).
pub fn mk_burp(
    kb_name: &str,
    sev: &str,
    confidence: &str,
    e: &HistEntry,
    param: &str,
    detail: impl Into<String>,
) -> ScanIssue {
    let mut i = mk(
        sev,
        kb_name,
        e,
        format!("Parameter {param}: {}", detail.into()),
    );
    i.confidence = confidence.into();
    i
}

/// [`mk_burp`] for an insertion-point check: the detail starts with Burp's
/// wording for the point (burp.Zsg0.ZD), "The value of the q request
/// parameter: ...", "The name of an arbitrarily supplied URL parameter: ...".
pub(crate) fn mk_point(
    kb_name: &str,
    sev: &str,
    confidence: &str,
    e: &HistEntry,
    ip: &InsertionPoint,
    detail: impl Into<String>,
) -> ScanIssue {
    let mut i = mk(
        sev,
        kb_name,
        e,
        format!("The {}: {}", ip.describe(), detail.into()),
    );
    i.confidence = confidence.into();
    i
}

/// Match the interactions `collab` recorded since the last call and add the
/// issues they prove (see `oob::OobState::match_new`). Called every frame by
/// whoever owns the Collaborator, whatever view is open.
pub fn match_new_interactions(
    shared: &Shared,
    collab: &crate::collaborator::CollaboratorState,
) -> usize {
    let issues = shared.oob.match_new(collab);
    let n = issues.len();
    if n > 0 {
        add_issues(shared, issues);
    }
    n
}

/// Match `interactions` against the pending ids and add the issues proved.
pub fn match_oob_interactions(
    shared: &Shared,
    interactions: &[crate::collaborator::Interaction],
) -> usize {
    let issues = shared.oob.match_interactions(interactions);
    let n = issues.len();
    if n > 0 {
        add_issues(shared, issues);
    }
    n
}

pub fn add_issues(shared: &Shared, mut issues: Vec<ScanIssue>) {
    if issues.is_empty() {
        return;
    }
    let mut iss = shared.issues.lock();
    for issue in issues.iter_mut() {
        issue.id = shared.next_issue_id.fetch_add(1, Ordering::SeqCst);
        // Issues renamed after construction (the Collaborator matcher)
        // get their type from the final name. Every issue is kept, as in
        // Burp: the list used to drop the oldest past 500, triaged High
        // findings included.
        if issue.type_id == 0 {
            issue.type_id = issue_type_id(&issue.name);
        }
        iss.push(issue.clone());
    }
    shared.event(
        crate::diagnostics::Level::Info,
        "scan.issues.reported",
        "Scanner reported issues",
        &[Field::Count("issues", issues.len() as u64)],
    );
}

/// Passive issues consolidated like the original (AuditDefaults.json
/// scanner.audit_optimization.consolidate_passive_issues = true, and
/// ConsolidationAction.KEEP_EXISTING for duplicates): the first instance of an
/// issue with the same severity + name + service + base URL is kept.
/// Burp's KnowledgeBase issue names (resources/KnowledgeBase/Issues/*.json).
pub const KB_ISSUE_NAMES: &str = include_str!("../kb_issue_names.txt");

/// True when `name` is an issue type Burp itself can report.
pub fn is_burp_issue(name: &str) -> bool {
    KB_ISSUE_NAMES.lines().any(|l| l == name)
}

// ------------------------------------------------------- manual issues

/// Burp's issue type for issues the user raises by hand
/// (burp.Zcot.MANUALLY_GENERATED, type 0x08008000).
pub const MANUAL_ISSUE_TYPE: &str = "Manually generated issue";

/// The severity choices of the "Create an issue" dialog, in Burp's order
/// (burp.Ze1r.Zd); the dialog selects "Information" (Ze1r.ZX(1)).
pub const MANUAL_SEVERITIES: [&str; 5] = ["High", "Medium", "Low", "Information", "False positive"];
pub const MANUAL_DEFAULT_SEVERITY: &str = "Information";

/// The confidence choices (burp.Zeue.Zf); the dialog selects "Certain"
/// (Zeue.ZZ(3)).
pub const MANUAL_CONFIDENCES: [&str; 3] = ["Certain", "Firm", "Tentative"];
pub const MANUAL_DEFAULT_CONFIDENCE: &str = "Certain";

/// What the user typed into the "Create an issue" dialog (burp.Zr7j, read
/// by Zr7j.ZN into burp.Zpmr).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManualIssueForm {
    pub name: String,
    /// "HTTP service": `https://host`, `http://host:8080`.
    pub service: String,
    pub path: String,
    /// One of [`MANUAL_SEVERITIES`].
    pub severity: String,
    /// One of [`MANUAL_CONFIDENCES`].
    pub confidence: String,
    /// "Issue detail (optional)".
    pub detail: String,
    /// "Remediation (optional)".
    pub remediation: String,
}

impl ManualIssueForm {
    /// The dialog as Burp opens it for a message (burp.Zr7j constructor):
    /// the service and path of the message, an empty name and detail,
    /// Information / Certain.
    pub fn for_message(host: &str, port: u16, https: bool, request: &[u8]) -> Self {
        ManualIssueForm {
            service: service_url(host, port, https),
            path: request_target(request).unwrap_or_default(),
            severity: MANUAL_DEFAULT_SEVERITY.into(),
            confidence: MANUAL_DEFAULT_CONFIDENCE.into(),
            ..Default::default()
        }
    }

    /// The fields that are not valid, in Burp's order and words ("name",
    /// "HTTP service", "path"): burp.Zr7j.ZX. Empty when "Create issue" may
    /// be pressed.
    pub fn invalid_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.name.trim().is_empty() {
            out.push("name");
        }
        if parse_service(&self.service).is_none() {
            out.push("HTTP service");
        }
        if !path_valid(&self.path) {
            out.push("path");
        }
        out
    }

    /// The error line under the dialog (burp.Zsl_.Zc): "Invalid: name,
    /// path", or None when every field is valid.
    pub fn error_text(&self) -> Option<String> {
        let bad = self.invalid_fields();
        (!bad.is_empty()).then(|| format!("Invalid: {}", bad.join(", ")))
    }
}

/// Burp's text for an HTTP service (burp.Zxrb.ZC): the port is left out
/// when it is the scheme's default, an IPv6 address goes in brackets.
pub fn service_url(host: &str, port: u16, https: bool) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match (https, port) {
        (true, 443) => format!("https://{host}"),
        (false, 80) => format!("http://{host}"),
        (true, p) => format!("https://{host}:{p}"),
        (false, p) => format!("http://{host}:{p}"),
    }
}

/// The request target of a request line, as Burp takes the path for the
/// dialog (burp.Zudh.Zc): the second word of the first line, query string
/// included; an absolute `http://` target is cut to its path. None when
/// the line has no target.
pub fn request_target(request: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(request);
    let line = text.lines().next()?;
    // Java's line.split(" +", 3)[1]: the word after the first run of spaces.
    let (_method, rest) = line.split_once(' ')?;
    let rest = rest.trim_start_matches(' ');
    let target = rest.split(' ').next().unwrap_or("").trim();
    if target.is_empty() {
        return None;
    }
    if let Some(rest) = target.strip_prefix("http://") {
        return Some(
            rest.find('/')
                .map(|i| rest[i..].to_string())
                .unwrap_or_default(),
        );
    }
    Some(target.to_string())
}

/// Parse the dialog's "HTTP service" into (host, port, https), or None when
/// Burp would refuse it. burp.Zpw7.ZT: the whole text matches
/// `https?://(.+?)(:\d+)?` (lower-case scheme), the host passes
/// burp.Zgt3.Zo and the port is 1..65535; burp.Zb4t.Ze then takes the
/// scheme's default port when none is given.
pub fn parse_service(text: &str) -> Option<(String, u16, bool)> {
    let (https, rest) = if let Some(r) = text.strip_prefix("https://") {
        (true, r)
    } else {
        (false, text.strip_prefix("http://")?)
    };
    // The lazy host group leaves a trailing ":digits" to the port group.
    let (host, port) = match rest.rfind(':') {
        Some(i)
            if i > 0 && rest[i + 1..].bytes().all(|b| b.is_ascii_digit()) && i + 1 < rest.len() =>
        {
            // Integer.parseInt: too many digits is a NumberFormatException.
            let port: i64 = rest[i + 1..].parse().ok()?;
            (&rest[..i], Some(port))
        }
        _ => (rest, None),
    };
    if host.is_empty() || !host_valid(host) {
        return None;
    }
    let port = match port {
        Some(p) if (1..65536).contains(&p) => p as u16,
        Some(_) => return None,
        None if https => 443,
        None => 80,
    };
    Some((host.to_string(), port, https))
}

/// burp.Zgt3.Zo: a host name of letters, digits, '-', '.' and '_' that does
/// not start with '.' or hold "..", or else an IP address (burp.Zhq_.ZK).
fn host_valid(host: &str) -> bool {
    if host.starts_with('.') || host.contains("..") {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        || host.parse::<std::net::IpAddr>().is_ok()
}

/// burp.Zuub.Zu: the path is not empty and `https://portswigger.net`
/// followed by it parses as a java.net.URI. Ported as java.net.URI's
/// character classes: in the path the unreserved and `;/:@&=+$,`
/// characters, in the query and fragment also `?[]` (and `/`), a '%'
/// only before two hex digits, a single '#', any non-ASCII character that
/// is neither a control nor a space. A path that does not start with '/',
/// '?' or '#' continues the host (`@evil.com`, `:80/a`) and must leave a
/// valid authority.
pub fn path_valid(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    fn unreserved(c: char) -> bool {
        c.is_ascii_alphanumeric() || "_-!.~'()*".contains(c)
    }
    fn other(c: char) -> bool {
        !c.is_ascii() && !c.is_control() && !c.is_whitespace()
    }
    fn escapes_ok(s: &str) -> bool {
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b'%' {
                i += 1;
                continue;
            }
            if !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
        }
        true
    }
    let (before_frag, fragment) = match path.split_once('#') {
        Some((a, f)) => (a, Some(f)),
        None => (path, None),
    };
    let (before_query, query) = match before_frag.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (before_frag, None),
    };
    // What precedes the first '/' still belongs to the authority.
    let (authority_tail, path_part) = match before_query.find('/') {
        Some(i) => (&before_query[..i], &before_query[i..]),
        None => (before_query, ""),
    };
    if !authority_tail.is_empty() {
        let auth = format!("portswigger.net{authority_tail}");
        let (userinfo, hostport) = match auth.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, auth.as_str()),
        };
        if let Some(u) = userinfo
            && !(escapes_ok(u)
                && u.chars()
                    .all(|c| unreserved(c) || "%;:&=+$,".contains(c) || other(c)))
        {
            return false;
        }
        let (host, port) = match hostport.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            || port.is_some_and(|p| !p.bytes().all(|b| b.is_ascii_digit()))
        {
            return false;
        }
    }
    let path_ok = path_part
        .chars()
        .all(|c| unreserved(c) || ";/:@&=+$,%".contains(c) || other(c));
    let uric = |s: &str| {
        s.chars()
            .all(|c| unreserved(c) || ";/?:@&=+$,[]%".contains(c) || other(c))
            && escapes_ok(s)
    };
    path_ok
        && escapes_ok(path_part)
        && query.is_none_or(uric)
        && fragment.is_none_or(|f| !f.contains('#') && uric(f))
}

/// Burp's escaping of user text in the advisory (burp.Zevt.Ze with no tag
/// allowed: '<' and '>' are escaped, '&' is kept).
fn escape_user_text(s: &str) -> String {
    s.replace('<', "&lt;").replace('>', "&gt;")
}

/// The issue the "Create issue" button records (burp.Zp_6.run through
/// burp.Zcxr.ZD): type MANUALLY_GENERATED, the user's name, host and path
/// from the dialog's service and path, the chosen severity and confidence,
/// the detail and remediation (blank = none), and the message the dialog
/// was opened on as its one piece of evidence. None when the service is not
/// valid (the dialog keeps the button disabled then).
///
/// WebProbe's issue has one detail text: the remediation follows the detail
/// under Burp's "Remediation detail" heading (burp.Ziiz.ZN). A "False
/// positive" severity is kept as an information issue marked false positive.
pub fn mk_manual_issue(
    form: &ManualIssueForm,
    request: &[u8],
    response: Option<&[u8]>,
) -> Option<ScanIssue> {
    let (host, _port, _https) = parse_service(&form.service)?;
    let (sev, false_positive) = match form.severity.as_str() {
        "High" => ("high", false),
        "Medium" => ("medium", false),
        "Low" => ("low", false),
        "False positive" => ("info", true),
        _ => ("info", false),
    };
    let confidence = if MANUAL_CONFIDENCES.contains(&form.confidence.as_str()) {
        form.confidence.as_str()
    } else {
        MANUAL_DEFAULT_CONFIDENCE
    };
    let mut detail = String::new();
    if !form.detail.trim().is_empty() {
        detail.push_str(&format!("<p>{}</p>", escape_user_text(&form.detail)));
    }
    if !form.remediation.trim().is_empty() {
        detail.push_str(&format!(
            "<p><b>Remediation detail</b></p><p>{}</p>",
            escape_user_text(&form.remediation)
        ));
    }
    Some(ScanIssue {
        id: 0, // assigned by add_issues
        sev: sev.into(),
        name: form.name.clone(),
        host,
        path: form.path.clone(),
        detail,
        false_positive,
        confidence: confidence.into(),
        ts: util::now_secs(),
        type_id: issue_type_id(MANUAL_ISSUE_TYPE),
        evidence: vec![ScanEvidence::new(request, response)],
        ident: String::new(),
    })
}

/// True for an issue the user raised by hand: what the "Add to an issue"
/// table lists (burp.Zm81.getIssues keeps the issues whose type is
/// MANUALLY_GENERATED).
pub fn is_manual_issue(issue: &ScanIssue) -> bool {
    issue.type_id == issue_type_id(MANUAL_ISSUE_TYPE)
}

/// "Add to issue" (burp.Zchl.run): the message is appended to the issue's
/// evidence (burp.Zs9s.Zf adds to the list, nothing is replaced). Only a
/// manual issue takes evidence this way; returns whether it was added.
pub fn add_manual_evidence(issue: &mut ScanIssue, request: &[u8], response: Option<&[u8]>) -> bool {
    if !is_manual_issue(issue) {
        return false;
    }
    issue.evidence.push(ScanEvidence::new(request, response));
    true
}

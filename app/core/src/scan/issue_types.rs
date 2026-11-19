// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// Largest request or response kept as issue evidence; longer messages are
/// truncated to this many bytes.
pub const EVIDENCE_MAX_BYTES: usize = 256 * 1024;

/// One exchange that confirmed an issue: the probe as sent and the response
/// it got (None when the target did not answer, or not known yet). Shared,
/// so cloning an issue does not copy the bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanEvidence {
    pub request: Arc<[u8]>,
    pub response: Option<Arc<[u8]>>,
}

impl ScanEvidence {
    /// A bounded copy: each message is cut at [`EVIDENCE_MAX_BYTES`].
    pub fn new(request: &[u8], response: Option<&[u8]>) -> Self {
        let cap = |b: &[u8]| -> Arc<[u8]> { Arc::from(&b[..b.len().min(EVIDENCE_MAX_BYTES)]) };
        ScanEvidence {
            request: cap(request),
            response: response.map(cap),
        }
    }
}

#[derive(Clone, Default)]
pub struct ScanIssue {
    pub id: u64,
    pub sev: String, // high | medium | low | info (DarkTheme.json ui.issue colors)
    pub name: String,
    pub host: String,
    pub path: String,
    pub detail: String,
    /// Burp lets the user classify an issue as a false positive
    /// (build 52685 burp.Ze1r line 12 returns "False positive").
    pub false_positive: bool,
    /// Burp vocabulary: Certain | Firm | Tentative.
    pub confidence: String,
    /// When the issue was reported (unix seconds), Burp's "Time" column.
    pub ts: u64,
    /// Burp's numeric issue type (KnowledgeBase `typeIndex`) for an issue
    /// name Burp knows, otherwise 0 (see [`issue_type_id`]).
    pub type_id: u64,
    /// The exchange(s) that confirmed the issue: the probe and its response
    /// for an active check (several when a control or a retrieval request is
    /// part of the proof), the audited exchange for a passive check. Empty
    /// for issues loaded from a project file and for checks that do not
    /// attach evidence yet.
    pub evidence: Vec<ScanEvidence>,
    /// Burp's pervasive issue identifier (Zu4s.PERVASIVE_ISSUE_IDENTIFIER),
    /// with the variant where Burp keys on it: the value an issue is about
    /// (an SSN, a cookie name, a library and version). Part of the merge
    /// key; empty for issues keyed by location only.
    pub ident: String,
}

impl ScanIssue {
    pub(crate) fn with_evidence(mut self, evidence: Vec<ScanEvidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Burp's numeric issue type for `name` (resources/KnowledgeBase/Issues
/// `typeIndex`, the names in kb_issue_names.txt), or 0 when Burp has no such
/// issue (WebProbe's own checks).
pub fn issue_type_id(name: &str) -> u64 {
    checks::KB_ISSUE_TYPES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .unwrap_or(0)
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
    let mut iss = shared.issues.lock().unwrap();
    for issue in issues.iter_mut() {
        issue.id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        // Issues renamed after construction (the Collaborator matcher)
        // get their type from the final name. Every issue is kept, as in
        // Burp: the list used to drop the oldest past 500, triaged High
        // findings included.
        if issue.type_id == 0 {
            issue.type_id = issue_type_id(&issue.name);
        }
        iss.push(issue.clone());
    }
    shared.log(&format!("Scanner reported {} issue(s)", issues.len()));
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

// Moved from core scan/issue_types.rs (L8, issue #38): the shared issue
// vocabulary oob and stored name. Pure data, no core deps, so modules that
// only need the types no longer pull scan (and its cycle) into their graph.

use std::sync::Arc;

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
    /// name Burp knows, otherwise 0 (see `issue_type_id` in core scan).
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
    pub fn with_evidence(mut self, evidence: Vec<ScanEvidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

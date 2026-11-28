//! S-03: a Bambda as a passive scan check.
//!
//! The script sees one exchange (`requestResponse`, `utilities`) and returns
//! an `AuditResult`. Every issue in it is reported as Burp's type
//! "Bambda generated issue" (0x09008000) against that exchange, with the
//! script's own issue name at the top of the detail.
use crate::bambda::{CheckIssue, Error, Kind, MAX_TABLE_ROWS, Program};
use crate::net::HistEntry;
use std::time::Duration;
use webprobe_support::issues::{ScanEvidence, ScanIssue};

/// Burp's name for an issue a Bambda scan check raises.
pub const ISSUE_NAME: &str = "Bambda generated issue";

/// What one run over a set of exchanges produced.
#[derive(Default)]
pub struct Report {
    pub issues: Vec<ScanIssue>,
    /// Exchanges whose script threw or returned something other than an
    /// `AuditResult`.
    pub row_errors: usize,
    /// Exchanges too large for one batch, never shown to the script.
    pub skipped: usize,
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One raised issue as a scanner issue on the exchange it was raised for.
pub fn issue(entry: &HistEntry, found: &CheckIssue) -> ScanIssue {
    let sev = match found.severity.as_str() {
        "HIGH" => "high",
        "MEDIUM" => "medium",
        "LOW" => "low",
        _ => "info",
    };
    let mut detail = format!("<p><b>{}</b></p>", escape(&found.name));
    if !found.detail.is_empty() {
        detail.push_str(&format!("<p>{}</p>", found.detail));
    }
    if !found.remediation.is_empty() {
        detail.push_str(&format!("<p>Remediation: {}</p>", found.remediation));
    }
    let mut out =
        crate::scan::mk(sev, ISSUE_NAME, entry, detail).with_evidence(vec![ScanEvidence::new(
            &entry.req_raw,
            entry.resp_raw.as_deref(),
        )]);
    out.confidence = match found.confidence.as_str() {
        "CERTAIN" => "Certain",
        "TENTATIVE" => "Tentative",
        _ => "Firm",
    }
    .into();
    // Two checks, or two findings of one check, on the same location stay
    // separate issues: the script's name is part of the merge key.
    out.ident = found.name.clone();
    out
}

/// Run a compiled passive check over `entries`. The deadline is per JVM
/// batch. A failed batch fails the run; a failed row is counted.
pub fn run_passive(
    program: &Program,
    entries: &[HistEntry],
    deadline: Duration,
) -> Result<Report, Error> {
    let mut report = Report::default();
    for chunk in entries.chunks(MAX_TABLE_ROWS) {
        let (exchanges, skipped) = crate::bambda_rows::history_rows(chunk);
        report.skipped += skipped.len();
        let outcome = program.apply(Kind::PassiveCheck, &exchanges, deadline)?;
        report.row_errors += outcome.row_errors;
        for (id, found) in &outcome.issues {
            let Some(entry) = chunk.iter().find(|e| e.id == *id) else {
                continue;
            };
            report.issues.extend(found.iter().map(|f| issue(entry, f)));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bambda::{Outcome, RowResult};

    fn row(id: u64, json: &str) -> RowResult {
        serde_json::from_str(&format!("{{\"id\":{id},{json}}}")).unwrap()
    }

    #[test]
    fn audit_results_become_issues_and_bad_shapes_are_row_errors() {
        let rows = vec![
            row(
                1,
                r#""value":{"issues":[{"name":"Debug header","detail":"d","severity":"MEDIUM","confidence":"CERTAIN"}]}"#,
            ),
            row(2, r#""value":null"#),
            row(3, r#""value":{"issues":[]}"#),
            row(4, r#""value":true"#),
            row(5, r#""error":"NullPointerException: x""#),
        ];
        let out = Outcome::interpret(Kind::PassiveCheck, rows, vec![9]);
        assert_eq!(out.issues.len(), 1);
        assert_eq!(out.issues[0].0, 1);
        assert_eq!(out.row_errors, 2);
        assert_eq!(out.skipped, [9]);
        let entry = HistEntry {
            id: 1,
            host: "h.test".into(),
            path: "/p".into(),
            ..Default::default()
        };
        let got = issue(&entry, &out.issues[0].1[0]);
        assert_eq!(got.name, ISSUE_NAME);
        assert_eq!(got.sev, "medium");
        assert_eq!(got.confidence, "Certain");
        assert_eq!(got.ident, "Debug header");
        assert!(got.detail.starts_with("<p><b>Debug header</b></p>"));
        assert_eq!(crate::scan::issue_type_id(&got.name), 0x0900_8000);
    }
}

//! One registration pattern for the check registries (AR-10 / F14).
//!
//! A check registry is a static slice of entries. Each entry names the check
//! (`id`), the issue it reports (`issue`) and its behaviour (a trait object
//! or a function pointer). Catalogue code derives from the registry; it must
//! not keep a second hand-maintained list of checks.
//!
//! [`CheckMeta`] is the metadata record every registry exposes. Passive checks
//! report findings at a fixed severity and confidence (one unit may name
//! several concrete issues, so its record carries the issue family); active
//! checks choose severity and confidence per finding, so their record carries
//! the identity only.
//!
//! The two enums serialize with the spellings the project file already uses,
//! so moving checks onto them does not change the format.

use serde::{Deserialize, Serialize};

/// Severity of a finding, Burp's vocabulary and the project-file spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    /// The severity for `s`, or `None` when it is not one of the four names.
    pub fn parse(s: &str) -> Option<Self> {
        [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
        ]
        .into_iter()
        .find(|v| v.as_str().eq_ignore_ascii_case(s))
    }
}

/// Confidence of a finding (Burp: Certain | Firm | Tentative).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Confidence::Tentative => "Tentative",
            Confidence::Firm => "Firm",
            Confidence::Certain => "Certain",
        }
    }

    /// The confidence for `s`, or `None` when it is not one of the three names.
    pub fn parse(s: &str) -> Option<Self> {
        [Confidence::Tentative, Confidence::Firm, Confidence::Certain]
            .into_iter()
            .find(|v| v.as_str().eq_ignore_ascii_case(s))
    }
}

/// One check's registration record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckMeta {
    /// Stable identifier (scan configuration, exports, tests).
    pub id: &'static str,
    /// The issue it reports: Burp's KnowledgeBase name where the check is a
    /// Burp port, otherwise WebProbe's wording.
    pub issue: &'static str,
    /// Fixed severity when the check's findings share one; `None` when each
    /// finding decides (active checks).
    pub severity: Option<Severity>,
    /// Fixed confidence, on the same rule as `severity`.
    pub confidence: Option<Confidence>,
}

impl CheckMeta {
    /// The identity record active checks expose: severity and confidence are
    /// per finding.
    pub const fn identified(id: &'static str, issue: &'static str) -> Self {
        Self {
            id,
            issue,
            severity: None,
            confidence: None,
        }
    }

    /// A record with fixed finding metadata (passive checks).
    pub const fn with_finding(
        id: &'static str,
        issue: &'static str,
        severity: Severity,
        confidence: Confidence,
    ) -> Self {
        Self {
            id,
            issue,
            severity: Some(severity),
            confidence: Some(confidence),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_and_confidence_round_trip_through_their_names() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
        ] {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        for c in [Confidence::Tentative, Confidence::Firm, Confidence::Certain] {
            assert_eq!(Confidence::parse(c.as_str()), Some(c));
        }
        assert_eq!(Severity::parse("critical"), None);
        assert_eq!(Confidence::parse("certain"), Some(Confidence::Certain));
        // The project file's spellings do not change with the enum.
        assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
        assert_eq!(
            serde_json::to_string(&Confidence::Tentative).unwrap(),
            "\"Tentative\""
        );
    }
}

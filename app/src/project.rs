//! Project snapshot persistence.
//!
//! Live state stays in memory; this module defines the serializable subset
//! written to a project file and the save/load helpers used by the UI.
//!
//! Saves serialize first, then replace the destination through a temporary
//! file in the same directory. A serialization or write failure therefore
//! never truncates an existing project file.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::upstream::UpstreamConfig;

/// Current project-file format version. `load` rejects any other value.
pub const PROJECT_VERSION: u32 = 1;

/// One proxy history entry as stored in a project file.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectHistory {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    pub method: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    pub path: String,
    pub status: String,
    pub request: String,
    pub response: Option<String>,
    pub note: Option<String>,
}

/// One match-and-replace rule.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectRule {
    pub enabled: bool,
    pub kind: String,
    pub match_text: String,
    pub replacement: String,
    pub comment: String,
    pub is_regex: bool,
}

/// One target-scope entry.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectScope {
    pub enabled: bool,
    pub include: bool,
    pub pattern: String,
    pub is_regex: bool,
}

/// One session-handling rule.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectSessionRule {
    pub enabled: bool,
    pub name: String,
    pub action: String,
    pub match_text: String,
    pub value: String,
}

/// One reusable macro request.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectMacro {
    pub name: String,
    pub request: String,
}

/// One Repeater tab.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectRepeater {
    pub name: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    pub request: String,
    pub response: Option<String>,
    pub result_line: String,
}
/// One scanner issue.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectIssue {
    pub id: u64,
    pub severity: String,
    pub name: String,
    pub host: String,
    pub path: String,
    pub detail: String,
}

/// One captured WebSocket record.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectWebsocket {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    pub host: String,
    pub direction: String,
    pub opcode: String,
    pub payload: String,
}

/// UI appearance persisted with the project (M-05).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Appearance {
    /// `dark`, `light` or `high_contrast`.
    #[serde(default = "default_palette")]
    pub palette: String,
    /// `compact` or `comfortable`.
    #[serde(default = "default_density")]
    pub density: String,
    /// Font size multiplier (0.7 - 2.0).
    #[serde(default = "default_font_scale")]
    pub font_scale: f32,
}

fn default_palette() -> String {
    "dark".into()
}

fn default_density() -> String {
    "comfortable".into()
}

fn default_font_scale() -> f32 {
    1.0
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            palette: default_palette(),
            density: default_density(),
            font_scale: default_font_scale(),
        }
    }
}

/// Everything the application persists in a project file.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectData {
    pub version: u32,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    #[serde(default)]
    pub saved_at: u64,
    #[serde(default)]
    pub appearance: Appearance,
    #[serde(default)]
    pub history: Vec<ProjectHistory>,
    #[serde(default)]
    pub match_request: Vec<ProjectRule>,
    #[serde(default)]
    pub match_response: Vec<ProjectRule>,
    #[serde(default)]
    pub scope: Vec<ProjectScope>,
    #[serde(default)]
    pub session_rules: Vec<ProjectSessionRule>,
    #[serde(default)]
    pub macros: Vec<ProjectMacro>,
    #[serde(default)]
    pub repeaters: Vec<ProjectRepeater>,
    #[serde(default)]
    pub issues: Vec<ProjectIssue>,
    #[serde(default)]
    pub websockets: Vec<ProjectWebsocket>,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default = "default_listener_port")]
    pub listener_port: u16,
}

fn default_listener_port() -> u16 {
    8080
}

impl Default for ProjectData {
    fn default() -> Self {
        Self {
            version: PROJECT_VERSION,
            saved_at: 0,
            appearance: Appearance::default(),
            history: Vec::new(),
            match_request: Vec::new(),
            match_response: Vec::new(),
            scope: Vec::new(),
            session_rules: Vec::new(),
            macros: Vec::new(),
            repeaters: Vec::new(),
            issues: Vec::new(),
            websockets: Vec::new(),
            upstream: UpstreamConfig::default(),
            listener_port: default_listener_port(),
        }
    }
}

/// Serialize `data` as pretty-printed JSON and atomically replace `path`.
///
/// The destination is only touched after serialization succeeds. The target
/// is written through a uniquely named file in the same directory and then
/// renamed into place, so a failed write leaves the previous project intact.
pub fn save(path: &Path, data: &ProjectData) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(data)
        .map_err(|err| format!("cannot serialize project: {err}"))?;
    bytes.push(b'\n');

    let temporary = temporary_path(path)?;
    // The temp file is deleted only after create_new succeeds; a failing open
    // must not remove an unrelated file that blocked the unique name.
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
    {
        Ok(file) => file,
        Err(err) => {
            return Err(format!(
                "cannot create project temporary file {}: {err}",
                temporary.display()
            ));
        }
    };

    if let Err(err) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!(
            "cannot write project temporary file {}: {err}",
            temporary.display()
        ));
    }

    if let Err(err) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!(
            "cannot replace project file {}: {err}",
            path.display()
        ));
    }

    Ok(())
}

/// Read and validate a project file.
pub fn load(path: &Path) -> Result<ProjectData, String> {
    let bytes = std::fs::read(path)
        .map_err(|err| format!("cannot read project {}: {err}", path.display()))?;
    let data: ProjectData = serde_json::from_slice(&bytes)
        .map_err(|err| format!("cannot parse project {}: {err}", path.display()))?;

    if data.version != PROJECT_VERSION {
        return Err(format!(
            "unsupported project version {} in {} (expected {})",
            data.version,
            path.display(),
            PROJECT_VERSION
        ));
    }

    Ok(data)
}

/// A unique sibling of the destination, so rename stays on one filesystem.
fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    if path.file_name().is_none() {
        return Err(format!(
            "project path has no file name: {}",
            path.display()
        ));
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);

    Ok(parent.join(format!(
        ".webprobe-project-{}-{stamp}-{sequence}.tmp",
        std::process::id()
    )))
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProjectData {
        ProjectData {
            version: PROJECT_VERSION,
            saved_at: 1_760_000_002,
            appearance: Appearance { palette: "light".into(), density: "compact".into(), font_scale: 1.1 },
            history: vec![ProjectHistory {
                id: 7,
                timestamp: 1_760_000_000,
                method: "GET".into(),
                host: "example.com".into(),
                port: 443,
                https: true,
                path: "/index.html".into(),
                status: "200".into(),
                request: "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
                response: Some("HTTP/1.1 200 OK\r\n\r\nok".into()),
                note: Some("checked".into()),
            }],
            match_request: vec![ProjectRule {
                enabled: true,
                kind: "request".into(),
                match_text: "old".into(),
                replacement: "new".into(),
                comment: "rewrite".into(),
                is_regex: false,
            }],
            match_response: vec![ProjectRule {
                enabled: false,
                kind: "response".into(),
                match_text: "server".into(),
                replacement: "hidden".into(),
                comment: String::new(),
                is_regex: true,
            }],
            scope: vec![ProjectScope {
                enabled: true,
                include: true,
                pattern: "example\\.com".into(),
                is_regex: true,
            }],
            session_rules: vec![ProjectSessionRule {
                enabled: true,
                name: "auth".into(),
                action: "set header".into(),
                match_text: "example.com".into(),
                value: "Authorization: Bearer token".into(),
            }],
            macros: Vec::new(),
            repeaters: Vec::new(),
            issues: vec![ProjectIssue {
                id: 11,
                severity: "medium".into(),
                name: "Missing header".into(),
                host: "example.com".into(),
                path: "/index.html".into(),
                detail: "Content-Security-Policy is absent".into(),
            }],
            websockets: vec![ProjectWebsocket {
                id: 13,
                timestamp: 1_760_000_001,
                host: "example.com".into(),
                direction: "out".into(),
                opcode: "text".into(),
                payload: "hello".into(),
            }],
            upstream: UpstreamConfig::default(),
            listener_port: 8080,
        }
    }

    fn temporary_project(tag: &str) -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "webprobe-project-test-{tag}-{}-{stamp}-{sequence}.json",
            std::process::id()
        ))
    }

    fn expect_error(result: Result<ProjectData, String>) -> String {
        match result {
            Ok(_) => panic!("expected project load to fail"),
            Err(err) => err,
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let path = temporary_project("round-trip");
        let data = sample();

        save(&path, &data).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(
            serde_json::to_value(&loaded).unwrap(),
            serde_json::to_value(&data).unwrap()
        );
        assert_eq!(loaded.version, PROJECT_VERSION);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_other_versions() {
        let path = temporary_project("version");
        let mut data = sample();
        data.version = PROJECT_VERSION + 1;

        save(&path, &data).unwrap();
        let err = expect_error(load(&path));

        assert!(err.contains("version"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_malformed_json() {
        let path = temporary_project("malformed");
        std::fs::write(&path, b"{\"version\": 1").unwrap();

        let err = expect_error(load(&path));

        assert!(err.contains("parse"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_reports_missing_file() {
        let path = temporary_project("missing");
        let err = expect_error(load(&path));

        assert!(err.contains("read"), "{err}");
    }

    #[test]
    fn save_rejects_path_without_file_name() {
        let err = match save(Path::new("/"), &sample()) {
            Ok(()) => panic!("expected save to fail"),
            Err(err) => err,
        };

        assert!(err.contains("file name"), "{err}");
    }
}

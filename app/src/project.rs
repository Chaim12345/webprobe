//! Project snapshot persistence.
//!
//! Live state stays in memory; this module defines the serializable subset
//! written to a project file and the save/load helpers used by the UI.
//!
//! A project file is one self-describing document: a magic header line
//! (`WEBPROBE PROJECT <version>`) followed by pretty-printed JSON. Older
//! bare-JSON files without the header still load, and files from a newer
//! build are rejected with a clear error instead of being misread.
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

/// First token of the header line that identifies a WebProbe project file.
pub const PROJECT_MAGIC: &str = "WEBPROBE PROJECT";

/// Current project-file format version. `load` accepts older versions and
/// rejects anything newer.
pub const PROJECT_VERSION: u32 = 2;

/// Oldest format version `load` still understands. Version 1 files were bare
/// JSON without a header.
const MIN_PROJECT_VERSION: u32 = 1;

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
    /// Burp "False positive" classification (Ze1r line 12); defaults false for
    /// legacy project files.
    #[serde(default)]
    pub false_positive: bool,
    /// Burp confidence (Certain | Firm | Tentative); legacy files load as Firm.
    #[serde(default = "default_confidence")]
    pub confidence: String,
}

fn default_confidence() -> String {
    "Firm".into()
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

/// One Logger entry (Burp keeps these separate from proxy history).
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectLoggerEntry {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    /// Tool that produced the entry (`proxy`, `repeater`, `intruder`, ...).
    pub tool: String,
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

/// One Organizer item: a request the user pinned for later.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectOrganizerItem {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub timestamp: u64,
    pub title: String,
    pub host: String,
    pub path: String,
    pub request: String,
    pub response: Option<String>,
    pub comment: String,
}

/// One Intruder result row.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectIntruderResult {
    pub payload: String,
    pub status: String,
    pub length: usize,
    pub request: String,
    pub response: Option<String>,
}

/// Intruder configuration and results as persisted with the project.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectIntruder {
    /// Attack type label (`sniper`, `battering_ram`, `pitchfork`,
    /// `cluster_bomb`).
    pub attack: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    /// The request template, including its `§` position markers.
    pub base_request: String,
    /// Raw payload text per position, one payload per line.
    #[serde(default)]
    pub payload_sets: Vec<String>,
    #[serde(default)]
    pub results: Vec<ProjectIntruderResult>,
}

impl Default for ProjectIntruder {
    fn default() -> Self {
        Self {
            attack: "sniper".into(),
            host: String::new(),
            port: 443,
            https: false,
            base_request: String::new(),
            payload_sets: Vec::new(),
            results: Vec::new(),
        }
    }
}

/// One Decoder conversion step (input and its output).
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectDecoderStep {
    pub input: String,
    pub output: String,
}

/// Decoder pane state: current input, latest output and the step history.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ProjectDecoder {
    #[serde(default)]
    pub input: String,
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub steps: Vec<ProjectDecoderStep>,
}

/// One row of the Target site map.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectTargetItem {
    pub host: String,
    pub method: String,
    pub path: String,
    /// History entry this row was derived from (0 when unknown).
    pub history_id: u64,
}

/// One HTTP header of a Collaborator interaction.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectHeader {
    pub name: String,
    pub value: String,
}

/// One Collaborator interaction, flattened to plain data.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectCollaboratorInteraction {
    pub id: u64,
    /// Unix timestamp in seconds, matching `util::now_secs`.
    pub at: u64,
    pub source: String,
    pub token: Option<String>,
    /// `http` or `dns`.
    pub kind: String,
    /// HTTP method (empty for DNS).
    pub method: String,
    /// HTTP request target (empty for DNS).
    pub target: String,
    /// HTTP body, lossy UTF-8 (empty for DNS).
    pub body: String,
    /// DNS query name (empty for HTTP).
    pub qname: String,
    /// DNS query type (0 for HTTP).
    pub qtype: u16,
    #[serde(default)]
    pub headers: Vec<ProjectHeader>,
}

/// Collaborator payloads and observed interactions.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ProjectCollaborator {
    #[serde(default)]
    pub payloads: Vec<String>,
    #[serde(default)]
    pub interactions: Vec<ProjectCollaboratorInteraction>,
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
    "light".into()
}

fn default_density() -> String {
    "compact".into()
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
    pub logger: Vec<ProjectLoggerEntry>,
    #[serde(default)]
    pub organizer: Vec<ProjectOrganizerItem>,
    #[serde(default)]
    pub intruder: ProjectIntruder,
    #[serde(default)]
    pub decoder: ProjectDecoder,
    #[serde(default)]
    pub target: Vec<ProjectTargetItem>,
    #[serde(default)]
    pub collaborator: ProjectCollaborator,
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
            logger: Vec::new(),
            organizer: Vec::new(),
            intruder: ProjectIntruder::default(),
            decoder: ProjectDecoder::default(),
            target: Vec::new(),
            collaborator: ProjectCollaborator::default(),
            upstream: UpstreamConfig::default(),
            listener_port: default_listener_port(),
        }
    }
}

/// The header line written before the JSON body.
fn header_line() -> String {
    format!("{PROJECT_MAGIC} {PROJECT_VERSION}\n")
}

/// The full document bytes: header, JSON, trailing newline.
fn document_bytes(data: &ProjectData) -> Result<Vec<u8>, String> {
    let mut normalized = data.clone();
    normalized.version = PROJECT_VERSION;
    let json = serde_json::to_vec_pretty(&normalized)
        .map_err(|err| format!("cannot serialize project: {err}"))?;

    let mut bytes = header_line().into_bytes();
    bytes.extend_from_slice(&json);
    bytes.push(b'\n');
    Ok(bytes)
}

/// Serialize `data` as a project document and atomically replace `path`.
///
/// The destination is only touched after serialization succeeds. The target
/// is written through a uniquely named file in the same directory, flushed,
/// and then renamed into place, so a failed write leaves the previous project
/// intact.
pub fn save(path: &Path, data: &ProjectData) -> Result<(), String> {
    let bytes = document_bytes(data)?;

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

    // Persist the directory entry too; best effort, the file data is already
    // durable and a failure here must not turn a good save into an error.
    sync_parent(path);
    Ok(())
}

/// Read and validate a project file.
pub fn load(path: &Path) -> Result<ProjectData, String> {
    let bytes = std::fs::read(path)
        .map_err(|err| format!("cannot read project {}: {err}", path.display()))?;
    decode(&bytes, &path.display().to_string())
}

/// Render a project document as a string (header plus JSON), for tests and
/// clipboard export.
pub fn export_json(data: &ProjectData) -> Result<String, String> {
    let bytes = document_bytes(data)?;
    String::from_utf8(bytes).map_err(|err| format!("project document is not UTF-8: {err}"))
}

/// Parse a project document from a string. Accepts both the header format and
/// legacy bare-JSON files.
pub fn import_json(text: &str) -> Result<ProjectData, String> {
    decode(text.as_bytes(), "input")
}

/// Split a document into its header version (if any) and the JSON body.
///
/// A body that starts with `{` is treated as a legacy headerless file.
fn split_document<'a>(text: &'a str, label: &str) -> Result<(Option<u32>, &'a str), String> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return Ok((None, trimmed));
    }

    let (header, body) = trimmed.split_once('\n').ok_or_else(|| {
        format!(
            "not a WebProbe project file {label}: missing \"{PROJECT_MAGIC} <version>\" header"
        )
    })?;
    let header = header.trim_end_matches('\r');

    let rest = match header.strip_prefix(PROJECT_MAGIC) {
        Some(rest) if rest.is_empty() || rest.starts_with(char::is_whitespace) => rest,
        _ => {
            return Err(format!(
                "not a WebProbe project file {label}: wrong magic header {header:?} (expected {PROJECT_MAGIC:?})"
            ));
        }
    };

    let version_text = rest.trim();
    let version = version_text.parse::<u32>().map_err(|_| {
        format!("invalid project header {header:?} in {label}: version {version_text:?} is not a number")
    })?;
    Ok((Some(version), body))
}

/// Reject versions this build cannot read.
fn check_supported(version: u32, label: &str) -> Result<(), String> {
    if version > PROJECT_VERSION {
        return Err(format!(
            "project version {version} in {label} is newer than this build supports ({PROJECT_VERSION}); upgrade WebProbe to open it"
        ));
    }
    if version < MIN_PROJECT_VERSION {
        return Err(format!(
            "unsupported project version {version} in {label} (expected {MIN_PROJECT_VERSION}..={PROJECT_VERSION})"
        ));
    }
    Ok(())
}

/// Parse a project document from raw bytes, validating the header and version.
fn decode(bytes: &[u8], label: &str) -> Result<ProjectData, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|err| format!("cannot parse project {label}: not UTF-8 ({err})"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let (header_version, body) = split_document(text, label)?;
    if let Some(version) = header_version {
        check_supported(version, label)?;
    }

    let mut data: ProjectData = serde_json::from_str(body)
        .map_err(|err| format!("cannot parse project {label}: {err}"))?;

    // The body carries a version too; the header wins when both are present,
    // so a headerless legacy file is still checked against this build.
    check_supported(data.version, label)?;
    data.version = PROJECT_VERSION;
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

/// Flush the directory entry after a rename (POSIX only; best effort).
fn sync_parent(path: &Path) {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
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
            macros: vec![ProjectMacro {
                name: "login".into(),
                request: "POST /login HTTP/1.1\r\n\r\nuser=a".into(),
            }],
            repeaters: vec![ProjectRepeater {
                name: "Repeater 1".into(),
                host: "example.com".into(),
                port: 443,
                https: true,
                request: "GET / HTTP/1.1\r\n\r\n".into(),
                response: Some("HTTP/1.1 200 OK\r\n\r\n".into()),
                result_line: "200 OK".into(),
            }],
            issues: vec![ProjectIssue {
                id: 11,
                severity: "medium".into(),
                name: "Missing header".into(),
                host: "example.com".into(),
                path: "/index.html".into(),
                detail: "Content-Security-Policy is absent".into(),
                false_positive: false,
                confidence: "Firm".into(),
            }],
            websockets: vec![ProjectWebsocket {
                id: 13,
                timestamp: 1_760_000_001,
                host: "example.com".into(),
                direction: "out".into(),
                opcode: "text".into(),
                payload: "hello".into(),
            }],
            logger: vec![ProjectLoggerEntry {
                id: 17,
                timestamp: 1_760_000_003,
                tool: "proxy".into(),
                method: "POST".into(),
                host: "api.example.com".into(),
                port: 8443,
                https: true,
                path: "/v1/items".into(),
                status: "201".into(),
                request: "POST /v1/items HTTP/1.1\r\n\r\n{\"a\":1}".into(),
                response: Some("HTTP/1.1 201 Created\r\n\r\n{}".into()),
                note: Some("logger note".into()),
            }],
            organizer: vec![ProjectOrganizerItem {
                id: 19,
                timestamp: 1_760_000_004,
                title: "Interesting endpoint".into(),
                host: "example.com".into(),
                path: "/admin".into(),
                request: "GET /admin HTTP/1.1\r\n\r\n".into(),
                response: Some("HTTP/1.1 403 Forbidden\r\n\r\n".into()),
                comment: "check auth bypass".into(),
            }],
            intruder: ProjectIntruder {
                attack: "cluster_bomb".into(),
                host: "example.com".into(),
                port: 443,
                https: true,
                base_request: "GET /?a=§1§&b=§2§ HTTP/1.1\r\n\r\n".into(),
                payload_sets: vec!["x\ny".into(), "1\n2".into()],
                results: vec![ProjectIntruderResult {
                    payload: "x,1".into(),
                    status: "200".into(),
                    length: 1234,
                    request: "GET /?a=x&b=1 HTTP/1.1\r\n\r\n".into(),
                    response: Some("HTTP/1.1 200 OK\r\n\r\n".into()),
                }],
            },
            decoder: ProjectDecoder {
                input: "aGVsbG8=".into(),
                output: "hello".into(),
                steps: vec![ProjectDecoderStep {
                    input: "aGVsbG8=".into(),
                    output: "hello".into(),
                }],
            },
            target: vec![ProjectTargetItem {
                host: "example.com".into(),
                method: "GET".into(),
                path: "/index.html".into(),
                history_id: 7,
            }],
            collaborator: ProjectCollaborator {
                payloads: vec!["http://127.0.0.1:9000/token".into()],
                interactions: vec![ProjectCollaboratorInteraction {
                    id: 23,
                    at: 1_760_000_005,
                    source: "10.0.0.5".into(),
                    token: Some("token".into()),
                    kind: "http".into(),
                    method: "GET".into(),
                    target: "/token".into(),
                    body: "ping".into(),
                    qname: String::new(),
                    qtype: 0,
                    headers: vec![ProjectHeader { name: "Host".into(), value: "127.0.0.1".into() }],
                }],
            },
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
            "webprobe-project-test-{tag}-{}-{stamp}-{sequence}.burp",
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
    fn save_writes_magic_header_before_json() {
        let path = temporary_project("header");
        save(&path, &sample()).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let first = text.lines().next().unwrap();
        assert_eq!(first, format!("{PROJECT_MAGIC} {PROJECT_VERSION}"));
        assert!(text.trim_start_matches(first).trim_start().starts_with('{'));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_accepts_legacy_bare_json() {
        let path = temporary_project("legacy");
        let legacy = r#"{
            "version": 1,
            "saved_at": 123,
            "history": [{
                "id": 1, "timestamp": 2, "method": "GET", "host": "old.test",
                "port": 80, "path": "/", "status": "200",
                "request": "GET / HTTP/1.1\r\n\r\n", "response": null, "note": null
            }]
        }"#;
        std::fs::write(&path, legacy).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.history.len(), 1);
        assert_eq!(loaded.history[0].host, "old.test");
        assert_eq!(loaded.version, PROJECT_VERSION);
        assert!(loaded.logger.is_empty());
        assert!(loaded.organizer.is_empty());
        assert!(loaded.target.is_empty());
        assert_eq!(loaded.listener_port, 8080);
        assert_eq!(loaded.appearance, Appearance::default());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_accepts_older_header_version() {
        let path = temporary_project("older-header");
        std::fs::write(
            &path,
            b"WEBPROBE PROJECT 1\n{\"version\":1,\"history\":[]}\n",
        )
        .unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.version, PROJECT_VERSION);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_wrong_magic() {
        let path = temporary_project("magic");
        std::fs::write(&path, b"WEBPROBE PROJECTX 2\n{\"version\":2}").unwrap();

        let err = expect_error(load(&path));
        assert!(err.contains("magic"), "{err}");

        std::fs::write(&path, b"some other tool's file\n{}").unwrap();
        let err = expect_error(load(&path));
        assert!(err.contains("magic"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_newer_version() {
        let path = temporary_project("version");
        let newer = PROJECT_VERSION + 1;
        std::fs::write(
            &path,
            format!("{PROJECT_MAGIC} {newer}\n{{\"version\":{newer}}}"),
        )
        .unwrap();

        let err = expect_error(load(&path));
        assert!(err.contains("version"), "{err}");
        assert!(err.contains("newer"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_truncated_file() {
        let path = temporary_project("truncated");
        save(&path, &sample()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

        let err = expect_error(load(&path));
        assert!(err.contains("parse"), "{err}");
        let _ = std::fs::remove_file(&path);

        // A header with no body is also truncated.
        std::fs::write(&path, b"WEBPROBE PROJECT 2\n").unwrap();
        let err = expect_error(load(&path));
        assert!(err.contains("parse"), "{err}");
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

    #[test]
    fn save_leaves_no_temporary_file() {
        // A private directory: parallel tests in this process also write temp
        // files into the shared temp dir, so a global count would race.
        let dir = temporary_project("atomic-dir");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("project.burp");

        save(&path, &sample()).unwrap();
        assert!(path.exists());

        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["project.burp".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unicode_and_crlf_bodies_survive() {
        let path = temporary_project("unicode");
        let mut data = sample();
        let request = "GET /caf\u{e9}/\u{65e5}\u{672c}\u{8a9e}?q=\u{2713} HTTP/1.1\r\nHost: ex\u{e4}mple.test\r\nX-Emoji: \u{1f600}\r\n\r\nna\u{ef}ve\r\n";
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\u{4f60}\u{597d}\r\n\u{1f680}";
        data.history[0].request = request.into();
        data.history[0].response = Some(response.into());
        data.history[0].note = Some("n\u{f6}te \u{2713}".into());
        data.decoder.input = "\u{fffd}\u{4e16}\u{754c}".into();

        save(&path, &data).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.history[0].request, request);
        assert_eq!(loaded.history[0].response.as_deref(), Some(response));
        assert_eq!(loaded.history[0].note.as_deref(), Some("n\u{f6}te \u{2713}"));
        assert_eq!(loaded.decoder.input, "\u{fffd}\u{4e16}\u{754c}");
        assert!(loaded.history[0].request.contains("\r\n"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn large_history_round_trips() {
        let path = temporary_project("large");
        let mut data = sample();
        data.history = (0..1000)
            .map(|i| ProjectHistory {
                id: i,
                timestamp: 1_760_000_000 + i,
                method: "GET".into(),
                host: format!("host{}.test", i % 17),
                port: 443,
                https: true,
                path: format!("/item/{i}"),
                status: "200".into(),
                request: format!("GET /item/{i} HTTP/1.1\r\nHost: h\r\n\r\n"),
                response: Some(format!("HTTP/1.1 200 OK\r\n\r\n{i}")),
                note: None,
            })
            .collect();

        save(&path, &data).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.history.len(), 1000);
        assert_eq!(loaded.history[0].id, 0);
        assert_eq!(loaded.history[999].path, "/item/999");
        assert_eq!(loaded.history[999].response.as_deref(), Some("HTTP/1.1 200 OK\r\n\r\n999"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn export_and_import_json_round_trip() {
        let data = sample();
        let text = export_json(&data).unwrap();
        assert!(text.starts_with(PROJECT_MAGIC));

        let loaded = import_json(&text).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded).unwrap(),
            serde_json::to_value(&data).unwrap()
        );

        // Legacy text without a header is accepted too.
        let legacy = import_json("{\"version\":1,\"scope\":[]}").unwrap();
        assert!(legacy.scope.is_empty());
        assert_eq!(legacy.version, PROJECT_VERSION);
    }

    #[test]
    fn save_reports_rename_failure_and_keeps_existing_file() {
        let path = temporary_project("keep");
        save(&path, &sample()).unwrap();
        let original = std::fs::read(&path).unwrap();

        // A directory at the destination makes the rename fail; the existing
        // project bytes must be untouched and the destination unchanged.
        let blocked = temporary_project("keep-blocked");
        std::fs::create_dir(&blocked).unwrap();
        let err = match save(&blocked, &sample()) {
            Ok(()) => panic!("expected save to fail"),
            Err(err) => err,
        };
        assert!(err.contains("replace"), "{err}");
        assert!(blocked.is_dir());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let _ = std::fs::remove_dir(&blocked);
        let _ = std::fs::remove_file(&path);
    }
}

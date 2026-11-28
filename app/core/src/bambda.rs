//! Compiled Java Bambda batches, isolated from the UI and proxy threads.
//!
//! Scripts are trusted local Java code, not sandboxed. The JVM has the user's
//! file/network access. A timeout and output/heap caps protect responsiveness,
//! not confidentiality. Call from a worker, never from an egui frame.
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_SOURCE: usize = 128 * 1024;
/// Maximum aggregate raw bytes passed to one JVM batch.
pub const MAX_RAW_BATCH_BYTES: usize = 1024 * 1024;

/// Rows one table application covers, newest first. The evaluator starts a
/// fresh JVM per batch, so a run over a whole 50,000-row history would keep a
/// worker busy for minutes; the tables say which rows the script saw.
pub const MAX_TABLE_ROWS: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Filter,
    Column,
    /// S-03: a passive scan check. The script returns an `AuditResult`;
    /// each exchange yields the issues it holds.
    PassiveCheck,
}

/// One issue a passive-check Bambda raised, as the script described it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct CheckIssue {
    pub name: String,
    pub detail: String,
    pub remediation: String,
    /// Montoya's `AuditIssueSeverity` name: HIGH, MEDIUM, LOW, INFORMATION.
    pub severity: String,
    /// Montoya's `AuditIssueConfidence` name: CERTAIN, FIRM, TENTATIVE.
    pub confidence: String,
}

/// One filter's verdict for one row. `Failed` covers a row exception and a
/// value that is not a boolean: the row stays visible and the run reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Hide,
    Failed,
}

/// One custom-column result for one row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cell {
    Text(String),
    Failed(String),
}

/// A table application: one verdict or one cell per evaluated row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Filters: newest-first row verdicts. Columns leave this empty.
    pub verdicts: Vec<(u64, Verdict)>,
    /// Columns: newest-first cell values. Filters leave this empty.
    pub cells: Vec<(u64, Cell)>,
    /// Passive checks: the issues raised per exchange. Others leave this empty.
    pub issues: Vec<(u64, Vec<CheckIssue>)>,
    /// Rows never handed to the script (too large for one batch).
    pub skipped: Vec<u64>,
    /// Rows whose script threw, or whose value had the wrong type.
    pub row_errors: usize,
}

/// Text shown in a custom column. Booleans, numbers and nested values keep
/// their JSON form; null is an empty cell. A long string is cut for display.
fn cell_text(value: &serde_json::Value) -> String {
    let text = match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    text.chars().take(4_096).collect()
}

impl Outcome {
    /// Fold raw row results into a table outcome. Interpreting here, not in the
    /// worker, keeps the rules testable without a JVM.
    pub fn interpret(kind: Kind, results: Vec<RowResult>, skipped: Vec<u64>) -> Self {
        let mut out = Self {
            skipped,
            ..Self::default()
        };
        for row in results {
            match kind {
                Kind::Filter => {
                    let verdict = if row.error.is_some() {
                        Verdict::Failed
                    } else {
                        match row.value {
                            Some(serde_json::Value::Bool(true)) => Verdict::Pass,
                            Some(serde_json::Value::Bool(false)) => Verdict::Hide,
                            // A filter must return a boolean; anything else is a
                            // script defect, reported per row.
                            _ => Verdict::Failed,
                        }
                    };
                    if verdict == Verdict::Failed {
                        out.row_errors += 1;
                    }
                    out.verdicts.push((row.id, verdict));
                }
                Kind::PassiveCheck => {
                    // null (no AuditResult) is "nothing found"; any other
                    // shape is a script defect, reported per row.
                    let found = match (row.error, row.value) {
                        (Some(_), _) => None,
                        (None, None | Some(serde_json::Value::Null)) => Some(Vec::new()),
                        (None, Some(mut value)) => value
                            .get_mut("issues")
                            .map(serde_json::Value::take)
                            .and_then(|v| serde_json::from_value::<Vec<CheckIssue>>(v).ok()),
                    };
                    match found {
                        Some(found) if found.is_empty() => {}
                        Some(found) => out.issues.push((row.id, found)),
                        None => out.row_errors += 1,
                    }
                }
                Kind::Column => {
                    let cell = match (row.error, row.value) {
                        (Some(error), _) => {
                            out.row_errors += 1;
                            Cell::Failed(error)
                        }
                        (None, Some(value)) => Cell::Text(cell_text(&value)),
                        (None, None) => {
                            out.row_errors += 1;
                            Cell::Failed("the script returned no value".into())
                        }
                    };
                    out.cells.push((row.id, cell));
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Exchange {
    #[serde(serialize_with = "serialize_id")]
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
}

fn serialize_id<S: serde::Serializer>(id: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_string())
}

#[derive(Debug, Deserialize)]
pub struct RowResult {
    pub id: u64,
    #[serde(default, deserialize_with = "present_value")]
    pub value: Option<serde_json::Value>,
    pub error: Option<String>,
}

fn present_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Bambda I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bambda compilation failed: {0}")]
    Compile(String),
    #[error("Bambda execution failed: {0}")]
    Execution(String),
    #[error("Bambda deadline exceeded")]
    Timeout,
    #[error("Bambda job cancelled")]
    Cancelled,
    #[error("Bambda limit exceeded: {0}")]
    Limit(&'static str),
}

#[derive(Debug)]
pub struct ChunkedResults {
    pub rows: Vec<RowResult>,
    pub skipped_ids: Vec<u64>,
}

#[derive(Debug)]
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "webprobe-bambda-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "cannot allocate Bambda directory",
        ))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
pub struct Program {
    java: PathBuf,
    classpath: std::ffi::OsString,
    kind: Kind,
    _classes: Scratch,
    cancelled: Arc<AtomicBool>,
}

impl Program {
    /// What this program was compiled for: a filter or a custom column.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Compile once per source change. Compilation errors include javac's
    /// diagnostics. No script is run by this operation.
    pub fn compile(
        java: &Path,
        api: &Path,
        kind: Kind,
        source: &str,
        deadline: Duration,
    ) -> Result<Self, Error> {
        Self::compile_cancellable(
            java,
            api,
            kind,
            source,
            deadline,
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Like compile, with a shared cancellation flag checked during compilation
    /// and every evaluation. Set it when a preview is cancelled or its UI closes.
    pub fn compile_cancellable(
        java: &Path,
        api: &Path,
        kind: Kind,
        source: &str,
        deadline: Duration,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if source.len() > MAX_SOURCE {
            return Err(Error::Limit("source exceeds 128 KiB"));
        }
        let java = std::fs::canonicalize(java)?;
        let api = std::fs::canonicalize(api)?;
        let classes = Scratch::new()?;
        let classpath = std::env::join_paths([api.as_path(), classes.0.as_path()])
            .map_err(|e| Error::Compile(e.to_string()))?;
        let ty = match kind {
            Kind::Filter => "boolean",
            Kind::Column => "Object",
            Kind::PassiveCheck => "burp.api.montoya.scanner.AuditResult",
        };
        // Names a scan check needs to build its result. Only this kind gets
        // them, so existing filters and columns compile exactly as before.
        let extra = match kind {
            Kind::PassiveCheck => {
                "import burp.api.montoya.scanner.AuditResult;\nimport burp.api.montoya.scanner.audit.issues.AuditIssue;\nimport burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;\nimport burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;\nimport java.util.List;\nimport java.util.ArrayList;\n"
            }
            Kind::Filter | Kind::Column => "",
        };
        // A scan check also receives `api` (see BambdaRunner).
        let params = match kind {
            Kind::PassiveCheck => {
                "ProxyHttpRequestResponse requestResponse, Utilities utilities, burp.api.montoya.MontoyaApi api"
            }
            Kind::Filter | Kind::Column => {
                "ProxyHttpRequestResponse requestResponse, Utilities utilities"
            }
        };
        let code = format!(
            "{extra}import burp.api.montoya.proxy.ProxyHttpRequestResponse;\nimport burp.api.montoya.utilities.Utilities;\nimport burp.api.montoya.http.message.StatusCodeClass;\nimport burp.api.montoya.http.message.params.HttpParameterType;\npublic final class WebProbeUserBambda {{\npublic static {ty} evaluate({params}) throws Exception {{\n{source}\n}}\n}}\n"
        );
        let source_path = classes.0.join("WebProbeUserBambda.java");
        std::fs::write(&source_path, code)?;
        let mut sources = Vec::new();
        for (name, source) in crate::paths::MONTOYA_BRIDGE_SOURCES {
            let path = classes.0.join(name);
            std::fs::write(&path, source)?;
            sources.push(path);
        }
        let runner = classes.0.join("BambdaRunner.java");
        std::fs::write(&runner, include_str!("../../sidecar/BambdaRunner.java"))?;
        sources.push(runner);
        let mut cmd = Command::new(&java);
        cmd.args([
            "-Xmx256m",
            "-m",
            "jdk.compiler/com.sun.tools.javac.Main",
            "-proc:none",
            "-encoding",
            "UTF-8",
            "-cp",
        ])
        .arg(&classpath)
        .arg("-d")
        .arg(&classes.0)
        .arg(source_path)
        .args(sources);
        let (status, _, stderr) = run(cmd, deadline, &cancelled)?;
        if !status.success() {
            return Err(Error::Compile(
                String::from_utf8_lossy(&stderr).into_owned(),
            ));
        }
        Ok(Self {
            java,
            classpath,
            kind,
            _classes: classes,
            cancelled,
        })
    }

    /// Compile and run one table snapshot, interpreting the results by kind.
    /// Any failed batch fails the whole application: a table never shows a
    /// half-evaluated filter.
    pub fn apply(
        &self,
        kind: Kind,
        rows: &[Exchange],
        deadline: Duration,
    ) -> Result<Outcome, Error> {
        let results = self.evaluate_chunked(rows, deadline)?;
        Ok(Outcome::interpret(kind, results.rows, results.skipped_ids))
    }

    /// Evaluate at most five rows / 1 MiB per JVM batch. The deadline is per
    /// batch; any failed batch returns an error, never a partial success.
    /// Individually oversized rows are reported explicitly in skipped_ids.
    pub fn evaluate_chunked(
        &self,
        rows: &[Exchange],
        deadline: Duration,
    ) -> Result<ChunkedResults, Error> {
        if rows.len() > 10_000 {
            return Err(Error::Limit("more than 10000 rows"));
        }
        let mut result = ChunkedResults {
            rows: Vec::new(),
            skipped_ids: Vec::new(),
        };
        let mut batch = Vec::new();
        let mut raw_bytes = 0;
        for row in rows {
            let size = row
                .request
                .len()
                .saturating_add(row.response.as_ref().map_or(0, Vec::len))
                .saturating_add(row.host.len());
            if size > MAX_RAW_BATCH_BYTES {
                result.skipped_ids.push(row.id);
                continue;
            }
            if !batch.is_empty() && (batch.len() == 5 || raw_bytes + size > MAX_RAW_BATCH_BYTES) {
                result.rows.extend(self.evaluate(&batch, deadline)?);
                batch.clear();
                raw_bytes = 0;
            }
            raw_bytes += size;
            batch.push(row.clone());
        }
        if !batch.is_empty() {
            result.rows.extend(self.evaluate(&batch, deadline)?);
        }
        Ok(result)
    }

    /// Evaluate a snapshot in a separate JVM, returning one result per row.
    /// The program may be reused across batches. Concurrent calls use separate
    /// input directories and JVMs, so user static state is not shared.
    /// The deadline covers the entire JVM batch, not each individual row.
    pub fn evaluate(&self, rows: &[Exchange], deadline: Duration) -> Result<Vec<RowResult>, Error> {
        if rows.len() > 10_000 {
            return Err(Error::Limit("more than 10000 rows"));
        }
        // Check the raw size before serde can allocate an oversized JSON buffer.
        let raw: usize = rows
            .iter()
            .map(|r| {
                r.request
                    .len()
                    .saturating_add(r.response.as_ref().map_or(0, Vec::len))
                    .saturating_add(r.host.len())
            })
            .try_fold(0usize, |a, b| a.checked_add(b))
            .ok_or(Error::Limit("input size overflow"))?;
        if raw > MAX_RAW_BATCH_BYTES {
            return Err(Error::Limit("batch too large"));
        }
        let input = serde_json::to_vec(rows).map_err(|e| Error::Execution(e.to_string()))?;
        if input.len() > MAX_INPUT {
            return Err(Error::Limit("input exceeds 16 MiB"));
        }
        let scratch = Scratch::new()?;
        let path = scratch.0.join("input.json");
        std::fs::write(&path, input)?;
        let mut cmd = Command::new(&self.java);
        cmd.args(["-Xmx256m", "-Djava.awt.headless=true", "-cp"])
            .arg(&self.classpath)
            .arg("BambdaRunner")
            .arg(path)
            .arg(std::process::id().to_string());
        let (status, out, stderr) = run(cmd, deadline, &self.cancelled)?;
        if !status.success() {
            return Err(Error::Execution(format!(
                "JVM exited with {status}: {}",
                String::from_utf8_lossy(&stderr)
            )));
        }
        let results: Vec<RowResult> = out
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|line| serde_json::from_slice(line).map_err(|e| Error::Execution(e.to_string())))
            .collect::<Result<_, _>>()?;
        if results.len() != rows.len() || results.iter().zip(rows).any(|(a, b)| a.id != b.id) {
            return Err(Error::Execution(
                "JVM returned an incomplete or reordered batch".into(),
            ));
        }
        Ok(results)
    }
}

fn run(
    mut cmd: Command,
    deadline: Duration,
    cancelled: &AtomicBool,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), Error> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    crate::util::own_process_group(&mut cmd);
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    for (is_error, pipe) in [
        (false, Box::new(stdout) as Box<dyn Read + Send>),
        (true, Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe
                .take(MAX_OUTPUT as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = tx.send((is_error, result));
        });
    }
    drop(tx);
    let start = Instant::now();
    let mut out = None;
    let mut err = None;
    let mut too_large = false;
    let result = loop {
        while let Ok((is_error, bytes)) = rx.try_recv() {
            match bytes {
                Ok(bytes) if bytes.len() <= MAX_OUTPUT => {
                    if is_error {
                        err = Some(bytes);
                    } else {
                        out = Some(bytes);
                    }
                }
                Ok(_) => {
                    too_large = true;
                    break;
                }
                Err(e) => {
                    crate::util::kill_process_tree(child.id(), None, Duration::from_millis(100));
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e.into());
                }
            }
        }
        if cancelled.load(Ordering::Relaxed) {
            break Err(Error::Cancelled);
        }
        if too_large {
            break Err(Error::Limit("JVM output exceeds 8 MiB"));
        }
        if start.elapsed() >= deadline {
            break Err(Error::Timeout);
        }
        match child.try_wait() {
            Ok(Some(status)) if out.is_some() && err.is_some() => {
                break Ok((status, out.take().unwrap(), err.take().unwrap()));
            }
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    crate::util::kill_process_tree(child.id(), None, Duration::from_millis(100));
    let _ = child.kill();
    let _ = child.wait();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u64, value: serde_json::Value) -> RowResult {
        RowResult {
            id,
            value: Some(value),
            error: None,
        }
    }

    #[test]
    fn a_filter_verdict_is_true_false_or_a_reported_row_error() {
        let outcome = Outcome::interpret(
            Kind::Filter,
            vec![
                row(3, serde_json::json!(true)),
                row(2, serde_json::json!(false)),
                RowResult {
                    id: 1,
                    value: None,
                    error: Some("fixture failure".into()),
                },
                // A filter that returns a number is a script defect, not a no.
                row(0, serde_json::json!(1)),
            ],
            vec![9],
        );
        assert_eq!(
            outcome.verdicts,
            vec![
                (3, Verdict::Pass),
                (2, Verdict::Hide),
                (1, Verdict::Failed),
                (0, Verdict::Failed),
            ]
        );
        assert_eq!(outcome.row_errors, 2);
        assert_eq!(outcome.skipped, vec![9]);
        assert!(outcome.cells.is_empty());
    }

    #[test]
    fn a_column_keeps_typed_text_and_reports_each_row_error() {
        let outcome = Outcome::interpret(
            Kind::Column,
            vec![
                row(4, serde_json::json!("fixture")),
                row(3, serde_json::json!(7)),
                row(2, serde_json::json!(null)),
                row(1, serde_json::json!(true)),
                RowResult {
                    id: 0,
                    value: None,
                    error: Some("boom".into()),
                },
            ],
            Vec::new(),
        );
        assert_eq!(
            outcome.cells,
            vec![
                (4, Cell::Text("fixture".into())),
                (3, Cell::Text("7".into())),
                // Null is an empty cell, not an error.
                (2, Cell::Text(String::new())),
                (1, Cell::Text("true".into())),
                (0, Cell::Failed("boom".into())),
            ]
        );
        assert_eq!(outcome.row_errors, 1);
        assert!(outcome.verdicts.is_empty());
    }

    #[test]
    fn a_missing_column_value_is_a_row_error() {
        let outcome = Outcome::interpret(
            Kind::Column,
            vec![RowResult {
                id: 1,
                value: None,
                error: None,
            }],
            Vec::new(),
        );
        assert!(matches!(
            &outcome.cells[0].1,
            Cell::Failed(message) if message.contains("no value")
        ));
        assert_eq!(outcome.row_errors, 1);
    }

    #[test]
    fn a_long_column_value_is_cut_for_display() {
        let outcome = Outcome::interpret(
            Kind::Column,
            vec![row(1, serde_json::json!("x".repeat(5_000)))],
            Vec::new(),
        );
        match &outcome.cells[0].1 {
            Cell::Text(text) => assert_eq!(text.chars().count(), 4_096),
            other => panic!("{other:?}"),
        }
    }
}

//! AR-09 core: byte-level transport evidence for NUL and non-UTF-8 bodies.
//! Source-only artifact for review: nothing here has been built or run.
//!
//! Two cases: a control proving the real send path carries the captured bytes
//! exactly, and a CHARACTERISATION of the lossy text conversion that the tool
//! state applies today (it passes while the defect exists and must be inverted
//! when a byte-backed design lands).
//!
//! Each case is a parent wrapper that never constructs `Shared`. The parent
//! creates a unique tempdir with a fake HOME, a fake XDG_CONFIG_HOME and an
//! explicit CA dir, writes non-secret sentinels, and spawns this test binary
//! with `--exact <case>` and those paths in the CHILD environment only. Child
//! output goes to files, never to an undrained pipe.
//!
//! Loopback only. The capture fixture records every byte it receives under an
//! absolute deadline, a size cap and a stop flag, independent of the declared
//! Content-Length, so header length, body length and trailing bytes stay
//! distinguishable.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use webprobe_core::net::{Shared, send_raw_with};

const CONNECTION_BUDGET: Duration = Duration::from_secs(10);
const QUIET_WINDOW: Duration = Duration::from_millis(150);
const TRAILING_DRAIN: Duration = Duration::from_millis(400);
const CASE_BUDGET: Duration = Duration::from_secs(90);
const WAIT_GRACE: Duration = Duration::from_secs(2);
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const CHILD_MARKER: &str = "WEBPROBE_AR09_CHILD_CASE";
const CHILD_ROOT: &str = "WEBPROBE_AR09_CHILD_ROOT";
const SENTINEL_HOME: &[u8] = b"ar09-sentinel-home: not a CA\n";
const SENTINEL_XDG: &[u8] = b"ar09-sentinel-xdg: not a CA\n";
const CONTROL: &str = "control_transport_preserves_nul_and_non_utf8_body_bytes";
const LOSSY: &str = "characterisation_repeater_text_state_is_lossy_for_non_utf8_bodies";

const BODY: &[u8] = &[0x00, 0xff, 0xfe, 0x00, 0xc3, 0x28];
const LOSSY_BODY: &[u8] = &[
    0x00, 0xef, 0xbf, 0xbd, 0xef, 0xbf, 0xbd, 0x00, 0xef, 0xbf, 0xbd, 0x28,
];

// ---------- child-process CA isolation ----------

struct Isolation {
    root: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
    ca: PathBuf,
    child: Option<Child>,
}

impl Isolation {
    fn new(tag: &str) -> Isolation {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let raw = std::env::temp_dir().join(format!(
            "webprobe-ar09-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&raw).expect("create isolation root");
        let root = raw.canonicalize().expect("canonical isolation root");
        let home = root.join("home");
        let xdg = root.join("xdg");
        let ca = root.join("ca");
        for dir in [
            home.join(".config").join("webprobe"),
            xdg.join("webprobe"),
            ca.clone(),
        ] {
            std::fs::create_dir_all(&dir).expect("create isolated dir");
        }
        std::fs::write(
            home.join(".config").join("webprobe").join("ca.json"),
            SENTINEL_HOME,
        )
        .expect("write HOME sentinel");
        std::fs::write(xdg.join("webprobe").join("ca.json"), SENTINEL_XDG)
            .expect("write XDG sentinel");
        Isolation {
            root,
            home,
            xdg,
            ca,
            child: None,
        }
    }

    fn spawn(&mut self, case: &str) {
        for var in [CHILD_MARKER, CHILD_ROOT] {
            assert!(
                std::env::var_os(var).is_none(),
                "{var} is inherited; a validation runner must clear child marker/root vars",
            );
        }
        let exe = std::env::current_exe().expect("current test binary");
        let stdout = std::fs::File::create(self.root.join("child.stdout")).expect("stdout file");
        let stderr = std::fs::File::create(self.root.join("child.stderr")).expect("stderr file");
        let mut cmd = Command::new(exe);
        cmd.arg("--exact")
            .arg(case)
            .arg("--nocapture")
            .arg("--test-threads=1");
        cmd.env(CHILD_MARKER, case)
            .env(CHILD_ROOT, &self.root)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("WEBPROBE_CA_DIR", &self.ca)
            .env_remove("RUST_BACKTRACE")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        self.child = Some(cmd.spawn().expect("spawn isolated child"));
    }

    /// Bounded wait. The child is owned by a kill-on-drop guard for the whole
    /// call, so a panic here cannot orphan it.
    fn finish(&mut self) -> ChildRun {
        let mut guard = ChildGuard::new(self.child.take().expect("child was spawned"));
        let exited = guard.wait_bounded(CASE_BUDGET);
        let status = guard.status();
        if !exited {
            println!("AR09-CLEANUP-TIMEOUT: child exceeded {CASE_BUDGET:?} and was killed");
        }
        let stdout = std::fs::read_to_string(self.root.join("child.stdout")).unwrap_or_default();
        let stderr = std::fs::read_to_string(self.root.join("child.stderr")).unwrap_or_default();
        ChildRun {
            status,
            timed_out: !exited,
            stdout,
            stderr,
        }
    }

    /// Exact-shape layout check, run before any status assertion so it is
    /// reported even when the child fails unexpectedly. Fails closed on
    /// inspection errors.
    fn verify_layout(&self, expect_ca: bool) {
        let home_sentinel = self.home.join(".config").join("webprobe").join("ca.json");
        let xdg_sentinel = self.xdg.join("webprobe").join("ca.json");
        let home_files = list_files(&self.home).expect("inspect the fake HOME");
        let xdg_files = list_files(&self.xdg).expect("inspect the fake XDG dir");
        assert_eq!(
            home_files,
            vec![home_sentinel.clone()],
            "the fake HOME may contain only its sentinel",
        );
        assert_eq!(
            xdg_files,
            vec![xdg_sentinel.clone()],
            "the fake XDG dir may contain only its sentinel",
        );
        assert_eq!(
            std::fs::read(&home_sentinel).expect("read the HOME sentinel"),
            SENTINEL_HOME,
            "the child changed the fake HOME CA file",
        );
        assert_eq!(
            std::fs::read(&xdg_sentinel).expect("read the XDG sentinel"),
            SENTINEL_XDG,
            "the child changed the fake XDG CA file",
        );
        let ca_files = list_files(&self.ca).expect("inspect the owned CA dir");
        for file in &ca_files {
            assert!(
                file.starts_with(&self.ca),
                "CA artifact outside the owned CA dir: {file:?}",
            );
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
            assert!(
                name == "ca.json" || name.starts_with("ca.json.retired-"),
                "unexpected CA artifact: {file:?}",
            );
        }
        if expect_ca {
            assert!(
                self.ca.join("ca.json").is_file(),
                "no CA artifact inside the owned CA dir; an empty dir is not proof",
            );
        }
        println!("AR09-CA-FILES: {ca_files:?}");
    }
}

impl Drop for Isolation {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_)) => {}
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> ChildGuard {
        ChildGuard { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("live child")
    }

    fn wait_bounded(&mut self, budget: Duration) -> bool {
        let end = Instant::now() + budget;
        loop {
            match self.child_mut().try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if Instant::now() >= end => {
                    let _ = self.child_mut().kill();
                    let _ = self.child_mut().wait();
                    return false;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(25)),
                Err(_) => return false,
            }
        }
    }

    fn status(&mut self) -> Option<ExitStatus> {
        self.child_mut().try_wait().ok().flatten()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_)) => {}
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

struct ChildRun {
    status: Option<ExitStatus>,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

fn list_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// True only inside the spawned child for `case`. The three paths must be the
/// exact owned children of the canonical root, not a lexical prefix match.
fn child_branch(case: &str) -> bool {
    if std::env::var(CHILD_MARKER).ok().as_deref() != Some(case) {
        return false;
    }
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root missing"));
    assert!(root.is_absolute(), "child root must be absolute: {root:?}");
    let canonical = root.canonicalize().expect("canonical child root");
    assert_eq!(canonical, root, "child root is not canonical: {root:?}");
    let expected = [
        ("HOME", root.join("home")),
        ("XDG_CONFIG_HOME", root.join("xdg")),
        ("WEBPROBE_CA_DIR", root.join("ca")),
    ];
    for (var, want) in &expected {
        let value = std::env::var_os(var).unwrap_or_else(|| panic!("{var} missing in the child"));
        let path = PathBuf::from(value);
        assert_eq!(&path, want, "{var} is not the owned path {want:?}");
        let canonical = path.canonicalize().expect("canonical isolated path");
        assert_eq!(
            canonical, *want,
            "{var} resolves through a symlink: {path:?}"
        );
    }
    println!("AR09-ISOLATION-OK root={}", root.display());
    true
}

fn assert_single_case(stdout: &str, want_pass: bool) {
    let summary = stdout
        .lines()
        .rev()
        .find(|l| l.starts_with("test result:"))
        .unwrap_or_else(|| panic!("child printed no test summary:\n{stdout}"));
    if want_pass {
        assert!(
            summary.contains("1 passed") && summary.contains("0 failed"),
            "child did not run exactly one passing case: {summary}",
        );
    } else {
        assert!(
            summary.contains("1 failed") && summary.contains("0 passed"),
            "child did not run exactly one failing case: {summary}",
        );
    }
}

fn report(run: &ChildRun) {
    println!("AR09-CHILD-STDOUT-BEGIN");
    print!("{}", run.stdout);
    println!("AR09-CHILD-STDOUT-END");
    eprint!("{}", run.stderr);
}

// ---------- capture fixture (child side only) ----------

fn find_head(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn declared_len(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn body_of(wire: &[u8]) -> &[u8] {
    let head = find_head(wire).expect("head terminator");
    &wire[head + 4..]
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn raw_request() -> Vec<u8> {
    let mut r = format!(
        "POST /ar09 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        BODY.len()
    )
    .into_bytes();
    r.extend_from_slice(BODY);
    r
}

struct Record {
    wire: Vec<u8>,
    complete: bool,
}

/// Reads one request under an absolute deadline, a size cap and the shared
/// stop flag. `complete` is set once the head and the declared body arrived,
/// but reading continues: trailing bytes past the declared length are the
/// defect under test, so stopping at Content-Length would hide them. The
/// post-complete drain ends after a quiet window or a hard drain cap.
fn read_client(stream: &mut std::net::TcpStream, stop: &AtomicBool) -> Record {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(25)));
    let deadline = Instant::now() + CONNECTION_BUDGET;
    let mut wire = Vec::new();
    let mut chunk = [0u8; 2048];
    let mut complete = false;
    let mut complete_at: Option<Instant> = None;
    let mut last_byte_at = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline || stop.load(Ordering::SeqCst) || wire.len() >= MAX_REQUEST_BYTES {
            break;
        }
        if let Some(at) = complete_at
            && (now.duration_since(at) >= TRAILING_DRAIN
                || now.duration_since(last_byte_at) >= QUIET_WINDOW)
        {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = MAX_REQUEST_BYTES - wire.len();
                wire.extend_from_slice(&chunk[..n.min(room)]);
                last_byte_at = Instant::now();
                if !complete
                    && let Some(head) = find_head(&wire)
                    && wire.len() >= head + 4 + declared_len(&wire[..head])
                {
                    complete = true;
                    complete_at = Some(Instant::now());
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    Record { wire, complete }
}

struct Capture {
    port: u16,
    accepts: Arc<AtomicUsize>,
    records: Arc<Mutex<Vec<Record>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Capture {
    fn start() -> Capture {
        let listener = TcpListener::bind("127.0.0.1:0").expect("capture bind");
        listener.set_nonblocking(true).expect("capture nonblocking");
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let records = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, r, s) = (
            Arc::clone(&accepts),
            Arc::clone(&records),
            Arc::clone(&stop),
        );
        let join = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        a.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                        let record = read_client(&mut stream, &s);
                        r.lock().unwrap().push(record);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return,
                }
            }
        });
        Capture {
            port,
            accepts,
            records,
            stop,
            join: Some(join),
        }
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }

    /// Bounded wait for the first complete record; the reader may still be
    /// draining its deadline when the sender returns.
    fn first_complete(&self, deadline: Duration) -> Vec<u8> {
        let end = Instant::now() + deadline;
        loop {
            if let Some(wire) = self
                .records
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.complete)
                .map(|r| r.wire.clone())
            {
                return wire;
            }
            assert!(
                Instant::now() < end,
                "the origin recorded no complete request in time",
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

// ---------- child bodies ----------

fn control_body() {
    let mut capture = Capture::start();
    let shared = Shared::new();
    let raw = raw_request();
    let up = send_raw_with(&shared, "127.0.0.1", capture.port, &raw, None);
    assert!(up.error.is_none(), "send error: {:?}", up.error);
    let wire = capture.first_complete(CONNECTION_BUDGET + WAIT_GRACE);
    let head = find_head(&wire).expect("head terminator");
    let declared = declared_len(&wire[..head]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    let accepts = capture.accepts.load(Ordering::SeqCst);
    capture.stop_and_join();
    println!("AR09-CONTROL-EVIDENCE accepts={accepts} declared={declared}");
    println!(
        "AR09-CONTROL-EVIDENCE body_len={} trailing={trailing}",
        body.len()
    );
    println!(
        "AR09-CONTROL-EVIDENCE sent_len={} wire_len={}",
        raw.len(),
        wire.len()
    );
    println!("AR09-CONTROL-EVIDENCE body_hex={}", hex(&body));
    assert_eq!(accepts, 1, "the origin accepted exactly one connection");
    assert_eq!(body, BODY, "body bytes intact (hex {})", hex(&body));
    assert_eq!(declared, BODY.len(), "declared length matches the body");
    assert_eq!(trailing, 0, "no bytes past the declared length");
    assert_eq!(
        wire.len(),
        raw.len() + b"Connection: close\r\n".len(),
        "only the Connection header was added",
    );
    println!("CASE-COMPLETE: {CONTROL}");
}

/// CHARACTERISATION of the tool-state conversion: the production expression
/// stores lossy text, Repeater sends `text.as_bytes()`, and the declared
/// length no longer matches the body. It passes while the defect exists and is
/// not a fix or GUI proof.
fn lossy_body() {
    let mut capture = Capture::start();
    let shared = Shared::new();
    let raw = raw_request();
    let stored: String = String::from_utf8_lossy(&raw).into_owned();
    let sent = stored.as_bytes().to_vec();
    let up = send_raw_with(&shared, "127.0.0.1", capture.port, &sent, None);
    assert!(up.error.is_none(), "send error: {:?}", up.error);
    let wire = capture.first_complete(CONNECTION_BUDGET + WAIT_GRACE);
    let head = find_head(&wire).expect("head terminator");
    let declared = declared_len(&wire[..head]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    capture.stop_and_join();
    println!(
        "AR09-LOSSY-EVIDENCE declared={declared} body_len={}",
        body.len()
    );
    println!("AR09-LOSSY-EVIDENCE trailing={trailing}");
    println!("AR09-LOSSY-EVIDENCE body_hex={}", hex(&body));
    assert_eq!(
        body,
        LOSSY_BODY,
        "lossy conversion result (hex {})",
        hex(&body),
    );
    assert_eq!(declared, 6, "header keeps the captured length");
    assert_eq!(
        declared,
        BODY.len(),
        "header still declares the original body",
    );
    assert_eq!(trailing, 6, "6 bytes sit past the declared length");
    println!("CASE-COMPLETE: {LOSSY}");
}

// ---------- top-level cases ----------

/// Control: the real send path carries NUL and non-UTF-8 body bytes exactly.
#[test]
fn control_transport_preserves_nul_and_non_utf8_body_bytes() {
    if child_branch(CONTROL) {
        control_body();
        return;
    }
    let mut iso = Isolation::new("control");
    iso.spawn(CONTROL);
    let run = iso.finish();
    iso.verify_layout(true);
    report(&run);
    assert!(
        !run.timed_out,
        "AR09-CLEANUP-TIMEOUT: the child had to be killed",
    );
    assert!(
        run.status.is_some_and(|s| s.success()),
        "child failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        run.status,
        run.stdout,
        run.stderr,
    );
    assert_single_case(&run.stdout, true);
    assert!(
        run.stdout.contains("AR09-CONTROL-EVIDENCE"),
        "no per-case completion record\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains(&format!("CASE-COMPLETE: {CONTROL}")),
        "no CASE-COMPLETE line\nstdout:\n{}",
        run.stdout,
    );
}

/// CHARACTERISATION: passes today and records the defect; invert it when
/// binary bodies are carried by tool state.
#[test]
fn characterisation_repeater_text_state_is_lossy_for_non_utf8_bodies() {
    if child_branch(LOSSY) {
        lossy_body();
        return;
    }
    let mut iso = Isolation::new("lossy");
    iso.spawn(LOSSY);
    let run = iso.finish();
    iso.verify_layout(true);
    report(&run);
    assert!(
        !run.timed_out,
        "AR09-CLEANUP-TIMEOUT: the child had to be killed",
    );
    assert!(
        run.status.is_some_and(|s| s.success()),
        "child failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        run.status,
        run.stdout,
        run.stderr,
    );
    assert_single_case(&run.stdout, true);
    assert!(
        run.stdout.contains("AR09-LOSSY-EVIDENCE"),
        "no per-case completion record\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains(&format!("CASE-COMPLETE: {LOSSY}")),
        "no CASE-COMPLETE line\nstdout:\n{}",
        run.stdout,
    );
}

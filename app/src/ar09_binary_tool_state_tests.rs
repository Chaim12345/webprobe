//! AR-09 app layer: NUL and non-UTF-8 bodies through the real Repeater and
//! Intruder send paths. Source-only artifact for review: nothing here has
//! been built or run.
//!
//! Each case that constructs `Shared` is a parent wrapper that never
//! constructs it itself. The parent creates a unique tempdir with a fake
//! HOME, a fake XDG_CONFIG_HOME and an explicit CA dir, writes non-secret
//! sentinels, and spawns this binary with `--exact <case>` and those paths in
//! the CHILD environment only. Child output goes to files, never to an
//! undrained pipe. The split-delivery fixture check constructs neither
//! `Shared` nor `App` and runs directly.
//!
//! Loopback only. The send-path cases are CHARACTERISATIONS of the current
//! lossy conversion, not a fix and not GUI proof.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use webprobe_core::intruder::{AttackType, SetSpec};
use webprobe_core::intruder_run::{self, AttackSettings, RunState};
use webprobe_core::net;

const CONNECTION_BUDGET: Duration = Duration::from_secs(10);
const CASE_BUDGET: Duration = Duration::from_secs(120);
const RUN_BUDGET: Duration = Duration::from_secs(15);
const SETTLE_BUDGET: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const CHILD_MARKER: &str = "WEBPROBE_AR09_APP_CHILD_CASE";
const CHILD_ROOT: &str = "WEBPROBE_AR09_APP_CHILD_ROOT";
const SENTINEL_HOME: &[u8] = b"ar09-app-sentinel-home: not a CA\n";
const SENTINEL_XDG: &[u8] = b"ar09-app-sentinel-xdg: not a CA\n";
const REPEATER: &str = "ar09_binary_tool_state_tests::repeater_send_once_sends_the_lossy_body";
const INTRUDER: &str =
    "ar09_binary_tool_state_tests::intruder_attack_sends_the_lossy_template_body";
const CLEANUP_FAILED: &str = "AR09-INTRUDER-CLEANUP-FAILED";

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
            "webprobe-ar09-app-{tag}-{}-{nanos}",
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
            println!("AR09-APP-CLEANUP-TIMEOUT: child exceeded {CASE_BUDGET:?}");
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
        println!("AR09-APP-CA-FILES: {ca_files:?}");
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
    println!("AR09-APP-ISOLATION-OK root={}", root.display());
    true
}

fn assert_single_case(stdout: &str) {
    let summary = stdout
        .lines()
        .rev()
        .find(|l| l.starts_with("test result:"))
        .unwrap_or_else(|| panic!("child printed no test summary:\n{stdout}"));
    assert!(
        summary.contains("1 passed") && summary.contains("0 failed"),
        "child did not run exactly one passing case: {summary}",
    );
}

fn report(run: &ChildRun) {
    println!("AR09-APP-CHILD-STDOUT-BEGIN");
    print!("{}", run.stdout);
    println!("AR09-APP-CHILD-STDOUT-END");
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
/// stop flag. `complete` is true only when the head and every declared body
/// byte arrived; a head seen at EOF or on error is never complete.
fn read_client(stream: &mut std::net::TcpStream, stop: &AtomicBool) -> Record {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let deadline = Instant::now() + CONNECTION_BUDGET;
    let mut wire = Vec::new();
    let mut chunk = [0u8; 2048];
    let mut complete = false;
    while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        if wire.len() >= MAX_REQUEST_BYTES {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = MAX_REQUEST_BYTES - wire.len();
                wire.extend_from_slice(&chunk[..n.min(room)]);
                if let Some(head) = find_head(&wire) {
                    if wire.len() >= head + 4 + declared_len(&wire[..head]) {
                        complete = true;
                        break;
                    }
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
                        records.lock().unwrap().push(record);
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

    /// Bounded wait for the first complete record.
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

/// Owns the running Intruder attack. `settle` is the explicit cleanup path; a
/// failed settle prints a non-success record that the parent rejects. Drop is
/// only a backstop and never panics.
struct RunGuard {
    state: Arc<RunState>,
    settled: bool,
}

impl RunGuard {
    fn new(state: Arc<RunState>) -> RunGuard {
        RunGuard {
            state,
            settled: false,
        }
    }

    fn stop_and_settle(&mut self, budget: Duration) -> bool {
        self.state.stop.store(true, Ordering::SeqCst);
        let end = Instant::now() + budget;
        while self.state.is_running() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.settled = !self.state.is_running();
        if !self.settled {
            println!("{CLEANUP_FAILED}: the run was still active after {budget:?}");
        }
        self.settled
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if !self.settled && self.state.is_running() {
            let _ = self.stop_and_settle(SETTLE_BUDGET);
        }
    }
}

// ---------- child bodies ----------

/// Real Repeater path: `request_for_tools` -> `send_following` ->
/// `send_once` -> `req.as_bytes()` -> socket.
fn repeater_body() {
    let mut capture = Capture::start();
    let shared = net::Shared::new();
    let text = crate::ui::request_for_tools(&raw_request());
    let edited = text.replacen("POST /ar09", "POST /ar09?edited=1", 1);
    let service = crate::repeater_ops::Service::new("127.0.0.1", capture.port, false);
    let out = crate::repeater_ops::send_following(
        &shared,
        &edited,
        &service,
        crate::repeater_ops::FollowMode::Never,
        false,
        &|| false,
        &|_, _| {},
    );
    assert!(out.error.is_none(), "send error: {:?}", out.error);
    let wire = capture.first_complete(CONNECTION_BUDGET + Duration::from_secs(2));
    let head = find_head(&wire).expect("head terminator");
    let declared = declared_len(&wire[..head]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    let accepts = capture.accepts.load(Ordering::SeqCst);
    capture.stop_and_join();
    let edited_line = String::from_utf8_lossy(&wire[..head]).starts_with("POST /ar09?edited=1 ");
    println!("AR09-REPEATER-EVIDENCE accepts={accepts} declared={declared}");
    println!(
        "AR09-REPEATER-EVIDENCE body_len={} trailing={trailing}",
        body.len()
    );
    println!("AR09-REPEATER-EVIDENCE edited_line={edited_line}");
    println!("AR09-REPEATER-EVIDENCE body_hex={}", hex(&body));
    assert!(edited_line, "the edited request line reached the wire");
    assert_eq!(accepts, 1, "one origin connection");
    assert_eq!(
        body,
        LOSSY_BODY,
        "the converted body was sent (hex {})",
        hex(&body),
    );
    assert_eq!(declared, 6, "header keeps the captured length");
    assert_eq!(trailing, 6, "6 bytes sit past the declared length");
    println!("CASE-COMPLETE: {REPEATER}");
}

/// Real Intruder path: `request_for_tools` -> template -> `intruder_run::start`
/// (dispatcher and `execute_probe`) -> `update_content_length` -> socket.
fn intruder_body() {
    let mut capture = Capture::start();
    let shared = net::Shared::new();
    let text = crate::ui::request_for_tools(&raw_request());
    let template = text.replacen("POST /ar09", "POST /ar09\u{a7}p\u{a7}", 1);
    let state = intruder_run::start(
        shared.clone(),
        &template,
        AttackType::Sniper,
        vec![SetSpec::List(vec!["x".into()])],
        ("127.0.0.1".into(), capture.port, false),
        AttackSettings::default(),
    )
    .expect("attack starts");
    let mut guard = RunGuard::new(Arc::clone(&state));
    let end = Instant::now() + RUN_BUDGET;
    while state.is_running() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    let finished = !state.is_running();
    if !finished {
        guard.stop_and_settle(SETTLE_BUDGET);
    }
    assert!(
        finished,
        "the Intruder run did not finish within {RUN_BUDGET:?} (done={})",
        state.done.load(Ordering::SeqCst),
    );
    state.drain_rows();
    let wire = capture.first_complete(CONNECTION_BUDGET + Duration::from_secs(2));
    let head = find_head(&wire).expect("head terminator");
    let declared = declared_len(&wire[..head]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    capture.stop_and_join();
    println!(
        "AR09-INTRUDER-EVIDENCE declared={declared} body_len={}",
        body.len()
    );
    println!("AR09-INTRUDER-EVIDENCE trailing={trailing}");
    println!("AR09-INTRUDER-EVIDENCE body_hex={}", hex(&body));
    assert_eq!(
        body,
        LOSSY_BODY,
        "the converted template body was sent (hex {})",
        hex(&body),
    );
    assert_eq!(
        declared,
        body.len(),
        "Intruder restamped Content-Length to the converted length",
    );
    assert_eq!(trailing, 0, "no bytes past the restamped length");
    println!("CASE-COMPLETE: {INTRUDER}");
}

// ---------- top-level cases ----------

/// Fixture self-check: constructs neither `Shared` nor `App`, so it needs no
/// child-process CA isolation. It proves the capture records a known byte
/// length across a split delivery, independent of the declared length.
#[test]
fn capture_fixture_records_a_split_delivery_without_trusting_content_length() {
    let mut capture = Capture::start();
    let raw = raw_request();
    let head_end = find_head(&raw).expect("head terminator") + 4;
    let mut client =
        std::net::TcpStream::connect(("127.0.0.1", capture.port)).expect("client connect");
    client
        .set_read_timeout(Some(CONNECTION_BUDGET))
        .expect("read timeout");
    client.write_all(&raw[..head_end]).expect("write head");
    let _ = client.flush();
    std::thread::sleep(Duration::from_millis(50));
    client.write_all(&raw[head_end..]).expect("write body");
    let _ = client.flush();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    let wire = capture.first_complete(CONNECTION_BUDGET + Duration::from_secs(2));
    let declared = declared_len(&wire[..find_head(&wire).expect("head")]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    capture.stop_and_join();
    println!(
        "AR09-FIXTURE-EVIDENCE known_len={} captured_len={}",
        raw.len(),
        wire.len(),
    );
    println!(
        "AR09-FIXTURE-EVIDENCE declared={declared} body_len={}",
        body.len()
    );
    println!("AR09-FIXTURE-EVIDENCE trailing={trailing}");
    assert_eq!(
        wire.len(),
        raw.len(),
        "the fixture captured the known length"
    );
    assert_eq!(body, BODY, "the split body is intact");
    assert_eq!(trailing, 0, "no bytes past the declared length");
}

#[test]
fn repeater_send_once_sends_the_lossy_body() {
    if child_branch(REPEATER) {
        repeater_body();
        return;
    }
    let mut iso = Isolation::new("repeater");
    iso.spawn(REPEATER);
    let run = iso.finish();
    iso.verify_layout(true);
    report(&run);
    assert!(
        !run.timed_out,
        "AR09-APP-CLEANUP-TIMEOUT: the child had to be killed",
    );
    assert!(
        run.status.is_some_and(|s| s.success()),
        "child failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        run.status,
        run.stdout,
        run.stderr,
    );
    assert_single_case(&run.stdout);
    assert!(
        run.stdout.contains("AR09-REPEATER-EVIDENCE"),
        "no per-case completion record\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains(&format!("CASE-COMPLETE: {REPEATER}")),
        "no CASE-COMPLETE line\nstdout:\n{}",
        run.stdout,
    );
}

#[test]
fn intruder_attack_sends_the_lossy_template_body() {
    if child_branch(INTRUDER) {
        intruder_body();
        return;
    }
    let mut iso = Isolation::new("intruder");
    iso.spawn(INTRUDER);
    let run = iso.finish();
    iso.verify_layout(true);
    report(&run);
    assert!(
        !run.timed_out,
        "AR09-APP-CLEANUP-TIMEOUT: the child had to be killed",
    );
    assert!(
        run.status.is_some_and(|s| s.success()),
        "child failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        run.status,
        run.stdout,
        run.stderr,
    );
    assert!(
        !run.stdout.contains(CLEANUP_FAILED),
        "the Intruder run did not settle; child termination is containment, not acceptance",
    );
    assert_single_case(&run.stdout);
    assert!(
        run.stdout.contains("AR09-INTRUDER-EVIDENCE"),
        "no per-case completion record\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains(&format!("CASE-COMPLETE: {INTRUDER}")),
        "no CASE-COMPLETE line\nstdout:\n{}",
        run.stdout,
    );
}

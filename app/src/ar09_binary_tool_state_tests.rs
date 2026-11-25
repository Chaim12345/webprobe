//! AR-09 app layer: NUL and non-UTF-8 bodies through the real Repeater and
//! Intruder send paths.
//!
//! Source-only revision under review: each case that constructs `Shared` is a
//! parent wrapper that never constructs it itself. The parent creates a unique
//! tempdir with a fake HOME, a fake XDG_CONFIG_HOME and an explicit CA dir,
//! writes non-secret sentinels, then spawns this binary with `--exact <case>`
//! and those paths in the CHILD environment only. The split-delivery fixture
//! check constructs neither `Shared` nor `App` and runs directly.
//!
//! Loopback only. No fix claim: these are characterisations of the current
//! code plus the transport control.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use webprobe_core::intruder::{AttackType, SetSpec};
use webprobe_core::intruder_run::{self, AttackSettings, RunState};
use webprobe_core::net;

const IDLE: Duration = Duration::from_millis(400);
const CASE_BUDGET: Duration = Duration::from_secs(120);
const CHILD_MARKER: &str = "WEBPROBE_AR09_APP_CHILD_CASE";
const CHILD_ROOT: &str = "WEBPROBE_AR09_APP_CHILD_ROOT";
const SENTINEL_HOME: &[u8] = b"ar09-app-sentinel-home: not a CA\n";
const SENTINEL_XDG: &[u8] = b"ar09-app-sentinel-xdg: not a CA\n";
const REPEATER: &str = "ar09_binary_tool_state_tests::repeater_send_once_sends_the_lossy_body";
const INTRUDER: &str = "ar09_binary_tool_state_tests::intruder_attack_sends_the_lossy_template_body";

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
    timed_out: bool,
}

impl Isolation {
    fn new(tag: &str) -> Isolation {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "webprobe-ar09-app-{tag}-{}-{nanos}",
            std::process::id()
        ));
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
            timed_out: false,
        }
    }

    fn spawn(&mut self, case: &str) {
        assert!(
            std::env::var_os(CHILD_MARKER).is_none(),
            "refusing to spawn a child from inside a child"
        );
        let exe = std::env::current_exe().expect("current test binary");
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.child = Some(cmd.spawn().expect("spawn isolated child"));
    }

    fn finish(&mut self) -> std::process::Output {
        let mut child = self.child.take().expect("child was spawned");
        let end = Instant::now() + CASE_BUDGET;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(_) => break,
                None if Instant::now() >= end => {
                    self.timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(25)),
            }
        }
        child.wait_with_output().expect("child output")
    }

    fn assert_sentinels(&self) {
        assert_eq!(
            std::fs::read(self.home.join(".config").join("webprobe").join("ca.json"))
                .expect("HOME sentinel readable"),
            SENTINEL_HOME,
            "the child changed the fake HOME CA file"
        );
        assert_eq!(
            std::fs::read(self.xdg.join("webprobe").join("ca.json"))
                .expect("XDG sentinel readable"),
            SENTINEL_XDG,
            "the child changed the fake XDG CA file"
        );
    }

    fn assert_no_ca_outside_owned_ca(&self) {
        let mut files = Vec::new();
        collect_files(&self.home, &mut files);
        collect_files(&self.xdg, &mut files);
        files.retain(|p| !p.ends_with("webprobe/ca.json"));
        assert!(
            files.is_empty(),
            "files created outside the owned CA dir: {files:?}"
        );
        println!("AR09-APP-CA-DIR: {:?}", self.ca);
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

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn child_branch(case: &str) -> bool {
    if std::env::var(CHILD_MARKER).ok().as_deref() != Some(case) {
        return false;
    }
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root missing"));
    assert!(root.is_absolute(), "child root must be absolute: {root:?}");
    for var in ["HOME", "XDG_CONFIG_HOME", "WEBPROBE_CA_DIR"] {
        let value = std::env::var_os(var).unwrap_or_else(|| panic!("{var} missing in the child"));
        let path = PathBuf::from(value);
        assert!(path.is_absolute(), "{var} is not absolute: {path:?}");
        assert!(
            path.starts_with(&root),
            "{var} {path:?} is outside the owned tempdir {root:?}"
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
        "child did not run exactly one passing case: {summary}"
    );
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

struct Capture {
    port: u16,
    accepts: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Capture {
    fn start() -> Capture {
        let listener = TcpListener::bind("127.0.0.1:0").expect("capture bind");
        listener.set_nonblocking(true).expect("capture nonblocking");
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, r, s) = (
            Arc::clone(&accepts),
            Arc::clone(&requests),
            Arc::clone(&stop),
        );
        let join = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        a.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(IDLE));
                        let mut wire = Vec::new();
                        let mut chunk = [0u8; 2048];
                        loop {
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => wire.extend_from_slice(&chunk[..n]),
                            }
                        }
                        r.lock().unwrap().push(wire);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return,
                }
            }
        });
        Capture {
            port,
            accepts,
            requests,
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

    fn first(&self, deadline: Duration) -> Vec<u8> {
        let end = Instant::now() + deadline;
        loop {
            if let Some(wire) = self.requests.lock().unwrap().first().cloned() {
                return wire;
            }
            assert!(Instant::now() < end, "the origin recorded no request in time");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

struct RunGuard {
    state: Arc<RunState>,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::SeqCst);
        let end = Instant::now() + Duration::from_secs(5);
        while self.state.is_running() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
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
    let wire = capture.first(IDLE + Duration::from_secs(3));
    let head = find_head(&wire).expect("head terminator");
    let declared = declared_len(&wire[..head]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    let accepts = capture.accepts.load(Ordering::SeqCst);
    capture.stop_and_join();
    let edited_line = String::from_utf8_lossy(&wire[..head]).starts_with("POST /ar09?edited=1 ");
    println!(
        "AR09-REPEATER-EVIDENCE accepts={accepts} declared={declared} body_len={} trailing={trailing} edited_line={edited_line} body_hex={}",
        body.len(),
        hex(&body)
    );
    assert!(edited_line, "the edited request line reached the wire");
    assert_eq!(accepts, 1, "one origin connection");
    assert_eq!(body, LOSSY_BODY, "the converted body was sent (hex {})", hex(&body));
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
    let guard = RunGuard {
        state: Arc::clone(&state),
    };
    let end = Instant::now() + Duration::from_secs(15);
    while state.is_running() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !state.is_running(),
        "the Intruder run did not finish within 15 s (done={})",
        state.done.load(Ordering::SeqCst)
    );
    state.drain_rows();
    let wire = capture.first(IDLE + Duration::from_secs(3));
    let head = find_head(&wire).expect("head terminator");
    let declared = declared_len(&wire[..head]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    capture.stop_and_join();
    println!(
        "AR09-INTRUDER-EVIDENCE declared={declared} body_len={} trailing={trailing} body_hex={}",
        body.len(),
        hex(&body)
    );
    assert_eq!(body, LOSSY_BODY, "the converted template body was sent (hex {})", hex(&body));
    assert_eq!(
        declared,
        body.len(),
        "Intruder restamped Content-Length to the converted length"
    );
    assert_eq!(trailing, 0, "no bytes past the restamped length");
    drop(guard);
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
        .set_read_timeout(Some(IDLE + Duration::from_secs(1)))
        .expect("client read timeout");
    client.write_all(&raw[..head_end]).expect("write head");
    let _ = client.flush();
    std::thread::sleep(Duration::from_millis(50));
    client.write_all(&raw[head_end..]).expect("write body");
    let _ = client.flush();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    let wire = capture.first(IDLE + Duration::from_secs(3));
    let declared = declared_len(&wire[..find_head(&wire).expect("head")]);
    let body = body_of(&wire).to_vec();
    let trailing = body.len().saturating_sub(declared);
    capture.stop_and_join();
    println!(
        "AR09-FIXTURE-EVIDENCE known_len={} captured_len={} declared={declared} body_len={} trailing={trailing}",
        raw.len(),
        wire.len(),
        body.len()
    );
    assert_eq!(wire.len(), raw.len(), "the fixture captured the known length");
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
    let out = iso.finish();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !iso.timed_out,
        "child timed out\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        out.status.success(),
        "child failed ({:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert_single_case(&stdout);
    assert!(
        stdout.contains("AR09-REPEATER-EVIDENCE"),
        "no per-case completion record\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("CASE-COMPLETE: {REPEATER}")),
        "no CASE-COMPLETE line\nstdout:\n{stdout}"
    );
    iso.assert_sentinels();
    iso.assert_no_ca_outside_owned_ca();
}

#[test]
fn intruder_attack_sends_the_lossy_template_body() {
    if child_branch(INTRUDER) {
        intruder_body();
        return;
    }
    let mut iso = Isolation::new("intruder");
    iso.spawn(INTRUDER);
    let out = iso.finish();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !iso.timed_out,
        "child timed out\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        out.status.success(),
        "child failed ({:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert_single_case(&stdout);
    assert!(
        stdout.contains("AR09-INTRUDER-EVIDENCE"),
        "no per-case completion record\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("CASE-COMPLETE: {INTRUDER}")),
        "no CASE-COMPLETE line\nstdout:\n{stdout}"
    );
    iso.assert_sentinels();
    iso.assert_no_ca_outside_owned_ca();
}


//! F9: a held intercepted HTTP request must not outlive its client, and no
//! request may reach the origin after the client cancels.
//!
//! Source-only revision under review: every case is a parent wrapper that
//! never constructs `Shared`. The parent creates a unique tempdir with a fake
//! HOME, a fake XDG_CONFIG_HOME and an explicit CA dir, writes non-secret
//! sentinels, then spawns this test binary with `--exact <case>` and those
//! paths in the CHILD environment only. See `notes/f9-intercept-disconnect.md`.
//!
//! Loopback only: a real `handle_conn` proxy path, a fake origin listener and
//! a raw client socket. No remote traffic.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use webprobe_core::net::{Shared, handle_conn, intercept_release_all};

const WAIT: Duration = Duration::from_secs(3);
const CASE_BUDGET: Duration = Duration::from_secs(60);
const CHILD_MARKER: &str = "WEBPROBE_F9_CHILD_CASE";
const CHILD_ROOT: &str = "WEBPROBE_F9_CHILD_ROOT";
const SENTINEL_HOME: &[u8] = b"f9-sentinel-home: not a CA\n";
const SENTINEL_XDG: &[u8] = b"f9-sentinel-xdg: not a CA\n";
const CONTROL: &str = "control_normal_request_reaches_the_origin_and_returns";
const HELD: &str = "held_request_is_released_when_the_client_disconnects";

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
        let name = format!("webprobe-f9-{tag}-{}-{nanos}", std::process::id());
        let root = std::env::temp_dir().join(name);
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
        Isolation { root, home, xdg, ca, child: None, timed_out: false }
    }

    /// Spawns this test binary on exactly `case` with isolated paths in the
    /// child environment only (no process-wide env mutation).
    fn spawn(&mut self, case: &str, ignored: bool) {
        assert!(
            std::env::var_os(CHILD_MARKER).is_none(),
            "refusing to spawn a child from inside a child",
        );
        let exe = std::env::current_exe().expect("current test binary");
        let mut cmd = Command::new(exe);
        cmd.arg("--exact").arg(case).arg("--nocapture").arg("--test-threads=1");
        if ignored {
            cmd.arg("--ignored");
        }
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

    /// Bounded wait: kill and reap on timeout, then collect the output.
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
            "the child changed the fake HOME CA file",
        );
        assert_eq!(
            std::fs::read(self.xdg.join("webprobe").join("ca.json"))
                .expect("XDG sentinel readable"),
            SENTINEL_XDG,
            "the child changed the fake XDG CA file",
        );
    }

    /// No new files under the fake HOME or XDG; any CA write must have gone to
    /// the explicit CA dir.
    fn assert_no_ca_outside_owned_ca(&self) {
        let mut files = Vec::new();
        collect_files(&self.home, &mut files);
        collect_files(&self.xdg, &mut files);
        files.retain(|p| !p.ends_with("webprobe/ca.json"));
        assert!(
            files.is_empty(),
            "files created outside the owned CA dir: {files:?}",
        );
        println!("F9-CA-DIR: {:?}", self.ca);
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

/// True only inside the spawned child for `case`; validates that every
/// isolated path is absolute and inside the owned tempdir.
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
            "{var} {path:?} is outside the owned tempdir {root:?}",
        );
    }
    println!("F9-ISOLATION-OK root={}", root.display());
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

// ---------- fixtures (child side only) ----------

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

struct Origin {
    port: u16,
    accepts: Arc<AtomicUsize>,
    parsed: Arc<AtomicUsize>,
    bytes: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Origin {
    fn start() -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
        listener.set_nonblocking(true).expect("origin nonblocking");
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let parsed = Arc::new(AtomicUsize::new(0));
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (a, p, b, s) = (
            Arc::clone(&accepts),
            Arc::clone(&parsed),
            Arc::clone(&bytes),
            Arc::clone(&stop),
        );
        let join = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        a.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        if let Some(wire) = read_request(&mut stream) {
                            p.fetch_add(1, Ordering::SeqCst);
                            b.lock().unwrap().push(wire);
                            let _ = stream.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok",
                            );
                            let _ = stream.flush();
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return,
                }
            }
        });
        Origin { port, accepts, parsed, bytes, stop, join: Some(join) }
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(head) = find_head(&buf) {
                    if buf.len() >= head + 4 + declared_len(&buf[..head]) {
                        return Some(buf);
                    }
                }
            }
        }
    }
    find_head(&buf).map(|_| buf)
}

struct Proxy {
    port: u16,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Proxy {
    fn start(shared: Arc<Shared>) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        listener.set_nonblocking(true).expect("proxy nonblocking");
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let conns = Arc::new(Mutex::new(Vec::new()));
        let (s, c) = (Arc::clone(&stop), Arc::clone(&conns));
        let join = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let shared = Arc::clone(&shared);
                        let handle = std::thread::spawn(move || handle_conn(shared, stream));
                        c.lock().unwrap().push(handle);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return,
                }
            }
        });
        Proxy { port, stop, join: Some(join), conns }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
        let handles = std::mem::take(&mut *self.conns.lock().unwrap());
        let mut detached = 0usize;
        for handle in handles {
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                detached += 1;
            }
        }
        if detached > 0 {
            // No safe way to time-bound a join: the parent's child kill is the
            // containment, and this line is the explicit blocker record.
            println!("F9-PROXY-WORKERS-DETACHED: {detached}");
        }
    }
}

fn wait_queue(shared: &Shared, want: usize, deadline: Duration) -> bool {
    let end = Instant::now() + deadline;
    while Instant::now() < end {
        if shared.queue.lock().unwrap().len() == want {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    shared.queue.lock().unwrap().len() == want
}

fn request(origin_port: u16) -> Vec<u8> {
    format!(
        "GET http://127.0.0.1:{origin_port}/f9 HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

// ---------- child bodies ----------

fn control_body() {
    let mut origin = Origin::start();
    let shared = Shared::new();
    let proxy = Proxy::start(Arc::clone(&shared));
    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).expect("client connect");
    client.set_read_timeout(Some(WAIT)).expect("client read timeout");
    client.write_all(&request(origin.port)).expect("client write");
    let _ = client.flush();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response).into_owned();
    let accepts = origin.accepts.load(Ordering::SeqCst);
    let parsed = origin.parsed.load(Ordering::SeqCst);
    let retained = origin.bytes.lock().unwrap().len();
    origin.stop_and_join();
    println!("F9-CONTROL-EVIDENCE accepts={accepts} parsed={parsed} retained={retained}");
    println!("F9-CONTROL-EVIDENCE response_bytes={}", response.len());
    assert!(
        text.contains("200 OK") && text.contains("upstream-ok"),
        "response: {text:?}",
    );
    assert_eq!(parsed, 1, "origin parsed exactly one request (accepts={accepts})");
    println!("CASE-COMPLETE: {CONTROL}");
}

fn held_body() {
    let mut origin = Origin::start();
    let shared = Shared::new();
    shared.intercept_on.store(true, Ordering::SeqCst);
    shared.intercept_rules.lock().unwrap().clear();
    let proxy = Proxy::start(Arc::clone(&shared));
    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).expect("client connect");

    // Fully sent request, then a full close: not a write-half shutdown.
    client.write_all(&request(origin.port)).expect("client write");
    let _ = client.flush();
    assert!(
        wait_queue(&shared, 1, WAIT),
        "the held entry was not established before the cancel",
    );
    let accepts_before = origin.accepts.load(Ordering::SeqCst);
    let parsed_before = origin.parsed.load(Ordering::SeqCst);

    let _ = client.shutdown(Shutdown::Both);
    drop(client);

    let started = Instant::now();
    let released = wait_queue(&shared, 0, WAIT);
    let released_after = started.elapsed();
    let held_after = shared.queue.lock().unwrap().len();
    let accepts_at_cancel = origin.accepts.load(Ordering::SeqCst);
    let parsed_at_cancel = origin.parsed.load(Ordering::SeqCst);
    let retained_at_cancel = origin.bytes.lock().unwrap().len();

    // Explicit characterisation action, never teardown: forward the held item
    // and record what the origin then sees.
    let mut forwarded = 0usize;
    if held_after > 0 {
        forwarded = intercept_release_all(&shared, false);
        let end = Instant::now() + WAIT;
        while Instant::now() < end && origin.parsed.load(Ordering::SeqCst) <= parsed_at_cancel {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let parsed_after_forward = origin.parsed.load(Ordering::SeqCst);

    // Teardown always drops held entries; it never forwards.
    let dropped_at_teardown = intercept_release_all(&shared, true);

    println!("F9-EVIDENCE released={released} released_after={released_after:?}");
    println!("F9-EVIDENCE held_after_3s={held_after} forwards={forwarded}");
    println!("F9-EVIDENCE accepts_before={accepts_before} parsed_before={parsed_before}");
    println!("F9-EVIDENCE accepts_at_cancel={accepts_at_cancel}");
    println!("F9-EVIDENCE parsed_at_cancel={parsed_at_cancel}");
    println!("F9-EVIDENCE retained_at_cancel={retained_at_cancel}");
    println!("F9-EVIDENCE parsed_after_forward={parsed_after_forward}");
    println!("F9-EVIDENCE dropped_at_teardown={dropped_at_teardown}");
    assert!(
        released && parsed_at_cancel == 0,
        "F9-EVIDENCE held request outlived its client: released={released}",
    );
    println!("CASE-COMPLETE: {HELD}");
}

// ---------- top-level cases ----------

#[test]
fn control_normal_request_reaches_the_origin_and_returns() {
    if child_branch(CONTROL) {
        control_body();
        return;
    }
    let mut iso = Isolation::new("control");
    iso.spawn(CONTROL, false);
    let out = iso.finish();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !iso.timed_out,
        "child timed out\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        out.status.success(),
        "child failed ({:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status,
    );
    assert_single_case(&stdout, true);
    assert!(
        stdout.contains("F9-CONTROL-EVIDENCE"),
        "no per-case completion record\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains(&format!("CASE-COMPLETE: {CONTROL}")),
        "no CASE-COMPLETE line\nstdout:\n{stdout}",
    );
    iso.assert_sentinels();
    iso.assert_no_ca_outside_owned_ca();
}

#[test]
#[ignore = "F9 defect: held HTTP request has no client-liveness wait; see notes/f9-intercept-disconnect.md"]
fn held_request_is_released_when_the_client_disconnects() {
    if child_branch(HELD) {
        held_body();
        return;
    }
    let mut iso = Isolation::new("held");
    iso.spawn(HELD, true);
    let out = iso.finish();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !iso.timed_out,
        "child timed out\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert_eq!(
        out.status.code(),
        Some(101),
        "expected the draft regression to fail with the F9 defect\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert_single_case(&stdout, false);
    assert!(
        stderr.contains("F9-EVIDENCE") && stderr.contains("released=false"),
        "child failed for an unexpected reason\nstderr:\n{stderr}",
    );
    assert!(
        !stdout.contains(&format!("CASE-COMPLETE: {HELD}")),
        "the draft regression unexpectedly passed; promote it out of #[ignore]",
    );
    iso.assert_sentinels();
    iso.assert_no_ca_outside_owned_ca();
}


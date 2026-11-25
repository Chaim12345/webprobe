//! F9: what happens to a held intercepted HTTP request when its client goes
//! away. Source-only artifact for review: nothing here has been built or run.
//!
//! `held_request_is_released_when_the_client_disconnects` records
//! the CURRENT behaviour (a request stays held and is still forwardable after
//! the client closed). It is a characterisation, not a fix guard: it passes
//! precisely because the defect exists. A future target-behaviour regression
//! (held request released, nothing sent) is planned once a fix is approved.
//!
//! Every case is a parent wrapper that never constructs `Shared`. The parent
//! creates a unique tempdir with a fake HOME, a fake XDG_CONFIG_HOME and an
//! explicit CA dir, writes non-secret sentinels, and spawns this test binary
//! with `--exact <case>` and those paths in the CHILD environment only. Child
//! output goes to files, never to an undrained pipe.
//!
//! Loopback only: a real `handle_conn` proxy path, a fake origin listener and
//! a raw client socket. No remote traffic.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use webprobe_core::net::{Shared, handle_conn, intercept_release_all};

const WAIT: Duration = Duration::from_secs(3);
const PROXY_SETTLE: Duration = Duration::from_secs(3);
const CASE_BUDGET: Duration = Duration::from_secs(90);
const CONNECTION_BUDGET: Duration = Duration::from_secs(10);
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const CHILD_MARKER: &str = "WEBPROBE_F9_CHILD_CASE";
const CHILD_ROOT: &str = "WEBPROBE_F9_CHILD_ROOT";
const SENTINEL_HOME: &[u8] = b"f9-sentinel-home: not a CA\n";
const SENTINEL_XDG: &[u8] = b"f9-sentinel-xdg: not a CA\n";
const CONTROL: &str = "control_normal_request_reaches_the_origin_and_returns";
const HELD: &str = "held_request_is_released_when_the_client_disconnects";
const DETACHED: &str = "F9-PROXY-WORKERS-DETACHED";

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
        let raw =
            std::env::temp_dir().join(format!("webprobe-f9-{tag}-{}-{nanos}", std::process::id()));
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

    /// Spawns this test binary on exactly `case` with isolated paths in the
    /// child environment only. Refuses to run with inherited marker vars: a
    /// validation runner must clear them before spawning.
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
            println!("F9-CLEANUP-TIMEOUT: child exceeded {CASE_BUDGET:?} and was killed");
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
        println!("F9-CA-FILES: {ca_files:?}");
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

    /// Waits for exit inside the budget; kills and reaps on timeout.
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

/// Prints the child output so the case, isolation and byte facts survive.
fn report(run: &ChildRun) {
    println!("F9-CHILD-STDOUT-BEGIN");
    print!("{}", run.stdout);
    println!("F9-CHILD-STDOUT-END");
    eprint!("{}", run.stderr);
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

struct OriginRecord {
    wire: Vec<u8>,
    complete: bool,
}

/// Reads one request under an absolute deadline, a size cap and the shared
/// stop flag. `complete` is true only when the head and every declared
/// body byte arrived; a head seen at EOF or on error is never complete.
fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> OriginRecord {
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
    OriginRecord { wire, complete }
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
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                        let record = read_request(&mut stream, &s);
                        if record.complete {
                            p.fetch_add(1, Ordering::SeqCst);
                            b.lock().unwrap().push(record.wire);
                            let _ = stream.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok",
                            );
                            let _ = stream.flush();
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return,
                }
            }
        });
        Origin {
            port,
            accepts,
            parsed,
            bytes,
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
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

struct Proxy {
    port: u16,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
    clients: Arc<Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    fn start(shared: Arc<Shared>) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        listener.set_nonblocking(true).expect("proxy nonblocking");
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let conns = Arc::new(Mutex::new(Vec::new()));
        let clients = Arc::new(Mutex::new(Vec::new()));
        let (s, c, k) = (Arc::clone(&stop), Arc::clone(&conns), Arc::clone(&clients));
        let acceptor_shared = Arc::clone(&shared);
        let join = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // A cloned handle lets teardown close the client side
                        // so the worker can finish inside the settle window.
                        if let Ok(handle) = stream.try_clone() {
                            k.lock().unwrap().push(handle);
                        }
                        let shared = Arc::clone(&acceptor_shared);
                        let handle = std::thread::spawn(move || handle_conn(shared, stream));
                        c.lock().unwrap().push(handle);
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => return,
                }
            }
        });
        Proxy {
            port,
            shared,
            stop,
            join: Some(join),
            conns,
            clients,
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // Order matters: close owned clients, stop the acceptor, drop held
        // entries, then give finished workers a bounded window to be joined.
        for client in self.clients.lock().unwrap().drain(..) {
            let _ = client.shutdown(Shutdown::Both);
        }
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
        let dropped = intercept_release_all(&self.shared, true);
        if dropped > 0 {
            println!("F9-PROXY-SETTLE: dropped {dropped} held entries");
        }
        let mut pending = std::mem::take(&mut *self.conns.lock().unwrap());
        let end = Instant::now() + PROXY_SETTLE;
        while !pending.is_empty() && Instant::now() < end {
            let mut still = Vec::new();
            for handle in pending {
                if handle.is_finished() {
                    let _ = handle.join();
                } else {
                    still.push(handle);
                }
            }
            pending = still;
            if !pending.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if !pending.is_empty() {
            // No safe time-bound join exists for a production worker thread:
            // the parent's child kill is containment, and the parent treats
            // this record as a non-success cleanup outcome.
            println!("{DETACHED}: {}", pending.len());
        }
    }
}

/// Drops held entries on any exit path, including a panic. Teardown never
/// forwards. Declared after the proxy so it runs before the proxy settle.
struct HeldQueueGuard {
    shared: Arc<Shared>,
    torn_down: bool,
}

impl HeldQueueGuard {
    fn new(shared: Arc<Shared>) -> HeldQueueGuard {
        HeldQueueGuard {
            shared,
            torn_down: false,
        }
    }

    fn release(&mut self, drop_held: bool) -> usize {
        let released = intercept_release_all(&self.shared, drop_held);
        if drop_held {
            self.torn_down = true;
        }
        released
    }
}

impl Drop for HeldQueueGuard {
    fn drop(&mut self) {
        if !self.torn_down {
            let dropped = intercept_release_all(&self.shared, true);
            if dropped > 0 {
                println!("F9-RAII-TEARDOWN: dropped {dropped} held entries");
            }
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
    client.set_read_timeout(Some(WAIT)).expect("read timeout");
    client
        .write_all(&request(origin.port))
        .expect("client write");
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
    assert_eq!(
        parsed, 1,
        "origin parsed exactly one request (accepts={accepts})"
    );
    println!("CASE-COMPLETE: {CONTROL}");
}

fn held_body() {
    let mut origin = Origin::start();
    let shared = Shared::new();
    shared.intercept_on.store(true, Ordering::SeqCst);
    shared.intercept_rules.lock().unwrap().clear();
    let proxy = Proxy::start(Arc::clone(&shared));
    // Declared after the proxy so it drops first: a panic anywhere below tears
    // the held queue down before the proxy settle window runs.
    let mut guard = HeldQueueGuard::new(Arc::clone(&shared));
    let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).expect("client connect");

    // Fully sent request, then a full close: not a write-half shutdown.
    client
        .write_all(&request(origin.port))
        .expect("client write");
    let _ = client.flush();
    assert!(
        wait_queue(&shared, 1, WAIT),
        "the held entry was not established before the cancel",
    );
    let accepts_before = origin.accepts.load(Ordering::SeqCst);
    let parsed_before = origin.parsed.load(Ordering::SeqCst);

    disconnect(client);

    let started = Instant::now();
    let released = wait_queue(&shared, 0, WAIT);
    let released_after = started.elapsed();
    let held_after = shared.queue.lock().unwrap().len();
    let accepts_at_cancel = origin.accepts.load(Ordering::SeqCst);
    let parsed_at_cancel = origin.parsed.load(Ordering::SeqCst);

    // A late forward by the proxy worker would land after the release: give
    // it time, then sample the origin again. The worker's own exit is checked
    // by the proxy settle on drop (a detached worker fails the parent).
    std::thread::sleep(Duration::from_millis(300));
    let accepts_final = origin.accepts.load(Ordering::SeqCst);
    let parsed_final = origin.parsed.load(Ordering::SeqCst);

    println!("F9-EVIDENCE released={released} released_after={released_after:?}");
    println!("F9-EVIDENCE held_after={held_after}");
    println!("F9-EVIDENCE accepts_before={accepts_before} parsed_before={parsed_before}");
    println!("F9-EVIDENCE accepts_at_cancel={accepts_at_cancel}");
    println!("F9-EVIDENCE parsed_at_cancel={parsed_at_cancel}");
    println!("F9-EVIDENCE accepts_final={accepts_final} parsed_final={parsed_final}");

    assert_eq!(
        (accepts_before, parsed_before),
        (0, 0),
        "nothing may reach the origin while the request is held",
    );
    assert!(
        released && held_after == 0,
        "F9-TARGET-FAILURE: held request outlived its client: released={released}",
    );
    assert_eq!(
        (accepts_at_cancel, parsed_at_cancel, accepts_final, parsed_final),
        (0, 0, 0, 0),
        "F9-TARGET-FAILURE: the origin was contacted after the client left",
    );

    // Nothing is left to forward or drop.
    let forwarded = guard.release(false);
    let dropped_at_teardown = guard.release(true);
    println!("F9-EVIDENCE forwards={forwarded} dropped_at_teardown={dropped_at_teardown}");
    assert_eq!(
        (forwarded, dropped_at_teardown),
        (0, 0),
        "the released entry must be gone from the queue",
    );
    println!("CASE-COMPLETE: {HELD}");
}

/// A full close of the client connection: both directions shut down, then
/// the socket is closed as the stream goes out of scope.
fn disconnect(client: TcpStream) {
    let _ = client.shutdown(Shutdown::Both);
}

// ---------- top-level cases ----------

#[test]
fn control_normal_request_reaches_the_origin_and_returns() {
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
        "F9-CLEANUP-TIMEOUT: the child had to be killed"
    );
    assert!(
        run.status.is_some_and(|s| s.success()),
        "child failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        run.status,
        run.stdout,
        run.stderr,
    );
    assert!(
        !run.stdout.contains(DETACHED),
        "a production worker could not be joined; child termination is containment, not acceptance",
    );
    assert_single_case(&run.stdout, true);
    assert!(
        run.stdout.contains("F9-ISOLATION-OK"),
        "the case never ran in the child; check the case constant against the test fn name\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains("F9-CONTROL-EVIDENCE"),
        "no per-case completion record\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains(&format!("CASE-COMPLETE: {CONTROL}")),
        "no CASE-COMPLETE line\nstdout:\n{}",
        run.stdout,
    );
}

/// Target-behaviour regression for F9: a held request is released when its
/// client disconnects and nothing reaches the origin afterwards.
#[test]
fn held_request_is_released_when_the_client_disconnects() {
    if child_branch(HELD) {
        held_body();
        return;
    }
    let mut iso = Isolation::new("held");
    iso.spawn(HELD);
    let run = iso.finish();
    iso.verify_layout(true);
    report(&run);
    assert!(
        !run.timed_out,
        "F9-CLEANUP-TIMEOUT: the child had to be killed"
    );
    assert!(
        run.status.is_some_and(|s| s.success()),
        "child failed ({:?})\nstdout:\n{}\nstderr:\n{}",
        run.status,
        run.stdout,
        run.stderr,
    );
    assert!(
        !run.stdout.contains(DETACHED),
        "a production worker could not be joined; child termination is containment, not acceptance",
    );
    assert_single_case(&run.stdout, true);
    assert!(
        run.stdout.contains("F9-ISOLATION-OK"),
        "the case never ran in the child; check the case constant against the test fn name\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains("F9-EVIDENCE released=true"),
        "the held request was not released\nstdout:\n{}",
        run.stdout,
    );
    assert!(
        run.stdout.contains(&format!("CASE-COMPLETE: {HELD}")),
        "no CASE-COMPLETE line\nstdout:\n{}",
        run.stdout,
    );
}

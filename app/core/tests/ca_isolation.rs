//! AR-01/F13 fixture: a test must not read or create the real user CA
//! (`$WEBPROBE_CA_DIR`, else `$XDG_CONFIG_HOME/webprobe`, else
//! `~/.config/webprobe`) unless it asks for the default path explicitly.
//!
//! The CA is selected by injection (`Shared::with_ca_dir`), never by mutating
//! the process environment. Each case runs in a child process: this same,
//! current-build test binary re-executed with an isolated HOME/XDG and its own
//! sentinel `ca.json` at the default path, so no case can mask another.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MARKER: &str = "WP_F13_CHILD";
const ROOT_VAR: &str = "WP_F13_ROOT";
const CA_VAR: &str = "WP_F13_CA_DIR";
const CASE_VAR: &str = "WP_F13_CASE";
const NONCE_FILE: &str = ".f13-nonce";
const CHILD_DEADLINE: Duration = Duration::from_secs(120);

/// A directory this process created exclusively and removes on drop. It never
/// reuses a PID-derived name and never deletes a path it did not create.
struct OwnedDir(PathBuf);

impl OwnedDir {
    fn create(tag: &str, nonce: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{tag}-{nonce}"));
        fs::create_dir(&path).expect("exclusive temp directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for OwnedDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Owns a spawned child for its whole lifetime: dropping the guard kills and
/// reaps it, so an unwind or an early `?` can never leave the process running
/// while `OwnedDir` removes the files underneath it.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn(command: Command) -> Self {
        Self {
            child: Some(command.spawn().expect("spawn child fixture")),
        }
    }

    fn wait_deadline(&mut self, limit: Duration) -> std::io::Result<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            let polled = match self.child.as_mut() {
                Some(child) => child.try_wait()?,
                None => return Err(std::io::Error::other("child already reaped")),
            };
            match polled {
                Some(status) => {
                    self.child = None;
                    return Ok(status);
                }
                None if Instant::now() >= deadline => {
                    self.kill_and_reap();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "child fixture timed out",
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

fn nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("f13-{}-{nanos:x}", std::process::id())
}

/// Everything a change to `ca.json` could move, with errors propagated: a
/// failed stat must fail the test rather than read as "unchanged".
#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    modified: std::time::SystemTime,
    digest: u64,
    mode: u32,
}

fn fingerprint(path: &Path) -> std::io::Result<Fingerprint> {
    use std::hash::{Hash, Hasher};
    let meta = fs::metadata(path)?;
    let bytes = fs::read(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    Ok(Fingerprint {
        len: meta.len(),
        modified: meta.modified()?,
        digest: hasher.finish(),
        mode: mode_of(&meta),
    })
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
const CA_FILE_MODE: u32 = 0o600;
#[cfg(not(unix))]
const CA_FILE_MODE: u32 = 0;

/// Absolute and resolvable; `canonicalize` removes `.`/`..` and follows
/// symlinks, so containment below cannot be defeated lexically.
fn canonical(path: &Path, what: &str) -> PathBuf {
    assert!(path.is_absolute(), "{what} must be absolute");
    fs::canonicalize(path).unwrap_or_else(|e| panic!("{what} must resolve: {e}"))
}

fn require_within(path: &Path, root: &Path, what: &str) -> PathBuf {
    let resolved = canonical(path, what);
    let owned = canonical(root, "owned root");
    assert!(resolved != owned, "{what} must not be the owned root");
    assert!(
        resolved.starts_with(&owned),
        "{what} escapes the owned root"
    );
    resolved
}

/// The CA directory is validated by its resolved parent: it must be a direct
/// child of the owned root and must not exist yet.
fn validate_ca_dir(ca_dir: &Path, root: &Path) -> PathBuf {
    assert!(ca_dir.is_absolute(), "CA dir must be absolute");
    assert!(
        fs::metadata(ca_dir).is_err(),
        "CA dir must not pre-exist"
    );
    let name = ca_dir
        .file_name()
        .and_then(|f| f.to_str())
        .expect("CA dir has a plain name");
    assert!(
        !name.is_empty() && name != "." && name != "..",
        "CA dir name must be a plain component"
    );
    let parent = ca_dir.parent().expect("CA dir has a parent");
    assert_eq!(
        canonical(parent, "CA parent"),
        canonical(root, "owned root"),
        "CA dir must be a direct child of the owned root"
    );
    ca_dir.to_path_buf()
}

/// Each case gets its own owned root and sentinel. `root` is declared before
/// the child guard on purpose: locals drop in reverse order, so the child is
/// killed and reaped before `OwnedDir` removes anything.
#[test]
fn injected_ca_leaves_the_default_user_ca_alone() {
    for var in [MARKER, ROOT_VAR, CA_VAR, CASE_VAR] {
        assert!(
            std::env::var_os(var).is_none(),
            "ambient {var}: this run is not its own child, refusing to launch"
        );
    }

    let mut cases = 0usize;
    for case in ["override", "in_memory", "default"] {
        let nonce = nonce();
        let root = OwnedDir::create("wp-f13-case", &nonce);
        fs::write(root.path().join(NONCE_FILE), &nonce).expect("nonce file");
        let home = root.path().join("home");
        let xdg = home.join(".config");
        let sentinel = xdg.join("webprobe").join("ca.json");
        let ca_dir = root.path().join("ca");
        fs::create_dir_all(sentinel.parent().unwrap()).expect("sentinel dir");
        fs::write(&sentinel, b"F13-SENTINEL-NOT-A-CA").expect("sentinel");
        let before = fingerprint(&sentinel).expect("sentinel fingerprint before");

        let out_path = root.path().join("child.out");
        let err_path = root.path().join("child.err");
        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        command
            .arg("--exact")
            .arg("child_case")
            .arg("--nocapture")
            .env_remove(MARKER)
            .env_remove(ROOT_VAR)
            .env_remove(CA_VAR)
            .env_remove(CASE_VAR)
            .env_remove("WEBPROBE_CA_DIR")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg)
            .env(MARKER, &nonce)
            .env(ROOT_VAR, root.path())
            .env(CA_VAR, &ca_dir)
            .env(CASE_VAR, case)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                fs::File::create(&out_path).expect("child stdout"),
            ))
            .stderr(Stdio::from(
                fs::File::create(&err_path).expect("child stderr"),
            ));
        let mut child = ChildGuard::spawn(command);

        let status = child
            .wait_deadline(CHILD_DEADLINE)
            .expect("child fixture must finish");
        let stdout = fs::read_to_string(&out_path).unwrap_or_default();
        let stderr = fs::read_to_string(&err_path).unwrap_or_default();
        assert!(
            status.success(),
            "child case {case} failed ({status}):\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("test result: ok. 1 passed"),
            "child case {case} did not run exactly one case:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("F13_CHILD_OK case={case}")),
            "child case {case} did not report completion:\n{stdout}"
        );

        let after = fingerprint(&sentinel).expect("sentinel fingerprint after");
        match case {
            "override" => {
                assert_eq!(after, before, "override case wrote the default user CA");
                let ca_file = ca_dir.join("ca.json");
                let injected = fingerprint(&ca_file).expect("injected CA file");
                assert_eq!(
                    injected.mode, CA_FILE_MODE,
                    "injected CA file must stay owner-only"
                );
            }
            "in_memory" => {
                assert_eq!(after, before, "in-memory case wrote the default user CA");
                assert!(
                    fs::metadata(&ca_dir).is_err(),
                    "in-memory case created a CA directory"
                );
            }
            _ => {
                // Probe, not a guarantee: in an integration binary `Shared::new()`
                // compiles the lib without cfg(test), so it still resolves the
                // default path. The child records which happened.
                assert!(
                    stdout.contains("default_path_written="),
                    "default case did not report its observation:\n{stdout}"
                );
            }
        }
        cases += 1;
        // `child` (declared after `root`) is reaped here before `root` drops.
    }
    assert_eq!(cases, 3, "case count");
}

/// Runs only in the child process started above. Any ambient or inconsistent
/// marker is rejected before a CA is constructed.
#[test]
fn child_case() {
    let Ok(marker) = std::env::var(MARKER) else {
        return;
    };
    assert!(marker.starts_with("f13-"), "inherited marker rejected");
    let root = PathBuf::from(std::env::var_os(ROOT_VAR).expect("child root"));
    let case = std::env::var(CASE_VAR).expect("child case");
    let ca_dir = PathBuf::from(std::env::var_os(CA_VAR).expect("child ca dir"));
    let home = PathBuf::from(std::env::var_os("HOME").expect("child HOME"));
    let xdg = PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").expect("child XDG_CONFIG_HOME"));

    // Ownership proof: only the parent can have written this file, so an
    // inherited marker alone can never reach a CA construction.
    let recorded = fs::read_to_string(root.join(NONCE_FILE))
        .expect("nonce file proves the parent owns this run");
    assert_eq!(recorded.trim(), marker.as_str(), "nonce file must match the marker");

    // Canonical containment of every injected path, before any CA work.
    canonical(&root, "owned root");
    let resolved_home = require_within(&home, &root, "HOME");
    let resolved_xdg = require_within(&xdg, &root, "XDG_CONFIG_HOME");
    assert!(
        resolved_xdg.starts_with(&resolved_home),
        "XDG_CONFIG_HOME must live under HOME"
    );
    let ca_dir = validate_ca_dir(&ca_dir, &root);

    match case.as_str() {
        "override" => {
            let shared =
                webprobe_core::net::Shared::with_ca_dir(Some(ca_dir)).expect("injected CA dir");
            assert!(shared.mitm.server_config("f13.test").is_ok());
        }
        "in_memory" => {
            let shared = webprobe_core::net::Shared::with_ca_dir(None).expect("in-memory CA");
            assert!(shared.mitm.server_config("f13.test").is_ok());
        }
        "default" => {
            let shared = webprobe_core::net::Shared::new();
            assert!(shared.mitm.server_config("f13.test").is_ok());
            let written = fs::metadata(resolved_xdg.join("webprobe").join("ca.json")).is_ok();
            println!(
                "default_path_written={}",
                if written { "yes" } else { "no" }
            );
        }
        other => panic!("unknown case {other}"),
    }
    println!("F13_CHILD_OK case={case}");
}

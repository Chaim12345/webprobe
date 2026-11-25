//! AR-01/F13 negative fixture: a test run must never read or create the real
//! user CA (`$WEBPROBE_CA_DIR`, else `$XDG_CONFIG_HOME/webprobe`, else
//! `~/.config/webprobe`).
//!
//! The CA is selected by explicit injection (`Shared::with_ca_dir`), never by
//! mutating the process environment. The check runs in a child process: this
//! same, current-build test binary re-executed with an isolated HOME/XDG and a
//! sentinel `ca.json` at the default path. Only length/mtime/digest metadata is
//! compared - CA content is never read into output.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MARKER: &str = "WP_F13_CHILD";
const ROOT_VAR: &str = "WP_F13_ROOT";
const CA_VAR: &str = "WP_F13_CA_DIR";
const OK_LINE: &str = "F13_CHILD_OK cases=2";

/// A directory this process created exclusively and removes on drop. It never
/// reuses a PID-derived name and never deletes a path it did not create.
struct OwnedDir(PathBuf);

impl OwnedDir {
    fn create(tag: &str, nonce: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{tag}-{nonce}"));
        std::fs::create_dir(&path).expect("exclusive temp directory");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for OwnedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("f13-{}-{nanos:x}", std::process::id())
}

/// Length, modified time and a non-cryptographic digest: enough to prove the
/// file is untouched without ever printing CA content.
fn fingerprint(p: &Path) -> (u64, Option<std::time::SystemTime>) {
    use std::hash::{Hash, Hasher};
    let bytes = std::fs::read(p).expect("sentinel readable");
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    (
        h.finish(),
        std::fs::metadata(p).ok().and_then(|m| m.modified().ok()),
    )
}

#[test]
fn explicit_ca_injection_leaves_the_default_user_ca_untouched() {
    let nonce = nonce();
    let root = OwnedDir::create("wp-f13-case", &nonce);
    let home = root.path().join("home");
    let xdg = home.join(".config");
    let sentinel = xdg.join("webprobe").join("ca.json");
    let ca_dir = root.path().join("ca");
    std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
    std::fs::write(&sentinel, b"F13-SENTINEL-NOT-A-CA").unwrap();
    let before = fingerprint(&sentinel);

    let out_path = root.path().join("child.out");
    let err_path = root.path().join("child.err");
    let out = std::fs::File::create(&out_path).unwrap();
    let err = std::fs::File::create(&err_path).unwrap();

    // The exact binary that is running now: deterministic, never a scan of the
    // profile tree, and a missing fixture fails instead of skipping.
    let exe = std::env::current_exe().expect("current test binary");
    let mut child = Command::new(&exe)
        .arg("--exact")
        .arg("child_injects_explicit_ca_dir")
        .arg("--nocapture")
        .env_remove(MARKER)
        .env_remove(ROOT_VAR)
        .env_remove(CA_VAR)
        .env_remove("WEBPROBE_CA_DIR")
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env(MARKER, &nonce)
        .env(ROOT_VAR, root.path())
        .env(CA_VAR, &ca_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn child fixture");

    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        match child.try_wait().expect("poll child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child fixture timed out after 120s");
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let stdout = std::fs::read_to_string(&out_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
    assert!(
        status.success(),
        "child fixture failed ({status}):\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "child did not run exactly one case:\n{stdout}"
    );
    let cases: usize = stdout
        .split("cases=")
        .nth(1)
        .and_then(|t| t.split_whitespace().next())
        .and_then(|t| t.parse().ok())
        .expect("child reports its case count");
    assert_eq!(cases, 2, "child case count");

    assert_eq!(
        fingerprint(&sentinel),
        before,
        "a test run wrote the default user CA sentinel"
    );
    let created = ca_dir.join("ca.json");
    assert!(created.exists(), "the injected CA dir receives the CA");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "CA key file stays owner-only");
    }
}

/// Runs only in the child process started above. Any inherited or inconsistent
/// marker is rejected before a CA is constructed.
#[test]
fn child_injects_explicit_ca_dir() {
    let Ok(marker) = std::env::var(MARKER) else {
        return;
    };
    assert!(marker.starts_with("f13-"), "inherited marker rejected");
    let root = PathBuf::from(std::env::var_os(ROOT_VAR).expect("child root"));
    let ca_dir = PathBuf::from(std::env::var_os(CA_VAR).expect("child ca dir"));
    assert!(root.is_dir(), "owned root must exist");
    assert!(
        root.file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.contains(&marker)),
        "owned root must carry the marker"
    );
    assert!(
        ca_dir.starts_with(&root),
        "CA dir must live inside the owned root"
    );
    assert!(!ca_dir.exists(), "CA dir must not pre-exist");

    let injected = webprobe_core::net::Shared::with_ca_dir(Some(ca_dir)).expect("injected CA dir");
    assert!(injected.mitm.server_config("f13.test").is_ok());
    let in_memory = webprobe_core::net::Shared::with_ca_dir(None).expect("in-memory CA");
    assert!(in_memory.mitm.server_config("f13.test").is_ok());
    println!("{OK_LINE}");
}

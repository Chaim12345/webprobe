//! AR-01/F13 negative fixture: a test run must never read or create the real
//! user CA (`$WEBPROBE_CA_DIR`, else `$XDG_CONFIG_HOME/webprobe`, else
//! `~/.config/webprobe`).
//!
//! Checks run in child processes with an isolated HOME/XDG and a sentinel
//! `ca.json` at the default path, and inspect only path/existence/mtime/hash/
//! permission metadata - never certificate or key content.

use std::path::{Path, PathBuf};
use std::process::Command;

fn sentinel(root: &Path) -> PathBuf {
    let p = root.join("home/.config/webprobe/ca.json");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"F13-SENTINEL-NOT-A-CA").unwrap();
    p
}

/// Length, modified time and a non-cryptographic digest: enough to prove the
/// file is untouched without ever printing CA content.
fn fingerprint(p: &Path) -> (u64, Option<std::time::SystemTime>) {
    use std::hash::{Hash, Hasher};
    let bytes = std::fs::read(p).unwrap();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    (
        h.finish(),
        std::fs::metadata(p).ok().and_then(|m| m.modified().ok()),
    )
}

/// A sibling test binary built by the same `cargo test` invocation. Cargo may
/// place it in a different fingerprint directory, so search the profile tree
/// (`<target>/debug`) a bounded depth for it.
fn sibling_test_binary(name: &str) -> Option<PathBuf> {
    let prefix = format!("{}-", name.replace('-', "_"));
    let mut dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    loop {
        let is_profile = dir
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f == "debug" || f == "release");
        if is_profile {
            break;
        }
        if !dir.pop() {
            return None;
        }
    }
    fn walk(dir: &Path, prefix: &str, depth: u8) -> Option<PathBuf> {
        for entry in std::fs::read_dir(dir).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if depth > 0
                    && let Some(found) = walk(&path, prefix, depth - 1)
                {
                    return Some(found);
                }
            } else if let Some(file) = path.file_name().and_then(|f| f.to_str())
                && file.starts_with(prefix)
                && !file.contains('.')
            {
                return Some(path);
            }
        }
        None
    }
    walk(&dir, &prefix, 4)
}

/// A real integration binary must leave the default user CA untouched when the
/// only isolation is HOME/XDG: it has to route its CA through an explicit
/// `WEBPROBE_CA_DIR`.
#[test]
fn integration_test_binary_leaves_the_default_user_ca_untouched() {
    let Some(bin) = sibling_test_binary("session_contracts") else {
        eprintln!("session_contracts binary not built in this invocation; skipped");
        return;
    };
    let root = std::env::temp_dir().join(format!("wp-f13-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let sentinel = sentinel(&root);
    let before = fingerprint(&sentinel);

    let out = Command::new(&bin)
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env_remove("WEBPROBE_CA_DIR")
        .output()
        .expect("run session_contracts");
    assert!(
        out.status.success(),
        "sibling suite failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fingerprint(&sentinel),
        before,
        "a test run wrote the default user CA sentinel"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `WEBPROBE_CA_DIR` is honored: with it set, the CA lands there (0600) and the
/// default-path sentinel stays byte-identical.
#[test]
fn explicit_ca_dir_is_honored_and_default_sentinel_untouched() {
    let root = std::env::temp_dir().join(format!("wp-f13-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let sentinel = sentinel(&root);
    let ca_dir = root.join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    let before = fingerprint(&sentinel);

    let out = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("child_loads_ca")
        .arg("--nocapture")
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("WEBPROBE_CA_DIR", &ca_dir)
        .env("WP_F13_CHILD", "1")
        .output()
        .expect("child run");
    assert!(
        out.status.success(),
        "child failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fingerprint(&sentinel), before, "sentinel must not change");
    let created = ca_dir.join("ca.json");
    assert!(created.exists(), "the explicit CA dir receives the CA");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "CA key file stays owner-only");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Loads the CA in the child process started above.
#[test]
fn child_loads_ca() {
    if std::env::var_os("WP_F13_CHILD").is_none() {
        return;
    }
    let shared = webprobe_core::net::Shared::new();
    assert!(shared.mitm.server_config("f13.test").is_ok());
}

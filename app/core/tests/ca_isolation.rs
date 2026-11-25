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
        restrict_to_owner(&path);
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
    fn spawn(mut command: Command) -> Self {
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

/// Any ambient f13 marker - a `WP_F13_*` key or an `f13-` value - means this
/// process is not the child of this run, so nothing may be launched from it.
fn ambient_marker() -> Option<String> {
    std::env::vars_os().find_map(|(key, value)| {
        let key = key.to_string_lossy().into_owned();
        if key.starts_with("WP_F13_") {
            return Some(key);
        }
        value
            .to_string_lossy()
            .starts_with("f13-")
            .then(|| format!("value of {key}"))
    })
}

/// The `WP_F13_*` keys this process actually carries, sorted.
fn f13_keys() -> Vec<String> {
    let mut keys: Vec<String> = std::env::vars_os()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .filter(|key| key.starts_with("WP_F13_"))
        .collect();
    keys.sort();
    keys
}

/// The private root is created owner-only, not with inherited permissions.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory mode");
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) {}

#[cfg(unix)]
fn is_private_dir(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|meta| meta.is_dir() && meta.permissions().mode() & 0o077 == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_private_dir(path: &Path) -> bool {
    path.is_dir()
}

/// `f13-<pid>-<hex nanos>`: the shape the parent produces.
fn nonce_is_well_formed(marker: &str) -> bool {
    match marker.split('-').collect::<Vec<_>>().as_slice() {
        ["f13", pid, hex] => {
            !pid.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && !hex.is_empty()
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// The child must be the exact launch this fixture makes: no extra arguments
/// and no other test filter.
fn assert_child_launch_shape() {
    let args: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        args.len(),
        4,
        "child must be launched as --exact child_case --nocapture"
    );
    assert_eq!(args[1], "--exact");
    assert_eq!(args[2], "child_case");
    assert_eq!(args[3], "--nocapture");
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

/// The CA path is rebuilt from the resolved owned root plus a fixed child name,
/// never from the caller's lexical path. Absence must be `NotFound`
/// specifically: a symlink or any other error is rejected, so a pre-existing
/// link cannot redirect where the CA is written.
fn validate_ca_dir(owned_root: &Path, name: &str) -> PathBuf {
    assert!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "CA child name must be a plain component"
    );
    let candidate = owned_root.join(name);
    match fs::symlink_metadata(&candidate) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("CA path must be absent: {error}"),
        Ok(meta) => panic!(
            "CA path must not pre-exist (symlink: {})",
            meta.file_type().is_symlink()
        ),
    }
    candidate
}

/// Each case gets its own owned root and sentinel. `root` is declared before
/// the child guard on purpose: locals drop in reverse order, so the child is
/// killed and reaped before `OwnedDir` removes anything.
#[test]
fn injected_ca_leaves_the_default_user_ca_alone() {
    if let Some(marker) = ambient_marker() {
        panic!("ambient f13 marker ({marker}): this run is not its own child, refusing to launch");
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
                // default path. Only a before/after change counts as a write;
                // the pre-created sentinel makes existence meaningless.
                assert!(
                    stdout.contains("default_path=changed")
                        || stdout.contains("default_path=unchanged"),
                    "default case did not report a before/after comparison:\n{stdout}"
                );
            }
        }
        // Reap explicitly before the owned root goes away instead of relying on
        // drop order alone; `kill_and_reap` is a no-op once the child is reaped.
        child.kill_and_reap();
        drop(root);
        cases += 1;
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
    assert_child_launch_shape();
    assert!(
        nonce_is_well_formed(&marker),
        "malformed marker rejected: {marker}"
    );
    let mut expected = vec![
        CA_VAR.to_string(),
        CASE_VAR.to_string(),
        MARKER.to_string(),
        ROOT_VAR.to_string(),
    ];
    expected.sort();
    assert_eq!(
        f13_keys(),
        expected,
        "unexpected ambient WP_F13_* marker in the child"
    );

    let root = PathBuf::from(std::env::var_os(ROOT_VAR).expect("child root"));
    let case = std::env::var(CASE_VAR).expect("child case");
    let ca_var = PathBuf::from(std::env::var_os(CA_VAR).expect("child ca dir"));
    let home = PathBuf::from(std::env::var_os("HOME").expect("child HOME"));
    let xdg = PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").expect("child XDG_CONFIG_HOME"));

    // Ambient-state protection, not authentication: a matching nonce file shows
    // this process was launched with the parent's inputs. A process that can
    // write the root and set every variable itself can forge all of this.
    let recorded = fs::read_to_string(root.join(NONCE_FILE))
        .expect("nonce file must match the parent's run");
    assert_eq!(
        recorded.trim(),
        marker.as_str(),
        "nonce file must match the marker"
    );

    // Exact owned layout, resolved, before any CA work.
    let owned = canonical(&root, "owned root");
    assert_eq!(
        owned.parent(),
        Some(canonical(&std::env::temp_dir(), "temp dir").as_path()),
        "owned root must be a direct child of the temp directory"
    );
    assert!(is_private_dir(&owned), "owned root must be owner-only");
    let resolved_home = canonical(&home, "HOME");
    let resolved_xdg = canonical(&xdg, "XDG_CONFIG_HOME");
    assert_eq!(resolved_home, owned.join("home"), "HOME must be <root>/home");
    assert_eq!(
        resolved_xdg,
        resolved_home.join(".config"),
        "XDG_CONFIG_HOME must be <root>/home/.config"
    );
    let ca_dir = validate_ca_dir(&owned, "ca");
    assert_eq!(
        canonical(ca_var.parent().expect("CA parent"), "CA parent"),
        owned,
        "CA dir must be a direct child of the owned root"
    );
    assert_eq!(
        ca_var.file_name().and_then(|f| f.to_str()),
        Some("ca"),
        "CA dir must be named ca"
    );

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
            // Paired before/after on the same file: the parent pre-creates the
            // sentinel, so existence alone would not show a write.
            let default_ca = resolved_xdg.join("webprobe").join("ca.json");
            let before = fingerprint(&default_ca).expect("default-path fingerprint before");
            let shared = webprobe_core::net::Shared::new();
            assert!(shared.mitm.server_config("f13.test").is_ok());
            let after = fingerprint(&default_ca).expect("default-path fingerprint after");
            println!(
                "default_path={}",
                if after == before { "unchanged" } else { "changed" }
            );
        }
        other => panic!("unknown case {other}"),
    }
    println!("F13_CHILD_OK case={case}");
}

//! Advisory OS-backed locks for project writers.
//!
//! The sidecar is intentionally persistent: unlinking it while another
//! process is waiting would allow two processes to lock different inodes.
//! Locks cover the canonicalized parent plus filename, matching save's
//! rename semantics even when the project path itself is a symlink.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

pub struct ProjectLock {
    _file: File,
    sidecar: PathBuf,
}

fn sidecar_path(project: &Path) -> std::io::Result<PathBuf> {
    let name = project.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "project path has no file name",
        )
    })?;
    let parent = project
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let parent = std::fs::canonicalize(parent)?;
    let mut lock_name = std::ffi::OsString::from(".");
    lock_name.push(name);
    lock_name.push(".lock");
    Ok(parent.join(lock_name))
}

impl ProjectLock {
    pub fn acquire(project: &Path) -> std::io::Result<Self> {
        let sidecar = sidecar_path(project)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&sidecar)?;
        file.try_lock().map_err(|e| {
            std::io::Error::other(format!("project is already open or cannot be locked: {e}"))
        })?;
        Ok(Self {
            _file: file,
            sidecar,
        })
    }

    pub fn matches(&self, project: &Path) -> bool {
        sidecar_path(project).is_ok_and(|sidecar| sidecar == self.sidecar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "webprobe-lock-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ))
            .join("project.json")
    }

    #[test]
    fn locks_are_exclusive_and_released_on_drop() {
        let path = project();
        let first = ProjectLock::acquire(&path).unwrap();
        assert!(first.matches(&path));
        assert!(ProjectLock::acquire(&path).is_err());
        drop(first);
        assert!(ProjectLock::acquire(&path).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn child_lock_probe() {
        let Some(path) = std::env::var_os("WEBPROBE_LOCK_TEST_PATH") else {
            return;
        };
        let expected = std::env::var("WEBPROBE_LOCK_TEST_EXPECT").unwrap();
        assert_eq!(
            ProjectLock::acquire(Path::new(&path)).is_ok(),
            expected == "free"
        );
    }

    #[test]
    fn another_process_cannot_lock_until_the_first_writer_exits() {
        let path = project();
        let first = ProjectLock::acquire(&path).unwrap();
        let probe = |expected: &str| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("child_lock_probe")
                .env("WEBPROBE_LOCK_TEST_PATH", &path)
                .env("WEBPROBE_LOCK_TEST_EXPECT", expected)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        };
        probe("busy");
        drop(first);
        probe("free");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn lock_failure_does_not_allow_a_save() {
        let parent = project();
        std::fs::create_dir_all(parent.parent().unwrap()).unwrap();
        std::fs::write(&parent, b"not a directory").unwrap();
        assert!(ProjectLock::acquire(&parent.join("project.json")).is_err());
        let _ = std::fs::remove_dir_all(parent.parent().unwrap());
    }
}

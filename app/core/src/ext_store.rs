//! Installed extensions, remembered across runs like Burp's extension list
//! (user-level, not per project): what to load, in order, and whether it is
//! enabled. Loading happens on a background thread so a slow JVM or a
//! misbehaving extension never stalls start-up or the UI.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ext_host::LoadedExtension;
use crate::net::Shared;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A Montoya .jar run by the sidecar JVM.
    Java,
    /// A WebProbe API v1 executable (ext_process).
    Process,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Java => "Java",
            Kind::Process => "Process",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    pub kind: Kind,
    /// The .jar path (Java) or the command line (Process).
    pub source: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

/// Per-call deadline for process extensions.
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(2);

pub fn store_file() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("WEBPROBE_CONFIG_DIR") {
        return Some(PathBuf::from(d).join("extensions.json"));
    }
    crate::tls::default_ca_dir().map(|d| d.join("extensions.json"))
}

pub fn load() -> Vec<Installed> {
    store_file().map(|f| load_from(&f)).unwrap_or_default()
}

pub fn save(list: &[Installed]) -> Result<(), String> {
    save_to(&store_file().ok_or("no config directory")?, list)
}

pub fn load_from(f: &std::path::Path) -> Vec<Installed> {
    std::fs::read(f).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save_to(f: &std::path::Path, list: &[Installed]) -> Result<(), String> {
    if let Some(d) = f.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(list).map_err(|e| e.to_string())?;
    std::fs::write(f, json).map_err(|e| format!("{}: {e}", f.display()))
}

/// Split a command line into words: whitespace separates, single or double
/// quotes group, a backslash escapes the next character outside single quotes.
pub fn split_command(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('\''), c) => cur.push(c),
            (_, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                has = true;
            }
            (None, '\'' | '"') => {
                quote = Some(c);
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                has = false;
            }
            (_, c) => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Extensions run in the temp directory, so words of the command that name
/// an existing file relative to WebProbe's working directory (a script
/// path, `./run`) are made absolute first; everything else is left alone.
pub fn absolutize(words: Vec<String>) -> Vec<String> {
    words
        .into_iter()
        .map(|w| {
            let p = std::path::Path::new(&w);
            if !w.is_empty() && p.is_relative() && (w.contains('/') || w.contains('\\') || p.extension().is_some()) && p.exists() {
                std::fs::canonicalize(p).map(|a| a.to_string_lossy().into_owned()).unwrap_or(w)
            } else {
                w
            }
        })
        .collect()
}

/// Start one extension (blocking: JVM start-up or the process's register).
pub fn start(item: &Installed) -> Result<LoadedExtension, String> {
    let mut loaded = match item.kind {
        Kind::Java => LoadedExtension::new(crate::ext_host::JavaSidecar::spawn(item.source.trim())?),
        Kind::Process => {
            let words = absolutize(split_command(&item.source));
            let (program, args) = words.split_first().ok_or("empty command")?;
            LoadedExtension::new(crate::ext_process::ProcessExtension::spawn(program, args, HOOK_TIMEOUT)?)
        }
    };
    loaded.enabled = item.enabled;
    loaded.source = Some(item.clone());
    Ok(loaded)
}

/// Load an extension in the background and append it to the host; the
/// outcome goes to the event log, and `done` is called with it.
pub fn start_in_background(shared: &Arc<Shared>, item: Installed, done: impl FnOnce(Result<String, String>) + Send + 'static) {
    let shared = Arc::clone(shared);
    std::thread::spawn(move || {
        let result = start(&item).map(|ext| {
            let name = ext.hooks.extension_name().to_string();
            shared.ext_host.lock().unwrap().extensions.push(ext);
            name
        });
        match &result {
            Ok(name) => shared.log(&format!("Extension loaded: {name} ({} {})", item.kind.label(), item.source)),
            Err(e) => shared.log(&format!("Extension failed to load ({} {}): {e}", item.kind.label(), item.source)),
        }
        shared.wake();
        done(result);
    });
}

/// The host's extensions that came from the store, in host order, with
/// their current enabled state (what `save` should write).
pub fn current(shared: &Shared) -> Vec<Installed> {
    shared
        .ext_host
        .lock()
        .unwrap()
        .extensions
        .iter()
        .filter_map(|e| e.source.clone().map(|s| Installed { enabled: e.enabled, ..s }))
        .collect()
}

/// Load every remembered extension, one after another, in order.
pub fn load_all(shared: &Arc<Shared>) {
    let list = load();
    if list.is_empty() {
        return;
    }
    let shared = Arc::clone(shared);
    std::thread::spawn(move || {
        for item in list {
            match start(&item) {
                Ok(ext) => {
                    shared.log(&format!("Extension loaded: {} ({} {})", ext.hooks.extension_name(), item.kind.label(), item.source));
                    shared.ext_host.lock().unwrap().extensions.push(ext);
                }
                // Kept in the list: a failed load is reported, not forgotten.
                Err(e) => shared.log(&format!("Extension failed to load ({} {}): {e}", item.kind.label(), item.source)),
            }
            shared.wake();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_split_like_a_shell() {
        assert_eq!(split_command("python3 -I ext.py"), ["python3", "-I", "ext.py"]);
        assert_eq!(split_command(r#"  "/opt/My Ext/run" --name 'a b' x\ y "" "#), ["/opt/My Ext/run", "--name", "a b", "x y", ""]);
        assert!(split_command("   ").is_empty());
    }

    #[test]
    fn relative_script_paths_are_made_absolute() {
        // Tests run in the crate dir; the example lives one level up.
        let w = absolutize(split_command("python3 -I ../extensions/examples/marker_reflection.py --x 1"));
        assert_eq!(&w[..2], ["python3", "-I"], "a program name on PATH is left alone");
        assert!(std::path::Path::new(&w[2]).is_absolute() && w[2].ends_with("marker_reflection.py"), "{w:?}");
        assert_eq!(&w[3..], ["--x", "1"]);
    }

    #[test]
    fn list_round_trips_through_the_config_dir() {
        let dir = std::env::temp_dir().join(format!("wp-ext-store-{}", std::process::id()));
        let file = dir.join("extensions.json");
        let list = vec![
            Installed { kind: Kind::Process, source: "python3 -I a.py".into(), enabled: true },
            Installed { kind: Kind::Java, source: "/x/b.jar".into(), enabled: false },
        ];
        save_to(&file, &list).unwrap();
        assert_eq!(load_from(&file), list);
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("\"kind\": \"process\""), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

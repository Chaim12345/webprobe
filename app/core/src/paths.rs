//! Where external resources come from (R-02). One place decides, so a
//! release binary on another machine never looks in a developer's tree:
//!
//! 1. an explicit override (an environment variable naming the file or
//!    directory);
//! 2. a Burp `resources/` directory the user extracted from burpsuite.jar
//!    (`WEBPROBE_BURP_RESOURCES`), for PortSwigger's own files;
//! 3. documented defaults: `~/.config/webprobe/…`, WebProbe's data
//!    directory, and the usual Burp install locations.
//!
//! Each lookup returns either the path or a [`Missing`] that says what is
//! missing, where it was looked for and how to provide it; the feature that
//! needs it shows that message (toast, tab note, stderr). PortSwigger's
//! files (issue texts, wordlists, the RetireJS repository, the jar) are never
//! bundled. WebProbe's own files (the Montoya bridge source, the extension
//! catalogue and its examples) are embedded and written out when needed.

use std::fmt;
use std::path::{Path, PathBuf};

/// A resource that could not be found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    /// What is missing, in a phrase.
    pub what: &'static str,
    /// Every place that was tried, in order.
    pub looked: Vec<PathBuf>,
    /// How to provide it.
    pub how: &'static str,
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let looked: Vec<String> = self.looked.iter().map(|p| p.display().to_string()).collect();
        write!(f, "{} not found (looked in: {}). {}", self.what, if looked.is_empty() { "nowhere".into() } else { looked.join(", ") }, self.how)
    }
}

impl std::error::Error for Missing {}


/// Where lookups read their settings from: the process environment, or a
/// fixed map in tests (so tests never touch the process-wide environment).
pub struct Lookup {
    vars: Option<std::collections::HashMap<String, std::ffi::OsString>>,
    /// Also try the fixed system locations (Burp install directories,
    /// /usr/bin/chromium, the directory of the running binary).
    system: bool,
}

impl Lookup {
    /// The real environment and system locations.
    pub fn process() -> Lookup {
        Lookup { vars: None, system: true }
    }

    /// Only these variables, no system locations.
    pub fn with_vars<'a>(vars: impl IntoIterator<Item = (&'a str, PathBuf)>) -> Lookup {
        Lookup { vars: Some(vars.into_iter().map(|(k, v)| (k.to_string(), v.into_os_string())).collect()), system: false }
    }

    fn var(&self, name: &str) -> Option<PathBuf> {
        let v = match &self.vars {
            Some(m) => m.get(name).cloned(),
            None => std::env::var_os(name),
        };
        v.filter(|v| !v.is_empty()).map(PathBuf::from)
    }

    fn home(&self) -> Option<PathBuf> {
        self.var("HOME")
    }

    /// `~/.config/webprobe` (or `$XDG_CONFIG_HOME/webprobe`).
    pub fn config_dir(&self) -> Option<PathBuf> {
        self.var("XDG_CONFIG_HOME").or_else(|| self.home().map(|h| h.join(".config"))).map(|d| d.join("webprobe"))
    }

    /// Where WebProbe writes out its own embedded files: `$WEBPROBE_DATA_DIR`,
    /// else `$XDG_DATA_HOME/webprobe`, else `~/.local/share/webprobe`, else
    /// the temp directory.
    pub fn data_dir(&self) -> PathBuf {
        self.var("WEBPROBE_DATA_DIR")
            .or_else(|| self.var("XDG_DATA_HOME").map(|d| d.join("webprobe")))
            .or_else(|| self.home().map(|h| h.join(".local/share/webprobe")))
            .unwrap_or_else(|| std::env::temp_dir().join("webprobe"))
    }

    /// `$WEBPROBE_BURP_HOME`, then the usual Burp installation directories.
    fn burp_install_dirs(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.var("WEBPROBE_BURP_HOME").into_iter().collect();
        if self.system {
            v.extend(["/opt/BurpSuite", "/opt/BurpSuitePro", "/opt/BurpSuiteCommunity"].iter().map(PathBuf::from));
            if let Some(h) = self.home() {
                v.extend(["BurpSuitePro", "BurpSuiteCommunity", "BurpSuite"].iter().map(|d| h.join(d)));
            }
        }
        v
    }

    /// The candidates for one PortSwigger resource: its own override `var`,
    /// `<WEBPROBE_BURP_RESOURCES>/<sub>`, `~/.config/webprobe/<sub>` and
    /// `<data dir>/<sub>`.
    fn burp_resource_candidates(&self, var: &str, sub: &str) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.var(var).into_iter().collect();
        if let Some(r) = self.var("WEBPROBE_BURP_RESOURCES") {
            v.push(r.join(sub));
        }
        if let Some(c) = self.config_dir() {
            v.push(c.join(sub));
        }
        v.push(self.data_dir().join(sub));
        v
    }

    /// Burp's issue definitions (`KnowledgeBase/Issues/*.json`), used for the
    /// background and remediation sections of reports.
    pub fn knowledge_base(&self) -> Result<PathBuf, Missing> {
        let looked = self.burp_resource_candidates("WEBPROBE_KB_DIR", "KnowledgeBase/Issues");
        first_dir_with(&looked, |d| has_ext(d, "json")).ok_or(Missing {
            what: "Burp's issue descriptions (KnowledgeBase/Issues/*.json)",
            looked,
            how: "Report backgrounds and remediation are omitted. Extract resources/ from your burpsuite.jar and set WEBPROBE_BURP_RESOURCES to it, or set WEBPROBE_KB_DIR to the Issues directory.",
        })
    }

    /// Burp's wordlists (`PayloadStrings/*.pay`), used by content discovery.
    pub fn payload_strings(&self) -> Result<PathBuf, Missing> {
        let looked = self.burp_resource_candidates("WEBPROBE_WORDLIST_DIR", "PayloadStrings");
        first_dir_with(&looked, |d| has_ext(d, "pay")).ok_or(Missing {
            what: "Burp's wordlists (PayloadStrings/*.pay)",
            looked,
            how: "Content discovery uses its small built-in lists. Extract resources/ from your burpsuite.jar and set WEBPROBE_BURP_RESOURCES, or set WEBPROBE_WORDLIST_DIR to a directory of .pay files.",
        })
    }

    /// A retire.js vulnerability repository: `$WEBPROBE_RETIREJS`, then
    /// Burp's `RetireJS/retirejs_repository.json` or retire.js's own
    /// `jsrepository.json` in the resource directories.
    pub fn retirejs_repository(&self) -> Result<PathBuf, Missing> {
        let mut looked: Vec<PathBuf> = self.var("WEBPROBE_RETIREJS").into_iter().collect();
        for dir in self.burp_resource_candidates("WEBPROBE_RETIREJS_DIR", "RetireJS") {
            looked.push(dir.join("retirejs_repository.json"));
            looked.push(dir.join("jsrepository.json"));
        }
        looked.iter().find(|p| p.is_file()).cloned().ok_or(Missing {
            what: "a retire.js repository (retirejs_repository.json or jsrepository.json)",
            looked,
            how: "\"Vulnerable JavaScript dependency\" is not checked. Set WEBPROBE_RETIREJS to a retire.js jsrepository.json, or extract resources/ from your burpsuite.jar and set WEBPROBE_BURP_RESOURCES.",
        })
    }

    /// A jar with the Montoya API classes for the Java extension sidecar:
    /// `$WEBPROBE_BURP_JAR`, `~/.config/webprobe/montoya-api.jar`, the
    /// newest `net.portswigger.burp.extensions:montoya-api` in the local
    /// Maven repository (`~/.m2`), then a Burp installation. WebProbe does
    /// not ship the API: its POM names the Burp Suite Professional Licence
    /// Agreement, not an open licence.
    pub fn montoya_jar(&self) -> Result<PathBuf, Missing> {
        let mut looked: Vec<PathBuf> = self.var("WEBPROBE_BURP_JAR").into_iter().collect();
        if let Some(c) = self.config_dir() {
            looked.push(c.join("montoya-api.jar"));
        }
        if let Some(h) = self.home() {
            let repo = h.join(".m2/repository/net/portswigger/burp/extensions/montoya-api");
            let mut versions: Vec<PathBuf> = std::fs::read_dir(&repo).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect()).unwrap_or_default();
            // Newest first ("2026.4" after "2025.12": compare numerically).
            let key = |p: &PathBuf| p.file_name().map(|n| n.to_string_lossy().split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>()).unwrap_or_default();
            versions.sort_by_key(|p| std::cmp::Reverse(key(p)));
            for v in versions {
                let name = v.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                looked.push(v.join(format!("montoya-api-{name}.jar")));
            }
        }
        for d in self.burp_install_dirs() {
            looked.push(d.join("burpsuite.jar"));
            looked.push(d.join("burpsuite_pro.jar"));
            looked.push(d.join("burpsuite_community.jar"));
        }
        looked.iter().find(|p| p.is_file()).cloned().ok_or(Missing {
            what: "a jar with the Montoya API (burpsuite.jar or montoya-api.jar)",
            looked,
            how: "Java (Montoya) extensions cannot load. Set WEBPROBE_BURP_JAR to burpsuite.jar or to montoya-api.jar from Maven Central (net.portswigger.burp.extensions:montoya-api).",
        })
    }

    /// Directories holding Burp's bundled Chromium (`burpbrowser/<version>/chrome`),
    /// `$WEBPROBE_BURP_BROWSER` first. Optional: the system browser is used
    /// when none exists, so this is a list, not an error.
    pub fn burp_browser_roots(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.var("WEBPROBE_BURP_BROWSER").into_iter().collect();
        v.extend(self.burp_install_dirs().into_iter().map(|d| d.join("burpbrowser")));
        if self.system {
            v.push(PathBuf::from("/usr/lib/burpbrowser"));
        }
        v
    }

    /// Chromium/Chrome binaries for the crawler and headless pages:
    /// `$WEBPROBE_CHROMIUM`, the usual system locations, then Burp's bundled one.
    pub fn chromium_candidates(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.var("WEBPROBE_CHROMIUM").into_iter().collect();
        if self.system {
            v.extend(["/usr/bin/chromium", "/usr/bin/google-chrome", "/usr/bin/chromium-browser"].iter().map(PathBuf::from));
        }
        for root in self.burp_browser_roots() {
            if let Ok(rd) = std::fs::read_dir(&root) {
                v.extend(rd.flatten().map(|d| d.path().join("chrome")));
            }
        }
        v
    }

    /// The first Chromium binary that exists.
    pub fn chromium(&self) -> Result<PathBuf, Missing> {
        let looked = self.chromium_candidates();
        looked.iter().find(|p| p.is_file()).cloned().ok_or(Missing {
            what: "a Chromium or Chrome binary",
            looked,
            how: "The browser crawl is skipped. Install Chromium, or set WEBPROBE_CHROMIUM to a Chrome/Chromium binary.",
        })
    }

    /// A `java` launcher (11+, it runs the bridge as a source file):
    /// `$WEBPROBE_JAVA`, then `$JAVA_HOME/bin/java`, then `java` on `$PATH`.
    pub fn java(&self) -> Result<PathBuf, Missing> {
        let mut looked: Vec<PathBuf> = self.var("WEBPROBE_JAVA").into_iter().collect();
        looked.extend(self.var("JAVA_HOME").map(|h| h.join("bin/java")));
        if let Some(path) = self.var("PATH") {
            looked.extend(std::env::split_paths(&path).map(|d| d.join("java")));
        }
        looked.iter().find(|p| p.is_file()).cloned().ok_or(Missing {
            what: "a Java runtime (java 22 or later: the Montoya bridge uses the multi-file source launcher)",
            looked,
            how: "Java (Montoya) extensions cannot load. Install a JDK, or set WEBPROBE_JAVA (or JAVA_HOME) to it.",
        })
    }

    /// The bridge source written out under the data directory (the JVM runs
    /// a source file, so it needs one on disk).
    pub fn montoya_bridge_source(&self) -> std::io::Result<PathBuf> {
        let dir = self.data_dir().join("sidecar");
        for (name, text) in MONTOYA_BRIDGE_SOURCES {
            write_out(&dir.join(name), text.as_bytes())?;
        }
        Ok(dir.join("MontoyaBridge.java"))
    }

    /// The extension catalogue directory: `$WEBPROBE_EXTENSIONS_DIR`, an
    /// `extensions/` directory next to the binary (a release archive), else
    /// the embedded catalogue written out under the data directory.
    pub fn extensions_dir(&self) -> std::io::Result<PathBuf> {
        let mut cands: Vec<PathBuf> = self.var("WEBPROBE_EXTENSIONS_DIR").into_iter().collect();
        if self.system {
            if let Ok(exe) = std::env::current_exe() {
                cands.extend(exe.parent().map(|d| d.join("extensions")));
            }
        }
        if let Some(d) = cands.into_iter().find(|d| d.join("catalogue.json").is_file()) {
            return Ok(d);
        }
        let root = self.data_dir();
        let dir = root.join("extensions");
        write_out(&dir.join("catalogue.json"), CATALOGUE_JSON.as_bytes())?;
        write_out(&dir.join("examples/marker_reflection.py"), EXAMPLE_MARKER.as_bytes())?;
        write_out(&dir.join("examples/security_headers.py"), EXAMPLE_HEADERS.as_bytes())?;
        // The catalogue names the demo jar as {dir}/../sidecar/demo-ext/demo-ext.jar.
        write_out(&root.join("sidecar/demo-ext/demo-ext.jar"), DEMO_EXT_JAR)?;
        Ok(dir)
    }
}

/// [`Lookup::knowledge_base`] in the process environment.
pub fn knowledge_base() -> Result<PathBuf, Missing> {
    Lookup::process().knowledge_base()
}

/// [`Lookup::payload_strings`] in the process environment.
pub fn payload_strings() -> Result<PathBuf, Missing> {
    Lookup::process().payload_strings()
}

/// [`Lookup::retirejs_repository`] in the process environment.
pub fn retirejs_repository() -> Result<PathBuf, Missing> {
    Lookup::process().retirejs_repository()
}

/// [`Lookup::montoya_jar`] in the process environment.
pub fn montoya_jar() -> Result<PathBuf, Missing> {
    Lookup::process().montoya_jar()
}

/// [`Lookup::burp_browser_roots`] in the process environment.
pub fn burp_browser_roots() -> Vec<PathBuf> {
    Lookup::process().burp_browser_roots()
}

/// [`Lookup::chromium`] in the process environment.
pub fn chromium() -> Result<PathBuf, Missing> {
    Lookup::process().chromium()
}

/// [`Lookup::java`] in the process environment.
pub fn java() -> Result<PathBuf, Missing> {
    Lookup::process().java()
}

/// [`Lookup::config_dir`] in the process environment.
pub fn config_dir() -> Option<PathBuf> {
    Lookup::process().config_dir()
}

/// [`Lookup::montoya_bridge_source`] in the process environment.
pub fn montoya_bridge_source() -> std::io::Result<PathBuf> {
    Lookup::process().montoya_bridge_source()
}

/// [`Lookup::extensions_dir`] in the process environment.
pub fn extensions_dir() -> std::io::Result<PathBuf> {
    Lookup::process().extensions_dir()
}

fn has_ext(dir: &Path, ext: &str) -> bool {
    std::fs::read_dir(dir).map(|rd| rd.flatten().any(|e| e.path().extension().is_some_and(|x| x == ext))).unwrap_or(false)
}

fn first_dir_with(cands: &[PathBuf], ok: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    cands.iter().find(|d| d.is_dir() && ok(d)).cloned()
}

// ---------------------------------------------------------------- embedded files

/// The Montoya bridge's source (WebProbe's own), compiled into the binary.
/// The Montoya bridge sources (one per API area; Java's multi-file source
/// launcher compiles them together from `MontoyaBridge.java`).
pub const MONTOYA_BRIDGE_SOURCES: [(&str, &str); 7] = [
    ("MontoyaBridge.java", include_str!("../../sidecar/MontoyaBridge.java")),
    ("Api.java", include_str!("../../sidecar/Api.java")),
    ("Wire.java", include_str!("../../sidecar/Wire.java")),
    ("Logs.java", include_str!("../../sidecar/Logs.java")),
    ("Messages.java", include_str!("../../sidecar/Messages.java")),
    ("Factory.java", include_str!("../../sidecar/Factory.java")),
    ("Bridge.java", include_str!("../../sidecar/Bridge.java")),
];
const DEMO_EXT_JAR: &[u8] = include_bytes!("../../sidecar/demo-ext/demo-ext.jar");
const CATALOGUE_JSON: &str = include_str!("../../extensions/catalogue.json");
const EXAMPLE_MARKER: &str = include_str!("../../extensions/examples/marker_reflection.py");
const EXAMPLE_HEADERS: &str = include_str!("../../extensions/examples/security_headers.py");

/// Write `bytes` to `path` unless it already holds them.
fn write_out(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wp-paths-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Every resource resolves from an override directory, and with
    /// nothing anywhere the message names what, where and how.
    #[test]
    fn resources_resolve_from_overrides_and_say_what_is_missing() {
        let empty = scratch("empty");
        let res = scratch("res");
        let own = scratch("own");
        let base = || vec![("HOME", empty.clone()), ("WEBPROBE_DATA_DIR", empty.join("data")), ("WEBPROBE_BURP_RESOURCES", res.clone())];
        let lk = Lookup::with_vars(base());
        // Nothing yet.
        let kb = lk.knowledge_base().unwrap_err();
        assert!(kb.looked.contains(&res.join("KnowledgeBase/Issues")), "{kb}");
        assert!(kb.to_string().contains("not found (looked in: ") && kb.to_string().contains("WEBPROBE_BURP_RESOURCES"), "{kb}");
        assert!(lk.payload_strings().unwrap_err().to_string().contains("PayloadStrings"));
        assert!(lk.retirejs_repository().unwrap_err().to_string().contains("WEBPROBE_RETIREJS"));
        assert!(lk.montoya_jar().unwrap_err().to_string().contains("montoya-api"));
        assert!(lk.chromium().unwrap_err().to_string().contains("WEBPROBE_CHROMIUM"));
        assert!(lk.java().unwrap_err().to_string().contains("WEBPROBE_JAVA"));
        // From the extracted resources directory.
        std::fs::create_dir_all(res.join("KnowledgeBase/Issues")).unwrap();
        std::fs::write(res.join("KnowledgeBase/Issues/0_x.json"), "{}").unwrap();
        std::fs::create_dir_all(res.join("PayloadStrings")).unwrap();
        std::fs::write(res.join("PayloadStrings/a.pay"), "x").unwrap();
        std::fs::create_dir_all(res.join("RetireJS")).unwrap();
        std::fs::write(res.join("RetireJS/retirejs_repository.json"), "{}").unwrap();
        assert_eq!(lk.knowledge_base().unwrap(), res.join("KnowledgeBase/Issues"));
        assert_eq!(lk.payload_strings().unwrap(), res.join("PayloadStrings"));
        assert_eq!(lk.retirejs_repository().unwrap(), res.join("RetireJS/retirejs_repository.json"));
        // Explicit overrides win.
        std::fs::write(own.join("jsrepository.json"), "{}").unwrap();
        std::fs::write(own.join("montoya-api.jar"), "PK").unwrap();
        std::fs::write(own.join("chrome"), "").unwrap();
        std::fs::create_dir_all(own.join("jdk/bin")).unwrap();
        std::fs::write(own.join("jdk/bin/java"), "").unwrap();
        let mut vars = base();
        vars.push(("JAVA_HOME", own.join("jdk")));
        vars.extend([("WEBPROBE_RETIREJS", own.join("jsrepository.json")), ("WEBPROBE_BURP_JAR", own.join("montoya-api.jar")), ("WEBPROBE_CHROMIUM", own.join("chrome"))]);
        let lk = Lookup::with_vars(vars);
        assert_eq!(lk.retirejs_repository().unwrap(), own.join("jsrepository.json"));
        assert_eq!(lk.montoya_jar().unwrap(), own.join("montoya-api.jar"));
        assert_eq!(lk.chromium().unwrap(), own.join("chrome"));
        assert_eq!(lk.java().unwrap(), own.join("jdk/bin/java"));
        // WebProbe's own files are written out on demand.
        let bridge = lk.montoya_bridge_source().unwrap();
        assert!(bridge.starts_with(empty.join("data")) && std::fs::read_to_string(&bridge).unwrap().contains("class MontoyaBridge"));
        let ext = lk.extensions_dir().unwrap();
        assert!(ext.join("catalogue.json").is_file() && ext.join("../sidecar/demo-ext/demo-ext.jar").is_file(), "{}", ext.display());
    }

    /// No absolute developer path or build-tree lookup remains in the
    /// sources outside tests.
    #[test]
    fn no_developer_paths_outside_tests() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut offenders = Vec::new();
        for dir in [root.join("core/src"), root.join("src")] {
            let mut stack = vec![dir];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).unwrap().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                        continue;
                    }
                    if p.extension().is_none_or(|x| x != "rs") || p.ends_with("paths.rs") {
                        continue;
                    }
                    let text = std::fs::read_to_string(&p).unwrap();
                    // Everything from the first test module on is test code.
                    let code = text.split("#[cfg(test)]").next().unwrap_or("");
                    for (n, line) in code.lines().enumerate() {
                        let l = line.trim_start();
                        if l.starts_with("//") {
                            continue;
                        }
                        if l.contains("\"/root/") || l.contains("/opt/BurpSuite") || l.contains("CARGO_MANIFEST_DIR") || l.contains("\"/tmp/") {
                            offenders.push(format!("{}:{}: {}", p.display(), n + 1, l));
                        }
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "developer paths at run time:\n{}", offenders.join("\n"));
    }
}

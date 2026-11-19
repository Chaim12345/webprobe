//! WebProbe without a window: the same engine as the desktop app, driven
//! from the command line.
//!
//!     webprobe-headless proxy [--port N] [--project FILE] [--seconds N]
//!         Run the intercepting proxy (with the live passive scan) and print
//!         one line per exchange. With --project, the history and issues are
//!         saved to FILE when it stops (after N seconds, or on Ctrl+C /
//!         end of standard input).
//!
//!     webprobe-headless scan URL... [--crawl] [--speed fast|normal|thorough]
//!                           [--report FILE.html|FILE.xml]
//!         Audit the given URLs (crawl first with --crawl) and print every
//!         issue as one JSON object per line. --report also writes Burp's
//!         HTML report or XML issue export, by the file's extension.
//!
//! Burp's command line flags (R-15), accepted before or after the
//! subcommand: --config-file FILE (project options JSON, repeatable,
//! last wins), --user-config-file FILE (user options JSON, repeatable),
//! --project-file FILE (alias of --project), --unpause-spider-and-scanner
//! (accepted for parity; the headless binary never starts paused),
//! --version, --help.
//!
//! Only point it at hosts you are authorised to test.

use std::io::BufRead;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use webprobe_core::{burp_config, net, project, report, rest_api, scan, scan_library};

const USAGE: &str = "usage:\n  webprobe-headless [--config-file FILE]... [--user-config-file FILE]... [--unpause-spider-and-scanner] [--data-dir DIR] [--diagnostics] proxy [--port N] [--project FILE | --project-file FILE] [--seconds N]\n  webprobe-headless [--config-file FILE]... [--user-config-file FILE]... scan URL... [--crawl] [--speed fast|normal|thorough] [--report FILE.html|FILE.xml]\n  webprobe-headless --version | --help";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2)
}

/// Burp puts its flags before the command word; accept that order too by
/// rotating `proxy` / `scan` to the front.
fn burp_command_first(args: &mut Vec<String>) {
    if !matches!(args.first().map(String::as_str), Some("proxy" | "scan" | "--version" | "--help")) {
        // Only a bare positional can be the command word: skip the values
        // of flags that take one, so `--config-file proxy` stays a file.
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if matches!(a.as_str(), "--config-file" | "--user-config-file") {
                i += 2;
                continue;
            }
            if a == "proxy" || a == "scan" {
                let cmd = args.remove(i);
                args.insert(0, cmd);
                return;
            }
            i += 1;
        }
    }
}

/// Burp's command line flags (R-15), collected from anywhere in the
/// argument list. Repeatable flags keep their order (last wins on apply).
#[derive(Default, Debug, PartialEq)]
struct BurpFlags {
    config_files: Vec<String>,
    user_config_files: Vec<String>,
    unpause_spider_and_scanner: bool,
}

fn take_burp_flags(args: &mut Vec<String>) -> BurpFlags {
    let mut flags = BurpFlags::default();
    while let Some(f) = take_opt(args, "--config-file") {
        flags.config_files.push(f);
    }
    while let Some(f) = take_opt(args, "--user-config-file") {
        flags.user_config_files.push(f);
    }
    flags.unpause_spider_and_scanner = take_flag(args, "--unpause-spider-and-scanner");
    flags
}

/// Read and merge the config JSONs. The scan-configuration keys go through
/// R-11's model (`scan_library`): each --config-file is one library entry,
/// overlaid in order (Burp: last wins per key). Notes name files and
/// sections only; API keys are never logged (pinned by burp_config tests).
fn load_burp_configs(flags: &BurpFlags) -> (burp_config::ProxyListener, burp_config::ApiConfig, Vec<scan_library::LibraryConfig>) {
    let mut listener = burp_config::ProxyListener::default();
    let mut api = burp_config::ApiConfig::default();
    let mut configs = Vec::new();
    let read = |path: &str| -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(1);
        })
    };
    for f in &flags.config_files {
        let text = read(f);
        let json: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
            eprintln!("{f}: not a JSON object: {e}");
            std::process::exit(1);
        });
        let mut notes = Vec::new();
        burp_config::apply_project_options(&json, &mut listener, &mut notes);
        for n in notes {
            eprintln!("{f}: {n}");
        }
        match scan_library::parse_config(f, text.as_bytes(), false) {
            Ok(mut c) => {
                // The proxy listener is applied above; keep it out of the
                // scan-configuration overlay so not_applied stays honest.
                c.tree.as_object_mut().map(|m| m.remove("proxy"));
                configs.push(c);
            }
            Err(e) => eprintln!("{f}: {e}"),
        }
    }
    for f in &flags.user_config_files {
        let json: serde_json::Value = serde_json::from_str(&read(f)).unwrap_or_else(|e| {
            eprintln!("{f}: not a JSON object: {e}");
            std::process::exit(1);
        });
        let mut notes = Vec::new();
        burp_config::apply_user_options(&json, &mut api, &mut notes);
        for n in notes {
            eprintln!("{f}: {n}");
        }
    }
    (listener, api, configs)
}

/// Overlay the loaded scan configurations on the shared scan settings
/// (Burp applies --config-file before the run starts) and note the keys
/// WebProbe does not apply.
fn apply_scan_configs(shared: &net::Shared, configs: &[scan_library::LibraryConfig]) {
    if configs.is_empty() {
        return;
    }
    let refs: Vec<&scan_library::LibraryConfig> = configs.iter().collect();
    for line in scan_library::not_applied(&refs) {
        eprintln!("not applied by WebProbe: {line}");
    }
    let base = shared.scan_config.lock().unwrap().clone();
    let applied = scan_library::apply(&refs, &base, shared.scan_speed.load(Ordering::SeqCst), shared.scan_accuracy.load(Ordering::SeqCst));
    *shared.scan_config.lock().unwrap() = applied.config;
    shared.scan_speed.store(applied.speed, Ordering::SeqCst);
    shared.scan_accuracy.store(applied.accuracy, Ordering::SeqCst);
}

/// Value of `--name V` in `args`, removing both.
fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    if i + 1 >= args.len() {
        usage();
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    match args.iter().position(|a| a == name) {
        Some(i) => {
            args.remove(i);
            true
        }
        None => false,
    }
}

fn issue_json(i: &scan::ScanIssue) -> String {
    serde_json::json!({
        "name": i.name,
        "severity": i.sev,
        "confidence": i.confidence,
        "host": i.host,
        "path": i.path,
        "type_id": i.type_id,
        "detail": i.detail,
        "evidence": i.evidence.len(),
    })
    .to_string()
}

fn save_project(shared: &net::Shared, path: &str) -> Result<(), String> {
    let data = project::ProjectData {
        history: shared.history.snapshot().iter().map(project::ProjectHistory::from_entry).collect(),
        issues: shared.issues.lock().unwrap().iter().map(project::ProjectIssue::from_issue).collect(),
        ..Default::default()
    };
    project::save(std::path::Path::new(path), &data)
}

fn proxy(mut args: Vec<String>) {
    let flags = take_burp_flags(&mut args);
    let (listener, api, scan_configs) = load_burp_configs(&flags);
    // Without a --config-file the headless default stays 8090; with one,
    // the config's listener port applies and an explicit --port beats it.
    let default_port = if flags.config_files.is_empty() { 8090 } else { listener.port };
    let port: u16 = take_opt(&mut args, "--port").map(|p| p.parse().unwrap_or_else(|_| usage())).unwrap_or(default_port);
    if !listener.running {
        eprintln!("proxy listener disabled by configuration; nothing to do");
        std::process::exit(0);
    }
    // --project-file is Burp's name for --project.
    let project_file = [take_opt(&mut args, "--project"), take_opt(&mut args, "--project-file")].into_iter().flatten().last();
    let seconds: Option<u64> = take_opt(&mut args, "--seconds").map(|s| s.parse().unwrap_or_else(|_| usage()));
    if !args.is_empty() {
        usage();
    }
    let shared = net::Shared::new();
    apply_scan_configs(&shared, &scan_configs);
    if api.enabled {
        // Burp serves the REST API from the running app; for the headless
        // binary that is the long-lived proxy mode. The key is never
        // printed (Burp shows it in its UI; a headless process refuses to
        // start without one instead).
        let kb = std::sync::Arc::new(report::KnowledgeBase::discover());
        match rest_api::start(&shared, &api, kb) {
            Ok(api_port) => {
                eprintln!("REST API listening on {}:{api_port}", if api.listen_mode == "all_interfaces" { "0.0.0.0" } else { "127.0.0.1" });
                shared.api_started.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    *shared.api_config.lock().unwrap() = api;
    shared.proxy_port.store(port, Ordering::SeqCst);
    net::start_proxy(shared.clone());
    let started = Instant::now();
    while !shared.listener_running.load(Ordering::SeqCst) {
        if started.elapsed() > Duration::from_secs(5) {
            eprintln!("could not listen on 127.0.0.1:{port}");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("proxy listening on 127.0.0.1:{port}");
    // Stop on end of standard input (Ctrl+D, or the parent closing it), and
    // on Ctrl+C / SIGTERM: the run then ends normally, so --project is saved.
    let stdin_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, stdin_closed.clone());
    }
    if seconds.is_none() {
        let flag = stdin_closed.clone();
        std::thread::spawn(move || {
            for _ in std::io::stdin().lock().lines() {}
            flag.store(true, Ordering::SeqCst);
        });
    }
    let mut printed = 0usize;
    loop {
        // Copy the new rows out first: printing to a slow pipe must not hold
        // the history lock every proxy thread needs to record.
        let fresh: Vec<String> = {
            let history = shared.history.snapshot();
            let rows = history.iter().skip(printed).map(|e| format!("{}\t{}\t{}\t{}\t{}", e.id, e.method, net::history_host(e), e.path, e.status)).collect();
            printed = history.len();
            rows
        };
        for row in fresh {
            println!("{row}");
        }
        let done = stdin_closed.load(Ordering::SeqCst) || seconds.is_some_and(|s| started.elapsed() >= Duration::from_secs(s));
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let issues = shared.issues.lock().unwrap().clone();
    for i in &issues {
        eprintln!("issue: {}", issue_json(i));
    }
    if let Some(path) = project_file {
        match save_project(&shared, &path) {
            Ok(()) => eprintln!("saved {printed} exchange(s) and {} issue(s) to {path}", issues.len()),
            Err(e) => {
                eprintln!("could not save {path}: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn scan_urls(mut args: Vec<String>) {
    let flags = take_burp_flags(&mut args);
    let (_listener, _api, scan_configs) = load_burp_configs(&flags);
    let crawl = take_flag(&mut args, "--crawl");
    let report_file = take_opt(&mut args, "--report");
    let speed = match take_opt(&mut args, "--speed").as_deref() {
        None | Some("normal") => 1,
        Some("fast") => 0,
        Some("thorough") => 2,
        Some(_) => usage(),
    };
    if args.is_empty() || args.iter().any(|a| a.starts_with("--")) {
        usage();
    }
    let shared = net::Shared::new();
    shared.scan_speed.store(speed, Ordering::SeqCst);
    apply_scan_configs(&shared, &scan_configs);
    let started = Instant::now();
    scan::crawl_and_audit(&shared, &args, !crawl);
    // crawl_and_audit returns once the last item's audit has finished.
    shared.scan.wait_idle(None);
    let issues = shared.issues.lock().unwrap().clone();
    for i in &issues {
        println!("{}", issue_json(i));
    }
    eprintln!("{} issue(s) in {:.1} s", issues.len(), started.elapsed().as_secs_f32());
    if let Some(path) = report_file {
        let format = if path.to_ascii_lowercase().ends_with(".xml") { report::ReportFormat::Xml } else { report::ReportFormat::Html };
        let options = report::ReportOptions { format, ..Default::default() };
        let mut known: Vec<net::HistEntry> = shared.crawl_items.snapshot();
        known.extend(shared.history.snapshot().iter().cloned());
        let chosen = report::select_issues(&issues, &options);
        let kb = report::KnowledgeBase::discover_checked().unwrap_or_else(|missing| {
            eprintln!("{missing}");
            report::KnowledgeBase::default()
        });
        let items = report::build_report_issues(&chosen, &known, &kb);
        let text = report::render(&items, &options, webprobe_core::util::now_secs());
        match std::fs::write(&path, text) {
            Ok(()) => eprintln!("report of {} issue(s) written to {path}", items.len()),
            Err(e) => {
                eprintln!("could not write {path}: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    // Burp's --data-dir and --diagnostics work before the subcommand.
    if let Some(dir) = take_opt(&mut args, "--data-dir") {
        // SAFETY: no threads exist yet, so setting the environment is
        // race-free here. paths::Lookup reads WEBPROBE_DATA_DIR at call time.
        unsafe { std::env::set_var("WEBPROBE_DATA_DIR", &dir) };
    }
    if take_flag(&mut args, "--diagnostics") {
        println!("webprobe-headless {}", env!("CARGO_PKG_VERSION"));
        println!("os: {} {}", std::env::consts::OS, std::env::consts::ARCH);
        println!("data dir: {}", webprobe_core::paths::Lookup::process().data_dir().display());
        return;
    }
    if args.is_empty() {
        usage();
    }
    burp_command_first(&mut args);
    match args.remove(0).as_str() {
        "--version" => println!("webprobe-headless {}", env!("CARGO_PKG_VERSION")),
        "--help" => println!("{USAGE}"),
        "proxy" => proxy(args),
        "scan" => scan_urls(args),
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn burp_command_first_ignores_flag_values() {
        // a flag value that happens to be `proxy` is not the command word
        let mut args: Vec<String> = ["--config-file", "proxy", "scan"].iter().map(|s| s.to_string()).collect();
        burp_command_first(&mut args);
        assert_eq!(args, ["scan", "--config-file", "proxy"]);
        // flags before the command rotate as Burp allows
        let mut args: Vec<String> = ["--unpause-spider-and-scanner", "proxy"].iter().map(|s| s.to_string()).collect();
        burp_command_first(&mut args);
        assert_eq!(args, ["proxy", "--unpause-spider-and-scanner"]);
        // no command word: untouched
        let mut args: Vec<String> = ["--config-file", "scan"].iter().map(|s| s.to_string()).collect();
        burp_command_first(&mut args);
        assert_eq!(args, ["--config-file", "scan"]);
    }

    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    /// Burp's repeatable config flags collect in order (last wins on
    /// apply) and are removed from the remaining arguments.
    #[test]
    fn burp_flags_are_repeatable_and_ordered() {
        let mut args = strings(&["--config-file", "a.json", "--crawl", "--config-file", "b.json", "--user-config-file", "u.json", "--unpause-spider-and-scanner", "http://x/"]);
        let flags = take_burp_flags(&mut args);
        assert_eq!(flags.config_files, vec!["a.json".to_string(), "b.json".to_string()]);
        assert_eq!(flags.user_config_files, vec!["u.json".to_string()]);
        assert!(flags.unpause_spider_and_scanner);
        assert_eq!(args, strings(&["--crawl", "http://x/"]));
    }

    /// --config-file feeds both the proxy listener and R-11's scan
    /// configuration model; the proxy section is applied to the listener
    /// and kept out of the scan overlay.
    #[test]
    fn config_file_feeds_listener_and_scan_library() {
        let dir = std::env::temp_dir().join(format!("webprobe-r15-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("config.json");
        std::fs::write(&f, r#"{"proxy": {"request_listeners": [{"listener_port": 9091}]}, "scanner": {"insertion_point_types": {"insert_cookies": false}}}"#).unwrap();
        let mut args = strings(&["--config-file", f.to_str().unwrap()]);
        let flags = take_burp_flags(&mut args);
        let (listener, _api, configs) = load_burp_configs(&flags);
        assert_eq!(listener.port, 9091);
        assert_eq!(configs.len(), 1);
        assert!(configs[0].tree.get("proxy").is_none());
        assert!(configs[0].tree.get("scanner").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Burp's flag-before-command order is accepted.
    #[test]
    fn burp_flags_may_precede_the_command() {
        let mut args = strings(&["--config-file", "a.json", "proxy", "--seconds", "1"]);
        burp_command_first(&mut args);
        assert_eq!(args[0], "proxy");
        let mut args = strings(&["scan", "http://x/"]);
        burp_command_first(&mut args);
        assert_eq!(args[0], "scan");
    }

    /// --project-file is an alias of --project; the last one given wins.
    #[test]
    fn project_file_alias_last_wins() {
        let mut args = strings(&["--project", "first.burp", "--project-file", "second.burp"]);
        let project_file = [take_opt(&mut args, "--project"), take_opt(&mut args, "--project-file")].into_iter().flatten().last();
        assert_eq!(project_file.as_deref(), Some("second.burp"));
        assert!(args.is_empty());
    }
}

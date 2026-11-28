//! WebProbe without a window: the same engine as the desktop app, driven
//! from the command line.
//!
//!     webprobe-headless proxy [--port N] [--project FILE] [--seconds N]
//!                             [--bambda-filter FILE] [--bambda-column FILE]
//!                             [--bambda-check FILE]
//!         --bambda-check (proxy and scan) runs a Bambda passive scan check:
//!         Java that returns an AuditResult for one exchange. What it raises
//!         is reported as "Bambda generated issue".
//!         Run the intercepting proxy (with the live passive scan) and print
//!         one line per exchange. With --project, the history and issues are
//!         saved to FILE when it stops (after N seconds, or on Ctrl+C /
//!         end of standard input). --bambda-filter keeps only the exchanges
//!         a Bambda VIEW_FILTER script returns true for; --bambda-column
//!         appends the value of a CUSTOM_COLUMN script as a last field
//!         (R-16). A script that fails to compile or throws prints its
//!         error to stderr and the run continues unfiltered.
//!
//!     webprobe-headless scan URL... [--crawl] [--collaborator SERVER] [--collaborator-wait SECONDS] [--bambda-check FILE] [--speed fast|normal|thorough]
//!                           [--report FILE.html|FILE.xml] [--project FILE]
//!         Audit the given URLs (crawl first with --crawl) and print every
//!         issue as one JSON object per line. --report also writes Burp's
//!         HTML report or XML issue export, by the file's extension.
//!
//! Burp's command line flags (R-15), accepted before or after the
//! subcommand: --config-file FILE (project options JSON, repeatable,
//! last wins), --user-config-file FILE (user options JSON, repeatable),
//! --project-file FILE (alias of --project), --unpause-spider-and-scanner
//! (accepted for parity; the headless binary never starts paused),
//! --data-dir DIR, --diagnostics, --version, --help.
//!
//! Only point it at hosts you are authorised to test.

use std::collections::HashMap;
use std::io::BufRead;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use webprobe_core::bambda::{Cell, Kind, Program, Verdict};
use webprobe_core::{burp_config, net, project, rest_api, scan, scan_config, scan_library};
use webprobe_report::report;

const USAGE: &str = "usage:\n  webprobe-headless [--config-file FILE]... [--user-config-file FILE]... [--unpause-spider-and-scanner] [--data-dir DIR] [--diagnostics] proxy [--port N] [--project FILE | --project-file FILE] [--seconds N] [--daemon] [--collaborator SERVER] [--bambda-filter FILE] [--bambda-column FILE] [--bambda-check FILE]\n  webprobe-headless [--config-file FILE]... [--user-config-file FILE]... scan URL... [--crawl] [--collaborator SERVER] [--collaborator-wait SECONDS] [--bambda-check FILE] [--speed fast|normal|thorough] [--report FILE.html|FILE.xml] [--project FILE]\n  webprobe-headless --version | --help";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2)
}

/// Burp puts its flags before the command word; accept that order too by
/// rotating `proxy` / `scan` to the front.
fn burp_command_first(args: &mut Vec<String>) {
    if !matches!(
        args.first().map(String::as_str),
        Some("proxy" | "scan" | "--version" | "--help")
    ) {
        // Only a bare positional can be the command word: skip the values
        // of flags that take one, so `--config-file proxy` stays a file.
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if matches!(
                a.as_str(),
                "--config-file" | "--user-config-file" | "--data-dir"
            ) {
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
fn load_burp_configs(
    flags: &BurpFlags,
) -> (
    burp_config::ProxyListener,
    burp_config::HttpOptions,
    burp_config::ApiConfig,
    Vec<scan_library::LibraryConfig>,
) {
    let mut listener = burp_config::ProxyListener::default();
    let mut http = burp_config::HttpOptions::default();
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
        burp_config::apply_project_options(&json, &mut listener, &mut http, &mut notes);
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
    (listener, http, api, configs)
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
    let slot = scan_config::shared_config(shared);
    let base = slot.lock().clone();
    let applied = scan_library::apply(
        &refs,
        &base,
        shared.scan_speed.load(Ordering::SeqCst),
        shared.scan_accuracy.load(Ordering::SeqCst),
    );
    *slot.lock() = applied.config;
    shared.scan_speed.store(applied.speed, Ordering::SeqCst);
    shared
        .scan_accuracy
        .store(applied.accuracy, Ordering::SeqCst);
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

/// Consume both project aliases in their original order, including repeats.
fn take_project_file(args: &mut Vec<String>) -> Option<String> {
    let mut selected = None;
    while let Some(index) = args
        .iter()
        .position(|a| matches!(a.as_str(), "--project" | "--project-file"))
    {
        if index + 1 >= args.len() {
            usage();
        }
        selected = Some(args.remove(index + 1));
        args.remove(index);
    }
    selected
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
    // AR-02: everything the engine holds, not only history and issues.
    let data = project::capture_engine(shared);
    project::save(std::path::Path::new(path), &data).map_err(String::from)
}

/// R-16: the Bambda filter and custom column of headless proxy mode. Rows are
/// evaluated in bounded chunks; a script that fails to compile or throws is
/// reported and the run continues, so a broken script never stops the proxy.
struct BambdaPrint {
    filter: Option<(Program, String)>,
    column: Option<(Program, String)>,
}

/// Per-batch deadline: the same bound the desktop tables use.
const BAMBDA_BATCH: Duration = Duration::from_secs(10);

/// S-03: run a passive-check Bambda over `rows` and report what it raises
/// as "Bambda generated issue". A failed run is reported and skipped; it
/// never stops the proxy or the scan.
fn bambda_check(shared: &net::Shared, check: &(Program, String), rows: &[net::HistEntry]) {
    if rows.is_empty() {
        return;
    }
    let (program, name) = check;
    match webprobe_core::bambda_scan::run_passive(program, rows, BAMBDA_BATCH) {
        Ok(report) => {
            if report.row_errors > 0 || report.skipped > 0 {
                eprintln!(
                    "bambda check {name}: {} exchange(s) threw or returned no AuditResult, {} too large to check",
                    report.row_errors, report.skipped
                );
            }
            scan::add_passive_issues(shared, report.issues);
        }
        Err(e) => eprintln!("bambda check {name} failed: {e}"),
    }
}

fn cell_text(cell: Option<&Cell>) -> String {
    match cell {
        Some(Cell::Text(text)) => text.clone(),
        Some(Cell::Failed(error)) => format!("Error: {error}"),
        None => String::new(),
    }
}

impl BambdaPrint {
    fn new(filter: Option<&str>, column: Option<&str>) -> Self {
        Self {
            filter: Self::load(filter, Kind::Filter),
            column: Self::load(column, Kind::Column),
        }
    }

    fn load(path: Option<&str>, kind: Kind) -> Option<(Program, String)> {
        let path = path?;
        let name = std::path::Path::new(path)
            .file_name()
            .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned());
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(e) => {
                eprintln!("bambda: cannot read {path}: {e}");
                return None;
            }
        };
        let (java, api) = match (
            webprobe_core::paths::java(),
            webprobe_core::paths::montoya_jar(),
        ) {
            (Ok(java), Ok(api)) => (java, api),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("bambda: {path} needs a JDK 17+ and the Montoya API jar: {e}");
                return None;
            }
        };
        match Program::compile(&java, &api, kind, &source, BAMBDA_BATCH) {
            Ok(program) => Some((program, name)),
            Err(e) => {
                eprintln!("bambda: {path}: {e}");
                None
            }
        }
    }

    /// The lines to print for these rows, in order.
    fn render(&mut self, rows: &[net::HistEntry]) -> Vec<String> {
        let mut out = Vec::new();
        for chunk in rows.chunks(webprobe_core::bambda::MAX_TABLE_ROWS) {
            let (exchanges, skipped) = webprobe_core::bambda_rows::history_rows(chunk);
            for id in &skipped {
                eprintln!("bambda: exchange {id} is larger than one batch; printed unfiltered");
            }
            let mut keep: Option<HashMap<u64, bool>> = None;
            if let Some((program, name)) = self.filter.take() {
                match program.apply(Kind::Filter, &exchanges, BAMBDA_BATCH) {
                    Ok(outcome) => {
                        if outcome.row_errors > 0 {
                            eprintln!(
                                "bambda filter {name}: {} row(s) threw; those rows are printed",
                                outcome.row_errors
                            );
                        }
                        keep = Some(
                            outcome
                                .verdicts
                                .iter()
                                .map(|(id, verdict)| (*id, *verdict != Verdict::Hide))
                                .collect(),
                        );
                        self.filter = Some((program, name));
                    }
                    Err(e) => {
                        eprintln!("bambda filter {name} failed: {e}; printing unfiltered")
                    }
                }
            }
            let mut cells: Option<HashMap<u64, String>> = None;
            if let Some((program, name)) = self.column.take() {
                match program.apply(Kind::Column, &exchanges, BAMBDA_BATCH) {
                    Ok(outcome) => {
                        if outcome.row_errors > 0 {
                            eprintln!("bambda column {name}: {} row error(s)", outcome.row_errors);
                        }
                        cells = Some(
                            outcome
                                .cells
                                .iter()
                                .map(|(id, cell)| (*id, cell_text(Some(cell))))
                                .collect(),
                        );
                        self.column = Some((program, name));
                    }
                    Err(e) => {
                        eprintln!("bambda column {name} failed: {e}; no column from here")
                    }
                }
            }
            for entry in chunk {
                if keep
                    .as_ref()
                    .is_some_and(|keep| keep.get(&entry.id) == Some(&false))
                {
                    continue;
                }
                let mut line = format!(
                    "{}\t{}\t{}\t{}\t{}",
                    entry.id,
                    entry.method,
                    net::history_host(entry),
                    entry.path,
                    entry.status
                );
                if let Some(cells) = &cells {
                    line.push('\t');
                    line.push_str(cells.get(&entry.id).map_or("", String::as_str));
                }
                out.push(line);
            }
        }
        out
    }
}

fn proxy(mut args: Vec<String>) {
    let flags = take_burp_flags(&mut args);
    let (listener, http, api, scan_configs) = load_burp_configs(&flags);
    // Without a --config-file the headless default stays 8090; with one,
    // the config's listener port applies and an explicit --port beats it.
    let default_port = if flags.config_files.is_empty() {
        8090
    } else {
        listener.port
    };
    let port: u16 = take_opt(&mut args, "--port")
        .map(|p| p.parse().unwrap_or_else(|_| usage()))
        .unwrap_or(default_port);
    if !listener.running {
        eprintln!("proxy listener disabled by configuration; nothing to do");
        std::process::exit(0);
    }
    // --project-file is Burp's name for --project.
    let project_file = take_project_file(&mut args);
    let seconds: Option<u64> =
        take_opt(&mut args, "--seconds").map(|s| s.parse().unwrap_or_else(|_| usage()));
    // R-16: the headless entry point applies the same Bambda filter and custom
    // column the desktop tables do.
    // Run as a service: with no terminal, standard input is closed (or
    // /dev/null) from the start, and "stop on end of input" would end the
    // proxy at once. --daemon stops only on SIGINT / SIGTERM (or --seconds).
    let daemon = take_flag(&mut args, "--daemon");
    // Scans started over the REST API in this mode need payloads too.
    let collaborator = take_opt(&mut args, "--collaborator");
    let bambda_filter = take_opt(&mut args, "--bambda-filter");
    let bambda_column = take_opt(&mut args, "--bambda-column");
    let bambda_check_file = take_opt(&mut args, "--bambda-check");
    if !args.is_empty() {
        usage();
    }
    let shared = net::Shared::new();
    webprobe_core::scan_config::shared_config(&shared)
        .lock()
        .http
        .http2_enabled = http.http2_enabled;
    apply_scan_configs(&shared, &scan_configs);
    let collab_pump = collaborator.map(|server| start_collaborator(&shared, &server));
    if api.enabled {
        // Burp serves the REST API from the running app; for the headless
        // binary that is the long-lived proxy mode. The key is never
        // printed (Burp shows it in its UI; a headless process refuses to
        // start without one instead).
        let defs = report::KnowledgeBase::discover().rest_api_definitions();
        match rest_api::start(&shared, &api, defs) {
            Ok(api_address) => {
                eprintln!("REST API listening on {api_address}");
                shared.api_started.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    *shared.api_config.lock() = api;
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
    if seconds.is_none() && !daemon {
        let flag = stdin_closed.clone();
        webprobe_core::util::spawn_contained("webprobe-headless", move || {
            for _ in std::io::stdin().lock().lines() {}
            flag.store(true, Ordering::SeqCst);
        });
    }
    let mut printer = BambdaPrint::new(bambda_filter.as_deref(), bambda_column.as_deref());
    let check = BambdaPrint::load(bambda_check_file.as_deref(), Kind::PassiveCheck);
    let mut printed = 0usize;
    loop {
        // Copy the new rows out first: printing to a slow pipe must not hold
        // the history lock every proxy thread needs to record.
        let (fresh, total) = {
            let history = shared.history.snapshot();
            let total = history.len();
            (history.into_iter().skip(printed).collect::<Vec<_>>(), total)
        };
        printed = total;
        for row in printer.render(&fresh) {
            println!("{row}");
        }
        if let Some(check) = &check {
            bambda_check(&shared, check, &fresh);
        }
        let done = stdin_closed.load(Ordering::SeqCst)
            || seconds.is_some_and(|s| started.elapsed() >= Duration::from_secs(s));
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if let Some((until, pump)) = collab_pump {
        // One last poll and match before the issues are listed and saved.
        let _ = until.send(Instant::now() + Duration::from_secs(2));
        let _ = pump.join();
    }
    // AR-05: live audits run on their own thread; let the last ones finish
    // before the issues are listed and saved.
    if !shared.passive.wait_idle(Duration::from_secs(10)) {
        eprintln!("some passive audits were still running after 10 s; their issues are not listed");
    }
    let issues = shared.issues.lock().clone();
    for i in &issues {
        eprintln!("issue: {}", issue_json(i));
    }
    if let Some(path) = project_file {
        match save_project(&shared, &path) {
            Ok(()) => eprintln!(
                "saved {printed} exchange(s) and {} issue(s) to {path}",
                issues.len()
            ),
            Err(e) => {
                eprintln!("could not save {path}: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// AR-02: register with an interactsh server and run the worker that keeps
/// the engine's Collaborator payload pool stocked and raises the issues
/// interactions prove (the desktop frame loop's job in the GUI). Sending a
/// deadline on the returned channel makes the worker poll until then and
/// exit; dropping the sender ends it at once. Exits the process when the
/// server cannot be registered with.
fn start_collaborator(
    shared: &Arc<net::Shared>,
    server: &str,
) -> (
    std::sync::mpsc::Sender<Instant>,
    std::thread::JoinHandle<()>,
) {
    let mut state = webprobe_core::collaborator::CollaboratorState::new();
    let route = webprobe_core::interactsh::parse_server(server)
        .map(|(host, _)| shared.upstream_for(&host))
        .unwrap_or_else(|e| {
            eprintln!("--collaborator {server}: {e}");
            std::process::exit(1);
        });
    match state.start_remote(server, &route) {
        Ok(domain) => eprintln!("Collaborator payloads use {domain}"),
        Err(e) => {
            eprintln!("--collaborator {server}: {e}");
            std::process::exit(1);
        }
    }
    let (until_tx, until_rx) = std::sync::mpsc::channel::<Instant>();
    let shared = shared.clone();
    let pump = webprobe_core::util::spawn_contained("collaborator-pump", move || {
        let mut until: Option<Instant> = None;
        let mut last_poll = Instant::now();
        loop {
            match until_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(deadline) => until = Some(deadline),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if shared.oob.is_wanted() {
                shared.oob.refill(200, 500, || {
                    let p = state.generate_payload();
                    (p.token, p.dns_name)
                });
            }
            // Interactions arrive after the request that caused them.
            if until.is_some() && last_poll.elapsed() >= Duration::from_secs(1) {
                state.poll_now();
                last_poll = Instant::now();
            }
            scan::match_new_interactions(&shared, &state);
            if until.is_some_and(|deadline| Instant::now() >= deadline) {
                break;
            }
        }
    });
    (until_tx, pump)
}

fn scan_urls(mut args: Vec<String>) {
    let flags = take_burp_flags(&mut args);
    let (_listener, http, _api, scan_configs) = load_burp_configs(&flags);
    let crawl = take_flag(&mut args, "--crawl");
    let report_file = take_opt(&mut args, "--report");
    // AR-02: out-of-band checks need Collaborator payloads, which only the
    // desktop app used to mint. Opt-in: the scan contacts this server.
    let collaborator = take_opt(&mut args, "--collaborator");
    let collaborator_wait: u64 = take_opt(&mut args, "--collaborator-wait")
        .map(|s| s.parse().unwrap_or_else(|_| usage()))
        .unwrap_or(10);
    let bambda_check_file = take_opt(&mut args, "--bambda-check");
    // AR-02: keep the scan as a project the desktop app can open.
    let project_file = take_opt(&mut args, "--project");
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
    // A --config-file's http.http2.enable_http2 gates Hidden HTTP/2 here
    // too, not only in proxy mode.
    webprobe_core::scan_config::shared_config(&shared)
        .lock()
        .http
        .http2_enabled = http.http2_enabled;
    apply_scan_configs(&shared, &scan_configs);
    let pump = collaborator.map(|server| start_collaborator(&shared, &server));
    let started = Instant::now();
    scan::crawl_and_audit(&shared, &args, !crawl);
    // crawl_and_audit returns once the last item's audit has finished.
    shared.scan.wait_idle(None);
    // S-03: the custom passive check sees every exchange the scan recorded.
    if let Some(check) = BambdaPrint::load(bambda_check_file.as_deref(), Kind::PassiveCheck) {
        let mut seen = shared.history.snapshot();
        seen.extend(shared.crawl_items.snapshot());
        bambda_check(&shared, &check, &seen);
    }
    if let Some((until, pump)) = pump {
        eprintln!("waiting {collaborator_wait} s for Collaborator interactions");
        let _ = until.send(Instant::now() + Duration::from_secs(collaborator_wait));
        let _ = pump.join();
    }
    let issues = shared.issues.lock().clone();
    for i in &issues {
        println!("{}", issue_json(i));
    }
    eprintln!(
        "{} issue(s) in {:.1} s",
        issues.len(),
        started.elapsed().as_secs_f32()
    );
    if let Some(path) = &project_file {
        match save_project(&shared, path) {
            Ok(()) => eprintln!("saved the scan to {path}"),
            Err(e) => {
                eprintln!("could not save {path}: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(path) = report_file {
        let format = if path.to_ascii_lowercase().ends_with(".xml") {
            report::ReportFormat::Xml
        } else {
            report::ReportFormat::Html
        };
        let options = report::ReportOptions {
            format,
            ..Default::default()
        };
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
    webprobe_core::diagnostics::init_stderr();
    webprobe_core::register_runtime();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    // Burp's --data-dir and --diagnostics work before the subcommand.
    if let Some(dir) = take_opt(&mut args, "--data-dir") {
        // No threads exist yet, so setting the environment is race-free
        // here. paths::Lookup reads WEBPROBE_DATA_DIR at call time.
        // SAFETY: no worker threads exist yet.
        unsafe { std::env::set_var("WEBPROBE_DATA_DIR", &dir) };
    }
    if take_flag(&mut args, "--diagnostics") {
        println!("webprobe-headless {}", env!("CARGO_PKG_VERSION"));
        println!("os: {} {}", std::env::consts::OS, std::env::consts::ARCH);
        println!(
            "data dir: {}",
            webprobe_core::paths::Lookup::process().data_dir().display()
        );
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
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn hist_entry(id: u64) -> net::HistEntry {
        net::HistEntry {
            id,
            method: "GET".into(),
            host: "example.test".into(),
            path: "/".into(),
            status: "200".into(),
            req_raw: webprobe_core::body::Body::from(&b"GET / HTTP/1.1\r\n\r\n"[..]),
            ..net::HistEntry::default()
        }
    }

    /// R-16: the two Bambda flags are consumed like every other option, and a
    /// missing script file leaves the run unfiltered instead of aborting it.
    #[test]
    fn bambda_flags_are_consumed_and_a_broken_script_does_not_stop_the_run() {
        let mut args = strings(&[
            "--bambda-filter",
            "f.bambda",
            "--bambda-column",
            "c.bambda",
            "--seconds",
            "2",
        ]);
        assert_eq!(
            take_opt(&mut args, "--bambda-filter").as_deref(),
            Some("f.bambda")
        );
        assert_eq!(
            take_opt(&mut args, "--bambda-column").as_deref(),
            Some("c.bambda")
        );
        assert_eq!(args, strings(&["--seconds", "2"]));

        let missing = std::env::temp_dir().join("webprobe-r16-missing.bambda");
        let mut print = BambdaPrint::new(Some(missing.to_str().unwrap()), None);
        assert!(print.filter.is_none());
        assert_eq!(
            print.render(&[hist_entry(1), hist_entry(2)]),
            vec![
                "1\tGET\thttp://example.test\t/\t200".to_string(),
                "2\tGET\thttp://example.test\t/\t200".to_string()
            ]
        );
    }

    #[test]
    fn bambda_cell_text_shows_values_and_row_errors() {
        assert_eq!(cell_text(Some(&Cell::Text("fixture".into()))), "fixture");
        assert_eq!(cell_text(Some(&Cell::Failed("boom".into()))), "Error: boom");
        assert_eq!(cell_text(None), "");
    }

    #[test]
    fn burp_command_first_ignores_flag_values() {
        // a flag value that happens to be `proxy` is not the command word
        let mut args = strings(&["--config-file", "proxy", "scan"]);
        burp_command_first(&mut args);
        assert_eq!(args, ["scan", "--config-file", "proxy"]);
        // flags before the command rotate as Burp allows
        let mut args = strings(&["--unpause-spider-and-scanner", "proxy"]);
        burp_command_first(&mut args);
        assert_eq!(args, ["proxy", "--unpause-spider-and-scanner"]);
        // no command word: untouched
        let mut args = strings(&["--config-file", "scan"]);
        burp_command_first(&mut args);
        assert_eq!(args, ["--config-file", "scan"]);
    }

    /// Burp's repeatable config flags collect in order (last wins on
    /// apply) and are removed from the remaining arguments.
    #[test]
    fn burp_flags_are_repeatable_and_ordered() {
        let mut args = strings(&[
            "--config-file",
            "a.json",
            "--crawl",
            "--config-file",
            "b.json",
            "--user-config-file",
            "u.json",
            "--unpause-spider-and-scanner",
            "http://x/",
        ]);
        let flags = take_burp_flags(&mut args);
        assert_eq!(
            flags.config_files,
            vec!["a.json".to_string(), "b.json".to_string()]
        );
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
        std::fs::write(
            &f,
            r#"{"proxy": {"request_listeners": [{"listener_port": 9091}]}, "scanner": {"insertion_point_types": {"insert_cookies": false}}}"#,
        )
        .unwrap();
        let mut args = strings(&["--config-file", f.to_str().unwrap()]);
        let flags = take_burp_flags(&mut args);
        let (listener, _http, _api, configs) = load_burp_configs(&flags);
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
        let project_file = take_project_file(&mut args);
        assert_eq!(project_file.as_deref(), Some("second.burp"));
        assert!(args.is_empty());
        let mut args = strings(&["--project-file", "first.burp", "--project", "second.burp"]);
        assert_eq!(take_project_file(&mut args).as_deref(), Some("second.burp"));
        assert!(args.is_empty());
        let mut args = strings(&["--project", "a", "--project", "b", "--project-file", "c"]);
        assert_eq!(take_project_file(&mut args).as_deref(), Some("c"));
        assert!(args.is_empty());
    }
}

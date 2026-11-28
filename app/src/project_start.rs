//! Choosing a project: the start window shown at launch and the Project
//! menu's New / Open / Recent items (Burp's startup wizard: temporary
//! project, new project on disk, open existing, recent list).

use eframe::egui::{self, RichText, Ui};
use webprobe_core::project_files;

use crate::App;
use crate::feedback::{self, Level};
use crate::theme;

/// State of the project chooser.
#[derive(Default)]
pub struct Chooser {
    pub open: bool,
    /// Shown at launch (adds "Continue with the current project").
    pub at_start: bool,
    path: String,
    checked: Option<(String, Result<project_files::Summary, String>)>,
}

fn after_switch(app: &mut App, path: &str, what: &str) {
    app.hist_cache_key.clear();
    app.site_cache_key.clear();
    app.history_sel = None;
    project_files::note_used(path);
    app.project_status = what.to_string();
    feedback::toast(Level::Success, format!("{what}: {path}"));
}

/// Save the session being left, when it has somewhere to go. A failed save
/// fails the switch: the current project keeps its contents and path.
/// WEBPROBE_NO_AUTOSAVE stays a deliberate opt-out and never blocks a switch.
fn save_current(app: &mut App) -> Result<(), String> {
    if std::env::var_os("WEBPROBE_NO_AUTOSAVE").is_some() {
        return Ok(());
    }
    crate::tools::save_project(app, true)
        .map_err(|e| format!("the current project could not be saved ({e})"))
}

/// Open an existing project after checking it. A damaged file is refused and
/// the current session is left as it was. The destination is loaded into
/// memory before anything about the running session changes; only an open
/// that checked, saved and loaded successfully switches over. The save runs
/// before the load so that opening the file that is already current loads
/// what the save just wrote, not the older on-disk state.
pub fn open(app: &mut App, path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    project_files::check(p)?;
    save_current(app)?;
    let data = webprobe_core::project::load(p).map_err(|e| format!("{path}: {e}"))?;
    app.project_path = path.to_string();
    crate::tools::apply_project(app, &data, true);
    after_switch(app, path, "Opened project");
    Ok(())
}

/// Something is at `path`, a dangling symlink included (a save would write
/// through it).
fn taken(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `path` as an absolute path with its directory resolved, for comparing two
/// spellings of one file whether or not the file exists.
fn resolved(path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    if let Ok(full) = abs.canonicalize() {
        return full;
    }
    match (abs.parent(), abs.file_name()) {
        (Some(dir), Some(name)) => dir
            .canonicalize()
            .unwrap_or_else(|_| dir.to_path_buf())
            .join(name),
        _ => abs,
    }
}

/// Start an empty project saved at `path` (or a temporary one when `None`).
/// The destination is checked and the current session saved before anything
/// is replaced; a refused path or a failed save leaves the running session
/// as it is (contents and path).
pub fn new_project(app: &mut App, path: Option<&str>) -> Result<(), String> {
    if let Some(p) = path {
        // Compared as resolved paths: "./x.json" and "x.json" are one file,
        // also when it does not exist yet.
        if resolved(p) == resolved(&app.project_path) {
            return Err(format!("{p} is the current project"));
        }
        if taken(p) {
            return Err(format!(
                "{p} already exists: open it instead, or choose another name"
            ));
        }
    }
    save_current(app)?;
    // Saving the outgoing session may have created the destination (an
    // unseen alias of the current path, or another process in between).
    if let Some(p) = path
        && taken(p)
    {
        return Err(format!(
            "{p} already exists: open it instead, or choose another name"
        ));
    }
    // Claim the destination atomically before the session is replaced: if
    // another process created it since the check, this fails and nothing has
    // changed. Later saves replace this file, which is now ours.
    if let Some(p) = path {
        webprobe_core::project::save_new(
            std::path::Path::new(p),
            &webprobe_core::project::ProjectData::default(),
        )
        .map_err(|e| format!("{p} could not be created ({e})"))?;
    }
    let target = match path {
        Some(p) => p.to_string(),
        None => std::env::temp_dir()
            .join(format!(
                "webprobe-temporary-{}-{}.json",
                std::process::id(),
                webprobe_core::util::now_secs()
            ))
            .display()
            .to_string(),
    };
    // A new project replaces the session, unlike settings import/defaults,
    // which deliberately keep traffic and tool contents.
    crate::tools::apply_project(app, &webprobe_core::project::ProjectData::default(), true);
    // Cross-response passive state (password tracking) is per project.
    app.shared.passive.clear();
    app.project_path = target.clone();
    if path.is_some() {
        // The switch has happened, so a failed first save can only be
        // reported, not aborted.
        let _ = crate::tools::save_project(app, true);
        after_switch(app, &target, "New project");
    } else {
        app.hist_cache_key.clear();
        app.site_cache_key.clear();
        app.history_sel = None;
        app.project_status = "temporary project".into();
        feedback::toast(Level::Success, "Temporary project started");
    }
    Ok(())
}

/// What the start dialog asks the app to do next.
type StartAction = Box<dyn FnOnce(&mut App) -> Result<(), String>>;

fn summary_line(s: &project_files::Summary) -> String {
    format!(
        "{} request(s), {} issue(s), {} Repeater tab(s); saved {}; {} KB",
        s.history,
        s.issues,
        s.repeater_tabs,
        if s.saved_at > 0 {
            crate::ui::history_time(s.saved_at)
        } else {
            "unknown".into()
        },
        s.bytes / 1024
    )
}

pub fn window(app: &mut App, ctx: &egui::Context) {
    if !app.chooser.open {
        return;
    }
    let mut shown = true;
    let mut action: Option<StartAction> = None;
    let title = if app.chooser.at_start {
        "Welcome to WebProbe"
    } else {
        "Project"
    };
    egui::Window::new(title)
        .open(&mut shown)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, |ui: &mut Ui| {
            ui.set_width(560.0);
            if app.chooser.at_start {
                ui.label(RichText::new("Current project").strong());
                ui.monospace(&app.project_path);
                if ui.button("Continue with this project").clicked() {
                    action = Some(Box::new(|_| Ok(())));
                }
                ui.separator();
            }
            if ui
                .button("Temporary project")
                .on_hover_text("Nothing is saved unless you save the project later")
                .clicked()
            {
                action = Some(Box::new(|app| new_project(app, None)));
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new("New project on disk, or open an existing project file").strong(),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.chooser.path)
                        .hint_text("/path/to/project.json")
                        .desired_width(330.0)
                        .font(egui::TextStyle::Monospace),
                );
                let path = app.chooser.path.trim().to_string();
                if ui
                    .add_enabled(!path.is_empty(), egui::Button::new("Check"))
                    .clicked()
                {
                    let r = project_files::check(std::path::Path::new(&path));
                    app.chooser.checked = Some((path.clone(), r));
                }
                if ui
                    .add_enabled(!path.is_empty(), egui::Button::new("Open"))
                    .clicked()
                {
                    let p = path.clone();
                    action = Some(Box::new(move |app| open(app, &p)));
                }
                if ui
                    .add_enabled(!path.is_empty(), egui::Button::new("New"))
                    .clicked()
                {
                    let p = path.clone();
                    action = Some(Box::new(move |app| new_project(app, Some(&p))));
                }
            });
            if let Some((p, r)) = &app.chooser.checked {
                let (text, colour) = match r {
                    Ok(s) => (format!("{p}: {}", summary_line(s)), theme::ink_dim()),
                    Err(e) => (e.clone(), crate::theme::c(theme::BAD)),
                };
                ui.label(RichText::new(text).size(12.0).color(colour));
            }
            let recent = project_files::recent_file()
                .map(|f| project_files::load_recent(&f))
                .unwrap_or_default();
            if !recent.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("Recent projects").strong());
                for p in recent {
                    let exists = std::path::Path::new(&p).is_file();
                    ui.horizontal(|ui| {
                        let label = RichText::new(&p).monospace().size(12.0).color(if exists {
                            theme::ink()
                        } else {
                            theme::ink_hint()
                        });
                        if ui
                            .add_enabled(exists, egui::Button::new(label).frame(false))
                            .on_disabled_hover_text("The file is no longer there")
                            .clicked()
                        {
                            let path = p.clone();
                            action = Some(Box::new(move |app| open(app, &path)));
                        }
                    });
                }
            }
        });
    if let Some(f) = action {
        match f(app) {
            Ok(()) => {
                app.chooser.open = false;
                app.chooser.checked = None;
            }
            Err(e) => feedback::toast(Level::Error, e),
        }
    } else if !shown {
        app.chooser.open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{logger, net, project, scan};

    fn session_with_traffic(name: &str) -> (App, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("wp-project-start-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut app = App::new(net::Shared::in_memory());
        app.project_path = dir.join("original.json").display().to_string();
        app.shared.push_history(net::HistEntry {
            id: 77,
            host: "previous-project.test".into(),
            ..Default::default()
        });
        app.shared.issues.lock().push(scan::ScanIssue {
            id: 78,
            name: "previous finding".into(),
            ..Default::default()
        });
        app.logger.push(logger::LogEntry {
            host: "previous-project.test".into(),
            ..Default::default()
        });
        app.shared.repeaters.lock().push(net::RepTab {
            id: 79,
            name: "previous request".into(),
            host: "previous-project.test".into(),
            port: 80,
            https: false,
            request: "GET / HTTP/1.1\r\nHost: previous-project.test\r\n\r\n".into(),
            response: None,
            result_line: String::new(),
            history: Vec::new(),
            hist_pos: 0,
            response_sources: Vec::new(),
            ws: None,
        });
        app.shared.tasks.lock().push(crate::tasks::ScanTask {
            id: 80,
            name: "previous scan".into(),
            kind: crate::tasks::TaskKind::Audit(Vec::new()),
            state: crate::tasks::TaskState::Paused,
            done: 0,
            total: Some(0),
            issues_found: 0,
            created: 0,
            finished: None,
        });
        app.log_sel = Some(1);
        app.log_seen = 77;
        app.decoder.input = "previous secret".into();
        app.history_sel = Some(77);
        (app, dir)
    }

    fn assert_empty_session(app: &App) {
        assert!(
            app.shared.history.snapshot().is_empty(),
            "new project inherited HTTP history"
        );
        assert!(
            app.shared.issues.lock().is_empty(),
            "new project inherited findings"
        );
        assert!(
            app.logger.entries.is_empty(),
            "project inherited Logger rows"
        );
        assert!(app.shared.repeaters.lock().is_empty());
        assert!(app.shared.tasks.lock().is_empty());
        assert!(app.log_sel.is_none());
        assert_eq!(app.log_seen, 0);
        assert!(
            app.decoder.input.is_empty(),
            "project inherited editor contents"
        );
        assert!(app.history_sel.is_none());
    }

    #[test]
    fn new_disk_project_does_not_inherit_session_data() {
        let (mut app, dir) = session_with_traffic("new-disk");
        let target = dir.join("new.json");
        new_project(&mut app, Some(target.to_str().unwrap())).unwrap();
        assert_empty_session(&app);
        let saved = project::load(&target).unwrap();
        assert!(saved.history.is_empty());
        assert!(saved.issues.is_empty());
        assert!(saved.logger.is_empty());
        assert!(saved.repeaters.is_empty());
        assert!(saved.tasks.scans.is_empty());
        let original = project::load(&dir.join("original.json")).unwrap();
        assert_eq!(
            original.history.len(),
            1,
            "previous session saved before switching"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn temporary_project_does_not_inherit_session_data() {
        let (mut app, dir) = session_with_traffic("new-temporary");
        new_project(&mut app, None).unwrap();
        assert_empty_session(&app);
        assert_eq!(app.project_status, "temporary project");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn opening_empty_project_clears_previous_logger() {
        let (mut app, dir) = session_with_traffic("open-empty");
        let target = dir.join("empty.json");
        project::save(&target, &project::ProjectData::default()).unwrap();
        open(&mut app, target.to_str().unwrap()).unwrap();
        assert_empty_session(&app);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A path `save` cannot write: its parent is a regular file, so the
    /// temporary file cannot be created.
    fn unsaveable_path(dir: &std::path::Path) -> String {
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        blocker.join("original.json").display().to_string()
    }

    #[test]
    fn new_project_aborts_when_current_session_cannot_be_saved() {
        let (mut app, dir) = session_with_traffic("new-abort");
        let target = dir.join("new.json");
        app.project_path = unsaveable_path(&dir);
        let err = new_project(&mut app, Some(target.to_str().unwrap())).unwrap_err();
        assert!(
            err.contains("could not be saved"),
            "unexpected error: {err}"
        );
        assert!(app.project_path.ends_with("original.json"));
        assert_eq!(
            app.shared.history.snapshot().len(),
            1,
            "session contents changed after the refused switch"
        );
        assert!(!target.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn open_aborts_when_current_session_cannot_be_saved() {
        let (mut app, dir) = session_with_traffic("open-abort");
        let target = dir.join("empty.json");
        project::save(&target, &project::ProjectData::default()).unwrap();
        app.project_path = unsaveable_path(&dir);
        let err = open(&mut app, target.to_str().unwrap()).unwrap_err();
        assert!(
            err.contains("could not be saved"),
            "unexpected error: {err}"
        );
        assert!(app.project_path.ends_with("original.json"));
        assert_eq!(
            app.shared.history.snapshot().len(),
            1,
            "session contents changed after the refused switch"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn new_project_refuses_existing_destination_before_saving() {
        let (mut app, dir) = session_with_traffic("new-exists");
        let target = dir.join("new.json");
        project::save(&target, &project::ProjectData::default()).unwrap();
        let err = new_project(&mut app, Some(target.to_str().unwrap())).unwrap_err();
        assert!(err.contains("already exists"), "unexpected error: {err}");
        // The refusal happens before the leaving-save: the current project
        // file was never written.
        assert!(
            !std::path::Path::new(&app.project_path).exists(),
            "a refused switch still saved the session"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn new_project_checks_destination_before_attempting_save() {
        let (mut app, dir) = session_with_traffic("new-exists-unsaveable");
        let target = dir.join("new.json");
        project::save(&target, &project::ProjectData::default()).unwrap();
        // The current session cannot be saved, so the refusal proves the
        // destination check runs before the save attempt.
        app.project_path = unsaveable_path(&dir);
        let err = new_project(&mut app, Some(target.to_str().unwrap())).unwrap_err();
        assert!(err.contains("already exists"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn new_project_refuses_the_current_path() {
        let (mut app, dir) = session_with_traffic("new-same");
        let current = app.project_path.clone();
        let err = new_project(&mut app, Some(&current)).unwrap_err();
        assert!(err.contains("current project"), "unexpected error: {err}");
        assert_eq!(app.shared.history.snapshot().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}

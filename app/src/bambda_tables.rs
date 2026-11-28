//! R-16: Bambda filters and custom columns applied to the History, Logger and
//! WebSocket tables.
//!
//! A table's filter and column are independent runs. Each one compiles and
//! evaluates the chosen saved script over a bounded snapshot of the table in a
//! worker thread, never on the UI or proxy thread. A failed run keeps the last
//! good result and shows the diagnostic; rows the run did not see stay visible,
//! so a user's script can never hide traffic it was not given.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use eframe::egui::{self, RichText, Ui};

use webprobe_core::bambda::{Cell, Kind, Outcome, Program, Verdict};
use webprobe_core::bambda_library::{Function, Script};
use webprobe_core::bambda_rows::{Snapshot, Stamp};

const COMPILE_DEADLINE: Duration = Duration::from_secs(15);
const BATCH_DEADLINE: Duration = Duration::from_secs(10);
/// One application covers at most `MAX_TABLE_ROWS` rows, five per batch, so a
/// per-batch deadline alone would let a uniformly slow script hold the worker
/// for minutes. The whole run gets this instead.
const TOTAL_DEADLINE: Duration = Duration::from_secs(60);

/// A run publishes a distinct version, so a view can key its row cache on it.
static NEXT_VERSION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Table {
    History,
    Logger,
    Websocket,
}

impl Table {
    pub fn label(self) -> &'static str {
        match self {
            Self::History => "HTTP history",
            Self::Logger => "Logger",
            Self::Websocket => "WebSockets history",
        }
    }
}

/// A saved script chosen for one slot, with the source text it will run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub id: String,
    pub name: String,
    pub source: String,
    pub function: Function,
}

impl Choice {
    fn of(script: &Script) -> Self {
        Self {
            id: script.id.clone(),
            name: script.name.clone(),
            source: script.source.clone(),
            function: script.function,
        }
    }
}

/// One successful run.
#[derive(Debug)]
pub struct Applied {
    pub label: String,
    pub kind: Kind,
    pub stamp: Stamp,
    /// Rows the script saw.
    pub rows: usize,
    /// Rows left out because one exchange was larger than a whole batch.
    pub skipped: usize,
    pub row_errors: usize,
    pub version: u64,
    verdicts: HashMap<u64, Verdict>,
    cells: HashMap<u64, Cell>,
}

impl Applied {
    fn from_outcome(kind: Kind, label: String, stamp: Stamp, outcome: Outcome) -> Self {
        Self {
            label,
            kind,
            stamp,
            rows: outcome.verdicts.len().max(outcome.cells.len()),
            skipped: outcome.skipped.len(),
            row_errors: outcome.row_errors,
            version: NEXT_VERSION.fetch_add(1, Ordering::Relaxed),
            verdicts: outcome.verdicts.into_iter().collect(),
            cells: outcome.cells.into_iter().collect(),
        }
    }

    /// Whether the table keeps this row. Rows the run did not evaluate (newer
    /// than the snapshot, older than its window, oversized, or a script error)
    /// are kept: a filter never hides what it did not judge.
    pub fn keeps(&self, id: u64) -> bool {
        !matches!(self.verdicts.get(&id), Some(Verdict::Hide))
    }

    pub fn cell(&self, id: u64) -> Option<&Cell> {
        self.cells.get(&id)
    }

    /// Rows the filter hides.
    pub fn hidden(&self) -> usize {
        self.verdicts
            .values()
            .filter(|v| **v == Verdict::Hide)
            .count()
    }
}

/// What one slot shows under the table: the choice, the last good run, the
/// last diagnostic, and the run in flight.
pub struct Slot {
    pub choice: Option<Choice>,
    /// The user acknowledged that this script runs with their files and
    /// network, as the library requires before a preview. Cleared whenever the
    /// picture of what will run changes.
    pub trusted: bool,
    applied: Option<Arc<Applied>>,
    /// Last failure. A later success clears it; the previous run stays applied.
    pub error: Option<String>,
    busy: bool,
    pending: Option<mpsc::Receiver<Result<Applied, String>>>,
    cancelled: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            choice: None,
            trusted: false,
            applied: None,
            error: None,
            busy: false,
            pending: None,
            cancelled: Arc::new(AtomicBool::new(false)),
            worker: None,
        }
    }
}

impl Slot {
    pub fn applied(&self) -> Option<&Arc<Applied>> {
        self.applied.as_ref()
    }

    pub fn busy(&self) -> bool {
        self.busy
    }

    /// Forget the run and stop any worker: the table goes back to unfiltered.
    pub fn reset(&mut self) {
        self.cancel();
        self.applied = None;
        self.error = None;
        self.trusted = false;
    }

    /// The user picked another script: what Apply would run changed, so the
    /// acknowledgement and the last diagnostic no longer apply. The run on
    /// screen stays until a replacement succeeds.
    fn repicked(&mut self) {
        self.trusted = false;
        self.error = None;
    }

    /// Re-read the chosen script from the library as it is now. A script saved
    /// again after it was picked must run its current source, and one deleted
    /// or turned into the other function must not run at all.
    fn refresh(&mut self, scripts: &[Script]) -> bool {
        let Some(choice) = self.choice.as_ref() else {
            return true;
        };
        let Some(script) = scripts.iter().find(|s| s.id == choice.id) else {
            self.error = Some(format!(
                "\"{}\": that script is no longer in the Bambda library. Pick it again or pick another.",
                choice.name
            ));
            return false;
        };
        if script.function != choice.function {
            self.error = Some(format!(
                "\"{}\" is now a {}; this picker runs a {}. Pick another script.",
                choice.name,
                script.function.label(),
                choice.function.label()
            ));
            return false;
        }
        self.choice = Some(Choice::of(script));
        true
    }

    /// Stop the run in flight and wait for its worker. Cancellation is checked
    /// every few milliseconds by the evaluator, so this is short.
    fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.pending = None;
        self.busy = false;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    fn start(&mut self, table: Table, snapshot: Snapshot, ctx: egui::Context) {
        self.cancel();
        let Some(choice) = self.choice.clone() else {
            return;
        };
        self.cancelled = Arc::new(AtomicBool::new(false));
        let cancelled = self.cancelled.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        self.pending = Some(rx);
        self.busy = true;
        let kind = choice.function.kind();
        let label = choice.name.clone();
        let worker_name = match table {
            Table::History => "bambda-history",
            Table::Logger => "bambda-logger",
            Table::Websocket => "bambda-websocket",
        };
        self.worker = Some(webprobe_core::util::spawn_contained(
            worker_name,
            move || {
                let result = run(&choice, &snapshot, cancelled)
                    .map(|outcome| Applied::from_outcome(kind, label, snapshot.stamp, outcome));
                let _ = tx.send(result);
                ctx.request_repaint();
            },
        ));
    }

    fn poll(&mut self) {
        let Some(rx) = self.pending.as_ref() else {
            return;
        };
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err(
                "The Bambda worker ended without a result. The previous run, if any, is unchanged."
                    .into(),
            ),
        };
        self.busy = false;
        self.pending = None;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.publish(result);
    }

    /// Apply one finished run: a failure is reported and the last good run is
    /// kept (the same rule as the library preview).
    fn publish(&mut self, result: Result<Applied, String>) {
        match result {
            Ok(applied) => {
                self.applied = Some(Arc::new(applied));
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Compile and evaluate one saved script over a table snapshot.
fn run(
    choice: &Choice,
    snapshot: &Snapshot,
    cancelled: Arc<AtomicBool>,
) -> Result<Outcome, String> {
    let kind = choice.function.kind();
    if snapshot.rows.is_empty() {
        // Compile anyway: a syntax error must still be reported with no rows.
        let _ = compile(choice, cancelled)?;
        return Ok(Outcome::interpret(
            kind,
            Vec::new(),
            snapshot.skipped.clone(),
        ));
    }
    let program = compile(choice, cancelled)?;
    let mut outcome = program
        .apply(&snapshot.rows, BATCH_DEADLINE, TOTAL_DEADLINE)
        .map_err(|e| e.to_string())?;
    outcome.skipped.extend(snapshot.skipped.iter().copied());
    Ok(outcome)
}

fn compile(choice: &Choice, cancelled: Arc<AtomicBool>) -> Result<Program, String> {
    let java = webprobe_core::paths::java().map_err(|e| e.to_string())?;
    let api = webprobe_core::paths::montoya_jar().map_err(|e| e.to_string())?;
    Program::compile_cancellable(
        &java,
        &api,
        choice.function.kind(),
        &choice.source,
        COMPILE_DEADLINE,
        cancelled,
    )
    .map_err(|e| e.to_string())
}

/// A table's two slots.
#[derive(Default)]
pub struct TableApply {
    pub filter: Slot,
    pub column: Slot,
}

impl TableApply {
    pub fn poll(&mut self) {
        self.filter.poll();
        self.column.poll();
    }

    /// Combine the existing views' own filtering with the Bambda verdict.
    pub fn keeps(&self, id: u64) -> bool {
        self.filter.applied.as_ref().is_none_or(|a| a.keeps(id))
    }

    /// Changes whenever the filter result changes: row caches key on it.
    pub fn filter_version(&self) -> u64 {
        self.filter.applied.as_ref().map_or(0, |a| a.version)
    }

    pub fn column_version(&self) -> u64 {
        self.column.applied.as_ref().map_or(0, |a| a.version)
    }

    /// Heading of the custom column, while one is applied.
    pub fn column_label(&self) -> Option<&str> {
        self.column.applied.as_ref().map(|a| a.label.as_str())
    }

    pub fn cell(&self, id: u64) -> Option<&Cell> {
        self.column.applied.as_ref().and_then(|a| a.cell(id))
    }

    /// The column run as an owned handle: a view whose closure captures the
    /// whole `App` cannot also hold a borrow of it.
    pub fn column_run(&self) -> Option<Arc<Applied>> {
        self.column.applied.clone()
    }
}

/// Every table's slots. Lives in the Bambda tool's state slot (`App::bambdas`),
/// so wiring the tables needs no new `App` field (ADR 0002).
#[derive(Default)]
pub struct Tables {
    pub history: TableApply,
    pub logger: TableApply,
    pub websocket: TableApply,
}

impl Tables {
    /// Forget every run. Results are keyed by row id, and a project's rows are
    /// not another project's rows: a loaded project must never inherit a
    /// verdict or a column value for a row that happens to carry the same id.
    pub fn reset_all(&mut self) {
        for table in [&mut self.history, &mut self.logger, &mut self.websocket] {
            table.filter.reset();
            table.column.reset();
        }
    }
}

/// The one-line Bambda control under a table's own filter bar. `snapshot` is
/// called only when the user presses Apply.
pub fn bar(
    ui: &mut Ui,
    table: Table,
    apply: &mut TableApply,
    scripts: &[Script],
    current: Stamp,
    snapshot: impl FnOnce() -> Snapshot,
) {
    apply.poll();
    let mut snapshot = Some(snapshot);
    let mut run = false;
    let mut picked = [Pick::Unchanged; 2];
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(format!("Bambda ({}):", table.label()))
                .size(12.0)
                .color(crate::theme::ink_dim()),
        );
        picked[0] = picker(
            ui,
            ("bambda_filter_pick", table),
            &mut apply.filter.choice,
            scripts,
            Function::ViewFilter,
            "Filter: none",
        );
        picked[1] = picker(
            ui,
            ("bambda_column_pick", table),
            &mut apply.column.choice,
            scripts,
            Function::CustomColumn,
            "Column: none",
        );
        // The library asks for this before it compiles a preview; a table run
        // executes the same code, so it asks once per selected script.
        for slot in [&mut apply.filter, &mut apply.column] {
            if slot.choice.is_some() {
                ui.checkbox(&mut slot.trusted, "trusted")
                    .on_hover_text(
                        "Bambda code runs with your files and network. Tick to allow this script to run.",
                    );
            }
        }
        let wanted = [&apply.filter, &apply.column]
            .into_iter()
            .filter(|slot| slot.choice.is_some())
            .collect::<Vec<_>>();
        let chosen = !wanted.is_empty();
        let trusted = wanted.iter().all(|slot| slot.trusted);
        let busy = apply.filter.busy() || apply.column.busy();
        if ui
            .add_enabled(
                chosen && trusted && !busy,
                egui::Button::new(if busy { "Applying\u{2026}" } else { "Apply" }),
            )
            .on_hover_text(
                "Compiles and runs the saved script in a separate JVM. Bambda code can read your files and network.",
            )
            .clicked()
        {
            run = true;
        }
        if busy {
            ui.spinner();
            if ui.button("Cancel").clicked() {
                apply.filter.cancel();
                apply.column.cancel();
            }
        }
        if !scripts
            .iter()
            .any(|s| s.function == Function::ViewFilter)
            || !scripts
                .iter()
                .any(|s| s.function == Function::CustomColumn)
        {
            ui.label(
                RichText::new("Save scripts in Extensions > Bambda library.")
                    .size(12.0)
                    .color(crate::theme::ink_hint()),
            );
        }
    });
    for (pick, slot) in picked
        .into_iter()
        .zip([&mut apply.filter, &mut apply.column])
    {
        match pick {
            // An explicit "none" is the way to take a run off a table.
            Pick::None => slot.reset(),
            Pick::Script => slot.repicked(),
            Pick::Unchanged => {}
        }
    }
    // Only a bar the user pressed Apply in produces a snapshot: a table that
    // merely displays a run never pays for one.
    if run && let Some(make_snapshot) = snapshot.take() {
        // Resolve the picked scripts against the library as it is now, so a
        // script saved again runs its new source and a deleted one is reported.
        let filter_ready = apply.filter.refresh(scripts);
        let column_ready = apply.column.refresh(scripts);
        let snapshot = make_snapshot();
        let ctx = ui.ctx().clone();
        if filter_ready && apply.filter.choice.is_some() {
            apply.filter.start(table, snapshot.clone(), ctx.clone());
        }
        if column_ready && apply.column.choice.is_some() {
            apply.column.start(table, snapshot, ctx);
        }
    }
    summary(ui, apply, current);
}

/// What the user did with a picker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pick {
    Unchanged,
    /// "none" was chosen: the table goes back to unfiltered.
    None,
    /// Another script was chosen: the run on screen stays until Apply.
    Script,
}

/// A "none / saved scripts of this function" picker.
fn picker(
    ui: &mut Ui,
    id: (&'static str, Table),
    choice: &mut Option<Choice>,
    scripts: &[Script],
    function: Function,
    none_text: &str,
) -> Pick {
    let mut pick = Pick::Unchanged;
    let selected = choice
        .as_ref()
        .map_or_else(|| none_text.to_string(), |c| c.name.clone());
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected)
        .width(150.0)
        .show_ui(ui, |ui| {
            if ui.selectable_label(choice.is_none(), none_text).clicked() {
                *choice = None;
                pick = Pick::None;
            }
            for script in scripts.iter().filter(|s| s.function == function) {
                let selected = choice.as_ref().is_some_and(|c| c.id == script.id);
                if ui.selectable_label(selected, &script.name).clicked() {
                    *choice = Some(Choice::of(script));
                    pick = Pick::Script;
                }
            }
        });
    pick
}

fn summary(ui: &mut Ui, apply: &TableApply, current: Stamp) {
    let mut line = String::new();
    for (slot, noun) in [(&apply.filter, "Filter"), (&apply.column, "Column")] {
        let Some(applied) = slot.applied() else {
            continue;
        };
        if !line.is_empty() {
            line.push_str("   ");
        }
        line.push_str(&format!(
            "{noun} \"{}\": {} row(s) evaluated",
            applied.label, applied.rows
        ));
        if applied.kind == Kind::Filter {
            line.push_str(&format!(", {} hidden", applied.hidden()));
        }
        if applied.skipped > 0 {
            line.push_str(&format!(", {} oversized skipped", applied.skipped));
        }
        if applied.row_errors > 0 {
            line.push_str(&format!(", {} row error(s)", applied.row_errors));
        }
    }
    if !line.is_empty() {
        ui.label(
            RichText::new(line)
                .size(12.0)
                .color(crate::theme::ink_dim()),
        );
    }
    // Rows that arrived after the run are shown but not filtered silently.
    for slot in [&apply.filter, &apply.column] {
        let Some(applied) = slot.applied() else {
            continue;
        };
        if applied.stamp != current {
            // A table at its retention cap replaces rows without growing, so
            // the difference can be zero while rows were replaced.
            let newer = current.rows.saturating_sub(applied.stamp.rows);
            let text = if newer > 0 {
                format!("{newer} row(s) changed since this run; Apply again to include them")
            } else {
                "The table changed since this run; Apply again to include it".to_string()
            };
            ui.label(
                RichText::new(text)
                    .size(12.0)
                    .color(crate::theme::ink_hint()),
            );
            break;
        }
    }
    for slot in [&apply.filter, &apply.column] {
        if let Some(error) = &slot.error {
            ui.label(
                RichText::new(error)
                    .size(12.0)
                    .color(crate::theme::c(crate::theme::BAD)),
            );
            ui.label(
                RichText::new(
                    "The table below is unchanged: a failed Bambda never replaces a good run.",
                )
                .size(12.0)
                .color(crate::theme::ink_hint()),
            );
        }
    }
}

/// Text for one custom-column cell.
pub fn cell_text(cell: Option<&Cell>) -> String {
    match cell {
        Some(Cell::Text(text)) => text.clone(),
        Some(Cell::Failed(error)) => format!("Error: {error}"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(kind: Kind, stamp: Stamp, outcome: Outcome) -> Applied {
        Applied::from_outcome(kind, "fixture".into(), stamp, outcome)
    }

    /// A table whose one slot holds a finished run.
    fn run_on(kind: Kind, applied: Applied) -> TableApply {
        assert_eq!(applied.kind, kind);
        let mut slot = Slot::default();
        slot.applied = Some(Arc::new(applied));
        let mut apply = TableApply::default();
        if kind == Kind::Filter {
            apply.filter = slot;
        } else {
            apply.column = slot;
        }
        apply
    }

    fn filter_run(hide: &[u64], failed: &[u64], rows: usize) -> Applied {
        let mut outcome = Outcome::default();
        for id in 0..rows as u64 {
            let verdict = if hide.contains(&id) {
                Verdict::Hide
            } else if failed.contains(&id) {
                Verdict::Failed
            } else {
                Verdict::Pass
            };
            outcome.verdicts.push((id, verdict));
        }
        applied(Kind::Filter, Stamp { rows, last_id: 0 }, outcome)
    }

    #[test]
    fn a_filter_hides_only_rows_it_judged_and_keeps_errors_visible() {
        let apply = run_on(Kind::Filter, filter_run(&[2, 4], &[3], 6));
        assert!(apply.keeps(0));
        assert!(apply.keeps(1));
        assert!(!apply.keeps(2), "a false verdict hides the row");
        assert!(apply.keeps(3), "a row error stays visible");
        assert!(!apply.keeps(4));
        // A row outside the evaluated window is shown untouched.
        assert!(apply.keeps(99));
        assert_eq!(apply.filter.applied().unwrap().hidden(), 2);
    }

    #[test]
    fn with_no_run_every_row_is_kept() {
        let apply = TableApply::default();
        assert!(apply.keeps(1));
        assert_eq!(apply.filter_version(), 0);
        assert!(apply.column_label().is_none());
        assert!(apply.cell(1).is_none());
    }

    #[test]
    fn a_failed_run_keeps_the_last_good_result_and_shows_the_error() {
        let mut slot = Slot::default();
        slot.applied = Some(Arc::new(filter_run(&[2], &[], 4)));
        let good = slot.applied().unwrap().version;
        slot.publish(Err("javac: cannot find symbol".into()));
        assert!(
            slot.error
                .as_deref()
                .unwrap()
                .contains("cannot find symbol")
        );
        assert_eq!(slot.applied().unwrap().version, good, "the good run stands");
        assert!(!slot.applied().unwrap().keeps(2));

        slot.publish(Ok(filter_run(&[1], &[], 4)));
        assert!(slot.error.is_none());
        assert!(!slot.applied().unwrap().keeps(1));
    }

    fn script(id: &str, function: Function, source: &str) -> Script {
        Script {
            id: id.into(),
            name: format!("script {id}"),
            function,
            location: webprobe_core::bambda_library::Location::ProxyHttpHistory,
            source: source.into(),
        }
    }

    #[test]
    fn applying_runs_the_library_text_not_the_text_that_was_picked() {
        let mut slot = Slot::default();
        slot.choice = Some(Choice::of(&script(
            "a",
            Function::ViewFilter,
            "return true;",
        )));
        // Saved again with a fix after it was picked.
        let saved = [script("a", Function::ViewFilter, "return false;")];
        assert!(slot.refresh(&saved));
        assert_eq!(slot.choice.as_ref().unwrap().source, "return false;");
        assert!(slot.error.is_none());
    }

    #[test]
    fn a_deleted_or_retyped_script_is_reported_instead_of_run() {
        let mut slot = Slot::default();
        slot.choice = Some(Choice::of(&script(
            "a",
            Function::ViewFilter,
            "return true;",
        )));
        assert!(!slot.refresh(&[]), "a deleted script must not run");
        assert!(
            slot.error
                .as_deref()
                .unwrap()
                .contains("no longer in the Bambda"),
            "{:?}",
            slot.error
        );
        assert!(slot.applied().is_none(), "nothing ran");

        slot.error = None;
        let saved = [script("a", Function::CustomColumn, "return \"x\";")];
        assert!(
            !slot.refresh(&saved),
            "the other function must not run here"
        );
        assert!(slot.error.as_deref().unwrap().contains("is now a Custom"));
    }

    #[test]
    fn picking_another_script_keeps_the_run_but_asks_for_trust_again() {
        let mut slot = Slot::default();
        slot.applied = Some(Arc::new(filter_run(&[2], &[], 4)));
        slot.trusted = true;
        slot.error = Some("old diagnostic".into());
        slot.repicked();
        assert!(!slot.trusted, "another script is not the one trusted");
        assert!(slot.error.is_none());
        assert!(!slot.applied().unwrap().keeps(2), "the run stays on screen");
    }

    #[test]
    fn resetting_every_table_forgets_all_six_runs() {
        let mut tables = Tables::default();
        for apply in [
            &mut tables.history,
            &mut tables.logger,
            &mut tables.websocket,
        ] {
            apply.filter.applied = Some(Arc::new(filter_run(&[1], &[], 2)));
            apply.column.applied = Some(Arc::new(applied(
                Kind::Column,
                Stamp::default(),
                Outcome::default(),
            )));
        }
        tables.reset_all();
        for apply in [&tables.history, &tables.logger, &tables.websocket] {
            assert!(apply.filter.applied().is_none());
            assert!(apply.column.applied().is_none());
        }
    }

    #[test]
    fn resetting_a_slot_returns_the_table_to_unfiltered() {
        let mut slot = Slot::default();
        slot.applied = Some(Arc::new(filter_run(&[1], &[], 2)));
        slot.error = Some("stale diagnostic".into());
        slot.reset();
        assert!(slot.applied().is_none());
        assert!(slot.error.is_none());
        assert!(!slot.busy());
    }

    #[test]
    fn each_publish_gets_a_new_version_for_cache_keys() {
        let a = filter_run(&[], &[], 1);
        let b = filter_run(&[], &[], 1);
        assert_ne!(a.version, b.version);
    }

    #[test]
    fn column_cells_render_values_and_row_errors() {
        let mut outcome = Outcome::default();
        outcome.cells.push((7, Cell::Text("fixture".into())));
        outcome.cells.push((8, Cell::Failed("boom".into())));
        outcome.row_errors = 1;
        let applied = applied(Kind::Column, Stamp::default(), outcome);
        assert_eq!(applied.rows, 2);
        assert_eq!(applied.row_errors, 1);
        let apply = run_on(Kind::Column, applied);
        assert_eq!(apply.column_label(), Some("fixture"));
        assert_eq!(cell_text(apply.cell(7)), "fixture");
        assert_eq!(cell_text(apply.cell(8)), "Error: boom");
        assert_eq!(cell_text(apply.cell(9)), "");
        // A column never filters.
        assert!(apply.keeps(7) && apply.keeps(8));
    }
}

# AR-10 — One extensibility pattern and a project format plan

Status: F14 implemented where the change is cheap and safe; the seams that
remain split are listed with their reason. F15 is a plan with its trigger
written down, not a format change: project files stay version 2 until the
trigger is measured.

Source: `qa/ARCH-REVIEW-2026-11-18.md`, findings F14 and F15 (issue #259).

## 1. Inventory: every seam and how it registers

| Seam | Registry (the only list) | Entry / metadata | Consumer |
| --- | --- | --- | --- |
| Active point checks | `scan_checks::POINT_CHECKS` | `dyn PointCheck` with `id`, `issue`, `meta`, `applies_to`, `check` | `start_active_scan` |
| Active request checks | `scan_checks::REQUEST_CHECKS` | `dyn RequestCheck` with `id`, `issue`, `meta`, `scope`, `group`, `run` | `start_active_scan` |
| Stored-input checks | `scan_checks::STORED_CHECKS` | `dyn StoredCheck` with `id`, `issue`, `meta`, `applies_to`, `server_side`, `run` | stage A4 |
| Passive checks | `scan::passive_checks::PASSIVE_CHECKS` | `PassiveCheck { def: CheckDef, run: fn }` | `run_passive_in` |
| Passive metadata | derived from `PASSIVE_CHECKS` by `scan::check_library()` | `CheckDef` = id, issue name, severity, confidence | scan configuration, tests |
| Scan catalogue | derived from all four registries by `scan::check_catalogue()` | `(id, issue, scope)` | Settings check list, issue-type lookup |
| Insertion point types | `webprobe_support::insertion::INSERTION_TYPES` | `InsertionType { key, label, burp }` | Settings, Burp config import/export, point vetoes |
| Extension hooks | `ext_host::LoadedExtension` list | `ProxyHooks` trait (request / response / tool call) | proxy pipeline |
| BChecks | data files named by the scan configuration | parsed script, one per file | scanner |
| Runtime seams | one `OnceLock` per seam | `register_*` functions | `webprobe_core::register_runtime()` |
| Project | `ProjectData` | one pretty-JSON document, `PROJECT_VERSION = 2` | load / save / autosave |

Before this change the passive checks had two lists: the function table
`PASSIVE_CHECKS` (62 units) and a hand-kept metadata list
`scan::PASSIVE_LIBRARY` (35 entries). The insertion point types had four
copies of the same keys: `scan_config::INSERTION_TYPES`,
`scan_config::INSERTION_KEYS`, the `TYPED` schema in `scan_library.rs` and the
`APPLIED` list in the same file.

## 2. The pattern

A seam is one static registry, one metadata record per entry, and one
metadata accessor with a default that derives the record from the entry's
`id` and `issue`. Consumers read the registry; they do not keep a second list.

Rules for adding a check:

1. Give the check its identity: a `CheckDef` for a passive check (id, issue,
   severity, confidence) or the `id()` / `issue()` methods of an active-check
   trait. Active checks keep severity and confidence per finding because one
   check can report several issue types; their `meta()` therefore fills only
   the identity.
2. Add the entry to exactly one registry, in the position that fixes run order.
3. Run `every_check_kind_exposes_one_meta_record`; it fails on an empty id or
   issue and on an id repeated across the four registries.
4. Do not add a catalogue list. `check_catalogue()` and `check_library()` are
   derived.

Rules for a runtime seam: a `OnceLock` of the implementation, one
`register_*` function, and the single `webprobe_core::register_runtime()`
called by the desktop and headless front ends. Registration is idempotent
(the first value wins), which the AR-10 integration test exercises.

Rules for an insertion point type: one `InsertionType` row with the project
key, the Settings label and Burp's configuration key. `TYPED` and `APPLIED`
in `scan_library.rs` still spell the Burp keys because they are the Burp
configuration schema, not the engine registry; `insertion_point_keys_match_the_one_table`
pins both to the table, so the four copies can no longer drift.

## 3. What changed here

- `core/src/scan/registry.rs`: `CheckMeta { id, issue, severity, confidence }`
  plus `Severity` and `Confidence` enums. Their serde spellings are exactly the
  strings the project file already stores (`"high"`, `"Tentative"`), so the
  format is unchanged.
- `CheckDef::meta()`, default `meta()` on `PointCheck`, `RequestCheck` and
  `StoredCheck`, and `PassiveCheck::meta()`. `check_catalogue()` now reads
  `meta()` for all four registries.
- `check_library()` moved from the hand-kept `PASSIVE_LIBRARY` to
  `PASSIVE_CHECKS`, so the catalogue now carries every registered passive
  unit (including the WebProbe-only checks that were never in the old
  35-entry list) and cannot omit a new one.
- One insertion point table in `webprobe_support::insertion`, next to the
  `IpKind` vocabulary it classifies. `INSERTION_KEYS` is gone;
  `scan_config::INSERTION_TYPES` re-exports the table so the eframe UI and the
  Burp importer/exporter read the same rows.
- `webprobe_core::register_runtime()` replaces the four registration calls
  duplicated in `src/main.rs` and `src/bin/webprobe-headless.rs`.
- Tests: `every_check_kind_exposes_one_meta_record` (one record per kind, ids
  unique across all registries), `check_library_is_derived_from_the_registry`,
  the insertion table tests, `insertion_point_keys_match_the_one_table`, the
  serde spelling test, and `core/tests/ar10_registration.rs`.

`net::Shared` is untouched. `scripts/arch-gate.py` stays green with the same
counts and the same two dependency cycles.

## 4. Deliberately not unified yet

- `ScanIssue.sev` / `ScanIssue.confidence` remain `String`. They are the
  project file and export format; changing them is a version-3 change, not a
  registry refactor. The typed enums now exist at the metadata boundary and
  are ready for that migration.
- The two extension transports (JSON-lines `ext_process` and the Montoya
  bridge) stay separate. `ProxyHooks` already unifies them at the pipeline;
  the shared `JsonLinesPeer` transport belongs to F2 / AR-08, where reply
  routing by id and the deadline policy are already being changed.
- Session-rule actions and `ext_calls` operations are still matched by
  string. Making them enums changes behaviour at the wire boundary and is a
  separate, testable change (F14's second half).
- `is_burp_issue` reads the KnowledgeBase text file per call. Index it once
  when a measurement shows the call on a hot path; it does not affect
  registration.
- BChecks register as data files in the scan configuration, not as
  compile-time entries. That is the intended extension point for user
  scripts and stays as it is.

## 5. Project persistence plan (F15)

### 5.1 Current format and cost

- One file: `WEBPROBE PROJECT` header line, `PROJECT_VERSION = 2`, then one
  pretty-JSON `ProjectData` document. History messages are written as text,
  with base64 only when the bytes are not UTF-8.
- `save` streams the document (bodies are written from their handles, one
  history item at a time), but it still rewrites every byte of every capture.
  Autosave runs off the UI thread, but `project_snapshot` builds the snapshot
  on it.
- `load` memory-maps the user's file. External truncation while mapped can
  raise SIGBUS.
- `body.rs` already has an append-only segment store for the live session. It
  is unlinked and saving does not reuse it, so the disk work is done twice.

### 5.2 Trigger

Switch when any one of these is measured on a real project:

- project file over about 100 MB, or
- an autosave that takes longer than about 1 s, or
- `project::load` over about 2 s, or
- more than 50,000 history rows with over 100 MB of body bytes.

Measurement, not guesswork: autosave already knows its start and end time;
`save` knows the byte count it wrote. Record both on the project record and
show a one-time notice above the trigger ("This project is large enough that
the segmented format is recommended"). Do not migrate automatically.

If the trigger is hit, open a dedicated F15 implementation task; the design
below is the starting point, not a commitment made by this task.

### 5.3 Target format (version 3)

A project directory, like Burp's project directory:

```
shop.webprobe/                  # project root
  project.json                  # index: settings, issues, history metadata
  bodies/000001.seg             # append-only raw bytes
  bodies/000002.seg
  export.json                   # optional v2-shaped export, on demand
```

`project.json` is small (history metadata only) and is read with `read`, not
mmap. It holds:

```json
{
  "format": "webprobe.project",
  "version": 3,
  "settings": { "...": "unchanged from version 2" },
  "issues": [ "...": "unchanged from version 2" ],
  "bodies": [
    { "id": 17, "segment": "000003.seg", "offset": 1048576, "length": 4211,
      "sha256": "..." }
  ],
  "history": [
    { "id": 9001, "request": 17, "response": 42, "...": "scalar fields" }
  ],
  "segments": [ { "name": "000003.seg", "bytes": 8388608 } ]
}
```

- Bodies are raw bytes, never base64. One `bodies[]` entry per unique `Body`
  handle, so a message repeated in twenty history rows is stored once.
- History rows keep the scalar columns the table needs and reference bodies by
  id. No body bytes in the index.
- `load` opens each referenced segment read-only, checks length against the
  index, and reads the range. A missing or short segment is a typed error
  (`MissingSegment`, `ShortSegment`) with the JSON export offered as recovery;
  it is not a panic.

### 5.4 Write path and crash safety

1. Snapshot on the UI thread, as now.
2. Off thread: append each body not already in `bodies[]` to the current
   segment; roll to a new segment at 64 MiB. `fsync` the segment.
3. Write `project.json.tmp`, `fsync`, then rename over `project.json`
   (atomic on POSIX; on Windows use replace-existing and retry).
4. Only after that rename report the save complete.

Crash windows:

- Segment appended, index not renamed: the index does not reference the new
  bytes; they are orphan garbage, collected later. The previous save is
  intact.
- Index renamed, old index gone: all referenced segments were fsynced first,
  so the new state is complete.
- Segment deleted outside WebProbe: typed load error, never SIGBUS, because no
  user file is mapped.

Segments are immutable once written. Compaction never truncates or rewrites a
live segment: it writes a new segment, swaps the index, then deletes old
segments after a grace period (and never while a reader has them open).

### 5.5 Incremental autosave and compaction

- Autosave appends only bodies captured since the last save and rewrites the
  small index. Target: under 100 ms at a 100 MB project, versus the current
  full rewrite.
- If nothing changed, no index write.
- Compaction when garbage exceeds 30% of segment bytes: copy live bodies to a
  new segment, swap the index, delete the old segment. Manual command in the
  Project menu, plus once on open when the project is over 100 MB.

### 5.6 Migration and rollback

- Version 3 is opt-in: an existing version-2 file opens and saves as version 2
  until the user chooses Convert, or the trigger notice is accepted.
- Convert: write a temporary directory next to the project, fsync everything,
  rename into place, and keep the original `.json` as `*.v2-backup` until the
  first successful reopen. Delete the backup only after that reopen.
- `project::load` keeps reading versions 1 and 2 for at least two minor
  releases after version 3 ships.
- JSON export stays available in both directions: a version-3 project can
  write a version-2-shaped `export.json`, and that file loads as a version-2
  project.

### 5.7 Tests the implementation must add

- Round trip: a version-2 project converts to version 3 and back to the same
  bytes, including NUL, non-UTF-8, empty bodies and a body shared by many
  rows.
- Crash before the index rename: loading yields the previous state.
- Crash after the index rename: loading yields the new state.
- Missing / short / truncated segment: typed error, no panic, export works.
- Autosave appends only new bodies; index size stays bounded as history grows.
- Load of version-1 and version-2 files is unchanged.
- A synthetic 100 MB project: save time, peak memory and appended bytes are
  inside the budget above (bench, not a unit assertion).

### 5.8 Risks

- Format migration can lose data. Mitigation: never delete the source before a
  successful reopen, checksum every body, keep the version-2 reader.
- Index corruption. Mitigation: write-temp-then-rename, keep the previous
  index as `project.json.prev` until the next successful save.
- Replacing mmap with `read` may slow very large single bodies. Mitigation:
  body references are ranges; read only the requested body, and revisit
  per-segment mapping only if a benchmark shows it matters.

## 6. Acceptance evidence

| Requirement | Evidence |
| --- | --- |
| F14: check registries follow one registration pattern | `CheckMeta` + `meta()` on all four kinds; catalogue derived; `every_check_kind_exposes_one_meta_record` |
| F14: insertion points follow one registration pattern | one `INSERTION_TYPES` table; `INSERTION_KEYS` deleted; schema pinned by `insertion_point_keys_match_the_one_table` |
| F14: extension seams have one pipeline contract | `ProxyHooks` unchanged and documented here; transport merge deferred to AR-08/F2 with reason |
| F15: project format plan with a documented trigger | sections 5.1–5.8 |
| Safety | `net::Shared` unchanged; `scripts/arch-gate.py` green; no format change |

# R-16: library, editor and explicit preview

## Scope

Extensions > Bambda library provides a local script library and editor for Java HTTP-history filters and custom columns. This is a preview-only milestone. It does not apply filters or custom columns to the HTTP history table, run on new traffic, or implement every Montoya method. R-16 is not complete.

Importing, loading, saving, exporting and deleting never compile or evaluate source. The user must acknowledge that Java can access local files and network, then press Compile and preview. This is trusted local code, not a sandbox. Source edits and selecting/importing another script reset that acknowledgement.

## Interchange and persistence

`.bambda` files are YAML containing `id`, `name`, `function`, `location` and `source`. Supported functions are `VIEW_FILTER` and `CUSTOM_COLUMN`; the sole supported location is `PROXY_HTTP_HISTORY`. Other targets, duplicate/unknown fields, malformed UUIDs, empty names/source and oversized files are rejected without executing anything. Import opens the editor, not the persistent library. Saving an existing ID requires a separate replacement checkbox. IDs and exact source text survive import/export. New scripts get random UUIDv4 IDs.

File input/output is capped at 256 KiB, source at 128 KiB and names at 200 characters. The local library lives under `bambda-library` in WebProbe's data directory. Loads report malformed entries individually and stop after 1000 files. New library directories/files use owner-only permissions on Unix. Saves and exports write and sync a temporary file before atomically publishing it. A new destination is claimed with a non-overwriting hard link; overwriting a saved ID uses rename. Unsupported filesystem operations return an error rather than falling back to a partial copy. Temporary files are removed on error. Export never overwrites an existing destination. These operations do not promise crash durability of the containing directory.

Caller-selected paths must be regular files; devices, FIFOs, sockets, directories and symlinks are rejected before opening. File operations are still synchronous. This check is not a defense against a concurrent local filesystem swap or a slow regular file on a network filesystem. Atomic exports never open an existing destination. A FIFO regression covers import, save, export and delete rejection.

The editor guards unsaved text when creating, selecting or importing another script. Delete requires its own confirmation and removes the saved copy, not the editor text.

## Worker and result state

Compilation runs off the UI thread with a 15-second process deadline. After compilation, preview captures the most recent20 recorded exchanges. Each JVM batch contains at most5 rows and 1 MiB of combined request/response/host bytes, with a 10-second process deadline per batch. Individually oversized rows are counted as skipped. Large raw rows are rejected before allocating their preview copies. The source and input serialization limits from the backend still apply.

Each row shows its recorded ID and either its typed JSON value or row exception. Null is shown as null, distinct from a missing error value. A failed compile, cancelled job, process failure, timeout, incomplete batch or output-limit failure leaves the last successful preview rows, script label and skip count unchanged, with a visible diagnostic. Partial successful batches are never published after a later batch fails. Row exceptions are results, not batch failures.

Cancel signals the active compile/evaluation process. Closing/dropping the page's owner signals cancellation and joins the worker. Unix cleanup kills the process group; Windows descendant-process cleanup is not verified. A deliberately escaping trusted Java program is outside that guarantee. Before loading user code, the evaluator starts a daemon watchdog bound to the expected Rust parent PID. If that parent exits, the JVM halts, including when its script loops. A Linux regression kills a surrogate parent and verifies the evaluator exits without relying on the Rust cleanup path. This is a trusted-code lifecycle guard, not a defense against Java deliberately disabling it. No background process runs just because a library file was imported.

## Verification

The library tests cover exact source/identity round-trip, explicit ID replacement, malformed and unsupported metadata, serialization size limits, non-overwriting export and temporary-file cleanup. A desktop-state regression proves errors keep the last successful snapshot and a later success clears its diagnostic. The real-JVM suite adds chunking across the raw cap, an individually oversized skipped row and prompt cancellation of looping code.

Desktop QA used actual loopback HTTP requests through WebProbe's proxy. A fixture response supplied a Server header, and a trusted test script threw on one request path. The inspected preview displayed both the non-null server value and the per-row exception. This does not claim history-table integration.

Run the workspace test build, full tests, rustfmt and all-target clippy gates documented in the backend note, plus the explicitly enabled real-JVM integration suite.

## References

- https://portswigger.net/burp/documentation/desktop/extend-burp/bambdas/importing
- https://portswigger.net/burp/documentation/desktop/extend-burp/bambdas/managing
- https://portswigger.net/burp/documentation/desktop/extend-burp/bambdas/creating/contribute-scripts
- https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history/scripts
- https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history/custom-columns

The YAML parser is the maintained yaml_serde fork, pinned through Cargo.lock. Import never invokes a Java compiler, a JVM or an imported function.

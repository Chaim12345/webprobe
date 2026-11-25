# S-04: Rust JavaScript parser feasibility (non-production)

Base: `692f09728039884c59a676ff314879c06dcb1cf5` (`origin/parity/2026-11-17`).
Research input: `docs/specs/R-13-static-js-analysis.research.md`, especially §5.2
(requirements) and §4 (budgets). This is a **source/metadata decision artifact**,
not production integration and not sink-coverage evidence.

## Recommendation

Use **`oxc_parser = 0.146.0` as the first isolated bake-off candidate**, not as
an approved production dependency. It is the newest Oxc release whose registry
metadata declares `rust_version = 1.95.0`, matching WebProbe's exact MSRV. It
has MIT licensing, byte-oriented AST spans, and documented recoverable errors.
Keep `boa_parser = 0.22.0` as the fallback only if the malformed-sibling and
byte-offset fixtures below show that Oxc cannot preserve the required evidence.

This recommendation is conditional on a future, separately authorized isolated
build. **No parser crate was compiled or run here.** No Cargo manifest or
lockfile changed, no dependency was downloaded, and no AGPL reference code was
copied.

## Decision matrix

Evidence labels: **source** = the pinned repository or official upstream API
documentation; **registry** = crates.io API response; **NOT_RUN** = no local
execution claim.

| Candidate | Actual Rust 1.95 constraint | License and project fit | Source offsets | Malformed input / valid sibling | Cancellation and bounds | Feasibility decision |
|---|---|---|---|---|---|---|
| **Oxc `oxc_parser 0.146.0`** | Registry declares **1.95.0**; latest 0.147–0.148 require 1.96, 0.149–0.155 require 1.97, 0.159–0.160 require 1.98. Pin exactly; do not use an open semver requirement. **MSRV build NOT_RUN.** | Registry/docs: **MIT**. WebProbe itself has no root license; its existing policy accepts permissive dependencies and requires separate review before distribution. No AGPL parser code used. | `oxc_span::Span` has `u32 start/end`, indexes Rust text, and `size()` is bytes. Suitable for UTF-8 response-byte mapping; cap input well below 4 GiB. Multibyte fixture **NOT_RUN**. | `Parser::parse` documents recoverable errors in `errors` and an empty `Program` on unrecoverable error. It does not promise that one malformed fragment preserves a sibling; test that explicitly. | No cancellation callback found in the inspected parse API. Enforce input bytes, per-unit memory, nesting/time limits at the adapter boundary; use process isolation if hard interruption is required. | **Provisional first choice** at `=0.146.0`; upgrade is blocked until WebProbe MSRV changes. |
| **Boa `boa_parser 0.22.0`** | Registry declares **1.91.0**, below project MSRV. Full transitive MSRV build **NOT_RUN**. | **Unlicense OR MIT**; permissive option fits current third-party policy, subject to normal review. | `boa_ast::Span` exposes line/column `Position`, not a direct byte range in the inspected API. Byte-exact response highlights require an independently verified mapping. | `parse_script`/`parse_module` documents `Err` on any parse error. A bad fragment must be isolated per script unit; no sibling-preserving partial AST is claimed. | No cancellation parameter in inspected parse methods. Bound reads and memory externally; hard cancellation requires an execution/process boundary. | **Fallback**, weaker direct offset/recovery fit than Oxc. |
| **SWC `swc_ecma_parser 48.1.0`** | Registry `rust_version` is **null**; this is not proof of 1.95 support. Exact crate plus transitive versions need a 1.95 build. **NOT_RUN.** | **Apache-2.0**, compatible with the existing permissive dependency family. | `swc_common::Span` uses source-map-global `BytePos`; map back through `SourceMap`, never treat `hi-lo` as a universal byte length across files. | Official docs demonstrate recovery from **some** errors while emitting diagnostics; fatal errors remain possible. Sibling preservation **NOT_RUN**. | No cancellation callback established. Input and process/adapter bounds required. | **Second-line alternative**, not the smallest evidence-preserving choice. |
| **RSLint `rslint_parser 0.3.1`** | Registry `rust_version` null; release dated 2021-10-06. Compilation on 1.95 and maintenance/transitive risk **NOT_RUN**. | **MIT**, permissive. | Parser token `range` is explicitly byte indices; lossless syntax nodes preserve original text. Strong offset model. | Documentation explicitly supports error-tolerant trees with `ERROR` nodes from arbitrary input. Actual valid-sibling AST behavior **NOT_RUN**. | No cancellation API established; age/maintenance and bounds need review. | **Do not select initially** despite strong recovery/offset properties; revisit only if maintained-status and 1.95 build are cleared. |
| **Ress `ress 0.11.7`** | Registry `rust_version` null; no 1.95 build run. | **MIT**, permissive. | Token items carry spans and source locations, with source slicing helpers. | Lexer/scanner, not the JavaScript AST parser needed by R-13 §5.2. It cannot establish the required scopes/CFG on its own. | Scanner state can support bounded adapter logic, but this does not solve parser cancellation. | **Reject as the parser**; possible lexer utility only. |

### License boundary

The pinned tree has no root `LICENSE`; its own crates declare no license.
`docs/management/SECURITY-COMPLIANCE-2026-11-22.md:12-17` describes the current
third-party permissive-license policy and the separate ARTEX AGPL boundary.
The matrix says only that the parser license declarations do not introduce an
AGPL-only dependency. It does **not** grant distribution, relicensing, or legal
clearance. No reference implementation source was copied into this artifact.

## Required fixture artifact

`fixtures.json` is an implementation-neutral harness contract for the future
isolated build. It contains the four mandated cases, expected UTF-8 byte spans,
per-unit malformed recovery, literal escape values, and an exactly 1 MiB bound.
It deliberately includes no parser API code because those APIs could not be
compiled against locally available crates.

All JavaScript parser outcomes below are **NOT_RUN**, not passes:

1. **Multibyte offsets:** `window.name` begins at UTF-8 byte 19 and `window`
   ends at byte 25, not character offsets 15 and 21. AST spans must slice the
   original response/script bytes exactly.
2. **Malformed fragment next to valid sibling:** parse `const broken = ;` and
   `window.name;` as separate units and in the requested combined-unit mode.
   A unit error must not abort the page or erase the valid unit's span. An empty
   partial program or loss of the sibling is a fixture failure, not a pass.
3. **Escape decoding:** literal source `"line\\n\\u0041\\x42"` must expose the
   decoded value `line\nAB` (six bytes: newline plus `AB`) while retaining its
   raw source span. Do not confuse raw bytes with decoded value bytes.
4. **Bounded large input:** exactly 1,048,576 bytes, generated as a block comment
   plus `\n;`, with a one-second fixture deadline and a 256 MiB harness RSS
   ceiling. Reject input above the fixture cap before parsing. Time/RSS and
   cancellation behavior remain unmeasured.

For every candidate record: exact resolved crate graph, toolchain, target,
elapsed time, peak RSS where available, error count/kinds, AST presence,
multibyte raw slices, decoded literal value, and whether the valid sibling was
retained. A 1 MiB success is not proof of acceptable performance on arbitrary
large minified bundles.

## Executed evidence and limitations

- `git fetch origin` completed; pin and `origin/parity/2026-11-17` both equal
  `692f09728039884c59a676ff314879c06dcb1cf5`, tree
  `6316124e746caa0d8f1706339474928ad5716259`.
- Pre-existing untracked `.evidence-export/` and `.openhands/` were observed and
  left untouched; `git stash list` was empty. Work occurred in the isolated
  `/workspace/qa/s04-js-parser-feasibility` worktree on the requested branch.
- `app/Cargo.toml:79` declares `rust-version = "1.95"`; the CI toolchain matrix
  includes 1.95.0. No parser dependency was present in the pinned lockfile.
- Local cache searches found **zero** candidate Oxc/SWC/Boa/RSLint/Ress source
  directories or crate archives. No `rustc`, `cargo`, or `rustup` executable was
  available on PATH or at the inspected conventional locations. Therefore all
  parser fixtures were **NOT_RUN**. No installation was attempted.
- Direct crates.io API reads supplied version/license/MSRV metadata. Official
  docs.rs and tagged upstream files supplied API behavior. Some guessed raw tag
  URLs returned 404 and were not used as evidence. Three Tavily searches failed
  with HTTP 432 plan usage-limit errors; no upgrade, purchase or retry occurred.
- Resource observation: 4 visible CPUs, 13.0 GiB available RAM, cgroup
  `cpu.max=max 100000`, `memory.max=max`, ~1.3 GiB free workspace disk. No target
  directory or build artifacts were created. Metadata was kept outside the repo.
- Fixture arithmetic and JSON syntax were validated locally with Python; these
  are not JavaScript parser tests. See `commands.md` and `validation.txt` for
  exact commands/results and `fixture-validation.json` for computed values.

**Test count: 0 JavaScript parser tests run, 0 passed, 0 failed, 4 fixture
families NOT_RUN. No production test suite, Clippy, formatting or MSRV build was
run.** No sink detection, scope analysis, CFG support, response coverage,
production compatibility, parser performance, or cancellation effectiveness is
claimed.

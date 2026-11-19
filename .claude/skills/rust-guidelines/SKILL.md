---
name: rust-guidelines
description: Apply the Microsoft Pragmatic Rust Guidelines (90 rules, M-* IDs) when writing, reviewing or refactoring Rust code, or planning crate and workspace structure, error types, panics, unsafe, logging, lints, tests, public API design, async or performance work. Use for questions like "does this follow Rust best practices", "should we split this crate", "how should errors/panics/statics be handled here", or when a PR touches Cargo.toml, error types, unsafe or public APIs.
---

# Pragmatic Rust Guidelines

Source: https://microsoft.github.io/rust-guidelines/ (site version 2026.6, MIT licensed). The full text is in
`references/pragmatic-rust-guidelines.md` (3,500 lines, unmodified copy). Rules have IDs like `M-PANIC-IS-STOP`.

## How to use this skill

1. Find the rules that apply from the index below. Do not load the whole reference file.
2. Read the rule's full text: `grep -n "M-RULE-ID" references/pragmatic-rust-guidelines.md`, then read about 40 lines
   from the `## ... (M-RULE-ID)` heading. Rules carry examples and exceptions that the one-liners leave out.
3. Cite the rule ID in review comments and commit messages, with a link such as
   `https://microsoft.github.io/rust-guidelines/guidelines/universal/#M-SMALLER-CRATES`.
4. The guidelines say to follow their spirit over the letter. They are written for libraries and Microsoft's own
   practice; applications may relax some of them (see `M-APP-ERROR`). State when you deviate and why.
5. They also point to the Rust API Guidelines (https://rust-lang.github.io/api-guidelines/checklist.html), the Rust
   Style Guide and Rust Design Patterns (`M-UPSTREAM-GUIDELINES`). This skill does not copy those.

## Rules that are easy to get wrong

- **Panics (`M-PANIC-IS-STOP`, `M-PANIC-ON-BUG`, `M-PANIC-CONTINUATION`, `M-PANIC-MESSAGE`):** a panic means stop the
  program. `unwrap` on a poisoned lock is explicitly a valid panic, and there is no blanket ban on `unwrap`/`expect`
  for programming errors. Never use panics to report errors. `catch_unwind` is a last resort and should be followed
  by a controlled restart; per-request `catch_unwind` is fine only to let other requests finish.
- **Errors (`M-ERRORS-CANONICAL-STRUCTS`, `M-FROM-ERROR`, `M-APP-ERROR`):** library errors are situation-specific
  structs with a `Backtrace`, an optional cause and helper methods. If an `ErrorKind` is stored, keep it private and
  expose `is_xxx()` methods. Prefer `From` over scattered `map_err`. Applications may use `anyhow`/`eyre` but must not
  mix several application-level error types; crates used by more than one crate follow the struct rule.
- **Crates (`M-SMALLER-CRATES`, `M-CARGO-WORKSPACE`, `M-CRATES-FLAT-FOLDER`, `M-CRATES-IN-WORKSPACE`):** err on the side
  of too many crates; the stated reasons are compile-time improvements (especially during development) and
  preventing cyclic component dependencies. One workspace `Cargo.toml` at the root, crates flat under `crates/`,
  versions and lints inherited from the workspace, `default-features = false` in workspace dependencies.
- **Statics (`M-AVOID-STATICS`):** statics and thread-locals are a problem where a consistent view matters; statics used
  only for performance are fine.
- **Lints (`M-STATIC-VERIFICATION`, `M-LINT-OVERRIDE-EXPECT`):** a concrete `[lints.rust]` / `[lints.clippy]` set is
  given in the rule; overrides use `#[expect(..., reason = "...")]`, not `#[allow]`.
- **Unsafe (`M-UNSAFE`, `M-UNSOUND`, `M-UNSAFE-IMPLIES-UB`):** only for novel abstractions, benchmarked performance or
  FFI; every use needs written safety reasoning; unsound code has no exceptions.
- **Logging (`M-LOG-STRUCTURED`, `M-LOG-NOT-PRINT`, `M-LOG-OVERHEAD`):** named structured events with message templates,
  redact sensitive data, no `println!`/`dbg!` in production (CLIs may print), keep telemetry out of hot loops.
- **Tests (`M-INTEGRATION-TESTS`, `M-TAUTOLOGICAL-TESTS`, `M-TEST-UTIL`, `M-MOCKABLE-SYSCALLS`):** public-API tests live
  in `tests/`, tests must not restate the code under test, test helpers sit behind a `test-util` feature, and I/O,
  clocks and entropy are mockable.
- **AI-written code (`M-NO-META-DESIGN-DOCUMENTATION`, `M-SINGLE-ITEM-PATH`, `M-TAUTOLOGICAL-TESTS`, `M-RUST-SHAPED`):**
  watch for design-journey prose in docs, duplicate re-export paths, tautological tests and ported-from-C#/Java
  patterns. Do not append a self-report table of "rules applied" to docs.
- **Not covered here:** no file-size or line-count rule exists; do not cite one.

## Rule index

Each row is the rule ID, title and the guideline's own one-line reason. Section names match the official site.

### AI Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-DESIGN-FOR-AI` Design with AI use in mind | maximum utility from agents working in your codebase |
| `M-NO-META-DESIGN-DOCUMENTATION` Avoid meta design documentation | docs focused on what is relevant to users |
| `M-RUST-SHAPED` Rust code solves Rust problems | idiomatic code |
| `M-SINGLE-ITEM-PATH` Items are only visible through one path | a single, clutter-free path to each type |
| `M-TAUTOLOGICAL-TESTS` Tests do not assert ground truth | tests that add value, not noise |

### Application Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-APP-ERROR` Applications may use Anyhow or derivatives | simple application-level error handling |
| `M-MIMALLOC-APPS` Use mimalloc for apps | significant performance at no cost |
| `M-TARGET-CPU` Applications target highest viable target-cpu | fleet performance |

### Correctness Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-PANIC-CONTINUATION` Panic continuation is last resort | state integrity and freedom from subtle bugs |
| `M-PANIC-IS-STOP` Panic means 'stop the program' | soundness and predictability |
| `M-PANIC-MESSAGE` Custom panics have a helpful message | faster bug diagnosis |
| `M-PANIC-ON-BUG` Detected programming bugs are panics, not errors | tractable error handling and runtime consistency |
| `M-UNSAFE-IMPLIES-UB` Unsafe implies undefined behavior | semantic consistency without warning fatigue |
| `M-UNSAFE` Unsafe needs reason, should be avoided | memory safety and a minimal attack surface |
| `M-UNSOUND` All code must be sound | predictable runtime behavior free of bugs and incompatibilities |

### Documentation

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-CANONICAL-DOCS` Documentation has canonical sections | established Rust documentation practices |
| `M-DOC-INLINE` Mark `pub use` items with `#[doc(inline)]` | re-exported items that fit in with their siblings |

### pub(crate) mod foo { pub struct Foo; }

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-FIRST-DOC-SENTENCE` First sentence is one line; approx. 15 words | easily skimmable API docs |
| `M-MODULE-DOCS` Has comprehensive module documentation | easy API docs navigation |

### FFI Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-FFI-NAMING` FFI crates follow established naming conventions | immediately recognizable crate roles across projects |
| `M-FFI-TRANSLATES` Business logic belongs in core crates, FFI only translates | maximal safe code and a clean separation of concerns |
| `M-ISOLATE-DLL-STATE` Isolate DLL state between FFI libraries | data integrity and defined behavior across DLL boundaries |

### Macros Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-EXAMPLE-OVER-PROC` Prefer 'macros by example' over proc macros | easy macro inspection and fast compilation |
| `M-MACRO-HELPERS` Third party items come from hidden `_private` module | predictable compilation |
| `M-MACRO-LAST-RESORT` Macros are a last resort | minimal complexity |
| `M-MACRO-MAIN-CRATE` Macros assume main crate | simple macro logic |
| `M-MACRO-VERSION-PIN` Pin supporting proc macro crates | keep generated code compatible with its library |

### foo/Cargo.toml

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-MACROS-DONT-LIE` Macros don't lie about signatures | clarity for users and LLMs |
| `M-PROC-IMPL` Proc macros should have separate impl crate incl. tests | thoroughly testable proc macros |
| `M-PROC-IMPLIED-ITEMS` Proc macros don't produce implied or hidden items | clear errors and correct hygiene and visibility |

### Performance Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-ASYNC-STACK-SIZE` Hot `async` functions reduce stack size | small async stack sizes and low memcpy overhead |
| `M-AVOID-INDIRECTION` Nested type hierarchies should avoid needless indirection | fast, cache-friendly memory access |
| `M-BOX-DST` Use boxed slices and strings for immutable owned sequences | low memory consumption and good cache utilization |
| `M-FAST-HASHER` Use a fast hasher where possible | hashing performance |
| `M-HOTPATH` Identify, profile, optimize the hot path early | high-performance code |
| `M-INITIAL-CAPACITY` Collections are created with sufficient initial capacity | efficient collection creation |
| `M-LOG-OVERHEAD` Library telemetry does not tank performance | low-overhead telemetry during diagnosis |
| `M-MEM-REUSE` Reuse allocations where possible | low allocation overhead and fast hot paths |
| `M-SHRINK-TO-FIT` Shrink collections to fit after building | a minimal memory footprint |
| `M-THROUGHPUT` Optimize for throughput, avoid empty cycles | COGS savings at scale |
| `M-YIELD-POINTS` Long-running tasks should have yield points | fair CPU time for all tasks |

### Project Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-CARGO-WORKSPACE` Common settings come from the workspace Cargo.toml | consistent, maintainable project configuration |
| `M-CRATES-FLAT-FOLDER` All crates are siblings in one folder | simple project navigation and a standard Rust layout |

### Never acceptable, crates inside `src/` folder

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-CRATES-IN-WORKSPACE` The workspace lists and versions all crates | simple inter-crate dependencies and debugging |

### Good, going through workspace

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-LATEST-EDITION` New crates target latest edition | access to the latest Rust features |
| `M-MSRV` MSRV is conservatively updated | modern features with stability for users |

### Universal Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-DOCUMENTED-MAGIC` Magic values are documented | maintainability and safe refactoring |
| `M-LINT-OVERRIDE-EXPECT` Lint overrides should use `#[expect]` | a current, tidy lint set |
| `M-LOG-STRUCTURED` Use structured logging with message templates | low-cost logging with strong filtering |
| `M-PUBLIC-DEBUG` Public types are Debug | easy debugging without leaking sensitive data |
| `M-PUBLIC-DISPLAY` Public types meant to be read are Display | usability |
| `M-REGULAR-FN` Prefer regular over associated functions | readability |
| `M-SHORT-NAMES` Names of items are short | idiomatic code |
| `M-SMALLER-CRATES` If in doubt, split the crate | fast compile times and good modularity |
| `M-STATIC-VERIFICATION` Use static verification | consistency and freedom from common issues |

### ...

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-UPSTREAM-GUIDELINES` Follow the upstream guidelines | a codebase that reflects community lessons and does not surprise users or contributors |
| `M-WEASEL-WORDS` Names are free of weasel words | readability |

### Libraries / Building Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-FEATURES-ADDITIVE` Features are additive | reliable compilation in large, complex projects |
| `M-OOBE` Libraries work out of the box | easy adoption across the Rust ecosystem |
| `M-SYS-CRATES` Native `-sys` crates compile without dependencies | libraries that just work on all platforms |

### Libraries / Interoperability Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-DONT-LEAK-TYPES` Don't leak external types | stable APIs and low long-term maintenance cost |
| `M-ESCAPE-HATCHES` Native escape hatches | workarounds for unsupported use cases until alternatives exist |

### type HNATIVE = *const u8;

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-FOREIGN-REEXPORTS` Items come from their original crate | unambiguous type identity |
| `M-IMPL-ASREF` Accept `impl AsRef<>` where feasible | flexibility for callers to use their own types |

### use std::path::Path;

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-IMPL-IO` Accept `impl 'IO'` where feasible ('sans IO') | business logic untangled from I/O, with N*M composability |
| `M-IMPL-RANGEBOUNDS` Accept `impl RangeBounds<>` where feasible | flexibility and clarity when specifying ranges |

### use std::ops::{RangeBounds, Range};

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-TYPES-SEND` Types are Send | use in Tokio and behind runtime abstractions |

### Libraries / Resilience Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-AVOID-STATICS` Avoid statics | consistency and correctness across crate versions |

### use std::sync::atomic::Ordering;

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-BUILD-RESULT` Builders validate in final `.build()` | clean builder error handling |
| `M-INTEGRATION-TESTS` Integration tests live under `tests/` | clean code files |
| `M-LOG-NOT-PRINT` Production code uses telemetry, not println | diagnostics available where they are needed |
| `M-MOCKABLE-SYSCALLS` I/O and system calls are mockable | testable edge cases that are otherwise hard to evoke |
| `M-NO-GLOB-REEXPORTS` Don't glob re-export items | a deliberate public surface |
| `M-STRONG-TYPES-GUARD` Newtypes guard their invariants | centralized correctness invariants |
| `M-STRONG-TYPES` Use the proper type family | the right data and safety invariants, at the right time |
| `M-TEST-UTIL` Test utilities are feature gated | production builds that cannot bypass safety checks |

### Libraries / UX Guidelines

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-ASYNC-FN` Functions are `async` over returning a Future | simpler code and easier-to-understand APIs |
| `M-AVOID-WRAPPERS` Avoid smart pointers and wrappers in APIs | low cognitive load and ergonomic APIs |
| `M-BALANCED-MODULES` Modules are balanced in size and scope | discoverable functionality and clear API usage |
| `M-COLLECTION-TRAITS` Collections implement the appropriate iter traits | composable collections |
| `M-DI-HIERARCHY` Prefer types over generics, generics over dyn traits | composable patterns and freedom from design lock-in |

### }

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-ERRORS-CANONICAL-STRUCTS` Errors are canonical structs | harmonized error types and consistent error handling |

### }

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-ESSENTIAL-FN-INHERENT` Essential functionality should be inherent | easily discoverable essential functionality |

### }

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-FROM-ERROR` Canonical error conversion uses `From`, not `map_err` | idiomatic error handling |
| `M-INIT-BUILDER` Complex type construction has builders | future-proof type construction in complex scenarios |

### struct FooBuilder;

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-INIT-CASCADED` Complex type initialization hierarchies are cascaded | construction free of parameter mix-ups |

### struct Currency

| Rule | What it asks for (the guideline's own 'why') |
|---|---|
| `M-NO-PRELUDE` Don't define preludes | a clean namespace and reliable downstream builds |
| `M-PARAMETER-CONSISTENCY` Parameter ordering is consistent | low development friction |
| `M-SERVICES-CLONE` Services are Clone | composable sharing of common services |
| `M-SIMPLE-ABSTRACTIONS` Abstractions don't visibly nest | low cognitive load and a good out-of-the-box UX |

## Applying it in this repository (WebProbe)

Decisions, measurements and the prioritised plan are in `docs/adr/0001-architecture-hardening-and-crate-split.md`
and the issues it links. Current gaps against the guidelines (counts from 2026-11-19, grep-based):
- No CI, `[workspace.lints]`, `rustfmt.toml` or `cargo audit` (`M-STATIC-VERIFICATION`); 82 clippy warnings in core.
- A 23-module dependency cycle blocks splitting crates (`M-SMALLER-CRATES`); run `python3 scripts/module-cycles.py`.
- About 650 `lock().unwrap()` plus 9 `catch_unwind` uses: a mixed panic policy (`M-PANIC-IS-STOP`,
  `M-PANIC-CONTINUATION`).
- 115 `Result<_, String>` signatures, no typed errors (`M-ERRORS-CANONICAL-STRUCTS`); the two binaries may use `anyhow`.
- Edition 2021 and no MSRV (`M-LATEST-EDITION`, `M-MSRV`); workspace manifest lives in `app/`, not the repo root.
- Inline test modules in 59 core files (`M-INTEGRATION-TESTS`); `net.rs` is about 55% tests.
- `net::Shared` has 77 public fields and exposes `Arc<rustls::ClientConfig>` (`M-DONT-LEAK-TYPES`, `M-AVOID-WRAPPERS`).
- Up to 56 `println!`/`eprintln!`/`dbg!` hits, free-text `shared.log` (`M-LOG-STRUCTURED`, `M-LOG-NOT-PRINT`).
- Rules that do not apply: FFI (`M-FFI-*`, `M-ISOLATE-DLL-STATE`) and macro rules, since there are no FFI exports and
  no proc macros.

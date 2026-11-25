# S-04 command evidence

All commands were local except the explicit `git fetch origin` and bounded public
metadata/documentation reads. No parser dependency was installed or downloaded.

## Source, state and resources

```sh
cd /workspace/project/webprobe
git status --short --branch
# ## lane/r11-verify-leftovers...origin/lane/r11-verify-leftovers
# ?? .evidence-export/
# ?? .openhands/
git stash list
# (no output)
git fetch origin
# Completed: 1054 objects, 572.63 KiB; origin/parity/2026-11-17 a3b0fbf9..692f0972.
git show -s --format='commit=%H%ntree=%T%nparents=%P%nsubject=%s' 692f09728039884c59a676ff314879c06dcb1cf5
# commit=692f09728039884c59a676ff314879c06dcb1cf5
# tree=6316124e746caa0d8f1706339474928ad5716259
# parents=2c61ade2253cd4d07c421e07e41c60d0ec4c50f2 d04471f068e801071d4e31de19405f81ddec11e7
# subject=Merge pull request #230 from Chaim12345/team/ci-montoya-cache-20261125
git rev-parse origin/parity/2026-11-17
# 692f09728039884c59a676ff314879c06dcb1cf5
nproc
# 4
awk '/MemTotal|MemAvailable/{print}' /proc/meminfo
# MemTotal: 16374236 kB
# MemAvailable: 13663752 kB
cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max
# max 100000
# max
df -h /workspace
# 25G total, 24G used, 1.3G available, 95% (later 96% after worktree)

git worktree add -b goal/s04-js-parser-feasibility-20261125 \
  /workspace/qa/s04-js-parser-feasibility \
  692f09728039884c59a676ff314879c06dcb1cf5
# Preparing worktree (new branch goal/s04-js-parser-feasibility-20261125)
# HEAD is now at 692f0972 ...
```

The original worktree's untracked paths were not copied, stashed, deleted or
modified. All subsequent edits occurred in the isolated worktree.

## Research, MSRV and dependency availability

```sh
grep -nE 'rust-version|MSRV' app/Cargo.toml .github/workflows/ci.yml
# app/Cargo.toml:79: rust-version = "1.95"
# CI matrix includes 1.95.0 and stable.
grep -nEi 'swc|oxc|boa|rslint|ress|tree-sitter|deno_ast|javascript|quick-js|quickjs' \
  app/Cargo.lock app/Cargo.toml app/core/Cargo.toml
# No JavaScript parser matches (other matches were unrelated clipboard/brotli text).
sed -n '423,510p' docs/specs/R-13-static-js-analysis.research.md
# Read budget requirements, parser requirements and staged non-reportable S1.
find "$HOME/.cargo/registry/src" -mindepth 2 -maxdepth 2 -type d \
  \( -iname 'oxc*' -o -iname 'swc*' -o -iname 'boa*' -o -iname 'rslint*' \
     -o -iname 'ress*' -o -iname 'tree-sitter-javascript*' -o -iname 'deno_ast*' \)
# (no output)
find "$HOME/.cargo/registry/cache" -type f \
  \( -iname 'oxc*' -o -iname 'swc*' -o -iname 'boa*' -o -iname 'rslint*' \
     -o -iname 'ress*' -o -iname 'tree-sitter-javascript*' -o -iname 'deno_ast*' \)
# (no output)
rustup toolchain list
# bash: rustup: command not found (exit 127)
"$HOME/.cargo/bin/rustup" toolchain list
# bash: /home/openhands/.cargo/bin/rustup: No such file or directory (exit 127)
command -v rustc; command -v cargo
# (no output)
```

No `rustc`/`cargo` executable was found at the inspected conventional locations.
Because dependencies were not already available, JavaScript syntax/span fixture
execution stopped before any prototype crate was created.

## Public metadata/API reads (no crate downloads)

A Python `urllib.request` loop read
`https://crates.io/api/v1/crates/{crate}` for `oxc_parser`, `swc_ecma_parser`,
`boa_parser`, `rslint_parser`, and `ress`. JSON was saved outside the repository
at `/workspace/qa/s04-parser-metadata/`; no `.crate` archives were requested.
Selected output:

```text
oxc_parser max_version=0.160.0 selected=0.160.0 rust_version=1.98.0 license=MIT
swc_ecma_parser max_version=48.1.0 rust_version=None license=Apache-2.0
boa_parser max_version=0.22.0 rust_version=1.91.0 license=Unlicense OR MIT
rslint_parser max_version=0.3.1 rust_version=None license=MIT
ress selected=0.11.7 rust_version=None license=MIT
oxc_parser 0.146.0 rust=1.95.0 license=MIT yanked=False
oxc_parser 0.147.0..0.148.0 rust=1.96.0
oxc_parser 0.149.0..0.155.0 rust=1.97.0
oxc_parser 0.156.0..0.158.0 rust=1.97.0
oxc_parser 0.159.0..0.160.0 rust=1.98.0
rslint_parser 0.3.1 created=2021-10-06T15:36:53.802943Z
```

Official API sources read:

- https://docs.rs/oxc_parser/0.146.0/oxc_parser/struct.Parser.html
- https://docs.rs/oxc_span/0.146.0/oxc_span/struct.Span.html
- https://docs.rs/swc_ecma_parser/48.1.0/swc_ecma_parser/
- https://docs.rs/swc_common/latest/swc_common/struct.Span.html
- https://docs.rs/boa_parser/0.22.0/boa_parser/
- https://docs.rs/boa_parser/0.22.0/boa_parser/parser/struct.Parser.html
- https://docs.rs/boa_parser/0.22.0/boa_parser/source/struct.Source.html
- https://docs.rs/boa_ast/0.22.0/boa_ast/struct.Position.html
- https://docs.rs/boa_ast/0.22.0/boa_ast/struct.Span.html
- https://docs.rs/rslint_parser/0.3.1/rslint_parser/
- https://raw.githubusercontent.com/rslint/rslint/v0.3.1/crates/rslint_parser/src/lib.rs
- https://raw.githubusercontent.com/rusty-ecma/ress/v0.11.7/src/lib.rs

Three Tavily search attempts failed with status 432, plan usage limit. Several
speculatively constructed raw GitHub tag URLs returned 404; only the successful
RSLint/Ress tagged reads above were used as raw-source evidence. No source was
copied from an AGPL reference.

## Artifact validation

The first artifact write failed because its new parent directory did not exist;
`mkdir -p qa/s04-js-parser-feasibility` then succeeded. This was not a test.

The first three validator invocations failed on hand-authored expected values:

```text
1. AssertionError at malformed combined end offset (expected end was wrong).
2. AssertionError at raw escape literal span (end 33 was wrong; exact is 34).
3. AssertionError at large input length (generator needed overhead 6, not 7).
```

The fixture was corrected, not the assertions weakened. Definitive local probes:

```text
multibyte source UTF-8 bytes=31; window.name=[19,30), window=[19,25)
combined malformed source: window.name=[17,28), trailing semicolon byte=28
escape source bytes=35; raw literal=[16,34); decoded hex=6c696e650a4142
large input: prefix 2 + suffix 4 + fill 1048570 = 1048576 bytes
large SHA256=d95efe00f25a50bbd1df379e2edaa7b00034abf594f4edba1d04c745c543db77
```

Final commands:

```sh
python3 qa/s04-js-parser-feasibility/validate_fixtures.py | \
  tee qa/s04-js-parser-feasibility/validation.txt
# PASS_FIXTURE_ARITHMETIC_ONLY; run=0 passed=0 failed=0 not_run_families=4
python3 -m json.tool qa/s04-js-parser-feasibility/fixtures.json >/dev/null
# exit 0
git diff --check
# exit 0
```

The Python checks validate artifact consistency only. They do not parse
JavaScript, establish parser behavior, measure time/RSS, or test cancellation.

## Delivery interruption

The first `git add ... commands.log ... && git commit ...` stopped at staging
because the repository ignores `*.log`; no commit was created. The file was
renamed to `commands.md`, references were updated, and fixture validation was
reproduced byte-for-byte. No ignored file was force-added and no ignore setting
was changed.

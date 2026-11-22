# CI acceptance and parity protection rollout

## Change

Base inspected: parity/2026-11-17 at d0e56832150334854665269fb9e2c27dc8c23058.
Its only workflow is CI/core, which checks, compiles tests and runs clippy
for webprobe-core. It does not execute tests.

The new Workspace acceptance workflow adds two independent, bounded jobs:

- `workspace`: fmt, workspace/all-target clippy, then exactly
  `cargo test --workspace --locked`, with no test-name filter. This includes
  desktop, core, support and report. Default features only; ignored tests remain
  ignored. This is not an all-features or browser/UI acceptance claim.
- `jvm-bridge`: Temurin JDK 21 and the checksum-verified Montoya API 2026.7 jar,
  then the five existing `ext_host::tests::stage*` contracts, serialized.
  A missing tool/jar, Cargo failure, prerequisite-skip diagnostic, ignored tests,
  absent/duplicate result summary, or fewer than five passing tests fails the job.
  This closes the existing tests' early-return-as-pass loophole without editing
  shared extension source. The guard checks all five exact test names as well as the passing count; its
  failure detection has twelve unit checks.

Both jobs pin Rust 1.100.0 through RUSTUP_TOOLCHAIN and explicit installation,
matching the repository's documented compiler generation. The stable manifest at
https://static.rust-lang.org/dist/channel-rust-stable.toml reported Rust 1.100.0
(release date 2026-11-12) when checked on 2026-11-22. Upgrade this workflow pin in
a reviewed PR with fresh workspace and JVM evidence, not an automatic stable
roll-forward. Existing workflows are not changed by this pin.

Both jobs check out the PR's exact head SHA (or pushed SHA), print it and use
read-only repository permissions. No path filters or continue-on-error apply.
Concurrency cancels obsolete runs for the same PR/ref. PR events exercise all
candidate branches; parity pushes recheck the landed tree. This is exact-head
rather than GitHub's synthetic merge-tree testing. Triage/QA still own the
combined-tree test before landing; these checks do not replace it.

No existing workflow or app source is changed. No billing/spending setting is
changed. Private-repository Actions availability remains subject to the owner's
existing quota and settings; a quota failure is not test evidence.

## Preserve the integration JVM coverage

Integration PR #125 was inspected at
2b756c1b37dae00d8f790f0b1f83471838e4060a:
https://github.com/Chaim12345/webprobe/pull/125

It adds Montoya analyzer/payload tests in CI/core, a Bambda JVM job that explicitly
runs ignored Java tests, and Repeater HTTP-handler JVM tests in a second workflow.
They cover different contracts from the existing stage tests and must remain.
This PR adds a separate workflow so it does not overwrite those pending changes.
Do not count this PR as having executed #125's tests. QA must test the final
combined tree, including #125's jobs, before acceptance.

## Protection recommendation, not applied

The live branch API reported `protected: false` for parity/2026-11-17 on
2026-11-22. The token's branch-protection detail read returned HTTP 403.
No rule was created and no administration capability is assumed.

CTO reviews gate design; QA/release accepts the evidence; triage remains the sole
parity writer. Proposed rollout, in that order:

1. Land this PR only after exact-head checks pass and independent review. Record
   actual job context names/IDs from its first green run. Do not require a check
   before its workflow exists on the branch.
2. Complete #125's acceptance and preserve its JVM jobs. Confirm fresh successful
   runs for `core`, `bambda`, `repeater-http`, `workspace`, and `jvm-bridge` on the
   accepted combined tree. These are proposed job names, not yet enforced checks.
3. Have the authorized repository administrator create a rule matching exactly
   parity/2026-11-17: require PRs, one independent approval, resolved conversations,
   no force pushes/deletion, and the verified Actions check contexts tied to the
   GitHub Actions app. Require the branch to be current before merging. Do not
   demand linear history, since the present triage lane uses merge commits.
4. Keep bypass limited to the owner's documented emergency route. Do not give
   every bot/admin a routine bypass or apply any change to master. If a narrow
   writer restriction is supported by the repository's existing plan, restrict
   parity pushes to the agreed triage identity without changing the plan.
5. Read back the rule and required checks, then verify a missing/failed check
   blocks a disposable PR and that the accepted green PR is mergeable. If the
   current plan or token cannot enforce this, report the exact limitation and
   retain procedural triage gates. Never change billing or buy enforcement.

Protection administration remains unverified and was not attempted. That part is
an administrator handoff after review, not completed work or a reason to relax
acceptance.

## Evidence limits

Local validation includes workflow structure, twelve Python guard tests, Python
compilation, whitespace checks and a fresh Maven artifact checksum. No local
Rust/JDK 21 build is claimed. Hosted run URLs and exact-head results belong in the
PR/board when available; queued, skipped or quota-blocked jobs are not passes.

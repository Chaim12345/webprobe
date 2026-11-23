# Security and compliance audit — 2026-11-22

Lane: security/compliance lead. Base: parity d0e5683. Repos: Chaim12345/webprobe (private) and Chaim12345/artex-rs (private). Everything below is verified against live clones and live registry/API data on 2026-11-22 unless marked unverified.

## 1. Dependency and license audit

Method: parsed every Cargo.lock (webprobe app + both vendor crates, artex-rs), resolved each unique name+version against the crates.io API for license metadata. Full inventories: `license-inventory-2026-11-22/*.tsv`.

**webprobe: 746 unique crate-versions** (app lock 585, egui-mcp vendor locks share the rest).
**artex-rs: 370 unique crate-versions.**

- No GPL-only, AGPL, SSPL, or Commons Clause dependency in either repo. Every third-party dependency is permissive (MIT/Apache-2.0 family, BSD, ISC, Zlib, BSL-1.0, CC0, Unicode-3.0, CDLA-Permissive-2.0).
- Optional-copyleft (safe as selected, do not flip): `self_cell` Apache-2.0 OR GPL-2.0-only; `r-efi` MIT OR Apache-2.0 OR LGPL-2.1-or-later. We consume the permissive option.
- Font licenses: `epaint_default_fonts` bundles Ubuntu Font License 1.0 and OFL-1.1 fonts. Permitted for distribution with the license texts; required if we ever ship binaries.
- Unlicensed own code: webprobe's four own crates (`webprobe`, `webprobe-core`, `webprobe-support`, `webprobe-report`) declare no license and the repo has no LICENSE file (verified at parity and master). Legally this is all-rights-reserved. See AGPL-POSITION-2026-11-22.md.
- artex-rs own 12 crates: AGPL-3.0-only (declared in workspace Cargo.toml and LICENSE).
- Vendored `vendor/egui-mcp-{client,server}`: upstream dijdzv/egui-mcp, MIT OR Apache-2.0, compatible.

## 2. Vulnerability scan (cargo-audit equivalent)

Method: OSV querybatch (RustSec + GHSA) over all 585 unique locked packages at PR #139 head 56ed24a. 7 crates flagged; none of them are packages added by #139.

| Crate | Advisory | Assessment |
|---|---|---|
| hpack 0.3.0 | RUSTSEC-2023-0084 (unmaintained), RUSTSEC-2023-0085 / GHSA-w7hm-hmxv-pvhf (decoder panics on invalid input) | Real exposure: we parse untrusted HPACK. PR #74 (hpack-patched migration) already exists — recommend landing it. |
| rsa 0.9.10 | RUSTSEC-2023-0071 / CVE-2023-49092 (Marvin timing sidechannel) | Marvin needs an RSA-decryption oracle; our use is CA keygen/signing, so practical exposure is low. Track. |
| url 2.5.8 | RUSTSEC-2026-0592 / GHSA-hrj5-67jp-wqp9 (stack overflow in `Url::origin()` on nested `blob:` URLs) | DoS on untrusted input; `url` sits in the request path. Recommend upgrade when a fixed release is available. |
| paste 1.0.15 | RUSTSEC-2024-0436 (unmaintained) | No known exploit. |
| zbus_names 4.3.5, zvariant 5.15.1, zvariant_derive 5.15.1 | RUSTSEC-2026-0371/0370/0372 (unmaintained) | Linux desktop stack only (atspi/accesskit). No known exploit. |

Note: OSV coverage of brand-new 2026 advisories can lag `cargo audit`; wire the real tool into CI (section 6).

## 3. PR #139 dependency-set review (requested)

#139 head 56ed24a adds 17 direct decoder-hash deps → 20 new locked packages plus 4 additional version lines (block-buffer 0.12.1, cpufeatures 0.3.1, crypto-common 0.2.2, digest 0.11.3). Verified against the lockfile diff from merge-base 4cddee0:

- **Licenses: all permissive.** RustCrypto crates (blake2, block-padding, gost94, hybrid-array, keccak, kupyna, md-5, md2, md4, ripemd, sha3, skein-hash, sm3, streebog, threefish-cipher, tiger, whirlpool, block-buffer, cpufeatures, crypto-common, digest): MIT OR Apache-2.0. blake3 1.8.7: CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception. constant_time_eq 0.4.2: CC0-1.0 OR MIT-0 OR Apache-2.0. tiny-keccak 2.0.2: CC0-1.0.
- **Advisories: zero** OSV/RustSec advisories on any of the new packages or new version lines.
- **No forced upgrades of existing dependencies**: the lock keeps digest 0.9.0/0.10.7, block-buffer 0.9.0/0.10.4, crypto-common 0.1.7, cpufeatures 0.2.17 alongside the new lines, so sha2/hmac and friends are untouched.
- Security note (not a blocker): this menu implements obsolete hashes (md2, md4, GOST, Tiger) by design for decoder parity. They must never be used for integrity decisions; that is a product-usage note, not a dependency issue.

Verdict from security/compliance: **no objection to #139 on dependency grounds.**

## 4. Secrets hygiene

Method: high-signal pattern scan (GitHub/GitLab/AWS/Slack/NVIDIA/Google key formats, PEM private-key blocks) over the working trees of **all 171 remote branch tips** of webprobe, plus a full-history pickaxe (`git log --all -p -G`, 601 commits); same scan on artex-rs (tips + full history).

- **No real secrets found** in either repo, in any branch tip or any historical commit.
- Only benign matches: the AWS documentation example key `AKIAIOSFODNN7EXAMPLE` in a bcheck test fixture (linear/m9/bcheck-scan), and a *quoted reference* to Burp's own hardcoded JWT test-key PEM inside docs/specs/R-09-jwt-checks.research.md (that key is PortSwigger's, embedded in their jar — it is third-party RE data, not an owner secret; see section 5).
- Corroboration: GitGuardian checks have been green on recent PRs (reported by triage; app-level check, unverified by this lane).
- CI gap: no repo-side secrets scanner workflow exists (GitGuardian is an external app). Recommend adding gitleaks to CI so scanning survives any change of GitHub app settings.

## 5. Third-party IP inside the webprobe repo

`re/mapping/` (classMap/methodMap/hierarchy/string-evidence TSVs), `graphify-out/`, `investigation.cany/`, `strings/map_merged.tsv` and `craft.json` contain deobfuscation maps and string extracts derived from PortSwigger's proprietary `burpsuite.jar` (build 52685), produced by the Craft Anything / graphify tooling.

- Both repos are **private** (verified via API 2026-11-22), so current exposure is limited to people with repo access.
- Risk: Burp Suite's license restricts reverse engineering; these artifacts must never be published or distributed. **Do not flip either repo to public** without a dedicated review of this content. Keep RE data out of release builds and docs that could be shared.
- `app/sidecar/demo-ext/demo-ext.jar` is our own locally built demo Montoya extension — no issue.

## 6. Safety rails — recommended gates

Current CI (verified `.github/workflows/ci.yml` + root `ci.yml`): clippy is the only blocking quality gate; tests run as subsets (CTO #132 already covers the full-workspace test gate). Recommended additions, in priority order:

1. **Branch protection** on `parity/2026-11-17` and `master`: require PR + green CI; restrict parity merges to the triage lane (today this is a social contract only). Requires repo admin — owner action.
2. **cargo-deny CI job** with `deny.toml` enforcing: license allow-list (the permissive set above), `advisories` check (cargo audit in CI), bans on new copyleft without sign-off.
3. **gitleaks workflow** on PRs and pushes (repo-side secrets scanning, complements GitGuardian).
4. **Redaction layer**: no central redaction/scrubbing module exists today (verified: no redact/scrub/mask code in app core). Before ARTEX evidence export or any report-sharing feature, add a redaction pass for credentials, cookies and auth headers in exported artifacts. Logging itself is minimal (one log macro site in core), so runtime log leakage is currently low.
5. Keep the repos private (see section 5).

## 7. Scope and limits

No Rust toolchain in this environment: nothing was compiled and `cargo audit` proper was not run; OSV querybatch was used as the advisory source. crates.io metadata reflects registry state on 2026-11-22. GitGuardian green-status claim is second-hand. This audit does not authorize license changes or distribution decisions; it feeds the CEO position in AGPL-POSITION-2026-11-22.md.

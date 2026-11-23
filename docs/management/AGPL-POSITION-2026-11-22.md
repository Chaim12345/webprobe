# AGPL position analysis — artex-rs and webprobe

For: CEO decision record (interim position in PR #133). From: security/compliance lead. Date: 2026-11-22. This is an engineering-compliance analysis, not legal advice.

## Verified facts

1. **artex-rs is AGPL-3.0-only and a declared derivative of upstream ARTEX.** LICENSE is GNU AGPL v3; NOTICE attributes upstream "ARTEX - AI autonomous penetration testing system, Copyright (C) 2026 Autumn-27 and contributors" (original repo withdrawn October 2026; continuation at github.com/BaaRai/ARTEX, fetched 2026-11-22: AGPL-3.0, multiple copyright holders including Autumn-27). The NOTICE states the domain model, dual-graph architecture, guard/intercept pipeline semantics and engine loop were ported from the AGPL original.
2. **The owner cannot unilaterally relicense artex-rs.** Whatever the port's exact code overlap, the repo declares itself a derivative work of a multi-author AGPL project. Those upstream rights persist; withdrawal of the original repo does not terminate downstream licenses. artex-rs stays AGPL-3.0 and its notices must be preserved.
3. **artex-rs commit authorship is owner-side only** (git shortlog --all: Chaim Shuster plus owner-directed agent identities; no external human contributors). So the owner's *own new code* inside artex-rs is his to reuse elsewhere — but only by extracting his parts, not by relicensing the whole.
4. **webprobe has no LICENSE file** (verified at parity d0e5683 and master) and no license fields on its four crates: default all-rights-reserved. Commit authorship is owner-side only (Chaim12345 identities, Instinct agents, the owner's Claude session; no external human contributors across all branches), so the owner can choose any license for webprobe, including AGPL-3.0, without third-party permission.
5. **webprobe code already flowed into artex-rs one way**: NOTICE records the recording-proxy component incorporating webprobe code "contributed by its author to this project under the AGPL-3.0". That contribution stands (the owner may license his own code to his own AGPL project); it does not pull artex-rs into webprobe.
6. **All webprobe/artex-rs third-party dependencies are permissive** (SECURITY-COMPLIANCE-2026-11-22.md §1), so dependencies impose no license constraint in either direction.
7. **Both repos are private** (GitHub API, 2026-11-22).

## What triggers AGPL obligations

- **Private local use triggers nothing.** Running, modifying and combining AGPL code privately creates no source-disclosure duty. The CEO interim position (PR #133: private, local, separate-process evaluation; no in-process linking, no combined distribution, no remote exposure) is fully compliant as long as it stays private and local.
- **Distribution (conveying) triggers §13-independent copyleft.** Shipping a binary that links or derives from artex-rs code requires offering the complete corresponding source of the combined work under AGPL-3.0 — which would include webprobe's source if they are one work.
- **Network use triggers §13.** Offering artex-rs functionality to users over a network requires offering those users its source (and, if modified into a combined service, arguably the combination). The CEO exclusion of "remote service exposure" is the right call for now.
- **Separate processes are a common compliance pattern, not automatic clearance.** The CEO already recorded this correctly. Where the boundary lands depends on the intimacy of communication. Two owner-controlled projects talking over stdio/ACP are low practical risk — the only plausible claimant is upstream ARTEX authors, and enforcement interest against a private tool is minimal — but a *distributed* bundle should be engineered and documented so each side is genuinely an independent program: own binary, own process lifecycle, generic documented protocol, no shared internal data structures, separate license notices.

## Decision tree for M0 (before artex-kernel code enters webprobe)

| Option | What it means | Cost |
|---|---|---|
| A. Keep interim position | Private local evaluation only, separate processes, nothing distributed. No obligations. | Zero; blocks any shipping. |
| B. Distribute with process separation | artex stays its own binary talking ACP/stdio; webprobe keeps its current unlicensed/private status or picks a permissive license. | Engineering discipline at the boundary; some legal gray area, low practical risk. |
| C. License webprobe AGPL-3.0 and integrate freely | In-process linking allowed; whole combination AGPL-3.0. Owner can do this unilaterally (fact 4). Precedent: owner moved sdrstream to AGPL-3.0 ("license is irrelevant", 2026-10-21). | webprobe source becomes AGPL on distribution — including the RE/parity data problem (below). |

**Blocker for option C today:** the webprobe repo contains PortSwigger-derived RE data (SECURITY-COMPLIANCE-2026-11-22.md §5). Releasing webprobe under AGPL — or making the repo public — publishes that data. Option C requires first removing `re/`, `graphify-out/`, `investigation.cany/`, `strings/map_merged.tsv` and related Burp-derived content from the tree *and* from history, and accepting that Burp-parity knowledge then lives only in private notes.

## Recommendations to the CEO

1. **Adopt the interim position as written in PR #133.** It is compliant; this audit found no contradiction in dependencies, contributors or packaging.
2. **M0 gate stays:** no artex-rs code, crates or patches land in the webprobe repo until the owner picks B or C. The vertical slice in PR #127 already plans a separate `artex-kernel` crate — keep it in the artex-rs repo so the AGPL boundary follows the repo boundary.
3. **Preserve notices:** never strip or edit LICENSE/NOTICE in artex-rs; keep the Autumn-27 attribution. Add SPDX headers to new artex-rs files.
4. **If the owner wants to ship a combined product**, present B vs C as a product decision with the costs above; C additionally requires the RE-data purge and a Burp-EULA review.
5. **Re-verify upstream provenance** before any public release of artex-rs: the original Autumn-27/ARTEX repo is withdrawn; the BaaRai/ARTEX continuation is AGPL-3.0 and consistent with our NOTICE, but the withdrawn original's exact license text should be archived privately (we hold artex-rs's own LICENSE copy — sufficient for now).
6. **License hygiene for webprobe even while private:** add a root LICENSE or an explicit "All rights reserved" note so the default is deliberate, not accidental.

## Unverified / open

- Exact line-level code overlap between artex-rs and upstream ARTEX (the NOTICE says design and pipeline semantics were "ported"; whether Go source was transliterated is not established here). Material only to how strong the derivative claim is; the declared NOTICE already binds our practical position.
- Whether the owner holds a Burp Suite license covering the RE activity; affects §5 of the audit, not this position.
- Autumn-27/ARTEX original repo state could not be fetched directly (withdrawn); continuation repo used as evidence.

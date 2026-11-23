# CEO decision record

2026-11-22, 13:13 Asia/Jerusalem. Supersedes the owner-question status in product note PR #130 for the decisions below. The owner delegated project choices at 13:12; this record does not widen spending, publication or account authority.

## Product calls, ready for the program board

- **D-CEO-01, MIME gate: accept #103's policy.** Interpret macro request bodies as forms only for application/x-www-form-urlencoded, and as JSON only for application/json or application/*+json. Unknown, missing, binary and multipart types remain unchanged. Preserve bytes and Content-Length when leaving a body untouched. Query substitution remains available. Reason: a security workbench must not silently rewrite unrelated data. Review and integrated regression gates still apply; this is not a merge instruction.
- **D-CEO-02, Organizer: deleting a collection preserves its items.** Move items to Inbox, retain request/response evidence and annotations, and say so in the confirmation. Deleting items is a different explicit action. Reason: removing organization must not silently remove captured evidence. Engineering must verify persistence and restart behavior before closure.
- **D-CEO-03, ARTEX builder: proceed with isolated private work.** Start the kernel/mock-contract slice on a new artex-rs branch and PR. Incorporate the CTO's one-shot transport, cancellation and durable intent corrections before promising a WebProbe send contract. Native integration remains the goal; no full scanner/Intruder autonomy or team-server expansion in M1.

Parser behavior, safety-rail defaults and timing-based smuggling are assigned to the CTO. They remain separate technical decisions, not implicitly changed here.

## D-CEO-04, interim licensing position

**Choose private, local, separate-process evaluation. Do not link ARTEX into WebProbe or distribute a combined product yet.** Preserve ARTEX's license and notices. Build and test ARTEX internals inside its own private repository. Develop the neutral protocol contract with mocks; a local stdio process is the evaluation boundary, not a claim of license exemption. Do not expose a modified ARTEX service to remote users as part of this phase.

### Reasoning and evidence

The live artex-rs main Cargo.toml declares AGPL-3.0-only; its LICENSE contains GNU AGPL version 3. The license's section 2 permits making and running works not conveyed, subject to its conditions. Section 13 separately addresses modified versions supporting remote network interaction and requires offering Corresponding Source to those remote users. Therefore, a private repository is not itself a reason to ignore network-use duties.

The LICENSE also defines Corresponding Source to include specifically required shared libraries and certain tightly coupled subprograms. A subprocess or ACP boundary is not enough evidence to conclude that the programs form independent works. We make no such legal conclusion here. Keeping an independent runtime and protocol contract preserves an architectural option while the distribution analysis is completed.

The security/compliance lead must inventory actual dependencies, ownership/contributor rights, notices and the proposed packaging/network interaction. Before any in-process integration, combined conveyance or remote service, return a concrete position: documented AGPL-compliant release plan, verified alternative licensing rights, or a reviewed independent-program arrangement. CEO records the resulting decision; if rights remain unclear, obtain qualified legal review. No relicensing, source publication or attribution removal is authorized by this interim position.

Sources read live: [artex-rs repository](https://github.com/Chaim12345/artex-rs), main Cargo.toml workspace.package.license and LICENSE sections 0-2 and 13. This is an engineering risk decision, not legal advice or an assertion that all project copyrights are owned by the account holder. GNU website fetches were unavailable; the checked-in license text, not search snippets, supports the analysis.

## Delivery boundary

Docs only. No product defaults, license files, dependency links, manifests, application code, releases or PR states change in this PR. The PM owns board entries; engineering owns implementation and proof. Existing non-master branch, single parity-writer, secret-handling and review rules remain in force.

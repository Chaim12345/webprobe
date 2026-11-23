# CEO licensing clarification after security review

2026-11-22, 13:26 Asia/Jerusalem. D-CEO-05. Supplements [#133](https://github.com/Chaim12345/webprobe/pull/133); review input: [security/compliance #143](https://github.com/Chaim12345/webprobe/pull/143).

**Decision: retain private, local, separate-process ARTEX evaluation. Isolated kernel/mock work continues. Do not link ARTEX into WebProbe, publish either repository, distribute a combined product or expose a modified ARTEX service to remote users under this decision.**

The live artex-rs NOTICE declares a derivative of ARTEX and attributes Autumn-27 and contributors; Cargo.toml and LICENSE specify AGPL-3.0-only. Preserve those notices. Do not assume the owner can relicense the whole derivative. Any alternative license route would require independently established rights from every relevant rightsholder, not owner-side commit names. The earlier reference to alternative licensing in #133 is conditional, not an available unilateral option.

Security review #143 reports proprietary Burp-derived maps, extracts and related research artifacts in WebProbe, including re/, graphify-out/, investigation.cany/ and strings/map_merged.tsv. The current parity tree independently confirms research-artifact paths remain present; this note does not re-audit their complete contents or history. WebProbe has no root LICENSE in that tree. Do not treat a new AGPL file or repository-visibility change as solving rights to third-party content.

Before any release, security/compliance must define the actual release contents, provenance, notices, applicable vendor terms and source obligations. If a clean release tree or history treatment is proposed, present it for review first. **No deletion, history rewrite, license-file change or publication is authorized here.** Removing named folders alone would not establish that the remainder is clear to distribute.

Process separation is not automatic copyleft clearance. A private repository is not an exemption from modified remote-use obligations. We do not rely on estimates of enforcement interest, and we do not certify legal compliance from this engineering review. Keep the existing no-combination/no-remote-exposure boundary until a concrete rights and packaging position is recorded, with qualified legal review if needed.

Sources read live: artex-rs main NOTICE, Cargo.toml and LICENSE; #143's AGPL-POSITION-2026-11-22.md and SECURITY-COMPLIANCE-2026-11-22.md; WebProbe parity tree at 8beefa2. No license, code or artifact changes in this docs-only PR. PM records D-CEO-05; security/compliance owns the release-readiness review.

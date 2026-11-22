# WebProbe product order

2026-11-22. Recommendation, not a new owner commitment.

## The bets, in order

1. **One trustworthy workbench.** Finish the review stack in [#125](https://github.com/Chaim12345/webprobe/pull/125), then prove Proxy -> Repeater -> Intruder -> Logger -> Organizer on one pinned build. Include redirects, request/response hooks, Drop variants, persistence and the crawl-counter follow-up. Automated suite success does not replace this cross-tool check. Keep hash-list/h2 work in its current lane, not another duplicate lane.
2. **Parity that preserves bytes and tells the truth.** Use [#128](https://github.com/Chaim12345/webprobe/pull/128) as the evidence queue: Decoder byte-safe stages and codecs first, then Sequencer biased/periodic/correlated controls, then response-variation values. Integrate the existing codec/hash work before adding more. Manual Drop validation belongs in bet 1; broader WebSocket, Logger and Organizer workflows follow. For [#121](https://github.com/Chaim12345/webprobe/pull/121), recount scanner coverage and add the regression gate first, then bounded GraphQL/server-feature/cache checks and DOM verification. Historical coverage counts disagree; do not launch a 113-item build queue from them.
3. **A native ARTEX task, not a second platform.** Start licensing research and isolated mock-contract preparation now. After the licensing choice, build only [#127](https://github.com/Chaim12345/webprobe/pull/127) M1: history read -> one loopback Repeater send -> visible result and Stop. Require feature-on/off tests and unchanged manual tools. M2 secret handling, budgets and persistence precede live BYOK use; drafts/findings and ACP follow. Do not wait for complete Burp parity to start this slice.

## Cut from this delivery, not from the vision

Defer team-server implementation until the native slice and identity/RBAC design are ready. Team server remains explicitly in scope. Defer broad agent-driven scanning, HTTP/3/gRPC, Wasm, web dashboard, report redesign and async Phase 3 without measured need. Fold duplicate AI-assist/agent plans into ARTEX rather than building two systems. No new public-target, public-OAST or paid-provider tests in this delivery.

## Owner decisions only

- **Allow AGPL obligations for a combined distributed WebProbe/ARTEX build?** Recommend **no for now**; finish the licensing review before combining/distributing. Process separation is an option to assess, not a legal exemption. A no does not cancel ARTEX.
- **Adopt #103's explicit form/JSON MIME gate, leaving unknown bodies unchanged?** Recommend **yes**. Avoid silent body rewriting.
- **Make #96 parser strictness a blanket compatibility change now?** Recommend **no**. Keep fuzz coverage; propose framing-specific changes with raw-traffic fixtures before changing behavior.
- **When deleting an Organizer collection, keep its items by moving them to Inbox?** Recommend **yes**, with clear confirmation text. This is a proposed product rule, not a claim about current behavior.
- **Enable scope-only sends, per-task budgets and typed tools without shell access as ARTEX defaults?** Recommend **yes**. These limits do not restore per-step prompts.
- **Lift the no-timing rule for smuggling/desync now?** Recommend **no**; keep the exclusion explicit until an opt-in design and false-positive evidence are ready.

Already settled, not questions again: native ARTEX, ACP option, assistant/team-server scope, and removal of per-step approval.

## Evidence boundary

Read #121, #127, #128, #125, #103 and #96 live on November 22. #128 proves narrow separate-head results against Burp Community, not integrated or Professional parity. #121's old PR statuses and counts are planning inputs, not current release facts. This note changes no code, licenses, permissions, defaults or PR state.

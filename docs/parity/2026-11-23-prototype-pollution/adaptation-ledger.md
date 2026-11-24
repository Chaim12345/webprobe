# Prototype-pollution adaptation ledger

Local preparation on #186 94eb2a9f8fe603526256fe5c2b72c068442c550f.
This is not a landing or closure approval. The final reviewed #186 pin,
combined exact-source review, independent QA and Triage landing remain pending.

## Replacement mapping

- Source PR #180, team/r13-proto-pollution,
  cc0f5dfd7c4871ad225272abaca2af1317c71db7, remains unchanged.
- This fresh adaptation carries its URL-driven addition-only pollution
  instrumentation, registry entry, source/confidence semantics, two live labs,
  and sink-table drift coverage onto #186's shared stored/reflected runtime.
- The former generic family-macro registration becomes a dedicated base-only
  check. Pollution does not claim reflected or stored variants. URL-source
  evidence keeps separate query/hash dedup and conservative confidence.
- Stored-token evidence is excluded at instrumentation and check boundaries.
  A stored token mixed with a URL token is also excluded, never relabeled.
- No dependency on #188's test branch. No writes to parity or master.

## Inherited source requests

The original #27/#63/#82 comparison and closure packets remain tied to #180.
They must be reconciled to the final replacement head and landed SHA before
Triage closes anything. #63 restacks #27 with corrections; #82's clippy repair
was already obsolete on the current runtime. This ledger does not itself
establish source closure or claim full historical-delta reconciliation.

## Local evidence

- Existing query and fragment labs: Tentative and Firm respectively.
- Multi-family isolation: query pollution and fragment DOM-XSS remain separate.
- Combined stored/query/hash fixture: two distinct pollution findings and one
  stored DOM-XSS finding; no source/family cross-labeling; separate dedup.
- Stored-only and mixed stored/URL pollution are excluded. Reflection without
  new own-key evidence and unchanged prototypes do not report pollution.
- Shared operation counts: 1 baseline + 1 stored submission + 1 navigation for
  simple pages; resource-heavy case is 1 baseline + 64 operation requests.
- Core test clippy with warnings denied passed during local preparation.
- Final expensive suite deliberately deferred; no final-API or UI verification
  claimed by these local results.

## Coverage limits and follow-ups

Addition-only Object.prototype polling, not existing-property overwrites.
Stored pollution is not covered. Transient additions between polls can be
missed. No gadget discovery or exploitability claim. The throwaway browser
profile contains inert random-token pollution; it is not the user's profile.
Cross-family consumption of already-proven cached hits after cancellation
must be tested on #186's final partial-outcome implementation. UI status
pixels are outside this local preparation and remain unverified here.

## Partial-outcome adaptation on 94eb2a9 (local, not accepted)

The dedicated check opts into stopped cached-DOM dispatch and its only probe
access is dom_analysis_hits, which after stop reads existing cells only.
Incomplete pollution findings retain source/confidence and explicitly display
the bounded diagnostic. A stopped-dispatch regression preserves pollution,
XSS and cookie findings plus their structured hits with zero connections and
no new cache cell. A live-browser regression retains both pollution and XSS
snapshots after cancellation. These targeted tests pass locally, but 94eb2a9
is not accepted: the runtime must retain a monotonic union across shrinking
or empty later snapshots. The corrected reviewed pin remains awaited.

## Source-approved dependency refresh

Final vehicle base: 03caee2b7df119c9f84cfc46e820eda60c8fff49 (#186),
source-approved as a dependency pin. Existing #180 remains unchanged at
cc0f5dfd7c4871ad225272abaca2af1317c71db7. The pending adaptation vehicle
owns only pollution instrumentation, its dedicated check, registration,
fixtures and these coverage/ownership notes. The inherited runtime owns
monotonic snapshot retention, partial outcomes, safe stop/cache dispatch,
response completeness and Scanner UI status records. Formatting-only changes
to inherited runtime/status files are separated from semantic adaptation.
No parser integration, UI-pixel verification, full-suite acceptance, parity
landing or historical-source closure is claimed by this refresh.

## Canonical-format replacement of #197

Replacement base: 7b7483f58b63c4c3e7321e26c35c5f769b072d1b.
Branch: team/proto-pollution-v2-20261123. The identity checkpoint
3190ff991f25a91b9b53582fa828c11c14e78477 has exactly the same complete
Git tree as original #197 head 38e8e8ae60d903e29c72700c049364a45d25685a:
63de527177ec5f7523451be3651b5fd89fe0a24a. The original inherited-format
commit is therefore not replayed. Semantic preparation commits are
consolidated without changing their final source; this note is a separate
documentation-only change after that identity checkpoint. The source #197
and #180 histories remain unchanged. No #188 tests or parser integration
are included. Triage owns composition and eventual closure.

Refreshed verification on the identity checkpoint: fmt check and core-test
clippy with warnings denied pass; six targeted tests pass, including both
stopped-dispatch tests and live-browser pollution+XSS cancellation. Full
suite and UI-pixel verification are still pending and not claimed here.

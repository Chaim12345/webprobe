# Prototype-pollution adaptation ledger

Local preparation on #186 b448c70473820f9c69f4021b3b32c898b41c8863.
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

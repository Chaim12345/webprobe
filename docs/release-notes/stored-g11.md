# Stored G.11 checks

Stored G.11 probes persist in the target wherever the application stores input. They use inert tokens and .example URLs. No cleanup is attempted.

Only GET/HEAD retrieval requests are replayed. The first G.11 hit stops the remaining G.11 families for that injection/retrieval pair. These limits reduce traffic and avoid replaying unsafe retrieval methods; they can leave other findings undetected.

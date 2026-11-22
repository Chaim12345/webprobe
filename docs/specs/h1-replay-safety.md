# HTTP/1 replay safety

An origin may commit a request and then lose its response. A transport error
therefore does not prove that a request was not sent or was not processed.
Method idempotency and reuse of an idle socket do not establish that proof.

HTTP/1 sends now make one exchange attempt, on both TCP and TLS. Any exchange
error retires the checked-out socket and returns the error without opening a
replacement connection. The opt-in h2c upgrade includes the original request,
so its failure likewise returns without replaying that request as plain HTTP/1.
A declined upgrade with an ordinary response still returns that response.
No new automatic retries are retained. Negotiated HTTP/2 retry policy is outside
this change, as are pool admission and response-completeness decisions.

This is the conservative alternative to a new outcome API: failures before any
send are not-sent; once an exchange begins, an error has a possibly-processed
outcome. Only an actual response supplies response evidence, interpreted by the
existing reader. In particular, the existing cleartext EOF behavior can return
an empty or incomplete non-reusable response rather than an error. This patch
does not relabel that result as a completed origin operation or change the
reader API. Callers must not infer absence of effects from missing responses.

The live replay-safety tests count accepted origin connections, received request
heads and fully committed POST effects. They cover pooled response loss, an
origin that commits but withholds its response, partial request writes, and
h2c response loss. TCP and TLS are exercised, including the positive case of
two successful effectful requests sharing one connection. Partial-write tests
send an 8 MiB body while the origin closes after its first byte, and assert an
actual write error, one received prefix, no completed effect and no replacement
connection. A bounded listener check also observes queued replacement sends.

Base: pinned PR #151 commit 5645ed3. Pool-admission behavior from that PR is
preserved. This PR must follow #151 and be reconciled with the then-current
parity branch before landing; it is not based on the integration stack #125.

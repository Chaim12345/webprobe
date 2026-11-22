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

Base: pinned PR #151 commit bf306bd (rebased from 5645ed3). Pool-admission behavior from that PR is
preserved. This PR must follow #151 and be reconciled with the then-current
parity branch before landing; it is not based on the integration stack #125.

## Visible behavior changes

- A peer can close a pooled socket between the idle check and the next write.
  That rare FIN/RST race can now surface a visible send error instead of being
  hidden by an automatic resend. There is no proof that a failed exchange had
  no origin effect, so callers must decide whether to send again.
- With opt-in h2c, an origin dropping the upgrade request no longer triggers a
  second, plain HTTP/1 request. An ordinary declined-upgrade response is still
  returned normally.
- Intruder makes one attempt per attack row, including when old settings ask
  for retries. Its default retry count is zero; the legacy saved fields remain
  compatible, while the controls explain that automatic retries are disabled.
- A failed check-session validation aborts the pending send. It does not carry
  on and send the same effectful request after losing the validation response.
  An empty/missing final validation head is a failure too. Existing successful
  validation and configured login-macro behavior are not changed.

## Caller retry audit

Audit scope: HTTP/1 transport errors through the following callers, plus their
shared send/session wrappers. This is not a claim that arbitrary configured
workflows never intentionally repeat requests.

| Caller | Call chain and policy |
| --- | --- |
| Repeater | `ui/repeater.rs::repeater_send` -> `repeater_ops::send_following` -> `send_once` -> `net::send_raw_with` / `send_tls_raw_with`. A missing response returns `FollowResult` immediately; the UI shows its error. The loop follows only an actual redirect response under the user's redirect mode. No error-based resend. |
| Scanner | `scan/engine.rs::start_active_scan` -> `scan_checks/context.rs::ScanCtx::send` -> `scan/request_builders.rs::send_one` -> raw send. Each call returns its optional response once. `send_following` advances only from an actual redirect. Active-check confirmation probes are planned scan traffic, not a generic transport-error retry loop. |
| Intruder | `intruder_run.rs::worker` -> `send_with_retry` -> raw send. This formerly retried any absent response, including possibly-processed POSTs. The helper now makes one attempt irrespective of legacy retry settings. The older `net/attack.rs::start_attack` also sends once per attack row. |
| Shared wrappers | `net/send.rs::send_raw_with` / `send_from` and `net/conn_reuse.rs::send_tls_raw_with` return the transport outcome without retry. Cookie/logging hooks do not resend. Session validation formerly continued after its probe failed, allowing the pending identical request to send again. The session helpers now return an error and the tool/Proxy/WebSocket callers abort that send. `net/session.rs::run_macro_text` stops on the first absent response; configured macro steps and post-request macros are explicit workflow traffic, not retries. |
| Other directly inspected sends | `sitemap_compare.rs` sends once per selected item; Sequencer's selected capture loop in `app/src/tools.rs` stops on a send error; `app/src/discovery.rs` returns one raw-send result to its discovery driver. These are not shared transport retry wrappers. |

Transport fixtures fail against the unmodified base retry logic. Additional live
fixtures exercise the real Intruder worker with three requested legacy retries,
and the shared raw-send wrappers with a configured check-session rule. Each
counts one committed POST effect and no replacement connection after the reply
is lost, over both TCP and TLS. Restoring either old higher-layer error policy
makes its fixture fail, even with the lower-level transport fix present.

### Known remaining item for separate triage

`crawl.rs::browser_entry` sends a captured browser request again when the
browser response head/body metadata are absent. Missing capture metadata does
not prove the browser request was unprocessed. This fallback can repeat an
effectful browser request and needs its own outcome policy and origin-counter
fixture. It is outside this PR's specified Repeater/Scanner/Intruder/shared
retry-wrapper scope and is not fixed here. Negotiated HTTP/2 retry remains
owned by the separate h2 lane.

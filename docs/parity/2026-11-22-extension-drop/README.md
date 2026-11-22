# Extension-dropped proxy requests

Spec: the measured Burp Community 2026.11.2 behavior in PR #112,
`docs/parity/2026-11-22-real-burp/evidence/drop-summary.json`.
Base: PR #99, `cc7407d`.

An extension request-hook Drop now returns a local HTTP 200 HTML error page,
with UTF-8 Content-Type, byte-accurate Content-Length, no-store, and connection
close. The fixed body says an extension dropped the request and that it was
not sent to the destination server. No request data or extension text is
reflected into HTML. This 200 is a local diagnostic, not an origin success;
it does not create an origin-response history entry. The return remains before
upstream target selection and forwarding. Response drops, manual-intercept
drops and WebSocket drops are unchanged.

Regression tests use real TCP sockets for GET and POST, plus TLS over CONNECT.
They assert the response status, content type, body length, diagnostic wording,
no reflected request HTML, no origin connection, and no history entry.

`curl-proof.txt` records a separate curl request through the real proxy handler,
with a request-dropping Rust extension registered and an origin listener
counting connections. curl exits 0, receives HTTP 200 and the HTML explanation,
and the origin receives zero connections. This isolates the generic extension
pipeline; the Java Montoya transport is not re-measured here.

Reproduce the client proof:

```sh
cd app
cargo run -p webprobe-core --example extension_drop_probe
# In another terminal:
curl --noproxy '' -i -x http://127.0.0.1:18081 http://127.0.0.1:18765/admin-drop
```

No new Burp execution or terms acceptance was needed for this change. The page
matches the measured response semantics, not Burp's proprietary page styling
or exact bytes.

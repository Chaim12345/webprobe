# Flows and states

Written by hand from the code (not generated). Class diagrams do not show
these: Rust has no inheritance, and the interesting structure here is the
order of steps and the states a held message moves through.

## A proxied HTTP request

`net/engine.rs` (`serve_plain`, `serve_mitm_conn`, `upstream_and_deliver`) and
`net/intercept.rs`.

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Proxy connection thread
    participant Q as Intercept queue (UI)
    participant X as Extensions
    participant O as Origin
    participant H as History and passive checks

    C->>P: request
    P->>P: read and validate (ambiguous or malformed is refused)
    alt interception on and rules match
        P->>Q: hold request
        Q-->>P: forward (possibly edited), drop, or client gone
    end
    P->>X: request hooks (may edit or drop)
    P->>O: send upstream (HTTP/1.1 or HTTP/2)
    O-->>P: response
    P->>P: match and replace rules
    P->>X: response hooks (may edit or drop)
    alt response interception rules match
        P->>Q: hold response
        Q-->>P: forward, drop, or client gone
    end
    P-->>C: response
    P->>H: record exchange, run passive checks
```

## A held intercept item

`intercept_request` / `intercept_response` wait in `intercept_wait`, which
polls the client's liveness every 200 ms.

```mermaid
stateDiagram-v2
    [*] --> Held: rules match, item queued
    Held --> Forwarded: user forwards (original bytes if unedited)
    Held --> Dropped: user drops
    Held --> Forwarded: interception turned off (release all)
    Held --> Abandoned: client disconnected
    Forwarded --> [*]: sent on
    Dropped --> [*]: nothing sent
    Abandoned --> [*]: removed from queue, nothing sent
```

## A REST API scan task

`rest_api.rs` and `scan_run.rs`.

```mermaid
stateDiagram-v2
    [*] --> Running: POST /v0.1/scan (one at a time)
    Running --> Running: scanner copies its own issues into the task's collection
    Running --> Succeeded: crawl and audit finished
    Running --> Failed: scan thread panicked
    Succeeded --> [*]
    Failed --> [*]
```

# R-12 — Burp Repeater send groups: evidence and WebProbe implementation plan

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

## Evidence conventions and limits

This is read-only research against the shipped Burp documentation and decompiled classes. `B:` below means `/root/burp-re/out/readable_strict/root/`; `D:` means `/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/repeater/`; `W:` means the WebProbe repository root. Line numbers refer to the files as inspected on 2026-11-18. Obfuscated names are retained rather than inventing friendly class names. Documentation establishes user-visible behaviour; decompilation establishes the implementation path. No Burp or WebProbe code was executed.

## 1. Repeater tab groups

### Creating and naming

* The documented creation flow is: add-tab button → **Create tab group**, enter **Group name**, choose tabs individually or with **Select all**, choose a colour, then **Create**. A group icon is added to the tab bar and clicking it reveals its tabs. Quotation: “Click the add tab button … **Create tab group**”; “Enter a **Group name**”; “Click **Select all** … or use the checkboxes”; “Select a group color”; “Click **Create** … An icon for the group is added to the tab bar.” (`D:groups.html:47-67`.)
* `Zu_x.showNewTabGroupDialog` constructs the creation dialog, collects the selected tab indices, and passes the entered name and selected colour into group creation (`B:Zu_x.java:29-42`). `Zg52` supplies separate **Create new group** and **Edit group** constructors (`B:Zg52.java:33-39`), a `Group name:` text field (`B:Zg52.java:105-113`), tab checkboxes and Select/Deselect all (`B:Zg52.java:116-147`, `B:Zg52.java:192-198`, `B:Zg52.java:247-260`), and Create/Save actions (`B:Zg52.java:157-168`). Create is enabled only when at least one tab is selected and the name is non-blank (`B:Zg52.java:171-173`).
* The default-name prefix in `Zu_x.java:31` is the undecoded static `a`; the default-name text is **not established** from the readable class or the decoded-string TSVs searched. User-chosen naming is established; the exact generated default name is not.
* Group creation allocates a group object from the name, applies its colour, marks it enabled, inserts its group header, associates the selected tabs, and increments their membership count (`B:Zfla.java:512-525`). The model exposes name, colour, UUID, enabled state and tab count (`B:Zisp.java:15-27`, `B:Zisp.java:36-67`). Editing updates both the visible title and the model's name/colour (`B:Zu_x.java:72-78`).

### Colour and tab-bar presentation

* The colour selector contains one `Zggv` per `Zxpb` value (`B:Zg52.java:200-217`); selection returns the selected value or `Zxpb.DEFAULT` (`B:Zg52.java:101-103`). There are 15 enum values, `GROUP_0` through `GROUP_14` (`B:Zxpb.java:11-26`). The enum stores a background colour, accent colour and persistent byte id (`B:Zxpb.java:28-38`), and `fromId` falls back to `DEFAULT` (`B:Zxpb.java:41-43`). Exact colour names/RGB values are **not established** here: they are indirect `Zfhh` theme references, not literals in `Zxpb`.
* The group header paints its background or accent depending on expansion state and recolours its folder icon (`B:Zhdx.java:58-63`). The adjacent badge displays the current tab count and uses the group's accent colour (`B:Zhiv.java:12-25`). The chooser itself draws a filled circle, with a white centre when selected (`B:Zggv.java:20-46`).
* Automatic initial colour selection takes the first unused colour, or cycles after the last group's colour when all are used (`B:Zs1q.java:9-17`).

### Membership operations and ordering

* Documentation: right-click a tab to add it to a group; remove it with **Remove tab from group**; removing the last tab closes the group; **Ungroup tabs** closes the group but leaves tabs open; **Delete entire group** closes the group and all tabs (`D:groups.html:71-95`). The implementation exposes Remove/Close other/Move for grouped tabs (`B:Zio9.java:103-135`), Add for ungrouped tabs (`B:Zio9.java:138-174`), and Edit/Ungroup/Close-all on the group menu (`B:Zio9.java:205-250`). (The readable implementation labels the last item **Close all tabs in group**, whereas the documentation says **Delete entire group**; do not silently treat those labels as identical.)
* Group tabs are physically rearranged together by `Zfla.Zx`, preserving their collected order (`B:Zfla.java:474-509`). Duplicating a tab is available for grouped tabs (`D:managing-tabs.html:52-54`; `B:Zio9.java:177-181`).

### Project persistence

* Documentation explicitly says: “Any tab groups you create remain open even if you restart Burp Suite.” (`D:groups.html:68-70`.) This establishes restart persistence, but the documentation does not name an on-disk schema.
* The serialized in-memory model has `@Zwgi(0)` on the name, `@Zwgi(1)` on the colour-id accessor, `@Zwgi(2)` on enabled state, `@Zwgi(3)` on tab count and `@Zwgi(4)` on the UUID wrapper (`B:Zisp.java:5-13`, `B:Zisp.java:65-73`). The alternate model reads/writes name and the colour byte through its backing store (`B:Zmf_.java:15-32`).
* Restore walks persisted Repeater entries and groups; after all tabs in a group have been recreated it calls group population with the persisted `ZhS()` name and `ZhH()` colour (`B:Zeag.java:32-40`, `B:Zeag.java:53-94`, especially `:83-86`). This is evidence of project-state restoration, not merely an in-memory tab convenience. The binary project-file field layout is **not established** and is unnecessary for the WebProbe design.

## 2. Send modes and per-tab outcomes

### Shared UI dispatch and validation

The Send drop-down contains exactly the three group choices, followed by **Send group** (`D:send-group.html:58-77`). Internally the choices are `SEND_ON_SINGLE_CONNECTION`, `SEND_SEQUENCE` (separate connections), and `SEND_PARALLEL` (`B:Zsmu.java:13-17`). `Zxnu` validates before starting either path and opens the **Cannot send group** dialog with the individual problems (`B:Zxnu.java:713-721`; dialog construction at `B:Ze17.java:18-38`, list items at `:72-74`). The validation categories are empty request, missing target, WebSocket tab, HTTP-service mismatch, protocol mismatch, HTTP/1 keep-alive, and disabled HTTP/2 pooling (`B:Zr4d.java:7-14`). `Zw1s` builds a separate error list for each send mode (`B:Zh87.java:84-105`).

A decoded-bytecode cross-check of `Zr4d`'s static initializer (the readable enum is at `B:Zr4d.java:7-14`) gives these user-facing explanations: “There are empty tabs in this group”; “You have not specified a target for one or more requests in this group”; “There are WebSocket tabs in this group”; “The selected target is not the same for all requests in this group”; “The selected protocol (HTTP/1 or HTTP/2) is not the same for all requests in this group”; “HTTP/1 connection reuse is enabled for one or more requests in this group”; and “HTTP/2 connection reuse is disabled for one or more requests in this group.” The string literals are not present in `map_merged.tsv`; they were decoded read-only from the class static initializer, so the stable source citation is the enum plus the validation construction above, not a fabricated TSV entry.

### Send group in sequence (single connection)

Documentation quotation: “Repeater establishes a connection to the target, sends the requests from all of the tabs in the group, and then closes the connection.” (`D:send-group.html:97-100`.) Burp also says this can test client-side desync and reduces TCP-establishment jitter (`D:send-group.html:101-103`). Requests follow tab order; the common sequence rule is that there must be no WebSocket or empty tabs (`D:send-group.html:117-128`). Extra single-connection prerequisites are that **all tabs have the same target** and **all use the same HTTP version, HTTP/1 or HTTP/2** (`D:send-group.html:129-139`). The implementation independently counts distinct target and protocol selections and records service/protocol mismatches (`B:Zw1s.java:39-209` bytecode, especially target/protocol `distinct().count()` at `:71-121`; mismatch filtering at `B:Zh87.java:64-70`, `:90-105`).

Implementation path: `Zxnu.issueRequestGroupInSequence` obtains the group's tabs in their collection order, maps each to a `Zrp4`, and puts the resulting queue into `Zx_o` (`B:Zxnu.java:657-691`). For this mode the per-tab factory selects `this.Za.Za(first, true, settings, groupToken)` (`B:Zxnu.java:1497-1515`), and `Zel4` turns `true` into a `Zbtd` connection-options factory (`B:Zel4.java:12-17`). `Zx_o` is strictly serial: first it prepares every `Zrp4`, then it calls each request's send method in queue order, then it performs completion work (`B:Zx_o.java:18-49`). The actual establish/send-all/close semantics are documented above; the obfuscated builder methods in `Zbtd.java:20-42` are not assigned unsupported friendly names here.

### Send group in sequence (separate connections)

Documentation quotation: “Repeater establishes a connection to the target, sends the request from the first tab, and then closes the connection. It repeats this process for all of the other tabs in the order they are arranged in the group.” (`D:send-group.html:110-115`.) It shares the no-WebSocket/no-empty-tab prerequisites but **does not** have the documented same-target or same-HTTP-version requirements of single-connection mode (`D:send-group.html:117-139`). The validator's `TARGET_MISSING` applies to this sequence mode, while target/protocol mismatch applies only to single-connection and parallel (`B:Zr4d.java:7-14`; mode-specific lists built at `B:Zh87.java:88-105`; decoded static initializer cross-check described above).

It uses the same ordered `Zx_o` queue (`B:Zxnu.java:657-691`; `B:Zx_o.java:18-49`), but its per-tab factory takes the non-single branch (`B:Zxnu.java:1513-1520`), for which `Zel4` returns `Zwgj` (`B:Zel4.java:12-18`). `Zwgj` builds the ordinary Repeater connection key (`B:Zwgj.java:13-17`). Again, the per-request open/send/close behaviour comes from the quoted documentation, not guessed meanings of obfuscated builder calls.

### Send group in parallel

Documentation quotation: “Repeater sends the requests from all of the group's tabs at once,” for race-condition testing (`D:send-group.html:140-143`). Prerequisites are **same host, port and transport-layer protocols** and **HTTP/1 keep-alive disabled for the project** (`D:send-group.html:170-181`). The implementation additionally has explicit same-selected-protocol and HTTP/2-connection-reuse validation (`B:Zr4d.java:11-14`; `B:Zh87.java:64-82`, `:90-105`), and the batch issuer throws “Must use connection pooling with HTTP/2 batched requests!” when its pooling check fails (constructor checks and decoded calls at `B:Zskj.java:47-79`; decoded text is `map_merged.tsv:28488`). Its corresponding HTTP/1 error is “Cannot use keep-alive with batched requests!” (`B:Zskj.java:47-67`; `map_merged.tsv:28487`). Documentation also prohibits macro requests in parallel because they would interfere with synchronization (`D:send-group.html:164-168`).

`Zxnu` creates one prepared `Zrp4` per tab and a `Zglm` group job (`B:Zxnu.java:693-710`). `Zglm` prepares all tabs, collects their requests, submits one batch through `Zpag.createBatchedRequests`, waits for the result list, and only then performs each tab's completion work (`B:Zglm.java:36-64`, `:66-101`). `Zpag` passes the whole list to the HTTP engine (`B:Zpag.java:28-30`); `Zx6v` creates the batch coordinator (`B:Zx6v.java:34-38`). Section 3 covers synchronization.

### Failure, cancellation and what remains in each tab

* **Sequence preparation failure:** `Zx_o` first calls `Zrp4.Zv()` on every queue entry and returns immediately if any preparation returns false, before entering the send loop (`B:Zx_o.java:18-30`). `Zrp4.Zv` builds the pending request, validates target/request state, and sets a per-tab status when incomplete (`B:Zrp4.java:61-85`).
* **Sequence send failure:** the second loop returns immediately when `Zrp4.Zw()` is false, so later requests are not issued (`B:Zx_o.java:32-42`). `Zrp4.Zw` performs one send and returns the result-processing boolean (`B:Zrp4.java:87-94`). An unknown host sets that tab's error state and returns false (`B:Zrp4.java:101-113`); cancellation also returns false (`B:Zrp4.java:130-132`). Other result categories are converted into per-tab state by the same result-processing path (`B:Zrp4.java:114-135`), so a blanket “every network error aborts” claim is **not established**.
* **Sequence cancellation:** documentation says clicking **Cancel** on one group tab cancels the sequence (`D:send-group.html:90-96`). `Zx_o.ZN` sets the shared cancellation flag and calls cancellation on every tab's request wrapper (`B:Zx_o.java:56-61`); `Zrp4.Zb` sets `CANCELLED` (`B:Zrp4.java:190-192`).
* **Parallel preparation failure:** `Zglm` does not issue the batch if any tab preparation fails (`B:Zglm.java:40-47`, `:83-101`). **Parallel send failure:** requests have already been scheduled concurrently; one result returning false prevents the final completion loop, but does not retroactively un-send siblings (`B:Zglm.java:47-60`, `:103-131`). Parallel cancel cancels the engine batch and marks all wrappers cancelled (`B:Zglm.java:133-142`).
* **Per-tab response/history state:** `Zrp4` copies the response, error, timestamps and durations into its `Zw7` model (`B:Zrp4.java:101-127`), then creates/stores the Repeater item and updates the tab (`B:Zrp4.java:148-152`). Completion updates status and publishes the item to Repeater history and the logger (`B:Zrp4.java:179-184`). `Zsa_` constructs a normal item with the arrival label/tooltip arguments or a streaming item (`B:Zsa_.java:20-57`).
* The documentation does not specify a universal “failed tab is blank” rule. The code instead preserves result/error state per tab as above; exact visual text for every failure category is **not established** in this pass.

## 3. Parallel synchronization internals

### Batch identity and concurrency

For each request, `Zskj` creates a `Zi2p` batch token containing the common random batch id, total request count and this request's index (`B:Zskj.java:101-120` bytecode; factory at `B:Zi2p.java:16-20`, `:48-50`). It schedules every request through the executor, stores results by original index and waits on a `CountDownLatch` sized to the group (`B:Zskj.java:85-176`, worker at `:198-201`). `Zi2p.ZD()` returns a 100 ms delay (`B:Zi2p.java:38-41`). `Zpmm` keeps one barrier per batch id and constructs it with the expected request count (`B:Zpmm.java:9-29`). `Zb9n` counts each arrival down and awaits the rest, with timeout and explicit release/cancel paths (`B:Zb9n.java:19-38`, `:77-84`).

### HTTP/1: last-byte synchronization

The documentation is explicit: “multiple requests are sent over concurrent connections, but the last byte of each request in the group is withheld. After a short delay, these last bytes are sent down each connection simultaneously.” (`D:send-group.html:150-156`.)

The implementation is unusually direct:

1. `Zcak` selects `Zi_c` when the request has a batch token, otherwise the ordinary `Zsiy` writer (`B:Zcak.java:64-66`).
2. `Zi_c.Zj` obtains the raw request and socket output stream, writes bytes `[0, length - 1)` and flushes (`B:Zi_c.java:21-26`). It then waits on the shared barrier (`:28-33`), sleeps for the batch token's duration (`:35`; the 100 ms value is `B:Zi2p.java:38-41`), writes exactly the final one-byte slice and flushes (`B:Zi_c.java:36-37`).
3. Thus connections and all but the last byte are prepared independently; the barrier prevents any thread from releasing early. The code does **not** gather the last bytes into one OS write across sockets—the simultaneous aspect is barrier release plus a final write/flush per connection. A literal wall-clock guarantee of server-side simultaneity is not claimed by the code and is not needed for WebProbe's deterministic tests.

The normal application HTTP/2 socket factory sets `TCP_NODELAY` from its `ZT()` policy (`B:Zmsk.java:52-55`). The ordinary factory returns true (`B:Zmsh.java:38-46`), while the batched HTTP/2 factory returns false (`B:Zmsm.java:60-68`). The separate HTTP/1 `Zi_c` path shown above does not itself call `setTcpNoDelay`; no HTTP/1-specific Nagle change was established.

### HTTP/2: single-packet attack

Documentation quotation: “When sending over HTTP/2+, Repeater sends the group using a single packet attack. This is where multiple requests are sent via a single TCP packet.” (`D:send-group.html:157-159`.) The decompiled path explains the mechanism and also qualifies what “single packet” means at Java level.

#### Connection and socket setup

`Zux4` chooses the special batched connection factory when the batch token is active (`B:Zux4.java:23-32`). `Zbey` wires the ordinary `Zmsh` and batched `Zmsm` factories into that choice (`B:Zbey.java:82-114`). The batched factory creates `Zst5` (`B:Zmsm.java:20-57`) and returns false from its TCP policy (`B:Zmsm.java:60-63`), so `Zmsk` calls `socket.setTcpNoDelay(false)` (`B:Zmsk.java:52-55`). The normal factory instead returns true (`B:Zmsh.java:38-41`). All writes for a connection share the `Zbig` monitor (`B:Zst5.java:56-68`; `B:Zcm5.java:29-39`), so the different request threads cannot interleave arbitrary frames on that connection.

`Zskj` enforces HTTP/2 connection pooling for batched requests (`B:Zskj.java:60-79`; `map_merged.tsv:28488`). Its batch token is carried into request and connection configuration (`B:Zpv5.java:11-14`, `:46-49`; `B:Zb0d.java:45-48`). This is the implementation basis for coordinating streams on the shared pooled connection; it is not evidence that separately opened HTTP/1 connections are shared.

#### Initial warm-up

After the ordinary HTTP/2 preface/settings startup in `Zstw.Zq` (`B:Zstw.java:81-99`), `Zst5.Zq` emits a PING with eight random bytes and sleeps for `Zq` (`B:Zst5.java:48-53`). The field initializer is omitted from readable_strict, but `javap -c -p burp.Zst5` shows `Duration.of(10, MILLIS)` in the static initializer. The PING frame type and payload are visible at `B:Zxg3.java:12-23`. Therefore the initial warm-up is **PING + 10 ms**, not an unmeasured guess.

#### Preparing and withholding request frames

`Zst5.createOpenStream` allocates a stream and asks `Ziex` for that request's complete frame list (`B:Zst5.java:55-64`). It splits the list into **all but the final frame** and **the final frame** (`B:Zst5.java:64-67`). It passes two send actions to `Zmal`, then waits at the batch barrier before returning the open stream (`B:Zst5.java:67-76`).

`Ziex` constructs HEADERS with `END_HEADERS` (flag 4), deliberately without `END_STREAM`, even when there is no body (`B:Ziex.java:15-24`). It appends a terminal empty DATA frame with `END_STREAM` (flag 1) for a bodyless request (`B:Ziex.java:31-32`). With a body, it chunks using `min(negotiatedMaximumFrameSize, 16384)` (`B:Ziex.java:35-42`; negotiated setting storage at `B:Zgbi.java:34-40`, `:55-57`). For the last body chunk, all but its last byte goes in a non-final DATA frame, and the **last byte alone** goes in a DATA frame carrying `END_STREAM` (`B:Ziex.java:41-55`, `:63-67`). Consequently every request, bodyless or not, has a final releasable DATA frame.

The frame encoder can split a large HPACK block into HEADERS/CONTINUATION frames according to the negotiated maximum (`B:Zsun.java:17-160` bytecode; logical HEADERS object at `B:Zxga.java:9-29`). This matters when estimating whether a real packet can contain the release set.

#### Release barrier, second PING and final frames

`Zmal` collects one initial-frame action and one final-frame action per request under the connection monitor. When the number arrived reaches the group size, it:

1. runs **all initial-frame actions** (`B:Zmal.java:26-32`);
2. sleeps for the batch delay (`:32`), which is 100 ms (`B:Zi2p.java:38-41`);
3. emits another eight-byte PING (`B:Zmal.java:33`; frame class `B:Zxg3.java:12-23`);
4. runs **all final-frame actions** (`B:Zmal.java:34-35`).

The action calls `Zbmc.ZI(list)` (`B:Zst5.java:79-81`), which goes through `Zbhk.send(List)` to `Zu4j.Zs` (`B:Zbhk.java:37-40`, `:92-94`; `B:Zu4j.java:48-60`). Each frame then reaches `Zcm5`, which serializes and writes/flushed it (`B:Zcm5.java:29-41`). **The source does not concatenate all final frames into one byte array or one `OutputStream.write`.** It emits them consecutively under the shared lock with Nagle enabled (`TCP_NODELAY=false`), after the warm-up PING. The documentation calls the resulting network behaviour a single TCP packet; the Java evidence establishes the batching/coalescing strategy, not a universal MTU/MSS guarantee.

#### Limits and assumptions

* The batch token uses the actual `List.size()` as its expected request count (`B:Zskj.java:85-107`). No explicit Repeater-group request-count cap was found in `Zxnu`, `Zglm`, `Zskj`, `Zi2p`, `Zst5`, `Zmal`, or the send-group documentation. A hard maximum is therefore **not established**, not “unlimited.”
* DATA frames are capped at the peer's negotiated maximum and 16,384 bytes (`B:Ziex.java:35-42`); the releasable body tail is exactly one byte (`:43-55`). Bodyless requests use a zero-length final DATA frame (`:31-32`). There is no explicit MTU, MSS, IP_PACKET_SIZE or total-release-byte check in the inspected path. Packet-size assumptions beyond those frame rules are **not established**.
* The batch delay is 100 ms (`B:Zi2p.java:38-41`), initial post-preface warm-up delay is 10 ms (`B:Zst5.java:48-53` plus the cited `javap` static initializer), and the HTTP/2 response-wait path uses 120000 ms (`B:Zpj0.java:207-218`). These are implementation values, not wall-clock assertions that tests should make.
* Batched HTTP/2 with NTLM authentication is rejected: “NTLM authentication is not supported for batched HTTP/2 requests.” (`B:Zpj0.java:207-217`.)

## 4. Timing and arrival data

### Timestamp and duration capture

* `Zhyr.ZV` marks request issue with `Zbx2.Za()` (`B:Zhyr.java:46-51`); `Zbx2.Za()` is `Instant.now()` (`B:Zbx2.java:18-20`). `Zu19` exposes separate response instants `ZA()` and `ZH()` (`B:Zu19.java:5-9`). For HTTP/2, `Zgo_` passes the response stream's `ZO()` and `Zn()` instants into `Zgmu` (`B:Zgo_.java:20-35`), which returns them from `ZA()`/`ZH()` (`B:Zgmu.java:19-40`).
* `Zmih` stores the request instant, response-start instant and response-end instant, and computes durations with `Duration.between` (`B:Zmih.java:44-62`, `:69-83`). The resulting `Zw4w` exposes request time as epoch milliseconds through `ZI()`, **response received at** (response-start) as epoch milliseconds through `Zo()`, and the two durations through `Zq()`/`Zn()` (`B:Zw4w.java:55-73`). `Zrr5.ZR` computes request-start → response-start; `Zrr5.ZC` computes request-start → response-end (`B:Zrr5.java:827-832`).
* `Zrp4` stores those two durations and the request timestamp in the tab model (`B:Zrp4.java:114-127`; builder fields at `B:Zx1a.java:52-65`, `:87-89`). The tab's additional-data label displays response length, the end-response duration in milliseconds, and any arrival suffix (`B:Zw_k.java:26-88` bytecode, particularly `ZW8()` at `:56-65` and `ZWA()` at `:70-81`). The documentation likewise lists response byte size and response time in milliseconds (`D:http-messages/index.html:85-110`). Protocol is a separate label (`B:Zrxx.java:1062-1067`).
* `Zfmd` forwards the Repeater item's request timestamp and end-response duration when publishing the exchange (`B:Zfmd.java:26-53`). `Zx4g` exposes the two durations as `ZWC()` and `ZW8()` (`B:Zx4g.java:6-8`); the in-memory item returns them at `B:Zs5a.java:71-79`.

### Arrival order shown after parallel send

`Zglm.processHttpRequestResults` sorts results by `var0.ZD().Zo()`—the response-start epoch described above—then assigns each result an identity-based ordinal (`B:Zglm.java:103-119`, sort key at `:148-150`). It formats label `%d/%d` and tooltip “This response arrived %d of the %d responses received.” (`B:Zglm.java:117-120`). The documentation's example is 1/3, 2/3 in the bottom-right (`D:send-group.html:161-163`). `Zsa_` passes the label and tooltip into the persisted Repeater item (`B:Zsa_.java:41-56`; `B:Zppn.java:4-5`, `:47-50`), and `Zw_k` renders the label and tooltip (`B:Zw_k.java:70-101`). The right-hand label is anchored in the same bottom row as the status label (`B:Zrxx.java:677-692`).

**Protocol qualification:** the implementation sets the label only when the response protocol matches `HTTP_V2`; HTTP/1 results get null label/tooltip (`B:Zglm.java:112-120`). The broader documentation sentence does not state that qualification (`D:send-group.html:161-163`). WebProbe should choose deliberately whether to match the implementation (HTTP/2-only rank) or the doc-level behaviour; this report recommends the implementation for parity and notes the discrepancy in acceptance tests.

### “End time” versus end-response timer

The Repeater evidence establishes an **end-response duration**, not a Repeater column literally called **End time**. In the general HTTP-history table, the documented optional columns are **Start response timer** (request sent → first response byte) and **End response timer** (request sent → complete response) (`.../desktop/tools/proxy/http-history/index.html:91-101`). `Zxwp` exposes those values from `Zp1u.Zqm().toMillis()` and `Zp1u.ZqF().toMillis()` respectively (`B:Zxwp.java:101-107`; the class static initializer binds `lambda$static$13` to **Start response timer** and `lambda$static$14` to **End response timer**, confirmed by `javap -v`'s bootstrap entries 17/18 and the decoded names in `map_merged.tsv:10418-10419`). `Zs5u` stores each as a duration in milliseconds (`B:Zs5u.java:314-331`).

A literal **End time** column does exist in `Zbs7` (`B:Zbs7.java:273-275`; decoded label `runtime_strings.tsv:167`), but `Zso2` constructs that model for the audit queue (`B:Zso2.java:4-7`), not Repeater send groups. Therefore a Repeater group-send **End-time column is not established**. Do not use that unrelated audit-queue column as evidence for one. Likewise, no Repeater label with the literal text “Response received at” was found; the absolute response-start value is `Zwhe.Zo()` and is used for arrival sorting as shown above.

## 5. WebProbe current capabilities and gaps

### Group model, UI and persistence

**Already present**

* `RepTab` has a stable id, name, target, request, response, result line and per-tab history (`W:app/core/src/net.rs:274-289`). Tabs can be created, duplicated, renamed, closed/reopened and reordered (`W:app/src/repeater_ops.rs:817-931`, UI at `:1255-1360`). `RepeaterRun::new_tab_id` never reuses ids (`W:app/core/src/repeater_run.rs:29-34`).
* Project save writes Repeater tabs in vector order and includes name/target/request/response/result line (`W:app/src/tools.rs:1823-1832`); load restores those fields and assigns fresh ids (`W:app/src/tools.rs:2031-2043`). `ProjectRepeater` defines that serialized shape (`W:app/core/src/project.rs:258-289`), and `ProjectData` owns the `repeaters` vector (`W:app/core/src/project.rs:887-917`).

**Missing**

* There is no group id/name/colour/membership/order in `RepTab` (`W:app/core/src/net.rs:274-289`) or in `ProjectRepeater` (`W:app/core/src/project.rs:258-274`). The tab context menu has only Rename/Close/Duplicate/Reopen variants (`W:app/src/repeater_ops.rs:1195-1223`); there is no create/edit/add/remove/ungroup UI.
* `RepeaterRun` holds one global `busy`, generation, result and tab id (`W:app/core/src/repeater_run.rs:9-25`). `begin` and `finish_with` handle one send (`:45-75`), and `cancel` handles that one send (`:90-102`). A group needs per-tab result state plus a shared generation/cancellation token; using the current singleton unchanged would make one tab's completion clear another's busy state and lose per-tab outcomes.
* The toolbar has one Send button and one Cancel button, not the group-send drop-down (`W:app/src/ui.rs:1959-1975`). The status line has left/right text only (`W:app/src/ui.rs:2175-2185`); there is no stored arrival rank or separate start/end timing model in `RepTab` (`W:app/core/src/net.rs:274-289`).

### Current send path and what can be reused

**Already present**

* The selected tab is snapshotted and sent on a worker thread (`W:app/src/ui.rs:2194-2235`). Completion routes by stable tab id and updates response, result line and history (`W:app/src/ui.rs:2264-2302`). Cancellation uses generation staleness so a late result is discarded (`W:app/core/src/repeater_run.rs:56-75`, `:90-102`; `W:app/src/ui.rs:2310-2318`). These are useful building blocks, but the group controller should complete each tab independently rather than route all results through the one global `result`.
* `send_once` chooses plain/TLS and supports a streaming sink (`W:app/src/repeater_ops.rs:379-396`); `send_following` implements redirects (`:398-430`). `Service` already compares host, port and HTTPS as one value (`:61-86`), directly useful for preflight target checks. `http2_choice` represents forced HTTP/1, forced HTTP/2 or ALPN override (`:2250-2276`; `W:app/core/src/net.rs:1395-1427`).
* Plain and TLS senders expose raw request entry points (`W:app/core/src/net.rs:1330-1353`, `:1884-1905`). HTTP/1 keep-alive is already a shared setting (`:908-920`) and parallel preflight can reject when it is true. `send_inner` uses one full connection per request when keep-alive is off (`:1800-1826`), which is close to separate-connection sequence behaviour.
* For a future single-connection HTTP/1 sequence, the existing pool demonstrates the needed response-framing/reuse decision (`W:app/core/src/net.rs:1785-1798`, `:1874-1880`; TLS equivalent `:2002-2008`). A group API must hold that connection explicitly instead of returning it to the global pool.
* The code already times a whole Repeater send with `Instant` (`W:app/src/ui.rs:2232-2235`, `:2260`) and has a streaming progress callback (`:2238-2250`). Those provide instrumentation points, but no response-start timestamp or arrival rank is currently retained.

**Missing at the HTTP/1 boundary**

* The HTTP/1 exchange writes the entire request in one `write_all`, flushes, and only then reads (`W:app/core/src/net.rs:2027-2038`). There is no API to write `len - 1`, wait at a barrier, then release the last byte.
* `UpstreamConn` abstracts plain TCP and rustls (`W:app/core/src/net.rs:1216-1244`), but has no `set_nodelay` operation. `connect_socket` configures read/write timeouts only (`W:app/core/src/upstream.rs:56-81`). The ordinary pool hands ownership back to `send_inner`, not to a group coordinator (`W:app/core/src/net.rs:1810-1826`, `:1874-1880`; TLS `:1913-1935`, `:2002-2008`). Missing primitives are therefore: explicit connection sessions, partial writes, a group barrier, per-connection protocol selection and optional `TCP_NODELAY` control.
* Current status covers only total elapsed milliseconds (`W:app/src/ui.rs:2260`, `:2289-2295`). Start-response and end-response times need separate capture in the network layer; UI-only total time cannot reconstruct first-byte arrival order.

### HTTP/2 client: reusable pieces and structural gaps

**Already present**

* Frame constants include DATA, HEADERS, SETTINGS and PING (`W:app/core/src/h2.rs:16-25`), with END_STREAM/END_HEADERS flags (`:27-31`). `write_frame` enforces the 24-bit frame ceiling (`:38-40`, `:47-50`), and `parse_frame`/`read_frame` implement inbound framing (`:71-108`).
* `H2Request` already models pseudo-headers, ordinary headers and a byte body (`:144-156`). `request_from_raw` builds it and de-chunks HTTP/1 input (`:652-687`). HPACK encoding lowercases fields and handles Content-Length/Connection policy (`:172-200`).
* Request DATA already honours peer SETTINGS_MAX_FRAME_SIZE and connection/stream flow-control windows (`:548-586`; peer setting handling at `:349-369`). PING received from a server is validated and ACKed (`:371-377`). Response HEADERS/CONTINUATION and DATA are normalized (`:416-487`, `:521-545`). These are reusable protocol mechanisms, not a group sender.

**Missing for grouped/multi-stream HTTP/2**

* The file explicitly scopes itself to **one request per connection** (`W:app/core/src/h2.rs:1-7`). Every `exchange` sends a fresh preface/settings (`:589-608`), request HEADERS always use stream 1 (`:203-207`), response handling accepts only stream 1 (`:416`, `:450`), and request DATA always uses stream 1 (`:568-576`). `send_tls_inner` deliberately avoids pooling for forced HTTP/2 and returns immediately after `h2::exchange` (`W:app/core/src/net.rs:1913-1917`, `:1952-1965`). There is no shared HTTP/2 connection session, stream-id allocator, per-stream response map or response demultiplexer.
* `encode_headers` creates a fresh HPACK `Encoder` for each request (`W:app/core/src/h2.rs:175-200`). A real multi-stream connection needs connection-scoped HPACK encoder/decoder state, not independent encoders whose dynamic-table state can diverge.
* `send_request_headers` puts END_STREAM on HEADERS for a bodyless request (`:203-207`), and `pump` sends the final DATA as soon as flow control permits (`:568-576`). There is no prepared-request representation that keeps HEADERS open, splits a final one-byte DATA frame, or appends a final empty DATA frame for a bodyless request.
* `write_frame` performs one write for the nine-byte header, another for payload, then flushes (`:47-62`). There is no `encode_frame`/`encode_batch` API and no single prepared-buffer `write_all` for a release burst. The current generic `Read + Write` interface also offers no socket option control (`:47`, `:552`, `:595`; wrapper at `W:app/core/src/net.rs:1216-1244`).
* PING support is reactive only (`W:app/core/src/h2.rs:371-377`); there is no client-initiated warm-up PING API or tracking of its ACK. Burp's required initial-frame/final-frame barrier and the connection-wide lock around release are absent.

### Minimum new architecture implied by the gaps

Use a `GroupRun` snapshot containing ordered tab ids, immutable requests and `Service`, a shared cancellation generation, and a result slot per tab. Put explicit `Http1Session` and `H2Session` beneath it; do not build synchronization into `RepeaterRun`'s singleton fields. Add a recording/injectable clock at the network boundary for start/end timings. Add protocol-specific prepare/release primitives rather than changing ordinary sends: HTTP/1 `write_prefix_and_hold_last`, and HTTP/2 `prepare_stream(initial_frames, final_frames)`, `write_batch`, and connection-scoped stream/HPACK state. Keep these APIs usable by deterministic tests with an in-memory `Read + Write` peer as well as real `TcpStream`/rustls sessions.

## 6. Proposed implementation order and deterministic acceptance checks

The order deliberately lands group semantics and ordinary HTTP/1 behaviour before replacing the one-request HTTP/2 client. Every acceptance check can be driven by a loopback server, an in-memory peer, or project serialization; none needs a “completed within N ms” assertion. Replace production sleeps with an injectable sleeper/gate: tests assert that the configured values are 10 ms and 100 ms where Burp uses them, while the test itself releases the gate explicitly. Server/client rendezvous, channels, barriers, `poll`/nonblocking readiness and task joins establish ordering without wall-clock thresholds.

### Step 1 — Group model, membership UI and project round-trip

Implement ordered group records (stable group id, name, colour id, ordered tab ids), create/edit/add/remove/ungroup/delete operations, colour selection, group headers/badges, and the Send drop-down shell. Store the records and tab order with `#[serde(default)]` for old projects; generate fresh runtime ids on load while preserving saved order and membership. Do not yet change the sender.

**Acceptance:** create two groups with different names/colours and interleaved source tabs; reorder tabs within one group; save and reload. Assert exact group/name/colour/member order, selected tab, nonblank-name rule, removal of the last member deleting the group, and ungroup keeping tabs while delete removes them. A second project written by the pre-group version must load with no groups and unchanged tabs. No server or timing is involved.

### Step 2 — `GroupRun`, preflight and sequence over separate connections

Introduce the immutable group snapshot, per-tab result slots, shared generation/cancel state and mode-specific validation described in Sections 2 and 5. Implement **separate connections** by calling the existing one-request sender once per tab in tab order, with a fresh explicit connection session each time. Complete each tab independently; never route group results through the singleton `RepeaterRun.result`. Initially support the protocols the current client can already send separately.

**Acceptance:**

* A loopback HTTP/1 server records accepted sockets and complete request paths. Three tabs produce three distinct accepted connections and paths in tab order; every response/history result lands on its original tab even when the server varies response content.
* Mixed targets and mixed HTTP versions are accepted in this mode (when supported), while empty/WebSocket/missing-target cases are rejected before any connect. A listener whose accept task is joined immediately after the rejected run records zero connections.
* Hold the third tab behind a test gate, cancel after the second response, then release the gate. Assert cancelled status and no third request bytes. This tests cancellation deterministically rather than claiming that every network exception has the same Burp result category (which is not established).

### Step 3 — Sequence over one HTTP/1 connection

Add an explicit `Http1Session` that exposes request/response exchange and remains owned by the group until the ordered list finishes or aborts. Reuse the existing response-framing/reusable decision, but do not return the session to the global pool. Force this mode's single connection even when ordinary keep-alive is off; close it at the end. Keep separate-connection mode unchanged.

**Acceptance:** with global keep-alive false, a server accepts exactly one socket and parses three complete requests in tab order, answering each before the next arrives. Assert the request order, one accepted socket, and EOF on that socket after group completion. A second run gets a new socket. Add an injected mid-sequence failure/cancel case and assert the third path is never received and earlier tabs retain their responses.

### Step 4 — HTTP/1 parallel last-byte release and timing records

Add per-connection preparation (`write_all(request[..len-1]); flush`), a countdown barrier, and release (`write_all(last_byte); flush`) on independent sessions. Reject HTTP/1 parallel if project keep-alive is enabled. Instrument request issue, first response byte and response completion; store response-start epoch and both durations per tab. Keep original tab-index result routing. As established in Section 4, Burp's visible arrival label is HTTP/2-only, so HTTP/1 timing can be recorded/tested without presenting a new parity label.

**Acceptance:** for three connections, the server reads each request through its final byte-minus-one position and uses a rendezvous to prove that no final byte arrives before all three prefixes exist. It then uses one readiness poll/nonblocking sweep and observes all three final bytes before reading any application response. The server replies in a chosen non-tab order; assert per-tab responses, response-start ordering, and start/end duration calculations from the injected clock. Assert byte-for-byte request reconstruction, including a bodyless request and a request whose last byte is not ASCII.

### Step 5 — Connection-scoped HTTP/2 and single-connection sequence

Build `H2Session`: one preface/settings lifecycle, odd stream-id allocation, connection-scoped HPACK encoder/decoder, per-stream flow-control and response state, a write lock, and response demultiplexing. Keep ordinary single-request `exchange` behaviour as a wrapper or migrate it only after equivalent tests pass. Use the session for HTTP/2 **single-connection sequence**; separate-connection HTTP/2 sequence creates one session per tab. Enforce same target and same selected protocol for single-connection, and HTTP/2 pooling/reuse support for parallel.

**Acceptance:** a local HTTP/2 server sees one preface on one connection and sequential requests on streams 1, 3, 5 in tab order, with valid HPACK decoding throughout. It returns each response before the next request and the client closes after the group; there is no second preface or connection. Include bodies larger than one frame and SETTINGS/WINDOW_UPDATE changes to prove existing flow-control is retained. The separate-connection variant opens three sessions/prefaces instead.

### Step 6 — HTTP/2 parallel preparation, warm-up and single-packet release

Add prepared per-stream frame batches matching Burp's shapes: HEADERS without END_STREAM; body DATA capped by peer maximum and 16 KiB; final one-byte END_STREAM DATA for bodies; final empty END_STREAM DATA for no body. Send initial PING after preface, all initial frames, second PING, then the release burst under the connection write lock. Production configuration uses the Burp delays (10 ms initial, 100 ms batch); the test gate controls them. Set `TCP_NODELAY=false` for this specialized session and restore ordinary policy for other sessions.

Expose `encode_frame`/`encode_batch` and one prepared release-buffer `write_all`. This is intentionally stronger and more directly testable than Burp's consecutive Java writes; do not claim it proves one packet on every network. Define a WebProbe release-size safeguard independently of Burp (whose cap is not established): preflight rejects a release set above the configured safeguard instead of silently degrading into multiple bursts.

**Acceptance:**

* An in-memory `Write` recorder asserts exactly one release-batch write containing every final frame in stream order; no final frame appears in the initial writes.
* A raw local HTTP/2 server verifies one connection, initial PING, all streams' HEADERS/non-final DATA before any END_STREAM, second PING, and a subsequent single `read` containing all final DATA frames. Use small requests so the test is about ordering rather than TCP segmentation. It reassembles each body and checks exact content, including empty bodies and one-byte bodies.
* The server responds in a deliberate stream order different from tab order. Assert original-tab result routing and visible `received i/N` labels/tooltips for HTTP/2, sorted by recorded response-start epoch. No elapsed-millisecond comparison is made.
* Set the WebProbe release-size safeguard artificially small and assert a preflight error with zero request frames on the wire. This validates only the WebProbe safeguard, not a Burp limit.
* Confirm socket options through a test wrapper (`TCP_NODELAY=false` only for the specialized batch session), and verify unrelated normal HTTP/2 sessions retain their existing policy.

### Step 7 — Cross-mode failure/cancel matrix and final UI integration

Finish group Cancel, per-tab busy/progress/error/history state, macro rejection, protocol/target diagnostics, and project persistence of the visible result metadata. Ensure cancellation releases all barriers and closes prepared sessions rather than leaving worker threads blocked.

**Acceptance:**

* Table-drive empty tab, WebSocket tab, missing target, target mismatch, protocol mismatch, HTTP/1 keep-alive enabled, HTTP/2 pooling disabled, and macro-containing parallel runs. Assert the exact allowed/denied mode and zero network connections for every preflight denial.
* For parallel HTTP/1, fail one prepared connection after all prefixes exist; for parallel HTTP/2, RST_STREAM one stream while returning valid responses on the others. Assert siblings retain results, the failed tab contains its error, all workers terminate, and there is no fabricated successful response.
* Cancel separately during preparation, while waiting at the last-byte/final-frame barrier, and while reading responses. Assert idempotent cancellation, no late write into a newer generation, no leaked connection back into the global pool, and stable per-tab status after joining every worker.
* Reopen the project and verify group order/name/colour and the per-tab response, status, timings and arrival metadata appropriate to each mode.

## Register of points explicitly marked “not established”

* Exact generated default group name (`Zu_x`'s undecoded prefix), and exact colour names/RGB values behind the `Zfhh` theme references.
* Burp's binary project-file field layout (restart persistence and restored name/colour/membership are established instead).
* A universal rule for every network-error category aborting a sequence, and exact visual text for every per-tab failure category.
* Any HTTP/1-specific `setTcpNoDelay` call in the last-byte writer path (the HTTP/2 special-session setting is established).
* A hard maximum number of requests in a Repeater group, and MTU/MSS/total-release-byte assumptions or checks. The 16,384-byte DATA-frame rule is established but is not a group/packet cap.
* A universal guarantee that every network will put all final HTTP/2 frames in one physical TCP packet; the documentation's intended behaviour and the Java batching/coalescing mechanism are established separately.
* A Repeater group-send column literally called **End time**, or a Repeater label literally called **Response received at**. The established items are end-response duration and the absolute response-start value used for sorting; the literal **End time** found belongs to the audit queue.

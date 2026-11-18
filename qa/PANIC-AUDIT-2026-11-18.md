# PANIC AUDIT — WebProbe network-facing Rust (2026-11-18)

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

> **Verification pass — 2026-11-18 (complete).**
> Count unit: **58 claim groups** — the 38 original groups, 8 findings and 10 coverage groups added during
> the continued audit, plus the new RetireJS finding and JWT coverage group. **Checked 58: right 31,
> corrected 16, deleted 9, still not established 2.** The remaining not-established items are `encode_png`
> callers outside `core/src` and third-party crate internals. One new HIGH finding (H3) was added.
> Corrections made (old -> new, with evidence):
> - H1: independent opening/closing title searches -> the closing tag is searched only after the opening tag;
>   the reversed range is no longer reachable (`net.rs:2345-2354`). Finding deleted from the current source.
> - H2: Unicode-lowercased offset reused on the original -> ASCII case folding preserves the offset
>   (`scan.rs:1271-1289`). Finding deleted.
> - Former H3: unrestricted HTTP-date arithmetic -> bounded clock fields and years (`cookie_jar.rs:89-108`).
>   Finding deleted.
> - Former H4: unbounded PHP-array recursion -> `MAX_DEPTH = 64` (`passive_pack.rs:957-968`). Finding deleted.
> - Former H5: interactsh `read_to_end` -> 16 MiB `read_capped` (`interactsh.rs:113-139`). Finding deleted.
> - Former H6: unbounded h2c fallback body -> `read_capped` at `codec::MAX_BODY` (`net.rs:1804-1808`). Finding deleted.
> - Former H7: unbounded browser stdout -> 64 MiB cap and engine termination (`headless.rs:80-117`). Finding deleted.
> - M1: direct PEM range and the claim that saved-CA loading calls `der_of` -> fallible `.get(body_start..b)`;
>   only `import_ca` calls `der_of`, while saved/imported JSON goes directly to `check_ca_pair`
>   (`tls.rs:31-41,62-64,203-207,254-256`). Finding deleted.
> - M2: unbounded extension lines -> `capped_lines` on all three affected readers (`ext_host.rs:599-626`,
>   `ext_process.rs:139-145`). Finding deleted.
> - M3: incomplete file-reader evidence -> added `ext_store.rs:65`, `jwt.rs:217-220`, and `paths.rs:467-483`;
>   current CA/seed citations are `tls.rs:172` and `net.rs:965-970`.
> - L1: "~2^31 WINDOW_UPDATE frames" -> exactly `4,294,967,298` maximum-increment frames (about 52 GiB),
>   from the 65,535 initial window and 31-bit increment (`h2.rs:36,379-390`).
> - Macro summary: assertions only in `intercept_all_tests` -> also in `tests`; current module starts are
>   `net.rs:4143-4144` and `net.rs:4280-4281`.
> - WebSocket safety: production `ws_relay_chunk` -> production `ws_relay_chunk_alive`; both the other wrapper
>   and `intercept_ws_stream` are test-only (`net.rs:2850-2867,2871-2899,3172,3193`).
> - HTTP/2 server windows: "`MAX_WINDOW` checks on all window additions" -> send-window additions only;
>   receive-window replenishment follows an equal subtraction (`h2_server.rs:371-456,521-557`).
> - Project header parsing: `strip_prefix(char::is_whitespace)` -> `rest.starts_with(char::is_whitespace)`
>   (`project.rs:1450-1452`).
> - TLS citations: `pem_armor` line 481 and startup `tls.rs:406` / `net.rs:931` -> `tls.rs:465-486,407` and
>   `net.rs:938`.
> - `net.rs` unwrap inventory: a stale count of 71 -> the non-test calls are lock unwraps or CA startup only.
> - Coverage: skipped files not established -> all current root `*.rs` files received the candidate scan and
>   external-input trace, including `jwt.rs`; the new RetireJS case is H3 below.
> - Scanner coverage: Unicode redirect matching remains an H2 exception -> it is now ASCII folded and safe
>   (`scan.rs:1271-1289`).
> - PHP upload evidence: caller `scan_checks.rs:1525` -> `scan_checks.rs:2415`; the callee clamps both ends
>   (`active_checks.rs:121-123`).
> - Passive-parser coverage: recursion listed as an open H4 -> bounded at depth 64; RetireJS is separately H3
>   (`passive_pack.rs:957-968`, `retirejs.rs:246-259`).
> - Analysis coverage: contrast with unbounded PHP recursion -> the PHP parser is now bounded; Hirschberg still
>   halves its left input (`analysis.rs:670-716`).
> - Compare coverage: `Row::any` evidence `sitemap_compare.rs:281` -> constructor `272-281` and expect `120-123`.
> - Crawl coverage: unbounded browser output -> capped `headless.rs::run`; the loopback DevTools client is not
>   treated as an upstream response parser (`headless.rs:80-117`, `crawl.rs:620-643`).

Read-only robustness audit. Target: `/root/Documents/Craft Anything/burpsuite/app/core/src/*.rs`.
Method: grep for `.unwrap()`/`.expect()`, computed slice/range indexing, integer arithmetic, panic macros,
unbounded allocation and recursion; then trace each candidate back to the read/parse call. Test code
(`#[cfg(test)]` / `#[cfg(all(test,…))]` modules and `mod tests`) is excluded, including non-test code after
those modules (for example, `net.rs` production code continues through line 4132 with earlier
`#[cfg(test)]` helper functions excluded, and `util.rs` has non-test code at 470-519 and 584-675). Line
numbers will drift because other agents are editing, so the **function name is the stable reference**. No
source code was edited; no build/test/network command was run.

## Counts

| Severity | Count |
|---|---|
| HIGH | 1 |
| MEDIUM | 1 |
| LOW | 1 |
| **Total** | **3** |

| File | HIGH | MEDIUM | LOW |
|---|---|---|---|
| retirejs.rs | 1 | 0 | 0 |
| project.rs, project_files.rs, intruder.rs, tls.rs, ext_store.rs, retirejs.rs, report.rs, jwt.rs, paths.rs, net.rs | 0 | 1 | 0 |
| h2.rs | 0 | 0 | 1 |

Explicit `panic!` / `unreachable!` / `todo!` / `assert!` reachable from input: **none found** in the
non-test code checked. In `net.rs`, assert macros occur in the `#[cfg(test)]` modules
`intercept_all_tests` (starting at `net.rs:4143-4144`) and `tests` (starting at `net.rs:4280-4281`), not only
in the former as the first pass stated.

---

## Findings

### HIGH

**H3 — `retirejs::file_name`: byte index 1 on a non-ASCII script URL → UTF-8 boundary panic**

- `retirejs.rs:246-251`, function `file_name`: when a non-empty URL has no `/`, it returns `&url[1..]`.
  `by_url` calls it when the URI extractors produced no hit (`retirejs.rs:255-259`).
- Provenance: `scan` passes every HTML `<script src=...>` value to `by_url` (`retirejs.rs:328-335,358-360`).
  `script_srcs` reads the value from the response's lossy UTF-8 text; no ASCII restriction is applied. The
  vulnerable-JS passive check is registered at `passive_checks.rs:126`, and proxy history invokes passive
  checks at `net.rs:2483` when passive scanning is enabled.
- Concrete input: an HTML response containing `<script src="é"></script>` (with no other URI-extractor hit).
  U+00E9 occupies bytes 0 and 1, so `&url[1..]` splits the character and panics. Any non-ASCII first
  character in a slash-less, non-empty `src` has the same problem.
- Severity: **HIGH** — a proxied server can trigger it with an ordinary HTML response when the RetireJS
  repository is installed and the vulnerable-JS passive check is enabled.

### MEDIUM

**M3 — project, settings and payload file loading: no input-size cap → memory exhaustion**

- `intruder.rs:1005-1007` (`PayloadSource::generate`) and `intruder.rs:1116-1118` (`PayloadSource::len`)
  read an entire RuntimeFile with `std::fs::read_to_string`, then materialise its lines.
- `project.rs:1406-1418` (`load`) maps the whole project and `project.rs:1492` deserialises it without a
  document-size or collection-size check. `project_files.rs:60-63` reaches the same loader through `check`.
- The other whole-file readers have the same missing cap: `tls.rs:172` (`MitmAuthority::load_or_create`,
  `ca.json`), `project_files.rs:28` (`load_recent`), `ext_store.rs:65` (`load_from`, `extensions.json`) and
  `ext_store.rs:249` (`load_catalogue`), `retirejs.rs:96-97` (`Repository::load`, repository plus deadlinks),
  `report.rs:223-233` (`KnowledgeBase::load_dir`), `jwt.rs:217-220` (`secrets`), the QA seed hook at
  `net.rs:965-970`, and the pre-write comparison at `paths.rs:467-483` (`write_out`).
- Concrete input: a multi-GB project/JSON/payload file (or a RuntimeFile with very long lines) chosen by
  the victim. These paths hold the file and/or its decoded collections without an application byte limit;
  allocation continues until failure/OOM. This is unbounded allocation, not an assertion that every such
  file produces a Rust panic.
- Severity: **MEDIUM** — requires a malicious local file or resource directory.

### LOW

**L1 — `h2.rs` `Rx::handle`: unbounded `i64` flow-control window growth (not practically reachable)**

- `h2.rs:358`: `self.stream_window += new - self.peer_initial_window;`; `h2.rs:388` / `h2.rs:390`:
  `self.send_window += inc;` / `self.stream_window += inc;`.
- Provenance: `new` is `val as i64` from peer `SETTINGS_INITIAL_WINDOW_SIZE` (`h2.rs:349-359`), and `inc`
  is a peer WINDOW_UPDATE masked to 31 bits (`h2.rs:379-390`). The windows are `i64`
  (`h2.rs:221-223`). No checked/saturating addition is used. SETTINGS deltas telescope and their difference
  fits `i64`; only repeated WINDOW_UPDATEs accumulate without bound.
- Trigger in principle: starting at 65,535 (`h2.rs:36,245-247`), `4,294,967,298` maximum-increment frames
  overflow `i64`. Each is 13 bytes, about 52 GiB on one connection. Debug arithmetic then panics; release
  arithmetic wraps and desynchronises flow control. No short input reaches it.
- Severity: **LOW** — retained because the arithmetic is real, but it is not a practical remote crash.

---

## Checked and safe

- Former H1, `net.rs::derive_history_fields`: the closing `</title>` is now searched only in `body[a..]` after the opening `<title`, and its relative offset is added to `a`; the range cannot be reversed (`net.rs:2345-2354`).
- Former H2, `scan.rs::redirect_target_with`: both the needle and each redirect target/body now use `to_ascii_lowercase`, which preserves byte offsets and UTF-8 boundaries; `run_open_redirect_check`'s `&target[..*at]` is therefore bounded and aligned (`scan.rs:1271-1289,1341-1343`).
- Former H3, `cookie_jar.rs::parse_http_date`: clock fields are restricted to `hh <= 23`, `mm <= 59`, `ss <= 60`, and years to `0..=9999`, so the civil-date and seconds arithmetic cannot overflow (`cookie_jar.rs:89-108,117-128`).
- Former H4, `passive_pack::php`: recursive arrays/objects have `MAX_DEPTH = 64`; `serialized_at` rejects `depth > MAX_DEPTH` before descending (`passive_pack.rs:957-968,985-1010`).
- Former H5, `interactsh.rs::https_request`: `util::read_capped` limits the complete response to `MAX_RESPONSE = 16 MiB` (`interactsh.rs:113-139`; helper at `util.rs:599-621`).
- Former H6, `net.rs::try_h2c_upgrade`: the EOF-delimited fallback now calls `util::read_capped(stream, codec::MAX_BODY, …)`, a 64 MiB cap (`net.rs:1804-1808`; `codec.rs:9-10`).
- Former H7, `headless.rs::run`: browser stdout is read through `util::read_capped` with `MAX_STDOUT = 64 MiB`, and an over-cap result kills the engine (`headless.rs:80-117`).
- Former M1, `tls.rs::der_of`: `text.get(body_start..b).unwrap_or("")` replaces the reversed-range slice; malformed PEM falls back to the input bytes (`tls.rs:31-41`). Only `import_ca` calls `der_of` (`tls.rs:62-64`); saved/imported JSON goes directly from base64 DER to `check_ca_pair` (`tls.rs:203-207,254-256`).
- Former M2, extension readers: Java sidecar stderr/stdout use `capped_lines` with `MAX_STDERR_LINE` / `MAX_BRIDGE_LINE` (`ext_host.rs:546-549,599-626`), and process-extension stderr uses `MAX_LINE` (`ext_process.rs:139-145`). The helper truncates and drains over-long lines without accumulating them (`util.rs:623-674`).

- `codec.rs` `line()` / `scan_chunked()` / `at()`: `from + position` cannot overflow (`position < len-from`),
  `body[lf-1]` guarded by `lf > from`, `stop` uses `checked_add` and is compared with `body.len()` before
  `&body[after..stop]`; `from_utf8(…).unwrap_or("x")` and the 16-hex-digit cap are safe. `MAX_BODY` caps
  reads.
- `codec.rs` `read_message()` / `stream_body()`: `buffer[from..]` uses `saturating_sub(3)`; `head_end` is
  bounded by the buffer; `Content-Length` uses `saturating_add`; `n - take` is guarded by `min`;
  `Dechunker::feed` returns `Fed::Done(i)` with `i <= input.len()` before `&pending[..take]`.
- `codec.rs` `normalize_response()` / `normalize_request()` / `body_complete()`: `head_len` guarded by
  `== 0 || >= raw.len()`; `body[..n.min(body.len())]` clamped; `saturating_add` on length.
- `util.rs` `b64_decode()`, `hex_decode()`, `url_decode()`, `origin_form()`, `parse_http()`,
  `patch_header()`, `update_content_length()`: byte-index guards (`i+3 <= len`, `line_end.min(len)`,
  even-hex check); `find()` on `&str` returns char boundaries; the multi-byte-`%` slicing bug is already
  fixed with an explanatory comment.
- `util.rs` `html_decode()`: `i` advances only by `c.len_utf8()` or `find(';')+1` (ASCII `;`), so
  `s[i..]`, `s[i+1..i+end]` and `num[1..]` stay on char boundaries.
- `util.rs` `b64_encode()` / `hex_encode()`: `data.len()+2` / `data.len()*2` cannot overflow (allocation bound).
- `util.rs` `encode_png()`: `w as usize * h as usize * 4` in `Vec::with_capacity` could in principle
  overflow on 64-bit for hostile dimensions, but there is **no caller anywhere in `core/src`** (grep for
  `encode_png` found only the definition); unreachable from the audited surface.
- `tls.rs` `pem_armor()` (`tls.rs:465-486`): `b64` is built only from an ASCII base64 constant table, so every
  `chunks(64)` slice is valid UTF-8 — `from_utf8(line).unwrap()` cannot fail.
- `tls.rs` `client_auth_config()` `pem_to_der`/`data_encoding_decode()`: base64 decoded with a `lut` and
  explicit invalid-character error; no unwrap on input.
- `tls.rs:407` `.expect("TLS versions")` and `net.rs:938` CA-init `.expect()`: startup/constants, not input.
- `streaming.rs` `Dechunker::feed()`: `n = min(len-i, left)`, `i+n <= len`, `left - n` guarded; `MAX_LINE`
  caps a size/trailer line; `Fed::Done(i)` with `i <= input.len()`.
- `streaming.rs` `Tee::push()`: `TEE_BUFFER - self.buf.len()` guarded by `self.buf.len() >= TEE_BUFFER`
  above it; `TEE_MAX.saturating_sub` for the total cap.
- `net.rs`: the non-test `.unwrap()`/`.expect()` calls are Mutex locks (poison-tolerant wrapper per project
  convention) or the startup CA init — none consume network bytes.
- `net.rs` `ws_frame_header()` / `parse_ws_frame()` / `ws_relay_chunk_alive()`: 8-byte and 2-byte header
  guards (`net.rs:2565-2585`), `usize::try_from(u64).unwrap_or(usize::MAX)` followed by the
  `len > MAX_WS_FRAME` (16 MiB) check *before* `start + len` (`net.rs:2595-2604`); mask bytes
  `start-4..start-1` valid because `start >= 6` when masked (`net.rs:2605-2611`). The production
  relay applies the `MAX_WS_MESSAGE` check before the same addition and drain (`net.rs:2871-2899`), and
  its two call sites are at `net.rs:3172,3193`. Both `intercept_ws_stream` (`net.rs:2850-2851`) and the
  `ws_relay_chunk` wrapper (`net.rs:2864-2867`) are `#[cfg(test)]`; the alleged `raw_left` variable is absent.
- `net.rs` `expand_placeholders()`: `open`/`close` both from `find` on the same `&str` (ASCII `{`/`}`),
  so `open <= open+close <= open+close+1` and all offsets are char boundaries.
- `net.rs` `split_host_port()` / `path_of()` / `derive_history_fields()` path/extension line: `rfind(':')`
  and `find('/')` on the same `&str` that is sliced, or preceded by `starts_with("http://")`.
- `net.rs` `read_request()`: `head_len + len` bounded (`len <= MAX_BODY`, head <= 4 MiB);
  `Log::log()` `n - 500` guarded by `n > 500`; `set_listener_http2()` `row - 1` guarded by `row == 0`.
- `h2.rs` `parse_frame()` / `read_frame()` / `header_fragment()` / `data_payload()`: 9-byte header guard,
  `9 + len` cannot overflow (24-bit length), `<= max` / `DEFAULT_MAX_FRAME` cap, `pad > rest.len()` guard,
  `p.len() < 5` guard for PRIORITY.
- `h2.rs` `Rx::handle()` HEADERS/CONTINUATION/DATA: `MAX_HEADER_BLOCK` cap; `body.len() > MAX_BODY` cap;
  flow-control decrements bounded by `allowance = min(send_window, stream_window)`; HPACK decode wrapped
  in `catch_unwind`.
- `h2.rs` `pump()` / `finish()`: `allowance > 0` guard before `as usize` and `rest[..n]`/`rest[n..]`;
  `status` length/digit validation before use.
- `h2_server.rs` `check_hpack_block()`: `b.get(*i)?` bounds, `shift > 28` cap, dynamic-table size check
  `> HEADER_TABLE_SIZE`; `b.len() - *i` safe because `int` only returns `Ok` with `*i <= b.len()`.
  `Conn::headers()` additionally wraps `dec.decode` in `catch_unwind`.
- `h2_server.rs` `Conn::frame()`: SETTINGS length `% 6`, initial-window and max-frame validation,
  `WINDOW_UPDATE`/`RST_STREAM`/`PING` length checks, `block.len()+payload.len()` and `frames+1` bounds,
  `body.len()+payload.len() > MAX_REQUEST_BODY`, and `MAX_WINDOW` checks on **send-window** additions
  (`h2_server.rs:371-410,431-456`). The first pass said "all window additions"; receive-window
  replenishment instead follows a preceding subtraction of the same `len`, so it cannot exceed its prior
  value (`h2_server.rs:521-530,541-557`).
  `Conn::dispatch()` `raw.truncate(raw.len() - 2)` is safe because `raw` comes only from `request_head()`,
  which always ends with `\r\n\r\n` (length >= 4; `h2_server.rs:818-826`); `request_head()` rejects
  malformed pseudo/regular header combinations and CRLF/NUL in values.
- `collaborator.rs` `parse_http_request()` / `decode_chunked_body()`: `checked_add` for Content-Length,
  `size > MAX_HTTP_BODY` cap before `size + 2`, `rest.len() < size+2` guard, CRLF checks;
  `&line[..line.len()-1]` guarded by `line.ends_with(b"\r")`.
- `collaborator.rs` `parse_dns_query()` / `read_dns_name()`: header and question-end guards
  (`question_end.saturating_add(4)`), `checked_add` for label bounds, `target < DNS_HEADER_LEN ||
  target >= position` and `jumps > 16` compression guards, `encoded_len > 255` and `labels.len() > 127`;
  `buffer[..size]` uses `recv_from`'s returned size.
- `decoder_ops.rs` `pad_be()` and digest loops: `16 - len_bytes` with constant 8/16 callers;
  `[i*4..i*4+4]` / `[i*8..i*8+8]` inside `chunks_exact(64/128)` with `i < 16`.
- `stored.rs` `find_tokens_counted()`: every slice preceded by `i + p.len() + TOKEN_BODY <= bytes.len()`.
- `ext_host.rs` / `ext_process.rs` / `ext_calls.rs` / `ext_store.rs`: JSON-line wire protocol uses
  `unwrap_or_default`, `unwrap_or`, `.get()`, and `as_u64() as usize` (never indexing a Vec with it —
  e.g. `HIGHLIGHT_COLOURS.get(i as usize)`); no unwrap on a value derived from the sidecar's line.
- `project.rs` `decode()` / `split_document()`: all fallible steps return `Result`; `serde_json::from_str`
  error is propagated (`project.rs:1482-1499`); the header uses `rest.starts_with(char::is_whitespace)`
  (`project.rs:1450-1452`, not `strip_prefix` as the first pass wrote); no unwrap on file contents.
- `interactsh.rs` `decrypt_messages()` / `parse_interaction()`: `raw.len() < 16` guard before
  `split_at(16)`, key-length match, `String::from_utf8_lossy`.
- `body.rs` `Store::segment()`: `cap - used` maintains `used <= cap` internally (no external input).

### Additional files covered by the verification pass

The first pass's "not audited" gap was closed by running the same non-test candidate searches over every
`app/core/src/*.rs` file and tracing the external-input candidates. The following are checks, not claims
that these whole modules are formally panic-free:

- `scan.rs`: `redirect_targets` and `link_targets` use ASCII-only lowercasing before sharing offsets;
  `multipart_parts` derives ordered ranges from delimiters in the same string. `find_emails` only unwraps
  `labels.last()` after `labels.len() >= 2`. The former Unicode-`to_lowercase` offset bug in
  `redirect_target_with` / `run_open_redirect_check` is now the ASCII-folded safe case above.
- `burp_checks.rs`: `openapi_in_swagger_init` explicitly returns false on `b <= a` before slicing
  (`burp_checks.rs:554-558`); `prssi` and `attr` use `to_ascii_lowercase`, which preserves byte offsets.
- `active_checks.rs`, `xss.rs`, `variations.rs`, `csp.rs`: the HTML/tag scanners use ASCII delimiter
  offsets or `to_ascii_lowercase`; generated token slices are ASCII. `php_upload_filename` clamps both
  ends of its range (`active_checks.rs:121-123`), and its caller generates the token with `rnd_id(20)`
  (`scan_checks.rs:2415`).
- `passive_checks.rs`: `find_ssns` bounds its `i + 10` loop before all fixed-width slices; `forms` and
  `attr` share offsets only with an ASCII-lowercased copy. `passive_pack.rs` has iterative bound checks
  for token scanning and serialized-string lengths; the recursive PHP array parser is capped at depth 64
  as described in former H4 above. `retirejs.rs::file_name` is the separate H3 finding.
- `analysis.rs`: case-insensitive excerpts map folded matches back through `folded_to_original`
  (`analysis.rs:145-194`). Hirschberg recursion halves the left input at every level
  (`analysis.rs:670-716`); the formerly linear PHP recursion is now explicitly capped as described above.
- `compare.rs`: UTF-8 token lengths are clamped to remaining bytes, and Myers exploration is capped by
  `MAX_EDITS`; `sitemap_compare.rs` constructs every `Row` with at least one side (`sitemap_compare.rs:272-281`),
  so `Row::any`'s `expect` (`sitemap_compare.rs:120-123`) is an internal invariant, not an input-controlled unwrap.
- `intruder.rs`, `intruder_run.rs`: payload matrices use checked arithmetic and `MAX_PAYLOADS` bounds;
  illegal-Unicode odometers are non-empty by construction (`intruder.rs:449-465,512-528`). RuntimeFile
  reading is M3. The local-only `i64::MIN.abs()` possibility in `number_run` (`intruder.rs:1532-1540`)
  was not promoted: `PayloadSource` has no file deserializer or network producer in the audited crate.
- `crawl.rs`: sitemap/robots parsers slice at delimiter offsets found in the same string. Browser-engine
  stdout is capped as described in former H7; `http_get_local` is a loopback DevTools client, not an upstream
  response parser.
- `ai.rs`, `macros.rs`, `rules.rs`, `inspector.rs`, `intercept_rules.rs`: response/body offsets are
  clamped or come from the same `find`; static regex `expect`s are constants; invalid user regexes return
  no match rather than unwrap.
- `logger.rs`, `organizer.rs`, `history.rs`, `ws_history.rs`, `notice.rs`, `mime.rs`, `seq_bits.rs`,
  `setup_page.rs`, `paths.rs`, `tasks.rs`, `scan_config.rs`, `ws_rules.rs`, `passive_state.rs`,
  `repeater_run.rs`, `scan_run.rs`, `upstream.rs`: no additional externally reachable panic candidate was
  established. Hits were poison-tolerant lock unwraps, constant/static expects, or bounded slices (for
  example, SOCKS5 address lengths are one byte and capped at 16, `upstream.rs:156-167`).
- `jwt.rs`: token parsing uses `Option` and base64/JSON errors instead of unwraps; `control_token` clamps its
  payload length to at least two before `len - 2` (`jwt.rs:139-145`). The secret-list whole-file read is M3.

---

## Not established

- **`util.rs::encode_png` reachability.** I grepped all of `app/core/src` for `encode_png` and found only
  the definition (`util.rs:376`) — no caller. Whether some crate outside `core/src` (GUI/UI workspace
  members, which were outside the stated scope) calls it with attacker-controlled `w`/`h`, and therefore
  whether the `w as usize * h as usize * 4` capacity arithmetic is externally reachable, is **not
  established**. I did not inspect files outside `app/core/src/*.rs`.
- **Third-party crate internals.** The HPACK decoder (`hpack` crate) and serde_json are external
  dependencies. Both `h2.rs::absorb_block` and `h2_server.rs::Conn::headers` wrap `dec.decode` in
  `catch_unwind`, and `h2_server.rs::check_hpack_block` pre-validates truncated encodings, but whether
  those guards cover *every* panic path inside the crate version in use is **not established** — dependency
  source was not read. `insertion::json_leaves` first validates with `serde_json::from_str::<IgnoredAny>`
  and then recursively walks the value (`insertion.rs:774-780,806-870`); the effective recursion limit of
  the configured serde_json build is likewise **not established**.
- No claims about Burp's decompiled classes are made in this report; the `/root/burp-re` trees were not
  consulted, so there are no unverified Burp statements to qualify.

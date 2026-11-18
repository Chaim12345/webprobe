# R-09 — Porting Burp Suite's JWT scanner checks into WebProbe (research note)

> **Delegated research (2026-11-18), not reviewed.** Written by a free model as leads for the task named in the title; confirm each class:line before relying on it.

Read-only research. No code, build, test or network was run. Evidence conventions:

- Burp claims are cited as `Class.java:line` under `/root/burp-re/out/readable_strict/root/` (one decompiled class per file), or as a resource path that was opened under `/root/burp-re/in/extract/resources/`.
- Restored string literals that the decompiler left as `a(int,int)` calls are cited as `strings/map_merged.tsv` rows (`class  int  int  text`) under `/root/burp-re/out/strings/`.
- WebProbe claims are cited as `file:line` relative to `/root/Documents/Craft Anything/burpsuite/app/core/src/`.
- Where the stripped decompilation does not let me establish a fact, I write **not established** and say what I looked at. Nothing below is filled in from general Burp knowledge.

## Scope: the eight issue types

Burp's issue-type enum `Zcot` declares the six scanner JWT issues at `Zcot.java:86-91`
(`JWT_SIGNATURE_NOT_VERIFIED`, `JWT_NONE_ALG_SUPPORTED`, `JWT_JWK_HEADER_SUPPORTED`,
`JWT_WEAK_HMAC_SECRET`, `JWT_JKU_HEADER_SUPPORTED`, `JWT_X5U_HEADER_SUPPORTED`) and the two
disclosure issues at `Zcot.java:174-175` (`JWK_DISCLOSED`, `JWT_PRIVATE_KEY_DISCLOSURE`).
`Zc84.java:98-103` and `Zc84.java:187-188` map those enum constants to the knowledge-base JSON
files; the `typeIndex` values below are read from those JSON files themselves. WebProbe already
has all eight names in `KB_ISSUE_TYPES` (`scan_checks.rs:2869-2875` and `scan_checks.rs:2879`) with
the same numeric values in hex (`0x00200900` = 2099456 etc.).

## Common Burp infrastructure (shared by all eight)

### Token discovery (where it looks)

`Zb2r.Zk(Zin1)` is the token source for both passive JWT checks:
`Zb2r.java:16-18` concatenates `requestParametersWithJWT` and `requestHeadersWithJWT`.

- **Request headers**: `Zb2r.java:20-29` walks every header line (`var0.ZB().Ze()`). `Zb2r.java:31-34`
  strips either the literal prefix `Authorization: Bearer ` (12 chars) or everything up to the
  first `:`, then trims. So it does **not** only look at `Authorization`; any header whose value
  text parses as a JWT is considered.
- **Request parameters**: `Zb2r.java:36-42` walks `var0.ZB().Zk()` (request parameters) and tries
  `Zs_w.ZT` on each parameter value `var0.ZO`. No separate whole-body or cookie branch exists in
  this class; parameters and headers are the two sources (`Zb2r.java:17`).
- Each hit becomes a `Zelh` (`Zb2r.java:44-45`, `:52-53`), which records the token and reads
  `alg` with `Zpsp.ZQ("alg")` (`Zelh.java:17`, `:23`) and the token's location (`Zelh.java:77-85`).

The **active** check does not use `Zb2r`; it is registered as an insertion-point check
`Zf8g.APIP_JsonWebTokens` (`Zu4y.java:37-39`, `Zcug.java:210-216`). `Zu4y.Zh()` parses the
insertion point's own value with `Zs_w.ZT` (`Zu4y.java:28`, `:41-44`), so in principle any
parameter/cookie/header/body insertion point is in scope; Burp's own insertion-point taxonomy
decides which those are.

### JWT recognition

`Zs_w.ZT(String)` (decompilation failed, but the bytecode is printed at `Zs_w.java:9-52`):
reject `null` and any value **starting with `"e"`** (bytecode offsets 01-0a), require
**length ≥ 23** (offsets 14-1d, `bipush 23`), then call
`com.nimbusds.jose.JWSObject.parse` (offset 2c) and wrap the result in `Z__`
(offsets 31-39). Parse failures are swallowed (`Zs_w.java:43-48`). So recognition is:
prefix + minimum length + Nimbus JOSE JWS parse.

> Note: the prefix test as decompiled rejects strings starting with `e` (`ifneq`/`ifeq` reading
> of `Zs_w.java:17-19` is ` if !startsWith("e") -> return empty ` at offset 0a). Taking the
> bytecode literally, a normal `eyJ...` JWT would be rejected; I flag this as an artefact of the
> failed decompilation rather than assert Burp's intended filter. **Not established**: the exact
> polarity/meaning of the `"e"` pre-filter. The ≥23 length test and the `JWSObject.parse` call
> are unambiguous (`Zs_w.java:25-26`, `:34-35`).

### Severity and confidence byte mapping

- Severity: `1=Information, 2=Low, 3=Medium, 4=High` (`Ze1r.java:13-22`).
- Confidence: `1=Tentative, 2=Firm, 3=Certain` (`Zeue.java:11-18`).
- `Zrh` stores the first byte after the evidence list as `ZA` and the second as `Zt`
  (`Zrh.java:31-38`); `Zs9s` uses `Zt` for severity and `ZA` for confidence
  (`Zs9s.java:244-249` vs `:239-240`, constructed from `Zrh.java:89-100`). These are the bytes
  the factories below set. WebProbe's own port of a Burp check corroborates the order:
  "burp.Zgo1 ... Certain, Low (Zrh bytes 3 / 2)" (`passive_checks.rs:158-159`), i.e. first byte =
  confidence, second = severity.

### Issue factories and the detail-text builder

- `Zmir.Zn` builds `JWT_WEAK_HMAC_SECRET` (`Zmir.java:13-26`): confidence byte `3`, severity byte `4`.
- `Zmir.ZL` builds the five active-check issues (`Zmir.java:28-48`): confidence is its `var7`
  parameter (`:37`), severity is hard-coded `4` (`:38`).
- `Zmir.Zl` builds JKU/X5U issues (`Zmir.java:50-54`): confidence `3`, severity `4`.
- `Zmir.ZJ` builds `JWK_DISCLOSED` (`Zmir.java:56-69`): confidence `3`, severity is its `var3`
  parameter (`:64`). `Zbfr.java:24-26` supplies `var7 = var5.isEmpty() ? 1 : 4`, i.e. Information
  when no private material was found, High when it was.
- `Zmir.ZK` builds `JWT_PRIVATE_KEY_DISCLOSURE` (`Zmir.java:71-89`): confidence `3`, severity `4`.
- `Zwfx.Zf` builds the detail text for the six scanner issues (`Zwfx.java:14-80`); `Zwf3.Zf`
  builds the JWK-set detail (`Zwf3.java:9-34`); `Zwf7.Zf` builds the private-key detail
  (`Zwf7.java:14-26`) from a single static literal `c` whose value was not restored —
  **not established** (no `burp.Zwf7` rows in `/root/burp-re/out/strings/*.tsv`).

---

## 1. JWT signature not verified

1. **Name/typeIndex/severity/confidence.** Name `JWT signature not verified` from
   `00200900_JwtSignatureNotVerified.json`; `typeIndex = 2099456`, `typicalSeverity = HIGH` in
   that file. Issue object: severity `4` (High) via `Zmir.java:38`, confidence passed as `(byte)1`
   (Tentative) by `Zs_2.java:48` (`Zs_2.java:40-51`); byte→name maps at `Ze1r.java:21-22` and
   `Zeue.java:13-14`.
2. **Check class / mode.** `Zu4y` is registered as an **active** insertion-point check for this
   issue (`Zcug.java:210-216`, `Zu4y.java:7`, `Zu4y.java:37-39`). The mutation/verification is
   `Zs_2.Zx(Zcot)` (`Zu4y.java:105-108`), driven by the token variants from `Zi8s.ZM`
   (`Zs_2.java:34`). Not passive: `Zs_2.java:35-36` builds and sends modified requests.
3. **Detection logic.**
   - Locate: the JWT is the insertion-point value parsed by `Zs_w.ZT` (`Zu4y.java:28`,
     `Zu4y.java:41-44`).
   - Recognise: see "JWT recognition" above (`Zs_w.java:9-52`).
   - Payload normalisation first: `Zu4y.java:57` replaces the payload with
     `"{" + " ".repeat(payload.length()-2) + "}"` (a same-length `{}` payload), re-parses it
     (`:58`), and gate-keeps with `Zx` (`:59`, `:114-117`) before attacking (`:60`).
   - What is modified: `Zi8s.java:18-22` (switch case 1) clones the token and replaces the
     **signature** with `"A".repeat(originalSignatureLength)`:
     `String var3 = "A".repeat(var1.Zh().length()); var4.Zz(var3); return ... var4.ZZ();`
     (`Zi8s.java:20-22`). Header and payload are left intact, so this is signature corruption,
     not algorithm substitution.
   - Send/compare: `Zs_2.java:34-37` loops the variants; `Zs_2.Zk` (`:62-88`) sends the attack
     token via `Zsnr.Zz(var6.Zj())` (`:69-71`) and the original token via `Zsnr.ZE(var6.Zi())`
     (`:75-77`), repeating 4/8/10 times by configured thoroughness (`Zs_2.java:8`, `:90-98`).
     The oracle is `Zsnr.Zt()` = `Zi.ZI() && Zu.ZI()` (`Zsnr.java:50-52`), where `Zr2x.ZI()` is
     "at least one discriminating response attribute remains" (`Zr2x.java:97-99`) and the
     ignored attributes are `CREDIT_CARD_COUNT`, `SOCIAL_SECURITY_NUMBER_COUNT`,
     `EMAIL_ADDRESS_COUNT`, `JSON_NODE_COUNT` (`Zsnr.java:8`). **Not established**: the exact
     equality-vs-difference polarity of `Zsnr.Zt()` — the stripped `Zr2x.ZO`/`Ze` pair
     (`Zr2x.java:24-45`, `:47-64`) implements a two-direction attribute filter but the class
     comments do not name which direction the vulnerability requires. Established facts: the
     check reports only when the oracle succeeds for both the modified and the original token.
4. **Timing dependence.** No. The decision is a response-attribute comparison
   (`Zsnr.java:50-52`, `Zr2x.java:97-99`), not a latency measurement. No `currentTimeMillis`,
   `nanoTime`, sleep or delay appears in `Zu4y.java`, `Zs_2.java`, `Zi8s.java`, `Zsnr.java`.
5. **Detail text.** `Zwfx.java:33-40`:
   `"The signature of the JWT within the " + Zsg0.Zj(var6, true, true) + " does not appear to be verified correctly by the application."`
6. **WebProbe mapping.** **Active.** Add a `PointCheck` whose `applies_to` accepts insertion
   points whose decoded value parses as a JWT, implementing the same signature→`AAAA...` variant,
   and register it in `POINT_CHECKS` (`scan_checks.rs:330`). Shape to copy: `ExternalInteraction`
   (`scan_checks.rs:760-819`) for send+evidence and `Cors` (`scan_checks.rs:2278-2304`) for the
   issue construction. Reuse: `mk()` (`scan.rs:259-274`) sets `type_id` from `KB_ISSUE_TYPES`;
   the existing KB row is `scan_checks.rs:2874`. `Recorder` (`scan_checks.rs:~220-260`) records
   the paired modified/original exchanges for `ScanIssue::evidence`. `base64::Engine` with
   `URL_SAFE` is already used in `insertion.rs:952-957`; `serde_json` is available (`Cargo.toml:17`,
   `:31`). The two-response comparison could reuse `compare.rs` (not yet verified line-by-line —
   **not established** which helper exactly).

---

## 2. JWT none algorithm supported

1. **Name/typeIndex/severity/confidence.** `00200901_JwtNoneAlgorithmSupported.json`:
   `typeIndex = 2099457`, `typicalSeverity = HIGH`. Issue object: severity `4` (High)
   (`Zmir.java:38`), confidence `(byte)1` = Tentative (`Zs_2.java:48`).
2. **Check class / mode.** Same active check `Zu4y`, registered for this issue at
   `Zcug.java:210-216`, enum constant at `Zu4y.java:7`. Variant list from `Zi8s.ZM` via
   `Zs_2.java:34`.
3. **Detection logic.**
   - Tokens and normalisation: identical to §1 (`Zu4y.java:28`, `:57-60`).
   - What is modified: `Zi8s.java:23-24` maps this issue to `case 2`, which iterates a static
     array of `alg` spellings and builds one token per spelling via
     `lambda$attackTokensFor$0` (`Zi8s.java:41-45`):
     `var2.ZQ("alg", var1); var2.Zz(""); return var2.ZZ();` — i.e. set the `alg` header to the
     variant and set the signature to the **empty string**.
   - The spellings: the `Zs` array's initialiser is not present in the stripped class, but the
     three string literals restored for this class are `nonE`, `None`, `none`
     (`strings/map_merged.tsv` rows `burp.Zi8s 17964 -13482 nonE`,
     `burp.Zi8s 17965 -31858 None`, `burp.Zi8s 17966 27961 none`). **Not established**: whether
     the array has any further entries — I grepped every `strings/*.tsv` for `burp.Zi8s` and only
     these three none-like literals are present.
   - Send/compare: exactly as §1 — `Zs_2.java:62-88`, `Zsnr.Zt()` (`Zsnr.java:50-52`).
4. **Timing dependence.** No — same response-attribute oracle, no latency measurement in
   `Zi8s.java`, `Zs_2.java`, `Zsnr.java`.
5. **Detail text.** `Zwfx.java:42-49`:
   `"The JWT within the " + Zsg0.Zj(var6, true, true) + " appears to be trusted by the application even when using the \"none\" algorithm with an empty signature."`
6. **WebProbe mapping.** **Active**, same `PointCheck` as §1 can emit this second issue by
   branching on the variant (alg spelling + empty signature). Reuse the same helpers as §1;
   KB row `scan_checks.rs:2871`. The `alg` values are literal strings, so no new dependency.

---

## 3. JWT self-signed JWK header supported

1. **Name/typeIndex/severity/confidence.** `00200902_JwtSelfSignedJwkHeaderSupported.json`:
   `typeIndex = 2099458`, `typicalSeverity = HIGH`. Issue object: severity `4` (High)
   (`Zmir.java:38`), confidence `(byte)1` = Tentative (`Zs_2.java:48`).
2. **Check class / mode.** **Active**, same `Zu4y` (`Zcug.java:210-216`, `Zu4y.java:7`);
   the token variant comes from `Zi8s.ZM` case 3 (`Zi8s.java:25-34`) via `Zs_2.java:34`.
3. **Detection logic.**
   - Locate/normalise as in §1 (`Zu4y.java:28`, `:57-60`).
   - What is modified (`Zi8s.java:25-34`): clone the token, then
     `var2.ZQ("alg", "RS256")` (`:27`),
     `var2.Zm("jwk", "<fixed RSA public JWK JSON>")` (`:28`; the literal contains
     `{"kty":"RSA","kid":"3baf1ea7-3ae1-4ef2-856c-5e4e7964eb45","e":"AQAB","n":"6urRDD..."}`),
     and — only if the token's `kid` is empty per `Zg7w.ZE(var2.ZQ("kid"))` —
     `var2.ZQ("kid", "3baf1ea7-3ae1-4ef2-856c-5e4e7964eb45")` (`:29-31`). Finally
     `var2.Z_("<fixed RSA PRIVATE KEY PEM>")` (`:33`) supplies the matching private key in PEM
     form (`-----BEGIN RSA PRIVATE KEY----- … -----END RSA PRIVATE KEY-----`). The JWK JSON and
     PEM literals are also in `strings/map_merged.tsv` rows `burp.Zi8s 17963 -12469` and
     `burp.Zi8s 17967 -685`. This is the classic self-signed / key-injection construction:
     attacker-chosen public key in `jwk`, token signed with the corresponding private key.
   - Send/compare: `Zs_2.java:34-88`, `Zsnr.Zt()` (`Zsnr.java:50-52`), same oracle as §1.
     **Not established**: the exact polarity of `Zsnr.Zt()` (see §1 item 3).
4. **Timing dependence.** No — response-attribute comparison only; no timing primitives in
   `Zi8s.java`, `Zs_2.java`, `Zsnr.java`.
5. **Detail text.** `Zwfx.java:51-58`:
   `"The JWT within the " + Zsg0.Zj(var6, true, true) + " appears to use an arbitrary key embedded in the \"jwk\" header to validate the token."`
6. **WebProbe mapping.** **Active**, third variant of the §1 `PointCheck`. The fixed JWK/PEM are
   public test material and can be copied as literals. Reuse `serde_json` for header manipulation
   (`Cargo.toml:17`) and `base64` URL_SAFE (`insertion.rs:952-957`); KB row `scan_checks.rs:2873`.
   Porting size M.

---

## 4. JWT weak HMAC secret

1. **Name/typeIndex/severity/confidence.** `00200903_JwtWeakHmacSecret.json`:
   `typeIndex = 2099459`, `typicalSeverity = HIGH`. Issue object: severity `4` (High) and
   confidence `3` (Certain) at `Zmir.java:20-21` (`Zrh.java:33-38` stores them).
2. **Check class / mode.** **Passive**, no requests sent. Check class `Zblw`
   (`Zblw.java:11`, id `Zugn.PPR_JwtWeakHmacSecret` at `:22-24`), registered in Burp's passive
   registry `Zsrp.ZM` at `Zsrp.java:97` (enabled only when the issue type is enabled).
   The brute-force helper is `Zbpi` (`Zbpi.java:13`, called at `Zblw.java:40`), the wordlist
   reader is `Zina` (`Zina.java:11-27`).
3. **Detection logic.**
   - Locate: `Zblw.java:30` — `Zb2r.Zk(this.ZX).filter(Zelh::Zz)`; i.e. request parameters and
     headers (`Zb2r.java:16-18`) whose `alg` is an HMAC algorithm. `Zelh.Zz()` returns true only
     for `HS256`, `HS384`, `HS512` (`Zelh.java:38-71`).
   - Recognise: `Zs_w.ZT` as above (`Zb2r.java:41`, `:49`).
   - What is tested (`Zbpi.java:27-71`): for each candidate secret from `Zina.ZJ()`
     (`Zbpi.java:49`), compute an HMAC over the token's signing input `var1.Zy()` with the
     algorithm from `var2` and compare it byte-for-byte with the token's signature `var1.Zr()`:
     `byte[] var11 = ZW(var1.Zy(), var2, var10); boolean var12 = net.portswigger.Zyn.Zw(var7, var11);`
     (`Zbpi.java:50-51`, with `var7 = var1.Zr()` at `:44`). On equality it returns the secret
     (`Zbpi.java:53-56`) and `Zblw.java:41` builds the issue via `Zmir.Zn`.
   - Algorithm map: `Zbpi.java:103-141` maps `HS256 → HmacSHA256`, `HS384 → HmacSHA384`,
     `HS512 → HmacSHA512`; an empty candidate secret is special-cased to the single byte
     `{0}` (`Zbpi.java:79-81`). The MAC itself uses `javax.crypto.Mac` with
     `SecretKeySpec` (`Zbpi.java:92-96`).
   - Wordlist: `Zina.java:16` opens a bundled resource with `getResourceAsStream(a)` and
     `Zina.java:20-26` reads it line by line. The task context says Burp ships
     `/root/burp-re/in/extract/resources/Scanner/jwt_secrets.txt`; I opened it (1,127,384 bytes,
     103,975 lines of candidate secrets). **Not established**: the literal value of `Zina.a`
     (the exact resource path) — there are no `burp.Zina` rows in any
     `/root/burp-re/out/strings/*.tsv` and no path literal in `Zina.java`. The linkage is by
     code shape only (`getResourceAsStream` + `readLine` + HMAC brute force).
   - Response condition: **none** — this is an offline cryptographic check on the observed
     token; no request is sent and no response is examined. De-duplication of already-tested
     token strings uses `Zr0v.Zx7/Zxq` (`Zbpi.java:28-35`), and same-type issues with the same
     location are merged (`Zbvp.java:56-63`).
4. **Timing dependence.** **No** for detection: the verdict is `Zyn.Zw(signature, computedHmac)`
   (`Zbpi.java:51`). There *is* a wall-clock brute-force budget — `var5 = Zb.ZR()` at `:42`,
   `var8 = Zb.ZR() - var5` at `:52`, abort when `var8 > ZY` at `:58-60` with metric
   `JWT_BRUTE_FORCE_TIMEOUT` (`Zm8i.JWT_BRUTE_FORCE_TIMEOUT` at `:60`) — but this is a local
   timeout, not any measurement of the server's response latency. WebProbe must not port a
   timing-based detector; this check has none.
5. **Detail text.** `Zwfx.java:17-31`:
   `"<p>Detected a JWT signed using a well-known HMAC secret key. The key used was <b>" + <found secret> + "</b>.</p>"`
   (the secret is escaped by `Zucz.ZL(var12, ((Zgtd)var13.get(0)).toString())` at `Zwfx.java:26`).
6. **WebProbe mapping.** **Passive** — add a `PassiveCheck` to `PASSIVE_CHECKS`
   (`passive_checks.rs:72-120`), using `PassiveCtx.req` / `PassiveCtx.p`
   (`passive_checks.rs:16-49`) to read request headers and parameters and locate JWTs; the
   private-key passive check shows the reporting shape (`passive_checks.rs:330-343`) and
   `CheckDef`/`mk_check` the metadata (`scan.rs:79-87`). Reuse `base64` URL_SAFE
   (`insertion.rs:952-957`) and `serde_json` (`Cargo.toml:17`). `sha2 = "0.10"` is present
   (`core/Cargo.toml:28`) but no `hmac` crate was found in `Cargo.toml`/`core/Cargo.toml`, so an
   HMAC primitive over SHA-2 must be supplied (or a dependency added). The 103,975-word list
   would need to be shipped as a WebProbe resource; Burp's copy is outside this repo.
   KB row `scan_checks.rs:2875`. Porting size M (wordlist + HMAC plumbing).

---

## 5. JWT arbitrary jku header supported

1. **Name/typeIndex/severity/confidence.** `00200904_JwtArbitraryJkuHeaderSupported.json`:
   `typeIndex = 2099460`, `typicalSeverity = HIGH`. Issue object: severity `4` (High) and
   confidence `3` (Certain) at `Zmir.java:52-53` (`Zmir.Zl`, called by `Zpy_.java:18`).
2. **Check class / mode.** **Active**, OOB-based. `Zu4y` is registered for the issue
   (`Zcug.java:210-216`, `Zu4y.java:7`); `Zu4y.ZB()` calls `Zk(var4)` after the in-band variants
   (`Zu4y.java:75-77`), and `Zk` builds the OOB checks via `Zs83.Zu()`
   (`Zu4y.java:88-103`). The OOB check itself is `Zegf` (`Zegf.java:5-17`), and the interaction
   is turned into the issue by `Zpy_.Zr` (`Zpy_.java:15-19`).
3. **Detection logic.**
   - Locate/normalise: same insertion-point JWT as §1 (`Zu4y.java:28`, `:56-61`).
   - What is modified (`Zs83.java:39-49`, `:53-68`): `Zu()` adds
     `this.Zl(Zpu2.JWT_JKU_INJECTION)` when the issue type is enabled (`:41-43`). `Zl` clones
     the token, asks the Collaborator for a unique label `var4` (`:56`), builds the URL
     `String.format("https://%s/%s/", var5.ZY(), var4)` when the collaborator has a host or
     `String.format("https://%s.%s/", var4, var5.ZY())` otherwise (`:59`), and writes it into the
     token header as **`jku`** — `Zp(var1)` returns `"jku"` for `JWT_JKU_INJECTION`
     (`Zs83.java:70-79`, `case 1 -> "jku"` at `:72`), applied at `Zs83.java:61`. The resulting
     token is packed into an OOB task with
     `EnumSet.of(Zsv3.DNS, Zsv3.HTTPS)` (`Zs83.java:62`), i.e. both DNS and HTTPS interactions
     are watched.
   - Response condition: the issue is raised by the OOB-result handler, not from the immediate
     HTTP response. `Zpy_.java:15-19` maps the injected header kind back to
     `Zcot.JWT_JKU_HEADER_SUPPORTED` via `ZX` (`:21-25`) and returns
     `Zmir.Zl(...)` when the issue type is enabled (`this.ZK.ZG(var7)` at `:18`). `Zegf` limits
     the check to these two issue types (`Zegf.java:6`, `:15-17`). **Not established**: the
     precise code that proves the interaction belongs to this delivered payload (it lives in
     the OOB base class `Zegp`/`Zbu3`, outside the classes I opened); established is that the
     reported event is a Collaborator DNS/HTTPS interaction (`Zs83.java:62`).
4. **Timing dependence.** **No** for detection: the verdict is receipt of an out-of-band
   interaction (`Zs83.java:62`, `Zpy_.java:15-19`), not a response-latency measurement. No
   timing primitive appears in `Zs83.java`, `Zpy_.java`, `Zegf.java` or `Zu4y.java`.
5. **Detail text.** `Zwfx.java:60-67`:
   `"The application appears to trust the \"jku\" header of the JWT found in the " + Zsg0.Zj(var6, true, true) + ". It fetched a public key from an arbitrary URL provided in this header and attempted to use it to verify the signature."`
6. **WebProbe mapping.** **Active**. Use the existing Collaborator/OOB machinery rather than
   polling for timing: `oob_slot` and `cx.shared.oob.register_delivered` in the
   `ExternalInteraction` check (`scan_checks.rs:760-819`) are the pattern; inject the generated
   URL into the JWT's `jku` header instead of replacing the whole parameter value. `crate::oob`
   and `collaborator.rs` already issue and match DNS/HTTP interactions. KB row
   `scan_checks.rs:2869`. Porting size L (JWT header rewrite + OOB registration + report on
   interaction).

---

## 6. JWT arbitrary x5u header supported

1. **Name/typeIndex/severity/confidence.** `00200905_JwtArbitraryX5uHeaderSupported.json`:
   `typeIndex = 2099461`, `typicalSeverity = HIGH`. Issue object: severity `4` (High) and
   confidence `3` (Certain) at `Zmir.java:52-53` (`Zmir.Zl`, called by `Zpy_.java:18`).
2. **Check class / mode.** **Active**, OOB-based, same classes as §5: `Zu4y`
   (`Zcug.java:210-216`), `Zs83` (`Zs83.java:45-47`), `Zegf` (`Zegf.java:6`, `:15-17`), `Zpy_`
   (`Zpy_.java:21-27`).
3. **Detection logic.**
   - Locate/normalise: identical to §5.
   - What is modified: `Zs83.java:45-47` adds `Zl(Zpu2.JWT_X5U_INJECTION)` when enabled. `Zl`
     builds the same collaborator URL shape (`:59`) and writes it into the token as **`x5u`**:
     `Zp(var1)` returns `"x5u"` (`Zs83.java:70-79`, `case 2 -> "x5u"` at `:73`), applied at
     `:61`; the OOB task again watches `DNS` and `HTTPS` (`Zs83.java:62`).
   - Response condition: OOB interaction, mapped by `Zpy_.java:21-27`
     (`case 2 -> Zcot.JWT_X5U_HEADER_SUPPORTED`) and reported through `Zmir.Zl` at
     `Zpy_.java:18`. Same **not established** caveat as §5 about the interaction-to-payload
     proof inside `Zegp`/`Zbu3`.
4. **Timing dependence.** **No** — Collaborator interaction, not latency (`Zs83.java:62`).
5. **Detail text.** `Zwfx.java:69-76`:
   `"The application appears to trust the \"x5u\" header of the JWT found in the " + Zsg0.Zj(var6, true, true) + ". It fetched a public key certificate from an arbitrary URL provided in this header and attempted to use it to verify the signature."`
6. **WebProbe mapping.** **Active**, same OOB `PointCheck` as §5 with a different header name
   and issue name. KB row `scan_checks.rs:2870`. Porting size S *given* a working §5 port
   (otherwise L).

---

## 7. Json Web Key Set disclosed

1. **Name/typeIndex/severity/confidence.** `00600700_JsonWebKeySetDisclosed.json`:
   `typeIndex = 6293248`, `typicalSeverity = INFO`. Issue object: confidence `3` (Certain)
   (`Zmir.java:63`); severity is dynamic — `Zbfr.java:24` chooses `1` (Information) when no
   private material was found and `4` (High) when it was, passed as `Zmir.ZJ`'s `var3`
   (`Zmir.java:56-69`, severity at `:64`). Byte→name maps: `Ze1r.java:15-22`, `Zeue.java:17-18`.
2. **Check class / mode.** **Active**, host/URL probing: `Zh7b` is registered for
   `Zcot.JWK_DISCLOSED` at `Zcug.java:114` and declares insertion-point type
   `Zf8g.APH_JwkDisclosed` (`Zh7b.java:34-36`). Response parsing/issue creation is `Zbfr`
   (`Zh7b.java:55-58`, `Zbfr.java:17-27`).
3. **Detection logic.**
   - Where it looks: `Zh7b.doCheck` (`:39-43`) runs only when the issue is enabled and the scan
     speed is not `Zsv7.FAST` (`:40`), then iterates the static URL list `ZA`
     (`Zh7b.java:12`, `:41`).
   - What it sends: `Zh7b.Zh` (`:45-48`) constructs a probe for each URL using
     `Zswt(this.ZN.ZA(), Zhs.Zq(var1))` and `Zpi0.Zm(var2, this.ZN.Zt(), var3).Zk(false).Zk()`,
     then lets `this.Zv.ZB(...)` analyse the response (`:47`).
   - Recognition/report: `Zbfr.ZG` (`:17-21`) parses the response with
     `Zwws.Zp(Zp9p.ZQ(var1).ZrP())` and returns an issue only if `var3.Zw()` says it is a JWK
     Set (`:19`). `Zbfr.ZW` (`:22-27`) gathers the private key material found (`var5`) and
     calls `Zmir.ZJ` with `var7 = var5.isEmpty() ? 1 : 4` and `!var5.isEmpty()` as the
     "has private material" flag (`:24-26`), which is stored in the issue's detail map as
     `Zu4s.JWT_JWKS_HAVE_PRIVATE_MATERIAL` (`Zmir.java:61`).
   - Response condition: the probe response parses as a JWK Set (`Zbfr.java:19`); the severity
     and detail branch on whether private key components were found (`Zbfr.java:24-26`).
   - **Not established**: the contents of `Zh7b.ZA` (the actual well-known URL paths probed).
     The field is declared at `Zh7b.java:12` but its static initialiser is stripped, and there
     are no `burp.Zh7b` rows in any `/root/burp-re/out/strings/*.tsv`. I did not guess URLs.
4. **Timing dependence.** **No** — the verdict is response content parsed as JWKS
   (`Zbfr.java:17-27`); no latency measurement anywhere in `Zh7b.java` or `Zbfr.java`.
5. **Detail text.** `Zwf3.java:12-30`, two branches:
   - with private material: `"The application publicly exposes a JSON Web Key (JWK) Set that contains private keys. These could be used by an attacker to generate arbitrary valid JWTs."`
     (`Zwf3.java:16-17`),
   - otherwise: `"The application publicly exposes a JSON Web Key (JWK) Set. Although no private keys have been found in the JWK set, exposed public key components can also be useful for attackers."`
     (`Zwf3.java:23-24`).
   Issue ordering compares severities (`Zwf3.java:37-39`).
6. **WebProbe mapping.** **Active**, request/host level — a `RequestCheck` with
   `Scope::Host` fits better than a `PointCheck` (trait and registry at `scan_checks.rs:310`,
   `:355`); see `TraceEnabled` for the host-scoped shape (`scan_checks.rs:~2340`). Reuse the
   existing path/host helpers in `paths.rs` and `serde_json` (`Cargo.toml:17`) to parse a JWKS,
   and `mk()`/`ScanIssue::with_evidence` (`scan.rs:259-274`, `scan_checks.rs:~230-260`) for the
   two severity variants. KB row `scan_checks.rs:2879`. Porting size M (the URL list must be
   re-derived from a live Burp instance or a non-stripped tree; this research note cannot supply it).

---

## 8. JWT private key disclosed

1. **Name/typeIndex/severity/confidence.** `00600800_JwtPrivateKeyDisclosed.json`:
   `typeIndex = 6293504`, `typicalSeverity = HIGH`. Issue object: severity `4` (High) and
   confidence `3` (Certain) at `Zmir.java:79-80`.
2. **Check class / mode.** **Passive**, no requests sent: `Zs73`
   (`Zs73.java:10`, id `Zugn.PPR_JwtPrivateKeyDisclosure` at `:18-20`), registered in Burp's
   passive registry at `Zsrp.java:98`. Issue built by `Zmir.ZK` (`Zmir.java:71-89`).
3. **Detection logic.**
   - Locate: `Zs73.java:24` — `Zb2r.Zk(this.ZB).filter(Zelh::Za)`. `Zelh.Za()` is
     `this.ZB().Zl()` (`Zelh.java:73-75`), i.e. the JWT header carries a `jwk` object that the
     model says holds private material. So this is again request parameters + headers
     (`Zb2r.java:16-18`), not the response body or cookies specifically.
   - Recognise: `Zs_w.ZT` (`Zb2r.java:41`, `:49`).
   - What it tests: `lambda$doCheck$0` collects the token text (`Zs73.java:44-46`). For each
     such token, `Zs73.java:32` searches the **response** bytes for that token string with
     `Zcxa.Zh(var6, var4, 0, var4.length, var7, false)`; `:33` builds the highlighted response
     location from the resulting spans; `:34` raises the issue via `Zmir.ZK`.
   - Response condition: the JWT string observed in the request (with a `jwk` containing private
     material) is also found in the response — i.e. the private key leaked back to the client.
4. **Timing dependence.** **No** — a byte-substring search (`Zs73.java:32-34`); no timing
   primitives in `Zs73.java` or `Zmir.java`.
5. **Detail text.** `Zwf7.java:14-26` appends one static literal `c` for this issue type
   (`Zwf7.java:18`). **Not established**: the value of `c` — it is declared at `Zwf7.java:6`
   with no restored value, and no `burp.Zwf7` rows exist in `/root/burp-re/out/strings/*.tsv`.
   (The knowledge-base description is in `00600800_JwtPrivateKeyDisclosed.json`.)
6. **WebProbe mapping.** **Passive** — a `PassiveCheck` in `PASSIVE_CHECKS`
   (`passive_checks.rs:72-120`), using `PassiveCtx.req` to find the request JWT and
   `PassiveCtx.body`/`text` (`passive_checks.rs:16-49`) to search the response. Reuse the PEM
   marker helpers (`pem_marker`, `pem_body`) already used by `private_key`
   (`passive_checks.rs:330-343`) for the private-key recognition and `mk_check`/`CheckDef`
   (`scan.rs:79-87`) for the issue. KB row `scan_checks.rs:2872`. Porting size M.

---

## Summary table

| Issue | passive/active | timing-dependent | Burp classes | porting size |
|---|---|---|---|---|
| JWT signature not verified (`2099456`) | active (insertion point) | no | `Zu4y`, `Zs_2`, `Zi8s`, `Zsnr`, `Zmir`, detail `Zwfx`; registered `Zcug:210-216` | M |
| JWT none algorithm supported (`2099457`) | active (insertion point) | no | `Zu4y`, `Zs_2`, `Zi8s`, `Zsnr`, `Zmir`, detail `Zwfx`; registered `Zcug:210-216` | S (with the first) |
| JWT self-signed JWK header supported (`2099458`) | active (insertion point) | no | `Zu4y`, `Zs_2`, `Zi8s`, `Zsnr`, `Zmir`, detail `Zwfx`; registered `Zcug:210-216` | M |
| JWT weak HMAC secret (`2099459`) | passive | no (local brute-force timeout only) | `Zblw`, `Zbpi`, `Zina`, `Zb2r`, `Zelh`, `Zmir`, merge `Zbvp`, detail `Zwfx`; registered `Zsrp:97` | M |
| JWT arbitrary jku header supported (`2099460`) | active (OOB) | no (Collaborator interaction) | `Zu4y`, `Zs83`, `Zegf`, `Zpy_`, `Zmir`, detail `Zwfx`; registered `Zcug:210-216` | L |
| JWT arbitrary x5u header supported (`2099461`) | active (OOB) | no (Collaborator interaction) | `Zu4y`, `Zs83`, `Zegf`, `Zpy_`, `Zmir`, detail `Zwfx`; registered `Zcug:210-216` | S (with jku) |
| Json Web Key Set disclosed (`6293248`) | active (URL probe) | no | `Zh7b`, `Zbfr`, `Zmir`, detail `Zwf3`; registered `Zcug:114` | M |
| JWT private key disclosed (`6293504`) | passive | no | `Zs73`, `Zb2r`, `Zelh`, `Zmir`, detail `Zwf7`; registered `Zsrp:98` | M |

## Points marked "not established"

1. `Zs_w.java:17-19` — the meaning/polarity of the `"e"` string pre-filter in JWT recognition
   (decompilation of `ZT` failed; bytecode was read directly).
2. `Zsnr.Zt()` (`Zsnr.java:50-52`, `Zr2x.java:24-64`, `:97-99`) — exact equality-vs-difference
   polarity of the response oracle for signature-not-verified / none / jwk.
3. `Zi8s` none-alg array (`Zs` at `Zi8s.java:24`) — whether it has more entries than the three
   literals `nonE`, `None`, `none` found in `strings/map_merged.tsv`.
4. `Zina.a` (`Zina.java:16`) — literal resource path for the HMAC wordlist (the shipped
   `jwt_secrets.txt` linkage is by code shape, not a restored string).
5. `Zegp`/`Zbu3` OOB plumbing — the exact proof that a Collaborator interaction belongs to the
   delivered `jku`/`x5u` payload (base classes not opened).
6. `Zwf7.c` (`Zwf7.java:6`, `:18`) — literal detail text for "JWT private key disclosed".
7. `Zh7b.ZA` (`Zh7b.java:12`, `:41`) — the well-known JWKS URLs probed by the active check.
8. WebProbe `compare.rs` — which exact helper (if any) implements the two-response attribute
   comparison used by `Zsnr`; only the file's existence and name were checked.

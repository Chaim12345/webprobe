# R-17 Intruder: payload types, processing, predefined lists (research)

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

Date 2026-11-18. Read-only inventory; no code changed. Burp evidence is class:line in `/root/burp-re/out/readable_strict/root/`, or the resource path opened. WebProbe evidence is `app/core/src/...:line`.

## A1. Burp's predefined Intruder payload lists

Location: `/root/burp-re/in/extract/resources/PayloadStrings/` - 48 `.pay` files, nothing else in the directory (each is a plain text list, one payload per line). No other directory under `/root/burp-re/in/extract/resources/` holds Intruder wordlists (`Scanner/`, `BuiltInConfigs/`, `Tooling/` were checked by name; the only other `.pay`-like resource set is `PayloadStrings`).

Display names: `Zckm.java` builds the "Add from list..." dropdown. `Zckm.java:457` loads `/resources/PayloadStrings/<name>.pay`, and the list of `<name>`s is the `Zj` string array assembled in `Zckm.java` (the decompiler left that array's `a(-31250, 19219)` calls; the text is in `/root/burp-re/out/strings/map_merged.tsv` lines 29017-29074, class `burp.Zckm`). Each entry there is used verbatim as the menu item and as the file base name, and `Zckm.java:461` strips a trailing `.pay` when the file name has one (`sipush -31240 / -3093` = ".pay", map_merged.tsv:29026). The "Add from list..." label itself is `Zckm.java:347` with text "Add from list..." (map_merged.tsv:29035).

| # | file | Burp menu display name | lines | first three entries |
|---|---|---|---|---|
| 0-9.pay | 0-9 | 10 | 0, 1, 2 |
| 10 letter words.pay | 10 letter words | 52709 | aardwolves, aaronsburg, abacterial |
| 11 letter words.pay | 11 letter words | 43106 | abacination, abactinally, abalienated |
| 12 letter words.pay | 12 letter words | 33529 | abalienating, abalienation, abandonments |
| 3 letter words.pay | 3 letter words | 4470 | aaa, aae, aaf |
| 4 letter words.pay | 4 letter words | 10794 | aaaa, aaal, aaas |
| 5 letter words.pay | 5 letter words | 22861 | aahed, aaium, aaiun |
| 6 letter words.pay | 6 letter words | 39399 | aaaaaa, aaberg, aachen |
| 7 letter words.pay | 7 letter words | 51787 | aalborg, aandahl, aaqbiye |
| 8 letter words.pay | 8 letter words | 59478 | aalesund, aardvark, aardwolf |
| 9 letter words.pay | 9 letter words | 59212 | aardvarks, aaronical, aaronitic |
| A-Z .pay | A-Z  | 26 | A, B, C |
| CGI scripts.pay | CGI scripts | 639 | %2e%2e/abyss.conf, ../../../../../../../../../../WINNT/system32/ipconfig.exe, .access |
| Directories - long.pay | Directories - long | 1808 | A, About, about-us |
| Directories - short.pay | Directories - short | 372 | a, about, access |
| Extensions - long.pay | Extensions - long | 1106 | $er, ^^^, {pb |
| Extensions - short.pay | Extensions - short | 86 | a, asp, aspx |
| Filenames - long.pay | Filenames - long | 1470 | A, About, about_us |
| Filenames - short.pay | Filenames - short | 230 | a, about, aboutus |
| Form field names - long.pay | Form field names - long | 6456 | access, admin, administration |
| Form field names - short.pay | Form field names - short | 29 | access, admin, administration |
| Form field values.pay | Form field values | 18 | 0, 1, 2 |
| Format strings.pay | Format strings | 10 | AAAAA%c, AAAAA%d, AAAAA%e |
| Fuzzing - JSON_XML injection.pay | Fuzzing - JSON_XML injection | 11 | {base}","x":", {base}"],"x":[", {base},"x":1 |
| Fuzzing - SQL injection.pay | Fuzzing - SQL injection | 166 | ', '', \ |
| Fuzzing - XSS.pay | Fuzzing - XSS | 221 | <script>onerror=alert;throw 1</script>, <script>{onerror=alert}throw 1</script>, <script>throw onerror=alert,1</script> |
| Fuzzing - email splitting attacks.pay | Fuzzing - email splitting attacks | 80 | =?iso-8859-1?q?{payload}=40{domain}=3e=00?=foo@example.com, =?iso-8859-1?q?{payload}=40{domain}=3e=01?=foo@example.com, =?iso-8859-1?q?{payload}=40{domain}=3e=02?=foo@example.com |
| Fuzzing - full.pay | Fuzzing - full | 169 | ', '', \ |
| Fuzzing - out-of-band.pay | Fuzzing - out-of-band | 77 | nslookup {domain}&, `nslookup {domain}`, \|nslookup {domain}& |
| Fuzzing - path traversal (single file).pay | Fuzzing - path traversal (single file) | 879 | ../{file}, ../../{file}, ../../../{file} |
| Fuzzing - path traversal.pay | Fuzzing - path traversal | 2200 | /{base}, ./{base}, ../{base} |
| Fuzzing - quick.pay | Fuzzing - quick | 39 | ', '', \ |
| Fuzzing - template injection.pay | Fuzzing - template injection | 46 | {77*77}, {{77*77}}, {{{77*77}}} |
| HTTP headers.pay | HTTP headers | 1137 | accept, accept-charset, accept-encoding |
| HTTP verbs.pay | HTTP verbs | 54 | GET, POST, HEAD |
| IIS files and directories.pay | IIS files and directories | 79 | /.printer, /%NETHOOD%/, /AccessPlatform/ |
| Interesting files and directories.pay | Interesting files and directories | 5462 | !.gitignore, !.htaccess, !.htpasswd |
| Local files - Java.pay | Local files - Java | 170 | JNLP-INF/APPLICATION.JNLP, META-INF/app-config.xml, META-INF/application-client.xml |
| Local files - Linux.pay | Local files - Linux | 34 | /etc/issue, /etc/passwd, /etc/shadow |
| Local files - Windows.pay | Local files - Windows | 247 | c:/$recycle.bin/s-1-5-18/desktop.ini, c:/apache/log/access.log, c:/apache/log/access_log |
| Passwords.pay | Passwords | 3424 | !@#$%, !@#$%^, !@#$%^& |
| SSRF targets.pay | SSRF targets | 43 | http://[::ffff:169.254.169.254], http://[0:0:0:0:0:ffff:169.254.169.254], http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy |
| Server-side variable names.pay | Server-side variable names | 2588 | id, action, page |
| Short words.pay | Short words | 27771 | aahed, aahing, aahs |
| User agents - long.pay | User agents - long | 5114 | Alcatel-OT-708/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 ObigoInternetBrowser/Q03C, BlackBerry7100i/4.1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/103, BlackBerry7130e/4.1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/104 |
| User agents - short.pay | User agents - short | 841 | Alcatel-OT-708/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 ObigoInternetBrowser/Q03C, BlackBerry7100i/4.1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/103, BlackBerry7230/3.7.0 |
| Usernames.pay | Usernames | 8894 | !root, $ALOC$, $system |
| a-z.pay | a-z | 26 | a, b, c |

Notes: line counts are `splitlines()` of each file as shipped (no trailing-newline adjustment). "A-Z .pay" has a trailing space in its file name and in the menu string (`-31265`, map_merged.tsv:29074).

Placeholder-bearing lists, per `Documentation/burp/documentation/desktop/tools/intruder/configure-attack/payload-lists.html`: CGI scripts (`{file}`, `{domain}`), Fuzzing - full (`{base}`, `{domain}`, `foo@{domain}`), Fuzzing - JSON_XML injection (`{base}`), Fuzzing - out of band (`{domain}`), Fuzzing - path traversal (single file) (`{file}`), Fuzzing - path traversal (`{base}`), Fuzzing - quick (`{base}`). Verified in the shipped files: `Fuzzing - out-of-band.pay` line 1 is `nslookup {domain}&` (note the shipped file name says "out-of-band" while the doc table says "out of band"; the `Zckm` table entry is "Fuzzing - out-of-band").

Extension/copyright: the file set is PortSwigger's; WebProbe must not copy it into its repository (see A3).

## A2. Payload types: Burp vs WebProbe

Burp list source: `Documentation/burp/documentation/desktop/tools/intruder/configure-attack/payload-types.html` (sections read in order: Simple list, Runtime file, Custom iterator, Character substitution, Case modification, Recursive grep, Illegal Unicode, Character blocks, Numbers, Dates, Brute forcer, Null payloads, Character frobber, Bit flipper, Username generator, ECB block shuffler, Extension-generated, Copy other payload, Collaborator payloads).

WebProbe: `PayloadSource` enum `app/core/src/intruder.rs:323-419`, labels `intruder.rs:977-998`, generation `intruder.rs:1002-1100`, count `intruder.rs:1108-1180`, validation `intruder.rs:1186-1245`. UI type dropdown `app/src/ui.rs:1781-1791`; per-type config panels `app/src/intruder_ui.rs:162-330`.

| Burp item | WebProbe (file:line) | missing/partial |
|---|---|---|
| Simple list | `PayloadSource::SimpleList` intruder.rs:327; label intruder.rs:979; generate intruder.rs:1004 | present |
| Runtime file | `RuntimeFile` intruder.rs:329; label 980; generate 1005-1008 (read at generation, unreadable = empty) | present; no "file changed while running" behaviour established |
| Custom iterator (up to 8 positions, separators, position 1 fastest) | `CustomIterator` intruder.rs:369-372 (comment cites burp.Zcce); label 989; generate 1085; count 1155-1168 | present |
| Character substitution (16 from/to slots, case-insensitive option) | `CharacterSubstitution` intruder.rs:374-376; defaults intruder.rs:559-568 (cites burp.Zrvh "abegiostz"->"483610572"); generate 1086-1097 | present |
| Case modification (No change / lower / upper / Propername / ProperName, duplicates discarded) | `CaseModification` intruder.rs:352-359; label 987; generate 1064-1069 via `case_forms` | present |
| Recursive grep (initial payload, extract-grep item, stop on duplicate) | `RecursiveGrep` intruder.rs:378-381; generate 1098 (initial only); runner intruder_run.rs:648-722 | present; needs >=1 grep-extract item (intruder_run.rs:694) |
| Illegal Unicode (overlong UTF-8, illegal continuation bytes, illegal hex, % prefix, case, cap) | `IllegalUnicode` intruder.rs:404-418; `illegal_unicode_encodings` 425-548; `illegal_hex_pairs` 421-424 | present |
| Character blocks | `CharacterBlocks` intruder.rs:341; label 984; generate 1053-1061 | present |
| Numbers (range, step, base 10/16, min/max integer and fraction digits) | `Numbers` intruder.rs:331-337; label 981; generate 1009-1014; `format_number` | partial: `fraction_digits` is a single field (intruder.rs:336) - no separate min/max fraction digits, no max-integer-digit truncation seen in `format_number` |
| Dates (range, step in days/weeks/months/years, format) | `Dates` intruder.rs:339; label 982; generate 1047-1052; `date_run`/`format_date` | present (strftime subset, UTC only per comment intruder.rs:338) |
| Brute forcer (charset, min/max length) | `BruteForcer` intruder.rs:330; label 983; generate 1015-1046 | present |
| Null payloads (count or indefinite) | `NullPayloads` intruder.rs:343; label 985; generate 1063 | partial: count only (`count` field), no "indefinite" option |
| Character frobber | `CharacterFrobber` intruder.rs:345; label 988; generate 1070-1078 | present |
| Bit flipper (base value or string, ASCII-hex mode, bit mask) | `BitFlipper` intruder.rs:383-386; label 990; generate 1099 (base) / 970 (position base); validation 1192-1207 | present |
| Username generator (max payloads per item) | `UsernameGenerator` intruder.rs:388-390; label 991; generate 1100-1103; `usernames` 807 | present |
| ECB block shuffler (base/string, hex, block size, extra strings) | `EcbBlockShuffler` intruder.rs:392-395; label 992; generate 1104-1107 | present |
| Extension-generated | `Extension { provider, payloads }` intruder.rs:325-326; label 986; generate 1062; validation 1188-1189; UI app/src/ui.rs:1823-1825 | present |
| Copy other payload (1-based position, Pitchfork/Cluster bomb only) | `CopyOtherPayload` intruder.rs:397-399; label 993; validation 1216-1230 | present |
| Collaborator payloads (unique id per payload, optional server location) | no `PayloadSource` variant; no "collaborator" string in intruder.rs or intruder_run.rs (grep, 2026-11-18) | **missing** |

## A3. Payload processing rules: Burp vs WebProbe

Burp list source: `Documentation/burp/documentation/desktop/tools/intruder/configure-attack/processing.html` ("Types of processing rules": Add prefix, Add suffix, Match / replace, Substring, Reverse substring, Modify case, Encode, Decode, Hash, Add raw payload, Skip if matches regex, Invoke Burp extension, Replace placeholder with base value, Replace placeholder with collaborator payload; plus the separate "Payload encoding" final URL-encode setting).

WebProbe: `Processor` enum `app/core/src/intruder.rs:1627-1657`, `process()` 1659-1697, `process_set()` 1699-1725, substring 1741-1755. Wired into the attack by `ext_calls::apply_extension_processors` (`app/core/src/ext_calls.rs:54-80`) for the extension processor only; the UI has no editor for the other rules (no `Processor::` in `app/src/`; `main.rs:305-306` holds only the per-set extension processor name).

| Burp item | WebProbe (file:line) | missing/partial |
|---|---|---|
| Add prefix | `Processor::AddPrefix` intruder.rs:1628, applied 1663 | present in engine; no UI editor |
| Add suffix | `AddSuffix` 1629, applied 1664 | present in engine; no UI editor |
| Match / replace (regex) | `MatchReplace { regex, replacement }` 1631-1632, applied 1665-1668; `$1` groups | present in engine; no UI editor |
| Substring (offset + length) | `Substring { start, end }` 1634, applied 1670, `substring()` 1741-1755 (end exclusive, negatives from the end) | partial: length is expressed as an end offset, not a length; no UI editor |
| Reverse substring | not present: `Processor` has no reverse-substring variant and `process()` has no such arm (intruder.rs:1627-1697) | **missing** |
| Modify case (same options as the case payload type) | `Lowercase` 1636, `Uppercase` 1637, applied 1672-1673 | partial: two fixed forms only - no "no change / Propername / ProperName" selection, and the two rules are separate pipeline steps; no UI editor |
| Encode (URL, HTML, Base64, ASCII hex, platform strings) | `Base64Encode` 1638, `UrlEncodeAll` 1641, `UrlEncodeKey` 1643, `HtmlEncode` 1645, `HexEncode` 1646; applied 1674-1683 | partial: no constructed platform strings (Burp's "constructed strings for various platforms"); `UrlEncodeKey` vs `UrlEncodeAll` is WebProbe's own split |
| Decode (URL, HTML, Base64, ASCII hex) | `Base64Decode` 1639, applied 1675-1678 | partial: Base64 only - no URL, HTML or ASCII-hex decode rule |
| Hash | `Md5` 1647, `Sha1` 1648, `Sha256` 1649, applied 1684-1686 via `decoder_ops::apply` | partial: three fixed digests, no hash selector/salt options; no UI editor |
| Add raw payload (before/after processed value) | not present (no variant, no arm in `process()`) | **missing** |
| Skip if matches regex | `SkipIfMatches { regex }` 1653, applied 1687-1691 (returns `None`, dropping the payload) | present in engine; no UI editor |
| Invoke Burp extension | `ext_calls::apply_extension_processors` ext_calls.rs:54-80, `ext_host.rs:145-148`; per-set name in main.rs:305-306, UI app/src/ui.rs:1805-1825 | present |
| Replace placeholder with base value ({base}) | not present as a processor; `{base}` handling exists only in the payload-list text, not as a rule (no `{base}` literal in `Processor`) | **missing** |
| Replace placeholder with collaborator payload | not present (no Collaborator placeholder processor; grep "collaborator" in intruder.rs/intruder_run.rs finds nothing) | **missing** |
| Final URL-encode of selected characters (post-processing, "Payload encoding") | no post-processing encode stage: `process()` is the last step before the request matrix (`SetSpec`, intruder.rs:1246+) | **missing** |
| Deduplicate list items (payload configuration "Deduplicate") | `Processor::MakeUnique { max }` 1655-1656, applied in `process_set` 1699-1725 | partial: it is a processing rule, not the payload-list "Deduplicate" button; no UI editor |

## A4. Offering the predefined lists without copying Burp's files

Extend `Lookup::payload_strings` in `app/core/src/paths.rs:128-136` (free function `paths::payload_strings()` at paths.rs:332-334). It already resolves, in order: `$WEBPROBE_WORDLIST_DIR`, `$WEBPROBE_BURP_RESOURCES/PayloadStrings`, `~/.config/webprobe/PayloadStrings`, `<data dir>/PayloadStrings` (`burp_resource_candidates`, paths.rs:104-116; `first_dir_with(.., has_ext(d,"pay"))` paths.rs:130). It returns the directory, not a list, so the Intruder "Add from list..." menu can enumerate `*.pay` in that directory at runtime and show the file stem as the display name - exactly what `Zckm.java:457` does. No new resolver function is needed; the menu should call `paths::payload_strings()` and read the directory (the same call content discovery already uses for wordlists).

The one existing caller is content discovery: `discovery::load_named_list` (`app/src/discovery.rs:115-127`) joins the resolved directory with `<name>.pay` and parses it, falling back to a built-in list with a status string - the same shape the Intruder "Add from list..." menu needs.

# Burp Suite Intruder — Feature Reference

> Extracted from the documentation shipped inside `/opt/BurpSuite/burpsuite.jar`
> (`resources/Documentation/burp/documentation/desktop/tools/intruder/`, 22 HTML pages,
> stripped to text). Applies to Burp Suite **Professional** and **Community** desktop editions;
> labels quoted verbatim from those pages, including where a feature is Professional-only.

---

## 1. Attack types (`attack-types.html`)

An attack type determines "the way in which payloads are assigned to payload positions" —
whether payloads come from a single set or multiple sets (up to 20), and whether they are
assigned to positions **in turn** or **simultaneously**. Selected from "the drop-down menu above
the message editor".

| Attack type | Payload sets | Payload → position mapping | Total requests |
|---|---|---|---|
| **Sniper** | single set | "places each payload into each payload position **in turn**" | number of positions × number of payloads in the set |
| **Battering ram** | single set | "places the **same** payload into **all** of the defined payload positions **simultaneously**" | number of payloads in the set |
| **Pitchfork** | one set per position (up to 20) | "iterates through a **different** payload set for each defined position"; payloads placed into each position **simultaneously** — request 1 = 1st payload of Set 1 + 1st of Set 2; request 2 = 2nd of each; etc. | number of payloads in the **smallest** payload set |
| **Cluster bomb** | one set per position (up to 20) | "iterates through a different payload set for each defined position", payloads placed **from each set in turn, so that all payload combinations are tested** — request 1 = (1,1), request 2 = (1,2), request 3 = (1,3) | product of the number of payloads in **all** defined payload sets ("may be extremely large") |

Documented use cases: Sniper — "fuzzing a number of request parameters individually";
Battering ram — same input in multiple places (e.g. "a username within a cookie and a body parameter");
Pitchfork — different but related input (e.g. username in one parameter and "a known ID number
corresponding to that username in another"); Cluster bomb — "unrelated or unknown input … guessing
both a username and password".

---

## 2. Payload positions (`positions.html`, `workflow.html`)

Each position is "enclosed by a pair of payload markers §, and highlighted for ease of identification".
The § marker is **purely visual** — "any § characters in your request won't define a payload position".
Positions may be set anywhere in the request **and target details** fields of the attack tab.

| Action | UI label / how |
|---|---|
| Add one marker pair | **Add §** — "place a pair of payload markers in the request" |
| Add around a selection | select text, then **Add §** — markers placed "on either side of the text" |
| Remove all | **Clear §** — with a selection, "markers are removed from within the selected area only" |
| Automatic markers | **Auto §** — "Burp inserts automatic payload positions"; "configure whether these replace or append to the base parameter value in the Settings dialog"; with a selection, auto markers go "within the selected area only" |
| Hotkey | "You can also configure a hotkey to add or clear payload positions" |
| From elsewhere in Burp | highlight the value, right-click → **Send to Intruder** — "set a single payload position" |

Rules and behaviour:
- "Payload positions **can't overlap**."
- "During the attack, both the payload markers and any enclosed text are replaced with the payload.
  If the payload position does not have an assigned payload, the enclosed text is unchanged but the
  markers are removed."
- **Update Host header to match target** is selected by default; deselect to send an arbitrary Host
  header to a fixed target (HTTP host header attacks).
- Positions double as scanner insertion points: top-level Intruder menu → **Scan defined insertion points**.
- From the results table: **Add payload position** / **Clear payload positions** in the right-click menu
  (`workflow.html`).

---

## 3. Payload types and their configuration fields (`payload-types.html`, `payload-lists.html`)

Selected from the **Payload type** drop-down in the **Payloads** side panel (toggled by the
**Payloads** tab). Shared list-editing buttons in the **Payload configuration** field:
**Paste**, **Load**, **Remove**, **Clear**, **Deduplicate**, **Add**, **Add from list**.

| Payload type | Configuration fields / options |
|---|---|
| **Simple list** | "a simple list of strings that are used as payloads" |
| **Runtime file** | file read at runtime; "One payload is read from each line of the file, hence payloads may not contain newline characters" (avoids holding a large list in memory) |
| **Custom iterator** | up to **eight** template positions, each with a list of items, optional separator between positions; **Clear all**; **Preset schemes** drop-down: *Directories / file . extensions*, *Two-digit hex*, *Passwords + digit* |
| **Character substitution** | apply substitutions to each list item; "all permutations of substituted characters for each list item in turn" (e.g. e > 3, t > 7 on "peter") |
| **Case modification** | options: **No change**, **To lower case**, **To upper case**, **To Propername** (first upper, rest lower), **To ProperName** (first upper, rest unchanged); duplicates discarded |
| **Recursive grep** | **Initial payload for first request**; **Extract grep item**; **Stop if duplicate payload found**. Must use a resource pool with **max concurrent requests of 1** |
| **Illegal Unicode** | *Overlong UTF-8 encodings* (toggle + max length up to 6 bytes); *Illegal UTF-8 continuation bytes*: **Do illegal UTF-8**, **Maximize permutations in multi-byte encodings**; *Illegal hex characters*: **Do illegal hex**, **Maximize permutations in multi-byte encodings**; *Hex formatting*: **Use lower case alpha characters**, **Add % prefix before each byte**; *Total encodings* (view estimate / set ceiling); *Match / replace in list items*: **Match character**, **Replace with encodings of** (ASCII char or two-digit hex) |
| **Character blocks** | **Base string**, **Min length**, **Max length**, **Step** (base string multiplied N times) |
| **Numbers** | *Number range*: **Type** (sequential / random), **From**, **To**, **Step** (may be negative), **How many**; *Number format*: **Base** (decimal / hexadecimal), **Min integer digits**, **Max integer digits**, **Min fraction digits**, **Max fraction digits** (fraction settings decimal-only); blank = no min/max; examples shown while editing |
| **Dates** | **From**, **To**, **Step** (days / weeks / months / years, positive), **Format** (predefined or custom: E/EEEE, d/dd, M/MM/MMM/MMMM, yy/yyyy, separators / . :) |
| **Brute forcer** | **Character set**, **Min length**, **Max length** |
| **Null payloads** | value is an empty string; "generate a specified number of null payloads, or continue indefinitely"; no payload positions needed |
| **Character frobber** | operates on the base value of the position or a specified string; cycles each character position, incrementing its ASCII code by one |
| **Bit flipper** | **Operate on** (base value of position / another string), **Format of original data** (literal / ASCII hex), **Select bits to flip** (least significant 0000000X → most significant X0000000) |
| **Username generator** | derives usernames from names or email addresses ("up to 115 possible usernames" for "peter wiener"); "configure a maximum number of payloads to generate per item in the list" |
| **ECB block shuffler** | **Encrypted data to shuffle** (base value / another string), **Format of original data** (literal / ASCII hex), **Block size** (bytes; usually 8 or 16), **Additional encrypted strings** |
| **Extension-generated** | **Select generator ...** — pick an extension-provided generator; "The extension must be registered as an Intruder payload generator" |
| **Copy other payload** | copies the current payload's value to another payload position (literal value; derive systematically via a payload processing rule) |
| **Collaborator payloads** | **Include Collaborator server location**; interactions shown in the attack results window, not the Collaborator tab |

**Predefined payload lists** (`payload-lists.html`, Professional): use **Add from list...** in the
**Payload configuration** field, then pick from the drop-down. Placeholder substitution is done with a
**Payload processing** rule of type **Match/replace** (regex e.g. `\{file\}`, `\{domain\}`).

| Predefined list | Placeholders |
|---|---|
| CGI Scripts | `{file}`, `{domain}` |
| Fuzzing - full | `{base}`, `{domain}`, `foo@{domain}` |
| Fuzzing - JSON_XML injection | `{base}` |
| Fuzzing - out of band | `{domain}` |
| Fuzzing - path traversal (single file) | `{file}` |
| Fuzzing - path traversal | `{base}` |
| Fuzzing - quick | `{base}` |

Placeholder meaning: `{file}` = filename (e.g. `/etc/passwd`); `{base}` = "Replaces {base} with
value marked as payload"; `{domain}` = web domain (e.g. `COLLAB_ID.oastify.com`);
`foo@{domain}` = domain inside an email address. Your own directory of custom payload lists is
uploaded in Burp's Settings dialog (Intruder settings).

---

## 4. Payload processing rules and encoding, in order (`processing.html`)

Rules are configured in the **Payload processing** field of the Payloads side panel: **Add** → pick a
rule type. "Processing rules are executed **in sequence**. Modify the sequence using the **Up** and
**Down** buttons. You can also toggle each rule on and off."

Rule types, in the order the documentation lists them:

1. **Add prefix** — literal prefix before the payload.
2. **Add suffix** — literal suffix after the payload.
3. **Match / replace** — replace parts matching a specific regular expression with a literal string.
4. **Substring** — extract from a specified offset (0-indexed) up to a specified length.
5. **Reverse substring** — as substring, but the end offset counts backwards from the end and the length counts backwards from that offset.
6. **Modify case** — same settings as the case modification payload type.
7. **Encode** — URL, HTML, Base64, ASCII hex, or constructed strings for various platforms.
8. **Decode** — URL, HTML, Base64, ASCII hex.
9. **Hash** — hashing operation on the payload.
10. **Add raw payload** — add the raw payload value before or after the current processed value (e.g. submit both raw and hashed).
11. **Skip if matches regex** — skip the payload if the processed value matches a regex.
12. **Invoke Burp extension** — the extension must have registered an Intruder payload processor.
13. **Replace placeholder with base value** — replace `{base}` with the base value of the payload position.
14. **Replace placeholder with collaborator payload** — replace regex matches with a Collaborator payload, optionally including the Collaborator server location.

**Payload encoding** (applied *after* all processing rules, so use it for final URL-encoding):
**Payload encoding** field → **URL-encode these characters** → enter the characters. It runs after
the payload grep check for echoed payloads.

---

## 5. Attack settings (`settings.html`) — **Settings** side panel

Many settings can also be edited while running, in "the cloned Settings side panel in the results window".

| Group | Setting | Effect |
|---|---|---|
| Save | **Save attack to project file** (Professional) | attacks are in-memory by default and lost on exit; only save interesting attacks |
| Request headers | **Update Content-Length header** | add/update Content-Length with the correct body length |
| Request headers | **Set Connection header** | add/update `Connection: close` |
| Error handling | **Number of retries on network failure** | retry count per failed request |
| Error handling | **Pause before retry** | milliseconds to wait before a retry |
| Attack results | **Store requests / responses** | persist full messages (disk in temp dir); enables full view, repeat, send to other tools |
| Attack results | **Make unmodified baseline request** | extra request with all positions at base values, shown as **item 0** |
| Attack results | **Use denial-of-service mode** | do not process responses; close the TCP connection as soon as the request is issued |
| Attack results | **Store full payloads** | store full payload values (memory cost; needed to change payload grep at runtime or resend with a modified template) |
| Auto-pause | **Enable auto-pause** | then **Pause if an expression in the list appears in a response** / **Pause if an expression in the list is missing from a response**; **Match type**: **Simple string** or **Regex**; **Case-sensitive match**; resume at any time (pauses again on each match) |
| Grep - match | **Flag responses matching these expressions** | list of expressions (pre-populated with common error strings); **Match type** (simple string / regex); **Case sensitive match**; **Exclude HTTP headers**; one results column per expression, value = number of matches |
| Grep - extract | **Extract the following items from responses** + **Add** | extract items; add the same item multiple times to capture multiple occurrences; **Maximum capture length**; adds a results column |
| Grep - payloads | **Case sensitive match**; **Exclude HTTP headers**; **Match against pre-URL-encoded payloads** | flag reflections of submitted payloads; a separate column per payload set |
| Redirections | **Follow redirections** | **Never**, **On-site only**, **In-scope only**, **Always** |
| Redirections | **Process cookies in redirections** | resubmit cookies set by the redirection response |
| HTTP/1 | **HTTP/1 connection reuse** | reuse connections for multiple HTTP/1 requests (speed); deselect = new connection per request |
| HTTP version | **Override the project-level HTTP/2 setting** → HTTP/2 or HTTP/1; **Default to HTTP/2 if the server supports it** | per-attack protocol control |

Notes: Burp follows "up to 10 chained redirections"; a results column indicates whether a redirect was
followed and the full chain is stored with the item. Suite-wide redirection types are under Proxy in the
Settings dialog. Single-threaded attacks may be necessary when following redirections.

---

## 6. Resource pools (`resource-pool.html`)

"A resource pool is a group of tasks that share a quota of resources." New tasks go to a **default
resource pool**; create a custom pool at any point **before** the attack starts
(**Intruder → Resource pool → Create new resource pool** → name + settings). "The pool is created when
you start the attack." After the attack starts, new pools must be created in another task or in
Settings → Project > Tasks.

| Setting | Meaning |
|---|---|
| **Maximum concurrent requests** | cap on simultaneous requests |
| **Delay between requests** (milliseconds) | **Fixed**, **With random variations**, or **Increase delay in increments** |
| **Increase delay in increments** | "determine the time taken for a session to expire if no requests are sent" |
| **Automatic throttling** | add a short delay when the server responds with specified codes; enabled/configured in the **default resource pool** |

Moving tasks: **Resource pool** side panel before the attack, or **Resource pool** in the results window
during an attack.

---

## 7. Results: columns, filtering, save/load

### Result columns (`results/viewing-results.html`)
**Request** (index; baseline = item 0) · **Position** (position number for the current payload, Sniper
with >1 position) · **Payload** · **Status code** · **Time of day** · **Response received** (ms to first
byte) · **Response completed** (ms) · **Error** · **Timeout** · **Length** (bytes) · **Cookies** ·
**Comment**. Conditional columns: each grep-match expression's match count; each extract-grep item;
payload-echoed count (payload grep); **Redirects followed**; **Interactions** (Collaborator payloads only).

### Analysis helpers (`results/analyzing-results.html`)
**Copy column contents** (control-click the header) · **Customize the table** (sort/customize) ·
**Filter the table** (capture filter + view filter) · **Add a note** (double-click the **Comment** cell) ·
**Highlight a result** (right-click → **Highlight** → colour).

### Capture filter vs view filter (`results/filtering-results.html`)

| | Capture filter | View filter |
|---|---|---|
| Effect | "Choose which items Intruder captures during the attack to control resource usage" | "Choose which items are displayed in the results table" — hidden items are not deleted |
| Applies | "only impacts items generated after it's applied" | live; **Apply** |
| Open | click the **Capture filter** bar → **Save settings** → **Apply capture filter** | click the **View filter** bar → **Apply** |
| Settings | **Discard items without responses**; **Capture by search term** (**Regex**, **Case sensitive**, **Negative search**); **Capture by status code**; **Capture by annotation** | **Filter by search term** (**Regex**, **Case sensitive**, **Negative search**); **Filter by status code**; **Filter by annotation** |
| Manage | **Show all**, **Hide all**, **Revert changes** | **Show all**, **Hide all**, **Revert changes** |

### Saving attacks (`results/saving-attacks.html`, Professional)
Attacks "are not saved by default, as they can result in large project files". Top-level **Save** menu:

| Command | What it saves |
|---|---|
| **Results table** | text file; choose rows, columns and delimiter (e.g. one column as input for later attacks) |
| **Server responses** | full responses; as sequentially numbered individual files, or concatenated into a single file |
| **Attack configuration** | reusable config file; reload with top-level Intruder menu → **Load attack config** |
| **Project file** | complete copy of configuration + results; disk-based projects only |

**Open saved attack** (top-level Intruder menu) reopens a closed saved attack. Attacks "can no longer
be saved to state files", though legacy state files can still be loaded. Closing a results window prompts:
let the attack carry on in the background, or discard it (plus save to project file once finished); the
default answer is set in Settings → Intruder → **Behavior when closing result windows**.

---

## Sources

All pages are entries under `resources/Documentation/burp/documentation/desktop/tools/intruder/`
inside `/opt/BurpSuite/burpsuite.jar`:

- `configure-attack/attack-types.html`
- `configure-attack/positions.html`
- `configure-attack/payload-types.html`
- `configure-attack/payload-lists.html`
- `configure-attack/processing.html`
- `configure-attack/settings.html`
- `configure-attack/resource-pool.html`
- `configure-attack/index.html`
- `configure-attack/managing-tabs.html`
- `results/viewing-results.html`
- `results/analyzing-results.html`
- `results/filtering-results.html`
- `results/saving-attacks.html`
- `results/workflow.html`
- `results/editing-attacks.html`
- `results/index.html`
- `index.html`, `getting-started.html`
- `uses/enumerating.html`, `uses/fuzzing.html`, `uses/harvesting.html`, `uses/index.html`

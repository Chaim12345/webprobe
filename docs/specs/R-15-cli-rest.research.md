# Burp Suite Professional CLI, Settings Files, REST API vs WebProbe Comparison

> **Delegated research (2026-11-18), not reviewed.** Written by a free model as leads for the task named in the title; confirm each class:line before relying on it.

## 1. Burp Suite Professional Command-Line Options

Source: `/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/troubleshooting/launch-from-command-line.html` and decompiled class `Zgz6.java` (string literals in `/root/burp-re/out/strings/map_merged.tsv`)

### 1.1 Burp-Specific Options

| Flag | Argument | Meaning | Default | Evidence |
|------|----------|---------|---------|----------|
| `--help` | none | Print help message and exit | — | Doc: line 93-96; Zgz6: 7424/31828, 7447/-27077 |
| `--disable-extensions` | none | Prevent loading extensions on startup | false | Doc: line 101-104; Zgz6: 7531/510, 7520/20264 |
| `--diagnostics` | none | Print diagnostic information | false | Doc: line 109-112; Zgz6: 7442/26548, 7455/1303 |
| `--use-defaults` | none | Start with default settings (overwrites saved settings) | false | Doc: line 117-120; Zgz6: 7486/4623, 7479/-27405 |
| `--collaborator-server` | none | Run in Collaborator server mode | false | Doc: line 125-128; Zgz6: 7432/-10642, 7437/-7770 |
| `--collaborator-config` | FILE | Specify Collaborator config file (default: collaborator.config) | collaborator.config | Doc: line 133-136; Zgz6: 7427/31928, 7441/-983, 7451/-28615 |
| `--project-file` | FILE | Open specified project file (create if not exists) | — | Doc: line 141-144; Zgz6: 7430/-13185 (×5), 7538/-11649 |
| `--config-file` | FILE | Load project config file (may repeat) | — | Doc: line 149-152; Zgz6: 7466/32311, 7475/12642, 7464/1535 |
| `--user-config-file` | FILE | Load user config file (may repeat) | — | Doc: line 157-160; Zgz6: 7483/-12485, 7539/-14498, 7461/-4266 |
| `--auto-repair` | none | Auto-repair corrupted project file (with `--project-file`) | false | Doc: line 165-168; Zgz6: 7457/-666, 7481/-31585, 7533/-20913 |
| `--unpause-spider-and-scanner` | none | Do not pause Spider/Scanner when opening existing project | false (paused by default) | Doc: line 173-176; Zgz6: 7482/-26185, 7477/19543, 7523/-1069 |
| `--temporary-project` | none | Open a temporary project (not saved) | false | Zgz6: 7537/18536, 7526/12908, 7474/-8381 |
| `--use-default-project-settings` | none | Start with default project settings | false | Zgz6: 7434/-17138, 7534/-20104, 7440/-29292 |
| `--data-dir` | DIR | Specify data directory | — | Zgz6: 7529/-8420, 7522/293 (×4), 7478/-19660 |
| `--suppress-jre-check` | none | Suppress JRE version check | false | Zgz6: 7530/27749, 7462/-13996, 7524/2163 |
| `--disable-auto-update` | none | Suppress auto-update behavior | false | Zgz6: 7476/-1231, 7439/-3877, 7542/31019 |
| `--disable-check-for-updates-dialog` | none | Disable update check dialog | false | Zgz6: 7525/-30047, 7428/-3209, 7480/297 |
| `--trust-project` | none | Trust the project file (skip warnings) | false | Zgz6: 7436/-24885, 7469/-12940, 7458/23344 |
| `--developer-extension-class-name` | CLASS | FQN of locally-developed extension to load from classpath | — | Zgz6: 7446/3696, 7463/27765, 7465/1840 |
| `--execution-mode` | MODE | Operation mode: desktop, enterprise-server, enterprise-agent | desktop | Zgz6: 7448/-17721, 7536/-4053, 7467/13482 |
| `--update-channel` | CHANNEL | Specify update channel | — | Zgz6: 7452/5080 (×2), 7471/20472, 7456/10892 |
| `--product-mode` | MODE | Override product mode (community) | professional | Zgz6: 7429/-8316, 7532/12004, 7425/22382 |
| `--version` | none | Print version details | — | Zgz6: 7473/-25312, 7527/26491, 7433/31753 |
| `--eula-content` | none | Get EULA content | — | Zgz6: 7431/30665, 7449/-10371, 7445/10103 |
| `--eula-serial-version` | none | Get EULA serial version | — | Zgz6: 7444/-4617, 7521/-7235, 7535/-20695 |
| `--i-accept-the-license-agreement` | none | Accept EULA non-interactively | false | Zgz6: 7438/-30162, 7472/-12676, 7426/12679 |

### 1.2 JVM-Level Options (Documented by Burp)

| Flag | Argument | Meaning | Evidence |
|------|----------|---------|----------|
| `-Xmx4g` | HEAP | Limit heap size (e.g., 4GB) | Doc: line 189-192 |
| `-XX:MaxRAMPercentage=50` | PERCENT | Limit max RAM to percentage of system memory | Doc: line 197-200 |
| `-Djava.awt.headless=true` | none | Run in headless mode (no GUI) | Doc: line 181-184 |

### 1.3 CLI Parsing Implementation

- Parser class: `Zgz6.java` (constructor takes `String[]` args)
- Uses `Zmo` (wrapper around Apache Commons CLI `Zu30`) for parsing
- Unknown args collected in `Zmo.Zt` (List<String>), reported via `Zm8i.UNRECOGNISED_CLI_ARG` (Zgz6.java:536-545, Zsly.java:672-677)
- Settings loaded via `Za()` (config-file), `ZE()` (user-config-file), `ZG()` (project-file) methods on `Zgz6`

---

## 2. Settings Files

### 2.1 File Application Logic

From `Zgz6.java` methods:
- `Za()` → `Zmo.ZQ("config-file")` returns `List<String>` — **multiple `--config-file` allowed, order preserved**
- `ZE()` → `Zmo.ZQ("user-config-file")` returns `List<String>` — **multiple `--user-config-file` allowed, order preserved**
- Partial files: each file is loaded and merged; later files override earlier ones (standard Burp behavior)
- Project settings (`--config-file`) apply to the project; user settings (`--user-config-file`) apply globally

### 2.2 ProjectDefaults.json Top-Level Structure

File: `/root/burp-re/in/extract/resources/Preferences/ProjectDefaults.json` (776 lines)

| Top-Level Key | Sub-Key Count (Leaf Keys) | Description |
|---------------|---------------------------|-------------|
| `bambda` | 5 sections × ~6 = ~30 | Bambda filters for history/logger/sitemap/WS |
| `logger` | 2 filters × ~30 = ~60 | Capture & display filters for Logger |
| `project_options` | 8 sections × ~50 = ~400 | Connections, DNS, HTTP, Misc, Resource Pools, Sessions, SSL |
| `proxy` | ~12 sections × ~30 = ~360 | Listeners, intercept, match/replace, WS, misc |
| `repeater` | 11 | Repeater behavior settings |
| `sequencer` | 3 sections × ~10 = ~30 | Live capture, token analysis, token handling |
| `target` | 2 sections × ~30 = ~60 | Filter, scope |
| `organiser` | 1 section × ~25 = ~25 | Display filter for Organizer |

**Total leaf keys (approx): ~965**

### 2.3 UserDefaults.json Top-Level Structure

File: `/root/burp-re/in/extract/resources/Preferences/UserDefaults.json` (511 lines)

| Top-Level Key | Sub-Key Count (Leaf Keys) | Description |
|---------------|---------------------------|-------------|
| `user_options.ai` | 1 | AI enabled |
| `user_options.auto_update` | 1 | Auto-update enabled |
| `user_options.comparer` | 1 | Sync views |
| `user_options.connections` | 3 sections × ~10 = ~30 | Platform auth, SOCKS, upstream proxy |
| `user_options.bchecks` | 1 | Imported scripts |
| `user_options.display` | 5 sections × ~15 = ~75 | Character sets, HTML, HTTP message, UI, table, window |
| `user_options.extender` | 4 sections × ~10 = ~40 | Extensions, Java/Python/Ruby env, settings |
| `user_options.intruder` | 3 | Sidebar, tab bar |
| `user_options.misc` | ~15 sections × ~20 = ~300 | API (REST), backup, collaborator, browser, search, hotkeys, inspector, editors, headers, logging, temp files |
| `user_options.proxy` | 1 section × 3 = 3 | Default display message |
| `user_options.repeater` | 1 | Tab bar layout |
| `user_options.ssl` | 3 sections × ~10 = ~30 | Client certs, custom CA, negotiation |
| `user_options.target` | 1 | View mode |

**Total leaf keys (approx): ~480**

**Notable REST API settings in UserDefaults.json (misc.api):**
```json
"api": {
    "address": null,
    "enabled": false,
    "insecure_mode": false,
    "keys": [],
    "listen_mode": "loopback_only",
    "port": 1337
}
```
(Default bind: loopback-only, port 1337, API keys required)

---

## 3. REST API

### 3.1 Base Path and Version

- Base path: `/` (root) with API key as path prefix: `[Service URL]/[API key]/`
- No explicit version in path; versioning via Burp version header
- API documentation browsable at `[Service URL]/[API key]/`
- Configured in user settings: `user_options.misc.api` (see above)

### 3.2 API Key Handling

- Default: API key required (`insecure_mode: false`)
- Keys stored as `RestApiKey{enabled, name, hashedKey, createdUtc}` (Zcuy.java)
- Hash: SHA-256 of key, base64-encoded (Zm1m.Zy())
- Authentication: `SingleApiKeyAuthenticationManager` (Zm1m.java:532-533)
- Key passed in URL path: `/<hashedKey>/...` (Zm1m.ZT:543)

### 3.3 Endpoints

#### 3.3.1 Core (Zihg.java — base class for all editions)

| Method | Path | Request | Response | Status Codes | Evidence |
|--------|------|---------|----------|--------------|----------|
| GET | `/info` | — | `Zku` (version, build) | 200 | Zihg:35-38 |
| GET | `/knowledgeBase` | — | `Zsxi` (KB) | 200 | Zihg:40-43 |
| GET | `/license` | — | `Zat` (license info) | 200 | Zihg:45-48 |
| DELETE | `/license` | — | — | 200 | Zihg:50-53 |
| PUT | `/licenseKey` | `{key: string}` | `Zrj` (empty) | 200, 400 (1002/1003/1004) | Zihg:55-68 |
| GET | `/licenseActivationRequest` | — | `Zr2` (activation request) | 200 | Zihg:70-73 |
| PUT | `/licenseActivation` | `{licenseActivationRequest: Zr2}` | `Zr9` (activation response) | 200 | Zihg:75-78 |
| PUT | `/licenseActivationResponse` | `{licenseActivationResponse: Zr9}` | `Zrj` (empty) | 200 | Zihg:80-84 |

#### 3.3.2 Enterprise Server (Zihc.java — extends Zihg)

| Method | Path | Request | Response | Status Codes | Evidence |
|--------|------|---------|----------|--------------|----------|
| GET | `/namedConfigurations` | — | `List<Zu_>` | 200 | Zihc:42-45 |
| GET | `/eula` | — | `Zhj` (EULA state) | 200 | Zihc:47-50 |
| PUT | `/eula` | `{eulaState: Zhj}` | `Zrj` | 200, 400 | Zihc:52-88 |
| GET | `/scanConfigurationResources` | — | `Zwo` (resources JSON) | 200 | Zihc:90-103 |
| DELETE | `/` (root) | — | — | 200 | Zihc:105-109 |
| GET | `/eventDetails` | — | `List<Zgj>` (event types) | 200 | Zihc:111-114 |

#### 3.3.3 Enterprise Agent / Desktop (Zihy.java — extends Zihg)

| Method | Path | Request | Response | Status Codes | Evidence |
|--------|------|---------|----------|--------------|----------|
| PUT | `/resumeScan` | `{resume: Zjh}` | `Zrj` | 200 | Zihy:68-80 |
| POST | `/scan` | `{scan: Zeq}` | `Zaq` (task) | 200 | Zihy:82-93 |
| POST | `/urlApiScan` | `{scan: Znq}` | `Zaq` (task) | 200 | Zihy:95-106 |
| POST | `/fileUploadApiScan` | `{scan: Za5}` | `Zaq` (task) | 200 | Zihy:108-119 |
| POST | `/retest` | `{retest: Zsi}` | `Zaq` (task) | 200 | Zihy:121-146 |
| GET | `/xml_reports` | — | `List<String>` (filenames) | 200 | Zihy:148-159 |
| POST | `/connection_check` | `{scan: Zeq}` | `Zaq` (task) | 200 | Zihy:161-172 |
| POST | `/generate_recorded_login` | `{generateRecordedLogin: Za7}` | `Zaq` (task) | 200 | Zihy:174-185 |
| POST | `/explore_issue` | `{exploreIssue: Zx5}` | `Zaq` (task) | 200 | Zihy:187-198 |
| GET | `/metrics` | — | `List<Zg_>` | 200 | Zihy:200-203 |
| PUT | `/configuration` | `{configurationRequest: Zor}` | `Zrj` | 200 | Zihy:205-209 |
| DELETE | `/` (root) | — | — (shutdown) | 200 | Zihy:211-229 |

#### 3.3.4 Desktop-Only (Zxqq.java)

| Method | Path | Request | Response | Status Codes | Evidence |
|--------|------|---------|----------|--------------|----------|
| GET | `/active_tasks` | — | `Zsd0` | 200 | Zxqq:113-116 |
| DELETE | `/carlos_montoya` | — | — | 200 | Zxqq:118-121 |
| PUT | `/license` | `Zor` (config) | `Zrj` | 200 | Zxqq:124-127 |
| GET | `/knowledgeBase` | — | `Zkh` | 200 | Zxqq:130-132 |
| WS | `/` (root) | — | `Zs1<Zz8,Zpx>` | 101 | Zxqq:135-137 |

### 3.4 Scan Definition (Zeq, Znq, Za5, Zsi, Zjh)

From Zihy.java parameter types:
- `Zeq`: Full scan definition (URLs, scope, scan_configurations by name or inline, application_logins, resource_pool, scan_callback)
- `Znq`: URL-based API scan
- `Za5`: File upload API scan (OpenAPI/Swagger)
- `Zsi`: Retest definition (issue identifiers to re-test)
- `Zjh`: Resume scan definition

### 3.5 Issue Events & Scan Status Reporting

- WebSocket endpoint (Zxqq:135-137) for real-time events
- `/metrics` (Zihy:200-203) returns `List<Zg_>` for Prometheus-style metrics
- Issue events: `Zm8i` enum values with `Zv()` true are streamed (Zihc:111-114)
- Scan status: `Zaq` (task) returned from scan endpoints contains task ID for polling

---

## 4. WebProbe Current State vs Burp

### 4.1 Command-Line Options

| Burp Item | WebProbe (file:line) | Gap |
|-----------|---------------------|-----|
| `--help` | app/src/main.rs:956-960 (only `--screenshot`) | Missing |
| `--disable-extensions` | app/src/main.rs: env `WEBPROBE_NO_EXTENSIONS` | Partial (env only) |
| `--diagnostics` | — | Missing |
| `--use-defaults` | — | Missing |
| `--collaborator-server` | — | Missing |
| `--collaborator-config` | — | Missing |
| `--project-file` | app/core/src/bin/webprobe-headless.rs:73 (`--project`) | Partial (headless only) |
| `--config-file` | — | Missing |
| `--user-config-file` | — | Missing |
| `--auto-repair` | — | Missing |
| `--unpause-spider-and-scanner` | — | Missing |
| `-Djava.awt.headless=true` | app/core/src/bin/webprobe-headless.rs (headless binary) | Different architecture |
| `-Xmx` / `-XX:MaxRAMPercentage` | N/A (Rust) | N/A |
| `--temporary-project` | — | Missing |
| `--data-dir` | app/src/main.rs: `project_path` from cwd | Partial (fixed) |
| `--suppress-jre-check` | N/A | N/A |
| `--disable-auto-update` | — | Missing |
| `--version` | — | Missing |

### 4.2 Settings Files

| Burp Item | WebProbe (file:line) | Gap |
|-----------|---------------------|-----|
| Project settings JSON (`--config-file`) | app/core/src/project.rs:845-925 `ProjectData` struct | Different schema |
| User settings JSON (`--user-config-file`) | app/src/main.rs: `shortcuts::Shortcuts` from `~/.config/webprobe/hotkeys.json` | Partial (hotkeys only) |
| Multiple config files, merge order | — | Missing |
| REST API settings in user config | — | Missing |

### 4.3 REST API

| Burp Item | WebProbe (file:line) | Gap |
|-----------|---------------------|-----|
| REST API server | — | Missing entirely |
| API key auth (SHA-256) | — | Missing |
| `/info`, `/knowledgeBase`, `/license*` | — | Missing |
| `/scan`, `/urlApiScan`, `/fileUploadApiScan` | — | Missing |
| `/retest`, `/resumeScan` | — | Missing |
| `/xml_reports`, `/metrics` | — | Missing |
| `/configuration` (PUT) | — | Missing |
| WebSocket for events | — | Missing |
| Bind address/port config | app/src/main.rs:1100-1103 (env `WEBPROBE_PORT`, `WEBPROBE_INTERCEPT`) | Partial (proxy only) |

### 4.4 Scan Definition

| Burp Item | WebProbe (file:line) | Gap |
|-----------|---------------------|-----|
| Scan config (speed, accuracy, checks) | app/core/src/scan.rs, app/core/src/project.rs:563-590 `ProjectScanner` | Partial (subset) |
| Scope (include/exclude) | app/core/src/project.rs:220-225 `ProjectScope` | Partial |
| Application logins | — | Missing |
| Resource pools | — | Missing |
| Scan callbacks | — | Missing |

---

## 5. Proposed Minimal Implementation Order

### Step 1: `--project-file` / `--config-file` / `--user-config-file` for Desktop App
**Acceptance check:**
```bash
webprobe --project-file /tmp/test-project.json --config-file /tmp/proj-config.json --user-config-file /tmp/user-config.json
# Expected: App loads project, applies project config, applies user config, no errors
```

### Step 2: `--disable-extensions` and `--diagnostics` flags
**Acceptance check:**
```bash
webprobe --disable-extensions --diagnostics 2>&1 | grep -i "extension.*disabled\|diagnostic"
# Expected: Shows extensions disabled and diagnostic output
```

### Step 3: `--version` and `--help` flags
**Acceptance check:**
```bash
webprobe --version
# Expected: Prints version string and exits 0
webprobe --help
# Expected: Prints usage with all flags and exits 0
```

### Step 4: Headless binary CLI parity (`webprobe-headless`)
Add `--config-file`, `--user-config-file`, `--unpause-spider-and-scanner` to headless
**Acceptance check:**
```bash
webprobe-headless proxy --project /tmp/p.json --config-file /tmp/c.json --user-config-file /tmp/u.json --unpause-spider-and-scanner --seconds 5
# Expected: Runs proxy with configs applied, unpauses scanner
```

### Step 5: Settings file schema — project settings (subset)
Implement `ProjectData` load/save for core sections: proxy listeners, scope, match/replace, scanner
**Acceptance check:**
```bash
webprobe --project-file /tmp/p.json --config-file /tmp/c.json
# Edit proxy listener port in UI, close, reopen — port persists
```

### Step 6: Settings file schema — user settings (REST API config)
Add `user_options.misc.api` equivalent to WebProbe user config
**Acceptance check:**
```bash
# Configure REST API port/key in Settings UI, restart — settings persist
cat ~/.config/webprobe/user.json | jq .api.enabled
# Expected: true
```

### Step 7: REST API skeleton — `/info` and `/knowledgeBase`
**Acceptance check:**
```bash
curl -H "X-Api-Key: <key>" http://127.0.0.1:1337/info
# Expected: {"version": "...", "build": "..."}
curl -H "X-Api-Key: <key>" http://127.0.0.1:1337/knowledgeBase
# Expected: KB JSON
```

### Step 8: REST API — scan endpoints (`/scan`, `/urlApiScan`)
**Acceptance check:**
```bash
curl -X POST -H "X-Api-Key: <key>" -H "Content-Type: application/json" \
  -d '{"scan":{"urls":["http://localhost:8080"],"crawl":true}}' \
  http://127.0.0.1:1337/scan
# Expected: {"task_id": "..."}
```

### Step 9: REST API — WebSocket for issue events
**Acceptance check:**
```bash
# Connect WS, trigger scan, receive issue event
wscat -c ws://127.0.0.1:1337/ -H "X-Api-Key: <key>"
# Expected: Receives JSON issue events in real time
```

### Step 10: REST API — `/configuration` PUT, `/metrics`, `/xml_reports`
**Acceptance check:**
```bash
curl -X PUT -H "X-Api-Key: <key>" -H "Content-Type: application/json" \
  -d '{"scanner":{"speed":2}}' http://127.0.0.1:1337/configuration
# Expected: 200 OK, subsequent scans use thorough speed
curl -H "X-Api-Key: <key>" http://127.0.0.1:1337/metrics
# Expected: Prometheus-format metrics
```

---

## Not Established Items

1. **Exact merge semantics for multiple `--config-file` / `--user-config-file`** — Zgz6 returns List but merge order not visible in decompiled code; assumed last-wins based on Burp convention.

2. **Full Zeq/Znq/Za5/Zsi/Zjh scan definition schemas** — Parameter types visible in Zihy.java but field structures not decompiled (opaque classes from `net.portswigger.api`).

3. **WebSocket event message format** — Zxqq:135-137 shows WS endpoint but message schema not in decompiled code.

4. **Default bind address for REST API when `address: null`** — UserDefaults.json shows `address: null` with `listen_mode: "loopback_only"`; exact behavior not confirmed.

5. **API key rotation/revocation endpoint** — Not found in decompiled classes; may be UI-only.

6. **`--execution-mode` values beyond "desktop"** — String literals show "enterprise-server", "enterprise-agent" but not confirmed in code.

7. **Project file corruption detection (`--auto-repair`)** — Zgz6.Zm() reads magic bytes (0x66616A70 / 0x80A5B2FC) but repair logic not fully visible.

8. **`--trust-project` behavior** — String literals exist but usage not traced in decompiled code.

9. **`Zxqq.Zy` static initialization** — List of API endpoint classes referenced in Zihc/Zihy productionFactory but initialization site not found.

10. **Complete ProjectDefaults.json leaf key count** — Approximated from structure; exact count requires full JSON traversal.
# R-11 — Burp built-in scan configurations mapped onto WebProbe

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

Read-only research. Scope: the 29 files in `/root/burp-re/in/extract/resources/BuiltInConfigs/`,
the two defaults files under `/root/burp-re/in/extract/resources/Preferences/`
(`AuditDefaults.json`, `CrawlDefaults.json`), the schema
`/root/burp-re/in/extract/net/portswigger/scan-config.schema.json`, the decompiled
tree limited to `/root/burp-re/out/readable_strict/root/`, and WebProbe source under
`/root/Documents/Craft Anything/burpsuite/` (paths below are repo-relative).

**Evidence conventions.** A "Burp resource" claim cites a file path I opened. A
"Burp class" claim cites `readable_strict/root/<Class>.java:<line>`. A WebProbe
claim cites `app/...:<line>`. Diffs were computed with `python3` by flattening
each config to leaf key paths and comparing to the flattened defaults; a key
present with exactly the default value is **not** counted as a change. "Changes
from defaults" below counts leaf key paths whose value differs from the
corresponding default, plus key paths that have no key at all in the defaults
file (marked `no default key`), because both change effective behaviour. The
`description` object (uuid/text/icon/featured/display_order) is metadata, not a
setting, and is excluded from all counts and diffs.

Key facts about the load path (evidence for the whole document):

- Built-in configs are discovered by walking `/resources/BuiltInConfigs` and
  accepting every path ending in `.json` (`Zb2v.java:36`, `Zb2v.java:42-70`,
  `Zb2v.java:73-75`). Each file's JSON is parsed into a `Zg4q` tree and wrapped
  in a `Zsnv` with the file name (minus `.json`) as its name
  (`Zb2v.java:94-103`, `Zb2v.java:114-117`, `Zsnv.java:20-33`).
- `Zsnv.Za()` returns that parsed config tree (`Zsnv.java:42-44`); `Zxpj` is the
  config interface (`Zxpj.java:1-12`).
- The schema is a single draft-07 document whose `properties` are exactly
  `crawler` and `scanner` (`scan-config.schema.json`, top-level `properties`),
  with `additionalProperties: false` on the nested objects (e.g.
  `scan-config.schema.json:372-375`, `:473-476`). It declares no merging,
  precedence, or ordering semantics; it is a validation schema only.

---

## 1. All built-in configs

Kind is derived from which top-level section(s) the file sets: `audit` =
`scanner.*` only, `crawl` = `crawler.*` only, `both` = both. "One-line meaning"
uses the config's own `description.text` where present (Balanced / Deep / Fast /
Lightweight) and is a literal description of the keys otherwise.

| File name | Kind | One-line meaning | Changes from defaults |
|---|---|---|---|
| `Add all links to site map.json` | crawl | Live passive crawl adds all discovered URLs and links to the site map | 3 |
| `Add requested item to site map.json` | crawl | Live passive crawl adds only the requested item itself, with suite scope and empty custom scope | 10 |
| `Audit checks - BChecks only.json` | audit | Report only BCheck-generated issues | 3 |
| `Audit checks - all except JavaScript analysis.json` | audit | All audit categories except JavaScript analysis | 1 |
| `Audit checks - all except time-based detection methods.json` | audit | Individual issues selected, but the "Time delays" detection method is disabled everywhere | 2 |
| `Audit checks - critical issues only.json` | audit | Report only 13 critical/high injection, code-execution and request-smuggling issue types | 3 |
| `Audit checks - extensions only.json` | audit | Report only extension-generated issues | 3 |
| `Audit checks - light active.json` | audit | Passive + light active only; medium and intrusive active off | 2 |
| `Audit checks - medium active.json` | audit | Passive + light + medium active only; intrusive active off | 1 |
| `Audit checks - passive.json` | audit | Passive checks only; all three active types and JavaScript analysis off | 4 |
| `Audit coverage - maximum.json` | audit | Maximum coverage: thorough speed, minimise false negatives, static JS analysis on, all quick-scan and insertion types on, no ignored parameters, moved-parameter points on | 24 |
| `Audit coverage - thorough.json` | audit | Thorough speed with minimise-false-negatives accuracy | 2 |
| `Crawl and Audit - Balanced.json` | both | "Provides a balance between coverage and speed. You will typically see the results of a Balanced scan within a few hours." | 3 |
| `Crawl and Audit - CICD Optimized.json` | both | 3-minute crawl, fast scan speed, restricted insertion points, no pause on failures, 10-second timeouts (CI/CD) | 16 |
| `Crawl and Audit - Deep.json` | both | "Achieve greater coverage and gain a better understanding of a site's security posture..." — raises the timeout pause thresholds | 2 |
| `Crawl and Audit - Fast.json` | both | "More thorough than a Lightweight scan, but still biased towards speed. Fast scans will generally complete within one hour." | 11 |
| `Crawl and Audit - Lightweight.json` | both | "Gain fast feedback on a site's security - for when speed is a priority. Lightweight mode will complete within 15 minutes." | 16 |
| `Crawl limit - 10 minutes.json` | crawl | Cap crawl time at 10 minutes | 1 |
| `Crawl limit - 30 minutes.json` | crawl | Cap crawl time at 30 minutes | 1 |
| `Crawl limit - 60 minutes.json` | crawl | Cap crawl time at 60 minutes | 1 |
| `Crawl strategy - faster.json` | crawl | Set crawl strategy to `faster` | 1 |
| `Crawl strategy - fastest.json` | crawl | Set crawl strategy to `fastest` | 1 |
| `Crawl strategy - more complete.json` | crawl | Set crawl strategy to `more complete` | 1 |
| `Crawl strategy - most complete.json` | crawl | Set crawl strategy to `most complete` | 1 |
| `Crawl strategy - slow client-side rendering.json` | crawl | Raise navigation / DOM-idle / network-idle thresholds to 200 for slow client-side rendering | 3 |
| `Minimize false negatives.json` | audit | Set scan accuracy to `minimise_false_negatives` | 1 |
| `Minimize false positives.json` | audit | Set scan accuracy to `minimise_false_positives` | 1 |
| `Never stop audit due to application errors.json` | audit | Set `pause_task_failed_audit_item_count` to 0 | 1 |
| `Never stop crawl due to application errors.json` | crawl | Set `pause_task_requests_timed_out_count` to 0 | 1 |

Defaults source for `audit` / `both` scanner keys:
`/root/burp-re/in/extract/resources/Preferences/AuditDefaults.json`; for
`crawl` / `both` crawler keys: `/root/burp-re/in/extract/resources/Preferences/CrawlDefaults.json`.
Every file above was opened at
`/root/burp-re/in/extract/resources/BuiltInConfigs/<File name>`.

---

## 2. Per-config diffs against the defaults

`no default key` means the key path does not appear in the corresponding
defaults file, so there is no literal default to print. Values are shown as
JSON. The large `selected_issues` arrays are expanded issue-by-issue in
section 4; here they are given as the exact array value.

#### `Add all links to site map.json`
- `crawler.live_passive_crawl.add_all_urls`: (no default key) → `true`
- `crawler.live_passive_crawl.add_form_submissions`: (no default key) → `false`
- `crawler.live_passive_crawl.add_links`: (no default key) → `true`

#### `Add requested item to site map.json`
- `crawler.live_passive_crawl.add_all_urls`: (no default key) → `false`
- `crawler.live_passive_crawl.add_form_submissions`: (no default key) → `false`
- `crawler.live_passive_crawl.add_item_itself`: (no default key) → `true`
- `crawler.live_passive_crawl.add_links`: (no default key) → `false`
- `crawler.live_passive_crawl.add_same_domain`: (no default key) → `false`
- `crawler.live_passive_crawl.add_urls_in_scope`: (no default key) → `false`
- `crawler.live_passive_crawl.custom_scope.advanced_mode`: (no default key) → `false`
- `crawler.live_passive_crawl.custom_scope.exclude`: (no default key) → `[]`
- `crawler.live_passive_crawl.custom_scope.include`: (no default key) → `[]`
- `crawler.live_passive_crawl.scope_type`: (no default key) → `"suite"`

#### `Audit checks - all except JavaScript analysis.json`
- `scanner.issues_reported.scan_type_javascript_analysis`: default `true` → `false`
- (sets to default, no change: `scan_type_intrusive_active`, `scan_type_light_active`, `scan_type_medium_active`, `scan_type_passive`, `select_individual_issues`, `selected_issues`)

#### `Audit checks - all except time-based detection methods.json`
- `scanner.issues_reported.select_individual_issues`: default `false` → `true`
- `scanner.issues_reported.selected_issues`: default `[]` → 9 issue objects; `enabled=true` for `0x00100210`, `0x00100100`, `0x00100200`, `0x00100c00`, and `enabled=false` for `0x00100f10`, `0x00100f00`, `0x00100e00`, `0x00100d00`, `0x00101000`; in each enabled issue the `Time delays` detection method is `enabled=false` while all other listed methods are `true` (full array in section 4).

#### `Audit checks - BChecks only.json`
- `scanner.issues_reported.scan_only_selected_issues`: (no default key) → `true`
- `scanner.issues_reported.select_individual_issues`: default `false` → `true`
- `scanner.issues_reported.selected_issues`: default `[]` → `[{"enabled":true,"type_index":"0x09000000","detection_methods":[{"enabled":true,"name":"Passive checks"},{"enabled":true,"name":"Active checks"}]}]`

#### `Audit checks - critical issues only.json`
- `scanner.issues_reported.scan_only_selected_issues`: (no default key) → `true`
- `scanner.issues_reported.select_individual_issues`: default `false` → `true`
- `scanner.issues_reported.selected_issues`: default `[]` → 13 issue objects, all `enabled=true`: `0x00100210`, `0x00100f10`, `0x00100c00`, `0x00100d00`, `0x00100e00`, `0x00100f00`, `0x00101000`, `0x00101200`, `0x00100100`, `0x00100200`, `0x00100f20`, `0x00400900`, `0x00200140` (detection methods in section 4).

#### `Audit checks - extensions only.json`
- `scanner.issues_reported.scan_only_selected_issues`: (no default key) → `true`
- `scanner.issues_reported.select_individual_issues`: default `false` → `true`
- `scanner.issues_reported.selected_issues`: default `[]` → `[{"enabled":true,"type_index":"0x08000000","detection_methods":[{"enabled":true,"name":"Passive checks"},{"enabled":true,"name":"Active checks"}]}]`

#### `Audit checks - light active.json`
- `scanner.issues_reported.scan_type_intrusive_active`: default `true` → `false`
- `scanner.issues_reported.scan_type_medium_active`: default `true` → `false`

#### `Audit checks - medium active.json`
- `scanner.issues_reported.scan_type_intrusive_active`: default `true` → `false`

#### `Audit checks - passive.json`
- `scanner.issues_reported.scan_type_intrusive_active`: default `true` → `false`
- `scanner.issues_reported.scan_type_javascript_analysis`: default `true` → `false`
- `scanner.issues_reported.scan_type_light_active`: default `true` → `false`
- `scanner.issues_reported.scan_type_medium_active`: default `true` → `false`

#### `Audit coverage - maximum.json`
- `scanner.audit_optimization.consolidate_passive_issues`: default `true` → `false`
- `scanner.audit_optimization.scan_accuracy`: default `"normal"` → `"minimise_false_negatives"`
- `scanner.audit_optimization.scan_speed`: default `"normal"` → `"thorough"`
- `scanner.audit_optimization.skip_ineffective_checks`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_body_params`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_cookies`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_entire_body`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_http_headers`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_param_name`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_url_params`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_url_path_filename`: default `true` → `false`
- `scanner.frequently_occurring_insertion_points.quick_scan_url_path_folders`: default `true` → `false`
- `scanner.ignored_insertion_points.skip_all_tests_for_parameters`: default = the 12-rule array in `AuditDefaults.json:31-116` → `[]`
- `scanner.ignored_insertion_points.skip_server_side_injection_for_parameters`: default = the 11-rule array in `AuditDefaults.json:117-195` → `[]`
- `scanner.javascript_analysis.max_dynamic_time_per_item`: default `30` → `600`
- `scanner.javascript_analysis.max_static_time_per_item`: default `30` → `600`
- `scanner.javascript_analysis.use_static_analysis`: default `false` → `true`
- `scanner.misc_insertion_point_options.max_insertion_points_per_base_request`: default `30` → `999`
- `scanner.modifying_parameter_locations.body_to_cookie`: default `false` → `true`
- `scanner.modifying_parameter_locations.body_to_url`: default `false` → `true`
- `scanner.modifying_parameter_locations.cookie_to_body`: default `false` → `true`
- `scanner.modifying_parameter_locations.cookie_to_url`: default `false` → `true`
- `scanner.modifying_parameter_locations.url_to_body`: default `false` → `true`
- `scanner.modifying_parameter_locations.url_to_cookie`: default `false` → `true`
- (sets to default, no change: the 8 `insertion_point_types.*`, `follow_redirections`, `maintain_session`, `fetch_out_of_scope_resources`, `request_missing_dependencies`, `use_dynamic_analysis`, `use_nested_insertion_points`)

#### `Audit coverage - thorough.json`
- `scanner.audit_optimization.scan_accuracy`: default `"normal"` → `"minimise_false_negatives"`
- `scanner.audit_optimization.scan_speed`: default `"normal"` → `"thorough"`
- (sets to default, no change: `consolidate_passive_issues`, `follow_redirections`, `maintain_session`, `skip_ineffective_checks`)

#### `Crawl and Audit - Balanced.json`
- `crawler.crawl_limits.maximum_crawl_time`: default `150` → `20`
- `crawler.crawl_limits.maximum_unique_locations`: default `1500` → `700`
- `crawler.crawl_optimization.crawl_using_provided_logins_only`: default `false` → `true`
- (sets to default, no change: both `crawler.error_handling` timeout keys and both `scanner.error_handling` consecutive-failure keys)

#### `Crawl and Audit - CICD Optimized.json`
- `crawler.crawl_limits.maximum_crawl_time`: default `150` → `3`
- `crawler.crawl_optimization.crawl_using_provided_logins_only`: default `false` → `true`
- `crawler.crawl_project_option_overrides.connect_timeout`: default `-1` → `10`
- `crawler.crawl_project_option_overrides.normal_timeout`: default `-1` → `10`
- `crawler.error_handling.pause_task_requests_timed_out_count`: default `15` → `0`
- `scanner.audit_optimization.maximum_crawl_and_audit_time`: default `0` → `15`
- `scanner.audit_optimization.scan_speed`: default `"normal"` → `"fast"`
- `scanner.audit_project_option_overrides.connect_timeout`: default `-1` → `10`
- `scanner.audit_project_option_overrides.normal_timeout`: default `-1` → `10`
- `scanner.error_handling.pause_task_failed_audit_item_count`: default `60` → `0`
- `scanner.insertion_point_types.insert_entire_body`: default `true` → `false`
- `scanner.insertion_point_types.insert_http_headers`: default `true` → `false`
- `scanner.insertion_point_types.insert_param_name`: default `true` → `false`
- `scanner.insertion_point_types.insert_url_path_filename`: default `true` → `false`
- `scanner.insertion_point_types.insert_url_path_folders`: default `true` → `false`
- `scanner.javascript_analysis.max_static_time_per_item`: default `30` → `10`

#### `Crawl and Audit - Deep.json`
- `crawler.error_handling.pause_task_requests_timed_out_count`: default `15` → `30`
- `scanner.error_handling.pause_task_failed_audit_item_count`: default `60` → `0`

#### `Crawl and Audit - Fast.json`
- `crawler.crawl_limits.maximum_crawl_time`: default `150` → `15`
- `crawler.crawl_limits.maximum_unique_locations`: default `1500` → `200`
- `crawler.crawl_optimization.crawl_using_provided_logins_only`: default `false` → `true`
- `crawler.error_handling.pause_task_requests_timed_out_count`: default `15` → `50`
- `scanner.audit_optimization.scan_speed`: default `"normal"` → `"fast"`
- `scanner.insertion_point_types.insert_entire_body`: default `true` → `false`
- `scanner.insertion_point_types.insert_http_headers`: default `true` → `false`
- `scanner.insertion_point_types.insert_param_name`: default `true` → `false`
- `scanner.insertion_point_types.insert_url_path_filename`: default `true` → `false`
- `scanner.insertion_point_types.insert_url_path_folders`: default `true` → `false`
- `scanner.javascript_analysis.max_static_time_per_item`: default `30` → `10`

#### `Crawl and Audit - Lightweight.json`
- `crawler.crawl_limits.maximum_crawl_time`: default `150` → `10`
- `crawler.crawl_optimization.crawl_using_provided_logins_only`: default `false` → `true`
- `crawler.crawl_project_option_overrides.connect_timeout`: default `-1` → `10`
- `crawler.crawl_project_option_overrides.normal_timeout`: default `-1` → `10`
- `crawler.error_handling.pause_task_requests_timed_out_count`: default `15` → `0`
- `scanner.audit_optimization.maximum_crawl_and_audit_time`: default `0` → `15`
- `scanner.audit_optimization.scan_speed`: default `"normal"` → `"fast"`
- `scanner.audit_project_option_overrides.connect_timeout`: default `-1` → `10`
- `scanner.audit_project_option_overrides.normal_timeout`: default `-1` → `10`
- `scanner.error_handling.pause_task_failed_audit_item_count`: default `60` → `0`
- `scanner.insertion_point_types.insert_entire_body`: default `true` → `false`
- `scanner.insertion_point_types.insert_http_headers`: default `true` → `false`
- `scanner.insertion_point_types.insert_param_name`: default `true` → `false`
- `scanner.insertion_point_types.insert_url_path_filename`: default `true` → `false`
- `scanner.insertion_point_types.insert_url_path_folders`: default `true` → `false`
- `scanner.javascript_analysis.max_static_time_per_item`: default `30` → `10`

#### `Crawl limit - 10 minutes.json`
- `crawler.crawl_limits.maximum_crawl_time`: default `150` → `10`

#### `Crawl limit - 30 minutes.json`
- `crawler.crawl_limits.maximum_crawl_time`: default `150` → `30`

#### `Crawl limit - 60 minutes.json`
- `crawler.crawl_limits.maximum_crawl_time`: default `150` → `60`

#### `Crawl strategy - faster.json`
- `crawler.crawl_optimization.crawl_strategy`: default `"normal"` → `"faster"`

#### `Crawl strategy - fastest.json`
- `crawler.crawl_optimization.crawl_strategy`: default `"normal"` → `"fastest"`

#### `Crawl strategy - more complete.json`
- `crawler.crawl_optimization.crawl_strategy`: default `"normal"` → `"more complete"`

#### `Crawl strategy - most complete.json`
- `crawler.crawl_optimization.crawl_strategy`: default `"normal"` → `"most complete"`

#### `Crawl strategy - slow client-side rendering.json`
- `crawler.crawl_optimization.await_navigation_timeout`: (no default key) → `200`
- `crawler.crawl_optimization.dom_idle_threshold`: (no default key) → `200`
- `crawler.crawl_optimization.network_idle_threshold`: (no default key) → `200`

#### `Minimize false negatives.json`
- `scanner.audit_optimization.scan_accuracy`: default `"normal"` → `"minimise_false_negatives"`

#### `Minimize false positives.json`
- `scanner.audit_optimization.scan_accuracy`: default `"normal"` → `"minimise_false_positives"`

#### `Never stop audit due to application errors.json`
- `scanner.error_handling.pause_task_failed_audit_item_count`: default `60` → `0`

#### `Never stop crawl due to application errors.json`
- `crawler.error_handling.pause_task_requests_timed_out_count`: default `15` → `0`

---

## 3. Union of key paths used by any built-in config, with WebProbe counterparts

The number in `[#N]` is how many of the 29 configs set that key (computed over
all 29 files; the `description` object excluded). "no counterpart" means I found
no `ScanConfig` field or saved setting that stores the value — a hardcoded
WebProbe constant that merely mirrors Burp's default is called out explicitly
and is **not** a loadable counterpart. Default-file keys that **no** built-in
config touches (e.g. `crawler.login_functions.*`, `crawler.customization.logging_*`,
`scanner.audit_optimization.parallel_crawl_and_audit`,
`scanner.issues_reported.indexed_bambdas` / `selected_bambda_scan_checks` /
`selected_bcheck_scan_checks`) are outside this union; where WebProbe happens to
model one, it is noted under its group.

WebProbe's whole `ScanConfig` surface is three things:
`disabled_checks`, `disabled_insertion`, and `crawl: CrawlLimits`
(`app/core/src/scan_config.rs:30-51`); it is persisted through
`from_saved` / `save_into` (`app/core/src/scan_config.rs:72-103`) and edited in
`scan_configuration` (`app/src/settings_dialog.rs:227-315`). Global "Audit
speed" / "Audit accuracy" are separate shared settings
(`app/src/settings_dialog.rs:144-145`).

### Audit optimization (`scanner.audit_optimization`)
| Key path | WebProbe today |
|---|---|
| `scan_speed` [#7] | Setting "Audit speed", `app/src/settings_dialog.rs:144`; core `Settings.speed`, `app/core/src/scan_checks.rs:28` |
| `scan_accuracy` [#4] | Setting "Audit accuracy", `app/src/settings_dialog.rs:145`; core `Settings.accuracy`, `app/core/src/scan_checks.rs:29` |
| `consolidate_passive_issues` [#4] | No field; behaviour hardcoded on — `app/core/src/scan.rs:337-340` ("consolidated like the original") |
| `follow_redirections` [#4] | no counterpart |
| `maintain_session` [#4] | no counterpart |
| `skip_ineffective_checks` [#4] | no counterpart |
| `maximum_crawl_and_audit_time` [#2] | no counterpart |

### Issues reported / selected issues (`scanner.issues_reported`)
| Key path | WebProbe today |
|---|---|
| `scan_type_passive` [#8] | no counterpart (no category switch; the closest lever is toggling each passive id in `disabled_checks`, `app/core/src/passive_checks.rs:72-140`, `app/core/src/scan_config.rs:33`) |
| `scan_type_light_active` [#8] | no counterpart |
| `scan_type_medium_active` [#8] | no counterpart |
| `scan_type_intrusive_active` [#8] | no counterpart |
| `scan_type_javascript_analysis` [#8] | no counterpart (no JS-analysis checks in any registry) |
| `select_individual_issues` [#8] | no counterpart (WebProbe always selects per check id) |
| `selected_issues` [#8] | Partial: `disabled_checks: BTreeSet<String>` holds check ids (`app/core/src/scan_config.rs:33`, `app/core/src/scan_config.rs:63-65`), but there is no per-issue `enabled` flag keyed by Burp `type_index`, and no per-detection-method selection |
| `scan_only_selected_issues` [#3] | no counterpart |
| `store_issues_within_queue_items` [#3] | no counterpart |
| `selected_bambda_scan_checks`, `selected_bcheck_scan_checks`, `indexed_bambdas` [#0] | no counterpart (in the defaults/schema but unused by built-in configs; no BCheck/Bambda engine) |

### Handling application errors — audit (`scanner.error_handling`)
| Key path | WebProbe today |
|---|---|
| `consecutive_audit_check_failures_to_skip_insertion_point` [#6] | no counterpart |
| `consecutive_insertion_point_failures_to_fail_audit_item` [#6] | no counterpart |
| `number_of_follow_up_passes` [#2] | no counterpart |
| `pause_task_failed_audit_item_count` [#4] | no counterpart |
| `pause_task_failed_audit_item_percentage` [#2] | no counterpart |

### Insertion point types (`scanner.insertion_point_types`)
All eight keys [#4 each] have a counterpart: `INSERTION_TYPES`
(`app/core/src/scan_config.rs:13-22`) stores a switched-off type in
`disabled_insertion` (`app/core/src/scan_config.rs:35`, `:67-69`), edited at
`app/src/settings_dialog.rs:258-266`. The mapping is
`insert_url_params→url`, `insert_body_params→body`, `insert_cookies→cookie`,
`insert_param_name→param_name`, `insert_http_headers→header`,
`insert_entire_body→entire_body`, `insert_url_path_folders→folder`,
`insert_url_path_filename→filename`.

### Modifying parameter locations (`scanner.modifying_parameter_locations`)
`body_to_cookie`, `body_to_url`, `cookie_to_body`, `cookie_to_url`, `url_to_body`,
`url_to_cookie` [#1 each] — **no counterpart**. WebProbe deliberately never
builds moved-parameter points: "Not built: Zuq.ZG's moved-parameter points
(every `scanner.modifying_parameter_locations` default is false)"
(`app/core/src/insertion.rs:1049-1051`); there is no field to turn them on.

### Ignored insertion points (`scanner.ignored_insertion_points`)
| Key path | WebProbe today |
|---|---|
| `skip_all_tests_for_parameters` [#1] | No field; the rule set is hardcoded (the `_ga`/`_gid`/`_gat`/XML-attribute rules) at `app/core/src/insertion.rs:293-307` |
| `skip_server_side_injection_for_parameters` [#1] | No field; hardcoded at `app/core/src/insertion.rs:309-320`, consulted by `skips_server_side()` (`app/core/src/insertion.rs:201-204`) and `check_applies` (`app/core/src/scan_checks.rs:370-372`) |

Both are only *read from the defaults*; the `Audit coverage - maximum.json`
override to `[]` cannot be represented.

### Frequently occurring insertion points (`scanner.frequently_occurring_insertion_points`)
`quick_scan_body_params`, `quick_scan_cookies`, `quick_scan_entire_body`,
`quick_scan_http_headers`, `quick_scan_param_name`, `quick_scan_url_params`,
`quick_scan_url_path_filename`, `quick_scan_url_path_folders` [#1 each] —
**no counterpart**. WebProbe has no quick-scan pass distinct from the full
insertion-point set.

### Misc insertion point options (`scanner.misc_insertion_point_options`)
| Key path | WebProbe today |
|---|---|
| `use_nested_insertion_points` [#1] | Yes: `NESTED_KEY`/`NESTED_LABEL` (`app/core/src/scan_config.rs:27-28`), stored in `disabled_insertion`, UI `app/src/settings_dialog.rs:268-274` |
| `max_insertion_points_per_base_request` [#1] | No field; hardcoded `MAX_INSERTION_POINTS: usize = 30` at `app/core/src/scan.rs:41`, enforced in `app/core/src/insertion.rs:392-400`. The `Audit coverage - maximum.json` value `999` cannot be loaded |

### JavaScript analysis (`scanner.javascript_analysis`)
`fetch_out_of_scope_resources` [#1], `max_dynamic_time_per_item` [#1],
`max_static_time_per_item` [#4], `request_missing_dependencies` [#1],
`use_dynamic_analysis` [#1], `use_static_analysis` [#1] — **no counterpart**.
WebProbe's crawl engine choice (`CrawlLimits.engine`,
`app/core/src/scan_config.rs:48-50`, UI `app/src/settings_dialog.rs:245-251`) is a
different setting and does not carry any of these values.

### Crawl optimization (`crawler.crawl_optimization`)
| Key path | WebProbe today |
|---|---|
| `crawl_strategy` [#4] | no counterpart |
| `crawl_using_provided_logins_only` [#4] | no counterpart |
| `await_navigation_timeout` [#1] | no counterpart |
| `dom_idle_threshold` [#1] | no counterpart |
| `network_idle_threshold` [#1] | no counterpart |
| `maximum_link_depth` [#0, defaults only] | `CrawlLimits.max_depth`, `app/core/src/scan_config.rs:44`, UI `app/src/settings_dialog.rs:233-235` — no built-in config sets it |

### Crawl limits (`crawler.crawl_limits`)
| Key path | WebProbe today |
|---|---|
| `maximum_unique_locations` [#5] | Yes: `CrawlLimits.max_locations`, `app/core/src/scan_config.rs:45`, `from_saved` clamp at `:85`, UI `app/src/settings_dialog.rs:236-238`; default constant `CRAWL_MAX_UNIQUE_LOCATIONS = 1500` at `app/core/src/scan.rs:43` |
| `maximum_crawl_time` [#7] | no counterpart |
| `maximum_request_count` [#3] | no counterpart |

### Login functions (`crawler.login_functions`)
`attempt_to_self_register_a_user`, `trigger_login_failures` — **[#0]**; no
built-in config sets them. no counterpart in WebProbe.

### Handling application errors — crawl (`crawler.error_handling`)
`number_of_follow_up_passes` [#6], `pause_task_requests_timed_out_count` [#6],
`pause_task_requests_timed_out_percentage` [#6] — **no counterpart**.

### Miscellaneous
| Key path | WebProbe today |
|---|---|
| `crawler.crawl_project_option_overrides.connect_timeout`, `.normal_timeout` [#2 each] | no counterpart |
| `scanner.audit_project_option_overrides.connect_timeout`, `.normal_timeout` [#2 each] | no counterpart (WebProbe's `*timeout` settings in project files are scanner speed inputs, not these overrides — `app/src/settings_dialog.rs:144`) |
| `crawler.live_passive_crawl.add_all_urls`, `.add_form_submissions`, `.add_links` [#2 each] | no counterpart |
| `crawler.live_passive_crawl.add_item_itself`, `.add_same_domain`, `.add_urls_in_scope`, `.scope_type`, `.custom_scope.advanced_mode`, `.custom_scope.exclude`, `.custom_scope.include` [#1 each] | no counterpart |
| `crawler.customization.request_robots_txt`, `.request_sitemap` [#0] | `CrawlLimits.robots` / `.sitemap`, `app/core/src/scan_config.rs:46-47`, UI `app/src/settings_dialog.rs:241-242` — no built-in config sets them |

---

## 4. How Burp selects issues, and the type-id → WebProbe-check mapping

### Structure

Evidence: `AuditDefaults.json:207-219`, the schema
`scan-config.schema.json:371-540`, and the four configs that populate it
(`Audit checks - BChecks only.json`, `... - critical issues only.json`,
`... - extensions only.json`, `... - all except time-based detection methods.json`).

Under `scanner.issues_reported` there are two independent selectors:

1. **Category switches** (booleans, all `true` in the defaults):
   `scan_type_passive`, `scan_type_light_active`, `scan_type_medium_active`,
   `scan_type_intrusive_active`, `scan_type_javascript_analysis`. Configs such
   as `Audit checks - passive.json` / `... - light active.json` / `... - medium
   active.json` turn these off; the schema declares each as a plain boolean
   (`scan-config.schema.json:372-398`).
2. **Individual-issue selection**, gated by `select_individual_issues` (bool,
   default `false`, `AuditDefaults.json:214`) and, when that is on,
   `scan_only_selected_issues` (bool, **not in the defaults** but declared in
   the schema at `scan-config.schema.json:403-406`; set `true` by the BChecks /
   extensions / critical-issues configs). `selected_issues` (default `[]`,
   `AuditDefaults.json:217`) is an array whose items have, per the schema
   (`scan-config.schema.json:465-501`), required `enabled` (bool) and
   `type_index` (string, e.g. `"0x00100200"`) and optional `detection_methods`:
   an array of `{ "enabled": bool, "name": string }`. A detection method with
   `enabled:false` suppresses that technique while leaving the issue type on —
   this is exactly how `Audit checks - all except time-based detection methods.json`
   works (`"Time delays"` is `enabled:false` in each selected issue). The
   method names that actually appear across the configs are: `Error messages`,
   `Time delays`, `Boolean conditions`, `Oracle specific`, `MySQL specific`,
   `SQL Server specific`, `Burp Collaborator`, `Burp Infiltrator`, `String echo`,
   `Back-end socket poisoning`, `Passive checks`, `Active checks`.
   WebProbe has no per-detection-method toggle: `scan_config.rs` stores only a
   set of disabled check ids (`app/core/src/scan_config.rs:33`).

`type_index` in the configs is a hex string whose digits match the filename
prefix of a KnowledgeBase file, e.g. `0x00100200` →
`KnowledgeBase/Issues/00100200_SqlInjection.json` (`typeIndex` 1049088,
`name` "SQL injection"). All issue names below were read from those opened
JSON files.

### Mapping table

WebProbe check ids come from the active registries `POINT_CHECKS` /
`REQUEST_CHECKS` (`app/core/src/scan_checks.rs:330-366`, each id/issue at its
`impl ... for` block) and `PASSIVE_CHECKS` (`app/core/src/passive_checks.rs:72-140`,
`CheckDef` id/name pairs e.g. `app/core/src/passive_pack.rs:19`). The id→Burp
issue-name association is confirmed by `check_catalogue`
(`app/core/src/scan.rs:2841-2847`) and WebProbe's own name→numeric-type table
`KB_ISSUE_TYPES` (`app/core/src/scan_checks.rs:2761-2764`, entries from the same
KnowledgeBase). "NONE" means no check in any of those registries reports that
issue type.

| Burp `type_index` | KB `name` (resource) | WebProbe check id(s) |
|---|---|---|
| `0x00100100` | OS command injection (`00100100_OsCommandInjection.json`) | `active.os-command-injection` (`app/core/src/scan_checks.rs:893-895`) |
| `0x00100200` | SQL injection (`00100200_SqlInjection.json`) | `active.sql-injection-error` (`:1774-1776`), `active.sql-injection-boolean` (`:1841-1843`) |
| `0x00100210` | SQL injection (second order) (`00100210_SqlInjectionSecondOrder.json`) | NONE |
| `0x00100c00` | PHP code injection (`00100c00_PhpCodeInjection.json`) | `active.php-code-injection` (`app/core/src/scan_checks.rs:1489-1491`) |
| `0x00100d00` | Server-side JavaScript code injection (`00100d00_ServerSideJavaScriptCodeInjection.json`) | NONE |
| `0x00100e00` | Perl code injection (`00100e00_PerlCodeInjection.json`) | NONE |
| `0x00100f00` | Ruby code injection (`00100f00_RubyCodeInjection.json`) | NONE |
| `0x00100f10` | Python code injection (`00100f10_PythonCodeInjection.json`) | NONE |
| `0x00100f20` | Expression Language injection (`00100f20_ExpressionLanguageInjection.json`) | NONE |
| `0x00101000` | Unidentified code injection (`00101000_UnidentifiedCodeInjection.json`) | NONE |
| `0x00101200` | React Server Components remote code execution (React2Shell) (`00101200_ReactServerComponentsRemoteCodeExecutionReact2shell.json`) | NONE — see collision note below |
| `0x00200140` | HTTP request smuggling (`00200140_HttpRequestSmuggling.json`) | NONE |
| `0x00400900` | Serialized object in HTTP message (`00400900_SerializedObjectInHttpMessage.json`) | `passive.serialized-object` (`app/core/src/passive_pack.rs:19`) |
| `0x08000000` | Extension generated issue (`08000000_ExtensionGeneratedIssue.json`) | NONE (no extension-issue check id) |
| `0x09000000` | BCheck generated issue (`09000000_BCheckGeneratedIssue.json`) | NONE (no BCheck engine in WebProbe) |

**KnowledgeBase collision, evidence-backed:** in
`00101200_ReactServerComponentsRemoteCodeExecutionReact2shell.json` the JSON
field is `"typeIndex": 1052160`, which is `0x00100e00` (Perl code injection),
not `0x00101200` (= 1052928). No KnowledgeBase JSON has a `typeIndex` field of
`0x00101200`. WebProbe's comment says "the file-name prefix is the same number
in hex except for two entries, where the JSON field wins"
(`app/core/src/scan_checks.rs:2761-2764`), so in WebProbe's `KB_ISSUE_TYPES`
the React2Shell name is registered under `0x00100e00`, and the config's literal
`0x00101200` matches no WebProbe numeric type. Either way there is no WebProbe
check id for it.

---

## 5. How several configs combine when a scan uses more than one

**Established — the merge primitive is last-write-wins per key.**
`Zxm6.Ze(Zg4q var1)` (`Zxm6.java:606-631`) builds a `HashMap` of the receiver's
existing entry keys to positions, then iterates the incoming config's entries:
if the key is already present it does `this.Zf.set(pos, newEntry)` (replace),
otherwise `this.Zf.add(newEntry)` (append). So a config merged later replaces
the earlier value for every key it specifies and leaves all other keys intact;
it is a key-by-key overlay, not a whole-file replacement.
`Zbqe.Zz()` (`Zbqe.java:63-75`) and `Zbqe.ZR()` (`Zbqe.java:111-125`) fold their
children through exactly this `Zxm6.Ze` in child iteration order, so within one
config tree later siblings win per key. `Zbqe.Zm(Zg4q var1)`
(`Zbqe.java:93-107`) is the inverse — it pushes a config's values into the
option widgets (`Zma2.Zg`), which is how a config is applied to the Scanner
settings UI (`Zx3i.Zd(Zg4q)` at `Zx3i.java:66-73`, `Zibv.ZG`/`Zibv.ZX` at
`Zibv.java:514-519`).

**Not established — the scan-time layering of several selected built-in
configs.** The merge primitive above is per key and last-write-wins, but I
could not establish from the examined classes what *order* Burp uses when a
single scan is given multiple built-in configs, hence which config is the
"later" winner. What I examined: the loader `Zb2v` (`Zb2v.java:42-70`) and its
wrapper `Zsnv` (`Zsnv.java:20-44`) only enumerate and parse each file into one
`Zxpj` each; `Zcwr` (`Zcwr.java:18-24`, `:135-145`) keeps the list for
name-collision checks when saving, not for layering. `Zx3i` holds four `Zbqe`
trees (`Zx3i.java:12-31`) that `Zibv` applies configs to (`Zibv.java:25-53`,
`:505-519`), but those are option-panel subtrees, not a ranked list of selected
built-in configs. I also grepped `readable_strict/root` for `BuiltInConfigs`,
`Zxpj`, `.Za()` and `.Ze(` (see the evidence list in the "Not established"
section); no scan-launch class that folds a `List<Zxpj>` in a defined order was
identified. Claiming "configs are applied in UI/display order, later overrides
earlier" would go beyond the evidence.

---

## 6. What WebProbe's `ScanConfig` would need to load every built-in config

Ordered by how many of the 29 built-in configs use the missing key (computed
from section 3). Counts are per key; a "capability" row groups keys that one
field could carry. Keys with a real WebProbe counterpart (section 3) and the
three hardcoded mirrors (consolidate_passive_issues, max insertion points,
ignored insertion lists) are excluded, since the question is about *losing a
setting on load*.

1. **Issue-category + individual-issue selection — 8 configs each.** Need
   `scan_type_passive`, `scan_type_light_active`, `scan_type_medium_active`,
   `scan_type_intrusive_active`, `scan_type_javascript_analysis`,
   `select_individual_issues`, `selected_issues` (with per-issue `enabled`,
   `type_index` and per-detection-method `enabled`). Today only `disabled_checks`
   exists (`app/core/src/scan_config.rs:33`). This is the single biggest gap:
   without it the six "Audit checks - …" configs cannot be loaded without loss.
2. **Crawl time cap `crawler.crawl_limits.maximum_crawl_time` — 7 configs.**
   No field; needed by all three `Crawl limit - …` and four `Crawl and Audit - …`
   configs (Balanced/CICD/Fast/Lightweight).
3. **Audit + crawl error-handling thresholds — 6 configs each.**
   `consecutive_audit_check_failures_to_skip_insertion_point` and
   `consecutive_insertion_point_failures_to_fail_audit_item` (audit, 6 each),
   `number_of_follow_up_passes`, `pause_task_requests_timed_out_count`,
   `pause_task_requests_timed_out_percentage` (crawl, 6 each); plus
   `pause_task_failed_audit_item_count` (4), `pause_task_failed_audit_item_percentage`
   (2) and audit `number_of_follow_up_passes` (2). Needed by both
   "Never stop …" configs and the Deep/Fast/CICD/Lightweight presets.
4. **Crawl strategy + provided-logins-only — 4 configs each.**
   `crawler.crawl_optimization.crawl_strategy` and
   `.crawl_using_provided_logins_only`; needed by the four `Crawl strategy - …`
   configs and the four `Crawl and Audit - …` presets respectively.
5. **Audit optimization booleans — 4 configs each.**
   `follow_redirections`, `maintain_session`, `skip_ineffective_checks`;
   `maximum_crawl_and_audit_time` is 2. `scan_speed`/`scan_accuracy` already
   have settings (section 3).
6. **JavaScript-analysis settings — up to 4 configs.**
   `max_static_time_per_item` (4), `max_dynamic_time_per_item`,
   `use_static_analysis`, `use_dynamic_analysis`,
   `fetch_out_of_scope_resources`, `request_missing_dependencies` (1 each).
7. **`scan_only_selected_issues` and `store_issues_within_queue_items` — 3 configs each.**
   Both in `scanner.issues_reported`; the former is required to interpret the
   critical/BChecks/extensions configs correctly.
8. **`maximum_request_count` — 3 configs** (`Crawl limit - …`).
9. **Project option timeouts — 2 configs each.**
   `crawler.crawl_project_option_overrides.{connect_timeout,normal_timeout}`
   and `scanner.audit_project_option_overrides.{connect_timeout,normal_timeout}`
   (CICD Optimized, Lightweight).
10. **Quick-scan toggles — 1 config each (8 keys).**
    `scanner.frequently_occurring_insertion_points.quick_scan_*` (Audit coverage -
    maximum).
11. **Moved-parameter locations — 1 config each (6 keys).**
    `scanner.modifying_parameter_locations.*` (Audit coverage - maximum);
    note this also needs the point builder to actually build those points
    (`app/core/src/insertion.rs:1049-1051`).
12. **Client-side rendering thresholds — 1 config each (3 keys).**
    `crawler.crawl_optimization.{await_navigation_timeout,dom_idle_threshold,network_idle_threshold}`
    (`Crawl strategy - slow client-side rendering`).
13. **Live passive crawl site-map settings — up to 2 configs (10 keys).**
    `crawler.live_passive_crawl.*` including `custom_scope.{include,exclude,advanced_mode}`
    (`Add all links to site map`, `Add requested item to site map`).

---

## Not established

1. **The order in which multiple built-in configs are combined at scan time,
   and therefore which one wins per key.** Established only that the merge
   primitive is per-key last-write-wins (`Zxm6.java:606-631`,
   `Zbqe.java:63-75`). Examined: `Zb2v.java:42-70` (loader),
   `Zsnv.java:20-44` (wrapper), `Zcwr.java:18-24`/`:135-145` (save/name list),
   `Zx3i.java:12-31`/`:66-73` and `Zibv.java:25-53`/`:505-519` (option-panel
   application), plus `timeout 60` recursive greps of
   `readable_strict/root` for `BuiltInConfigs` (only `Zb2v.java`), `Zxpj`,
   `.Za()` and `.Ze(`. No scan-launch class folding a `List<Zxpj>` in a defined
   order was found.
2. **The exact meaning of Burp's internal `consecutive_*` / `number_of_follow_up_passes`
   counters** beyond the key names and the values in the configs; no readable
   class was tied to a specific counter, so their runtime semantics are not
   claimed here.
3. **Whether `scan_only_selected_issues:false` is the effective default** when
   the key is absent (as in `Audit checks - all except time-based detection
   methods.json`): the key is absent from `AuditDefaults.json` but present in
   the schema (`scan-config.schema.json:403-406`) with no stated default. Its
   fallback value is not established; only its presence/`true` value is.

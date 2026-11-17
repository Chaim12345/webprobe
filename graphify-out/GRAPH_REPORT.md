# Graph Report - app  (2026-11-17)

## Corpus Check
- 70 files · ~214,106 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 2 file(s) not represented in the graph (top: .toml 1, .jar 1)

## Summary
- 3319 nodes · 7620 edges · 140 communities (127 shown, 13 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 200 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `010fdfa7`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- scan.rs
- burp_checks.rs
- scan_checks.rs
- h2.rs
- tls.rs
- discovery.rs
- shortcuts.rs
- intruder_run.rs
- intruder.rs
- ui.rs
- rules.rs
- ext_host.rs
- msgpane.rs
- active_checks.rs
- ScanCtx
- tools.rs
- theme.rs
- decoder_ops.rs
- .new
- RequestCheck
- ScanSpeed
- Shared
- collaborator.rs
- repeater_ops.rs
- net.rs
- table.rs
- UpstreamConn
- logger.rs
- Attr
- settings_dialog.rs
- ScanIssue
- AttackType
- TcpStream
- feedback.rs
- engagement.rs
- crawl.rs
- IpKind
- core/src/report.rs
- entry
- recovery.rs
- analysis.rs
- DnsCapture
- interactsh.rs
- RepTab
- ProjectData
- PayloadSource
- util.rs
- main.rs
- intruder_ui.rs
- cookie_jar.rs
- upstream.rs
- passive_issues
- editor.rs
- xss.rs
- seq_bits.rs
- Service
- codec.rs
- Processor
- project.rs
- temporary_project
- ReportIssue
- egui
- apply_as
- fuzz_tests.rs
- Organizer
- start_active_scan
- onboarding.rs
- App
- RepAction
- Color32
- Tab
- DemoExtension.java
- Mutex
- parse_dns_query
- intercept_ws_stream
- run_open_redirect_check
- Tok
- FollowMode
- proxy_history
- analysis_ui.rs
- intercept_rules.rs
- .generate
- super
- menus.rs
- ai.rs
- InteractionLog
- CollaboratorState
- HistEntry
- .run
- MontoyaBridge
- history_filter.rs
- browser_crawl
- build_report_issues
- InteractionDetail
- collaborator_ui.rs
- Kind
- requests
- .run
- variations.rs
- fingerprint
- history_and_issues_convert_both_ways
- SqlBoolGen
- Mechanics sheet — WebProbe (rebuild of Burp Suite Pro build 52685)
- http_loop
- csrf_static_token_hit
- Json
- gl_env.rs
- response_body_kind
- listener_worker
- ScanEvidence
- proxy_settings.rs
- webprobe-headless.rs
- DiffKind
- ExtractItem
- decode
- appearance
- apply_action
- SequencerReport
- Accuracy
- btreeset
- a_headless_browser_leaves_no_processes_behind
- Organization
- InsertionPoint
- is_light
- run_xml_injection_check
- regularized_gamma_q
- NumberBase
- ProjectCookieJar
- run_ssi_check
- run_ssti_check
- TextEditMargin
- DnsInteraction
- .for_palette
- find_window
- base_text_styles
- webprobe
- build-demo-ext.sh

## God Nodes (most connected - your core abstractions)
1. `App` - 147 edges
2. `Shared` - 126 edges
3. `HistEntry` - 70 edges
4. `c()` - 68 edges
5. `ScanCtx` - 52 edges
6. `CheckDef` - 43 edges
7. `Attr` - 43 edges
8. `ProjectData` - 39 edges
9. `PayloadSource` - 37 edges
10. `inject()` - 35 edges

## Surprising Connections (you probably didn't know these)
- `prssi_follows_zwza()` --calls--> `page()`  [INFERRED]
  core/src/burp_checks.rs → src/settings_dialog.rs
- `live_smtp_recipient_forms()` --calls--> `line()`  [INFERRED]
  core/src/interactsh.rs → src/theme.rs
- `close_launched_browsers()` --references--> `Shared`  [EXTRACTED]
  src/tools.rs → core/src/net.rs
- `history_view()` --calls--> `history_host()`  [INFERRED]
  src/ui.rs → core/src/net.rs
- `proxy_history()` --calls--> `history_host()`  [INFERRED]
  src/ui.rs → core/src/net.rs

## Import Cycles
- 1-file cycle: `core/src/net.rs -> core/src/net.rs`
- 1-file cycle: `core/src/sync.rs -> core/src/sync.rs`
- 1-file cycle: `src/ui.rs -> src/ui.rs`
- 1-file cycle: `core/src/rules.rs -> core/src/rules.rs`
- 1-file cycle: `core/src/tls.rs -> core/src/tls.rs`
- 2-file cycle: `src/main.rs -> src/ui.rs -> src/main.rs`
- 3-file cycle: `core/src/h2.rs -> src/ui.rs -> src/main.rs -> core/src/h2.rs`
- 3-file cycle: `core/src/intruder_run.rs -> src/ui.rs -> src/main.rs -> core/src/intruder_run.rs`

## Communities (140 total, 13 thin omitted)

### Community 0 - "scan.rs"
Cohesion: 0.03
Nodes (79): base_status(), BURP_TLDS, CH_ASPNET, CH_AUTOCOMPLETE, CH_CACHE, CH_CLEARTEXT, CH_COOKIE_HTTPONLY, CH_COOKIE_SAMESITE (+71 more)

### Community 1 - "burp_checks.rs"
Cohesion: 0.06
Nodes (47): as_http(), attr(), body_of(), Collector, cors_detail(), CorsFinding, CorsKind, Arbitrary (+39 more)

### Community 2 - "scan_checks.rs"
Cohesion: 0.04
Nodes (25): Baseline, BURP_GROUP, ClientTemplateInjection, FilePathManipulation, HeaderInjection, InputReflected, KB_ISSUE_TYPES, LdapInjection (+17 more)

### Community 3 - "h2.rs"
Cohesion: 0.05
Nodes (49): base64url(), data_payload(), DEFAULT_MAX_FRAME, DEFAULT_WINDOW, empty_settings_value(), encode_headers(), exchange(), exchange_upgraded() (+41 more)

### Community 4 - "tls.rs"
Cohesion: 0.05
Nodes (21): AcceptAnyServerCert, add_calendar_years(), ca_not_before_year(), CA_NOT_BEFORE_YEAR, ca_persists_byte_identical_across_restarts(), CA_SERIAL_BITS, CA_VALIDITY_YEARS, CaSeed (+13 more)

### Community 5 - "discovery.rs"
Cohesion: 0.07
Nodes (45): file_path_manip_detects_a_file_selector(), add_new_to_site_map(), body_len(), build_request(), BUILTIN_DIRS, BUILTIN_FILES, candidates(), candidates_respect_mode_extensions_and_case() (+37 more)

### Community 6 - "shortcuts.rs"
Cohesion: 0.08
Nodes (32): a(), ActionDef, ACTIONS, an_unbound_action_stays_unbound_after_a_reload(), canonical_key_name(), Capture, Cancelled, Chord (+24 more)

### Community 7 - "intruder_run.rs"
Cohesion: 0.07
Nodes (40): analyse(), AttackSettings, body_offset(), csv_field(), csv_quotes_and_lists_grep_columns(), curl_command(), DEFAULT_MATCH_ITEMS, extract_all() (+32 more)

### Community 8 - "intruder.rs"
Cohesion: 0.05
Nodes (27): add_and_clear_markers(), add_marker(), auto_mark(), character_substitution_uses_burps_table_and_bit_order(), civil_from_days(), clear_markers(), custom_iterator_varies_position_one_fastest_with_separators(), default_substitutions() (+19 more)

### Community 9 - "ui.rs"
Cohesion: 0.10
Nodes (46): history_host(), c(), add_marker(), burp_ai(), comparer(), dashboard(), dashboard_summary(), decoder() (+38 more)

### Community 10 - "rules.rs"
Cohesion: 0.08
Nodes (36): apply_edits(), apply_header(), apply_params(), apply_rule(), apply_rules(), collect_param_edits(), Edit, find_subslice() (+28 more)

### Community 11 - "ext_host.rs"
Cohesion: 0.07
Nodes (14): DropExtension, EchoExtension, ExampleHeaderExtension, ExtensionHost, java_sidecar_runs_a_real_montoya_extension(), JavaSidecar, LoadedExtension, ProxyAction (+6 more)

### Community 12 - "msgpane.rs"
Cohesion: 0.08
Nodes (36): body_of(), byte_at(), cookies(), decode_image(), editable_pane(), editable_pane_ex(), image_kind(), IMAGE_MAX_SIDE (+28 more)

### Community 13 - "active_checks.rs"
Cohesion: 0.08
Nodes (41): ALNUM36, angular_scopes(), angular_scopes_follow_zg1t(), angular_version_in(), body_of(), contains(), csti_check_follows_zrmh(), csti_context_ok() (+33 more)

### Community 14 - "ScanCtx"
Cohesion: 0.20
Nodes (19): add_issues(), PointRun, ScanCtx, ScanState, server_host_hdr(), cookie_insertion_point(), encode_query_payload(), header_insertion_points() (+11 more)

### Community 15 - "tools.rs"
Cohesion: 0.09
Nodes (42): ProjectRule, add_sequencer_sample(), appearance_options(), attack_name(), attack_of(), browser_args(), browser_candidates(), browser_home_with_ca() (+34 more)

### Community 16 - "theme.rs"
Cohesion: 0.05
Nodes (40): BAD, DENSITY, EDITOR_CUR_LINE, EDITOR_TEXT, FONT_BODY, FONT_H1, FONT_H2, FONT_MONO (+32 more)

### Community 17 - "decoder_ops.rs"
Cohesion: 0.07
Nodes (34): apply(), ascii_hex_decode(), ascii_hex_encode(), base64_decode(), K256, K512, md5_hex(), Op (+26 more)

### Community 18 - ".new"
Cohesion: 0.10
Nodes (37): absolute_form_forwarded_as_origin_form(), assert_normalised_h2_view(), client_certificate_presented_to_mtls_server(), client_config(), connect_intercepts_https_with_a_ca_signed_host_certificate(), connections_beyond_the_limit_get_a_503_and_slots_are_returned(), content_length(), handle_conn() (+29 more)

### Community 19 - "RequestCheck"
Cohesion: 0.05
Nodes (12): Cors, HeaderManipulation, OpenApiDefinition, PathRelativeStyleSheet, REQUEST_CHECKS, RequestCheck, Scope, Host (+4 more)

### Community 20 - "ScanSpeed"
Cohesion: 0.06
Nodes (41): file_marker_baseline(), file_marker_hits(), file_markers_are_case_insensitive_and_baseline_suppressed(), file_path_manip_variants_match_burp_zulm(), file_path_variants(), FilePathManipHit, FileReadHit, generic_error_in() (+33 more)

### Community 21 - "Shared"
Cohesion: 0.09
Nodes (34): append_cookie(), apply_session_rules_for(), ClientCertRule, expand_placeholders(), in_scope(), in_session(), intercept_forward(), intercept_release() (+26 more)

### Community 22 - "collaborator.rs"
Cohesion: 0.06
Nodes (28): DEFAULT_DNS_PORT, DEFAULT_HTTP_PORT, DNS_HEADER_LEN, DNS_READ_TIMEOUT, dns_token(), DNS_TTL_SECS, find_header_end(), generated_tokens_are_unique_and_safe() (+20 more)

### Community 23 - "repeater_ops.rs"
Cohesion: 0.09
Nodes (29): change_method_get_to_post_moves_query_to_body(), change_method_post_to_get_moves_body_to_query(), CROSS_SITE_HEADERS, cross_site_redirects_strip_headers_and_rewrite_host(), encode_typed(), follow_policy_and_hop_cap(), head_lines_and_body(), header_name() (+21 more)

### Community 24 - "net.rs"
Cohesion: 0.07
Nodes (24): app(), Attack, AttackRow, body(), check_session_logs_in_once_and_only_for_tools_in_scope(), DEFAULT_INTERCEPT_EXCLUDED_EXTENSIONS, header_cookie_and_post_request_actions_apply_in_order(), INTRUDER_REQUEST_LIMIT (+16 more)

### Community 25 - "table.rs"
Cohesion: 0.16
Nodes (20): cell(), cell_w(), cells(), Column, column_chooser(), data_table(), DIVIDER, empty_filter_returns_every_row() (+12 more)

### Community 26 - "UpstreamConn"
Cohesion: 0.08
Nodes (20): browser_item_response(), browser_item_routes_show_and_repeat(), exchange(), host_matches(), new_tls_conn(), ProxyIo, relay_ws_tls(), response_allows_reuse() (+12 more)

### Community 27 - "logger.rs"
Cohesion: 0.13
Nodes (19): BODIES_KEPT, cap_evicts_oldest(), clear_empties_but_ids_continue(), CSV_COLUMNS, csv_field(), csv_has_table_columns_and_filtered_rows_in_view_order(), DEFAULT_CAP, empty_query_matches_everything() (+11 more)

### Community 28 - "Attr"
Cohesion: 0.06
Nodes (35): Attr, AnchorLabels, BodyContent, ButtonSubmitLabels, CanonicalLink, ColonCount, Comments, ContentLength (+27 more)

### Community 29 - "settings_dialog.rs"
Cohesion: 0.09
Nodes (29): install(), Kind, Project, User, labels(), manage_menu(), page(), PageDef (+21 more)

### Community 30 - "ScanIssue"
Cohesion: 0.11
Nodes (23): ScanIssue, advisory_text(), advisory_text_drops_markup_and_keeps_the_words(), CONFIDENCES, detail_markup_is_rendered_and_plain_details_are_untouched(), detail_text(), filter_selects_by_severity_confidence_and_false_positive(), group_issues() (+15 more)

### Community 31 - "AttackType"
Cohesion: 0.12
Nodes (23): apply_copies(), Attack, attack(), AttackType, BatteringRam, ClusterBomb, Pitchfork, Sniper (+15 more)

### Community 32 - "TcpStream"
Cohesion: 0.12
Nodes (22): apply_session_rules(), browser_listener(), derive_history_fields(), diff_attrs(), DiffTracker, handle_connect(), handle_tls_websocket(), handle_websocket() (+14 more)

### Community 33 - "feedback.rs"
Cohesion: 0.11
Nodes (20): Level, Error, Info, Success, Warn, take_queued(), toast(), drain() (+12 more)

### Community 34 - "engagement.rs"
Cohesion: 0.13
Nodes (24): attr_value(), comments_in_html_and_inline_scripts(), find_comments(), find_in_branch(), find_references(), find_scripts(), FindResults, in_branch() (+16 more)

### Community 35 - "crawl.rs"
Cohesion: 0.11
Nodes (27): browser_response(), browser_response_drops_codings_and_fixes_length(), CLICKABLES_JS, crawl(), fetch(), field(), fill_and_submit_js(), fill_kind() (+19 more)

### Community 36 - "IpKind"
Cohesion: 0.08
Nodes (27): body_and_json_insertion_points(), disposition_attr(), insertion_points(), insertion_points_follow_burp_order_and_cap(), insertion_type(), IpKind, Body, Cookie (+19 more)

### Community 37 - "core/src/report.rs"
Cohesion: 0.11
Nodes (24): CONFIDENCES, defaults_match_burp_wizard_model(), EXTENSION_TYPE, FALSE_POSITIVE, html_extract_truncates_long_bodies_and_omit_hides_messages(), HTML_STYLE, issue(), issue_body_html() (+16 more)

### Community 38 - "entry"
Cohesion: 0.17
Nodes (28): add_passive_issues(), binary_bodies_are_ignored_entirely(), cacheable_https_response_needs_a_sensitive_body(), clean(), clean_https_response_produces_no_issues(), cookie_flags_are_checked_individually(), cors_wildcard_null_and_reflection_with_credentials(), cross_host_redirect_carrying_a_session_cookie() (+20 more)

### Community 39 - "recovery.rs"
Cohesion: 0.16
Nodes (23): backup_and_temporary_paths_never_hit_the_project_file(), backup_path(), begin(), clean_start_writes_marker_and_clean_exit_removes_it(), crash_without_project_file_or_with_garbage_marker(), decide(), leftover_marker_from_dead_process_means_recover(), live_owner_is_another_instance_and_keeps_its_marker() (+15 more)

### Community 40 - "analysis.rs"
Cohesion: 0.13
Nodes (22): analyze_tokens(), case_insensitive_excerpt_survives_lowercase_expansion(), close(), empty_token_input_has_zero_stats(), EXCERPT_AFTER, EXCERPT_BEFORE, find_excerpt(), hirschberg_recursion() (+14 more)

### Community 41 - "DnsCapture"
Cohesion: 0.13
Nodes (3): dns_loop(), DnsCapture, HttpCapture

### Community 42 - "interactsh.rs"
Cohesion: 0.13
Nodes (15): B64, CID_LEN, decrypt_messages(), decrypts_interactsh_messages(), DEFAULT_SERVERS, https_request(), live_round_trip_on_public_server(), live_smtp_recipient_forms() (+7 more)

### Community 43 - "RepTab"
Cohesion: 0.13
Nodes (25): RepTab, apply_tab_command(), close_tabs(), ClosedTab, CloseWhich, Left, Others, Right (+17 more)

### Community 44 - "ProjectData"
Cohesion: 0.10
Nodes (22): apply_settings(), default_listener_port(), ProjectData, ProjectEditors, ProjectIntruder, ProjectIntruderResult, ProjectLayout, ProjectListener (+14 more)

### Community 45 - "PayloadSource"
Cohesion: 0.09
Nodes (22): illegal(), illegal_unicode_follows_burps_encoding_table(), new_types_sit_at_their_burp_positions(), PayloadSource, BitFlipper, BruteForcer, CaseModification, CharacterBlocks (+14 more)

### Community 46 - "util.rs"
Cohesion: 0.11
Nodes (17): absolute_form_becomes_origin_form(), adler32(), B64, crc32(), duplicate_headers_are_preserved(), encode_png(), find_head_end(), find_sub() (+9 more)

### Community 47 - "main.rs"
Cohesion: 0.14
Nodes (14): autosave_enabled(), autosave_signature(), main(), mirror_appends_new_rows_in_history_order(), mirror_assigns_monotonic_ids_and_copies_fields(), mirror_history(), mirror_respects_the_logger_cap(), mirror_skips_ids_below_seen_and_advances_past_gaps() (+6 more)

### Community 48 - "intruder_ui.rs"
Cohesion: 0.18
Nodes (19): base_choice(), effective_sources(), ExtractForm, format_choice(), heading(), intern(), IntruderExtra, is_running() (+11 more)

### Community 49 - "cookie_jar.rs"
Cohesion: 0.16
Nodes (16): apply_updates_known_cookies_and_appends_the_rest(), bare_host(), Cookie, CookieJar, default_path(), defaults_follow_burp(), domain_attribute_must_cover_the_setting_host(), domain_matches() (+8 more)

### Community 50 - "upstream.rs"
Cohesion: 0.15
Nodes (22): CONNECT_TIMEOUT_MS, DNS_TIMEOUT_MS, READ_TIMEOUT_MS, absolute_form_request(), connect_socket(), connect_target(), connect_tls_target(), http_proxy_connect_rejects_407() (+14 more)

### Community 51 - "passive_issues"
Cohesion: 0.09
Nodes (24): attr_value(), body_slice(), burp_sniff_unknown(), burp_tld_set(), card_prefix_ok(), CookieParts, find_card(), find_email() (+16 more)

### Community 52 - "editor.rs"
Cohesion: 0.17
Nodes (16): apply_font_size(), body_colour(), EditorState, hex_decode(), hex_dump(), hex_dump_shows_offsets_and_ascii(), hex_encode(), hex_round_trips_through_the_editor_buffer() (+8 more)

### Community 53 - "xss.rs"
Cohesion: 0.14
Nodes (19): text(), has(), at(), attr_context(), classify(), EVENT_HANDLERS, is_event_handler(), is_script_url_attr() (+11 more)

### Community 54 - "seq_bits.rs"
Cohesion: 0.17
Nodes (21): analyze(), bit_columns(), BitReport, BitResult, counters_rate_extremely_poor_and_small_samples_are_refused(), erfc(), exports_list_every_bit_and_tokens_round_trip(), LEVEL_LABELS (+13 more)

### Community 55 - "Service"
Cohesion: 0.14
Nodes (18): can_follow(), current_tab(), follow_stops_and_the_button_continues_from_the_last_hop(), FollowResult, is_hostname(), load_redirect(), next_redirect(), paste_url_as_request() (+10 more)

### Community 56 - "codec.rs"
Cohesion: 0.15
Nodes (14): at(), body_complete(), brotli_decode(), chunked_body_of_four_mib(), chunked_single_and_multi(), chunked_with_trailers(), decode_chunked(), decode_content() (+6 more)

### Community 57 - "Processor"
Cohesion: 0.10
Nodes (22): pipeline_order_is_respected(), prefix_and_suffix_wrap_the_payload(), process_set_drops_skipped_payloads(), Processor, AddPrefix, AddSuffix, Base64Decode, Base64Encode (+14 more)

### Community 59 - "project.rs"
Cohesion: 0.13
Nodes (13): Appearance, default_density(), default_font_scale(), default_palette(), MIN_PROJECT_VERSION, PROJECT_MAGIC, PROJECT_VERSION, ProjectCollaborator (+5 more)

### Community 60 - "temporary_project"
Cohesion: 0.22
Nodes (21): expect_error(), large_history_round_trips(), load(), load_accepts_legacy_bare_json(), load_accepts_older_header_version(), load_rejects_malformed_json(), load_rejects_newer_version(), load_rejects_truncated_file() (+13 more)

### Community 61 - "ReportIssue"
Cohesion: 0.20
Nodes (18): bar_chart_html(), body_html(), Evidence, export_time(), html_has_summary_contents_and_escaped_evidence(), html_report(), html_toc_levels_and_organization(), number() (+10 more)

### Community 62 - "egui"
Cohesion: 0.12
Nodes (13): MessageMode, Extract, Full, Omit, ReportFormat, Html, Xml, default_report_path() (+5 more)

### Community 63 - "apply_as"
Cohesion: 0.13
Nodes (9): apply_as(), Density, Comfortable, Compact, Palette, Dark, HighContrast, Light (+1 more)

### Community 64 - "fuzz_tests.rs"
Cohesion: 0.16
Nodes (7): h2_frames(), Hostile, mutate(), NASTY, parsers_survive_random_and_mutated_input(), Rng, seeds()

### Community 65 - "Organizer"
Cohesion: 0.19
Nodes (9): add_and_get(), ids_stay_stable_after_removal(), list_is_sorted_by_id(), org(), Organizer, OrganizerItem, remove_reports_success(), rename_and_set_note() (+1 more)

### Community 66 - "start_active_scan"
Cohesion: 0.14
Nodes (19): active_scan_finds_stored_xss_and_cookie_xss_on_a_local_server(), active_scan_reports_traversal_against_a_vulnerable_server(), audit_entries(), characterisation_active_scan_issue_list(), characterisation_server(), check_catalogue(), collaborator_pending_issues_carry_their_probe(), crawl_and_audit() (+11 more)

### Community 67 - "onboarding.rs"
Cohesion: 0.18
Nodes (16): local_response(), SETUP_HOSTS, setup_page(), ca_downloads_have_the_right_content_type(), Check, checks(), export_ca(), is_real() (+8 more)

### Community 68 - "App"
Cohesion: 0.16
Nodes (17): App, cancel_abandons_the_in_flight_send(), cancel_repeater_send(), current_repeater(), cycle_tab(), dec_add(), dec_result(), repeater() (+9 more)

### Community 69 - "RepAction"
Cohesion: 0.10
Nodes (20): RepAction, ActiveScan, BothToComparer, ChangeMethod, CompareRequestWithPrevious, CompareWithPrevious, CopyCurl, CopyPython (+12 more)

### Community 70 - "Color32"
Cohesion: 0.19
Nodes (18): chrome(), chrome_alt(), editor_ink(), header_bg(), header_ink(), ink(), ink_dim(), ink_faint() (+10 more)

### Community 71 - "Tab"
Cohesion: 0.10
Nodes (20): TAB_NAMES, Tab, BurpAi, Collaborator, Comparer, Dashboard, Decoder, Discover (+12 more)

### Community 73 - "Mutex"
Cohesion: 0.19
Nodes (7): QUEUE, QUEUE_MAX, set_waker(), WAKER, a_panic_while_holding_the_lock_does_not_poison_it(), Mutex, Mutex<T>

### Community 74 - "parse_dns_query"
Cohesion: 0.18
Nodes (15): build_dns_response(), decode_chunked_body(), dns_non_a_query_gets_no_answer(), dns_query(), dns_query_parses_and_a_query_gets_loopback_answer(), DnsParseError, Incomplete, Malformed (+7 more)

### Community 75 - "intercept_ws_stream"
Cohesion: 0.16
Nodes (16): build_ws_frame(), build_ws_frame_roundtrips_through_parse(), intercept_ws_stream(), InterceptItem, InterceptKind, Request, parse_ws_frame(), relay_ws() (+8 more)

### Community 76 - "run_open_redirect_check"
Cohesion: 0.14
Nodes (18): crawl_links(), crawl_links_resolve_same_origin_paths(), header_injection_follows_burp_zwi(), HeaderInjectionHit, js_redirect_at(), link_targets(), LinkManipHit, open_redirect_follows_burp_zuag() (+10 more)

### Community 77 - "Tok"
Cohesion: 0.21
Nodes (12): html_attributes(), is_header_close(), is_header_open(), parse_attrs(), Tok, Comment, End, SelfClose (+4 more)

### Community 78 - "FollowMode"
Cohesion: 0.14
Nodes (15): burp_in_scope(), FollowMode, .ALL, Always, InScope, Never, OnSite, intercept_options_menu() (+7 more)

### Community 79 - "proxy_history"
Cohesion: 0.17
Nodes (18): a_sort_sees_the_whole_history(), bulk_history_command(), csrf_poc_html(), csrf_poc_replays_the_body(), curl_command_of(), detail(), entry(), history_new_rows() (+10 more)

### Community 80 - "analysis_ui.rs"
Cohesion: 0.23
Nodes (11): ComparerState, byte_label(), compare_row_colors(), hint(), line_label(), number(), show_bit_report(), show_comparer() (+3 more)

### Community 81 - "intercept_rules.rs"
Cohesion: 0.21
Nodes (13): defaults(), defaults_hold_everything_except_static_file_types(), extension_of(), Facts, facts(), InterceptRule, Operator, And (+5 more)

### Community 82 - ".generate"
Cohesion: 0.18
Nodes (12): bit_flips(), case_forms(), custom_iterations(), date_run(), ecb_shuffles(), hex_pair(), latin1_bytes(), number_run() (+4 more)

### Community 83 - "super"
Cohesion: 0.20
Nodes (13): extract_value(), normalise(), parse(), plain_text_is_one_step_and_marked_text_splits(), prepare(), prepare_derives_from_the_previous_response_only(), recorded_steps_round_trip_through_the_text_form(), replace_pair() (+5 more)

### Community 84 - "menus.rs"
Cohesion: 0.20
Nodes (11): copy_path(), help_menu(), intruder_menu(), intruder_request_to_repeater(), IntruderPrefs, off(), project_window(), project_window_id() (+3 more)

### Community 85 - "ai.rs"
Cohesion: 0.23
Nodes (10): AiChat, body_and_reply_round_trip(), chat_against_a_local_server(), ChatMsg, complete(), explain_prompt(), live_model_explains_an_exchange(), parse_reply() (+2 more)

### Community 86 - "InteractionLog"
Cohesion: 0.18
Nodes (4): CaptureShared, Interaction, InteractionLog, lock()

### Community 88 - "HistEntry"
Cohesion: 0.20
Nodes (8): auditable(), crawl_single(), referenced_static(), burp_mime(), burp_mime_of(), HistEntry, entry(), HistoryFilter

### Community 89 - ".run"
Cohesion: 0.14
Nodes (7): check_issue_names_resolve_to_burp_types(), CsrfTokenNotEnforced, registry_order_is_pinned(), request_body(), request_ct(), run_request_checks(), ServerOptions

### Community 90 - "MontoyaBridge"
Cohesion: 0.25
Nodes (4): FactoryStub, MontoyaBridge, MsgState, MsgStub

### Community 91 - "history_filter.rs"
Cohesion: 0.23
Nodes (10): burp_default_filter_hides_css_images_and_listed_extensions(), DEFAULT_HIDE_EXT, entry(), in_scope_uses_the_shared_scope_list(), method_and_status_filters_match_substrings(), mime_filter_matches_the_essence_not_the_parameters(), mime_is_taken_from_the_recorded_response(), shared() (+2 more)

### Community 92 - "browser_crawl"
Cohesion: 0.25
Nodes (7): browser_crawl(), Cdp, chromium_binary(), eval_json(), http_get_local(), live_browser_crawl_debug(), WebSocket

### Community 93 - "build_report_issues"
Cohesion: 0.21
Nodes (9): build_attaches_latest_matching_history_entry(), build_report_issues(), confidence_index(), KbEntry, knowledge_base_parses_burp_entries_and_falls_back(), KnowledgeBase, link_list(), select_issues() (+1 more)

### Community 94 - "InteractionDetail"
Cohesion: 0.21
Nodes (9): dns_qtype_from_label(), HttpInteraction, InteractionDetail, Dns, Http, Smtp, remote_detail(), SmtpInteraction (+1 more)

### Community 95 - "collaborator_ui.rs"
Cohesion: 0.35
Nodes (11): MAX_INTERACTIONS, dns_details(), error_label(), format_clock(), hint(), http_details(), listener_notes(), settings_panel() (+3 more)

### Community 96 - "Kind"
Cohesion: 0.15
Nodes (10): Kind, .ALL, AnyHeader, Body, DomainName, FileExtension, HasParameters, HttpMethod (+2 more)

### Community 97 - "requests"
Cohesion: 0.19
Nodes (13): bad_input_is_reported_not_swallowed(), battering_ram_puts_one_payload_everywhere(), cluster_bomb_tries_every_combination_last_position_fastest(), parse_splits_positions_and_render_strips_markers(), pitchfork_walks_in_lock_step_and_stops_at_the_shortest_set(), process_set(), processed_sets_feed_the_attack_matrix(), requests() (+5 more)

### Community 98 - ".run"
Cohesion: 0.18
Nodes (9): bump_progress(), burp_send(), origin_of(), Settings, get_request_like(), openapi_hosts(), same_origin_path(), SmtpOob (+1 more)

### Community 99 - "variations.rs"
Cohesion: 0.19
Nodes (9): ALL, Crc, crc_matches_java_char_semantics(), crc_of(), differential_needs_consistent_separation(), fingerprint_reads_burp_attributes(), HEADER_TAGS, java_space() (+1 more)

### Community 100 - "fingerprint"
Cohesion: 0.40
Nodes (6): Comparator, comparator_follows_zr2x_rules(), differential(), fingerprint(), get(), Side

### Community 101 - "history_and_issues_convert_both_ways"
Cohesion: 0.21
Nodes (7): binary_messages_round_trip_exactly(), decode_message(), encode_message(), history_and_issues_convert_both_ways(), ProjectEvidence, ProjectHistory, ProjectIssue

### Community 102 - "SqlBoolGen"
Cohesion: 0.23
Nodes (7): sql_boolean_payloads_match_burp_zguq(), SqlBoolGen, SqlBoolShape, And, AndComment, Or, OrComment

### Community 103 - "Mechanics sheet — WebProbe (rebuild of Burp Suite Pro build 52685)"
Cohesion: 0.15
Nodes (12): Behavior notes, Current Deep-mode verification pass, Custom / simplified in this rebuild, Deep decompilation — live build 52685, Mechanics sheet — WebProbe (rebuild of Burp Suite Pro build 52685), Proxy / connections (source: `resources/Preferences/ProjectDefaults.json`, montoya API sources), Reference library cross-check (/root/burp-re, deobfuscated build 2026.7.1 / 51467; live target 52685), Scanner (sources: `resources/Preferences/AuditDefaults.json`, `resources/Preferences/CrawlDefaults.json`, `resources/Preferences/LivePassiveCrawlDefaults.json`, bundled montoya API sources) (+4 more)

### Community 104 - "http_loop"
Cohesion: 0.20
Nodes (8): http_loop(), InteractionKind, Dns, Http, Smtp, ParsedHttpRequest, read_http_request(), write_http_response()

### Community 105 - "csrf_static_token_hit"
Cohesion: 0.17
Nodes (10): blank_csrf_params(), blank_csrf_params_keeps_names_and_empties_values(), csrf_applicable(), csrf_static_token_hit(), form_token_value(), is_csrf_token_param(), planned_progress(), StaticTokenHit (+2 more)

### Community 107 - "gl_env.rs"
Cohesion: 0.41
Nodes (11): a_render_node_keeps_the_hardware_path(), apply(), env(), explicit_user_choice_wins(), has_render_node(), indirect_glx_is_always_dropped(), native_opt_out_skips_every_edit(), Plan (+3 more)

### Community 108 - "response_body_kind"
Cohesion: 0.20
Nodes (9): BodyKind, Chunked, Length, None, UntilEof, header_values(), normalize_request(), read_message() (+1 more)

### Community 109 - "listener_worker"
Cohesion: 0.27
Nodes (10): extra_listener_serves_traffic(), free_port(), listener_redirect_and_non_proxy_style_requests(), listener_specs(), listener_worker(), ListenerSpec, ListenerState, set_listeners() (+2 more)

### Community 110 - "ScanEvidence"
Cohesion: 0.29
Nodes (4): evidence(), Recorder, recorder_picks_probe_and_control(), ScanEvidence

### Community 111 - "proxy_settings.rs"
Cohesion: 0.36
Nodes (6): ca_buttons(), cell(), heading(), intercept_rules_table(), listeners_table(), parse_target()

### Community 112 - "webprobe-headless.rs"
Cohesion: 0.42
Nodes (8): issue_json(), main(), proxy(), save_project(), scan_urls(), take_flag(), take_opt(), usage()

### Community 113 - "DiffKind"
Cohesion: 0.24
Nodes (9): added_row(), CompareRow, diff_line_rows(), DiffKind, Added, Changed, Removed, Same (+1 more)

### Community 114 - "ExtractItem"
Cohesion: 0.33
Nodes (8): ExtractEnd, Delimiter, Length, ExtractItem, ExtractStart, After, Offset, grep_extract_follows_burps_delimiter_and_regex_rules()

### Community 115 - "decode"
Cohesion: 0.25
Nodes (9): check_supported(), decode(), document_bytes(), export_and_import_json_round_trip(), export_json(), header_line(), import_json(), pre_j01_file_loads_with_defaults_for_new_sections() (+1 more)

### Community 116 - "appearance"
Cohesion: 0.31
Nodes (7): appearance(), apply(), apply_current(), every_glyph_the_ui_prints_can_be_drawn(), install_fonts(), missing(), window_pos()

### Community 117 - "apply_action"
Cohesion: 0.22
Nodes (8): apply_action(), curl_command(), curl_command_matches_burp_shape(), previous_request(), previous_response(), python_requests(), python_script_repeats_the_request(), request_url()

### Community 119 - "SequencerReport"
Cohesion: 0.38
Nodes (7): analyze_sequence(), chi_square_survival(), chi_square_uniform(), ChiSquareStats, numeric_stats(), NumericStats, SequencerReport

### Community 120 - "Accuracy"
Cohesion: 0.29
Nodes (5): xml_injection_rounds(), Accuracy, MinimizeFalseNegatives, MinimizeFalsePositives, Normal

### Community 122 - "a_headless_browser_leaves_no_processes_behind"
Cohesion: 0.40
Nodes (5): a_forking_child_is_ended_with_all_its_descendants(), a_headless_browser_leaves_no_processes_behind(), alive_with(), kill_process_tree(), own_process_group()

### Community 123 - "Organization"
Cohesion: 0.33
Nodes (5): Organization, .ALL, BySeverity, ByType, ByUrl

### Community 124 - "InsertionPoint"
Cohesion: 0.33
Nodes (3): run_point_checks(), XmlInjectionError, InsertionPoint

### Community 125 - "is_light"
Cohesion: 0.33
Nodes (6): editor_colours(), EditorColours, is_light(), issue_colour(), method_color(), status_color()

### Community 126 - "run_xml_injection_check"
Cohesion: 0.40
Nodes (3): run_xml_injection_check(), xml_injection_follows_zp7s(), xml_markers_in()

### Community 127 - "regularized_gamma_q"
Cohesion: 0.50
Nodes (5): gamma_continued_fraction(), gamma_series(), ln_gamma(), regularized_gamma_q(), poker()

### Community 128 - "NumberBase"
Cohesion: 0.50
Nodes (4): format_number(), NumberBase, Decimal, Hex

### Community 129 - "ProjectCookieJar"
Cohesion: 0.40
Nodes (3): cookie_jar_round_trips_and_old_files_get_the_default_jar(), ProjectCookie, ProjectCookieJar

### Community 130 - "run_ssi_check"
Cohesion: 0.40
Nodes (5): run_ssi_check(), ssi_check_detects_processed_directives(), ssi_payload(), ssi_shift(), SsiHit

### Community 131 - "run_ssti_check"
Cohesion: 0.40
Nodes (5): run_ssti_check(), ssti_check_detects_evaluation_not_echo(), ssti_probes(), SstiHit, SstiProbe

### Community 134 - ".for_palette"
Cohesion: 0.50
Nodes (3): dark_tokens_equal_the_legacy_constants(), light_text_is_dark_on_light_surfaces(), light_tokens_differ_from_dark_where_the_ui_flips()

## Knowledge Gaps
- **255 isolated node(s):** `webprobe`, `webprobe-core`, `Same`, `Added`, `Removed` (+250 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 893 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `App` connect `App` to `discovery.rs`, `shortcuts.rs`, `find_window`, `ui.rs`, `msgpane.rs`, `tools.rs`, `decoder_ops.rs`, `Shared`, `table.rs`, `logger.rs`, `settings_dialog.rs`, `ScanIssue`, `AttackType`, `feedback.rs`, `engagement.rs`, `recovery.rs`, `analysis.rs`, `RepTab`, `PayloadSource`, `main.rs`, `intruder_ui.rs`, `editor.rs`, `seq_bits.rs`, `Service`, `egui`, `Organizer`, `onboarding.rs`, `Tab`, `Mutex`, `FollowMode`, `proxy_history`, `analysis_ui.rs`, `menus.rs`, `ai.rs`, `CollaboratorState`, `HistEntry`, `proxy_settings.rs`, `apply_action`, `SequencerReport`?**
  _High betweenness centrality (0.119) - this node is a cross-community bridge._
- **Are the 54 inferred relationships involving `c()` (e.g. with `compare_row_colors()` and `hint()`) actually correct?**
  _`c()` has 54 INFERRED edges - model-reasoned connections that need verification._
- **What connects `webprobe`, `webprobe-core`, `Same` to the rest of the system?**
  _255 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `scan.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.026450361488273674 - nodes in this community are weakly interconnected._
- **Why does `Shared` connect `Shared` to `scan.rs`, `tls.rs`, `intruder_run.rs`, `rules.rs`, `ext_host.rs`, `ScanCtx`, `tools.rs`, `.new`, `repeater_ops.rs`, `net.rs`, `UpstreamConn`, `ScanIssue`, `TcpStream`, `crawl.rs`, `entry`, `RepTab`, `cookie_jar.rs`, `upstream.rs`, `Service`, `start_active_scan`, `onboarding.rs`, `App`, `Mutex`, `intercept_ws_stream`, `FollowMode`, `intercept_rules.rs`, `ai.rs`, `HistEntry`, `history_filter.rs`, `browser_crawl`, `.run`, `csrf_static_token_hit`, `listener_worker`, `webprobe-headless.rs`, `btreeset`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Should `burp_checks.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.05837837837837838 - nodes in this community are weakly interconnected._
- **Why does `Mutex` connect `Mutex` to `.run`, `tls.rs`, `discovery.rs`, `App`, `intruder_run.rs`, `ui.rs`, `ext_host.rs`, `listener_worker`, `main.rs`, `intruder_ui.rs`, `ai.rs`, `InteractionLog`, `collaborator.rs`, `net.rs`, `Shared`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
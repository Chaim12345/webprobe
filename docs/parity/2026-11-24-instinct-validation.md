# Investigation report

**Question:** Validate the Instinct-agent work that landed in WebProbe and reconcile the roadmap/task ledger with the shipped code.

**Purpose:** Close out the 2026-11-24 integration with evidence, and leave Craft's project memory current for the next session.

**Done when:** Task ledger and roadmap notes match merged parity 6a3b1c9; Instinct features validated in tests and in the built binary; Craft handoff written.

## What we looked at

- `app/target/debug/webprobe` (ELF x86_64, sha256 `da6859a20246178a32ab97d3d1d882d662338f2208c9cf28ddb460abdf5bc97c`)
- /root/Documents/Craft Anything/burpsuite
- /root/Documents/Craft Anything/burpsuite/app/target/debug/webprobe
- https://github.com/Chaim12345/webprobe

## What we found

### The refreshed webprobe artifact exposes the /v0.1/scan REST route (string plus a referencing function).

- **Confidence:** Worked it out (derived)
- **Evidence:**
  - `ev_131b6713361c6689e6222afda4e2f07a52feda9b40646a874f249242f2ad5303` — "/v0.1/scan/": 1 matching strings, 0 matching function names, 0 matching imports; 1 functions involved. (address=0x23380c0)

### The refreshed artifact contains the client-side prototype-pollution check (5 strings, 25 referencing functions).

- **Confidence:** Worked it out (derived)
- **Evidence:**
  - `ev_1b70e874031fe7433b7a6fbdba89ed6ad4a50002a1c65baedd396489ad301775` — "Client-side prototype pollution": 5 matching strings, 0 matching function names, 0 matching imports; 25 functions involved. (address=0x20d7a80, address=0x24aaf10, address=0x24acd70, address=0x24cc410, address=0x24cc840, address=0x24cc8c0, address=0x24cd310, address=0x24cd520, … +17 more)

### The refreshed artifact contains the Repeater send-group refusal path and group-mode code.

- **Confidence:** Worked it out (derived)
- **Evidence:**
  - `ev_5024eda74ecd84466aa73ec3ee68acb29f5f7498738dfa0602c3a934aec0ebaa` — "Send group refused": 1 matching strings, 0 matching function names, 0 matching imports; 0 functions involved.

### The refreshed artifact contains BCheck issue generation (3 strings, 24 referencing functions).

- **Confidence:** Worked it out (derived)
- **Evidence:**
  - `ev_50a0e770b6bcf016de7393a88fc0a1271f74088b064db3ec2a601cc7e016147d` — "BCheck generated issue": 3 matching strings, 0 matching function names, 0 matching imports; 24 functions involved. (address=0x24aaf10, address=0x24acd70, address=0x24cc410, address=0x24cc840, address=0x24cc8c0, address=0x24cd310, address=0x24cd520, address=0x24cdae0, … +16 more)

### The refreshed artifact contains the Flash/Silverlight cross-domain policy checks (3 strings, 22 referencing functions).

- **Confidence:** Worked it out (derived)
- **Evidence:**
  - `ev_a8873c6daa6ee0d20fe261313d310d3bdc34b928be03ddca4d2b1d3cfa19b618` — "Flash cross-domain policy": 3 matching strings, 0 matching function names, 0 matching imports; 22 functions involved. (address=0x24cc410, address=0x24cc840, address=0x24cc8c0, address=0x24cd310, address=0x24cd520, address=0x24cdae0, address=0x24ce230, address=0x24ce670, … +14 more)

### The refreshed TLS check reports the chain-validity wording from #206 rather than the old unparseable-leaf wording.

- **Confidence:** Worked it out (derived)
- **Evidence:**
  - `ev_36ced40481afbc00212c999366e100d20b084cd67c97388015979563abb3c191` — "certificate in the chain could not be identified": 1 matching strings, 0 matching function names, 0 matching imports; 0 functions involved.

## Open questions

- R-13 is not at 48/48 DOM types: stored-token submission is disabled and the coverage matrix lists uncovered sinks (jQuery.parseJSON/parseXML, document.URL/referrer/name, storage reads). Is closing that boundary required for Burp parity? _(severity Medium, Open)_

## How this was done

- **Mode:** Deep (the original's code and files could be read)
- **Engines:** builtin
- **Limitations:**
  - 8240 indirect jumps could not be resolved; code they reach may be missing
  - function discovery stopped after 50000 functions; the function list is incomplete and some code is not analysed
  - functions reached only through computed pointers or at run time may be missing; absence is not proof
  - nothing matched; the text may be built at run time, encrypted, or come from a resource file (absence is not proof)

## Handoff

Complete 2026-11-24. Parity is 6a3b1c9.
Merged: #203, #163, #181, #190, #205 (host probes #201, DOM #200, D-12/R-12 #192, Rust 2024/MSRV 1.95 #196), #206 (TLS chain validity), #207 (roadmap/task reconciliation), #208 (request-reader CI flake).
tasks.json is 120 done / 15 todo / 2 rejected. R-13 remains open by design: stored submission disabled and uncovered DOM sinks listed in docs/specs/R-13-dom-coverage-matrix.md.
Validation: scripts/ci.sh five gates green; cargo test --workspace 164 desktop + 1209 core passed, 15 ignored, 0 failed; clippy/fmt clean; hosted CI green on #205/#206/#207/#208 and on parity merge commits c74dc69 and 6a3b1c9, including core 1.95.0.
Craft target is the rebuilt app/target/debug/webprobe sha256 da6859a20246...; evidence ev_131b67 / ev_1b70e8 / ev_5024ed / ev_50a0e7 / ev_a8873c / ev_36ced4 confirm the merged features in the artifact.
No Instinct-authored TODO/unimplemented/FIXME markers found in the audited modules (send_group, url_payloads, sni, rest_api, burp_config, bcheck, dom, host_probe_state).
Remaining backlog: R-13 boundary, R-16, R-18/AR-01..AR-10, R-19, R-20. No open PRs; open issues are #173, #44, #41, #38, #36, #34.

## Evidence ledger

- `ev_0863b48b7a1137608eb0b82e41a5a47a2effeb5a7dbe4cb23b56186013052e98` **core_overview_show** — ELF (Linux, Android, BSD) executable for x86_64 with 50000 functions, 92504 strings, 200 imports from 4 libraries. Function discovery stopped at an analysis limit, so the function list is incomplete. (Worked it out)
- `ev_c26e3a36d24c3c4cff795dc5327127c266c96d30d7a1169b97a8c3dad2773d7d` **core_feature_find** — "/v0.1": 1 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_1e33a89ec52bb5d3b2bac52d29ae8f76860eb24f2014f018d30887d4dd9595ec` **core_feature_find** — "Client-side prototype pollution": 5 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_36b462195fee6836601bdac67128b442b0818ea9b5072985e95a35851c237bec` **core_feature_find** — "TLS certificate": 3 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_ef364902cf6a613bb3c08d8411ff0d75dbf1aa733f42e356998263f67658a4f0` **core_feature_find** — "Send group": 2 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_5b1d8a1cf95984d68c0a7ffd880604854461d5bcd9009baef000507e02796929` **core_feature_find** — "BCheck generated issue": 3 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_b587d9e06332a7c142a6ce35e1fd8977be318d2c95dd11306c0393459c213956` **core_feature_find** — "Flash cross-domain policy": 3 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_36ced40481afbc00212c999366e100d20b084cd67c97388015979563abb3c191` **core_feature_find** — "certificate in the chain could not be identified": 1 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_131b6713361c6689e6222afda4e2f07a52feda9b40646a874f249242f2ad5303` **core_feature_find** — "/v0.1/scan/": 1 matching strings, 0 matching function names, 0 matching imports; 1 functions involved. (Worked it out)
- `ev_1b70e874031fe7433b7a6fbdba89ed6ad4a50002a1c65baedd396489ad301775` **core_feature_find** — "Client-side prototype pollution": 5 matching strings, 0 matching function names, 0 matching imports; 25 functions involved. (Worked it out)
- `ev_5024eda74ecd84466aa73ec3ee68acb29f5f7498738dfa0602c3a934aec0ebaa` **core_feature_find** — "Send group refused": 1 matching strings, 0 matching function names, 0 matching imports; 0 functions involved. (Worked it out)
- `ev_50a0e770b6bcf016de7393a88fc0a1271f74088b064db3ec2a601cc7e016147d` **core_feature_find** — "BCheck generated issue": 3 matching strings, 0 matching function names, 0 matching imports; 24 functions involved. (Worked it out)
- `ev_a8873c6daa6ee0d20fe261313d310d3bdc34b928be03ddca4d2b1d3cfa19b618` **core_feature_find** — "Flash cross-domain policy": 3 matching strings, 0 matching function names, 0 matching imports; 22 functions involved. (Worked it out)


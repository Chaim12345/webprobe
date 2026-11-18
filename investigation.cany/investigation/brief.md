# Brief

**Question:** Rebuild WebProbe, a clone of Burp Suite Pro (reference build 52685, v2026.7.3), to feature parity with the task backlog in tasks.json, and produce a readable, evidence-backed name map for the obfuscated Burp jar.

**Purpose:** Interoperable reimplementation plus per-build deobfuscation; behaviour claims must come from the shipped jar or the running reference app, never guessed.

**Targets:**
- /opt/BurpSuite/burpsuite.jar
- /root/Documents/Craft Anything/burpsuite/app

**Constraints:**
- Test ports are 6566 (WebProbe proxy), 6567 (collaborator) and 6570 (reference Burp); 8080/8081 belong to a working tool and must never be bound or killed
- Visual QA drives live windows on Xvfb (qa/qa.sh on :97, reference Burp on :98) with a multimodal subagent pinned to kilo/nvidia/nemotron-3.5-super-vl:free; no OCR
- No rebuild or cargo test while a QA agent is mid-run, so the binary stays stable
- Free models only for the builder; all work git-tracked; never touch ~/.zshrc or the user's real Burp config

**Done when:** Every task in tasks.json (125 on 2026-11-18: 101 done, 2 rejected, 22 todo = D-09..D-11 and roadmap R-01..R-19) is done or explicitly rejected with status+evidence+date, no open unknowns, mechanics.json claims updated, full test suite and scripts/ci.sh green, and re/mapping covers every class that has evidence in the current build.

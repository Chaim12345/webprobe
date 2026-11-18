# Burp parity scores (MiniMax M3.1 Flash / Nemotron VL), 2026-11-15

> **Superseded (2026-11-18).** This report is a dated snapshot and is no longer the statement of where the project stands. Current status: `tasks.json` and `qa/ZOOM-OUT-REVIEW-2026-11-18.md`.


Each WebProbe screen scored against its Burp counterpart, 5 categories x 10, total /50.

| Screen | Layout | Key area | Views/controls | Inspector/target | Clarity | Total |
|---|---:|---:|---:|---:|---:|---:|
| Proxy HTTP history | 6 | 7 (columns) | 7 (filter) | 3 (message pane) | 6 | **29/50** |
| Repeater (pre-rewrite) | 6 | 5 (toolbar) | 8 (views) | 3 (inspector) | 8 | **30/50** |
| Intruder | 6 | 8 (attack config) | 8 (positions/sets) | 7 (results) | 6 | **35/50** |
| Dashboard (pre-rewrite) | 3 | 1 (task/issue) | 5 (chrome) | 3 (density) | 5 | **17/50** |

## Biggest gaps called out
- **History:** the message pane reads as an empty placeholder (false positive: `detail()` renders on selection); table should match Burp's denser schema; more base font/row height.
- **Repeater:** no dedicated right Inspector pane, no Cancel/navigation/target, stacked panes instead of three columns. (Addressed by the three-pane rewrite; needs re-score.)
- **Intruder:** single dense column, no onboarding empty state, accent overused.
- **Dashboard:** no task list/issue table/task configuration; long plain-text sections; wasted viewport. (Addressed by the task/issue rewrite; needs re-score.)

## Re-scores pending
Repeater and Dashboard were rewritten after these reviews (three-pane Repeater; task+issue Dashboard). Re-score against the new captures in /root/webprobe-shots/tour/.

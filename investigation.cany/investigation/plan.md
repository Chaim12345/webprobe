# Plan

1. [done] Visual bridge pass: horizontal Repeater/Intruder panes, menu bar, Proxy sub-tab names — Editor zero-width bug came from inherited horizontal layout; fixed at root and verified in v8-repeater.png / v8-intruder.png.
2. [todo] Light-palette token pass + remaining chrome — Panel fills are hardcoded MONO1/MONO1X, so View > Light theme is mixed; menu items and right-side globals still differ from Burp.
3. [todo] Structural tool gaps: Logger/Organizer/Discover, Proxy Match and replace, Dashboard and Intruder sub-tabs — Largest remaining parity gap after chrome; WebProbe currently substitutes Scanner/Sessions/Search.
4. [done] Engine done + verified: Logger (app/src/logger.rs) — fnd_8; logger.rs L12/16-29/114-158 + 8 tests L167-293; engine only, no Logger UI tab.
5. [done] Engine done + verified: Organizer (app/src/organizer.rs) — fnd_9; organizer.rs L8-15/24-99 + 6 tests L110-188; engine only, no Organizer UI panel.
6. [done] Engine done + verified: Match and Replace (app/src/match_replace.rs) — fnd_10; match_replace.rs L16-48/71-121 + 10 tests L123-250; net.rs still uses legacy rules.rs::apply_rules.
7. [done] Engine done + verified: Project .burp save/load (app/src/project.rs) — fnd_11; project.rs L25/29/33/383-386/401-447/450-535 + 15 tests; round_trip_preserves_every_field L749-763; Burp byte-format parity unverified.

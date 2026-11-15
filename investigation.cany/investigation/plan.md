# Plan

1. [doing] Close the 16 recorded parity gaps in priority order — Logger, project save/load, HTTP/2, Match&Replace and session auth are the blocking gaps; the build is NOT feature-complete
2. [todo] Re-verify the 62 mechanics values against decompiled functions — mechanics.json says 62 sourced / 0 estimated, but whole tools are missing, so some sources are suspect
3. [done] Keep the existing rebuild green (build, screenshot, mechanics) — all 3 checks pass, 13/13 claims hold
4. [todo] Implement Logger, then project save/load — highest-severity missing features
5. [todo] Add HTTP/2 to the proxy — modern sites break without it

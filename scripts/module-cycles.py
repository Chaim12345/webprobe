#!/usr/bin/env python3
"""List strongly connected components of webprobe-core's `crate::` module imports
(non-test code only). Usage: python3 scripts/module-cycles.py  (run from the repo root).
Used by docs/adr/0001-architecture-hardening-and-crate-split.md; a crate boundary cannot contain a cycle."""
import glob, os, re, sys
sys.setrecursionlimit(10000)
SRC = os.path.join(os.path.dirname(__file__), "..", "app", "core", "src")
mods = [os.path.basename(f)[:-3] for f in glob.glob(os.path.join(SRC, "*.rs")) if not f.endswith("lib.rs")]
is_test = lambda m: m.endswith("_tests") or m == "fuzz_tests"
deps = {}
for m in mods:
    s = open(os.path.join(SRC, m + ".rs")).read()
    if not is_test(m):
        s = s.split("#[cfg(test)]")[0]
    d = set(re.findall(r"crate::([a-z0-9_]+)", s)) & set(mods)
    d.discard(m)
    deps[m] = d
idx, low, stack, on, out, n = {}, {}, [], set(), [], [0]
def visit(v):
    idx[v] = low[v] = n[0]; n[0] += 1; stack.append(v); on.add(v)
    for w in deps[v]:
        if w not in idx:
            visit(w); low[v] = min(low[v], low[w])
        elif w in on:
            low[v] = min(low[v], idx[w])
    if low[v] == idx[v]:
        comp = []
        while True:
            w = stack.pop(); on.discard(w); comp.append(w)
            if w == v: break
        out.append(sorted(comp))
for m in sorted(mods):
    if m not in idx: visit(m)
for c in out:
    if len(c) > 1:
        print(f"cycle of {len(c)} modules: {', '.join(c)}")
print("no cycles" if not any(len(c) > 1 for c in out) else "")

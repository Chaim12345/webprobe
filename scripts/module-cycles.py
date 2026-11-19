#!/usr/bin/env python3
"""Non-test crate:: import graph of webprobe-core: strongly connected
components (Tarjan). Usage: python3 scripts/module-cycles.py [core/src].
Submodules fold into their top-level module (net/x.rs -> net)."""
import os, re, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "app/core/src"

def strip_tests(text):
    # Drop cfg(test) items: from the attribute line to the item's closing brace.
    out, i, n = [], 0, len(text)
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith("#[cfg(test)]"):
            # find the opening brace of the item and skip to its match
            depth, started = 0, False
            i += 1
            while i < len(lines):
                for ch in lines[i]:
                    if ch == "{":
                        depth += 1; started = True
                    elif ch == "}":
                        depth -= 1
                i += 1
                if started and depth == 0:
                    break
            continue
        out.append(lines[i]); i += 1
    return "\n".join(out)

def top_module(path):
    rel = os.path.relpath(path, ROOT)
    parts = rel.split(os.sep)
    name = parts[0]
    if name.endswith(".rs"):
        return name[:-3]
    return name  # net/ -> net, scan/ -> scan, scan_checks/ -> scan_checks

mods = {}
for dirpath, _, files in os.walk(ROOT):
    for f in files:
        if f.endswith(".rs"):
            m = top_module(os.path.join(dirpath, f))
            if m in ("bin",):
                continue
            mods.setdefault(m, []).append(os.path.join(dirpath, f))

# scan_checks is `checks` under scan
edges = {m: set() for m in mods}
ref = re.compile(r"crate::([a-z_0-9]+)")
alias = {"checks": "scan", "scan_checks": "scan"}
for m, files in mods.items():
    src = alias.get(m, m)
    for f in files:
        text = strip_tests(open(f).read())
        for hit in ref.findall(text):
            dst = alias.get(hit, hit)
            if dst != src and dst in mods or dst == "scan" and src != "scan":
                edges.setdefault(src, set()).add(dst)

# fold scan_checks into scan node
if "scan_checks" in edges:
    edges.setdefault("scan", set()).update(x for x in edges.pop("scan_checks") if x != "scan")
for m in edges:
    edges[m].discard("scan_checks")

# Tarjan SCC
index, low, onstack, stack, sccs, counter = {}, {}, set(), [], [], [0]
def strongconnect(v):
    index[v] = low[v] = counter[0]; counter[0] += 1
    stack.append(v); onstack.add(v)
    for w in edges.get(v, ()):
        if w not in edges: continue
        if w not in index:
            strongconnect(w); low[v] = min(low[v], low[w])
        elif w in onstack:
            low[v] = min(low[v], index[w])
    if low[v] == index[v]:
        scc = []
        while True:
            w = stack.pop(); onstack.discard(w); scc.append(w)
            if w == v: break
        sccs.append(scc)

sys.setrecursionlimit(10000)
for v in sorted(edges):
    if v not in index:
        strongconnect(v)

big = sorted((s for s in sccs if len(s) > 1), key=len, reverse=True)
print(f"modules: {len(edges)}")
for s in big:
    print(f"SCC size {len(s)}: {', '.join(sorted(s))}")
if not big:
    print("no cycles")

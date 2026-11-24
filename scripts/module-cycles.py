#!/usr/bin/env python3
"""Non-test `crate::` import graph of webprobe-core and its strongly
connected components (Tarjan).

Usage: python3 scripts/module-cycles.py [core/src] [--json]

Submodules fold into their top-level module (net/x.rs -> net). A file that
another module mounts with `#[path = "../x.rs"]` belongs to that module.
Exits 2 when no module is found, so a wrong path cannot read as "no cycles".
scripts/arch-gate.py compares the result with the committed baseline.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.join(HERE, "..", "app", "core", "src")
CFG_TEST = "#[cfg(test)]"


ITEM_WORDS = {"mod", "fn", "use", "impl", "struct", "enum", "union", "type", "trait",
              "static", "const", "extern", "macro_rules", "thread_local"}
_HEAD = re.compile(r'(?:pub(?:\([^)]*\))?\s+)?(?:(?:unsafe|async|default)\s+)*([A-Za-z_][A-Za-z_0-9]*)')


def _skip_literal(text, k):
    """If a comment, string or char literal starts at k, the index after it;
    otherwise k."""
    two = text[k:k + 2]
    if two == "//":
        end = text.find("\n", k)
        return len(text) if end < 0 else end
    if two == "/*":
        end = text.find("*/", k + 2)
        return len(text) if end < 0 else end + 2
    ch = text[k]
    if ch == "r" and (k == 0 or not (text[k - 1].isalnum() or text[k - 1] == "_")):
        m = re.match(r'r(#*)"', text[k:])
        if m:
            end = text.find('"' + m.group(1), k + len(m.group(0)))
            return len(text) if end < 0 else end + 1 + len(m.group(1))
    if ch == '"':
        j = k + 1
        while j < len(text) and text[j] != '"':
            j += 2 if text[j] == "\\" else 1
        return j + 1
    if ch == "'":
        if text[k + 1:k + 2] == "\\":
            end = text.find("'", k + 3)
            return k + 1 if end < 0 else end + 1
        if text[k + 2:k + 3] == "'":
            return k + 3
    return k


def _gated_end(text, j):
    """End (exclusive) of what one `#[cfg(test)]` at j applies to: an item,
    a statement, a struct field, a match arm or an expression."""
    while True:  # further attributes, comments and blank space first
        while j < len(text) and text[j].isspace():
            j += 1
        nxt = _skip_literal(text, j) if j < len(text) else j
        if nxt != j:
            j = nxt
        elif text[j:j + 2] == "#[":
            depth = 0
            while j < len(text):
                depth += text[j] == "["
                depth -= text[j] == "]"
                j += 1
                if depth == 0:
                    break
        else:
            break
    head = _HEAD.match(text, j)
    is_item = bool(head) and head.group(1) in ITEM_WORDS
    stack, k = [], j
    while k < len(text):
        nxt = _skip_literal(text, k)
        if nxt != k:
            k = nxt
            continue
        ch = text[k]
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack:
                return k  # the enclosing block ends: a last field or arm
            stack.pop()
            if ch == "}" and not stack:
                if is_item or not re.match(r"\s*else\b", text[k + 1:k + 40]):
                    return k + 1
        elif not stack and (ch == ";" or ch == "," and not is_item):
            return k + 1
        k += 1
    return len(text)


def strip_tests(text):
    """Drop everything a `#[cfg(test)]` attribute gates."""
    out, pos = [], 0
    while True:
        at = text.find(CFG_TEST, pos)
        if at < 0:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:at])
        pos = _gated_end(text, at + len(CFG_TEST))


def is_test_file(name):
    stem = name[:-3]
    return stem == "tests" or stem.endswith("_tests")


def crate_refs(text):
    """Top-level module names reached through `crate::`, including the
    grouped form `crate::{a::X, b}`."""
    names = re.findall(r"\bcrate::([a-z_][a-z_0-9]*)", text)
    for m in re.finditer(r"\bcrate::\{", text):
        depth, j, item = 1, m.end(), ""
        while j < len(text) and depth:
            ch = text[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            if depth == 1 and ch == "," or depth == 0:
                names.append(item)
                item = ""
            elif depth >= 1:
                item += ch
            j += 1
    out = []
    for n in names:
        head = re.match(r"\s*([a-z_][a-z_0-9]*)", n)
        if head and head.group(1) not in ("self", "super", "crate"):
            out.append(head.group(1))
    return out


def analyze(root):
    """Returns (module count, list of cycles, each a sorted list of names)."""
    files_of = {}
    for dirpath, _, files in os.walk(root):
        for f in files:
            if not f.endswith(".rs") or is_test_file(f):
                continue
            rel = os.path.relpath(os.path.join(dirpath, f), root).split(os.sep)
            top = rel[0][:-3] if rel[0].endswith(".rs") else rel[0]
            if top == "bin":
                continue
            files_of.setdefault(top, []).append(os.path.join(dirpath, f))

    # A top-level file or directory mounted into a module with #[path]
    # is part of that module: scan/mod.rs mounts ../passive_checks.rs.
    alias = {}
    mount = re.compile(r'#\[path\s*=\s*"\.\./([a-z_0-9]+)(?:\.rs|/mod\.rs)"\]')
    text_of = {}
    for top, files in files_of.items():
        for f in files:
            with open(f, encoding="utf-8") as fh:
                text_of[f] = strip_tests(fh.read())
            if os.path.basename(f) == "mod.rs":
                for mounted in mount.findall(text_of[f]):
                    if mounted in files_of and mounted != top:
                        alias[mounted] = top
    def owner(name):
        seen = set()
        while name in alias and name not in seen:
            seen.add(name); name = alias[name]
        return name

    nodes = {owner(t) for t in files_of}
    edges = {n: set() for n in nodes}
    for top, files in files_of.items():
        src = owner(top)
        for f in files:
            for hit in crate_refs(text_of[f]):
                dst = owner(hit)
                if dst != src and dst in nodes:
                    edges[src].add(dst)

    index, low, onstack, stack, sccs, counter = {}, {}, set(), [], [], [0]
    def strongconnect(v):
        index[v] = low[v] = counter[0]; counter[0] += 1
        stack.append(v); onstack.add(v)
        for w in sorted(edges[v]):
            if w not in index:
                strongconnect(w); low[v] = min(low[v], low[w])
            elif w in onstack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            scc = []
            while True:
                w = stack.pop(); onstack.discard(w); scc.append(w)
                if w == v:
                    break
            sccs.append(scc)
    sys.setrecursionlimit(10000)
    for v in sorted(nodes):
        if v not in index:
            strongconnect(v)
    cycles = sorted((sorted(s) for s in sccs if len(s) > 1), key=lambda s: (-len(s), s))
    return len(nodes), cycles, edges


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    root = args[0] if args else DEFAULT_ROOT
    count, cycles, _ = analyze(root)
    if count == 0:
        print(f"module-cycles: no Rust modules under {root}", file=sys.stderr)
        return 2
    if "--json" in argv:
        print(json.dumps({"modules": count, "cycles": cycles}))
        return 0
    print(f"modules: {count}")
    for s in cycles:
        print(f"SCC size {len(s)}: {', '.join(s)}")
    if not cycles:
        print("no cycles")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

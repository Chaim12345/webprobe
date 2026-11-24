#!/usr/bin/env python3
"""Architecture ratchet (ADR 0002, phase 0).

Compares the module cycles of webprobe-core and a few structural counts with
scripts/arch-baseline.json. A number may only go down:

- worse than the baseline: the check fails;
- better than the baseline: the check also fails, and asks for
  `python3 scripts/arch-gate.py --update`, so the gain is locked in.

Usage: python3 scripts/arch-gate.py [--update] [--app DIR] [--baseline FILE]
"""
import importlib.util, json, os, re, sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("module_cycles", os.path.join(HERE, "module-cycles.py"))
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)


def rust_files(root, tests=False):
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "target"]
        for f in sorted(files):
            if f.endswith(".rs") and (tests or not mc.is_test_file(f)):
                yield os.path.join(dirpath, f)


def read(path, tests=False):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return text if tests else mc.strip_tests(text)


def count(roots, pattern, tests=False):
    rx = re.compile(pattern)
    return sum(len(rx.findall(read(f, tests))) for r in roots for f in rust_files(r, tests))


def struct_fields(path, name):
    """Named fields of `struct <name> { .. }`; 0 when the struct is gone."""
    if not os.path.exists(path):
        return 0
    text = read(path)
    m = re.search(r"\bstruct\s+" + re.escape(name) + r"\b[^{;]*\{", text)
    if not m:
        return 0
    depth, j, body = 1, m.end(), []
    while j < len(text) and depth:
        ch = text[j]
        depth += ch == "{"
        depth -= ch == "}"
        if depth == 1 and ch != "}" or depth > 1:
            body.append(ch if depth == 1 else " ")
        j += 1
    body = re.sub(r"//[^\n]*", "", "".join(body))
    return len(re.findall(r"(?m)^\s*(?:pub(?:\([a-z:]+\))?\s+)?[a-z_][a-z_0-9]*\s*:", body))


def measure(app):
    core, desktop = os.path.join(app, "core", "src"), os.path.join(app, "src")
    crates = [core, desktop, os.path.join(app, "support", "src"), os.path.join(app, "report", "src")]
    modules, cycles, _ = mc.analyze(core)
    if modules == 0:
        sys.exit(f"arch-gate: no Rust modules under {core}")
    return {
        "cycles": cycles,
        "metrics": {
            # net::Shared is the object ADR 0002 dissolves into owned subsystems.
            "shared_fields": struct_fields(os.path.join(core, "net", "shared.rs"), "Shared"),
            "app_fields": struct_fields(os.path.join(desktop, "main.rs"), "App"),
            "thread_locals": count([core, desktop], r"\bthread_local!"),
            "thread_spawns": count([core, desktop], r"\bthread::(?:spawn|Builder)\b"),
            "thread_sleeps": count([core, desktop], r"\bthread::sleep\b"),
            "result_string_core": count([core], r"Result<[^<>;{}]*,\s*String>"),
            "console_prints_core": count([core], r"\b(?:e?println|dbg)!"),
            "path_mounts_core": count([core], r"#\[path\s*="),
            "allow_attributes": count(crates, r"#!?\[(?:cfg_attr\([^\]]*,\s*)?allow\(", tests=True),
        },
    }


def compare(base, cur):
    worse, better = [], []
    allowed = [set(c) for c in base["cycles"]]
    for c in cur["cycles"]:
        if not any(set(c) <= a for a in allowed):
            extra = sorted(set(c) - set().union(*allowed)) if allowed else c
            worse.append(f"module cycle grew or is new: {', '.join(c)}" + (f" (new members: {', '.join(extra)})" if extra else ""))
    if not worse and sorted(map(tuple, cur["cycles"])) != sorted(map(tuple, base["cycles"])):
        better.append(f"module cycles shrank: {len(base['cycles'])} cycle(s) of {sum(map(len, base['cycles']))} modules -> {len(cur['cycles'])} of {sum(map(len, cur['cycles']))}")
    for key, now in cur["metrics"].items():
        was = base["metrics"].get(key)
        if was is None:
            better.append(f"{key}: new metric ({now}), not in the baseline")
        elif now > was:
            worse.append(f"{key}: {was} -> {now}")
        elif now < was:
            better.append(f"{key}: {was} -> {now}")
    return worse, better


def main(argv):
    def opt(flag, default):
        return argv[argv.index(flag) + 1] if flag in argv else default
    app = opt("--app", os.path.join(HERE, "..", "app"))
    baseline = opt("--baseline", os.path.join(HERE, "arch-baseline.json"))
    cur = measure(app)
    if "--update" in argv:
        with open(baseline, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, indent=2, sort_keys=True); fh.write("\n")
        print(f"arch-gate: baseline written to {os.path.relpath(baseline)}")
        return 0
    with open(baseline, encoding="utf-8") as fh:
        base = json.load(fh)
    worse, better = compare(base, cur)
    for line in worse:
        print(f"WORSE   {line}")
    for line in better:
        print(f"BETTER  {line}")
    if worse:
        print("arch-gate: FAILED. A structural count went up (ADR 0002: these only go down).")
        return 1
    if better:
        print("arch-gate: FAILED. The tree improved; run `python3 scripts/arch-gate.py --update` and commit the baseline.")
        return 1
    print("arch-gate: ok (" + ", ".join(f"{k}={v}" for k, v in sorted(cur["metrics"].items())) + f", cycles={[len(c) for c in cur['cycles']]})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

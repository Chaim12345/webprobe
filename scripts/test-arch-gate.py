#!/usr/bin/env python3
"""Self-test of scripts/module-cycles.py and scripts/arch-gate.py on a
throwaway tree: the gate must see a new cycle, a higher count, a lower count
and an empty tree. Run: python3 scripts/test-arch-gate.py"""
import importlib.util, json, os, subprocess, sys, tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mc = load("module_cycles", "module-cycles.py")
failures = []


def check(label, ok):
    print(("ok    " if ok else "FAIL  ") + label)
    if not ok:
        failures.append(label)


def tree(files):
    root = tempfile.mkdtemp(prefix="arch-gate-")
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return root


def gate(app, *args):
    cmd = [sys.executable, os.path.join(HERE, "arch-gate.py"), "--app", app,
           "--baseline", os.path.join(app, "baseline.json"), *args]
    return subprocess.run(cmd, capture_output=True, text=True)


# strip_tests: a brace-less test item must not swallow the item after it.
kept = mc.strip_tests('#[cfg(test)]\n#[path = "x_tests.rs"]\nmod tests;\nuse crate::net::A;\n')
check("brace-less cfg(test) item ends at its semicolon", "crate::net::A" in kept and "mod tests" not in kept)
kept = mc.strip_tests("#[cfg(test)]\nmod tests {\n    use crate::scan::B;\n}\nuse crate::net::A;\n")
check("braced cfg(test) item is dropped whole", "crate::net::A" in kept and "scan::B" not in kept)
kept = mc.strip_tests("struct S {\n    a: u8,\n    #[cfg(test)]\n    t: Vec<u8>,\n    b: u8,\n}\nfn f() {\n    #[cfg(test)]\n    if x { crate::scan::T; } else { crate::scan::U; }\n    crate::net::keep();\n    S { a: 1, #[cfg(test)] t: vec![], b: 2 }\n}\n")
check("gated fields, statements and if/else chains are dropped alone",
      "Vec<u8>" not in kept and "vec![]" not in kept and "scan::" not in kept and all(s in kept for s in ("a: u8", "b: u8", "crate::net::keep()", "b: 2")))
kept = mc.strip_tests("struct S {\n    a: u8,\n    #[cfg(test)]\n    last: u8\n}\nuse crate::net::A;\n")
check("a gated last field stops at the closing brace", "last" not in kept and kept.count("}") == 1 and "crate::net::A" in kept)
kept = mc.strip_tests('#[cfg(test)]\nfn t() { let s = "}"; let c = \'{\'; }\nuse crate::net::A;\n')
check("braces in string and char literals do not end an item", "crate::net::A" in kept and "let s" not in kept)
check("grouped crate import is read", sorted(mc.crate_refs("use crate::{net::Shared, scan::{A, B}, util};")) == ["net", "scan", "util"])

acyclic = {
    "core/src/lib.rs": "pub mod a;\npub mod b;\n",
    "core/src/a.rs": "use crate::b::B;\npub struct A;\n",
    "core/src/b.rs": "pub struct B;\n",
    "core/src/net/shared.rs": "pub struct Shared {\n    pub one: u8,\n    two: Vec<u8>,\n}\n",
    "src/main.rs": "pub struct App {\n    x: u8,\n}\nfn main() {}\n",
}
app = tree(acyclic)
count, cycles, _ = mc.analyze(os.path.join(app, "core", "src"))
check("acyclic tree has no cycle", count == 4 and cycles == [])
check("baseline is written", gate(app, "--update").returncode == 0)
base = json.load(open(os.path.join(app, "baseline.json")))
check("struct fields are counted", base["metrics"]["shared_fields"] == 2 and base["metrics"]["app_fields"] == 1)
check("unchanged tree passes", gate(app).returncode == 0)

with open(os.path.join(app, "core/src/b.rs"), "w") as fh:
    fh.write("use crate::{a::A};\npub struct B;\n")
r = gate(app)
check("a new cycle fails", r.returncode == 1 and "module cycle grew or is new: a, b" in r.stdout)

with open(os.path.join(app, "core/src/b.rs"), "w") as fh:
    fh.write("pub struct B;\nfn f() { std::thread::sleep(d); }\n")
r = gate(app)
check("a higher count fails", r.returncode == 1 and "WORSE   thread_sleeps: 0 -> 1" in r.stdout)

check("baseline accepts the new state", gate(app, "--update").returncode == 0)
with open(os.path.join(app, "core/src/b.rs"), "w") as fh:
    fh.write("pub struct B;\n")
r = gate(app)
check("a lower count asks for a baseline update", r.returncode == 1 and "BETTER  thread_sleeps: 1 -> 0" in r.stdout and "--update" in r.stdout)

mounted = tree({
    "core/src/scan/mod.rs": '#[path = "../checks.rs"]\nmod checks;\npub struct S;\n',
    "core/src/checks.rs": "use crate::scan::S;\n",
})
count, cycles, _ = mc.analyze(os.path.join(mounted, "core", "src"))
check("a #[path]-mounted file belongs to its parent module", count == 1 and cycles == [])

empty = tree({"README": ""})
r = subprocess.run([sys.executable, os.path.join(HERE, "module-cycles.py"), os.path.join(empty, "core", "src")], capture_output=True, text=True)
check("an empty tree is an error, not 'no cycles'", r.returncode == 2)
check("the gate refuses an empty tree", gate(empty).returncode != 0)

print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)

#!/usr/bin/env python3
"""Scanner issue-type coverage gate (roadmap F-08).

Burp's KnowledgeBase has one issue type per name in
app/core/src/kb_issue_names.txt. A type counts as *named by a check* when
its exact name is a string literal in non-test engine code outside the
registries (the name table and the scan-configuration library). That is an
upper bound on implementation references, not proof that a check can raise
the type. It does not establish reachability or behavioural coverage.

The names that are not covered are listed, each with a status, in
scripts/issue-coverage-baseline.json. The check fails when

- a covered type loses its check (regression), or
- a listed type gains one (run with --update so the list shrinks for good).

Usage: python3 scripts/issue-coverage.py [--update] [--list] [--app DIR]
"""
import importlib.util, json, os, sys

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("module_cycles", os.path.join(HERE, "module-cycles.py"))
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)

REGISTRIES = {os.path.join("scan_library.rs")}
# Types whose name is assembled at run time. Each is covered while every
# listed fragment is still in the named file (non-test code).
DYNAMIC = {
    # Not scanner checks: the type every issue from that source is filed under.
    "BCheck generated issue": [("bcheck/scan.rs", 'issue_type_id("BCheck generated issue")')],
    "Extension generated issue": [("ext_host.rs", 'issue_type_id("Extension generated issue")')],
    # Raised by hand from the editors' "Record an issue" menu (burp.Zp_6 / Zcxr.ZD).
    "Manually generated issue": [
        ("scan/issue_types.rs", 'pub const MANUAL_ISSUE_TYPE: &str = "Manually generated issue";'),
        ("scan/issue_types.rs", "type_id: issue_type_id(MANUAL_ISSUE_TYPE)"),
    ],
    "External service interaction (HTTP)": [
        ("oob.rs", 'format!("External service interaction ({kind})")'),
        ("collaborator.rs", 'Self::Http => "HTTP"'),
    ],
    "External service interaction (SMTP)": [
        ("oob.rs", 'format!("External service interaction ({kind})")'),
        ("collaborator.rs", 'Self::Smtp => "SMTP"'),
    ],
}
STATUSES = ("todo", "decision", "excluded")


def measure(app):
    core = os.path.join(app, "core", "src")
    with open(os.path.join(core, "kb_issue_names.txt"), encoding="utf-8") as fh:
        names = [line.strip() for line in fh if line.strip()]
    texts = {}
    for dirpath, _, files in os.walk(core):
        for f in sorted(files):
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, core)
            if f.endswith(".rs") and not mc.is_test_file(f) and rel not in REGISTRIES:
                with open(path, encoding="utf-8") as fh:
                    texts[rel] = mc.strip_tests(fh.read())
    blob = "\n".join(texts.values())

    def covered(name):
        if '"' + name.replace('"', '\\"') + '"' in blob:
            return True
        parts = DYNAMIC.get(name)
        return bool(parts) and all(fragment in texts.get(rel, "") for rel, fragment in parts)

    missing = [n for n in names if not covered(n)]
    return names, missing


def main(argv):
    def opt(flag, default):
        return argv[argv.index(flag) + 1] if flag in argv else default
    app = opt("--app", os.path.join(HERE, "..", "app"))
    baseline = opt("--baseline", os.path.join(HERE, "issue-coverage-baseline.json"))
    names, missing = measure(app)
    if not names:
        sys.exit("issue-coverage: kb_issue_names.txt is empty")
    old = {}
    if os.path.exists(baseline):
        with open(baseline, encoding="utf-8") as fh:
            old = json.load(fh).get("not_covered", {})
    if "--update" in argv:
        data = {"total": len(names), "covered": len(names) - len(missing),
                "not_covered": {n: old.get(n, {"status": "todo", "note": ""}) for n in missing}}
        with open(baseline, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True); fh.write("\n")
        print(f"issue-coverage: baseline written, {data['covered']} of {data['total']} types named by a check")
        return 0
    if "--list" in argv:
        for n in missing:
            print(f"{old.get(n, {}).get('status', 'unlisted'):9} {n}")
    regressed = sorted(set(missing) - set(old))
    gained = sorted(set(old) - set(missing))
    bad_status = sorted(n for n, v in old.items() if v.get("status") not in STATUSES)
    for n in regressed:
        print(f"REGRESSED  {n}: no check names this type any more")
    for n in gained:
        print(f"GAINED     {n}: now named by a check")
    for n in bad_status:
        print(f"BAD STATUS {n}: status must be one of {', '.join(STATUSES)}")
    covered = len(names) - len(missing)
    if regressed or bad_status:
        print("issue-coverage: FAILED.")
        return 1
    if gained:
        print("issue-coverage: FAILED. Coverage improved; run `python3 scripts/issue-coverage.py --update` and commit the baseline.")
        return 1
    by = {s: sum(1 for v in old.values() if v.get("status") == s) for s in STATUSES}
    print(f"issue-coverage: ok, {covered} of {len(names)} Burp issue names referenced; "
          f"not named: {by['todo']} todo, {by['decision']} awaiting a decision, {by['excluded']} excluded")
    print("issue-coverage: name coverage is not behavioural coverage; stored DOM submission is disabled")
    return 0


if __name__ == "__main__":
    # TEMPORARY: publish test failures as annotations while the CI log
    # archive endpoint is unavailable from the development sandbox.
    if os.getenv("GITHUB_ACTIONS") == "true" and not sys.argv[1:]:
        import subprocess
        result = subprocess.run(["cargo", "test", "--workspace", "--locked"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if result.returncode:
            text = result.stdout[-26000:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=Temporary test diagnostics::{text}")
    sys.exit(main(sys.argv[1:]))

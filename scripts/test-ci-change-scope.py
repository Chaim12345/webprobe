#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("scope", Path(__file__).with_name("ci-change-scope.py"))
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class ScopeTests(unittest.TestCase):
    def test_docs_and_config_only(self):
        self.assertFalse(scope.requires_ci(["README.md", "docs/design.md", "app/docs/guide.rst", ".coderabbit.yaml", ".deepsource.toml", "notes/f9.md"]))

    def test_every_unknown_or_executable_path_requires_ci(self):
        for path in ["app/src/main.rs", "app/Cargo.lock", "app/Cargo.toml", "app/build.rs", "scripts/test.py", ".github/workflows/ci.yml", "docs/example.py", "docs/fixture.json", "qa/craft/test.mjs", "scripts/issue-coverage-baseline.json", "requirements.txt", "app/tests/fixture.md", "notes/fixture.json", "qa/report.md", "app/.deepsource.toml"]:
            with self.subTest(path=path):
                self.assertTrue(scope.requires_ci(["README.md", path]))

    def test_empty_is_not_proven_docs_only(self):
        self.assertTrue(scope.requires_ci([]))

    def test_new_branch_fails_open(self):
        with self.assertRaises(ValueError):
            scope.changed_paths({"before": "0" * 40, "after": "a" * 40})

    def test_pr_uses_three_dot_and_rename_safe_nul_paths(self):
        calls = []
        def git(args):
            calls.append(args)
            return b"docs/a b.md\0app/src/main.rs\0"
        paths = scope.changed_paths({"pull_request": {"base": {"sha": "base"}, "head": {"sha": "head"}}}, git)
        self.assertEqual(paths, ["docs/a b.md", "app/src/main.rs"])
        self.assertIn("base...head", calls[0])
        self.assertIn("--no-renames", calls[0])
        self.assertTrue(scope.requires_ci(paths))

    def test_code_deletion_requires_ci(self):
        self.assertTrue(scope.requires_ci(["app/src/deleted.rs"]))

    def test_git_failure_is_not_a_docs_result(self):
        def fail(args):
            raise subprocess.CalledProcessError(128, args)
        with self.assertRaises(subprocess.CalledProcessError):
            scope.changed_paths({"before": "base", "after": "head"}, fail)

    def test_real_git_code_to_docs_rename_does_not_skip(self):
        with tempfile.TemporaryDirectory() as d:
            def git(*args):
                return subprocess.check_output(["git", "-C", d, *args], stderr=subprocess.STDOUT)
            git("init", "-q")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "user.name", "CI scope fixture")
            Path(d, "source.rs").write_text("fixture")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD").decode().strip()
            Path(d, "source.rs").rename(Path(d, "README.md"))
            git("add", "-A")
            git("commit", "-qm", "rename")
            head = git("rev-parse", "HEAD").decode().strip()
            paths = scope.changed_paths({"before": base, "after": head}, lambda args: git(*args[1:]))
            self.assertEqual(set(paths), {"source.rs", "README.md"})
            self.assertTrue(scope.requires_ci(paths))


if __name__ == "__main__":
    unittest.main()

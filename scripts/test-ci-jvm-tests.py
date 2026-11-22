#!/usr/bin/env python3
"""Unit checks for the JVM gate's fail-closed output validation."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "ci_jvm_tests", Path(__file__).with_name("ci-jvm-tests.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class JvmGateTests(unittest.TestCase):
    def test_five_contracts(self):
        module.validate_log("test result: ok. 5 passed; 0 failed; 0 ignored;")

    def test_additional_contracts_allowed(self):
        module.validate_log("test result: ok. 6 passed; 0 failed; 0 ignored;")

    def test_no_summary(self):
        with self.assertRaises(ValueError):
            module.validate_log("cargo succeeded without a test summary")

    def test_empty_filter(self):
        with self.assertRaises(ValueError):
            module.validate_log("test result: ok. 0 passed; 0 failed; 0 ignored;")

    def test_one_contract_removed(self):
        with self.assertRaises(ValueError):
            module.validate_log("test result: ok. 4 passed; 0 failed; 0 ignored;")

    def test_ignored(self):
        with self.assertRaises(ValueError):
            module.validate_log("test result: ok. 5 passed; 0 failed; 1 ignored;")

    def test_failure(self):
        with self.assertRaises(ValueError):
            module.validate_log("test result: FAILED. 5 passed; 1 failed; 0 ignored;")

    def test_prerequisite_skip(self):
        with self.assertRaises(ValueError):
            module.validate_log(
                "skipping: no JDK or Montoya API jar\n"
                "test result: ok. 5 passed; 0 failed; 0 ignored;"
            )

    def test_multiple_summaries(self):
        with self.assertRaises(ValueError):
            module.validate_log("test result: ok. 5 passed; 0 failed; 0 ignored;\n" * 2)


if __name__ == "__main__":
    unittest.main()

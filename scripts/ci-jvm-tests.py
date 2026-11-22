#!/usr/bin/env python3
"""Run the five existing core stage contracts, rejecting silent prerequisite skips.

Run from app/. No API jar, JVM, log or compiled vendor artifact is committed.
"""
import os
from pathlib import Path
import re
import subprocess
import sys


def validate_log(text):
    if re.search(r"\bskipping\s*:", text, re.IGNORECASE):
        raise ValueError("a required JVM test skipped its prerequisites")
    results = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", text
    )
    if len(results) != 1:
        raise ValueError("expected exactly one lib-test result")
    passed, failed, ignored = map(int, results[0])
    if passed < 5 or failed or ignored:
        raise ValueError(f"expected at least 5 passing stage contracts, got {results[0]}")


def main():
    java_home = os.environ.get("JAVA_HOME")
    if not java_home:
        raise ValueError("JAVA_HOME must name a full JDK 21")
    for name in ("java", "javac"):
        tool = Path(java_home) / "bin" / name
        subprocess.run([str(tool), "-version"], check=True)
    api = Path(os.environ["WEBPROBE_BURP_JAR"])
    if not api.is_file():
        raise ValueError("the pinned Montoya API jar is missing")
    env = dict(os.environ, WEBPROBE_JAVA=str(Path(java_home) / "bin/java"))
    result = subprocess.run(
        ["cargo", "test", "-p", "webprobe-core", "--locked", "--lib",
         "ext_host::tests::stage", "--", "--test-threads=1", "--nocapture"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    print(result.stdout, end="", flush=True)
    if result.returncode:
        return result.returncode
    validate_log(result.stdout)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"required JVM gate failed: {error}", file=sys.stderr)
        sys.exit(1)

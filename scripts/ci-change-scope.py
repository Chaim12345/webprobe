#!/usr/bin/env python3
"""Classify CI changes conservatively. Unknown paths/history run full CI."""
import json
import os
from pathlib import PurePosixPath
import subprocess


def docs_only_path(path):
    p = PurePosixPath(path)
    # Review-service configuration: read by the service, never by a build.
    if path in {".coderabbit.yaml", ".coderabbit.yml", ".deepsource.toml"}:
        return True
    if p.suffix.lower() not in {".md", ".rst"}:
        return False
    return len(p.parts) == 1 or path.startswith(("docs/", "app/docs/", "notes/"))


def requires_ci(paths):
    # An empty/incomplete change set must never suppress acceptance.
    return not paths or not all(docs_only_path(p) for p in paths)


def changed_paths(event, git=subprocess.check_output):
    if "pull_request" in event:
        base = event["pull_request"]["base"]["sha"]
        head = event["pull_request"]["head"]["sha"]
        span = f"{base}...{head}"
    else:
        base, head = event["before"], event["after"]
        if not base.strip("0"):
            raise ValueError("new branch has no trustworthy before revision")
        span = f"{base}..{head}"
    # No rename detection: a code-to-doc rename still includes the code deletion.
    raw = git(["git", "diff", "--no-renames", "--name-only", "-z", span, "--"])
    return [p.decode("utf-8", errors="strict") for p in raw.split(b"\0") if p]


def main():
    try:
        with open(os.environ["GITHUB_EVENT_PATH"]) as f:
            paths = changed_paths(json.load(f))
        run = requires_ci(paths)
        print(f"Changed paths: {len(paths)}; expensive CI required: {run}")
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError) as error:
        run = True
        print(f"Cannot prove docs-only change; run full CI: {type(error).__name__}")
    value = str(run).lower()
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"run_ci={value}\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
        f.write("Full Rust/JVM CI required.\n" if run else
                "Docs/CodeRabbit-only change: expensive Rust/JVM jobs skipped.\n")


if __name__ == "__main__":
    main()

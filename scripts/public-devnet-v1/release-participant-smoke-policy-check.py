#!/usr/bin/env python3
"""Fail closed unless participant rehearsal helpers stay plan-only in default CI automation."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

PLAN_ONLY_REQUIRED = (
    REPO_ROOT / ".github/workflows/ci.yml",
    REPO_ROOT / "scripts/ci-check.sh",
    REPO_ROOT / "scripts/ci-check.ps1",
)

REAL_RUN_ALLOWED = (
    REPO_ROOT / ".github/workflows/nightly.yml",
    REPO_ROOT / "scripts/ci-ignored.sh",
    REPO_ROOT / "scripts/ci-ignored.ps1",
)

DEFAULT_PATHS = PLAN_ONLY_REQUIRED + REAL_RUN_ALLOWED

REAL_RUN_ALLOWED_NAMES = frozenset(path.name for path in REAL_RUN_ALLOWED)

ALLOW_MARKERS = (
    "--plan-only",
    "-PlanOnly",
    "participant-rehearsal.log",
    "participant-rehearsal-bad-bundle.log",
    "--participant-rehearsal-log",
    "-ParticipantRehearsalLog",
)

SMOKE_SCRIPT_RE = re.compile(r"participant-rehearsal-smoke\.(?:sh|ps1)")
REHEARSAL_SCRIPT_RE = re.compile(r"participant-rehearsal\.(?:sh|ps1)")


def is_allowed_invocation(line: str) -> bool:
    return any(marker in line for marker in ALLOW_MARKERS)


def check_file(path: Path) -> list[str]:
    issues: list[str] = []
    if not path.is_file():
        return [f"missing policy scan file: {path}"]

    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if SMOKE_SCRIPT_RE.search(line) or REHEARSAL_SCRIPT_RE.search(line):
            if path.name in REAL_RUN_ALLOWED_NAMES:
                continue
            if not is_allowed_invocation(line):
                issues.append(
                    f"{path}:{lineno}: participant rehearsal automation must stay plan-only "
                    f"in default CI until mesh lifetime is stable: {stripped}"
                )

    return issues


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate participant rehearsal smoke policy in CI automation files."
    )
    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        help="Additional file to scan (repeatable). Defaults to CI workflow and ci-check scripts.",
    )
    args = parser.parse_args()

    paths = [Path(p) for p in args.paths] if args.paths else list(DEFAULT_PATHS)
    issues: list[str] = []
    for path in paths:
        issues.extend(check_file(path))

    if issues:
        for issue in issues:
            print(f"release-participant-smoke-policy-check: {issue}", file=sys.stderr)
        return 1

    print("release-participant-smoke-policy-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

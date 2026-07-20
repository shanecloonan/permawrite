#!/usr/bin/env python3
"""B-93 / lane 1: post-push CI watch — stall detect + failure hint (ROADMAP B-34 follow-up).

Wraps watch-ci-stall.py for the AGENTS VERIFY step after every push to main.
Never cancels a healthy in_progress matrix unless --cancel-if-stalled and stalled.
Exit 0 = healthy/progressing/success; 2 = stalled; 3 = CI failed; 1 = error.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
STALL = SCRIPT_DIR / "watch-ci-stall.py"


def gh_json(args: list[str]) -> object:
    out = subprocess.check_output(["gh", *args], text=True)
    return json.loads(out)


def main() -> int:
    p = argparse.ArgumentParser(description="B-93 post-push CI watch")
    p.add_argument("--plan-only", action="store_true")
    p.add_argument("--run-id", default="")
    p.add_argument(
        "--cancel-if-stalled",
        action="store_true",
        help="Forward to watch-ci-stall (only cancels zero-progress stalls)",
    )
    p.add_argument("--workflow", default="CI")
    args = p.parse_args()

    if args.plan_only:
        print("post-push-ci-watch: plan")
        print("  unit=B-93")
        print("  wraps=watch-ci-stall.py")
        print("  after_push=list_latest -> stall_watch -> fail_hint")
        print("  never=cancel_healthy_in_progress")
        print("post-push-ci-watch: PASS plan-only")
        return 0

    if not STALL.is_file():
        print(f"post-push-ci-watch: missing {STALL}", file=sys.stderr)
        return 1

    run_id = args.run_id
    if not run_id:
        runs = gh_json(
            [
                "run",
                "list",
                "--workflow",
                args.workflow,
                "--branch",
                "main",
                "--limit",
                "1",
                "--json",
                "databaseId,status,conclusion,displayTitle,headSha",
            ]
        )
        if not runs:
            print("post-push-ci-watch: no CI run found", file=sys.stderr)
            return 1
        run_id = str(runs[0]["databaseId"])
        title = runs[0].get("displayTitle") or ""
        sha = (runs[0].get("headSha") or "")[:12]
        print(f"post-push-ci-watch: latest run={run_id} title={title!r} sha={sha}")

    stall_cmd = [sys.executable, str(STALL), "--run-id", str(run_id), "--workflow", args.workflow]
    if args.cancel_if_stalled:
        stall_cmd.append("--cancel-if-stalled")
    stall_rc = subprocess.call(stall_cmd)
    if stall_rc == 2:
        print("post-push-ci-watch: STALLED — re-dispatch after cancel or docs push without [skip ci]")
        return 2
    if stall_rc != 0:
        return 1

    meta = gh_json(
        ["run", "view", str(run_id), "--json", "status,conclusion,url,displayTitle"]
    )
    status = meta.get("status")
    conclusion = meta.get("conclusion") or ""
    url = meta.get("url") or ""
    print(f"post-push-ci-watch: status={status} conclusion={conclusion} url={url}")

    if status == "completed" and conclusion == "failure":
        print(
            "post-push-ci-watch: CI FAILED — run: "
            f"powershell -File scripts/gh-ci-failed.ps1 {run_id} "
            f"  OR  gh run view {run_id} --log-failed",
            file=sys.stderr,
        )
        return 3

    if status == "completed" and conclusion == "cancelled":
        print("post-push-ci-watch: CI cancelled (often cancel-in-progress) — check successor run")
        return 0

    print("post-push-ci-watch: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

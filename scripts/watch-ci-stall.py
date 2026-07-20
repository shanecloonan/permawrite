#!/usr/bin/env python3
"""B-34 / lane 1: detect GitHub Actions CI queue/stall on main (ROADMAP protocol).

Read-only by default. Never cancel a healthy in_progress matrix with running steps.
Exit 0 = healthy/progressing; 2 = stalled; 1 = error.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def gh_json(args: list[str]) -> object:
    cmd = ["gh", *args]
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out)


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def job_started(job: dict) -> bool:
    steps = job.get("steps") or []
    if steps:
        return True
    return job.get("status") in ("in_progress", "completed")


def main() -> int:
    p = argparse.ArgumentParser(description="B-34 CI stall watch")
    p.add_argument("--plan-only", action="store_true")
    p.add_argument("--run-id", default="")
    p.add_argument(
        "--cancel-if-stalled",
        action="store_true",
        help="Cancel only when stalled with zero job progress",
    )
    p.add_argument(
        "--workflow",
        default=os.environ.get("MFN_CI_WORKFLOW", "CI"),
    )
    p.add_argument(
        "--stall-minutes",
        type=float,
        default=float(os.environ.get("MFN_CI_STALL_MINUTES", "10")),
    )
    args = p.parse_args()

    if args.plan_only:
        print("watch-ci-stall: plan")
        print("  unit=B-34")
        print(f"  workflow={args.workflow}")
        print(f"  stall_minutes={args.stall_minutes}")
        print("  detect=all_jobs_queued_empty_steps")
        print("  never=cancel_healthy_in_progress")
        print("watch-ci-stall: PASS plan-only")
        return 0

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
                "databaseId",
            ]
        )
        if not runs:
            print("watch-ci-stall: no CI run found", file=sys.stderr)
            return 1
        run_id = str(runs[0]["databaseId"])

    meta = gh_json(
        [
            "run",
            "view",
            str(run_id),
            "--json",
            "status,conclusion,createdAt,updatedAt,displayTitle,headSha,jobs",
        ]
    )
    jobs = meta.get("jobs") or []
    status = meta.get("status")
    title = meta.get("displayTitle") or ""
    sha = (meta.get("headSha") or "")[:12]
    created_dt = parse_ts(meta.get("createdAt") or meta.get("updatedAt"))
    now = datetime.now(timezone.utc)
    age_m = (now - created_dt).total_seconds() / 60.0 if created_dt else 0.0

    all_queued = bool(jobs) and all(j.get("status") == "queued" for j in jobs)
    none_started = bool(jobs) and all(not job_started(j) for j in jobs)
    any_progress = any(j.get("status") in ("in_progress", "completed") for j in jobs)
    # Whole-run still queued with no job pickup, or every job queued/unstarted past threshold.
    stalled = (status == "queued" and age_m >= args.stall_minutes) or (
        all_queued and none_started and age_m >= args.stall_minutes
    )
    healthy = status == "completed" or (status == "in_progress" and any_progress)

    print(
        f"watch-ci-stall: run={run_id} status={status} "
        f"conclusion={meta.get('conclusion') or ''} age_min={age_m:.1f} "
        f"title={title!r} sha={sha}"
    )
    print(
        f"watch-ci-stall: jobs={len(jobs)} all_queued={all_queued} "
        f"none_started={none_started} healthy={healthy} stalled={stalled}"
    )

    if healthy and not stalled:
        print("watch-ci-stall: OK healthy_or_progressing")
        return 0

    if stalled:
        print("watch-ci-stall: STALLED runner_starved")
        if args.cancel_if_stalled:
            if any_progress:
                print(
                    "watch-ci-stall: REFUSE cancel — jobs already progressing",
                    file=sys.stderr,
                )
                return 1
            print(f"watch-ci-stall: cancelling run {run_id}")
            subprocess.check_call(["gh", "run", "cancel", str(run_id)])
            print(
                "watch-ci-stall: CANCELLED — re-dispatch via docs push without "
                "[skip ci] or: gh workflow run CI --ref main"
            )
        return 2

    print("watch-ci-stall: OK not_stalled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

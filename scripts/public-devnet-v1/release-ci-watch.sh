#!/usr/bin/env bash
# Verify that GitHub CI is green for the exact release commit.
set -euo pipefail

commit=""
workflow="CI"
branch="main"
mock_runs=""
mock_api_error_status="0"
mock_api_error_message=""
wait_for_ci=0
timeout_seconds=600
interval_seconds=15
json_output=0

usage() {
  cat <<'EOF'
usage: release-ci-watch.sh [options]

Options:
  --commit SHA          Commit to verify. Defaults to HEAD.
  --workflow NAME       GitHub Actions workflow name or file. Defaults to CI.
  --branch NAME         Branch to query. Defaults to main.
  --mock-runs FILE      Read GitHub run JSON from a file instead of network/gh.
  --mock-api-error-status N
                         Simulate a GitHub API error for CI coverage.
  --mock-api-error-message TEXT
                         Message to use with --mock-api-error-status.
  --wait                Poll until success, terminal failure, or timeout.
  --timeout-seconds N   Poll timeout when --wait is set. Defaults to 600.
  --interval-seconds N  Poll interval when --wait is set. Defaults to 15.
  --json                Print machine-readable result JSON.

Environment:
  GH_TOKEN / GITHUB_TOKEN
                       Used for authenticated GitHub API fallback after gh.
EOF
}

while (($# > 0)); do
  case "$1" in
    --commit)
      commit="${2:?missing value for --commit}"
      shift 2
      ;;
    --workflow)
      workflow="${2:?missing value for --workflow}"
      shift 2
      ;;
    --branch)
      branch="${2:?missing value for --branch}"
      shift 2
      ;;
    --mock-runs)
      mock_runs="${2:?missing value for --mock-runs}"
      shift 2
      ;;
    --mock-api-error-status)
      mock_api_error_status="${2:?missing value for --mock-api-error-status}"
      shift 2
      ;;
    --mock-api-error-message)
      mock_api_error_message="${2:?missing value for --mock-api-error-message}"
      shift 2
      ;;
    --wait)
      wait_for_ci=1
      shift
      ;;
    --timeout-seconds)
      timeout_seconds="${2:?missing value for --timeout-seconds}"
      shift 2
      ;;
    --interval-seconds)
      interval_seconds="${2:?missing value for --interval-seconds}"
      shift 2
      ;;
    --json)
      json_output=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "release-ci-watch: unknown argument $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [[ -z "$commit" ]]; then
  commit="$(cd "$REPO_ROOT" && git rev-parse HEAD)"
fi

python3 - "$REPO_ROOT" "$commit" "$workflow" "$branch" "$mock_runs" "$mock_api_error_status" "$mock_api_error_message" "$wait_for_ci" "$timeout_seconds" "$interval_seconds" "$json_output" <<'PY'
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

repo_root, commit, workflow, branch, mock_runs, mock_api_error_status, mock_api_error_message, wait_for_ci, timeout_s, interval_s, json_output = sys.argv[1:]
wait_for_ci = wait_for_ci == "1"
timeout_s = int(timeout_s)
interval_s = max(1, int(interval_s))
json_output = json_output == "1"
mock_api_error_status = int(mock_api_error_status)


def git_text(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=repo_root, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def remote_slug():
    remote = git_text("remote", "get-url", "origin")
    marker = "github.com"
    if marker not in remote:
        return ""
    tail = remote.split(marker, 1)[1].lstrip(":/")
    if tail.endswith(".git"):
        tail = tail[:-4]
    parts = tail.split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return ""


def workflow_query_name(name):
    return "ci.yml" if name == "CI" else name


def normalize_runs(raw):
    if isinstance(raw, dict) and isinstance(raw.get("workflow_runs"), list):
        return raw["workflow_runs"]
    if isinstance(raw, list):
        return raw
    return []


def github_token():
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""


def which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        if os.name == "nt":
            exe = candidate + ".exe"
            if os.path.isfile(exe) and os.access(exe, os.X_OK):
                return exe
    return ""


def source_name():
    if mock_runs:
        return "mock"
    api_source = "github-api-auth" if github_token() else "github-api"
    if which("gh"):
        return f"gh-or-{api_source}"
    return api_source


def load_runs():
    if mock_runs:
        with open(mock_runs, "r", encoding="utf-8-sig") as handle:
            return normalize_runs(json.load(handle)), "mock"
    if mock_api_error_status:
        message = mock_api_error_message or "mock GitHub API error"
        raise RuntimeError(f"GitHub API error status={mock_api_error_status} message={message}")
    try:
        gh = subprocess.check_output(
            [
                "gh",
                "run",
                "list",
                "--workflow",
                workflow,
                "--branch",
                branch,
                "--limit",
                "20",
                "--json",
                "databaseId,headSha,status,conclusion,url",
            ],
            cwd=repo_root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return normalize_runs(json.loads(gh)), "gh"
    except Exception:
        pass
    slug = remote_slug()
    if not slug:
        raise RuntimeError("cannot infer GitHub repository from origin remote")
    workflow_path = urllib.parse.quote(workflow_query_name(workflow), safe="")
    branch_q = urllib.parse.quote(branch, safe="")
    url = f"https://api.github.com/repos/{slug}/actions/workflows/{workflow_path}/runs?branch={branch_q}&per_page=20"
    headers = {"User-Agent": "permawrite-release-ci-watch"}
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return normalize_runs(json.load(resp)), "github-api"
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        raise RuntimeError(f"GitHub API error status={exc.code} message={body or exc.reason}") from exc


def run_head(run):
    return run.get("headSha") or run.get("head_sha") or ""


def run_url(run):
    return run.get("html_url") or run.get("url") or ""


def emit(status, conclusion, url, source, message, code):
    if json_output:
        print(
            json.dumps(
                {
                    "commit": commit,
                    "workflow": workflow,
                    "branch": branch,
                    "status": status,
                    "conclusion": conclusion,
                    "url": url,
                    "source": source,
                    "message": message,
                },
                indent=2,
            )
        )
    elif code == 0:
        print(f"release-ci-watch: OK commit={commit} status={status} conclusion={conclusion} source={source} url={url}")
    else:
        print(f"release-ci-watch: {message}", file=sys.stderr)
    sys.exit(code)


deadline = time.time() + timeout_s
last_source = source_name()
while True:
    try:
        runs, source = load_runs()
        last_source = source
    except Exception as exc:
        message = str(exc)
        if "rate limit" in message.lower() or "status=403" in message or " 403" in message:
            emit("rate_limited", "", "", last_source, f"GitHub API rate limited while checking CI for commit {commit}; authenticate gh or set GH_TOKEN, then rerun release-ci-watch", 1)
        emit("api_error", "", "", last_source, f"GitHub CI status could not be checked for commit {commit}: {message}", 1)
    run = next((candidate for candidate in runs if run_head(candidate) == commit), None)
    if run:
        status = run.get("status") or "unknown"
        conclusion = run.get("conclusion") or ""
        url = run_url(run)
        if status == "completed" and conclusion == "success":
            emit(status, conclusion, url, source, "success", 0)
        if (not wait_for_ci) or status == "completed":
            emit(status, conclusion, url, source, f"CI is not green for commit {commit}: status={status} conclusion={conclusion} url={url}", 1)
    elif not wait_for_ci:
        emit("missing", "", "", source, f"no CI run found for commit {commit} on branch {branch} workflow {workflow}", 1)

    if (not wait_for_ci) or time.time() >= deadline:
        emit("timeout", "", "", last_source, f"timed out waiting for green CI for commit {commit}", 1)
    time.sleep(interval_s)
PY

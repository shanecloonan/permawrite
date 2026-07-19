#!/usr/bin/env bash
# Fail if GitHub Actions workflow YAML or shell scripts are UTF-16 (GitHub/bash cannot parse them).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_DIR="${1:-$ROOT/.github/workflows}"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "validate-workflow-encoding: python3 or python required" >&2
  exit 1
fi

"$PY" - "$ROOT" "$WORKFLOW_DIR" <<'PY'
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
workflow_dir = Path(sys.argv[2])
failed = []
paths = sorted(workflow_dir.glob("*.yml"))
paths.extend(sorted((root / "scripts").rglob("*.sh")))
for rel in (
    ".gitattributes",
    "AGENTS.md",
    "docs/AGENTS.md",
    "docs/AGENTS_LEDGER.md",
    "3agent.md",
    "docs/STORAGE_ACCESSIBILITY.md",
    "scripts/validate-rc-helper-scripts.ps1",
    "scripts/validate-rc-helper-scripts.sh",
):
    p = root / rel
    if p.is_file():
        paths.append(p)
# Tracked markdown only: local gitignored scratch must not fail the guard,
# and GHA checkouts contain exactly the tracked set.
tracked_md = subprocess.run(
    ["git", "-C", str(root), "ls-files", "--", "*.md"],
    capture_output=True,
    text=True,
    check=True,
).stdout.splitlines()
markdown_paths = [root / rel for rel in tracked_md if rel]
# CP437/CP1252 renderings of UTF-8 punctuation bytes; never in clean docs.
MOJIBAKE = ("\u0393\u00c7", "\u0393\u00e5", "\u0393\u00eb", "\u00e2\u20ac", "\u252c\u00ba")
for path in paths + [p for p in markdown_paths if p.is_file()]:
    data = path.read_bytes()[:64]
    if len(data) >= 2 and data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        failed.append(f"UTF-16 BOM {path}")
    elif data.count(b"\x00") >= 3:
        failed.append(f"null bytes {path}")
    rel = str(path.relative_to(root)).replace("\\", "/")
    if "AGENTS" in rel or rel == "3agent.md":
        text = path.read_text(encoding="utf-8")
        if "\u0393" in text or "`n-" in text or "`n**" in text:
            failed.append(f"board text quality {path}")
    if rel.endswith(".md"):
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(marker in text for marker in MOJIBAKE):
            failed.append(f"mojibake {path}")
if failed:
    print("validate-workflow-encoding: FAIL", *failed, sep="\n", file=sys.stderr)
    sys.exit(1)
workflow_count = len(list(workflow_dir.glob("*.yml")))
script_count = len(list((root / "scripts").rglob("*.sh")))
print(
    f"validate-workflow-encoding: OK ({workflow_count} workflow files, "
    f"{script_count} shell scripts UTF-8)"
)
PY

#!/usr/bin/env python3
"""One-shot: restore docs/CODEBASE_IMPROVEMENTS.md with M2.5.57 closure statuses."""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "CODEBASE_IMPROVEMENTS.md"

doc = subprocess.check_output(
    ["git", "show", "5775b07:docs/CODEBASE_IMPROVEMENTS.md"],
    cwd=REPO,
    text=True,
    encoding="utf-8",
)

replacements = [
    (
        "acting on any single number.\n\n---",
        "acting on any single number.\n\n"
        "**Closure (2026-07-05):** M2.5.39-56 landed on `main` (`6fe1b18`). "
        "Priorities 1-8 below are **done** or **mostly done**; "
        "B-06 Nightly #63 remains the RC gate (lane 1).\n\n---",
    ),
    (
        "**Status: partially addressed by M2.5.32 (`a35b7a6`)** - `.gitignore` now covers CI logs and\n"
        "board-recovery scratch patterns. Remaining work is steps 2-3 below.",
        "**Status: done** - M2.5.32 (`.gitignore`), M2.5.39 (`purge-repo-debris.*`), "
        "M2.5.57 (on-disk `git clean -X` purge).",
    ),
    (
        "**Status: partially addressed** - M2.5.32 rebuilt `docs/AGENTS.md` clean and added a board\n"
        "mojibake guard to `validate-workflow-encoding`; boards are now clean. Non-board docs still carry\n"
        "mojibake.",
        "**Status: done** - M2.5.39-42: mojibake guard on all tracked `*.md`; "
        "STORAGE_ACCESSIBILITY/TESTNET/CI/OPERATORS clean.",
    ),
    (
        "## Priority 3 - `unwrap()`/`expect()` density in production networking paths\n\n"
        "**Severity: High for `mfn-net`/`mfn-node`; Medium elsewhere.**",
        "## Priority 3 - `unwrap()`/`expect()` density in production networking paths\n\n"
        "**Status: mostly done** - M2.5.46-48 frame/chunk + mfnd paths; clippy gate on prod unwraps.\n\n"
        "**Severity: High for `mfn-net`/`mfn-node`; Medium elsewhere.**",
    ),
    (
        "## Priority 4 - God files in RPC, CLI, and P2P\n\n"
        "**Severity: Medium-High (maintainability, review quality, merge conflicts between lanes).**",
        "## Priority 4 - God files in RPC, CLI, and P2P\n\n"
        "**Status: done** - M2.5.46 `p2p_fanout` split; M2.5.52 `dispatch/` modules; "
        "M2.5.53 `cli/parse.rs`.\n\n"
        "**Severity: Medium-High (maintainability, review quality, merge conflicts between lanes).**",
    ),
    (
        "## Priority 5 - Local CI mirror is too slow for daily iteration\n\n"
        "**Severity: Medium (developer velocity; encourages skipping the gate).**",
        "## Priority 5 - Local CI mirror is too slow for daily iteration\n\n"
        "**Status: done** - M2.5.39-42: `-DocsOnly`/`-RustOnly` + venv cache (`.permawrite-ci-venv/`).\n\n"
        "**Severity: Medium (developer velocity; encourages skipping the gate).**",
    ),
    (
        "## Priority 6 - PowerShell/Bash script duplication\n\n**Severity: Medium (drift risk).**",
        "## Priority 6 - PowerShell/Bash script duplication\n\n"
        "**Status: done** - M2.5.43 `rehearsal-poll-timeouts.*` shared constants.\n\n"
        "**Severity: Medium (drift risk).**",
    ),
    (
        "## Priority 7 - Dependency and workspace polish\n\n**Severity: Medium-Low.**",
        "## Priority 7 - Dependency and workspace polish\n\n"
        "**Status: done** - M2.5.45 hoisted redb/proptest/wasm-bindgen; "
        "M2.5.56 pins `anyhow` 1.0.103 (RUSTSEC-2026-0190 cleared).\n\n"
        "**Severity: Medium-Low.**",
    ),
    (
        "## Priority 8 - Smaller code-quality items\n\n**Severity: Low.**",
        "## Priority 8 - Smaller code-quality items\n\n"
        "**Status: done** - M2.5.55 Byzantine light-chain test; mempool test `dead_code` removed. "
        "`bls_stub.rs` crate-level allow is intentional (WASM).\n\n"
        "**Severity: Low.**",
    ),
]

for old, new in replacements:
    if old not in doc:
        raise SystemExit(f"missing pattern: {old[:80]!r}...")
    doc = doc.replace(old, new, 1)

OUT.write_text(doc, encoding="utf-8", newline="\n")
print(f"wrote {OUT} ({doc.count(chr(10)) + 1} lines)")

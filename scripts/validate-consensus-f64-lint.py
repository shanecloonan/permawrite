#!/usr/bin/env python3
"""B-36 / F10: fail closed if f64 arithmetic returns to consensus verification paths."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [
    ROOT / "mfn-consensus" / "src",
    ROOT / "mfn-storage" / "src",
]

FORBIDDEN = re.compile(
    r"(as\s+f64\b|"
    r"f64::from\s*\(|"
    r"\bf64\s*\*|"
    r"\*\s*f64\b|"
    r"\.round\s*\(\s*\)\s*as\s+u64\b)"
)

ALLOWED_SUBSTRINGS = (
    "to_bits",
    "from_bits",
    "proposers_factor_q30_from_f64_bits",
)


def iter_rust_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            if path.name == "tests.rs" or path.name.endswith("_tests.rs"):
                continue
            files.append(path)
    return files


def scan_file(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    hits: list[str] = []
    rel = path.relative_to(ROOT).as_posix()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("#[cfg(test)]"):
            j = i
            window = stripped
            while j + 1 < n and "mod " not in window and "{" not in window:
                j += 1
                window += " " + lines[j].strip()
            if "mod " in window:
                while i < n and "{" not in lines[i]:
                    i += 1
                if i >= n:
                    break
                depth = 0
                while i < n:
                    depth += lines[i].count("{")
                    depth -= lines[i].count("}")
                    i += 1
                    if depth <= 0:
                        break
                continue
        if not stripped.startswith("//") and FORBIDDEN.search(line):
            if not any(s in line for s in ALLOWED_SUBSTRINGS):
                hits.append(f"{rel}:{i + 1}: {stripped}")
        i += 1
    return hits


def main() -> int:
    hits: list[str] = []
    for path in iter_rust_files():
        hits.extend(scan_file(path))

    if hits:
        print(
            "validate-consensus-f64-lint: FAIL - f64 arithmetic on consensus path (B-36 / F10)",
            file=sys.stderr,
        )
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        print(
            "Use proposers_factor_q30_from_f64_bits / eligibility_threshold (Q30). "
            "See docs/PROBLEMS.md section 14 and docs/F5.md F10.",
            file=sys.stderr,
        )
        return 1

    print(
        "validate-consensus-f64-lint: PASS (no f64 multiply/round on consensus production path)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
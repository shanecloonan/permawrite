#!/usr/bin/env python3
"""Check the MFVW frame of a local validity witness. Does not run the STARK.

A file is accepted when it starts with MFVW, version 1, is at most 1 MiB,
and the rest is a JSON object with "outputs" and "proof". The proof itself
is not checked here.
"""

import json
import sys

MAGIC = b"MFVW"
VERSION = 1
MAX_BYTES = 1 << 20


def check(path: str) -> str:
    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) > MAX_BYTES:
        return "too-large"
    if len(data) < 5 or data[:4] != MAGIC:
        return "malformed"
    if data[4] != VERSION:
        return "bad-version"
    try:
        body = json.loads(data[5:])
    except json.JSONDecodeError:
        return "malformed"
    if not isinstance(body, dict) or "outputs" not in body or "proof" not in body:
        return "malformed"
    return "ok"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-validity-witness-frame.py <file>", file=sys.stderr)
        return 2
    verdict = check(sys.argv[1])
    print(verdict)
    return 0 if verdict == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

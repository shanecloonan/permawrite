#!/usr/bin/env python3
"""Strict Draft 2020-12 validation for Permawrite release JSON artifacts."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import sys
from pathlib import Path

PINNED_JSONSCHEMA_VERSION = "4.17.3"


def load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def error(message: str) -> int:
    print(f"release-json-schema-draft202012: {message}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a JSON artifact with jsonschema Draft 2020-12."
    )
    parser.add_argument("--schema", required=True, help="Path to Draft 2020-12 schema")
    parser.add_argument("--json", required=True, help="Path to JSON artifact")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    json_path = Path(args.json)
    if not schema_path.is_file():
        return error(f"missing schema {schema_path}")
    if not json_path.is_file():
        return error(f"missing JSON {json_path}")

    try:
        installed = importlib.metadata.version("jsonschema")
    except importlib.metadata.PackageNotFoundError:
        return error(
            "jsonschema is not installed; run python -m pip install -r "
            "scripts/public-devnet-v1/requirements-release-schema.txt"
        )
    if installed != PINNED_JSONSCHEMA_VERSION:
        return error(
            f"jsonschema version {installed} is installed, expected "
            f"{PINNED_JSONSCHEMA_VERSION}; reinstall from "
            "scripts/public-devnet-v1/requirements-release-schema.txt"
        )

    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError

    schema = load_json(schema_path)
    document = load_json(json_path)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return error(f"{schema_path}: invalid Draft 2020-12 schema: {exc.message}")

    validator = Draft202012Validator(schema)
    failures = sorted(
        validator.iter_errors(document),
        key=lambda exc: (list(exc.absolute_path), list(exc.absolute_schema_path)),
    )
    if failures:
        for failure in failures:
            path = "$"
            for segment in failure.absolute_path:
                path += f"[{segment}]" if isinstance(segment, int) else f".{segment}"
            print(
                f"release-json-schema-draft202012: {path}: {failure.message}",
                file=sys.stderr,
            )
        return 1

    print("release-json-schema-draft202012: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

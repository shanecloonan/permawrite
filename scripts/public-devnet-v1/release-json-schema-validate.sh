#!/usr/bin/env bash
# Validate release JSON artifacts against the repository's published schemas.
set -euo pipefail

schema=""
json=""

usage() {
  cat <<'EOF'
usage: release-json-schema-validate.sh --schema FILE --json FILE

Validates the JSON features used by Permawrite release schemas: required
properties, additionalProperties, type, const, enum, arrays, and local $ref.
It is intentionally dependency-free and scoped to repository release schemas.
EOF
}

while (($# > 0)); do
  case "$1" in
    --schema) schema="${2:?missing value for --schema}"; shift 2 ;;
    --json) json="${2:?missing value for --json}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "release-json-schema-validate: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$schema" || -z "$json" ]]; then
  echo "release-json-schema-validate: --schema and --json are required" >&2
  exit 2
fi
if [[ ! -f "$schema" ]]; then
  echo "release-json-schema-validate: missing schema $schema" >&2
  exit 1
fi
if [[ ! -f "$json" ]]; then
  echo "release-json-schema-validate: missing JSON $json" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "release-json-schema-validate: python3 is required" >&2
  exit 127
fi

python3 - "$schema" "$json" <<'PY'
import json
import sys

schema_path, json_path = sys.argv[1:3]
with open(schema_path, "r", encoding="utf-8-sig") as handle:
    schema = json.load(handle)
with open(json_path, "r", encoding="utf-8-sig") as handle:
    document = json.load(handle)

issues = []


def issue(path, message):
    issues.append(f"{path}: {message}")


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def resolve_ref(ref):
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported non-local $ref {ref}")
    current = schema
    for segment in ref[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        current = current[segment]
    return current


def validate(node_schema, value, path):
    if "$ref" in node_schema:
        validate(resolve_ref(node_schema["$ref"]), value, path)
        return

    if "const" in node_schema and value != node_schema["const"]:
        issue(path, f"expected const {node_schema['const']!r}")

    if "enum" in node_schema and value not in node_schema["enum"]:
        issue(path, f"expected one of {node_schema['enum']!r}")

    expected_types = node_schema.get("type")
    if isinstance(expected_types, str):
        expected_types = [expected_types]
    if expected_types:
        actual = json_type(value)
        if actual not in expected_types:
            issue(path, f"expected type {'/'.join(expected_types)}, got {actual}")
            return

    if isinstance(value, dict):
        required = node_schema.get("required", [])
        properties = node_schema.get("properties", {})
        for key in required:
            if key not in value:
                issue(path, f"missing required property {key}")
        if node_schema.get("additionalProperties") is False:
            allowed = set(properties)
            for key in value:
                if key not in allowed:
                    issue(path, f"additional property {key} is not allowed")
        for key, child_schema in properties.items():
            if key in value:
                validate(child_schema, value[key], f"{path}.{key}")

    if isinstance(value, list) and "items" in node_schema:
        for index, item in enumerate(value):
            validate(node_schema["items"], item, f"{path}[{index}]")


validate(schema, document, "$")

if issues:
    for message in issues:
        print(f"release-json-schema-validate: {message}", file=sys.stderr)
    sys.exit(1)

print("release-json-schema-validate: OK")
PY

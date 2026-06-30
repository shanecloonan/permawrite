#!/usr/bin/env bash
# Validate a staged public release-candidate archive.
set -euo pipefail

archive_dir=""
allow_dry_run=0

usage() {
  cat <<'EOF'
usage: release-archive-validate.sh --archive-dir DIR [--allow-dry-run]

Options:
  --archive-dir DIR   Staged release archive directory to validate.
  --allow-dry-run     Allow template/sample evidence files from release-archive-dry-run output.
EOF
}

while (($# > 0)); do
  case "$1" in
    --archive-dir)
      archive_dir="${2:?missing value for --archive-dir}"
      shift 2
      ;;
    --allow-dry-run)
      allow_dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "release-archive-validate: unknown argument $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$archive_dir" ]]; then
  echo "release-archive-validate: --archive-dir is required" >&2
  exit 2
fi
if command -v cygpath >/dev/null 2>&1 && [[ "$archive_dir" =~ ^[A-Za-z]:[\\/] ]]; then
  archive_dir="$(cygpath -u "$archive_dir")"
fi
if [[ ! -d "$archive_dir" ]]; then
  echo "release-archive-validate: missing archive directory $archive_dir" >&2
  exit 1
fi

archive_root="$(cd "$archive_dir" && pwd)"
issues=()

add_issue() {
  issues+=("$1")
}

relative_path() {
  python3 - "$archive_root" "$1" <<'PY'
import os
import sys

print(os.path.relpath(sys.argv[2], sys.argv[1]).replace("\\", "/"))
PY
}

is_private_looking() {
  local path="$1"
  local base
  base="$(basename "$path")"
  [[ "$base" =~ [Ww]allet|[Ss]eed|[Ss]ecret|[Aa][Pp][Ii][-_]?[Kk]ey|[Pp]rivate|[Cc]redential|peers\.json ]]
}

require_file() {
  local rel="$1"
  if [[ ! -f "$archive_root/$rel" ]]; then
    add_issue "missing required file: $rel"
  fi
}

test_directory_checksums() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0

  local files=()
  local path
  for path in "$dir"/*; do
    [[ -f "$path" ]] || continue
    [[ "$(basename "$path")" != "checksums.sha256" ]] || continue
    files+=("$(basename "$path")")
  done
  ((${#files[@]} > 0)) || return 0

  local rel_dir
  rel_dir="$(relative_path "$dir")"
  local checksum_file="$dir/checksums.sha256"
  if [[ ! -f "$checksum_file" ]]; then
    add_issue "missing checksum manifest: $rel_dir/checksums.sha256"
    return 0
  fi

  local expected_names=()
  local expected_hashes=()
  local file hash
  mapfile -t files < <(printf '%s\n' "${files[@]}" | sort)
  for file in "${files[@]}"; do
    hash="$(sha256sum "$dir/$file" | awk '{print tolower($1)}')"
    expected_names+=("$file")
    expected_hashes+=("$hash")
  done

  local seen=()
  local line_number=0
  local line parsed_hash parsed_name found
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    line="${line#$'\xef\xbb\xbf'}"
    line="${line%$'\r'}"
    [[ -n "${line//[[:space:]]/}" ]] || continue
    if [[ ! "$line" =~ ^([0-9a-fA-F]{64})[[:space:]]+([^/\\]+)$ ]]; then
      add_issue "invalid checksum line in $rel_dir/checksums.sha256:$line_number"
      continue
    fi
    parsed_hash="${BASH_REMATCH[1],,}"
    parsed_name="${BASH_REMATCH[2]}"
    parsed_name="${parsed_name#"${parsed_name%%[![:space:]]*}"}"
    parsed_name="${parsed_name%"${parsed_name##*[![:space:]]}"}"
    found=0
    for i in "${!expected_names[@]}"; do
      if [[ "${expected_names[$i]}" == "$parsed_name" ]]; then
        found=1
        if [[ "${expected_hashes[$i]}" != "$parsed_hash" ]]; then
          add_issue "checksum mismatch: $rel_dir/$parsed_name"
        fi
        seen+=("$parsed_name")
        break
      fi
    done
    if ((found == 0)); then
      add_issue "checksum references unknown file: $rel_dir/$parsed_name"
    fi
  done < "$checksum_file"

  local expected seen_name found_seen
  for expected in "${expected_names[@]}"; do
    found_seen=0
    for seen_name in "${seen[@]}"; do
      if [[ "$seen_name" == "$expected" ]]; then
        found_seen=1
        break
      fi
    done
    if ((found_seen == 0)); then
      add_issue "checksum missing file entry: $rel_dir/$expected"
    fi
  done
}

while IFS= read -r -d '' path; do
  rel="$(relative_path "$path")"
  if is_private_looking "$rel"; then
    add_issue "private-looking path is present: $rel"
  fi
done < <(find "$archive_root" -mindepth 1 -print0)

for required in \
  README.md \
  network/genesis.json \
  network/public_devnet_manifest.json \
  docs/TESTNET.md \
  docs/SECURITY.md \
  docs/PUBLIC_DEVNET_THREAT_MODEL.md \
  docs/OPERATORS.md \
  evidence/release-evidence-v1.schema.json \
  evidence/release-signoff-manifest-v1.schema.json; do
  require_file "$required"
done

if ((allow_dry_run)); then
  require_file "evidence/release-evidence-v1.sample.json"
  require_file "evidence/release-signoff-manifest-v1.sample.json"
  if [[ ! -f "$archive_root/evidence/release-artifact-inventory.md" && ! -f "$archive_root/evidence/release-artifact-inventory-template.md" ]]; then
    add_issue "missing dry-run inventory artifact: evidence/release-artifact-inventory.md or evidence/release-artifact-inventory-template.md"
  fi
else
  for required in \
    evidence/release-evidence.md \
    evidence/release-evidence.json \
    evidence/release-artifact-inventory.md \
    evidence/release-signoff-review.md \
    evidence/release-signoff-manifest.json \
    support/manifest.json; do
    require_file "$required"
  done
fi

test_directory_checksums "$archive_root"
while IFS= read -r -d '' dir; do
  test_directory_checksums "$dir"
done < <(find "$archive_root" -mindepth 1 -type d -print0)

if ((${#issues[@]} > 0)); then
  printf 'release-archive-validate: %s\n' "${issues[@]}" >&2
  exit 1
fi

echo "release-archive-validate: OK"

#!/usr/bin/env bash
# Stage public release-candidate archive artifacts without secrets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

output_dir=""
plan_only=0
include_binaries=0
release_evidence_md=""
release_evidence_json=""
support_bundle=""
signoff_review=""
signoff_manifest=""
audit_packet=""
inventory=""
include_release_schema_wheelhouse=0

usage() {
  cat <<'EOF'
usage: release-archive-dry-run.sh [options]

Options:
  --output-dir DIR              Parent directory for the staged archive.
  --plan-only                   Print the copy plan without writing files.
  --include-binaries            Require and stage local release binaries.
  --release-evidence-md FILE    Stage a reviewed Markdown evidence record.
  --release-evidence-json FILE  Stage a reviewed JSON evidence record.
  --support-bundle PATH         Stage a reviewed support bundle archive, or only manifest.json from a directory.
  --signoff-review FILE         Stage release-signoff-review output.
  --signoff-manifest FILE       Stage release-signoff-manifest output.
  --audit-packet FILE           Stage release-audit-packet output.
  --inventory FILE              Stage a filled release artifact inventory.
  --include-release-schema-wheelhouse
                                Stage hash-pinned release-schema wheels for air-gapped hosts.
EOF
}

while (($# > 0)); do
  case "$1" in
    --output-dir)
      output_dir="${2:?missing value for --output-dir}"
      shift 2
      ;;
    --plan-only)
      plan_only=1
      shift
      ;;
    --include-binaries)
      include_binaries=1
      shift
      ;;
    --release-evidence-md)
      release_evidence_md="${2:?missing value for --release-evidence-md}"
      shift 2
      ;;
    --release-evidence-json)
      release_evidence_json="${2:?missing value for --release-evidence-json}"
      shift 2
      ;;
    --support-bundle)
      support_bundle="${2:?missing value for --support-bundle}"
      shift 2
      ;;
    --signoff-review)
      signoff_review="${2:?missing value for --signoff-review}"
      shift 2
      ;;
    --signoff-manifest)
      signoff_manifest="${2:?missing value for --signoff-manifest}"
      shift 2
      ;;
    --audit-packet)
      audit_packet="${2:?missing value for --audit-packet}"
      shift 2
      ;;
    --inventory)
      inventory="${2:?missing value for --inventory}"
      shift 2
      ;;
    --include-release-schema-wheelhouse)
      include_release_schema_wheelhouse=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "release-archive-dry-run: unknown argument $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

short_commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [[ -z "$output_dir" ]]; then
  output_dir="${TMPDIR:-/tmp}/permawrite-release-archive-dry-run-$short_commit"
fi
archive_root="$output_dir/permawrite-public-devnet-dry-run-$short_commit"

is_private_looking() {
  local path="$1"
  local base
  base="$(basename "$path")"
  [[ "$base" =~ [Ww]allet|[Ss]eed|[Ss]ecret|[Aa][Pp][Ii][-_]?[Kk]ey|[Pp]rivate|[Cc]redential|peers\.json ]]
}

test_public_source() {
  local src="$1"
  local allow_public_genesis="${2:-0}"
  if [[ ! -e "$src" ]]; then
    echo "release-archive-dry-run: missing source $src" >&2
    exit 1
  fi
  if [[ "$allow_public_genesis" != "1" || "$(basename "$src")" != "public_devnet_v1.json" ]]; then
    if is_private_looking "$src"; then
      echo "release-archive-dry-run: refusing private-looking source $src" >&2
      exit 1
    fi
  fi
}

copy_public_file() {
  local src="$1"
  local dest="$2"
  local allow_public_genesis="${3:-0}"
  test_public_source "$src" "$allow_public_genesis"
  if ((plan_only)); then
    echo "PLAN copy $src -> $dest"
    return
  fi
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
}

write_directory_checksums() {
  local dir="$1"
  ((plan_only)) && return 0
  [[ -d "$dir" ]] || return 0
  local discovered=()
  local path
  for path in "$dir"/*; do
    [[ -f "$path" ]] || continue
    [[ "$(basename "$path")" != "checksums.sha256" ]] || continue
    discovered+=("$(basename "$path")")
  done
  ((${#discovered[@]} > 0)) || return 0
  mapfile -t files < <(printf '%s\n' "${discovered[@]}" | sort)
  ((${#files[@]} > 0)) || return
  : > "$dir/checksums.sha256"
  local file
  for file in "${files[@]}"; do
    sha256sum "$dir/$file" | awk -v name="$file" '{ print $1 "  " name }' >> "$dir/checksums.sha256"
  done
}

write_tree_checksums() {
  local dir="$1"
  ((plan_only)) && return 0
  [[ -d "$dir" ]] || return 0
  write_directory_checksums "$dir"
  local child
  while IFS= read -r -d '' child; do
    write_directory_checksums "$child"
  done < <(find "$dir" -mindepth 1 -type d -print0)
}

stage_release_schema_wheelhouse() {
  local archive_root_path="$1"
  local toolchain_dir="$archive_root_path/toolchain"
  local wheelhouse_dir="$toolchain_dir/wheelhouse-release-schema"
  local requirements_source="$SCRIPT_DIR/requirements-release-schema.txt"
  local helper
  for helper in \
    release-schema-wheelhouse.sh \
    release-schema-install-offline.sh \
    release-json-schema-draft202012.sh \
    release-json-schema-draft202012.py; do
    copy_public_file "$SCRIPT_DIR/$helper" "$toolchain_dir/$helper"
  done
  copy_public_file "$requirements_source" "$toolchain_dir/requirements-release-schema.txt"
  if ((plan_only)); then
    echo "PLAN download hash-pinned wheels -> toolchain/wheelhouse-release-schema"
    return 0
  fi
  mkdir -p "$wheelhouse_dir"
  local python="${PERMAWRITE_RELEASE_SCHEMA_PYTHON:-python3}"
  "$python" -m pip download --disable-pip-version-check --require-hashes \
    -r "$requirements_source" -d "$wheelhouse_dir"
  local wheel_count
  wheel_count="$(find "$wheelhouse_dir" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')"
  if ((wheel_count < 3)); then
    echo "release-archive-dry-run: expected at least 3 release-schema wheels, found $wheel_count" >&2
    exit 1
  fi
  echo "release-archive-dry-run: staged release-schema wheelhouse packages=$wheel_count"
}

stage_release_policy_toolchain() {
  local archive_root_path="$1"
  local toolchain_dir="$archive_root_path/toolchain"
  local helper
  for helper in \
    release-participant-smoke-policy-check.py \
    release-participant-smoke-policy-check.sh \
    release-participant-smoke-policy-check.ps1; do
    copy_public_file "$SCRIPT_DIR/$helper" "$toolchain_dir/$helper"
  done
  if ((plan_only)); then
    echo "PLAN stage participant smoke CI policy helpers -> toolchain/"
  else
    echo "release-archive-dry-run: staged participant smoke CI policy helpers"
  fi
}

echo "release-archive-dry-run: archive=$archive_root"
echo "release-archive-dry-run: public-only staging; private wallet, seed, API-key, credential, and peers.json sources are refused"

copy_public_file "mfn-node/testdata/public_devnet_v1.json" "$archive_root/network/genesis.json" 1
copy_public_file "mfn-node/testdata/public_devnet_v1.manifest.json" "$archive_root/network/public_devnet_manifest.json"
copy_public_file "docs/TESTNET.md" "$archive_root/docs/TESTNET.md"
copy_public_file "SECURITY.md" "$archive_root/docs/SECURITY.md"
copy_public_file "docs/PUBLIC_DEVNET_THREAT_MODEL.md" "$archive_root/docs/PUBLIC_DEVNET_THREAT_MODEL.md"
copy_public_file "scripts/public-devnet-v1/OPERATORS.md" "$archive_root/docs/OPERATORS.md"
copy_public_file "docs/release-evidence-v1.schema.json" "$archive_root/evidence/release-evidence-v1.schema.json"
copy_public_file "docs/release-evidence-v1.sample.json" "$archive_root/evidence/release-evidence-v1.sample.json"
copy_public_file "docs/release-signoff-manifest-v1.schema.json" "$archive_root/evidence/release-signoff-manifest-v1.schema.json"
copy_public_file "docs/release-signoff-manifest-v1.sample.json" "$archive_root/evidence/release-signoff-manifest-v1.sample.json"
copy_public_file "docs/release-audit-packet-v1.schema.json" "$archive_root/evidence/release-audit-packet-v1.schema.json"
copy_public_file "docs/release-audit-packet-v1.sample.json" "$archive_root/evidence/release-audit-packet-v1.sample.json"

if [[ -n "$inventory" ]]; then
  copy_public_file "$inventory" "$archive_root/evidence/release-artifact-inventory.md"
else
  copy_public_file "docs/RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md" "$archive_root/evidence/release-artifact-inventory-template.md"
fi
[[ -n "$release_evidence_md" ]] && copy_public_file "$release_evidence_md" "$archive_root/evidence/release-evidence.md"
[[ -n "$release_evidence_json" ]] && copy_public_file "$release_evidence_json" "$archive_root/evidence/release-evidence.json"
[[ -n "$signoff_review" ]] && copy_public_file "$signoff_review" "$archive_root/evidence/release-signoff-review.md"
[[ -n "$signoff_manifest" ]] && copy_public_file "$signoff_manifest" "$archive_root/evidence/release-signoff-manifest.json"
[[ -n "$audit_packet" ]] && copy_public_file "$audit_packet" "$archive_root/evidence/release-audit-packet.json"

if ((include_binaries)); then
  for binary in mfnd mfn-cli mfn-storage-operator; do
    copy_public_file "target/release/$binary" "$archive_root/binaries/local/$binary"
  done
fi

if [[ -n "$support_bundle" ]]; then
  test_public_source "$support_bundle"
  if [[ -d "$support_bundle" ]]; then
    manifest="$support_bundle/manifest.json"
    [[ -f "$manifest" ]] || { echo "release-archive-dry-run: support bundle directory is missing manifest.json" >&2; exit 1; }
    copy_public_file "$manifest" "$archive_root/support/manifest.json"
    if ((plan_only)); then
      echo "PLAN write support/support-bundle-source.txt"
    else
      cat > "$archive_root/support/support-bundle-source.txt" <<'EOF'
Support bundle directory source was not copied wholesale. Review, redact, compress, and place the approved public archive at support/support-bundle.zip.
EOF
    fi
  else
    ext="${support_bundle##*.}"
    if [[ "$ext" == "$support_bundle" ]]; then
      ext=""
    else
      ext=".$ext"
    fi
    copy_public_file "$support_bundle" "$archive_root/support/support-bundle$ext"
  fi
fi

if ((include_release_schema_wheelhouse)); then
  if ((plan_only == 0)); then
    mkdir -p "$archive_root"
  fi
  stage_release_schema_wheelhouse "$archive_root"
fi

if ((plan_only == 0)); then
  mkdir -p "$archive_root"
fi
stage_release_policy_toolchain "$archive_root"

if ((plan_only)); then
  echo "release-archive-dry-run: PLAN OK"
  exit 0
fi

mkdir -p "$archive_root"
cat > "$archive_root/README.md" <<EOF
# Permawrite Public-Devnet Release Archive Dry Run

Commit: $short_commit

This archive was assembled by \`release-archive-dry-run.sh\` from public release artifacts only. Treat it as a staging rehearsal until reviewers fill out the artifact inventory, attach release evidence, and explicitly approve any support-bundle archive.

Do not add wallet seeds, validator private seeds, RPC API keys, private \`peers.json\`, host credentials, or private operator notes to this directory.
EOF

write_tree_checksums "$archive_root"

echo "release-archive-dry-run: OK path=$archive_root"

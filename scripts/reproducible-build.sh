#!/usr/bin/env bash
# Reproducible Permawrite release build.
#
# Pins rustc 1.83.0, remaps the workspace path out of the binaries, and can
# compare two sha256sum manifests. Does not change consensus.
#
#   scripts/reproducible-build.sh --plan-only --epoch 1700000000 --target x86_64-unknown-linux-gnu
#   scripts/reproducible-build.sh --compare left.sha256 right.sha256
#   scripts/reproducible-build.sh --build --target x86_64-unknown-linux-gnu
set -euo pipefail

PINNED_RUSTC=1.83.0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EPOCH="${SOURCE_DATE_EPOCH:-}"
TARGET="${MFN_REPRO_TARGET:-x86_64-unknown-linux-gnu}"
MODE=plan

usage() {
  echo "usage: $0 --plan-only|--compare LEFT RIGHT|--build [--epoch N] [--target TRIPLE] [--root PATH]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) MODE=plan; shift ;;
    --build) MODE=build; shift ;;
    --compare)
      MODE=compare
      LEFT="${2:-}"
      RIGHT="${3:-}"
      if [[ -z "$LEFT" || -z "$RIGHT" ]]; then
        usage
        exit 2
      fi
      shift 3
      ;;
    --epoch) EPOCH="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --root) ROOT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$EPOCH" ]]; then
  if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse HEAD >/dev/null 2>&1; then
    EPOCH="$(git -C "$ROOT" log -1 --format=%ct)"
  else
    echo "pass --epoch or SOURCE_DATE_EPOCH" >&2
    exit 2
  fi
fi

flags="-D warnings --remap-path-prefix=${ROOT}=/permawrite -C target-cpu=generic -C debuginfo=0 -C incremental=false -C codegen-units=1"
case "$TARGET" in
  *linux*) flags="$flags -C link-arg=-Wl,--build-id=none" ;;
esac

print_plan() {
  echo "rustc=${PINNED_RUSTC}"
  echo "target=${TARGET}"
  echo "SOURCE_DATE_EPOCH=${EPOCH}"
  echo "CARGO_INCREMENTAL=0"
  echo "RUSTFLAGS=${flags}"
  echo "binary=mfnd"
  echo "binary=mfn-cli"
  echo "binary=mfn-storage-operator"
}

compare_manifests() {
  python3 - "$LEFT" "$RIGHT" <<'PY'
import sys
def load(path):
    out = {}
    for raw in open(path, encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) < 66:
            raise SystemExit(f"bad line in {path}")
        digest, name = line[:64], line[64:].lstrip(" *")
        if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            raise SystemExit(f"bad digest in {path}")
        if name.startswith("/") or ".." in name.split("/") or ".." in name.split("\\"):
            raise SystemExit(f"bad name {name}")
        out[name.replace("\\", "/")] = digest.lower()
    return out
left, right = load(sys.argv[1]), load(sys.argv[2])
bad = False
for name in sorted(set(left) - set(right)):
    print(f"only-left {name}")
    bad = True
for name in sorted(set(right) - set(left)):
    print(f"only-right {name}")
    bad = True
for name in sorted(set(left) & set(right)):
    if left[name] != right[name]:
        print(f"mismatch {name}")
        bad = True
if bad:
    raise SystemExit(1)
print(f"match artifacts={len(left)}")
PY
}

case "$MODE" in
  plan) print_plan ;;
  compare) compare_manifests ;;
  build)
    command -v rustc >/dev/null
    got="$(rustc --version)"
    case "$got" in
      *" ${PINNED_RUSTC}"*|*"${PINNED_RUSTC} "*) ;;
      *) echo "rustc is '$got'; reproducible builds pin ${PINNED_RUSTC}" >&2; exit 1 ;;
    esac
    export SOURCE_DATE_EPOCH="$EPOCH"
    export CARGO_INCREMENTAL=0
    export LC_ALL=C
    export TZ=UTC
    export RUSTFLAGS="$flags"
    print_plan
    cargo build --release --locked --target "$TARGET" --manifest-path "$ROOT/Cargo.toml" \
      -p mfn-node --bin mfnd \
      -p mfn-cli --bin mfn-cli \
      -p mfn-storage-operator --bin mfn-storage-operator
    stage="$ROOT/target/${TARGET}/release"
    (cd "$stage" && sha256sum mfnd mfn-cli mfn-storage-operator > checksums.sha256)
    echo "manifest=$stage/checksums.sha256"
    ;;
esac

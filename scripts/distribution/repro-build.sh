#!/usr/bin/env bash
# Reproducible release build.
#
# --plan-only   print the pinned toolchain and flags (no compile)
# --compare A B fail if two artifact directories differ
# --build       compile the three release binaries twice and compare them
#
# The double build is local and slow. CI does not run --build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRATE="$ROOT/distribution/repro"
MODE="${1:---plan-only}"

run_repro() {
  cargo run --quiet --manifest-path "$CRATE/Cargo.toml" -- "$@"
}

case "$MODE" in
  --plan-only|plan)
    run_repro plan "$ROOT"
    ;;
  --compare)
    if [[ $# -ne 3 ]]; then
      echo "usage: repro-build.sh --compare DIR_A DIR_B" >&2
      exit 2
    fi
    run_repro compare "$2" "$3"
    ;;
  --verify)
    if [[ $# -ne 3 ]]; then
      echo "usage: repro-build.sh --verify DIR CHECKSUMS" >&2
      exit 2
    fi
    run_repro verify "$2" "$3"
    ;;
  --build)
    export RUSTUP_TOOLCHAIN=1.83.0
    export SOURCE_DATE_EPOCH=0
    export CARGO_INCREMENTAL=0
    export CARGO_PROFILE_RELEASE_DEBUG=none
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    export CARGO_PROFILE_RELEASE_LTO=thin
    export TZ=UTC
    export LC_ALL=C
    flags="-D warnings --remap-path-prefix=${ROOT}=/permawrite -C symbol-mangling-version=v0"
    case "$(uname -s)" in
      Linux) flags="$flags -C link-arg=-Wl,--build-id=none" ;;
    esac
    export RUSTFLAGS="$flags"
    rustc_ver="$(rustc --version)"
    case "$rustc_ver" in
      *1.83.0*) ;;
      *)
        echo "repro-build: rustc must be 1.83.0, got: $rustc_ver" >&2
        exit 1
        ;;
    esac
    stage_a="$ROOT/target/repro-a"
    stage_b="$ROOT/target/repro-b"
    rm -rf "$stage_a" "$stage_b"
    mkdir -p "$stage_a" "$stage_b"
    build_once() {
      local dest="$1"
      local target_dir="$2"
      cargo build --release --locked \
        --target-dir "$target_dir" \
        -p mfn-node --bin mfnd \
        -p mfn-cli --bin mfn-cli \
        -p mfn-storage-operator --bin mfn-storage-operator
      cp "$target_dir/release/mfnd" "$dest/mfnd"
      cp "$target_dir/release/mfn-cli" "$dest/mfn-cli"
      cp "$target_dir/release/mfn-storage-operator" "$dest/mfn-storage-operator"
    }
    build_once "$stage_a" "$ROOT/target/repro-build-a"
    build_once "$stage_b" "$ROOT/target/repro-build-b"
    run_repro compare "$stage_a" "$stage_b"
    run_repro hash "$stage_a"
    ;;
  *)
    echo "usage: repro-build.sh [--plan-only|--compare A B|--verify DIR FILE|--build]" >&2
    exit 2
    ;;
esac

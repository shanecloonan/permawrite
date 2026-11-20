#!/usr/bin/env bash
# Build a release mfn-cli, write SHA256SUMS, and sign that file.
# People install the binary. They do not need a Rust toolchain.
#
#   bash scripts/release-pack.sh --self-test
#   SOURCE_DATE_EPOCH=1700000000 bash scripts/release-pack.sh --pack
#   SOURCE_DATE_EPOCH=1700000000 RELEASE_SIGNING_KEY=key.pem bash scripts/release-pack.sh --pack
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

recipe() {
  echo "recipe=cargo build --locked --release -p mfn-cli"
  echo "remap=--remap-path-prefix"
  echo "epoch=SOURCE_DATE_EPOCH"
}

write_checksum() {
  local bin="$1"
  local out="$2"
  local name
  name="$(basename "$bin")"
  mkdir -p "$out"
  cp "$bin" "$out/$name"
  # Touch to the epoch so the copied file's metadata is not part of the hash.
  # The hash is of the bytes only.
  (
    cd "$out"
    sha256sum "$name" > SHA256SUMS
  )
}

sign_sums() {
  local out="$1"
  local key="$2"
  openssl dgst -sha256 -sign "$key" -out "$out/SHA256SUMS.sig" "$out/SHA256SUMS"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  _release_pack_tmp="$tmp"
  trap 'rm -rf "$_release_pack_tmp"' EXIT
  printf 'permawrite-fixture' > "$tmp/mfn-cli"
  write_checksum "$tmp/mfn-cli" "$tmp/out"
  (cd "$tmp/out" && sha256sum -c SHA256SUMS)
  openssl req -new -x509 -newkey rsa:2048 -nodes \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -days 1 \
    -subj "/CN=permawrite-test" >/dev/null 2>&1
  sign_sums "$tmp/out" "$tmp/key.pem"
  openssl x509 -in "$tmp/cert.pem" -pubkey -noout > "$tmp/pub.pem"
  openssl dgst -sha256 -verify "$tmp/pub.pem" \
    -signature "$tmp/out/SHA256SUMS.sig" "$tmp/out/SHA256SUMS" >/dev/null
  recipe
  echo "release_pack=checksum-and-signature"
  echo "source_date_epoch=1700000000"
  echo "binary=mfn-cli"
}

pack() {
  if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    echo "SOURCE_DATE_EPOCH is required so the build does not embed today's clock." >&2
    exit 1
  fi
  export SOURCE_DATE_EPOCH
  export CARGO_INCREMENTAL=0
  export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${ROOT}=."
  recipe
  (
    cd "$ROOT"
    cargo build --locked --release -p mfn-cli
  )
  local out="$ROOT/dist/release"
  write_checksum "$ROOT/target/release/mfn-cli" "$out"
  if [[ -n "${RELEASE_SIGNING_KEY:-}" ]]; then
    sign_sums "$out" "$RELEASE_SIGNING_KEY"
    echo "signed=$out/SHA256SUMS.sig"
  else
    echo "signed=no (set RELEASE_SIGNING_KEY to sign SHA256SUMS)"
  fi
  echo "checksum=$out/SHA256SUMS"
  echo "source_date_epoch=$SOURCE_DATE_EPOCH"
}

case "${1:-}" in
  --self-test) self_test ;;
  --pack) pack ;;
  *)
    echo "usage: release-pack.sh --self-test | --pack" >&2
    exit 2
    ;;
esac

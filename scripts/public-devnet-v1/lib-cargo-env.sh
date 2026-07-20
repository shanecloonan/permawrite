# Source from VPS ops scripts so non-interactive shells find rustup cargo.
# shellcheck shell=bash
if [[ -f "${HOME}/.cargo/env" ]]; then
  # shellcheck source=/dev/null
  source "${HOME}/.cargo/env"
elif [[ -d "${HOME}/.cargo/bin" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "lib-cargo-env: cargo not found (expected ~/.cargo/bin after rustup)" >&2
  return 1 2>/dev/null || exit 1
fi
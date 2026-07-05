#!/usr/bin/env bash
# Public-devnet participant preflight for Linux/macOS operators.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
TOOLCHAIN_RECOVERY="See scripts/public-devnet-v1/OPERATORS.md#toolchain-recovery"
STRICT=0
HAS_FAILURES=0
HAS_WARNINGS=0

usage() {
  cat <<'EOF'
usage: preflight.sh [--strict]

Checks required public-devnet tools, optional helper runtimes, release binaries,
running mfnd processes, and local devnet port discovery.

Options:
  --strict    treat warnings as failures for CI/push preparation
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      STRICT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "preflight: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

add_check() {
  local name="$1" status="$2" message="$3" fix="${4:-}"
  echo "preflight: status=$status check=$name message=$message"
  if [[ -n "$fix" ]]; then
    echo "preflight: fix=$fix"
  fi
  if [[ "$status" == "fail" ]]; then
    HAS_FAILURES=1
  elif [[ "$status" == "warn" ]]; then
    HAS_WARNINGS=1
  fi
}

add_command_check() {
  local name="$1" purpose="$2" required="$3" fix="$4"
  if command -v "$name" >/dev/null 2>&1; then
    add_check "$name" ok "$purpose available at $(command -v "$name")"
  elif [[ "$required" == "required" ]]; then
    add_check "$name" fail "$purpose is not on PATH" "$fix"
  else
    add_check "$name" warn "$purpose is not on PATH" "$fix"
  fi
}

add_release_binary_check() {
  local name="$1" build_command="$2"
  local path="$REPO_ROOT/target/release/$name"
  if [[ -x "$path" ]]; then
    add_check "$name" ok "release binary exists at $path"
  else
    add_check "$name" warn "release binary is missing at $path" "Run: $build_command"
  fi
}

add_mfnd_process_check() {
  local pids=""
  if command -v pgrep >/dev/null 2>&1; then
    pids="$(pgrep -x mfnd 2>/dev/null | tr '\n' ',' | sed 's/,$//' || true)"
  fi
  if [[ -z "$pids" ]]; then
    add_check "mfnd processes" ok "no running mfnd processes detected"
  else
    add_check "mfnd processes" warn "running mfnd processes detected: pids=$pids" "Run scripts/public-devnet-v1/stop-all.sh --dry-run, then stop recorded devnet PIDs before release rebuilds or CI; use --all-mfnd only for stale daemons."
  fi
}

add_ports_file_check() {
  if [[ -f "$PORTS_FILE" ]]; then
    add_check "devnet-ports.env" ok "found $PORTS_FILE"
  else
    add_check "devnet-ports.env" warn "no devnet-ports.env found; helper scripts need --rpc or a started local mesh" "Run start-all.sh or pass --rpc HOST:PORT to wallet/demo helpers."
  fi
}

add_command_check cargo "Rust package manager" required "Install Rust stable from https://rustup.rs/ and reopen the shell."
add_command_check rustc "Rust compiler" required "Install Rust stable from https://rustup.rs/ and reopen the shell."
add_command_check git "Git client" required "Install Git and reopen the shell."
add_command_check node "CODEBASE_STATS.md generator runtime" optional "Install Node.js or expose node on PATH before regenerating CODEBASE_STATS.md. $TOOLCHAIN_RECOVERY."
add_command_check nc "JSON-RPC health-check transport" optional "Install netcat (nc) before running health-check.sh against a local mesh. $TOOLCHAIN_RECOVERY."
add_command_check python3 "permanence-demo.sh sample-payload fallback and support-bundle.sh manifest writer" optional "Install python3, pass --payload to permanence-demo.sh, or run the PowerShell support bundle on Windows. $TOOLCHAIN_RECOVERY."
add_command_check wasm-pack "WASM package test runner used by the local CI mirror" optional "Install with: cargo install wasm-pack --locked. $TOOLCHAIN_RECOVERY."
add_command_check wasm-opt "Binaryen optimizer invoked by wasm-pack during the local CI mirror wasm32 build" optional "Install Binaryen and expose wasm-opt on PATH (see scripts/public-devnet-v1/OPERATORS.md#toolchain-recovery). $TOOLCHAIN_RECOVERY."
add_command_check cargo-audit "dependency advisory scanner used by the local CI mirror" optional "Install with: cargo install cargo-audit --locked. $TOOLCHAIN_RECOVERY."
add_release_binary_check mfnd "cargo build -p mfn-node --release --bin mfnd"
add_release_binary_check mfn-cli "cargo build -p mfn-cli --release --bin mfn-cli"
add_release_binary_check mfn-storage-operator "cargo build -p mfn-storage-operator --release --bin mfn-storage-operator"
add_mfnd_process_check
add_ports_file_check

if (( HAS_FAILURES || (STRICT && HAS_WARNINGS) )); then
  if (( STRICT && HAS_WARNINGS && ! HAS_FAILURES )); then
    echo "preflight: result=warn strict=true"
  else
    echo "preflight: result=fail"
  fi
  exit 1
fi

if (( HAS_WARNINGS )); then
  echo "preflight: result=warn"
else
  echo "preflight: result=ok"
fi

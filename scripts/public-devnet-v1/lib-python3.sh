#!/usr/bin/env bash
# B-144: resolve python3 for MSYS/Windows hosts where only `python` is installed.
# shellcheck shell=bash

mfn_require_python3() {
  if command -v python3 >/dev/null 2>&1; then
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    return 0
  fi

  local cand=""
  local probe
  for probe in \
    "/c/Users/shane/AppData/Local/Programs/Python/Python312/python.exe" \
    "/c/Users/${USER:-}/AppData/Local/Programs/Python/Python312/python.exe" \
    "/c/Users/${USERNAME:-}/AppData/Local/Programs/Python/Python312/python.exe" \
    "/c/Python312/python.exe"; do
    if [[ -n "$probe" && -x "$probe" ]]; then
      cand="$probe"
      break
    fi
  done

  if [[ -z "$cand" ]] && command -v cmd.exe >/dev/null 2>&1; then
    cand="$(cmd.exe /c where python 2>/dev/null | tr -d '\r' | head -1 || true)"
  fi

  if [[ -n "$cand" && -f "$cand" ]]; then
    export MFN_PYTHON3_BIN="$cand"
    # Prefer PATH shim so `python3 - <<'PY'` and `python3 -c` work.
    mkdir -p /tmp/mfn-py-shim
    cat > /tmp/mfn-py-shim/python3 <<EOF
#!/bin/bash
exec "\$MFN_PYTHON3_BIN" "\$@"
EOF
    chmod +x /tmp/mfn-py-shim/python3
    export PATH="/tmp/mfn-py-shim:$PATH"
    return 0
  fi

  echo "mfn_require_python3: need python3 or python on PATH" >&2
  return 1
}

mfn_resolve_release_bin() {
  local base="$1"
  if [[ -x "$base" ]]; then
    printf '%s\n' "$base"
    return 0
  fi
  if [[ -x "${base}.exe" ]]; then
    printf '%s\n' "${base}.exe"
    return 0
  fi
  printf '%s\n' "$base"
}
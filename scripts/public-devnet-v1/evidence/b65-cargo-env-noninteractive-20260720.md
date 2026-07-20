# B-65 — cargo on PATH for VPS non-interactive builds (2026-07-20)

## Problem

`vps-prebuild-mfnd.sh --apply` via `nohup`/`ssh` non-login shell failed:

```text
cargo: command not found
```

Rustup installs to `~/.cargo/bin`; that directory is only on PATH after sourcing `~/.cargo/env` (login shells).

## Fix

- `lib-cargo-env.sh` — source `~/.cargo/env` or prepend `~/.cargo/bin`
- Wired into `vps-prebuild-mfnd.sh` and `vps-roll-mfnd.sh` before `cargo build`

## Note

Does not restart services. Re-run prebuild after land so B-63/B-64 bins exist before CI-GREEN roll.

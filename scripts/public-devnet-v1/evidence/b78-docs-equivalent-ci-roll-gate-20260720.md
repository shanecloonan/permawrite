# B-78 — Docs-equivalent CI roll gate (2026-07-20)

## Problem

JOIN docs thrash (lane 3) and board `[skip ci]` / docs commits leave latest CI `in_progress`/`cancelled` while an ancestor GREEN already proved the Rust tree. `assert-vps-roll-ready` / `vps-roll-mfnd` refused rolls, forcing `MFN_ROLL_ALLOW_RED_CI=1` (B-77).

## Fix

`lib-ci-roll-gate.sh`:
1. Latest CI completed+success → OK (head).
2. Else find recent GREEN ancestor of HEAD; if `git diff` since that SHA touches no protocol paths (`mfn-*/src/*`, Cargo*, workflows, toolchain) → OK (docs-equivalent).
3. Else fail closed.

Wired into `assert-vps-roll-ready.sh` and `vps-roll-mfnd.sh`. Rehearsal smoke needles updated.

## Proof (VPS)

While CI `#29742419169` was `in_progress` on docs head:

```
mfn_ci_roll_gate: OK #29739903305 62a9c02 docs-equivalent
assert-vps-roll-ready: READY
```
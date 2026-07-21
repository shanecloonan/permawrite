# B-96 outside-in invite soak pin assert (2026-07-21)

## Summary

Lane 1 hardens B-27 soak evidence so archives must pin green Nightly + CI run IDs.
Assert fails closed without `# nightly_run=` / `# ci_run=`. Soak fails closed if `gh` cannot resolve pins (override: `MFN_B27_ALLOW_UNPINNED=1`).

| Field | Value |
| --- | --- |
| Tooling | `assert-outside-in-invite-soak-evidence.{sh,ps1}` + soak fail-closed |
| Evidence | `outside-in-invite-soak-20260721T022948Z.txt` |
| Assert | `assert-outside-in-invite-soak-evidence: OK` |
| Proxy | `http://5.161.201.73:8787/rpc` |
| Tip | 4820 -> 4822 (delta=2) |
| Genesis | `454fa5d4...a005` (public_devnet_v1) |
| Head at capture | `665c166` (B-95) |
| Nightly pin | `#29790006106` GREEN |
| CI pin | `#29793832972` GREEN |

## B-15 safety

Read-only public proxy. Never restarts faucet-http / mfnd; never runs JOIN.

## Remaining for full gate close

Invite-path participant half after lane-3 formal JOIN archive assert, unless waived in favor of Nightly participant + this soak + JOIN SUMMARY.

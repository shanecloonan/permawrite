# B-27 outside-in invite-head soak (2026-07-20)

## Summary

Lane 1 successor soak for invite-head liveness on the **live systemd** public testnet (classic `vps-internet-soak.sh` expects `start-all` `devnet-ports.env` PIDs — not the Hetzner systemd topology).

| Field | Value |
| --- | --- |
| Tooling | `outside-in-invite-soak.ps1` / `.sh` |
| Evidence | `outside-in-invite-soak-20260720T155203Z.txt` |
| Assert | `assert-outside-in-invite-soak-evidence: OK` |
| Proxy | `http://5.161.201.73:8787/rpc` |
| Tip | 4501 → 4503 (delta=2 over 5×40s samples) |
| Genesis | `454fa5d4…42a005` (public_devnet_v1) |
| Head at capture | `a84614d` (B-29 close; includes B-75) |
| Nightly pin | `#29755942849` GREEN (participant+observer+ignored P2P) |
| CI pin | `#29753244727` GREEN on B-75 `9d8bd30` |

## B-15 safety

Read-only public proxy. Never restarts `faucet-http` / mfnd; never runs JOIN.

## Remaining for full B-27 close

Live invite-path participant half (fund→upload→restore→prove) after lane-3 **B-15** formal archive assert, unless waived in favor of Nightly participant + this soak + JOIN SUMMARY.

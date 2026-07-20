# B-27 outside-in invite-head soak refresh (2026-07-20)

## Summary

Lane 1 refreshed the invite-head soak on the live public observer proxy (B-15-safe; never faucet/mfnd/JOIN). Tip advanced 4663 -> 4665 over 5 samples.

| Field | Value |
| --- | --- |
| Tooling | outside-in-invite-soak.ps1 / .sh |
| Evidence | outside-in-invite-soak-20260720T211608Z.txt |
| Assert | ssert-outside-in-invite-soak-evidence: OK |
| Proxy | http://5.161.201.73:8787/rpc |
| Tip | 4663 -> 4665 (delta=2) |
| Genesis | 454fa5d4...a005 (public_devnet_v1) |
| Head at capture | e460b2 (includes B-34) |
| Nightly pin | #29779143837 GREEN — participant + observer + ignored P2P/produce |
| CI pin | #29777008854 GREEN on B-34 c752992 |

## B-15 safety

Read-only public proxy. Never restarts aucet-http / mfnd; never runs JOIN.

## Remaining for full B-27 close

Invite-path participant half (fund -> upload -> restore -> prove) after lane-3 formal JOIN archive assert, unless waived in favor of Nightly participant + this soak + JOIN SUMMARY.

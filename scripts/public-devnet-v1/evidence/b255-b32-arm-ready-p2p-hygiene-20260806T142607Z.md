# B-255 B-32 arm-ready + p2p-forward hygiene (2026-08-06)

## Unit
Lane 7: extend `assert-b32-arm-ready.sh` with B-254-class p2p-forward hygiene before day-of multi-op packs.

## Live prove (Hetzner 5.161.201.73)
- tip_height=16328 (flat 8s WARN — slow seal OK)
- peers-clean OK
- B-71 persistable-peer marker OK
- CI roll gate OK (docs-equivalent; tip CI #31109005252 noted in_progress on VPS)
- uploads_total=93 recent_proven=8
- p2p-forward@ failed_units_clean
- mfn-p2p-forward-hub / 19002 / 19003 / 19004 **active**
- distinct_hosts=1 hosts=5.161.201.73 → **NOT READY** (honest; need MFN_B32_OPERATOR_HOSTS>=2)
- F62 block-log: get_block_ok tip=16327 (observer RPC); PASS without data-dir

## Never
faucet-http restart, mfnd restart, join-testnet-rehearsal, fake READY

## Verdict
B-255 tooling + live hygiene PASS; B-32 still blocked on 2nd distinct host.
# B-254 — public-testnet health fail-closed on p2p-forward@ templates (2026-08-06)

## Why

B-253 showed JOIN operators can misread systemctl --failed mfn-p2p-forward@* as a seed outage. Health assert must fail closed on that class of false alarm and require dedicated B-41 forwards.

## Change

ssert-public-testnet-health.sh:
- plan unit B-91+B-254
- FAIL if any mfn-p2p-forward@ is in failed units (hint: scrub script)
- require mfn-p2p-forward-hub + 19002/19003/19004 active
- rehearsal smoke needles (.sh / .ps1) + OPERATORS

## Prove (Hetzner)

`
assert-public-testnet-health: tip=16326 ckpt_max=16321 lag=5 threshold=16
p2p-forward@ failed_units_clean
mfn-p2p-forward-hub.service active
mfn-p2p-forward-19002.service active
mfn-p2p-forward-19003.service active
mfn-p2p-forward-19004.service active
OK
`

B-15-safe (no mfnd/faucet/proxy restart).

# B-253 — scrub failed mfn-p2p-forward@ templates + F114 hub prove (2026-08-06)

## Symptom

systemctl --failed showed three failed units:
- mfn-p2p-forward@19001 / @19003 / @19004

Those came from a leftover template mapping %i -> 127.0.0.1:%i (same public port). Live seeds stayed OPEN via dedicated units mfn-p2p-forward-hub / 19002 / 19003 / 19004 (1900x->1910x). Failed list looked like a P2P outage during B-15 JOIN.

## Fix (B-15-safe)

scrub-failed-p2p-forward-templates.sh --apply:
- disable/reset failed @ instances
- remove broken mfn-p2p-forward@.service template
- keep dedicated forwards; never restart mfnd/faucet

Also wired into 
epair-vps-p2p-binds.sh for future full applies + rehearsal smoke needles.

## Prove (Hetzner)

`
scrub-failed-p2p-forward-templates: hub_tip=16323 F114_hub_rpc=ok
seed 5.161.201.73:19001 OPEN
seed 5.161.201.73:19002 OPEN
seed 5.161.201.73:19003 OPEN
failed_units_clean
faucet ok busy=False pending=0
OK
`

Closes §6 F114 Ack (hub RPC reachable for faucet target without restart).

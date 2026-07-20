# B-15 JOIN_TESTNET outside-in SUMMARY (DRAFT) - 2026-07-20

**Status:** DRAFT - not yet archive-assert PASS. Cite live evidence waves 6-20 under scripts/public-devnet-v1/evidence/live-testnet-probe-20260720-wave*.md.
**Lane:** 3
**Network:** public-devnet-v1 / genesis 454fa5d4...a005
**Public endpoints:** seeds 5.161.201.73:19001-19003; RPC proxy http://5.161.201.73:8787/rpc; faucet http://5.161.201.73:8788; FE http://5.161.201.73:3000 (+ /testnet)

## What a new joiner can do today (proven on live tip)

| Capability | Evidence | Notes |
| --- | --- | --- |
| Dial seeds / sync observer | waves 6-7, B-41, B-68 tip restore | Prefer local mfnd + seed dials; compare tip_id to proxy |
| Faucet F7 dual-send (1e6 / owned=2) | alice, bob, carol, frank, heidi, ivan, judy, karl | ~90-130s; IP cooldown 429 after success |
| Peer dual-send when faucet cools | judy->lisa (wave20) | Works; still need owned>=2 for upload |
| Soft checkpoint bootstrap | frank soft_rc=0; Windows .ps1 -Apply (F68b) | JOIN-safe path |
| Hard light-scan --checkpoint-log at live tip | F45 FAIL while ckpt max << tip | Blocked until near-tip attestation |
| Transfer (send) | alice->bob, grace<->dave, etc. | Need >=2 inputs (F75) |
| Upload + SPoRA prove | heidi/ivan/judy/karl (+ earlier) | Bound authorship via upload --message |
| Retrieve local artifact | multiple waves | 64B samples OK |
| Authorship claims for / claims recent | karl wave19/20 | Recent index can lag minutes (F86) |

## New-wallet permanence loops (public tip)

| Wallet | Fund | F71 after faucet? | Bound upload | last_proven |
| --- | --- | --- | --- | --- |
| heidi | faucet | no | yes | ~4200 (wave15) |
| ivan | faucet | yes | yes | 4217 |
| judy | faucet | no | yes | 4229 |
| karl | faucet | yes | yes | 4270 |
| lisa | peer | n/a | CLI Fresh only | not public (F88 local fork) |
| mike | faucet+peer | n/a | yes | **4304** (wave21; proxy verified) |
| nina | faucet+peer | n/a | yes | **4318** (wave22; proxy verified) |
| oscar | peer+faucet | n/a | yes | **4337** (wave23; proxy verified) |

Seven wallets with public last_proven: heidi/ivan/judy/karl/mike/nina/**oscar**. Lisa excluded (F88). Runbook: F88b tip_id wait, F89 /faucet, F90 re-scan after receive.

## Hard findings operators must know

1. **F45** - Hard checkpoint-log scan needs attestation at exact tip; use soft bootstrap.
2. **F67/F79** - Pin height too high hides older UTXOs; pin <= oldest fund height.
3. **F71** - Intermittent trusted N vs checkpoint 0 after faucet/spend; re-pin recovers.
4. **F74/F88** - Local tip_id diverge / session_count=0 -> wipe+resync; never trust Fresh upload on divergent tip.
5. **F75/F76** - Need owned>=2; faucet done may precede visible owned=2 by a tip.
6. **F78** - Stale pending_spent_utxo_keys hides balances after re-pin - clear on pin.
7. **F85** - Local RPC wedges under concurrent snapshot/pin; serialize + restart.
8. **F86** - claims recent may lag; use claims for DATA_ROOT after settle.
9. **F87** - Probe tooling can corrupt wallets if dumping path string - assert dict before write.

## Still open before formal archive PASS

- [x] Local observer tip_id == proxy tip_id after wave21 wipe/resync
- [x] Mike new-wallet loop post-B-68 with proxy-visible last_proven=4304
- [ ] Near-tip checkpoint (reduce F45 lag) - lane 7
- [ ] Formal join-testnet-rehearsal SUMMARY transcript + assert script green
- [ ] Human sign-off per TESTNET_CHECKLIST

## Recommended JOIN runbook (Windows outside-in)

1. Start local observer dialing all three seeds; wait until tip_id matches proxy.
2. wallet new -> bootstrap-wallet-from-checkpoint-log.ps1 -Apply (soft).
3. Pin at bootstrap height; faucet fund; if F71, re-pin; wait owned=2.
4. wallet upload FILE --message "..." -> poll uploads status and proxy list_recent_uploads.
5. operator challenge / operator prove -> confirm last_proven.
6. claims for <data_root>; optionally claims recent after lag.
7. Do not restart faucet-http / run parallel Hetzner JOIN during evidence windows.

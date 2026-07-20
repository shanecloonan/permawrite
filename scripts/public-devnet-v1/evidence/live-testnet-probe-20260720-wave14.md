# Live public testnet probe — wave 14 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~04:55Z–05:15Z
**Prior:** wave13 3bb6de7
**Tip:** **4179 → 4188**
**Checkpoint max:** **4173** (entries=10; lag ~6–15)

## Executive verdict

| Gate | Result |
| --- | --- |
| F68b frank re-Apply | **PASS** — soft F45; pin@4173 |
| Frank POST /faucet dual-send | **PASS** — job 3a62ec8c… done in ~190s; 2 tx ids |
| Frank receive verify (2 UTXOs) | **PASS after tip+1** — first saw 500k/owned=1; at tip 4182 → **1e6/owned=2** (F76) |
| Grace upload with 1 UTXO | **FAIL F75** — input count 1 < consensus minimum 2 |
| Faucet re-fund grace | **429** IP cooldown (expected) |
| Frank upload 64B | **PASS** Fresh tx 97246bb9…; commitment 90aae951… |
| Frank local challenge/prove immediate | **FAIL then OK on chain** — unknown commitment until indexed; last_proven_height=**4183** matched without successful local prove RPC (F77) |
| Grace post-pin false poverty | **PASS after F78 fix** — pending_spent hid UTXOs; clear → **940000**/owned=2 |
| Dave send 50k → grace | **PASS** Fresh 505cc1f… |
| Tip local vs proxy | **PASS** — matched through 4184+ (no F74 recur) |

## Finding F75 — F7 uniform-tier floor blocks single-UTXO spend/upload

Grace after wave13 transfer held **one** change UTXO (890k). Upload failed:

`	ext
mempool admit: tx invalid … input count 1 < consensus minimum 2 (uniform-tier anti-fingerprinting floor)
`

**JOIN implication:** faucet F7 dual-send is not optional cosmetics — a wallet that consolidates to 1 owned output cannot upload/send until it receives another UTXO (peer transfer or second faucet after cooldown). Document in JOIN Step after first spend.

## Finding F76 — second faucet UTXO lags one tip / cache

Faucet job reported done with two tx_ids and 	otal_amount=1000000, but immediate wallet balance showed **500000/owned=1**. After tip advanced 4181→4182 (and light-scan), balance became **1000000/owned=2**.

**JOIN implication:** receive-verify must wait for owned_count>=2 (or total_amount), not merely job done.

## Finding F77 — upload indexed asynchronously on local observer

Right after frank upload Fresh, operator challenge / prove returned:

`	ext
rpc error -32602: unknown storage commitment 90aae951…
`

Within ~24–36s, uploads status moved local_only → matched with **last_proven_height=4183** (tip ~4183). Local prove RPC was never green in this wave; hub/network settlement still advanced last_proven.

**JOIN implication:** challenge/prove immediately after upload can false-fail; poll uploads status until commitment is known / proven.

## Finding F78 — stale pending_spent_utxo_keys hides real UTXOs after re-pin

After dave→grace send + re-pin, grace showed **50000/owned=1** while wallet scan --json reported **pending_spent_count=3**. Clearing pending_spent_utxo_keys (+ owned cache) and re-pin@4173 restored **940000/owned=2** (890k change + 50k receive).

Same class risk as F71: recovery pins that do not clear pending-spent create false “lost funds” reports.

**Ask lane 5:** should re-pin / bootstrap clear or reconcile pending_spent_utxo_keys automatically?

## Frank permanence log

| Step | Result |
| --- | --- |
| faucet | job done; txs 8df7f94…, c02dfb93… |
| upload | Fresh; tip 4182; fee 1003; commitment 90aae951d1316320dc61edd4def54dcb7a2a5161dae7ecce44eeac7af866d132 |
| last_proven | **4183** (matched) |
| balance after recover | **998997** / owned=2 |

## B-15 status

Outside-in loop reinforced: bootstrap -Apply → faucet → wait owned≥2 → upload → poll uploads status for last_proven. Remaining for SUMMARY archive: run soft JOIN rehearsal without Hetzner parallel jobs; keep F75/F76/F78 in participant docs.

## Continuity

- Eve 129a34ce… still last_proven **4156** (visible as chain_only from frank wallet index)
- Alice 20fcb43… still **4071** (F70)
- Do not commit wallets / live-testnet-data*

## Addendum (same session, post-6ead0f0)

### Grace upload after F78 recovery — PASS

With owned_count=2 / balance=940000, grace upload Fresh:

| Field | Value |
| --- | --- |
| tx_id | 376d00bb7f2cc13f701e02ef6200c6c000bc6542479799cca4936d412eac0346 |
| commitment | 3e728a8e91d97916efd18c5fa6cac9fdf6a56d8fec1823a5964f5ad3e60cd40c |
| tip | 4188 |
| fee | 1003 |

Confirms F75 root cause was single-input floor, not permanence path.

### Finding F79 — pin-too-high hides pre-pin UTXOs (F67 inverse)

Dave balance after tip-near pins (4173/4148/4159/4170): **90000**/owned=1. Pin at **4050** + clear pending/owned: **1090000**/owned=3.

Light-scan starts at pin height; UTXOs created **at or before** the pin are invisible. Near-tip re-pins after F71 recovery can strand older outputs and look like lost funds.

**JOIN rule:** recovery pin must be ≤ oldest expected receive height (checkpoint log max used for bootstrap is fine for new wallets; for aged wallets prefer earliest known fund tip or genesis-adjacent trusted checkpoint).


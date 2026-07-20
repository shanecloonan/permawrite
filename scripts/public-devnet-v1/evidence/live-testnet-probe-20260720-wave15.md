# Live public testnet probe — wave 15 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~05:22Z–05:37Z
**Prior:** wave14 36c4e91 / open d8b1d0
**Tip:** **4191 → 4200**
**Checkpoint max:** **4173** (lag ~18–27; entries=10; verify PASS)

## Executive verdict

| Gate | Result |
| --- | --- |
| Tip soak (6×10s) | **PASS** — deltas ∈ {-1,0}; tip_ids match when heights equal |
| FE / /testnet | **PASS** HTTP 200 (~30 KB) |
| Faucet /health | **PASS** tip 4192, busy=false |
| Checkpoint-log verify | **PASS** max_tip=4173, 10 entries, 2 signers |
| F78/F79 wallet recover | **PASS** — grace 938997/2; dave 1.09M/3 @pin4050; eve 938997/1; frank 998997/2 |
| F45 hard --checkpoint-log | **FAIL** exit 1 — no attestation at tip 4195 (log max 4173) |
| F68b soft -Apply | **PASS** f45-soft |
| Retrieve frank/grace/eve | **PASS** 64B each; last_proven 4183 / 4190 / 4156 |
| Heidi new → pin@4173 → faucet | **PASS** job ce5b4b0… ~180s; F76 lag then **1e6/owned=2** |
| Heidi upload | **PASS** Fresh e4ed5afa…; commitment c56e1c69… |
| Heidi last_proven | **PASS** → **4200** matched (~90s; F77 local_only then matched) |
| Frank → heidi 25000 | **PASS** Fresh tx 2178cc31… |

## Tip health (F74 watch)

| Sample | local | proxy | delta | tip_id equal @ same h |
| --- | --- | --- | --- | --- |
| 0 | 4192 | 4191 | -1 | n/a |
| 1–3 | 4192 | 4192 | 0 | **True** |
| 4–5 | 4193 | 4192 | -1 | n/a |

Local occasionally seals 1 height ahead of the public proxy; when heights match, tip_ids match. No quarantine/wipe needed this wave.

## F45 vs soft path (lag ~22)

Hard JOIN command still fails while tip races:

`	ext
…checkpoints.jsonl has no attestation at tip_height 4195
`

Bootstrap soft path remains the workable Windows JOIN gate (PASS f45-soft). **Ask lane 7:** Path A republish near tip (B-22) if hard exit 0 is required for SUMMARY.

## Wallet hygiene reconfirm

| Wallet | Pin | Balance | Owned | Notes |
| --- | --- | --- | --- | --- |
| grace | 4173 + clear pending | 938997 | 2 | upload change recovered (F78) |
| dave | **4050** | 1090000 | 3 | near-tip pin still hides stack (F79) |
| eve | 4148 + clear pending | 938997 | 1 | F75: cannot upload until 2nd UTXO |
| frank | catch-up | 998997 | 2 | soft Apply preserves funds |
| heidi | 4173 then faucet | 1000000 | 2 | new participant path |

## Permanence: retrieve + new upload

Local artifact retrieve (no HTTP backfill needed):

| Wallet | commitment | retrieve | last_proven |
| --- | --- | --- | --- |
| frank | 90aae951… | ok 64B | **4183** |
| grace | 3e728a8e… | ok 64B | **4190** |
| eve | 129a34ce… | ok 64B | **4156** |
| heidi | c56e1c69… | (new) | **4200** |

Heidi prove timeline: samples 0–8 local_only / null last_proven; sample 9 matched **4200**. Reinforces F77 — wait on uploads status, not immediate operator challenge.

## Heidi outside-in loop (JOIN-shaped)

1. wallet new → address mfff5ccd…
2. pin get_light_snapshot(4173) + clear caches
3. POST /faucet → job done (~180s), dual txs
4. balance first **500k/1** then tip+1 → **1e6/2** (F76)
5. wallet upload Fresh at tip 4199
6. poll until last_proven **4200**
7. receive frank transfer 25k (tx 2178cc31…)

This is the strongest single-wallet JOIN rehearsal evidence since wave12, without Hetzner parallel rehearsal (§6).

## Transfer

| From → to | Amount | tx | Outcome |
| --- | --- | --- | --- |
| frank → heidi | 25000 | 2178cc31ae62482759137592871e793521ba24b4690aca99c5856ca00ea5423f | Fresh; frank owned→0 until re-pin (F71 class) |

## B-15 status

| Step | Wave15 |
| --- | --- |
| Sync + tip-diff | PASS |
| Checkpoint verify | PASS |
| Windows soft bootstrap | PASS |
| Hard F45 exact-tip | FAIL (lag 22) |
| New wallet fund+receive | PASS (heidi) |
| Upload+settle | PASS (heidi last_proven 4200) |
| Retrieve prior uploads | PASS |
| Formal SUMMARY archive file | Still open — content now sufficient to draft |

**Recommendation:** draft join-testnet-rehearsal SUMMARY from heidi loop + soft F45; keep hard --checkpoint-log as soft-fail until B-22 catches tip.

## Artifacts (local only)

- user-wallet/heidi.json (+ upload-artifacts)
- _wave15-heidi-faucet.json, _wave15-heidi-upload.json, _wave15-frank-to-heidi.json
- _wave15-retrieve-{frank,grace,eve}.bin


## Finding F80 — post-pin balance can lag tip by one block

Immediately after pin_clean@4173 following frank→heidi send, both wallets reported **998997/owned=2** while tip was 4200–4201. Mempool empty; tx 2178cc31… already in **block 4201**.

One more wallet light-scan to tip 4201 corrected:

| Wallet | Correct balance | Owned | Notes |
| --- | --- | --- | --- |
| frank | **963997** | 1 | 998997 − 25000 − 10000 |
| heidi | **1023997** | 3 | 25k receive + 997997 change + **1000** upload anchor UTXO |

**JOIN implication:** never trust balances when sync_needed / locks_behind>0 after re-pin. Always light-scan to tip (or wait until locks_behind=0) before receive-verify or spend.

## Corrected transfer settlement

| Field | Value |
| --- | --- |
| tx_id | 2178cc31ae62482759137592871e793521ba24b4690aca99c5856ca00ea5423f |
| inclusion height | **4201** |
| frank after | 963997 / owned=1 (**F75 risk** — cannot upload/send until 2nd UTXO) |
| heidi after | 1023997 / owned=3 |

## Proxy RPC surface

list_methods via :8787/rpc returns 32 methods with classes (public-safe / wallet-write / operator-admin). Local observer: peer_count=3, tip advancing.


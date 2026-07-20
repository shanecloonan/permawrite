# Live public testnet probe - wave 18 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~06:18Z-06:37Z (+ settle after interrupt)
**Prior:** wave17 `1bf6dac` / open `f928647`
**Tip:** **4219 -> 4229** during runner; later tip **~4258** at SYNC

## Executive verdict

| Gate | Result |
| --- | --- |
| Tip soak (local often +1) | **PASS** - peers live; not F74 diverge |
| `get_block_headers` object params | **PASS** - headers for tip-2..tip |
| `list_recent_uploads` | **PASS** - total 10+; judy/frank/ivan visible |
| Wallet hygiene (frank/heidi/eve/dave/grace/ivan) | **PASS** |
| F45 hard `--checkpoint-log` | **FAIL** - no attestation at tip 4224 (log max 4173) |
| F68b soft `-Apply` | **PASS** |
| dave -> grace 50000 | **PASS** Fresh tx `19115205…` (dave F71 after send) |
| Judy new wallet faucet | **PASS** job `21a55cc6…` ~156s; **no F71** this time |
| Judy F76 2nd UTXO lag | **PASS** - 500k/1 then tip+1 -> **1e6/2** |
| Judy upload `411bed87…` | **PASS** Fresh; **last_proven=4229** |
| Standalone `wallet claim` | **FAIL expected F84** - disabled; use upload `--message` |
| heidi -> judy 20000 | **PASS** Fresh tx `c75ae8b0…`; judy later **1018997**/owned=3 |
| Grace upload after F75 unlock | **PASS** Fresh commitment `12a11d7d…` tip 4232 |

## Finding F84 - standalone claim disabled

```text
standalone `wallet claim` is disabled: attach optional discovery metadata at upload time
with `wallet upload FILE --message "..."` (bound, upload-co-anchored claims only)
```

**JOIN implication:** do not document a separate post-upload `wallet claim` step for public testnet. Authorship metadata must be bound at upload.

## Finding F71 is intermittent after faucet

Wave17 **ivan** hit F71 immediately after faucet `done`. Wave18 **judy** did **not** (`judy_f71=false`) and scanned cleanly to 500k then 1e6. Post-spend F71 still common (dave after send to grace; heidi after send to judy).

**JOIN implication:** keep re-pin recovery in the runbook, but do not treat F71-after-faucet as guaranteed; still watch for it.

## Judy JOIN micro-loop (3rd confirmation)

1. `wallet new` + pin@4173
2. faucet dual-send ~156s (txs `42d9ff00…`, `1b5c0c3c…`)
3. receive: 500k/1 -> **1e6/2** (F76)
4. upload tip 4228 -> last_proven **4229** (~120s local_only)
5. receive heidi 20k -> **1018997**/owned=3

Together with heidi (wave15) and ivan (wave17): **three** successful outside-in new-wallet permanence loops.

## Permanence board (wave18)

| Commitment | Wallet | last_proven |
| --- | --- | --- |
| `411bed87…` | judy | **4229** |
| `12a11d7d…` | grace | settled after tip 4232 (poll in addendum) |
| `1ce26efa…` | frank | **4218** |
| `5f942d28…` | ivan | **4217** |
| `a20fcb43…` | alice old | **4071** (F70) |

## Transfer settles

| From -> to | Amount | Notes |
| --- | --- | --- |
| dave -> grace | 50000 | unlocked grace F75 for upload |
| heidi -> judy | 20000 | judy 1018997/3 after settle |

## Proxy surface

- `get_block_headers` with `{"from_height","to_height"}` works (not array)
- Uploads index includes recent wave17/18 commitments
- Faucet health OK throughout; busy=false between jobs

## B-15 status

SUMMARY spine is solid: three new wallets (heidi/ivan/judy) pin->fund->upload->last_proven. Remaining: formal SUMMARY archive; Path A ckpt still lagging (~4173 vs tip 4200+); F84 claim UX note for JOIN docs.

## Artifacts (local only)

- `user-wallet/judy.json` + upload-artifacts
- `_wave18-results.json`, `_wave18-judy-*.json`, `_wave18-grace-upload.json`, `_wave18-*-to-*.json`
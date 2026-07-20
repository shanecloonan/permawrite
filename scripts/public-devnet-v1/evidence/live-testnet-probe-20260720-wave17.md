# Live public testnet probe - wave 17 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~05:50Z-06:20Z
**Prior:** wave16 `026eaad` / open `1227e78`
**Tip:** **4205 -> 4218**

## Executive verdict

| Gate | Result |
| --- | --- |
| Tip soak / watch | **PASS with lag** - local often +1 vs proxy; tip_ids match when heights equal; peers=3 |
| Eve `fadfaba2` on `list_recent_uploads` | **PASS** - last_proven **4206** (earlier wave16 index lag cleared) |
| Wallet hygiene pin+clear | **PASS** - eve/heidi/grace/frank/dave balances restored |
| F45 hard `--checkpoint-log` | **FAIL** exit 1 (log max 4173 vs tip ~4210) |
| F68b soft `-Apply` | **PASS** |
| Ivan faucet job `0ecc7c6a…` | **PASS** done ~124s dual-send |
| Ivan post-faucet F71 | **REPRO** - trusted 4213 vs checkpoint 0 before receive verify |
| Ivan receive after re-pin | **PASS** 1e6 / owned=2 |
| Ivan upload `5f942d28…` | **PASS** Fresh; **last_proven=4217** (~130s local_only) |
| Frank upload `1ce26efa…` | **PASS** Fresh; **last_proven=4218** |
| Grace -> ivan 30000 | **PASS** Fresh tx `74a42007…` (F71 on grace; settle via re-pin) |

## Finding F71 on brand-new faucet wallet (JOIN-critical)

Ivan was pinned at 4173 before `POST /faucet`. After job `done`, the first `wallet balance` / light-scan path hit:

```text
weak-subjectivity: tip_height mismatch (trusted 4213 vs checkpoint 0)
```

Funds were on-chain (faucet reported 2 tx ids) but the wallet was unusable until `pin_clean@4173` again. This is the same class as post-spend/post-upload F71, now shown on the **receive-verify** step of a fresh participant.

**JOIN implication:** after faucet job `done`, if light-scan/balance fails WS, re-pin from checkpoint log / `get_light_snapshot(log_max)` before declaring receive FAIL. Do not wipe observer store first.

## Finding F83 - upload index lag (narrowed / closed for eve)

Early wave17 soak (tip ~4205) omitted eve `fadfaba2` from `list_recent_uploads` despite local `uploads status` matched@4206. Later list (tip ~4208+) included it first with last_proven **4206**. Index/propagation lag on the public proxy, not permanence failure.

## Tip lag pattern (not F74 diverge)

| Phase | Observation |
| --- | --- |
| Early soak | local 4206 / proxy 4205 for ~40s |
| Mid watch | local 4208 / proxy 4207 for ~40s; tip_ids match when equal |
| Close | local 4218 / proxy 4217; peers=3 throughout |

Local observer seals slightly ahead of the VPS proxy view. When heights match, tip_ids match - not a divergent fork requiring wipe.

## Ivan JOIN micro-loop (second confirmation after heidi)

1. `wallet new` -> pin@4173
2. faucet dual-send ~124s
3. F71 brick -> re-pin -> **1e6/owned=2**
4. upload Fresh tip 4215 -> last_proven **4217**
5. receive grace 30k (tx `74a42007…`)

Together with wave15 heidi, this is repeatable outside-in evidence for SUMMARY.

## Permanence board (wave17)

| Commitment | Wallet | last_proven |
| --- | --- | --- |
| `5f942d28…` | ivan | **4217** |
| `1ce26efa…` | frank | **4218** |
| `fadfaba2…` | eve | **4206** (now on proxy list) |
| `c56e1c69…` | heidi | **4200** |
| `a20fcb43…` | alice old | **4071** (F70 still stale) |

## F45 lag

Checkpoint max still **4173** (~40+ behind tip). Soft bootstrap remains the Windows JOIN gate.

## B-15 status

Two successful new-wallet loops (heidi wave15, ivan wave17) with upload settlement. Remaining: formal SUMMARY archive file; hard F45 still tip-race; document F71 after faucet in JOIN copy.

## Artifacts (local only)

- `user-wallet/ivan.json` + upload-artifacts
- `_wave17-ivan-faucet.json`, `_wave17-ivan-upload.json`, `_wave17-frank-upload.json`, `_wave17-grace-to-ivan.json`

## Transfer settle (post F71 re-pin)

| Wallet | Balance | Owned |
| --- | --- | --- |
| grace | **898997** | 1 |
| ivan | **1028997** | 3 |

Proxy list shows frank 1ce26efa…@4218 and ivan 5f942d28…@4217 at tip ~4219.


## Addendum - retrieve / challenge / claims

| Probe | Result |
| --- | --- |
| uploads retrieve ivan 5f942d28… | **PASS** 64B |
| operator challenge after index | **PASS** next_height **4220** |
| list_recent_claims | **empty** total=0 (no authorship claims published this wave) |
| Proxy get_status | tip **4218**, peer_count **3**, session_count **3**, proof_pool 0 |

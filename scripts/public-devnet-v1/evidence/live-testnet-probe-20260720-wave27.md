# Live public testnet probe - wave 27 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~12:53Z-13:28Z
**Prior:** wave26 / rose last_proven=4412
**Tip close:** **4430** (matched)
**Runner wall time:** ~35 min

## Executive verdict

| Gate | Result |
| --- | --- |
| tip_id match | **PASS** (long F88b waits; stuck-ahead common) |
| Ports | **OPEN** |
| Rose proxy recheck | **PASS** listed; claims=7 at open |
| Sam faucet job | reached **done** (~115s) but first pins showed 0 |
| Sam balance @4173 | **TIMEOUT 180s** (F85/F97) -> fell to peer-fund path |
| rose->sam peer #1 120k | **PASS** Fresh |
| rose->sam peer #2 120k | **FAIL** input count 1 < consensus min 2 (F98) |
| Sam funded | **PASS** mode=peer |
| Sam upload bound | **PASS** |
| Sam last_proven | **PASS** **4430** |
| Proxy + claims | **PASS** |

## Finding F97 - wallet balance timeout after faucet

After faucet `done`, `wallet balance` at pin@4173 **timed out at 180s**. Tip continued advancing. JOIN scripts need longer timeouts and/or soft-fail into peer-fund / alternate pin heights without treating timeout as hard failure.

## Finding F98 - second peer-send hits input-count floor despite owned=2

After rose->sam #1 Fresh (balance_after=0), tip settle + re-pin showed rose **998997 / owned=2** (change visible; F90). Second 120k send failed:

```
mempool admit: tx invalid: input count 1 < consensus minimum 2 (uniform-tier anti-fingerprinting floor)
```

**JOIN implication:** peer dual-fund is not just F91 (RBF) — after a consolidating first send, the wallet may only *select* one input even when owned_count=2. Mitigations: wait for change to settle with clear pending_spent; send smaller amounts that leave two spendable UTXOs; or fund with faucet dual-send (true F7).

## Finding F96 reconfirmed

Faucet done + pin@4262 still showed owned=0 before timeout path; funding eventually succeeded via peer path / later pin visibility.

## Permanence board

| Commitment | Wallet | last_proven | Notes |
| --- | --- | --- | --- |
| `518e69ba` | sam | 4430 | wave27 |
| `b3debb6a` | rose | 4412 | wave26 |
| `750e2d52` | quinn | 4390 | wave25 |

## JOIN scorecard

Eleven new-wallet public permanence loops … rose, **sam** (last_proven=4430, claims=8).

## Artifacts (local)

- `_wave27-results.json`, `_wave27-sam-upload.json`, `_wave27-rose-to-sam-*.json`
- `user-wallet/sam.json`

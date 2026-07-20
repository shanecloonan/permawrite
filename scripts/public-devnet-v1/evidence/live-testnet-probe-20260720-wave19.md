# Live public testnet probe - wave 19 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~07:40Z-08:01Z
**Prior:** wave18 `42528d9` / F85 `13f6aff` / open `c26cc11`
**Tip:** **4260 -> 4270** (after local observer restart)

## Executive verdict

| Gate | Result |
| --- | --- |
| Local mfnd restart after F85 wedge | **PASS** - tip synced ~4263 without wipe |
| Grace upload `12a11d7d…` last_proven | **PASS** **4234** matched; retrieve 64B |
| Judy upload `411bed87…` last_proven | **PASS** **4229** matched; retrieve 64B |
| Soft bootstrap (frank) | attempted in aborted runner; not re-run this close |
| Karl faucet job `d14f5c7c…` | **PASS** ~121s dual-send |
| Karl F71 after faucet | **REPRO** (`karl_f71=true`) - same class as ivan |
| Karl receive after re-pin | **PASS** 1e6 / owned=2 |
| Karl upload `--message wave19-karl-authorship` | **PASS** Fresh; `authorship_claim=bound`; claim_message_len=22 |
| Karl last_proven | **PASS** **4270** |
| `list_recent_claims` after bound upload | **empty** total=0 (F86) |

## Finding F86 - bound upload claim not listed by `list_recent_claims`

Karl upload returned:

```json
"authorship_claim": "bound",
"claim_message_len": 22
```

Proxy `list_recent_claims` still `{total:0, claims:[]}`. Bound metadata is co-anchored on the upload tx but does not populate the recent-claims index (or indexing lags / filters differently).

**JOIN implication:** F84 path (`upload --message`) succeeds for binding, but operators should not expect `list_recent_claims` to show the message immediately (or at all). Verify via upload status / tx / claims-for-root APIs instead.

## Finding F71 after faucet - 2 of 3 new wallets

| Wallet | Wave | F71 after faucet? |
| --- | --- | --- |
| heidi | 15 | no (not noted) |
| ivan | 17 | **yes** |
| judy | 18 | **no** |
| karl | 19 | **yes** |

Intermittent but common. Re-pin@ckpt max recovers funds every time observed.

## Finding F85 (cross-ref wave18)

Local observer wedged under concurrent pin/balance load; restart recovered. Wave19 completed only after serializing ops post-restart.

## Karl JOIN micro-loop (4th confirmation)

1. pin@4173 -> faucet ~121s
2. F71 brick -> re-pin -> **1e6/owned=2**
3. `wallet upload FILE --message "..."` -> `authorship_claim=bound`
4. last_proven **4270** (~120s local_only)

## Permanence board (wave19)

| Commitment | Wallet | last_proven | retrieve |
| --- | --- | --- | --- |
| `53b5c837…` | karl | **4270** | (new) |
| `12a11d7d…` | grace | **4234** | ok 64B |
| `411bed87…` | judy | **4229** | ok 64B |

## B-15 status

Four new-wallet permanence loops (heidi/ivan/judy/karl). F84 message path proven (`bound`). SUMMARY can cite these four + soft F45 + F71 re-pin + F85 serialize-ops note.

## Artifacts (local only)

- `user-wallet/karl.json` + upload-artifacts
- `_wave19-karl-faucet.json`, `_wave19-karl-upload.json`, `_wave19-results.json`
- `_wave19-retrieve-{grace,judy}.bin`
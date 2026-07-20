# Live public testnet probe - wave 21 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~08:42Z-09:20Z
**Prior:** wave20 F88 diverge
**Public tip close:** **4304** (local tip_id matched proxy)

## Executive verdict

| Gate | Result |
| --- | --- |
| Wipe + fresh sync to public tip_id | **PASS** (matched @4287 in ~3 min; tip advanced to 4304) |
| Transient tip_id lag (local +1 ahead) | **Observed** repeatedly; wait until tip_id match before upload |
| Soft pin@4262 | **PASS** |
| F45 HARD @ tip ~4296 | **FAIL** (ckpt max 4262) |
| Faucet path | **POST /faucet** (not /fund — 404); job **done** ~161s dual-send |
| Mike owned>=2 after faucet+grace | **PASS** 650000 / owned=2 |
| Mike upload --message | **PASS** bound; commitment 61731fb9… |
| Proxy list_recent_uploads contains mike | **PASS** |
| last_proven | **PASS** **4304** (status matched) |
| claims for data_root | **PASS** claim_count=1; message_hex=wave21-mike-authorship |
| tip_id match at close | **PASS** |

## Finding F88b - tip_id lag is common; wait before permanence claims

Even after clean wipe/resync, local tip frequently sits **one height ahead** of proxy with a different tip_id for 30-90s (session_count often 0 while peer_count=3). Uploading during mismatch risks orphan Fresh (wave20 F88).

**Ops rule:** loop until local.tip_id == proxy.tip_id immediately before wallet upload / prove; re-check after settle.

## Finding F89 - faucet HTTP path is /faucet not /fund

POST http://5.161.201.73:8788/fund → **404**. Correct: POST /faucet + poll /faucet/job?id=… (as in JOIN_TESTNET / fund-wallet-http).

## Mike JOIN micro-loop (5th public permanence)

1. Wipe divergent data dir; sync seeds → tip_id match
2. wallet new + pin@4262
3. Peer grace 150k (owned=1) + faucet job b372195… done ~161s
4. Re-pin → **650000 / owned=2**
5. Wait tip_id match → upload --message wave21-mike-authorship → Fresh
6. last_proven **4304**; proxy index **True**; claims for **PASS**

## Permanence board add

| Commitment | Wallet | last_proven | Proxy listed | Claims |
| --- | --- | --- | --- | --- |
| 61731fb9… | mike | **4304** | yes | yes (bound msg) |
| 53b5c837… | karl | 4270 | yes | yes |
| 12a11d7d… | grace | 4234 | yes | — |
| 411bed87… | judy | 4229 | yes | — |

## B-15 status

Five new-wallet public permanence loops: heidi, ivan, judy, karl, **mike**. JOIN SUMMARY draft updated. Formal rehearsal archive assert still open (F45 hard + human sign-off).

## Artifacts (local only)

- user-wallet/mike.json + upload-artifacts
- _wave21-results.json, _wave21-mike-upload.json, _wave21-grace-to-mike.json

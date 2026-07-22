# Live public testnet probe - wave 66 findings (2026-07-22) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~10:41Z–11:12Z (~31 min wall; includes 600s F95 cooldown)
**Prior:** wave65 gwen last_proven=5784; F110 streak x5
**Tip close:** **5800** (matched)
**Mode:** F95 429 → 600s wait → faucet-retry-F101b → proxy-prove; **permanence_public PASS**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer tip match (open) | **PASS** @5785; mem=0; peer_count=3; session_count=0 |
| Path A ckpt_max / F45 lag | **5290** / **495** (hard TIMEOUT 60s) |
| Faucet first POST | **429 Too Many Requests** (F95; post-wave65 cooldown) |
| F95 wait | 600s then retry once |
| Faucet retry | **done** in 220389ms (~220s) |
| F110 early owned=1 exit | **PASS** (timeouts=None) |
| F101b round 0 | **PASS** owned=2 |
| Fund mode | `faucet-retry-F101b` |
| Upload + prove | **PASS** last_proven=**5800** `a9ae8fec` |
| Claims | **39 → 40** |
| **permanence_public** | **PASS** |

## Timeline (selected)

| Event | Detail |
| --- | --- |
| open | tip match @5785; F45 lag=495 |
| faucet | HTTP 429 immediately (cooldown from gwen wave65) |
| wait | 600s F95 policy |
| faucet-retry | job accepted; done ~220s |
| pin ladder | tip−20 owned=0 → tip−80 owned=1 → early F101b |
| F101b_0 | owned=2 @ near tip |
| upload | Fresh @5798; prove → proxy_has @5800 |

## Findings

### F95 reconfirmed — density waves hit IP cooldown

Back-to-back permanence waves from the same public IP hit faucet 429 after wave65 success. Runner correctly waited 600s and retried once. **JOIN lesson:** when grinding density, either space waves ≥15m (cooldown_ms=900000) or accept ~10m idle + faucet-retry path. Peer dual-fund remains a fallback but donors are often owned=1 (F106).

### F110 + F101b still hold under retry path

Fund mode `faucet-retry-F101b` is a new labeled combo (429 wait + delayed second UTXO). Zero bal TIMEOUTs. Near-tip ladder remains mandatory while F45 lag ≫ 0.

### F45 lag **495** — still climbing

Tip **5800** vs Path A **5290**. Soft JOIN only. Lane 7 Path A republish would cut operator pain.

### Cost model with F95

| Phase | Wall time this wave |
| --- | --- |
| F95 cooldown | 10.0 min |
| Faucet retry dual-send | ~3.7 min |
| F101b + tip match + upload/prove | ~8–12 min |
| **Total** | **~31 min** |

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `a9ae8fec` | **hugo** | **5800** | faucet-retry-F101b |
| `5a47083c` | gwen | 5784 | faucet-F101b |
| `da677677` | finn | 5775 | faucet-F101b |
| `8f9142a9` | ella | 5761 | faucet-F101b |

**JOIN scorecard:** forty-three proxy-proven wallets.

## Artifacts

- `_wave66-results.json`, `_wave66-hugo-upload.json` (gitignored `_`)
- this markdown

## Follow-up

- Wave67+: space ≥15m after faucet success OR expect F95+600s.
- Path A republish (lane 7) for F45.


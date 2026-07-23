# Live public testnet probe - wave 97 findings (2026-07-23) — permanence PASS

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T13:08Z` → close ~13:29Z (~21 min wall; resume day)
**Prior:** wave96 pax last_proven=6141; overnight interrupt; tip jumped ~6141→6575
**Tip close:** **6586** (matched)
**Mode:** faucet-F101b; **permanence_public PASS** (after tip-slip recover)

## Executive verdict

| Gate | Result |
| --- | --- |
| Overnight attempt | **INTERRUPTED** at F101b tip~6151 (no prove) |
| Resume ops | F113 TIMEOUT → mfnd restart → runners 300s+retry |
| Faucet / F110 / F101b | **PASS** owned=1→2 |
| Pre-upload | tip match then **slip** once (recovered) |
| Upload + prove | **PASS** last_proven=**6586** `ecc0d3f2` |
| Claims | **67 → 68** |
| F45 lag | **1286** (ckpt 5290; **>>800**) |
| **permanence_public** | **PASS** |

## Findings

### F45 lag **1286** — overnight cliff confirmed

Idle overnight while tip sealed ~400 blocks with Path A frozen at 5290 produced lag **838 → 1286**. Soft JOIN only; Path A republish is now a hard JOIN UX blocker.

### F113 validated then mitigated

Morning recreate hit `get_light_snapshot` TimeoutError @180s and wedged RPC. After mfnd restart (same data dir), snapshot @ tip−20 completed in ~54s. Hardened runners (300s + 3× retry) completed wave97 pins without further TIMEOUT.

### Tip/mempool slip at upload is recoverable

Runner logged `ABORT upload: tip/mempool slipped False 0` then re-waited and uploaded successfully. Not an F107 (mem stayed 0; prove cleared local_only→matched→proxy_has).

### Post-wipe streak continues (x17) across overnight gap

Waves 81–96 were continuous density; wave97 resumes the permanence streak after ops recovery (not a wipe).

## Permanence board (newest)

| Commitment | Wallet | last_proven | Fund |
| --- | --- | --- | --- |
| `ecc0d3f2` | **quill** | **6586** | faucet-F101b |
| `b2e0ef61` | pax | 6141 | faucet-retry-F101b |
| `063c60ee` | orin | 6128 | faucet-retry-F101b |

**JOIN scorecard:** seventy-one proxy-proven wallets.

## Artifacts

- this markdown
- `live-testnet-ops-20260723-wave97-resume.md`

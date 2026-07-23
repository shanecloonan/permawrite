# Live public testnet probe - wave 106 findings (2026-07-23) — UNFUNDED FAIL (F114)

**Lane:** 3 (onboarding / B-15)
**UTC window:** open `2026-07-23T17:06Z` → close ~long (~1.8h incl. F101b×6 + peer attempt)
**Prior:** wave105 yara F107 wipe #2 + resync
**Tip close:** ~6745 match True
**Mode:** unfunded; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Observer resync | **PASS** (post-wipe tip match before run) |
| Faucet HTTP accept | accepted job |
| Faucet job | **ERROR** — VPS `mfn-cli` → hub **Connection refused (os error 111)** |
| F101b×6 | owned stayed 0 (no UTXO landed) |
| Peer-fund nora/kate | **SKIP** insufficient owned; bal **TIMEOUT 400s** |
| Upload/prove | skipped (unfunded) |
| F45 lag | **1403** (ckpt 5290) |
| **permanence_public** | **FAIL** (not a prove failure — fund path broke) |

## Findings

### F114 — Faucet job fails with hub Connection refused (111)

Job `b6cc849a48b1938db7e7aafe` status=`error`:

```
/root/permawrite/target/release/mfn-cli exited 1: io: Connection refused (os error 111)
```

Distinct from F95 (HTTP 429). Faucet HTTP service accepted the request, but the VPS faucet worker could not reach hub RPC (`os error 111`). Honor §6: **did not** restart `faucet-http` from this lane; recorded for lane 7/ops.

### Peer fallback exhausted

nora/kate both skipped (owned insufficient) and hit bal TIMEOUT 400s — tall-tip donor scans are costly; peer pool often already spent down after dense waves.

### Density ops implication

Post-wipe waves can still fail before upload if faucet→hub path is down. Next wave should re-probe faucet health; if 111 persists, escalate to lane 7 without thrashing faucet.

## JOIN scorecard

Still seventy-seven (no increment).

## Artifacts

- this markdown
- session update in waves100-106 rollup

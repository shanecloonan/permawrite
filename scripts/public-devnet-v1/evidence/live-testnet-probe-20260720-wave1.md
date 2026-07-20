# Live public testnet probe — wave 1 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15 outside-in evidence)
**Probe host:** Windows 10 workstation (outside the VPS), outbound internet only
**Repo head at start:** `5dc3aa8` (B-29 CLI fix); evidence landed against later heads including lane-7 B-31 `6f637a4`
**UTC window:** 2026-07-20T01:47Z through ~01:55Z (addenda through ~01:54Z)
**Claim note:** Outside-in probe only. Did **not** restart `faucet-http` or run parallel VPS JOIN rehearsals (honors §6 lock). Complements lane-7 [`b31-threat-posture-20260720.md`](./b31-threat-posture-20260720.md) (VPS-side bind root cause).

## Executive verdict

| Surface | Verdict | Severity |
| --- | --- | --- |
| Observer HTTP proxy (`:8787`) | **UP** — tip advancing, index complete | OK |
| HTTP faucet (`:8788`) | **UP** — full fund job DONE in ~111s; cooldown 429 | OK |
| Published P2P seeds (`:19001–19003`) | **DOWN from outside** — TCP fail; local `mfnd` stuck tip 0 / `peer_count=0` | **BLOCKER for JOIN Steps 2–3** |
| Signed checkpoint log in repo | Verifies OK but **stale** (`max_tip_height=3` vs live tip ~4020) | **High** (B-22 / TL-8) |
| Full B-15 JOIN rehearsal (local sync → fund → light-scan → permanence) | **Blocked** until P2P seeds accept outside dials | Blocked |

**Bottom line:** Chain is live and HTTP onboarding surfaces work. A brand-new outside user following [`docs/JOIN_TESTNET.md`](../../../docs/JOIN_TESTNET.md) **cannot sync a local observer**. Lane-7 B-31 confirms root cause: VPS `mfnd` P2P bound to `127.0.0.1:1900x`, not `0.0.0.0`.

---

## Environment under test

| Item | Value |
| --- | --- |
| Network | `public-devnet-v1` |
| Expected genesis | `454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005` |
| Manifest seeds | `5.161.201.73:19001`, `:19002`, `:19003` |
| Observer proxy | `http://5.161.201.73:8787/rpc` |
| Faucet | `http://5.161.201.73:8788/faucet` |
| Local binaries | `target/release/mfnd.exe`, `mfn-cli.exe` |
| Local observer | `mfnd --data-dir ./live-testnet-data --rpc-listen 127.0.0.1:18734 --p2p-listen 0.0.0.0:0 serve` |
| Local P2P listen observed | `0.0.0.0:51926` |

---

## Test matrix

### T1. ICMP / TCP reachability

| Target | Result | Notes |
| --- | --- | --- |
| Ping `5.161.201.73` | **PASS** | `PingSucceeded: True` |
| TCP `19001` | **FAIL** | `TcpTestSucceeded: False` |
| TCP `19002` | **FAIL** | same |
| TCP `19003` | **FAIL** | same |
| TCP `8787` / `8788` | **PASS** | OPEN |
| TCP `18731–18734`, `19000`, `19004` | **FAIL** | expected for RPC; confirms no alternate public P2P |

**Finding F1 (BLOCKER):** Published `seed_nodes` unreachable from outside IPv4 that can reach the same host on HTTP. Cross-check: B-31 VPS `ss` shows P2P on `127.0.0.1` only.

### T2. Local observer sync (JOIN Steps 2–3)

```text
mfnd_p2p_boot_dials=5.161.201.73:19001,5.161.201.73:19002,5.161.201.73:19003
mfnd_chain_genesis_id=454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005
```

After several minutes (and rechecked after faucet):

```text
tip_height=0
peer_count=0
session_count=0
```

Genesis **matches**. Tip does **not** advance.

**Finding F2:** Outside-in JOIN path broken end-to-end. B-15 cannot archive honest `SUMMARY: PASS` for local-observer rehearsal until seeds accept dials (or ops publishes corrected public listen addresses).

### T3. Observer proxy — tip / status / health

| Call | HTTP | Result |
| --- | --- | --- |
| `get_tip` | 200 | tip **4016 → 4024** during window; genesis match; `validator_count=3` |
| `get_status` | 200 | observer RPC `127.0.0.1:18734`; VPS observer `peer_count=1` |
| `GET /health` | 200 | `ok=true`, index `complete=true`, `covered_heights` matches tip, `index_errors=0` |

**Tip soak samples:**

| UTC | tip_height | tip_id prefix |
| --- | --- | --- |
| ~01:51:12Z | 4019 | `054505429cc7f19e` |
| +35s | 4020 | `480a3d110e829167` |
| 01:52:12Z | 4022 | `365528a2c66d1328` |
| 01:52:46Z | 4023 | `c5f1fd0a3b70cdcb` |
| 01:53:54Z | 4024 | `37c79d210f15d91c` |

Slot timing ~30s matches `slot_duration_ms: 30000`. **Chain liveness via proxy: PASS.**

### T4. Observer proxy — method allowlist

| Method | Live result |
| --- | --- |
| `list_methods` | 200 — full class map |
| `get_block` h=1 | 200 |
| `get_block_header` h=4016 | 200 |
| `get_light_snapshot` | 200 |
| `get_light_follow` `{from_height:4015,to_height:4020}` | 200 — rows returned |
| `get_light_follow` with `max_blocks` | **-32602** `missing params.to_height` |
| `get_chain_params` | 200 — `subsidy_to_treasury_bps=0`, treasury `712503` |
| `get_checkpoint` | 200 — `byte_len=783380` |
| `get_tx_count_totals` | 200 — `total_user_tx_count` 52→53 during faucet |
| `get_block_txs` / `get_block_txs_range` | 200 |
| `list_recent_uploads` | 200 — **2** uploads |
| `list_recent_claims` | 200 — 0 |
| `list_utxos` limit 3 | 200 — `total=4159` |
| `get_mempool` | 200 |
| `get_proof_pool` | 200 — empty |
| `list_fraud_contests` | 200 — 0 |
| `get_storage_challenge` (known commit `070da207…`) | 200 — challenge for next height |
| `clear_mempool` | **403** denied |
| `submit_storage_proof` | **403** denied |
| `submit_tx` garbage hex | forwarded — JSON-RPC decode error (allowlisted for browser wallet in `observer-rpc-proxy.mjs`) |

**Finding F4 (doc honesty):** JOIN/INVITE say proxy is public-safe only and “never `submit_tx`”. Code intentionally allowlists `submit_tx` for browser testnet. Align docs with allowlist; still warn against using the proxy as a primary spend-key wallet RPC.

**Finding F5:** Operator-admin and `submit_storage_proof` correctly denied.

**Finding F10:** `get_light_follow` requires `to_height` (not `max_blocks`).

### T5. Checkpoint log (F12)

```text
mfn-cli checkpoint-log verify …/public_devnet_v1.checkpoints.jsonl
→ checkpoint_log_verify_ok entries=1 max_tip_height=3 signer_ids=permawrite-maintainer-1
```

Live tip ~4020+. **Finding F6 (HIGH):** Log valid but useless for JOIN light-scan weak-subjectivity at current tip. Matches B-31 / B-22.

### T6. Permanence (read-only)

| commitment prefix | size_bytes | last_proven_height |
| --- | --- | --- |
| `070da207…` | 131072 | **1915** |
| `175bac7b…` | 8388608 | **1909** |

**Finding F7:** Uploads indexed; last proofs ~2100 heights behind tip; proof pool empty. Permanence-ops signal (B-25 / B-38), not a faucet bug. `get_storage_challenge` still returns a challenge for the 128 KiB commit.

### T7. HTTP faucet (full outside-in fund)

| Step | Result |
| --- | --- |
| `GET /` | 404 |
| `GET /health` | 200 |
| `POST` invalid address | 400 `invalid mf address` |
| `POST` valid `mf…` | **202** job `33bb1a52708db006e4b83e4a` |
| Poll while running | `running` |
| Concurrent POST | **503** `faucet busy - retry shortly` |
| Final | **done** in **111291 ms** |
| amounts | 2×500000, fee 10000 each, total 1000000 |
| tx_ids | `2a33b3afe7f139f610f660e09c35c07eda00744be6cfc18f23cc5b9cc45d1f62`, `7ee732854429cec3c585afb8851274ab49b0cb0dce6395d0493f8504801cc9e5` |
| Re-POST after done | **429** `address cooldown` `retry_after_ms=870717` (~14.5 min) |

Post-fund health: `busy=false`, `wallet_blocks_behind=0`, `wallet_sync_needed=false`.

**Finding F8/F11/F12 (SUCCESS):** Async job, busy 503, F7 dual-send, ~2 min completion at tip ~4k, cooldown 429 — all match JOIN Step 5. Faucet wallet near tip (major improvement vs 2026-07-15 exercise notes).

**Finding F9:** Cannot verify receive via local `wallet light-scan` until F1/F2 fixed (CLI needs TCP RPC to a synced node; proxy is HTTP).

---

## What we could not run (blocked)

1. Full `join-testnet-rehearsal-smoke --use-live-urls` (needs local tip > 0).
2. Checkpoint-log light-scan receive verification.
3. Permanence upload/restore against local observer.
4. Windows lacks `bash` in PATH; `.ps1` smoke wrappers only delegate to bash.

---

## Comparison to prior evidence

| Topic | 2026-07-15 live-wallet-exercise | 2026-07-20 this probe |
| --- | --- | --- |
| Tip | ~1910–1950 | ~4016–4024 |
| Faucet catch-up | Hostile (multi-minute) | Health near-tip / behind=0 |
| Outside P2P join | Ran on mesh host | **Fails** from outside |
| Checkpoint log | n/a | tip=3 only |
| Uploads / proofs | exercise-era | 2 uploads; last proven ~1910 |

---

## Recommended ops actions

1. Repair P2P binds to `0.0.0.0` (or republish correct seeds) — **blocks B-15 PASS and TL-9 invites** (also B-31 / B-41).
2. Publish near-tip checkpoint log (B-22); signer seed not on VPS per B-31.
3. Align JOIN/INVITE proxy wording with intentional `submit_tx` allowlist.
4. Investigate SPoRA stall (last_proven ~1915 vs tip ~4020).
5. After P2P fix: rerun B-15 smoke + assert.

---

## Artifacts (local, not committed)

- `live-testnet-data/` — local observer (tip 0) + logs
- `live-testnet-data/wallets/probe-alice.json` — **seed; do not commit**
- Faucet job `33bb1a52708db006e4b83e4a` (view_pub `4fe8ddf4…`)

## Wave 2+ plan

- Longer tip soak; mempool observation around faucet inclusion
- Front-end reachability if published
- After P2P repair: full JOIN rehearsal archive

---

## Wave 2 addendum (same session, ~01:55–01:57Z)

### Tip / index continuity

- Tip advanced to **4026–4027**; mempool empty after faucet inclusion.
- `get_tx_count_totals`: `total_user_tx_count=54`, briefly `complete=false` while index lagged tip by 1 height (healthy catch-up).
- `list_data_roots_with_claims`: total **0**.

### F13 — IP cooldown (distinct from address cooldown)

Created a second wallet (`probe-bob`) with a fresh `mf…` address and POSTed faucet from the **same outside IP** shortly after alice's successful fund:

```text
HTTP 429 {"ok":false,"error":"ip cooldown - try again later"}
```

**Finding F13 (SUCCESS / ops-important):** Faucet enforces **per-TCP-peer-IP cooldown** in addition to per-address cooldown (alice got `address cooldown` earlier). JOIN docs mention "~15 min cooldown per TCP peer IP / address" — confirmed live. Outside invitees behind shared NAT will serialize faucet access.

### F14 — Testnet front-end not reachable on VPS public ports

Probed TCP/HTTP on `5.161.201.73` ports 80, 443, 3000, 5173, 8080, 8789, 8790, 8888, 9000 — all closed/timeout. HTTPS root timed out. Docs claim "mesh + faucet + observer proxy + testnet front-end" on this host; **front-end was not externally reachable** from this probe path (may be hosted elsewhere / down / firewalled). Track as ops follow-up for lane 7 (not a JOIN Step 2–5 blocker by itself).

### Cross-check with B-31

Lane-7 [`b31-threat-posture-20260720.md`](./b31-threat-posture-20260720.md) independently found P2P bound to `127.0.0.1:1900x`. This outside-in probe is the client-side symptom of that bind mistake.
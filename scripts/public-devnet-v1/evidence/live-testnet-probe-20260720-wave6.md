# Live public testnet probe — wave 6 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~02:51Z–03:00Z
**Prior docs:** wave5 d18fe7b
**This commit:** documents tip recovery + faucet SUCCESS after multi-wave stall/EAGAIN

## Executive snapshot

| Check | Result |
| --- | --- |
| Tip production | **RECOVERED** — advanced **4031 → 4040** during this wave (~9 blocks in ~8 min) |
| Tip IDs observed | 4035 d9010c2…, 4036 ece99524…, 4037 15b89313…, 4040 7571fe79… |
| P2P (proxy get_status) | peers=3, sessions=1–2 (was peers=1 sess=0 in wave4/5) |
| Seeds 19001/2/3 | **all OPEN** (19001 recovered) |
| Proxy /health | ok; index complete at tip; index_errors still **4671** (stale counter) |
| Faucet /health | wallet telemetry **restored** (scan/tip/behind populated) |
| Alice re-fund | **SUCCESS** job 65cd9931… done in **122157 ms**, 2 txs (F7 dual-send) |
| Front-end ports 80/443/3000/8080 | still CLOSED |
| Local laptop mfnd :18734 | degraded (BadStatusLine / connection reset) — laptop-only |

## Finding F35 → F35b (STALL CLEARED)

Waves 4–5 documented tip frozen at **4031** / cdb54fa85473… for 20+ minutes with peers=1 sess=0.
Wave 6 open soak (~02:56Z) already saw tip at **4035** then **4036**. By faucet completion tip was **4040**.

**Interpretation:** production resumed (lane 7 / cluster self-heal). Outside-in observers can again see advancing tips. Stall was real and multi-minute; recovery is also real.

### Tip soak (wave6 python, 20s samples)

| Sample UTC | tip_height | tip_id prefix | peers | sess |
| --- | --- | --- | --- | --- |
| 02:56:18 | 4035 | fd9010c2b371bed3 | 3 | 1 |
| 02:56:38 | 4035 | fd9010c2b371bed3 | 3 | 1 |
| 02:56:58 | 4036 | ece995240dfff262 | 3 | 1 |
| 02:57:18 | 4036 | ece995240dfff262 | 3 | 1 |
| 02:57:53 | 4037 | 15b89313de10eb16 | 3 | 1 |
| 02:59:39 | 4040 | 7571fe79f8966ff4 | (end of faucet poll) | |

Slot time still ~30s/block when healthy.

## Finding F36 (P2P mesh improved before tip moved)

Even while tip was still catching up, get_status.p2p showed **peer_count=3** and **session_count≥1**, and TCP **19001** returned OPEN. Earlier waves had 19001 FAIL and sess=0. Reachability recovered first; block production followed.

## Finding F37 (Public proxy API contract — detailed)

| Method | HTTP / outcome |
| --- | --- |
| get_tip, get_status | 200 |
| get_block height≥1 | 200 (lock_hex present); height 0 → -32602 genesis not in chain.blocks |
| get_block_txs 4031 | 200; includes coinbase/user txs; block_id matches stalled tip id cdb54fa8… |
| list_utxos | params must be **object** {limit,offset}; total **4181** at tip ~4036 |
| submit_tx 	x_hex=00 | -32602 short buffer (allowlisted but validates codec) |
| get_network_info / get_checkpoint_log / get_proof_pool_status / get_uploads | **403** method not allowed (expected) |
| PowerShell note | result field is 	ip_height not height — empty $r.result.height is a probe bug, not chain bug |

## Finding F38 (Faucet FULLY GREEN after EAGAIN streak)

### Health before/after fund

Before fund (wave6 open): wallet_* fields were null during stall window; by ~02:56Z:

`
wallet_scan_height=4035, wallet_tip_height=4036, wallet_blocks_behind=1, wallet_sync_needed=true
`

During running job: usy=true, pending_jobs=1, wallet synced (locks_behind=0).

### Alice re-fund (same address as wave1)

- Address: mf4f9ac2d26c8810e13b118f24a973f1e185a4d6e6dde76b003929fd39c31e73a508bed642a52fada4ae538e03b8b12780b0968b600f6fcfc0879e0dcede328a282a4cafd7
- POST /faucet → **202** job_id 65cd9931ce939a143a026b3a
- Poll path must be **/faucet/job?id=** (bare /job?id= returns 404 with route hint containing unicode arrow)
- Terminal: **status=done**, duration_ms=**122157**, sends=2, total_amount=1000000, fee_per_send=10000
- tx_ids:
  - d9a9173a5f6fc03abca5110b679f735cf1bafd79633edbbd7f84f06fea7ab9e5
  - 9c7ed8b5f7c291b6be55780e18a7fc49d9146bb47a432af3466d97fdf660877e

This breaks the post-wave1 **3/3 EAGAIN** failure streak (alice re-fund / bob / carol). EAGAIN (os error 11) appears correlated with tip stall + null wallet telemetry, not a permanent faucet bug.

### Cooldown

cooldown_ms=900000 (15 min). Expect 429 on immediate re-fund of same address/IP.

## Finding F39 (index_errors sticky)

/health reports index_errors=4671 even while index complete=true and tip advances. Do **not** use this counter as a live liveness signal; tip_height + tip_id movement are authoritative.

## Finding F40 (Front-end still dark)

TCP closed: 80, 443, 3000, 8080. Open: 8787, 8788. Invite path remains CLI/API.

## Finding F41 (Local observer process dead)

Laptop 127.0.0.1:18734 returns JSON-RPC parse errors / connection resets to Python; PowerShell sees ResponseStatusLine violation. Safe to restart local mfnd (does not touch Hetzner faucet lock). Needed for checkpoint-bootstrap light-scan receive verify next.

## Finding F42 (Alice scan_height=250 residue)

mfn-cli wallet address reports scan_height=250 on alice.json — partial progress from earlier attempts. After successful fund, next step is light-scan from checkpoint/trusted tip (prefer Path A checkpoint ~4028) and assert owned_count≥2 for the two faucet outputs.

## Port / seed matrix (wave6)

| Target | Open |
| --- | --- |
| 5.161.201.73:19001 | True |
| 5.161.201.73:19002 | True |
| 5.161.201.73:19003 | True |
| 5.161.201.73:8787 | True |
| 5.161.201.73:8788 | True |
| 5.161.201.73:80/443/3000/8080 | False |

## B-15 status after wave6

| Gate | Status |
| --- | --- |
| Outside tip readable + advancing | **PASS** |
| Seeds dialable | **PASS** |
| Faucet fund completes (F7 dual send) | **PASS** (alice) |
| Receive verify (owned UTXOs after light-scan) | **PENDING** (wave7) |
| Full JOIN rehearsal SUMMARY PASS | **PENDING** |
| Front-end invite UX | **N/A / blocked** (ports closed) |

**Next (lane 3):** restart local mfnd if needed → checkpoint-aware light-scan alice → document owned_count → optionally bob/carol funds after cooldown → JOIN assert when ready.

**Lane 7:** tip/faucet appear healthy again; still watch for re-stall. Do not restart faucet-http during B-15 lock.

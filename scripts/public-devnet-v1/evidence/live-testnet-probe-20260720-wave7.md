# Live public testnet probe — wave 7 findings (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~03:01Z–03:22Z
**Prior:** wave6 e5d57de / wave7 open 2abbf5e
**Public tip during close:** ~4068 (advancing ~30s/slot)
**Local observer:** 127.0.0.1:18734 tip-matched public chain

## Executive verdict

| Gate | Result |
| --- | --- |
| Tip production | **PASS** (4041 → 4068+) |
| Faucet (alice re-fund wave6, bob wave7) | **PASS** (both done ~95–122s, F7 dual send) |
| Receive verify alice | **PASS** — owned_count=2, alance=1000000, sync_needed=false |
| Receive verify bob | **PASS** — owned_count=2, alance=1000000 |
| Naive light-scan --checkpoint-log from genesis/mid-scan | **FAIL / impractical** (see F44–F46) |
| Snapshot-bootstrap + wallet balance near tip | **PASS** (~24–42s for ~13–27 blocks) |
| Checkpoint log freshness | **PASS** (entries=5, max_tip_height=4057 after lane-7 B-22 refresh) |
| Full JOIN SUMMARY PASS archive | **PENDING** (permanence + formal join-testnet-rehearsal next) |

## Finding F43 (pre-scan residue)

Alice entered wave7 with scan_height=250, owned_count_cached=1, alance_cached=1000000, locks_behind≈3791. Partial historical scan + wave6 fund not fully reflected until re-bootstrap.

## Finding F44 (CRITICAL JOIN UX — checkpoint-log does not skip history)

Code review + live behavior: wallet light-scan --checkpoint-log FILE only **cross-checks** the post-sync wallet light checkpoint against the Schnorr log (cross_check_checkpoint_log_if_requested). It does **not** jump scan_height to max_tip_height in the log.

Implication: at tip ~4k, a fresh or mid-scan wallet still walks essentially every height via get_block_txs (~1.2–1.7s each on this laptop→local mfnd path). Mid-scan wallet status keeps showing the old scan_height until completion (no mid-persist) — confirms F17/F25/F34.

JOIN_TESTNET.md wording (“refresh with light-scan… not a full genesis wallet scan”) is true relative to full-block wallet scan, but still ops-hostile without a **near-tip light snapshot bootstrap**.

## Finding F45 (checkpoint-log cross-check requires attestation at exact tip)

After bootstrapping bob to scan_height=4050 and scanning to tip **4063**:

`
mfn-cli ... wallet light-scan --checkpoint-log ... 
→ exit 1: checkpoints.jsonl has no attestation at tip_height 4063
`

Log max_tip_height was **4057** (5 entries). Cross-check demands an attestation **at the wallet tip**, so any tip advance past the latest published entry fails the JOIN-documented command even when the wallet is correctly synced.

**Workaround that worked:** omit --checkpoint-log for the catch-up scan; run checkpoint-log verify separately; optionally checkpoint-log cross-check against a summary exported at a logged height.

## Finding F46 (SUCCESS path — get_light_snapshot + wallet balance)

Operator/debug path that made receive verify practical:

1. get_light_snapshot at height H near tip (local TCP RPC; ~50–100s first call; proxy timed out at 30s / may be disallowlisted or slow).
2. Patch wallet JSON: scan_height=H, light_checkpoint_hex, 	rusted_light_summary.
3. wallet balance (or light-scan without failing cross-check) for tip−H blocks.

### Bob (funded wave7 job dc2b02f2…)

- Fund: **done** 94672 ms; txs 7e1f911e…, 182460ef…; total 1_000_000
- Snapshot H=4050; then wallet balance → locks_scanned=13, **owned_count=2**, balance=1000000 (~23s light-scan attempt + balance)

### Alice (funded wave6 job 65cd9931…)

- Snapshot H=4036 (just before wave6 fund heights)
- wallet balance → locks_scanned=27, **owned_count=2**, balance=1000000, **sync_needed=false** in **41.7s**

## Finding F47 (B-22 near-tip publish is load-bearing)

During this wave the repo log moved **4028 → 4050 → 4057** (entries 2 → 4 → 5) via lane-7 Path A refresh (22-checkpoint-tip4049-20260720.md). Without near-tip entries, even post-sync cross-check cannot pass. Publish cadence should track tip within a small delta of live height for JOIN.

## Finding F48 (concurrent light-scans thrash)

Two parallel mfn-cli light-scan processes showed ~1s CPU over minutes while mfnd served serial get_block_txs ~1.5s each. Prefer single-wallet scan against a local observer.

## Finding F49 (local RPC is TCP, not HTTP)

Invoke-RestMethod http://127.0.0.1:18734 → protocol violation. mfn-cli / newline-delimited JSON-RPC TCP works. Public :8787 is HTTP JSON-RPC only.

## Faucet job matrix (waves 6–7)

| Wallet | Job | Duration | Status | tx_ids |
| --- | --- | --- | --- | --- |
| alice | 65cd9931ce939a143a026b3a | 122157 ms | done | d9a9173a…, 9c7ed8b5… |
| bob | dc2b02f247454f4595f9fa28 | 94672 ms | done | 7e1f911e…, 182460ef… |

EAGAIN streak from waves 4–5 is cleared while tip advances and faucet wallet telemetry is non-null.

## B-15 status

Receive verify is **green** for two wallets. Remaining for formal JOIN PASS:
1. Run join-testnet-rehearsal (or smoke) with archive — respect faucet lock / no parallel JOIN on Hetzner
2. Permanence upload/restore evidence
3. Document JOIN doc fix: snapshot bootstrap + tip-delta checkpoint publish (file §6/ROADMAP request to lanes 5/7)

**Ask lane 5:** clarify JOIN_TESTNET that --checkpoint-log is post-sync attestation, not a skip-ahead; document get_light_snapshot bootstrap for tall tips.
**Ask lane 7:** keep Path A checkpoint within ~tens of blocks of live tip; consider allowing cross-check against latest attestation ≤ tip.

## Finding F50 (permanence upload SUCCESS)

Alice uploaded _wave7-permanence-sample.txt (72 bytes) via local RPC:

| Field | Value |
| --- | --- |
| outcome | Fresh |
| tip_height at submit | 4069 |
| tx_id | 12d714056c3b8a69e99d8bb8b236fc22350e60c7ea74314069bcf4eef7a68957 |
| data_root | d672f484780350a38a858c15ef48ac0396b4b41eb4278ae155ffa98407cc4cc6 |
| storage_commitment_hash | a20fcb43a5aec973e5621aa0db5b303380a41a4a4b0d76cd4700412117e2bee9 |
| fee / anchor_value | 1005 / 1000 |
| ring_size | 16 |
| replication | 3 |
| upload_elapsed | ~12.9s |
| artifact saved | true (under alice.upload-artifacts/…) |

Post-submit wallet: pending_spent_count=2, alance_cached=0 (change not yet scanned / spent both faucet UTXOs into upload+change). Confirm inclusion by tip advance + rescan in follow-up.

## Tools note

Board mentions ootstrap-wallet-from-checkpoint-log.sh — prefer that over hand-patched wallet JSON for JOIN archive once verified.


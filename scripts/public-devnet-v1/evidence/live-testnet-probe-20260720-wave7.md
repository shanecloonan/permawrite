# Live public testnet probe — wave 7 open (2026-07-20)

**Lane:** 3 (onboarding / B-15)
**UTC open:** ~03:02Z
**Prior:** wave6 e5d57de (tip recovered, alice faucet SUCCESS)
**Goal:** receive verify — checkpoint light-scan alice → owned_count >= 2

## Pre-scan wallet status (local mfnd TCP 127.0.0.1:18734)

Local mfnd tip matched public tip (**4041–4042**). PowerShell HTTP to :18734 fails (raw TCP JSON-RPC); mfn-cli works.

`json
{
  "balance_cached": 1000000,
  "owned_count_cached": 1,
  "scan_height": 250,
  "blocks_behind": 3791,
  "sync_needed": true,
  "tip_height": 4041,
  "light_checkpoint_present": false
}
`

**F43:** Cached balance already 1_000_000 with only **1** owned UTXO at scan_height 250 — consistent with partial historical scan + wave6 dual-send not yet fully discovered. Receive verify requires re-scan to tip.

## Checkpoint log

mfn-node/testdata/public_devnet_v1.checkpoints.jsonl:
- checkpoint_log_verify_ok entries=2
- max_tip_height=4028 (Path A signer permawrite-maintainer-path-a-2)
- Gap to live tip ~4042 ≈ **14 blocks** if bootstrap works (vs ~3790 from scan_height 250)

## In flight

`
mfn-cli --rpc 127.0.0.1:18734 --wallet scripts/public-devnet-v1/user-wallet/alice.json \
  wallet light-scan --checkpoint-log mfn-node/testdata/public_devnet_v1.checkpoints.jsonl
`

- pid started alive; --json **rejected** on this binary (light-scan has no --json flag — docs/script drift vs wallet status/balance)
- Logs: evidence/_alice-light-scan-wave7.out / .err (local, not committed)

## Public chain pulse at open

- tip_height **4042** advancing
- faucet still green post-wave6

## Pass criteria (this wave)

| Check | Target |
| --- | --- |
| light-scan exits 0 | required |
| wallet status sync_needed | false |
| owned_count_cached | >= 2 (F7 dual faucet outputs) |
| balance_cached | >= 1000000 (prefer 2000000 if wave1+wave6 both kept) |

Addendum will record exit timing, final status JSON, and any checkpoint bootstrap errors.

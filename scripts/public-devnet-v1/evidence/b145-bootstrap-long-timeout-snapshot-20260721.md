# B-145 — tall-tip bootstrap snapshot timeout (B-15 unblock)

Date: 2026-07-21
Lane: 3 (seat C)
Unit: B-145

## Root cause

`get_light_snapshot` at Path A tip **5290** takes ~**145s** on a synced local observer and returns ~2KiB.
`mfn-cli` default RPC I/O timeout is **30s**, so F67 pin-then-fund fails with os error 10060 (mislabeled as hub EAGAIN).

## Fix

`bootstrap-wallet-from-checkpoint-log.sh` fetches the snapshot via python NDJSON with
`MFN_BOOTSTRAP_SNAPSHOT_TIMEOUT_SECS` (default **300**).

Follow-up (lane 5): wire `MFN_CLI_RPC_IO_TIMEOUT_SECS` into mfn-cli for native long calls.

## B-15

Re-run `join-testnet-rehearsal-smoke --use-live-urls --archive-evidence` after this lands.

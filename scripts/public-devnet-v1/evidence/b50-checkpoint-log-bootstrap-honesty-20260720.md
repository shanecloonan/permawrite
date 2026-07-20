# B-50 — Checkpoint-log light-scan honesty + bootstrap helper (2026-07-20)

## Finding

`wallet light-scan --checkpoint-log` **does not bootstrap** to the signed tip. It only cross-checks the post-sync summary against the JSONL (**F12** phase 2). Fresh wallets still start at height 1 and walk headers — B-15 wave7 alice scan at tip ~4k was effectively a long genesis walk despite the published tip-4028/4050/4057 log.

## Live corroboration

- Tip-4057 Path A entry published (public seed anchors).
- Fresh-wallet `light-scan --checkpoint-log` on VPS produced no progress for >3 minutes (silent walk).
- `get_light_snapshot(height=4057)` under concurrent faucet keepalive hit hub RPC EAGAIN (os error 11).
- Hub journal again: `mfnd_p2p_peer_quarantine … os error 11` on voter — **B-48 still not on main** (lane-4 WIP).

## Delivered

- `bootstrap-wallet-from-checkpoint-log.sh` — pin via snapshot then light-scan delta + cross-check.
- `JOIN_TESTNET.md` corrected.
- Rehearsal smoke plan gate.

## Follow-ups

- Lane 5+7: Rust — make `--checkpoint-log` (or a new flag) auto-bootstrap from log max tip (preferred UX).
- Lane 4: commit **B-48** immediately — live EAGAIN quarantine recurred at tip ~4063.

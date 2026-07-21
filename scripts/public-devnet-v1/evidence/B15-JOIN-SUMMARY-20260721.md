# B-15 JOIN_TESTNET outside-in SUMMARY — 2026-07-21

**Status:** PASS (assert green)
**Lane:** 3 (seat C)
**Evidence:** `scripts/public-devnet-v1/evidence/join-testnet-rehearsal-windows-20260721T191340Z.txt`
**Assert:** `assert-join-testnet-rehearsal-evidence` OK tip_height=5322

## Proven on live public-devnet-v1

| Step | Result |
| --- | --- |
| Local observer tip_id match / sync | PASS (fresh `b15-fresh` after corrupt chain quarantine) |
| Checkpoint-log verify | PASS (entries=48, max tip 5290) |
| F67 pin-then-fund | PASS (after B-145 long snapshot timeout + B-146 plain wait scan) |
| Soft light-scan (F45 tip race) | PASS soft |
| Observer proxy cross-check | PASS |
| Permanence upload+prove+restore | PASS commitment `a2b15268…` restored_sha256 `d67c656e…` |
| Evidence assert | PASS |

## Tooling that unblocked this run

- **B-141** `3agent.md` three-seat cockpit
- **B-144** Windows/MSYS `lib-python3.sh` + mfn-cli.exe resolve
- **B-145** tall-tip `get_light_snapshot` ~145s > mfn-cli 30s I/O — python NDJSON 300s
- **B-146** fund-wait plain light-scan (hard `--checkpoint-log` F45 aborted UTXO discovery)

## Still open (not B-15 blockers)

- [ ] Human sign-off cell in TESTNET_CHECKLIST
- [ ] Path A republish (lag tip~5322 vs ckpt 5290) for exact-tip F12 hard path
- [ ] **B-42** invite-load live (unlocked)
- [ ] 2nd operator host for **B-32**

## §6

B-15 parallel-JOIN lock can clear after this archive is on `main`.

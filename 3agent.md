# 3agent — three-seat session cockpit

> **Authority:** [`AGENTS.md`](./AGENTS.md) wins every disagreement (claims, backlog, §6, pipeline).
> **This file:** human-facing Done / Doing / Next for up to **three concurrent agents**.
> **History:** retired 3agent session dumps live in [`docs/AGENTS_LEDGER.md`](./docs/AGENTS_LEDGER.md).
> **Release gates:** still tick [`docs/TESTNET_CHECKLIST.md`](./docs/TESTNET_CHECKLIST.md) and mirror TL in [`docs/TESTNET_LAUNCH.md`](./docs/TESTNET_LAUNCH.md).

Update this cockpit in the **same commit** as the unit it describes. If it drifts from `AGENTS.md` §5, fix the board first, then mirror here.

## Seats (map to lanes)

| Seat | Focus | Owns (lanes) | Does not steal |
| --- | --- | --- | --- |
| **A** RC/CI | CI, Nightly, board integrity | Lanes 1–2 | **B-296**, protocol tests |
| **B** Protocol/Privacy | Consensus / privacy / economics | Lanes 4–5–6 | **B-296**, Nightly cancel, VPS/faucet |
| **C** Validity proofs | F5 phase 4 / B-12 / B-39 (research) | `validity_stark_*`, FRAUD_PROOFS phase 4 | VPS, faucet, Seat A economics, Seat B privacy/slash |
| **D** Network anonymity | Transport, Dandelion, eclipse/DoS, RPC exposure | Lane 8: `mfn-net`, node P2P, RPC bind | Consensus, `validity_stark_*`, wallet rings, VPS/faucet |
| **F** Ease of use | Wallet, CLI, WASM, frontend for ordinary people | User flows in `mfn-wallet`, `mfn-cli`, `mfn-wasm`, `testnet-frontend` | Consensus, header versions, ring-floor pins, validity proofs, VPS/faucet |
| **G** Security hardening | Hostile input must not crash, stall, or fork the node | Fuzz, resource limits, adversarial tests, minimal decode fixes | Other seats' features, VPS/faucet, header-version flips |

Lane **6** (permanence sims) arms day-of L4; park under seat A or B when claimed — never silent.

## Live seats (NOW)

Synced at Seat C **B-12** Plonky3 aggregate (off consensus; not an inner verifier). Path A and F-A unchanged. Nightly `#31861932921` **GREEN**.

| Seat | Done | Doing | Next |
| --- | --- | --- | --- |
| **A** RC/CI | Arweave weave-is-the-copy availability (`7464ad8d`); CI-commit bind `b0bd1caa` | *Idle* | Fix scripts FAIL on historical heads; **B-26** after B-15 |
| **B** Protocol/Privacy | **B-323** distinct ring members (PR #151); **B-331** light trusted-evolution binds `slashing_root` + CLI/WASM tagged decode (this PR); **B-330** equivocation bind (`54c86aa8`); **B-317**; **B-37** | *Idle* (agent 2/3 between rounds) | Bind `bond_root` after §6 storage-operator section; then lock rule / seed grinding (review §2). No DEFAULT flip |
| **C** Validity proofs | **B-12** Plonky3 aggregate (this commit); **B-317**; **B-316** | *Idle* | Inner STARK verifier (rest of B-12) |
| **D** Network anonymity | **D-1** Dandelion stem privacy (PR #40); onion no-clearnet advertise (PR #42 `a5e83d68`); inbound /16 cap (PR #45); peer exchange + seed bootstrap (PR #88/#89) | *Idle* | Noise_XX (PR #67 open); anchor connections (PR #82 open) |
| **F** Ease of use | **F-8** browser file backup card | *Idle* | **F-9** `wallet ready` checklist |
| **G** Security | **G-12** mempool cheap-reject before verification (this PR); **G-11** (`2d4aaacf`, PR #153); **G-1** (`6eb8473f`, PR #99) | *Idle* | **G-13** next resource bound; G-3/4/9/10 merged; G-2/5/6/7/8 are in open PRs #105/#117/#123/#129/#133 |

### Hard locks (all seats)

1. **B-15 lock:** do **not** run parallel `join-testnet-rehearsal*` on Hetzner; prefer not to restart `faucet-http` / thrash `mfnd-hub` while tip sealing.
2. **CI concurrency:** if GitHub CI is in_progress on main, prefer [skip ci] for docs/ops; never cancel a healthy run. Tip CI `#32578440244` rust GREEN / scripts FAIL; Nightly `#31861932921` GREEN. PRs run slim CI (fmt, clippy, Linux tests/scripts); full multi-OS matrix + wasm + audit run on main push and nightly — watch the main head after merging.
3. **Foreign WIP:** never stage lane4 `apply_block_proptest.rs` / B-275 body, or another seat's uncommitted files. Seat C owns `onchain-tx-storm*` for **B-277**.
4. **Privacy/permanence first:** no silent ring/SPoRA/endowment downgrades for speed.
5. **Lane7 VPS apply:** restart `observer-rpc-proxy` + `testnet-frontend` only — never mfnd / faucet-http.
6. **Seat C validity track (2026-11-14):** no join rehearsal, no faucet, no mfnd restart. Do not edit Seat A economics files or Seat B privacy/slash files. Validity leaves stay off `apply_block` (no fork, no Path A / F-A, no DEFAULT flip).

## Critical path (shared)

```text
L4 public testnet harden
  ├─ Seat C: F5 phase 4 (B-316, B-317, B-12 aggregate done). Inner verifier still open. No VPS.
  ├─ Seat B: sixteenth prove matrix (B-241→B-242…) → B-32 (needs 2nd host)
  ├─ Seat A/B+lane6: B-13a GREEN pin → B-40 / B-25 permanence gate
  └─ Seat A: green CI+Nightly pins on heads
→ TL-9 invites: B-42 → B-14 (seat C) after B-15 PASS
```

## Collaboration protocol

1. **SYNC** `AGENTS.md` §5–§8 + this file + `git log -15` + `gh run list` (when API allows).
2. **CLAIM** on `AGENTS.md` §5 first (lane Doing + claim base), then mirror the seat row here.
3. **BUILD / PROVE / LAND** per `AGENTS.md` §3; tick TESTNET checklist when a release gate closes.
4. **CLOSE:** clear seat Doing (or claim next), prepend `AGENTS.md` §8, keep this cockpit ≤ one screen of Now.

## Chat announcement (copy)

```text
3agent — Seat A: Done Arweave weave-is-the-copy availability docs / Doing idle / Next fix scripts FAIL #31909490680
3agent — Seat B: Done B-317 retrieval challenges at header v7 / Doing idle / Next output-count padding, header-gated (no DEFAULT flip)
3agent — Seat C: Done B-12 Plonky3 aggregate / Doing idle / Next inner STARK verifier
(AGENTS.md §5 remains the claim surface)
```

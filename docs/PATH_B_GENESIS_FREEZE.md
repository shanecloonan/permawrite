# B-43 — Path B genesis freeze inventory

**Status:** inventory draft (lane 7). Does **not** start a Path B ceremony. Does **not** claim L5.

**Doctrine:** privacy (ring policy, no silent downgrade) and permanence (endowment, SPoRA verification, treasury floors) are non-negotiable. Path B must not weaken them to ship faster.

**Gates before ceremony:** **B-25** Phase-1 permanence go/no-go (or explicit named-human waiver). Green CI + Nightly on the invite head. See [`ROADMAP.md` B-43](./ROADMAP.md#b-43--path-b-genesis-freeze-inventory-lane-7--before-l5) and [`TESTNET_GENESIS_CEREMONY.md`](./TESTNET_GENESIS_CEREMONY.md) Path B.

---

## Freeze table

| Freeze item | Owner | Locked when | Current note |
| --- | --- | --- | --- |
| Constitution / ring / endowment floors | 4+6 | Written invariant list Path B must preserve | Enforced today via `mfn_consensus::constitution` load; Path B genesis must keep floors |
| Header v2 / `utxo_root` in BLS bytes | 4 | Decision: enable `header_version: 2` on **new** chain only (yes/no + rationale) | **TBD** — lane 4 design note before ceremony |
| Validator / BLS PoP material | 7+human | Ceremony roles named; offline seed handling; never paste keys in chat | Roles: **TBD (human)**; tooling: `genesis-validator-bls-pop.sh --verify` |
| `require_validator_bls_pop` + genesis JSON shape | 4+6 | Spec fields + verify command pinned | Helper exists; Path B must set `require_validator_bls_pop: 1` |
| Economics levers | 6 | Which of B-13c / B-306b drip+backstop / PM1 bonds / **B-20** fee-shift / PM41 cap / fee params land on Path B vs stay Path A | **B-306c** helper pins Path B `storage_proof_reward`; **B-307** helper pins Path B `min_storage_operator_bond = recommended_min_storage_operator_bond`; **B-308** lottery ranking is Path B / **B-44** after **B-32** (Path A stays first-to-publish); **B-309** pins stressed `fee_to_treasury_bps=10000` (Path A stays 9000); **B-310** prune is optional Path B archival-node later (Path A keeps full `chain.blocks`); **B-311** PM41 cap binds only after prize shrink (Path A stays unbounded mint); **B-312** runway metric is ops/RPC (same formula Path A/B). Do not silent-fork Path A (prize stays 0.1 MFN, drip stays 0, bonds stay 0, fees stay 9000, full log, unbounded backstop) |
| Topology | 7 | Role-separated hosts per [`REFERENCE_TOPOLOGY.md`](./REFERENCE_TOPOLOGY.md) | Current public testnet is single-VPS Path A — **not** Path B topology |
| Wipe + re-soak plan | 7 | Data-dir wipe, TL-5/TL-6 re-run, invite/docs republication | Checklist below |
| Sign-off cells | human | Named approvers | **TBD (human)** |

---

## Wipe + re-soak checklist (Path B day-of)

1. Halt Path A invites; announce cutover window.
2. Archive final Path A tip + checkpoint log + release evidence for the last toy head.
3. Offline-generate validator VRF/BLS seeds; run PoP verify; never commit seeds.
4. Publish new genesis JSON + `genesis_id` + manifest `seed_nodes`.
5. Wipe VPS data dirs (hub/voters/observer); redeploy role-separated hosts if available.
6. Re-run TL-5 soak + TL-6 participant rehearsal; archive PASS transcripts.
7. Republish JOIN / INVITE / checkpoint log; open invites only after `launch-go-no-go`.

---

## Explicit non-goals

- No Path B genesis bytes in this unit.
- No weakening of ring size / decoy policy / endowment enforcement / SPoRA verification for ceremony convenience.
- Path A toy keys remain **non-value** forever on `public-devnet-v1`.

---

## Sign-off (fill at ceremony, not now)

```text
B-43 inventory reviewed: ____________________ (date UTC)
B-25 (or waiver) reference: ____________________
Path B ceremony approver: ____________________
Halt authority: ____________________
```

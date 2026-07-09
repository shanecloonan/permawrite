# B1 — Endowment range-proof binding (B-11 phase 2)

Permanence hardening companion to [`PERMANENCE_HARDENING.md § B1`](./PERMANENCE_HARDENING.md#b1-range-proof-endowment-binding-b-11-phase-2--consensus).

## Problem

**Phase 1 (shipped)** binds `StorageCommitment.endowment` via an `MFEO` Pedersen opening in `tx.extra`. Consensus verifies the opened amount is ≥ `required_endowment(...)` and matches the commitment point. The opened amount is **public on-chain** — over-payment privacy is lost.

**Phase 2 (this track)** replaces the opening reveal with a Bulletproof range proof that the committed endowment opens to at least the protocol-required amount **without revealing** how much was over-paid.

Networks with `require_endowment_opening = 0` still rely on the fee route only (no Pedersen binding). Phase 2 closes that gap with a privacy-preserving alternative to phase 1.

## Cryptographic sketch

For each new storage anchor in a tx:

1. Let `R = required_endowment(size_bytes, replication, params)` (public).
2. Let `C = sc.endowment` (Pedersen point in the commitment).
3. Let `B = commit(R, 0)` (Pedersen commitment to the required minimum with zero blinding).
4. Homomorphically form `D = C − B` (point subtraction).
5. Prove with a Bulletproof that `D` opens to a value in `[0, 2^64)` — i.e. the user escrowed at least `R` without revealing the surplus.

Reuses [`bp_prove` / `bp_verify`](../mfn-crypto/src/bulletproofs.rs) from transaction output range proofs (~700 bytes per upload).

## Consensus flag

| Field | Default | Meaning |
| --- | --- | --- |
| `require_endowment_range_proof` | `0` | Inert until phase 2b wires verification |
| `require_endowment_opening` | `0` | Phase 1 MFEO reveal (public devnet: `1`) |

**Mutual exclusion:** `require_endowment_range_proof` and `require_endowment_opening` cannot both be `1`. A chain picks one binding mode per era.

Checkpoint **v10** persists `require_endowment_range_proof`.

## Rollout phases

| Phase | Scope | Status |
| --- | --- | --- |
| **2a** | Inert param + checkpoint v10 + genesis merge + validation | **Done** — `76b5f8f` |
| **2b** | Wire `MFER` proof frames in `tx.extra`; `apply_block` + mempool verify | **This commit** |
| **2c** | Wallet upload builds proof; M5 proptests (valid / forged / mixed CLSAG) | Partial — proptest treasury + reject/accept |
| **2d** | Optional devnet flip after green CI + RC evidence | Planned |

## Test plan (phase 2b+)

- Reject upload when proof missing and flag enabled.
- Reject forged proof (wrong commitment / under-funded).
- Accept valid proof with over-payment hidden.
- Treasury identity proptests unchanged when fee route + proof both satisfied.
- Checkpoint roundtrip with `require_endowment_range_proof = 1`.

## See also

- [`PERMANENCE_HARDENING.md § A6`](./PERMANENCE_HARDENING.md#a6-pedersen-endowment-opening-binding-b-11-phase-1-commits-3511346--9f0a0aa--0fee187) — phase 1 MFEO
- [`AGENTS.md`](../AGENTS.md) — B-11 backlog (phase 1 done)

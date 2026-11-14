# Validity STARK backend (F5 phase 4)

Decision for recursive block validity. Off consensus: nothing here is a header
field, a `DEFAULT_*` change, or a Path A / F-A genesis change.

## What shipped in 4b.1

`mfn-consensus/src/validity_stark_winterfell.rs` (Winterfell **0.10.1**, feature
`winterfell`, base field `f128`, hasher Blake3-256, no field extension).

The AIR is one quadratic step, `acc' = acc * 127 + chunk`, over
`parent_checkpoint || block_wire`, plus three public counters (`tx_count`,
`spora_count`, `coinbase_flag`) written onto a side column. Trace length is a
power of two in `[8, 4096]`. Proof options match a fast conjectured ~96-bit
setting: 32 queries, blowup 8, grinding 0, `FieldExtension::None`.

That proof shows the prover hashed those bytes and those three counters. It
does not show that a transaction, the coinbase, or a storage proof is valid.
Witness kind `3` still replays `apply_block` after the STARK check.

`dhash` (the Merkle compression in `mfn-crypto`) is domain-separated SHA-512.
A SPoRA path is not a small AIR. A field accumulator is not a substitute for
`verify_merkle_proof`.

## Backend choice

| Stage | Backend | Why |
| --- | --- | --- |
| **4a leaves** (this track) | **Stay on Winterfell 0.10** | Already linked, transparent setup, enough for algebraic leaves. Same options as 4b.1. |
| **4b.2 / B-12 recursion** | **Re-express the leaves in Plonky3** | Winterfell 0.10 has `Prover` / `verify` and no recursive verifier, no IVC, and no composition API. Recursing it means arithmetizing FRI and Blake3 inside an AIR. Plonky3 is the maintained transparent STARK stack whose recursion path is actually used. The Winterfell leaves stay the conformance spec the port must match. |
| **CLSAG / Bulletproof leaf** (later) | Halo2, only if we must verify curve25519 inside the circuit | Not the aggregator. Pasta/KZG assumptions are a worse fit for the "no trusted setup" story than a STARK. |
| **Nova / HyperNova** | Not the first aggregator | Folding wants one repeated step. A block is several shapes (subsidy, fee split, Merkle, ring). |
| **Groth16** | No | A trusted setup per circuit. |
| **zkVM (SP1 / RISC Zero)** | Not this unit | A possible later shortcut to "prove `apply_block`". It does not replace small leaves we can audit against the Rust functions. |

Phase 4a order stays: algebraic leaves first, then a STARK-friendly Merkle leaf
once a compression is chosen, then rings. Aggregation waits until those leaves
exist. SPoRA challenges stay Merkle-native; a validity proof may wrap
`verify_storage_proof`, not replace the operator challenge.

## Leaf landed with this decision (B-316)

`mfn_consensus::validity_stark_coinbase`, still feature-gated, still not called
from `apply_block`:

1. **`emission_at_height`.** Public inputs are height, halving period, halving
   count (at most 64), initial reward, tail, and the claimed subsidy. The
   witness is the era quotient. The AIR checks `era * period + rem = height - 1`
   with `rem < period`, then either the tail (`era >= count`) or
   `initial = subsidy * 2^era + low` with `low < 2^era`. Height 0 forces
   subsidy 0. The honest prover also requires the claim to equal
   `emission::emission_at_height`; `verify` does not recompute that function.
2. **Coinbase bps split** inside `producer_portion_amount` (no storage-proof
   term). Public inputs are the subsidy, both bps values, the fee sum, and the
   treasury / producer / portion outputs. The AIR checks
   `amount * bps = treasury * 10000 + rem` with `rem <= 9999`, plus the two
   exact sums. That is the unique integer quotient for `bps <= 10000`.

Both verifiers reject a tampered public output. Neither proof is gossiped.

## Field-Merkle leaf (B-317)

`mfn_consensus::validity_stark_merkle` proves a depth-4 opening under
`field_merkle_compress`: eight MiMC-5 rounds (`x -> (x + c)^5`) on the same
`f128`. Lists pad to 16 leaves with the pad element `2`. The public inputs are
the leaf, the root, and the index. Siblings stay in the proof.

This does not verify `mfn_crypto::merkle` or a SPoRA path. Those compress with
SHA-512 `dhash`. The fifth-power rounds are there so the parent mix is not a
single multiplication. Raising the depth is a constant change; it is not a
consensus fork.

## B-12 first Plonky3 aggregate

`mfn_consensus::validity_stark_plonky3` (feature `plonky3`, not a default
feature) is one BabyBear STARK of three statements: the fee basis-point split,
and two depth-4 openings under a 4-round seventh-power hash. It is statement
aggregation. It does not verify a Winterfell proof inside another proof. That
inner verifier is the rest of B-12. Numbers that do not fit in BabyBear are
rejected. Path A and F-A are unchanged.

The public input ends with four parent-digest limbs. `verify_aggregated_outputs`
checks a proof against those limbs and the claimed fee split and roots. It does
not divide the fee and it does not hash the path. `fee * bps` still has to sit
under the field modulus, and the remainder has to be below 10_000, so the
in-circuit equation has one integer solution. A different parent limb does not
verify. Nothing here is written into a block header or gossiped.

## B-318 local witness envelope

`encode_aggregated_witness` writes `MFVW`, version 1, and a JSON object of the claimed outputs plus the Plonky3 proof. `verify_aggregated_witness` checks that envelope with `verify_aggregated_outputs`. A bad magic, a truncated body, or a version other than 1 is rejected before the STARK. This is the producer-side file for phase 4c. It is not gossiped.

`parent_limbs_from_coinbase` packs height, emission, treasury fee, and producer fee into the four parent-digest limbs. A light client that passes a different height does not verify. Values that do not fit in BabyBear are rejected. The limbs are not a hash of a Winterfell proof.

The same statement now names `tx_count` and `spora_count`, each at most 1_024. Both values are public inputs and trace columns. A different count does not verify.

A witness bigger than one mebibyte is refused before it is parsed. `scripts/check-validity-witness-frame.py` checks the frame only. It does not run the STARK.

`prove_empty_block_witness` is the file for a block that moved no fee and named no user transaction or storage proof. The two openings are a public zero leaf. The empty claim is the zero fee and the zero counts.

`parent_limbs_from_outputs` pins an inner statement's fee sum, treasury fee, producer fee, and tx count into the outer proof's parent digest. The outer AIR does not verify the inner FRI proof. That inner verifier is still open.

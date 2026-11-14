# Design review — fundamental-mechanics pass (2026-11)

**Scope.** Read-only review of `main` at `1d5061c` (merge of PR #7), dated
**2026-11-13**. Open PRs #8–#20 were not on `main` and are not covered. The
question asked: *is there anything in the mechanics that would make Permawrite
not work as intended, no matter how well it is implemented?* Environmental
issues (encryption aging, harvest-now-decrypt-later, access revocation) and
ordinary unfinished work are out of scope.

**Verdict key.** **SOUND** — no gap found. **GAP** — real problem, solvable
(fix described). **FUNDAMENTAL (as worded)** — the stated guarantee cannot be
delivered by any implementation; an honest, deliverable restatement is given.

## Overall answer

Nothing found makes Permawrite unworkable no matter how well it is built. No
coin-forging, inflation, or double-spend path was found in the privacy layer.
One serious but easy-to-fix slashing bug and one consensus-protocol gap were
found. Two storage *claims* — "N independent replicas" and "guaranteed
retrieval" — cannot hold as worded and should be restated. Hidden endowments
are currently cosmetic: storage is paid from the public fee.

| # | Area | Verdict |
| --- | --- | --- |
| 1 | Equivocation slashing evidence | GAP (serious, easy fix) |
| 2 | Finality voting / lock rule | GAP |
| 3 | "N independent replicas" | FUNDAMENTAL (as worded) |
| 4 | "Guaranteed retrieval" | FUNDAMENTAL (as worded) |
| 5 | Hidden endowments | GAP (coherence) |
| 6 | Privacy proofs (CLSAG / Bulletproofs / key images / ring membership) | SOUND |
| 7 | Block formation, fee split, coinbase, perpetuity math | SOUND (assumption-dependent economics) |
| 8 | Validity proofs (STARK / recursion path) | GAP (feasible, unfinished) |

## 1. Equivocation evidence does not bind height or slot — GAP (serious)

[`verify_equivocation_evidence`](../mfn-consensus/src/slashing.rs)
(`mfn-consensus/src/slashing.rs`, ~L374) accepts evidence when the two header
hashes differ and both BLS signatures verify under the validator's key. The
`height` and `slot` fields carried in `EquivocationEvidence` are never checked
against what was actually signed: committee votes sign `header_signing_hash`
([`block/header.rs`](../mfn-consensus/src/block/header.rs)), and the evidence
carries only hashes, so the verifier cannot tell whether the two headers share
a height and slot. An honest validator signs a different header every block,
so two of its ordinary votes satisfy the check, and
`apply_equivocation_slashings`
([`validator_evolution/equivocation.rs`](../mfn-consensus/src/validator_evolution/equivocation.rs))
then zeroes its stake. The defect is a missing validation rule, not a
cryptographic weakness.

**Fix (small).** Either (a) carry the two header preimages (or the signing
bytes) in the evidence and require equal `height` and `slot` with distinct
hashes, or (b) make votes sign a transcript that explicitly binds
`(height, slot, header_hash)` and verify the two transcripts share height and
slot. Add an `apply_block`-level negative test: two votes at different heights
must be rejected as evidence. (Defensive description only.)

## 2. Single-round finality has no lock rule — GAP

Voting is one round: a producer gathers ≥ 2/3 stake of BLS votes
([`cast_vote`](../mfn-consensus/src/consensus/engine.rs), staged in
[`mfn-runtime/src/producer.rs`](../mfn-runtime/src/producer.rs)), and
[`CONSENSUS.md`](./CONSENSUS.md) claims a single finalized chain. There is no
rule tying a validator's vote at one slot to its votes in later slots at the
same height. Under partial synchrony this forces a choice: if validators may
vote again at the same height in a later slot, a withheld quorum block and a
later one can both finalize (safety loss); if they may vote only once per
height, a split vote can leave no block with 2/3, and the height stalls
permanently (liveness loss). This is the classic reason BFT protocols use
multi-round voting with locks/justifications.

**Fix.** Adopt a Tendermint- or HotStuff-style round structure (prevote /
precommit or chained QCs, lock on a QC, unlock only on a higher-round QC,
round-change timeouts), with slashing defined over that transcript (ties into
§1).

**Smaller note — seed grinding.** [`slot_seed`](../mfn-consensus/src/consensus/engine.rs)
hashes `prev_id`, which the producer can vary by changing block contents, so
a producer can bias its own next-slot eligibility. Deriving the seed from the
previous VRF output (or an epoch randomness beacon) reduces this to a
publish-or-withhold bias.

## 3. "N independent replicas" — FUNDAMENTAL (as worded)

Challenges are salted per operator
([`chunk_index_for_operator_challenge`](../mfn-storage/src/spora.rs)) and the
number of accepted proofs per commitment is capped at `replication`
([`block/apply.rs`](../mfn-consensus/src/block/apply.rs), storage-proof loop).
Possession proofs show that *a* copy is reachable by the prover, not that
separate operators each hold one: one party can register several operator
identities over a single copy, or fetch a challenged chunk just in time from
another holder. Sealing / proof-of-replication (Filecoin-style slow encoding)
can prove N *encoded copies*, but no on-chain proof can show N *independent
operators* (different owners, hardware, jurisdictions). Distinct-seal
enforcement is not wired into consensus today (`distinct_replica_floor_met`
is a non-consensus helper).

**Honest restatement.** "Proofs show at least one retrievable copy;
replication is paid for and incentivized; with sealing, N distinct encoded
copies can be proven."

## 4. "Guaranteed retrieval" — FUNDAMENTAL (as worded)

SPoRA ([`verify_storage_proof`](../mfn-storage/src/spora.rs),
`verify_storage_proof_operator_salted`) proves possession, not serving;
[`STORAGE.md`](./STORAGE.md) already places retrieval in an off-chain gateway
layer. Refusing to serve a user is not provable to the chain (the user cannot
show non-delivery to third parties), so it cannot be fairly slashed.

**Honest restatement.** "At least one copy is proven to exist, and serving is
incentivized (reputation, paid retrieval, gateway redundancy), not
guaranteed."

## 5. Hidden endowments are not backed by coins — GAP (coherence)

The `StorageCommitment.endowment` Pedersen point is range-proven to be ≥
`required_endowment(...)`
([`verify_endowment_range_proof_wire`](../mfn-storage/src/spora.rs);
B-11 phase 2 block in [`block/apply.rs`](../mfn-consensus/src/block/apply.rs);
[`B1_ENDOWMENT_RANGE_PROOF.md`](./B1_ENDOWMENT_RANGE_PROOF.md)), but it is not
a term in the transaction balance equation
([`transaction/verify.rs`](../mfn-consensus/src/transaction/verify.rs):
Σ pseudo − Σ outputs − fee·H = 0). Nothing debits the committed value.
Storage is actually funded by the public check
`tx.fee × fee_to_treasury_bps / 10_000 ≥ required_endowment`
(`UploadUnderfunded` in `apply.rs`), and rewards are computed from the public
`required_endowment(size, replication)` in
[`accrue_proof_reward`](../mfn-storage/src/endowment.rs), not the hidden
value. "Hidden over-payment" therefore hides money that was never paid.

**What a real hidden endowment would require.** A public treasury cannot
absorb hidden amounts without revealing them. Options: put the endowment
commitment into the balance equation and route it to a *committed* (hidden)
treasury or per-file escrow, with payouts and solvency proven in zero
knowledge; or drop the hidden-surplus claim and document the endowment as
public-fee funded.

## 6. Privacy proofs — SOUND

[`verify_transaction`](../mfn-consensus/src/transaction/verify.rs) checks
Bulletproof range proofs bound to each output commitment, the balance
equation, and rejects identity and non-prime-order (torsion) key images.
`apply_block` requires every ring member to be a live UTXO with a matching
commitment (`RingMemberNotInUtxoSet` / `RingMemberCommitMismatch`) and rejects
reused key images (`DoubleSpend`). `H = hash_to_point(G)`
([`mfn-crypto/src/point.rs`](../mfn-crypto/src/point.rs)) has no known
discrete log. No forging, inflation, or double-spend path found. Ring-16
anonymity remains a statistical property ([`PROBLEMS.md` § 9](./PROBLEMS.md)).

## 7. Block formation and economics — SOUND (assumption-dependent)

Fee split, treasury-first storage payouts with a mint backstop, and the
coinbase layout in `apply_block` have no circular dependency; the treasury
cannot go negative. Perpetuity math is internally consistent: deflation mode
`E = C₀(1+d)/d` converges only if storage cost keeps falling (an assumption,
not a theorem); yield mode requires `r > i`
([`validate_endowment_params`](../mfn-storage/src/endowment.rs)); a nonzero
tail emission is mandatory ([`emission.rs`](../mfn-consensus/src/emission.rs)).
No regime requires a finite fund to pay forever — permanence is ultimately
backed by tail emission and token value.

## 8. Validity proofs — GAP (feasible)

[`validity_stark_winterfell.rs`](../mfn-consensus/src/validity_stark_winterfell.rs)
proves a field accumulator over `parent_checkpoint || block_wire` — byte
binding, not state-transition validity; light clients still trust the 2/3
quorum ([`SECURITY_CONSIDERATIONS.md` § 2](./SECURITY_CONSIDERATIONS.md)).
Proving CLSAG / Bulletproofs / ed25519 arithmetic in a STARK with recursive
aggregation is expensive but feasible in principle.

## See also

- [`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md) — protocol trust model
- [`PROBLEMS.md`](./PROBLEMS.md) — known weaknesses inventory
- [`CONSENSUS.md`](./CONSENSUS.md) / [`STORAGE.md`](./STORAGE.md) / [`PRIVACY.md`](./PRIVACY.md)

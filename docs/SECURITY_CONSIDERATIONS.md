# Protocol Security Considerations

This document is the **protocol-level** trust-assumption and threat-model
reference for Permawrite: what the cryptography actually proves, what it
assumes, and where the residual risks live. It is the companion to
[`PROBLEMS.md`](./PROBLEMS.md) (economic/architectural weaknesses) and is
deliberately distinct from
[`PUBLIC_DEVNET_THREAT_MODEL.md`](./PUBLIC_DEVNET_THREAT_MODEL.md), which covers
**deployment/operational** risk (RPC exposure, key custody, operator mistakes)
for release candidates.

Everything below is verified against the Rust sources referenced inline. When a
statement in this document conflicts with another doc, treat the code as the
source of truth and file the discrepancy.

---

## 1. Trust assumptions

The protocol's guarantees are conditional. The complete list of things a
Permawrite node (full or light) must assume:

### Cryptographic hardness

| Assumption | What breaks without it |
|---|---|
| Discrete log on the ed25519 prime-order subgroup | Pedersen binding, CLSAG unforgeability, stealth-address security, Schnorr, VRF |
| Decisional Diffie–Hellman on the same group | Pedersen hiding, stealth-address unlinkability |
| SHA-256 / SHA-512 collision resistance | Every `dhash` domain, Merkle roots, tx/block ids, key-image derivation |
| Bulletproof inner-product soundness + Fiat–Shamir | Range proofs (no negative-amount minting) |
| BLS12-381 co-CDH / pairing hardness | Producer signatures, committee finality, slashing evidence |

These are the same assumptions Monero, Zcash-adjacent systems, and Ethereum 2.0
already make in production. None has a known practical break.

### Structural assumptions

1. **Genesis is trusted setup.** `GenesisConfig`
   ([`mfn-consensus/src/block/genesis.rs`](../mfn-consensus/src/block/genesis.rs))
   installs the initial validator set, initial UTXOs, initial storage
   commitments, and every consensus parameter without cryptographic
   authentication. Nothing downstream can detect a malicious genesis. See
   [§ 4 BLS aggregation](#4-bls-aggregation-and-rogue-key-resistance) for one
   concrete consequence (genesis validators bypass proof-of-possession).
2. **Honest ≥ quorum stake.** Finality, slashing, and the single-finalized-chain
   model all assume less than `quorum_stake_bps` (default 2/3 + 1 bp) of stake
   is adversarial.
3. **Loosely synchronized clocks.** Slot production assumes validators agree on
   wall-clock time to within a slot (~12 s target). Timestamps are not
   consensus-verified beyond monotonicity at header ingress.
4. **Network-layer privacy is out of scope for the chain.** Broadcast timing,
   IP-level correlation, and mempool observation are wallet/transport concerns
   (Tor/Dandelion-style relaying is not part of consensus). See
   [`PRIVACY.md § What "privacy" means here`](./PRIVACY.md#what-privacy-means-here).

---

## 2. What a finalized header does — and does not — prove

**Intuition.** A BLS finality quorum is a signature over a *header*, produced
by validators. It is tempting to read it as "2/3 of stake certified this block
is fully valid." That is **not** what the code enforces.

The reference voting helper
([`cast_vote`](../mfn-consensus/src/consensus/engine.rs)) verifies, before
signing:

- the producer's VRF proof and slot eligibility, and
- the producer's own BLS signature over `header_signing_hash(header)`.

It does **not** run `apply_block`. Nothing in the protocol layer forces a
committee member to have executed the state-transition function before voting.
A finalized header therefore proves:

| Proven by a finality quorum | NOT proven by a finality quorum |
|---|---|
| The producer was VRF-eligible for the slot | That the block's txs verify (CLSAG, range proofs, balance) |
| ≥ quorum stake signed exactly these header bytes | That `storage_root` / `utxo_root` match the real post-state |
| The header's body-root commitments are what the quorum saw | That the coinbase amount is correct |
| The bitmap's stake accounting is consistent | That bond ops / slashings / storage proofs were valid |

Full nodes close this gap by re-executing
[`apply_block`](../mfn-consensus/src/block/apply.rs) — an invalid block is
rejected locally regardless of its signatures. **Honest validators are expected
to validate before voting** (a quorum that finalizes an invalid block is a
slashable-in-spirit safety failure and implies ≥ quorum adversarial stake,
which is outside the threat model). But the distinction matters for:

- **Light clients.** `verify_header` + `verify_block_body`
  ([`mfn-consensus/src/header_verify/`](../mfn-consensus/src/header_verify))
  prove the delivered `(header, body)` pair is byte-for-byte what the quorum
  endorsed — **not** that the state transition inside it is valid. A light
  client's state-validity confidence is exactly "≥ quorum stake would have had
  to sign an invalid block." There are **no fraud proofs or validity proofs**
  yet; a Tier-4 recursive-SNARK milestone would upgrade this.
- **Operator documentation.** Validator implementations MUST apply the block
  (or at minimum fully validate it) before casting a finality vote, even though
  the protocol cannot verify that they did.

**Mitigation roadmap (PROBLEMS § 11).** Tier-4 work targets succinct validity
proofs bundled in (or referenced by) the header so light clients verify STF
correctness without re-executing every block. Until then: full nodes remain
the correctness anchor; light clients should treat finalized headers as
ordering + byte-binding only; exchanges and deposit infrastructure should
prefer full-node confirmation or wait for fraud-proof support.

---

## 3. Header commitment coverage — what the quorum actually signs

The committee and producer BLS-sign `header_signing_hash(header)` =
`dhash(BLOCK_HEADER, header_signing_bytes(header))`. The block id — which the
next block's `prev_hash` points to — is `dhash(BLOCK_ID, block_header_bytes(header))`.
These two encodings differ
([`mfn-consensus/src/block/header.rs`](../mfn-consensus/src/block/header.rs)):

| Header field | In `header_signing_bytes` (BLS-signed) | In `block_header_bytes` (block id) |
|---|---|---|
| `version`, `prev_hash`, `height`, `slot`, `timestamp` | ✓ | ✓ |
| `tx_root` | ✓ | ✓ |
| `storage_root` | ✓ | ✓ |
| `bond_root` | ✓ | ✓ |
| `slashing_root` | ✓ | ✓ |
| `storage_proof_root` | ✓ | ✓ |
| `validator_root` | ✓ | ✓ |
| `claims_root` | ✓ | ✓ |
| `producer_proof` | ✗ (it *contains* the signatures) | ✓ |
| **`utxo_root`** | **✗ on v1**; **✓ on v2+** ([`HEADER_VERSION_UTXO_QUORUM`](../mfn-consensus/src/block/header.rs)) | ✓ |

### The `utxo_root` nuance

On **header version 1** (public devnet v1), `utxo_root` — the UTXO-accumulator root *after* the block applies — is **not**
covered by the finality signature. On **header version 2+**, it is included in
`header_signing_bytes` and directly BLS-attested. Use
[`utxo_root_quorum_confirmation_lag`](../mfn-consensus/src/header_verify/types.rs)
when building light-client policy (`0` on v2+, `1` on v1).

**v1 binding only:**

1. **Locally**, by every full node recomputing it in `apply_block` Phase 9 and
   rejecting mismatches; and
2. **Transitively**, one block later: `utxo_root` is inside `block_header_bytes`,
   so it is committed by `block_id`, which becomes the next header's
   `prev_hash`, which *is* inside the next header's signing bytes.

Consequences:

- A full node is unaffected (it never trusts `utxo_root`; it recomputes it).
- For a light client, the **tip block's** `utxo_root` carries strictly weaker
  assurance than the other roots: it is consistent with the tip's `block_id`
  but not directly attested by the tip's quorum. One confirmation later it
  inherits full quorum binding via `prev_hash` chaining.
- Anything that consumes `utxo_root` at the tip (e.g. future OoM/Tier-3 ring
  membership proofs against the accumulator, exchange deposit logic on
  light-client infrastructure) should wait one block, or treat the tip root as
  provisional.

> **Open design question (hard fork for existing chains).** Migrating a live v1
> chain to v2 header signing is a consensus hard fork. New Path B genesis
> files may set `header_version: 2` at launch. Tracked here deliberately;
> **not** changed silently on public devnet v1.

---

## 4. BLS aggregation and rogue-key resistance

**Intuition.** Committee finality uses same-message BLS aggregation: verify one
pairing against the *sum* of the signers' public keys
([`verify_aggregate_same_message`](../mfn-bls/src/sig.rs)). Textbook attack: an
adversary who may pick their public key *after* seeing yours can register
`pk_evil = pk_target − pk_honest`, making the sum verify for signatures the
honest party never made. The standard defenses are proof-of-possession (PoP),
message augmentation, or distinct messages.

Permawrite's defense is **PoP-by-registration**:

- Every `BondOp::Register` must carry a BLS signature, verified under the
  *registering key itself*, over a payload that **includes that key**:
  `dhash(REGISTER_OP_SIG, stake ‖ vrf_pk ‖ bls_pk ‖ payout…)`
  ([`verify_register_sig`](../mfn-consensus/src/bond_wire.rs)). Producing this
  signature requires knowing the secret key — a functional proof of
  possession. A rogue key of the form `pk_target − pk_honest` has no known
  secret key, so it cannot be registered.

**The gap: genesis validators never register.** `apply_genesis` installs
`cfg.validators` directly with no PoP check. This is safe **only** under the
"genesis is trusted setup" assumption (§ 1). For any genesis whose validator
list is assembled from third-party submissions — e.g. a public-testnet
ceremony — an unverified submission could smuggle a rogue key in.

**Recommendations (Path B ceremonies):**

- Set `require_validator_bls_pop: 1` in the genesis JSON and include a valid
  `bls_register_sig_hex` per validator row (verified by
  [`genesis_config_from_json_bytes`](../mfn-runtime/src/genesis_spec.rs)).
- `apply_genesis` itself still does not carry an on-chain PoP field; spec-load
  validation is the enforcement point before any node applies the genesis.

**Residual gap:** programmatic `GenesisConfig` construction in tests bypasses
the JSON gate — safe only under trusted-setup assumptions.

---

## 5. VRF: near-RFC-9381, not RFC 9381

The leader-election VRF ([`mfn-crypto/src/vrf.rs`](../mfn-crypto/src/vrf.rs))
follows the ECVRF-EDWARDS25519-SHA512 construction of RFC 9381 **with one
deliberate deviation**: hash-to-curve uses the protocol's try-and-increment
`hash_to_point` (cofactor cleared by multiply-by-8) instead of the
RFC-mandated Elligator2 map.

- **Security:** equivalent in the random-oracle model; the output distribution
  differs slightly but the unpredictability/uniqueness arguments carry over.
- **Interop:** an off-the-shelf RFC 9381 verifier will **reject** Permawrite
  VRF proofs. Any external tooling (block explorers, alternative clients,
  auditors' scripts) must implement the MFBN-1 `hash_to_point`, or the chain
  must migrate to strict Elligator2 (a hard fork) before claiming RFC
  conformance.

  Docs elsewhere in this repo describe the VRF as "RFC 9381"; read that as
  **MFBN-1 near-RFC** — full spec in [`interop/VRF_MFBN1.md`](./interop/VRF_MFBN1.md).
  The wire format (80-byte proof: `Γ ‖ c₁₆ ‖ s₃₂`) is protocol-owned and
  pinned by unit tests in `mfn-crypto`.

---

## 6. Determinism surface: consensus sortition parameter

The workspace invariant is "integer math only in consensus paths"
([`CONTRIBUTING.md`](../CONTRIBUTING.md), ARCHITECTURE design pillar 1).

[`eligibility_threshold`](../mfn-consensus/src/consensus/engine.rs) converts
`expected_proposers_per_slot` to Q30 via
[`proposers_factor_q30_from_f64_bits`](../mfn-consensus/src/consensus/engine.rs)
— **integer IEEE-754 decode, no `f64` multiply/round on the verification
path**. `expected_proposers_per_slot` remains an `f64` in `ConsensusParams`
checkpoint encoding; header verification only calls `to_bits()` then integer
math.

- **Default chains:** `F = 1.5` ⇒ factor `1_610_612_736` (unchanged behavior).
- **Future hard-fork option:** store Q30 directly in `ConsensusParams` wire
  encoding to drop `f64` from checkpoints entirely (not required for
  determinism today).

---

## 7. Privacy caveats (protocol-level summary)

Full treatment: [`PRIVACY.md`](./PRIVACY.md). The residual risks in one place:

1. **Decoy selection is statistical, not cryptographic.** Gamma-age sampling
   inherits Monero's known limitation: it protects you only insofar as your
   spending behavior matches the calibration. Tier 3 (OoM over the whole UTXO
   accumulator) removes this class entirely.
2. **Transaction-graph topology, fees, and timing are public.** Input/output
   counts, fee values, and broadcast timing are visible; fee values in
   particular can fingerprint wallet implementations. Uniform/standardized fee
   policy is a wallet-layer concern.
3. **Storage metadata is public.** `size_bytes`, `chunk_size`, `num_chunks`,
   and `replication` of every upload are cleartext. A globally unique file
   size is a correlation handle even though the payer/endowment amount is
   hidden. Padding to size buckets is a wallet-layer mitigation.
4. **Uploaded bytes are public.** Permanence applies to whatever you upload;
   encrypt-before-upload is the only confidentiality mechanism for content.
5. **Key separation is a wallet obligation.** Authorship-claim keys
   ([`AUTHORSHIP.md`](./AUTHORSHIP.md)) are intentionally public identities and
   must never be derived from, or correlated with, stealth view/spend keys.
6. **Ring size is consensus-enforced (uniform ring-16).** Production genesis
   requires `min_ring_size >= 16` and `uniform_ring_size >= 16`
   ([`validate_constitution`](../mfn-consensus/src/constitution.rs));
   [`verify_transaction`](../mfn-consensus/src/transaction/verify.rs) rejects
   undersized or non-uniform rings. Residual Tier-3 work (OoM over full UTXO
   set) remains in [`PRIVACY.md`](./PRIVACY.md). See
   [`PROBLEMS.md § 18`](./PROBLEMS.md#18-no-consensus-enforced-minimum-or-uniform-ring-size-resolved).

**Mitigation now in place — key-image subgroup validity.** ed25519's cofactor
means a decompressed point can carry a low-order (torsion) component.
[`verify_transaction`](../mfn-consensus/src/transaction/verify.rs) rejects any
CLSAG key image that is the identity point or is not a prime-order-subgroup
member (`!is_torsion_free()`), before it can enter the double-spend set. Honest
images `I = x·H_p(P)` are torsion-free by construction (`H_p` clears the
cofactor), so no honest spend is affected; this closes the classic
key-image-malleability / small-subgroup double-spend footgun (Monero parity).

---

## 8. Permanence caveats (protocol-level summary)

Full treatment: [`STORAGE.md`](./STORAGE.md), [`PROBLEMS.md`](./PROBLEMS.md).

1. **Operators post no bond.** Dropping data costs an operator only future
   revenue on that data; there is no slashing. Permanence rests on the
   continued profitability of holding data (see PROBLEMS § 1).
2. **The SPoRA race favors low latency.** First-valid-proof-wins is a
   centralization pressure toward well-peered operators (PROBLEMS § 6).
3. **Challenge indices have negligible-but-nonzero modulo bias.**
   [`chunk_index_for_challenge`](../mfn-storage/src/spora.rs) reduces the first
   8 digest bytes modulo `num_chunks` without rejection sampling. For any
   realistic `num_chunks` (≪ 2⁶⁴) the bias is ≈ `num_chunks / 2⁶⁴` —
   irrelevant in practice, stated here so nobody assumes perfect uniformity.
4. **Proof-of-access ≠ proof-of-replication.** A valid SPoRA proof shows *an*
   operator can produce the chunk; it does not prove `replication` distinct
   copies exist on independent failure domains. `replication` is enforced
   economically at upload pricing, not cryptographically per proof.
5. **Legacy (validator-less) mode burns the producer fee share.** When
   `state.validators` is empty there is no coinbase: the treasury share of
   fees is credited, but the producer share (default 10%) is dropped and no
   subsidy is minted ([`apply_block` Phase 8](../mfn-consensus/src/block/apply.rs)).
   Acceptable for the dev/test mode this configuration is documented for;
   listed so nobody repurposes the mode expecting producer revenue.
6. **Storage rewards accrue to the block producer, not the proving operator.**
   `StorageProof` has no operator payout field; per-proof rewards are folded
   into the producer's coinbase (`apply_block` settlement). A non-producing
   storage operator earns nothing on-chain for proving data, and a producer can
   bank a relayed proof. This undercuts the permanence incentive and storage
   decentralization until an operator-direct payout path ships. Full analysis
   in [`PROBLEMS.md § 17`](./PROBLEMS.md#17-storage-rewards-are-paid-to-the-block-producer-not-to-the-operator-that-proved-the-data).

---

## 9. Summary risk table

| # | Area | Risk | Current mitigation | Residual status |
|---|---|---|---|---|
| 1 | Finality semantics | Quorum ≠ state validity; no fraud proofs | Full nodes re-execute `apply_block`; honest-quorum assumption | Open (light clients); Tier-4 SNARKs would close |
| 2 | Header binding | `utxo_root` outside signing hash | Full-node recompute + next-block `prev_hash` binding | Open design question (hard fork) |
| 3 | BLS rogue keys | Same-message aggregation | PoP via `Register` signature over `bls_pk` | Closed for registered validators; **open at genesis** (trusted setup) |
| 4 | Determinism | `f64` in eligibility threshold | Default `F = 1.5` exactly representable | Latent; integer fixed-point recommended |
| 5 | VRF interop | Non-Elligator2 hash-to-curve | Protocol-owned golden vectors | Documented deviation; RFC conformance needs fork |
| 6 | Privacy | Decoy statistics, fee/timing/graph metadata, storage-size fingerprints | Gamma calibration; wallet-layer policy | Tier 3 removes decoy class; metadata remains |
| 7 | Permanence | No operator bonds; latency race; access ≠ replication | Endowment pricing, replication floor at upload | Open (see PROBLEMS §§ 1, 5, 6) |
| 8 | Genesis | Entire initial state is unauthenticated | Social/operational verification of genesis artifacts | Inherent; document + tooling checks |
| 9 | Storage incentive | SPoRA reward paid to producer, not proving operator | None yet (operator must also produce) | **Closed:** operator-direct coinbase outputs + `StorageProof` payout keys (PROBLEMS § 17) |
| 10 | Privacy enforcement | No consensus min/uniform ring size; under-mixing possible | Wallet-default ring size only | **Closed:** consensus enforces `min_ring_size = uniform_ring_size = 16` (PROBLEMS § 18) |
| 11 | Key-image malleability | Torsion/small-order key images | **Closed:** `verify_transaction` rejects non-prime-order & identity images | Closed (Monero parity) |

---

## See also

- [`PROBLEMS.md`](./PROBLEMS.md) — economic and architectural weaknesses
- [`PUBLIC_DEVNET_THREAT_MODEL.md`](./PUBLIC_DEVNET_THREAT_MODEL.md) — deployment/operational threat model
- [`PRIVACY.md`](./PRIVACY.md) / [`STORAGE.md`](./STORAGE.md) / [`CONSENSUS.md`](./CONSENSUS.md) — subsystem deep dives
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system-wide specification
- [`../SECURITY.md`](../SECURITY.md) — vulnerability disclosure process

**Maintenance rule:** whenever a consensus encoding, signing transcript, or
verification rule changes, re-audit §§ 2–6 of this document in the same PR.

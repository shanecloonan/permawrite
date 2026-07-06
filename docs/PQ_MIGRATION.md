# Post-Quantum Migration Plan (F5-PM9)

Permawrite's permanence horizon exceeds any sane confidence interval for
elliptic-curve cryptography. This document is the **committed migration
path**: which cryptographic surfaces are at risk, in what order they are
migrated, and — most importantly — why every step is a **soft fork today**
because the wire formats already carry the version bytes and length fields
the migration needs. The plan is normative for reference clients; a chain
that migrates in a different order may be fine, but a chain that *cannot*
migrate is not Permawrite (see the constitutional framing in
[`F5.md` §PM13](./F5.md)).

Companion frontier item: [`F5.md` §P12](./F5.md) (hybrid ML-KEM stealth
derivation) is the *privacy* half of this plan; this file is the
*integrity* half plus the shared wire-format headroom audit.

---

## 1. Threat model: two different clocks

| Attack | Clock starts | What breaks |
|---|---|---|
| **Harvest-now-decrypt-later** | The moment a tx is archived (today) | *Privacy*: stealth-address ECDH linkage, view-key confidentiality. Retroactive — a discrete-log break in 2060 deanonymizes 2026 outputs. |
| **Forge-later** | The moment a quantum adversary exists | *Integrity*: signature forgery (CLSAG, VRF, BLS finality), key-image forgery (double-spends), bond/validator impersonation. Not retroactive — old blocks stay valid; only *new* forgeries become possible. |

Consequences for ordering:

1. **Privacy surfaces migrate first** (P12): the damage is already
   accruing in every archived block. This is unusual — most chains plan
   signatures first — but a permanence chain guarantees the ciphertexts
   will still be public when the adversary arrives.
2. **Integrity surfaces migrate on a deadline we control**: they need to
   be done *before* a cryptographically-relevant quantum computer, not
   before one is announced. Validator/finality keys rotate operationally,
   so they go first; user spend keys are the long tail.
3. **Amounts never need migration.** Pedersen commitments are
   information-theoretically **hiding**: even an unbounded adversary
   learns nothing about committed amounts. (Binding is computational — a
   quantum adversary could *open* a commitment two ways — which is an
   integrity concern handled by the balance-proof migration, not a
   privacy leak.)

## 2. Surface inventory

| Surface | Primitive | Where | Quantum risk | Phase |
|---|---|---|---|---|
| Stealth addresses | X25519-style ECDH over edwards25519 | `mfn-crypto/src/stealth.rs` | **Privacy, retroactive** | **A** |
| Encrypted amounts | SHA-512 pad keyed by ECDH secret | `mfn-crypto/src/encrypted_amount.rs` | Privacy, retroactive (falls with stealth ECDH) | **A** |
| Ring signatures | CLSAG over edwards25519 | `mfn-crypto/src/clsag.rs` | Integrity (forgery, key-image forgery) | **C** |
| Range proofs | Bulletproofs | `mfn-crypto/src/bulletproof.rs` | Integrity (false range statements) | **C** |
| Producer eligibility | EC-VRF over edwards25519 | `mfn-crypto/src/vrf.rs` | Integrity (grinding/impersonation) | **B** |
| Finality | BLS12-381 aggregate signatures | `mfn-bls` | Integrity (forged finality) | **B** |
| Authorship claims | ed25519 | `mfn-crypto/src/authorship.rs` | Integrity (claim forgery) | **B/C** |
| Hashes / Merkle / SPoRA | SHA-512-based `dhash` (256-bit output) | `mfn-crypto/src/hash.rs` | Grover only: 2^128 effective preimage — **no action** | — |
| Endowment commitments | Pedersen (hiding) | `mfn-crypto/src/pedersen.rs` | Hiding survives; binding covered by Phase C | — |

## 3. Migration phases

Every phase is gated the same way: a **consensus version bump** on the
relevant wire object, accepted alongside the old version for a deprecation
window, then the old version is refused for *new* objects while remaining
valid for historical verification. Historical blocks are never
re-validated under new rules (the chain's memory is immutable; the rules
that admitted a block are pinned by its height).

### Phase A — retroactive-privacy hybrid (highest urgency)

Hybrid the stealth shared-secret derivation with an ML-KEM-768
encapsulation: `s_shared = dhash(ECDH || ML-KEM shared secret)`, ciphertext
carried per-output. Unlinkability then holds if **either** assumption
survives. New output version; old outputs remain scannable forever.
This is F5-P12 and is spec'd there; it ships first because every day of
delay adds permanently-archived ECDH transcripts.

### Phase B — operator-key hybrid signatures

Validator and finality keys are few, rotate operationally, and their
compromise breaks consensus rather than one wallet:

1. **Finality**: hybrid BLS + ML-DSA-65 — a finality proof carries both,
   verifiers require both. The `finality_proof` field is already an
   opaque length-prefixed blob (`BlockHeader.finality_proof`, MFBN-encoded),
   so the container needs no layout change — only a new proof version
   inside the blob and a validator-record extension.
2. **Producer VRF**: EC-VRF stays for eligibility randomness (its output
   is consumed within one slot; retroactive breaks are worthless) but the
   *proposal signature* moves to hybrid with the finality keys.
3. **Validator records**: `encode_validator` (fixed 48-byte `bls_pk`)
   lives inside the *versioned* checkpoint codec (versions 1–3 accepted
   today) — a version 4 record adds the PQ public key.

### Phase C — user-facing spend migration (research-gated)

A PQ successor for CLSAG + Bulletproofs does not exist at production
grade today (lattice ring signatures and PQ range proofs are 10–100×
larger). The committed posture:

1. Track the research line (Monero FCMP++/post-quantum successors,
   lattice-based linkable ring signatures).
2. When a candidate matures: new `TX_VERSION` with PQ input/output
   sections; a **migration window** in which users move funds from v1
   (EC) outputs to v2 (PQ) outputs with both accepted; then v1 *spends*
   are refused past a flag height (outputs remain counted; unmigrated
   funds are frozen, not confiscated — endowment and storage state are
   untouched per the PM13 constitution).
3. Storage uploads and SPoRA proofs migrate with the tx version they
   ride in; `data_root` Merkle machinery is hash-based and needs nothing.

## 4. Wire-format headroom audit (why this is a soft fork)

The point of committing this plan *now* is that the codecs already leave
room — future decoders can branch on version, and current decoders reject
unknown versions cleanly instead of misparsing:

| Object | Version field | Variable-length crypto payloads |
|---|---|---|
| `TransactionWire` | `varint(version)` first field (`TX_VERSION = 1`); decoder rejects mismatches (`verify_transaction` checks `tx.version != TX_VERSION`) | CLSAG sig: `blob(encode_clsag(sig))`; Bulletproof: `blob(...)`; `extra`: `blob` — all length-prefixed, so bigger PQ objects need no framing change |
| `BlockHeader` | `varint(version)` first field (`HEADER_VERSION = 1`) | `producer_proof`: length-prefixed blob; `finality_proof`: opaque MFBN blob |
| Chain checkpoint | Explicit version byte, **multiple versions already accepted** (1–3) | Validator records re-encodable under a new checkpoint version |
| P2P frames | Per-message-type versioning (`HelloV1`, `ChunkV1`, …) | New message types are additive |
| Storage commitment | Hash-domain-separated (`dhash(STORAGE_COMMIT, …)`) | Hash-based; PQ-indifferent |

Codec discipline that must be preserved (conformance suite,
[`mfn-wallet/tests/canonical_conformance.rs`](../mfn-wallet/tests/canonical_conformance.rs),
pins the current version byte): **every new cryptographic object enters
the wire as a length-prefixed blob behind a version field**. Reviewers
should reject any patch that adds a fixed-width crypto field to an
unversioned position.

## 5. Explicit non-goals

- **No hash migration.** 256-bit SHA-512-based `dhash` retains 128-bit
  quantum preimage resistance (Grover); Merkle/SPoRA/commitment hashing
  is out of scope indefinitely.
- **No "PQ someday" flag day for amounts.** Pedersen hiding is
  information-theoretic; there is nothing to migrate.
- **No speculative primitive picks for Phase C.** Naming a lattice ring
  signature today would be archaeology by the time it ships; the
  commitment is the version-gated *path*, not the primitive.

## See also

- [`F5.md`](./F5.md) — PM9 (this plan), P12 (stealth hybrid), PM13 (constitution)
- [`PRIVACY.md`](./PRIVACY.md) — current privacy mechanisms
- [`SUPPLY_CURVE.md`](./SUPPLY_CURVE.md) — deep-time horizons that motivate all of this
- [`PROBLEMS.md`](./PROBLEMS.md) — weakness catalogue

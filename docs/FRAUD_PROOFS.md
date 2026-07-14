# Interactive fraud proofs (F5 phase 0)

Light clients today treat a BLS finality quorum as soft confidence: validators
sign **header bytes**, not an `apply_block` digest
([`PROBLEMS.md` §11](./PROBLEMS.md), [`SECURITY_CONSIDERATIONS.md` §2](./SECURITY_CONSIDERATIONS.md#2-what-a-finalized-header-does--and-does-not--prove)).

**Phase 0** ships the first **interactive fraud proof** class that a light
client can verify **without the UTXO set**: body-root mismatch.

---

## What phase 0 proves

Given a finalized (or gossiped) header and a candidate block body, a challenger
attaches the full block and names one Merkle root. Verification recomputes that
root from the body and checks disagreement:

| Kind | Header field | Body source |
|---|---|---|
| `TxRoot` | `tx_root` | `tx_merkle_root(txs)` |
| `BondRoot` | `bond_root` | `bond_section_merkle_root(bond_ops, storage_operator_ops)` |
| `SlashingRoot` | `slashing_root` | `slashing_merkle_root(slashings)` |
| `StorageProofRoot` | `storage_proof_root` | `storage_proof_merkle_root(storage_proofs)` |

If the header root ≠ recomputed root → **valid fraud** → light clients MUST
reject the header (or treat finality as soft until contested).

If roots match → **not fraud** (challenge rejected). This does **not** mean the
block is valid under `apply_block`.

---

## Soft finality UX

Until on-chain producer slash lands, wallets should treat:

- **0 confirmations:** tip only (weak)
- **&lt; [`FRAUD_PROOF_SOFT_FINALITY_SLOTS`](../mfn-consensus/src/fraud_proof.rs) (32):** soft finality — prefer waiting
- **≥ 32 slots uncontested:** practical hard finality for phase 0 body-root class

Permanent-money UX (Arweave-grade horizon) still wants Tier-4 validity proofs
later; phase 0 is the honest interim for public testnet light clients.

---

## Wire

Consensus codec (`mfn_consensus::fraud_proof`):

```text
u32le version (=1) || u8 kind || encode_block(block)
```

P2P tag reserved: `0x13` (`mfn_net::FRAUD_PROOF_V1_TAG`). Phase 1 gossips verified
proofs on the mesh via `send_fraud_proof_v1` / `recv_gossip_v1` / `fanout_fraud_proof`.
Slash of the producer remains deferred.

### Phase 2 wire (coinbase amount)

```text
u32le version (=2)
u128le fee_sum
u16le settlement_count
  repeat: u32le proof_wire_len || proof_wire || u128le bonus
view_pub || spend_pub   (producer payout witness)
encode_block(block)
```

Verifier supplies chain [`EmissionParams`](../mfn-consensus/src/emission.rs); challenger must attach
`fee_sum` and per-proof settlement bonuses that match the body.

### Phase 3 wire (invalid CLSAG / SPoRA)

```text
u32le version (=3)
u8 kind (=1 invalid CLSAG, =2 invalid SPoRA, =3 ring UTXO)
u16le index   (tx index or storage_proof index)
if kind=2:
  u32le commit_wire_len || encode_storage_commitment(witness)
if kind=3:
  u16le input_index || u16le ring_index || parent_utxo_witness
encode_block(block)
```

- **CLSAG (`kind=1`)** — stateless: runs [`verify_transaction`](../mfn-consensus/src/transaction/verify.rs)
  with [`RingPolicy::PRODUCTION`](../mfn-consensus/src/block/state.rs). Valid fraud when the tx
  fails ingress checks (bad CLSAG, balance, range proof, ring floors).
- **SPoRA (`kind=2`)** — challenger attaches the parent-state [`StorageCommitment`](../mfn-consensus/src/storage.rs)
  witness; verifier runs [`verify_storage_proof`](../mfn-storage/src/spora.rs) against
  `prev_hash` + `slot` from the block header.

Ring-membership fraud (fabricated ring mint) uses wire v3 `kind=3`:

```text
u16le input_index
u16le ring_index
u8 parent_witness_tag (=0 absent, =1 present)
if tag=1: [u8;32] parent_commit || u32le parent_height
encode_block(block)
```

- **Absent (`tag=0`)** — challenger attests ring `P` was not in the parent UTXO map (`RingMemberNotInUtxoSet`).
- **Present (`tag=1`)** — challenger supplies the on-chain commit for `P`; fraud when ring `C` ≠ parent commit (`RingMemberCommitMismatch`).

Producer slash hooks: `fraud_proof_producer_slash_hint` + `mfnd_fraud_proof_producer_slash_hint`
log on valid gossip. Full nodes also record contests in memory; light clients query
`list_fraud_contests` RPC. On-chain producer slash for invalid blocks remains deferred
(equivocation evidence only today).

### Phase 1b RPC

```json
{"jsonrpc":"2.0","method":"list_fraud_contests","id":1}
```

Returns `{ configured, contest_count, contests: [{ block_id, height, producer_index, label }] }`
when P2P is enabled on the node. Integration: `mfnd_smoke.rs` exercises configured vs
unconfigured paths over TCP.

---

## API

```rust
use mfn_consensus::{
    encode_body_root_fraud_proof, tx_root_fraud_proof, verify_body_root_fraud_proof,
};

let proof = tx_root_fraud_proof(tampered_block);
verify_body_root_fraud_proof(&proof)?; // ValidFraud
let wire = encode_body_root_fraud_proof(&proof);
```

---

## Roadmap

| Phase | Scope |
|---|---|
| **0 (shipped)** | Body-root kinds + consensus verify + P2P tag reserve |
| **1 (shipped)** | `mfnd` gossip recv + verify + fan-out (`fanout_fraud_proof`); producer slash deferred |
| **2 (shipped)** | Coinbase amount fraud (`verify_coinbase_amount_fraud_proof`); wire version 2 |
| **3 (shipped)** | Invalid CLSAG + invalid SPoRA (`verify_tx_fraud_proof`); wire version 3 |
| **3b (shipped)** | Ring-membership UTXO witness + producer slash ops hints |
| **1b (shipped)** | In-memory fraud contest registry + RPC `list_fraud_contests` |
| **1c (shipped)** | On-chain `InvalidBlockSlashEvidence` — producer stake zero on valid interactive fraud (`HEADER_VERSION_FRAUD_SLASH` = 3) |
| **4** | SNARK / STARK validity proofs (Tier-4 / P11) |

See [`F5.md` §F5](./F5.md).

---

## Phase 1c — on-chain producer slash (shipped)

**Status:** shipped behind `HEADER_VERSION_FRAUD_SLASH` (3). Public devnet v1 stays on header v1 until TL-7 ceremony.

### Problem

Today [`SlashEvidence`](../../mfn-consensus/src/slashing.rs) is **equivocation-only** (two conflicting BLS signatures at the same slot). A producer who includes an invalid body (wrong coinbase, bad CLSAG, etc.) is only logged via [`fraud_proof_producer_slash_hint`](../../mfn-consensus/src/fraud_proof.rs) — no on-chain penalty.

### Goal

Anyone who holds a gossip-verified interactive fraud proof can include **invalid-block slash evidence** in a later block. `apply_block` verifies the fraud wire, attributes fault to the producer named in `producer_proof`, and zeroes that validator's stake (same outcome as equivocation slash).

### Evidence shape (proposed)

Tagged union in `mfn-consensus/src/slashing.rs` (replaces flat `SlashEvidence` struct):

| Variant | When | Payload |
| --- | --- | --- |
| `Equivocation` | Two conflicting header sigs at same slot | Current fields (`height`, `slot`, `voter_index`, `header_hash_a/b`, `sig_a/b`) |
| `InvalidBlock` | Valid interactive fraud against a finalized header | `height`, `block_id`, `producer_index`, `fraud_proof_wire` |

Wire encoding: leading `u8` kind tag (`0` = equivocation, `1` = invalid-block) then variant body. Canonical sort order for Merkle leaves uses `(kind, height, block_id, producer_index)` for invalid-block and existing lexicographic rule for equivocation.

`InvalidBlock` verification (`verify_invalid_block_evidence`):

1. `verify_interactive_fraud_proof(&fraud_proof_wire)` → `ValidFraud`.
2. `fraud_proof_contested_block(&fraud_proof_wire)` → `(height, block_id, producer_index)` matches evidence fields.
3. `producer_index` is `Some` and matches `decode_producer_proof` on the attached block header.
4. `validators[producer_index].stake > 0` at slash application height.
5. Contested `height` is **strictly below** the block that includes the evidence (cannot slash in the same block as the fraud).

### `apply_block` integration

- Extend [`apply_equivocation_slashings`](../../mfn-consensus/src/validator_evolution/equivocation.rs) (or rename to `apply_slashings`) to branch on evidence kind.
- Invalid-block path calls the same stake-zero primitive as equivocation; bond/treasury routing unchanged.
- `slashing_merkle_root` hashes tagged leaves via `SLASHING_LEAF` domain separation per variant.

### Consensus fork gate

Requires **`header_version` bump** (checkpoint v12+) because `slashings` wire shape changes. Public devnet genesis stays on current version until TL-7 ceremony; phase 1c ships behind the version gate with ignored integration tests on synthetic chains.

### P2P / mempool

- Gossip tag `0x13` unchanged; evidence construction is local once fraud is verified.
- Mempool accepts slash txs only when evidence verifies against current validator set snapshot.
- Dedup: same `(block_id, fraud_proof_wire_hash)` cannot slash twice.

### Tests (acceptance)

| Test | Crate | Assert |
| --- | --- | --- |
| `invalid_block_slash_evidence_roundtrip` | `mfn-consensus` | encode/decode + Merkle root stable |
| `apply_block_zeros_producer_on_coinbase_fraud` | `mfn-consensus` | synthetic chain; producer stake → 0 (**shipped** `69c0531`) |
| `invalid_block_slash_rejects_same_height` | `mfn-consensus` | evidence in block H cannot target block H (**shipped** `69c0531`) |
| `mfnd_gossip_fraud_to_slash_hint` | `mfn-node` | ops log still emitted; registry + future slash builder |

### Non-goals (phase 1c)

- SNARK/STARK validity proofs (phase **4**).
- Operator storage fraud slash (separate B5 audit path).
- Automatic slash inclusion in block builder (proposer may omit; anyone can include in next block).

### Launch-status linkage

`launch-status.v7` exposes `fraud_proof.on_chain_producer_slash: "shipped"` with `phase_shipped: "1c"` (since `83fdca7`).

---

## Phase 4 — SNARK / STARK validity proofs (research)

**Status:** research (lane 4). Interactive fraud (phases 0–1c) closes the public-testnet light-client gap; phase 4 is the **Tier-4** path to constant-size block validity and compressed fraud witnesses ([`P18`](./F5.md), [`ROADMAP.md` § Tier 3 → Tier 4](./ROADMAP.md)).

### Problem interactive fraud leaves open

Phases 0–3b ship **witness-heavy** challenges: a fraud proof carries the full contested `block` (or large tx/storage witnesses). Light clients can verify without the UTXO set, but:

| Limitation | Impact |
| --- | --- |
| Proof size ∝ block body | Bandwidth cost scales with txs, storage proofs, slash evidence |
| Per-class verifiers | CLSAG, SPoRA, coinbase, body-root each need separate logic |
| Soft finality window | Honest quorum + 32-slot uncontested rule; no succinct “valid state transition” attestation |
| Root-consistent invalid bodies | Malicious producer can craft bodies whose Merkle roots match while `apply_block` would still reject (mitigated only when a challenger posts the right fraud class) |

Phase **1c** adds economic penalty (producer stake zero) once someone includes slash evidence — but constructing that evidence still requires the full interactive wire.

### Goal

One **succinct validity proof** per block (or per epoch) that attests:

```text
apply_block(parent_state, block) succeeds  OR  block_id is rejected with a deterministic error code
```

Light clients verify the SNARK/STARK in constant time (~milliseconds) instead of re-running interactive fraud classes or trusting quorum alone. Fraud proofs compress to “here is a block + validity proof that disagrees with the header quorum” — or disappear entirely when validity proofs ship in-headers.

### Proof statement (candidate)

Partition into sub-circuits aligned with existing `apply_block` gates (reuse test vectors from `mfn-consensus` integration + proptest suites):

| Sub-circuit | Witness | Public inputs |
| --- | --- | --- |
| Header binding | `header_signing_bytes`, BLS sig aggregate (optional cross-check) | `block_id`, `prev_hash`, roots |
| Tx ingress | CLSAG + range + balance per tx | `tx_root`, ring policy params |
| Coinbase | emission + fee_sum + settlements | `coinbase` fields, `EmissionParams` digest |
| Storage proofs | SPoRA verify per proof | `storage_proof_root`, operator registry snapshot |
| Bond / slash / operator ops | Schnorr + Merkle paths | respective section roots |
| State transition digest | full `apply_block` on witness state | `utxo_root`, `treasury`, `validator_root` (post-state) |

**Phase 4a (minimal):** prove “all txs + coinbase + storage proofs in this block are individually valid under parent state digest” without proving full UTXO accumulator update (lighter fork gate).

**Phase 4b (full):** recursive aggregation over 4a sub-proofs + UTXO/bond/validator delta = complete `apply_block` digest. Matches [`P18`](./F5.md) / Tier 4 in [`PRIVACY.md`](./PRIVACY.md).

### Backend candidates

| Backend | Pros | Cons | Permawrite fit |
| --- | --- | --- | --- |
| **STARK (Winterfell / Plonky2 STARK)** | Transparent setup; post-quantum friendly narrative | Larger proofs; prover RAM | Aligns with “no trusted setup” docs; good for public testnet story |
| **Halo2 / Nova recursion** | Small proofs; Rust ecosystem | Curve setup assumptions | Natural if we stay on Pasta/BLS12-381 family for recursion |
| **Groth16 per sub-circuit** | Mature CLSAG-adjacent tooling (limited) | Trusted setup per circuit; awkward recursion | Poor fit for open ceremony |

**Recommendation (2026-07):** prototype **4a** with a STARK backend for tx+coinbase+SPoRA batch verify (deterministic, no trusted setup); keep Halo2/Nova as fallback if proof size on block-heavy workloads exceeds gossip budget. SPoRA stays Merkle-native — SNARK wraps existing `verify_storage_proof`, does not replace operator challenges ([`STORAGE.md` § Why we don't use ZK SNARKs](./STORAGE.md#why-we-dont-use-zk-snarks-here-yet)).

### Wire / fork gate

| Artifact | Proposal |
| --- | --- |
| Header field | `validity_proof` blob (optional until phase 4 ships) |
| `header_version` | Bump to **4** (after 1c's version 3 slash wire) |
| Checkpoint | v13+ carries validity-proof params (circuit digest, max proof bytes) |
| Gossip | New tag `0x14` reserved for standalone validity proofs (full nodes); headers carry succinct proof at finalize |
| Mempool | Reject blocks with invalid validity proof when `require_validity_proof: 1` |

Public devnet stays on header v1 until TL-7; phase 4 ships behind version gate like phase 1c.

### Relationship to phase 1c slash

Invalid-block slash evidence can shrink to:

```text
(height, block_id, producer_index, validity_proof_ref)
```

where `validity_proof_ref` is a hash of a succinct proof that `apply_block` rejects the contested block — instead of embedding the full interactive fraud wire. Slashing verification calls the same validity verifier used for block acceptance.

### Acceptance tests (phase 4a)

| Test | Crate | Assert |
| --- | --- | --- |
| `validity_proof_roundtrip` | `mfn-consensus` | encode/decode; max size bound |
| `validity_proof_rejects_tampered_block` | `mfn-consensus` | flip one tx byte → verify fails |
| `validity_proof_accepts_empty_block` | `mfn-consensus` | genesis→height-1 empty chain |
| `mfnd_validity_proof_gossip` | `mfn-node` | tag `0x14` recv + verify + ops log |
| `ignored_apply_block_validity_equivalence` | `mfn-consensus` | SNARK verdict matches `apply_block` on proptest seeds |

### Non-goals (phase 4)

- Replacing SPoRA Merkle challenges with ZK storage proofs (see [`STORAGE_ACCESSIBILITY.md` § Phase D](./STORAGE_ACCESSIBILITY.md)).
- P11 curve-tree / OoM membership (separate Tier-3 fork).
- Wallet-side proof generation at phase 4a (block producer or dedicated prover service only).

### Dependencies

- **P18** — recursive SNARK block validity (F5 phase 4 implements the F5-facing slice).
- **F7** — canonical input-count shapes reduce circuit variability.
- **F10** — purge `f64` from consensus before embedding economics in circuits.
- **TL-7** — genesis ceremony pins `header_version` + validity-proof params together.

### Launch-status linkage (future)

Extend `launch-status.v8` with `fraud_proof.validity_proof: "deferred" | "research" | "shipped"` and `validity_proof_phase: "4a" | "4b"`.

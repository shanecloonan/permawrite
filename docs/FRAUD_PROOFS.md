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
| **4** | SNARK / STARK validity proofs (Tier-4 / P11) |

See [`F5.md` §F5](./F5.md).

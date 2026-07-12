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

Until gossip + slash hooks land (phase 1), wallets should treat:

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

P2P tag reserved: `0x13` (`mfn_net::FRAUD_PROOF_V1_TAG`). Phase 0 does **not**
fan out on the mesh yet — encode/decode only.

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
| **0 (this)** | Body-root kinds + consensus verify + P2P tag reserve |
| **1** | `mfnd` gossip fan-out; optional slash of producer if fraud valid + evidence age window |
| **2** | Coinbase amount fraud (fee_sum + emission witness) |
| **3** | Invalid CLSAG / SPoRA with compact witnesses (state-heavy) |
| **4** | SNARK / STARK validity proofs (Tier-4 / P11) |

See [`F5.md` §F5](./F5.md).

# Storage Subsystem

> **Audience.** Protocol designers, storage-system engineers, and cryptographers. Sections open with **intuition** in plain language before the math.
> The non-formula version lives in [`OVERVIEW.md § How the permanence half works`](./OVERVIEW.md#how-the-permanence-half-works-no-formulas).

---

## What "permanence" means here

A file uploaded to Permawrite has these guarantees:

1. **The file is anchored on-chain forever.** Its Merkle root is recorded in the block header, irreversible.
2. **Storage operators are economically incentivized to hold the bytes forever.** The user pays an upfront endowment whose yield covers the storage cost in perpetuity, given the protocol's `r > i` condition holds.
3. **Operators are randomly audited every block.** SPoRA challenges force them to prove they still have the data.
4. **Multiple independent operators must hold the data.** Protocol-enforced `replication` factor with minimum and maximum bounds.

The user does **not** get:

- **An SLA on retrieval time.** Retrieval is a separate concern handled by the (off-chain) gateway layer.
- **Hidden file contents by default.** Upload plaintext, get plaintext on-chain. Encrypt locally if you need confidentiality.
- **Ability to delete.** Permanence is an explicit commitment. There is no `unannounce_file()`.

### Anonymity vs optional authorship

**Uploads are anonymous-by-default at the RingCT layer:** which UTXO paid the endowment is hidden by CLSAG; `StorageCommitment` deliberately carries **no** author or stable publisher field so the permanence wire format stays minimal.

**Optional authorship** is a separate, voluntary layer: a user can attach one or more **Schnorr-signed claims** (claiming pubkey + short message + signature over a domain-separated digest of `data_root`) inside `TransactionWire.extra`, indexed by the chain for permaweb-style discovery. That pubkey is **not** the stealth spend/view key material; wallets should use a dedicated “publishing identity” keypair so leaking a claim key does not compromise financial privacy.

Full specification: [**docs/AUTHORSHIP.md**](./AUTHORSHIP.md).

---

## Threat model

We assume:

- Storage operators are economically rational. Some are honest; some try to cheat.
- A cheating operator's best strategy is to **claim they hold a file they actually deleted** (saves disk cost).
- An attacker might try to **upload garbage at low cost** (to spam the storage layer).
- An attacker might try to **falsely accuse honest operators** of failing audits.
- The chain has bounded compute per block (cannot run expensive ZK provers).

We do **not** defend against:

- A 51%+ adversarial validator set choosing to censor honest storage proofs. That's a consensus-layer concern.
- The user uploading garbage (it's their MFN; we just enforce the math).
- The user encrypting data such that no human will ever read it again. Permanence is bytes, not meaning.

---

## 1. Chunking + content addressing

**Intuition.** A file is sliced into fixed-size pages (256 KiB each). Each page gets a hash. Those hashes are arranged in a binary tree; the root of that tree *is* the file's identity on the chain. Any single page can be later proven authentic with a small Merkle proof.

### Mechanism

[`mfn_storage::spora::chunk_data`](../mfn-storage/src/spora.rs):

```rust
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;  // 256 KiB

pub fn chunk_data(data: &[u8]) -> Result<Vec<&[u8]>, SporaError> {
    if data.is_empty() {
        return Ok(vec![data]);   // canonical empty case = 1 chunk of 0 bytes
    }
    Ok(data.chunks(DEFAULT_CHUNK_SIZE).collect())
}
```

A file's `num_chunks = ceil(size_bytes / chunk_size)`. The final chunk may be shorter than 256 KiB; this is handled by the prover (publishes the actual bytes) and verifier (knows the expected size from `size_bytes`).

### Chunk hashes

```text
chunk_hash_i = dhash(CHUNK_HASH, [chunk_bytes_i])
```

[`mfn_storage::spora::chunk_hash`](../mfn-storage/src/spora.rs). Domain tag: `MFBN-1/chunk-hash`.

### The data root

`data_root` is the Merkle root over the per-chunk hashes:

```text
data_root = merkle_root_or_zero(
    leaves = { chunk_hash_0, chunk_hash_1, …, chunk_hash_{n-1} }
)
```

Using the binary Merkle tree from [`mfn_crypto::merkle`](../mfn-crypto/src/merkle.rs):

- Leaves are wrapped with `dhash(MERKLE_LEAF, leaf_bytes)` to prevent leaf-vs-node ambiguity attacks.
- Internal nodes are `dhash(MERKLE_NODE, [left, right])`.
- Odd-count levels duplicate the last node up the tree (Bitcoin-style).
- Empty leaf set → `[0u8; 32]` sentinel.

The data root is the **stable, content-addressed identity of the file**. Two identical byte sequences produce identical `data_root`s.

---

## 2. StorageCommitment

**Intuition.** When you upload a file, you're not really storing it *in* the chain — that would explode block size. You're publishing a small fixed-size header (the "commitment") that pins the file's identity, size, and required replication. Storage operators hold the actual bytes off-chain but the chain is what proves they're holding the right bytes.

### Wire format

[`mfn_storage::commitment`](../mfn-storage/src/commitment.rs):

```rust
pub struct StorageCommitment {
    pub data_root:   [u8; 32],     // file identity
    pub size_bytes:  u64,
    pub chunk_size:  u32,          // currently always 256 KiB
    pub num_chunks:  u32,
    pub replication: u8,
    pub endowment:   EdwardsPoint, // Pedersen commitment to the endowment amount
}
```

### Canonical hash

```text
storage_commitment_hash(c) = dhash(STORAGE_COMMIT, [
    c.data_root,
    c.size_bytes.to_be_bytes(),
    c.chunk_size.to_be_bytes(),
    c.num_chunks.to_be_bytes(),
    [c.replication],
    c.endowment.compress().to_bytes()
])
```

This hash is the commitment's chain-level identity. The chain's `storage` registry is keyed by it.

### Endowment is a Pedersen commitment

The `endowment` field is **not** a plaintext amount — it's a Pedersen commitment, just like a transaction output. This means:

- The chain knows the *expected* endowment (from `required_endowment(size_bytes, replication)`) and can reconstruct the expected commitment to verify.
- An external observer cannot tell how much the user paid (they could have over-paid; their privacy).
- The endowment is amount-private but consensus-verified.

### Replication factor

Hard bounds in [`EndowmentParams`](../mfn-storage/src/endowment.rs):

```rust
min_replication: 3   // hard floor: a 2-replica system has no quorum recoverability
max_replication: 32  // DoS protection: prevents pinning tiny data at absurd replication
```

`apply_block` rejects uploads outside `[min_replication, max_replication]`.

---

## 3. SPoRA — deterministic challenges

**Intuition.** Every block, the chain says: "Operator, for commitment X, show me chunk 1234 right now." The operator has to actually have the file to produce the proof. The challenge is determined by the previous block — so operators can prepare, but they can't predict far in advance, and they can't fake it.

### Deterministic challenge derivation

[`chunk_index_for_challenge`](../mfn-storage/src/spora.rs):

```text
seed = dhash(STORAGE_COMMIT, [prev_block_id, slot.to_be_bytes(), commit_hash])
chunk_index = challenge_index_from_seed(seed, num_chunks)
```

`challenge_index_from_seed` interprets the seed as a big-endian `u128` and reduces modulo `num_chunks` **using rejection sampling** to eliminate modulo bias:

```text
let max_uniform = (u128::MAX / num_chunks) * num_chunks;
loop {
    if seed_as_u128 < max_uniform {
        return (seed_as_u128 % num_chunks) as u32;
    }
    // re-hash and try again (extremely rare path)
}
```

### Properties

| Property | Why it matters |
|---|---|
| **Public computability** | Every node, including the operator, can derive the answer the moment a new block lands. No oracle, no off-chain coordination. |
| **Unpredictability for future blocks** | Operators cannot precompute future challenges because `prev_block_id` of block N+1 depends on block N being finalized. |
| **No bias toward any chunk** | Rejection sampling guarantees a uniform draw. |
| **Per-commitment specific** | Different commitments get independent challenges; an operator can't reuse one proof for another. |

### Wire-format StorageProof

```rust
pub struct StorageProof {
    pub commit_hash: [u8; 32],
    pub chunk:       Vec<u8>,        // 256 KiB (or partial-final) raw bytes
    pub proof:       Vec<[u8; 32]>,  // Merkle authentication path
}
```

Encoding ([`encode_storage_proof`](../mfn-storage/src/spora.rs)):

```text
[commit_hash (32 B)] [varint(chunk.len()) ‖ chunk_bytes] [varint(proof.len()) ‖ proof[0] … proof[k-1]]
```

### Verification

`verify_storage_proof(commit, prev_block_id, slot, proof)` returns a `StorageProofCheck` enum:

```rust
pub enum StorageProofCheck {
    Ok,
    UnknownCommit,
    WrongChunkIndex { expected: u32, got: u32 },
    BadMerkleProof,
    BadChunkSize,
}
```

The verifier:

1. Recomputes the expected challenge index `expected_idx = chunk_index_for_challenge(prev_id, slot, commit_hash, commit.num_chunks)`.
2. Verifies the supplied Merkle proof connects `dhash(CHUNK_HASH, proof.chunk)` to `commit.data_root` *at position `expected_idx`*.
3. If the proof says it's at a different index, returns `WrongChunkIndex`.

The "at position N" check is critical — without it, an honest-looking proof at the wrong position could trick the verifier. The Merkle tree's `verify_merkle_proof` in [`mfn_crypto::merkle`](../mfn-crypto/src/merkle.rs) takes the expected leaf index and validates the proof's directional bits accordingly.

### Why we don't use ZK SNARKs here (yet)

A ZK SNARK proof of "I have chunk N of file F" is asymptotically smaller than 256 KiB + log-many hashes. The reason we ship Merkle proofs instead:

- **Verifier cost.** A Merkle proof verifies in microseconds. A SNARK verifier is milliseconds to tens of milliseconds — at thousands of storage proofs per block, this becomes prohibitive.
- **Prover cost.** A SNARK prover is seconds to minutes for the data sizes we care about. Storage operators would need GPUs.
- **Simplicity.** Merkle proofs are mechanically reviewable. SNARK toolchains require dedicated audits.

We may move to a SNARK-based proof aggregation at Tier 4 (one proof per block covering all storage audits in that block), but the per-proof primitive will remain Merkle.

---

## 4. Endowment math

**Intuition.** "How much do you need to pay up front so that the interest covers the storage cost forever?" The answer is a small piece of finance math involving the storage cost, the inflation rate of storage cost, and the real yield you'll earn. The chain hard-codes this calculation. Underfund the endowment and your upload is rejected.

### The formula (derivation in [`ECONOMICS.md`](./ECONOMICS.md#1-the-permanence-equation-derived))

```text
E₀ = C₀ · (1 + i) / (r − i)
```

with:

- `E₀` = required upfront endowment, in MFN base units.
- `C₀ = cost_per_byte_year × size_bytes × replication` = first-year cost.
- `i` = annual storage-cost inflation rate.
- `r` = annual real yield rate.

The non-degeneracy condition `r > i` is the **single equation that makes infinite-horizon storage solvent**. It guarantees the geometric series converges. `validate_endowment_params` rejects any parameter set violating it.

### PPB precision

[`mfn_storage::endowment`](../mfn-storage/src/endowment.rs) uses **parts per billion** for all rate quantities:

```rust
pub const PPB: u128 = 1_000_000_000;

pub struct EndowmentParams {
    pub cost_per_byte_year_ppb: u64,   // default 200_000 = 2 × 10⁻⁴ base units / byte-year
    pub inflation_ppb:          u64,   // default 20_000_000 = 2.0%
    pub real_yield_ppb:         u64,   // default 40_000_000 = 4.0%
    pub min_replication:        u8,    // default 3
    pub max_replication:        u8,    // default 32
    pub slots_per_year:         u64,   // default 2_629_800 (~12-second slots)
    pub proof_reward_window_slots: u64, // default 7_200 (anti-hoarding cap)
}
```

PPB gives 9 decimal places of precision without floating point. Determinism-safe across implementations.

### Implementation

[`required_endowment`](../mfn-storage/src/endowment.rs):

```rust
pub fn required_endowment(
    size_bytes: u64,
    replication: u8,
    params: &EndowmentParams,
) -> Result<u128, EndowmentError> {
    let c0_ppb: u128 = u128::from(params.cost_per_byte_year_ppb)
        .checked_mul(u128::from(size_bytes))
        .ok_or(EndowmentError::Overflow)?
        .checked_mul(u128::from(replication))
        .ok_or(EndowmentError::Overflow)?;

    // numerator   = C₀ × PPB × (PPB + i)
    // denominator = PPB × (r − i)
    let r = u128::from(params.real_yield_ppb);
    let i = u128::from(params.inflation_ppb);
    if r <= i { return Err(EndowmentError::RealYieldNotAboveInflation); }

    let num = c0_ppb.checked_mul(PPB + i).ok_or(EndowmentError::Overflow)?;
    let den = PPB.checked_mul(r - i).ok_or(EndowmentError::Overflow)?;

    Ok(ceil_div(num, den))
}
```

- `u128` arithmetic throughout — the worst-case numerator for realistic params is ≈ 6×10²⁴, comfortably within `u128`'s 3.4×10³⁸ ceiling.
- `checked_mul` returns `Err` on overflow instead of panicking.
- `ceil_div` ensures we never *under-fund*, even by 1 base unit.

### Default calibration

| Parameter | Value | Equivalent |
|---|---|---|
| `cost_per_byte_year_ppb` | 200_000 | 2 × 10⁻⁴ base units / byte-year / replica |
| `inflation_ppb` | 20_000_000 | 2.0% / year |
| `real_yield_ppb` | 40_000_000 | 4.0% / year |
| `min_replication` | 3 | enforced floor |
| `max_replication` | 32 | enforced ceiling |
| `slots_per_year` | 2_629_800 | ≈ 12-second slots |

Worked example: 1 GB at 3× replication.

```
C₀ = 200_000 × 10⁹ × 3 / 10⁹ = 600_000 base units = 6 × 10⁵ base units per year
    = 0.006 MFN/year (initial cost)

E₀ = 600_000 × (1 + 0.02) / (0.04 − 0.02)
   = 600_000 × 1.02 / 0.02
   = 30_600_000 base units
   = 0.306 MFN
```

So 1 GB at 3× replication endowed for permanence costs **~0.3 MFN** at the default calibration. This is intentionally Arweave-comparable.

For 1 TB at 3× replication: ~306 MFN.

---

## 5. Per-slot payout to operators

**Intuition.** The endowment is the *principal*. Operators earn the *yield* — paid out slot by slot, every time they successfully prove they're holding the data.

### Formula

[`payout_per_slot`](../mfn-storage/src/endowment.rs):

```text
per_slot_payout_ppb = E₀ × real_yield_ppb / slots_per_year
```

For our example (1 GB × 3, E₀ = 30.6M base units at 4% yield over 2.63M slots/year):

```
per_slot_payout = 30_600_000 × 0.04 / 2_629_800
               ≈ 0.465 base units/slot
```

Note the per-slot value is **less than 1 base unit** — which is why we need the next section.

### PPB-precision accumulator

Each `StorageEntry` carries:

```rust
pub struct StorageEntry {
    pub commit: StorageCommitment,
    pub last_proven_height: u32,
    pub last_proven_slot:   u64,
    pub pending_yield_ppb:  u128,   // ← the accumulator
}
```

The `pending_yield_ppb` accumulator collects fractional yield. Every successful proof:

1. Computes `elapsed_slots = min(current_slot - last_proven_slot, proof_reward_window_slots)`.
2. Adds `elapsed_slots × per_slot_payout_ppb` to `pending_yield_ppb`.
3. Flushes any whole base units (`pending_yield_ppb / PPB`) out as the proof reward.
4. Keeps the fractional remainder for next time.

This means commitments whose per-slot payout is < 1 base unit still eventually pay out integer amounts. The chain doesn't lose precision; it just delays the payout.

### Anti-hoarding cap (`proof_reward_window_slots`)

Without a cap, a malicious operator could sit idle for a year, then submit one proof and claim a year's worth of yield in one transaction. We cap the "elapsed_slots" credit at `proof_reward_window_slots` (default 7200 ≈ 1 day). Operators are forced to prove regularly or forfeit the gap.

This is configured in `EndowmentParams::proof_reward_window_slots`.

### `accrue_proof_reward` in code

```rust
pub fn accrue_proof_reward(args: AccrueArgs) -> AccrueResult {
    let elapsed = args.slot_now
        .saturating_sub(args.last_proven_slot)
        .min(args.params.proof_reward_window_slots);

    let new_yield_ppb = args.pending_yield_ppb
        + (args.per_slot_payout_ppb as u128 * elapsed as u128);

    let payout_base_units = new_yield_ppb / PPB;
    let leftover_ppb      = new_yield_ppb % PPB;

    AccrueResult {
        payout_base_units,
        new_pending_yield_ppb: leftover_ppb,
    }
}
```

`apply_block` calls this whenever it verifies a SPoRA proof, takes the `payout_base_units`, and pays them to the proof submitter.

---

## 6. Treasury settlement

**Intuition.** Storage rewards come from the treasury. The treasury is filled by fee revenue from privacy transactions. If the treasury ever runs short, the chain mints a tiny amount of new tokens as a backstop — but the main funding path is fees → treasury → storage rewards.

### Inflow

Every regular tx fee splits according to `EmissionParams::fee_to_treasury_bps` (default 9000 = 90%):

```
treasury_share = fee × 9000 / 10_000
producer_share = fee × 1000 / 10_000
```

The treasury share is added to `ChainState::treasury` (a `u128`) inside `apply_block`.

### Outflow

After all storage proofs in a block are verified, `apply_block` sums the payouts. The treasury is drained:

```rust
let total_storage_reward: u128 = sum_of_all_accepted_proof_rewards;
let from_treasury = total_storage_reward.min(next.treasury);
let from_emission = total_storage_reward - from_treasury;

next.treasury -= from_treasury;
// from_emission is freshly minted via the emission_params.storage_proof_reward sink
```

### Emission backstop

If `from_emission > 0` (i.e., the treasury was insufficient), the chain mints the shortfall. This is the **only** sustained sink for fresh tokens beyond the subsidy curve. In equilibrium (sufficient privacy-tx fee flow) this term should be zero or near-zero.

---

## 7. `apply_block` storage flow

Putting it all together, the storage portion of `apply_block` is:

```python
# Phase 3 (during tx walk) — register new commitments
for tx in block.txs:
    if tx.storage_commit is not None:
        required = required_endowment(commit.size_bytes, commit.replication, endowment_params)
        if tx_treasury_fee_share < required: REJECT(UploadUnderfunded)
        if commit.replication < params.min_replication: REJECT(StorageReplicationTooLow)
        if commit.replication > params.max_replication: REJECT(StorageReplicationTooHigh)
        next.storage[storage_commitment_hash(commit)] = StorageEntry {
            commit, last_proven_height: height, last_proven_slot: slot, pending_yield_ppb: 0
        }

# Phase 4 — verify SPoRA proofs
proofs_in_this_block = set()
storage_reward_total = 0
for proof in block.storage_proofs:
    if proof.commit_hash in proofs_in_this_block: REJECT(DuplicateStorageProof)
    if proof.commit_hash not in next.storage:    REJECT(StorageProofUnknownCommit)
    proofs_in_this_block.add(proof.commit_hash)

    check = verify_storage_proof(commit, prev_id, slot, proof)
    if check != Ok: REJECT(StorageProofInvalid)

    entry = next.storage[proof.commit_hash]
    per_slot_ppb = payout_per_slot_ppb(entry, endowment_params)
    accrue = accrue_proof_reward(AccrueArgs {
        slot_now: slot,
        last_proven_slot: entry.last_proven_slot,
        per_slot_payout_ppb: per_slot_ppb,
        pending_yield_ppb: entry.pending_yield_ppb,
        params: endowment_params,
    })

    storage_reward_total += accrue.payout_base_units
    entry.pending_yield_ppb = accrue.new_pending_yield_ppb
    entry.last_proven_height = height
    entry.last_proven_slot   = slot

# Phase 5 — drain treasury, mint backstop if needed
from_treasury = min(storage_reward_total, next.treasury)
from_emission = storage_reward_total - from_treasury
next.treasury -= from_treasury
# (from_emission is added to the coinbase amount by the coinbase build step)
```

This is the actual logic in [`mfn_consensus::block::apply_block`](../mfn-consensus/src/block.rs).

---

## 8. Worked end-to-end example

> Alice uploads a 100 MB scientific dataset at 3× replication.

### At upload time (block 1)

- `size_bytes = 100_000_000`, `chunk_size = 262_144`, `num_chunks = 382`, `replication = 3`.
- `C₀ = 200_000 × 100_000_000 × 3 / 10⁹ = 60_000` base units of first-year cost (= 6×10⁻⁴ MFN).
- `E₀ = 60_000 × 1.02 / 0.02 = 3_060_000` base units ≈ 0.031 MFN.
- Alice constructs `StorageCommitment { data_root, size_bytes, chunk_size, num_chunks, replication: 3, endowment: pedersen_commit(3_060_000, b_endow) }`.
- Alice's tx fee earmarks `0.031 MFN × 100/90 ≈ 0.034 MFN` (so 90% of the fee covers E₀).
- `apply_block` verifies the endowment math, registers `StorageEntry { last_proven_height: 1, last_proven_slot: 1, pending_yield_ppb: 0 }`.

### At block 1000 (operator's first proof)

- `slot = 1000`, `prev_id = block_999_id`.
- `expected_chunk = chunk_index_for_challenge(block_999_id, 1000, commit_hash, 382)` — say, `chunk #214`.
- Operator publishes `StorageProof { commit_hash, chunk: bytes_of_chunk_214, proof: merkle_authentication_path }`.
- `apply_block` verifies the Merkle proof connects chunk 214's hash to `data_root`.
- `elapsed = 1000 - 1 = 999` slots (within the 7200-slot anti-hoarding cap).
- `per_slot_payout_ppb = 3_060_000 × 40_000_000 / 2_629_800 ≈ 46.5 base-units-worth-of-PPB per slot` = `4.65 × 10⁴ PPB/slot`.
- `pending_yield_ppb = 0 + 999 × 46_500 ≈ 4.64 × 10⁷ PPB`.
- `payout = 4.64 × 10⁷ / 10⁹ = 0` base units (still fractional).
- `pending_yield_ppb` carries to next proof.

### At block 25000 (cumulative)

- `elapsed = 25000 - 1000 = 24000` slots (uncapped: 24000 > 7200, so capped at 7200).
- `pending_yield_ppb += 7200 × 46_500 = 3.35 × 10⁸ PPB`. Total now ≈ `3.8 × 10⁸ PPB`.
- Still `< 10⁹`, so still 0 base units. Operator gets nothing this proof — but their stake in the file's yield carries forward.

### After many proofs

- After roughly 21500 cumulative covered slots, `pending_yield_ppb` crosses `10⁹`. Operator gets 1 base unit (= 10⁻⁸ MFN).
- This is correct: 0.031 MFN endowed at 4% yield = 0.00124 MFN/year ≈ 124000 base units/year. Spread across 2.63M slots, that's tiny per slot — but it accumulates.

---

## 9. Public API surface

```rust
// Build a commitment from data
let built: BuiltCommitment = build_storage_commitment(
    data: &[u8],
    replication: u8,
    endowment_amount: u64,
    endowment_blinding: &Scalar,
)?;

// Generate a proof
let proof: StorageProof = build_storage_proof(
    &built.commit,
    &built.chunks,
    &built.tree,
    prev_block_id: &[u8; 32],
    slot: u64,
)?;

// Verify a proof
let check: StorageProofCheck = verify_storage_proof(
    &commit,
    prev_block_id: &[u8; 32],
    slot: u64,
    &proof,
);

// Endowment math
let required: u128 = required_endowment(size_bytes, replication, &params)?;
let per_slot_ppb: u128 = payout_per_slot_ppb(endowment, &params)?;
```

For full type signatures see [`mfn-storage/README.md`](../mfn-storage/README.md).

---

## See also

- [`ECONOMICS.md`](./ECONOMICS.md) — full derivation of the endowment formula + parameter sensitivity
- [`PRIVACY.md`](./PRIVACY.md) — the privacy half (which funds this half)
- [`CONSENSUS.md`](./CONSENSUS.md) — how SPoRA proofs are gated by block production
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — full system view
- [`GLOSSARY.md`](./GLOSSARY.md) — terms

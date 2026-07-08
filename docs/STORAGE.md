# Storage Subsystem

Sections open with **intuition** in plain language before the math. See also [`OVERVIEW.md § How the permanence half works`](./OVERVIEW.md#how-the-permanence-half-works-no-formulas).

---

## What "permanence" means here

A file uploaded to Permawrite has these guarantees:

1. **The file is anchored on-chain forever.** Its Merkle root is recorded in the block header, irreversible.
2. **Storage operators are economically incentivized to hold the bytes forever.** The user pays an upfront endowment. In the default (r = 0) mode permanence is funded by storage-cost deflation (Kryder's law) plus ongoing treasury inflows; the old yield-bearing `r > i` model is still supported for parameter upgrades.
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
chunk_hash_i = dhash(MERKLE_LEAF, chunk_bytes_i)
```

[`mfn_storage::spora::chunk_hash`](../mfn-storage/src/spora.rs). Domain tag: `MFBN-1/merkle-leaf` — the leaf domain, so a chunk's bytes can never collide with an interior node hash (which uses `MFBN-1/merkle-node`). The separate `MFBN-1/chunk-hash` domain is used by the [challenge derivation](#3-spora--deterministic-challenges), not here.

### The data root

`data_root` is the Merkle root over the per-chunk hashes:

```text
data_root = merkle_root_or_zero(
    leaves = { chunk_hash_0, chunk_hash_1, …, chunk_hash_{n-1} }
)
```

Using the binary Merkle tree from [`mfn_crypto::merkle`](../mfn-crypto/src/merkle.rs) (which operates on pre-hashed leaves — it does not re-hash them):

- Leaves arrive already domain-tagged: `chunk_hash` = `dhash(MERKLE_LEAF, chunk)`, preventing leaf-vs-node ambiguity attacks.
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

### Structural (shape) validation — M5.49

Before anchoring any NEW commitment, `apply_block` (and the mempool, byte-for-byte) runs
`validate_storage_commitment_shape`:

- `chunk_size` must be a positive power of two,
- `num_chunks` must equal `ceil(size_bytes / chunk_size)` (`1` for an empty payload).

Without this, a commitment could declare `num_chunks: 1` for a gigabyte payload — SPoRA
challenges are derived `mod num_chunks`, so the network would only ever audit chunk 0
while the endowment prices the full size, silently voiding the permanence guarantee.

### Endowment is a Pedersen commitment

The `endowment` field is **not** a plaintext amount — it's a Pedersen commitment, just like a transaction output. This means:

- An external observer cannot tell how much the user paid (they could have over-paid; their privacy).
- What consensus always enforces is the *funding route*: the tx's treasury-bound fee share
  (`fee × fee_to_treasury_bps / 10_000`) must cover `required_endowment(size_bytes, replication)`
  or the block is rejected (`UploadUnderfunded`).
- When `endowment_params.require_endowment_opening = 1` (public devnet v1 since B-11), each new
  storage output must also carry a matching **`MFEO`** opening in `tx.extra`: consensus verifies
  `commit(opened_value, blinding) == sc.endowment` and `opened_value ≥ required_endowment(...)`
  ([`PERMANENCE_HARDENING.md` §A6](./PERMANENCE_HARDENING.md#a6-pedersen-endowment-opening-binding-b-11-phase-1)).
  The opened amount is visible on-chain (over-payment privacy is not range-proved yet).
- Networks with `require_endowment_opening = 0` still rely on the fee route only; the Pedersen
  point is not opened. Optional **range-proof** binding (amount-private over-payment) remains in
  [`PERMANENCE_HARDENING.md` §B1](./PERMANENCE_HARDENING.md#b1-range-proof-endowment-binding-b-11-phase-2--consensus).

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
digest      = dhash(CHUNK_HASH, prev_block_id ‖ slot (u32, BE) ‖ commit_hash)
chunk_index = (first 8 bytes of digest, as big-endian u64)  mod  num_chunks
```

(`num_chunks == 0` degenerates to index `0`; commitments always have ≥ 1 chunk
in practice.) A separate helper, [`challenge_index_from_seed`](../mfn-storage/src/spora.rs),
serves arbitrary-seed callers: `SHA-512(commit_hash ‖ seed)`, first 8 bytes as a
big-endian `u64`, reduced mod `num_chunks`.

> **Modulo-bias note.** The reduction is a plain `u64 % num_chunks` — there is
> **no rejection sampling**. The resulting bias is ≈ `num_chunks / 2⁶⁴`, i.e.
> immeasurably small for any realistic chunk count (a 1 TiB file at 256 KiB
> chunks has `num_chunks = 2²²`, bias ≈ 2⁻⁴²). Stated explicitly so nobody
> assumes perfect uniformity; see
> [`SECURITY_CONSIDERATIONS.md § 8`](./SECURITY_CONSIDERATIONS.md#8-permanence-caveats-protocol-level-summary).

### Properties

| Property | Why it matters |
|---|---|
| **Public computability** | Every node, including the operator, can derive the answer the moment a new block lands. No oracle, no off-chain coordination. |
| **Unpredictability for future blocks** | Operators cannot precompute future challenges because `prev_block_id` of block N+1 depends on block N being finalized. |
| **No meaningful bias toward any chunk** | Uniform up to a ≈ `num_chunks / 2⁶⁴` modulo bias (see note above). |
| **Per-commitment specific** | Different commitments get independent challenges; an operator can't reuse one proof for another. |

### Wire-format StorageProof

```rust
pub struct StorageProof {
    pub commit_hash: [u8; 32],
    pub chunk:       Vec<u8>,      // 256 KiB (or partial-final) raw bytes
    pub proof:       MerkleProof,  // { siblings: Vec<[u8; 32]>, right_side: Vec<bool>, index: usize }
}
```

Encoding ([`encode_storage_proof`](../mfn-storage/src/spora.rs)):

```text
commit_hash (32 B)
‖ varint(chunk.len()) ‖ chunk_bytes
‖ varint(proof.index)
‖ varint(siblings.len()) ‖ [ sibling_i (32 B) ‖ side_i (u8: 0 = left, 1 = right) ]*
```

### Verification

`verify_storage_proof(commit, prev_block_id, slot, proof)` returns a `StorageProofCheck` enum:

```rust
pub enum StorageProofCheck {
    Valid,
    CommitHashMismatch,                          // proof targets a different commitment
    WrongChunkIndex { expected: u32, got: u32 }, // answered the wrong challenge
    MerkleInvalid,                               // path doesn't open under data_root
}
```

(The "unknown commitment" case is handled one level up: `apply_block` rejects a
proof whose `commit_hash` has no `StorageEntry` with
`BlockError::StorageProofUnknownCommit` before the verifier is even called.)

The verifier:

1. Recomputes `storage_commitment_hash(commit)` and requires it to equal `proof.commit_hash` (`CommitHashMismatch` otherwise).
2. Recomputes the expected challenge index `expected_idx = chunk_index_for_challenge(prev_id, slot, commit_hash, commit.num_chunks)`; if `proof.proof.index` differs, returns `WrongChunkIndex`.
3. Verifies the supplied Merkle proof connects `chunk_hash(proof.chunk)` (= `dhash(MERKLE_LEAF, chunk)`) to `commit.data_root` *at that position* (`MerkleInvalid` otherwise).

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

The non-degeneracy condition depends on the mode:

- When `real_yield_ppb > 0`: `r > i` (yield must beat the inflation buffer).
- When `real_yield_ppb = 0` (the expected/default case): the system is in **deflation-funded mode**. `inflation_ppb` is treated as the conservative assumed annual deflation rate `d` under Kryder's law. `validate_endowment_params` accepts `r = 0` unconditionally and the endowment math uses `E₀ = C₀ · (1 + i) / d`.

This lets the protocol expect zero nominal yield on endowment principal (no reliable way to generate real yield on escrowed funds) while still guaranteeing permanence via hardware cost deflation — exactly as Arweave does.

### PPB precision

[`mfn_storage::endowment`](../mfn-storage/src/endowment.rs) uses **parts per billion** for all rate quantities:

```rust
pub const PPB: u128 = 1_000_000_000;

pub struct EndowmentParams {
    pub cost_per_byte_year_ppb: u64,   // default 200_000 = 2 × 10⁻⁴ base units / byte-year
    pub inflation_ppb:          u64,   // default 20_000_000 = 2.0%
    pub real_yield_ppb:         u64,   // default 0 (deflation-funded mode)
    pub min_replication:        u8,    // default 3
    pub max_replication:        u8,    // default 32
    pub slots_per_year:         u64,   // default 2_629_800 (~12-second slots)
    pub proof_reward_window_slots: u64, // default 7_200 (anti-hoarding cap)
}
```

PPB gives 9 decimal places of precision without floating point. Determinism-safe across implementations.

### Implementation

[`required_endowment`](../mfn-storage/src/endowment.rs) (abridged — the mode
selection is the important part):

```rust
pub fn required_endowment(
    size_bytes: u64,
    replication: u8,
    params: &EndowmentParams,
) -> Result<u128, EndowmentError> {
    validate_endowment_params(params)?; // r = 0 OK; r > 0 must beat inflation
    // … replication-range check; size · repl == 0 ⇒ Ok(0) …

    let cost = u128::from(params.cost_per_byte_year_ppb);
    let inflation = u128::from(params.inflation_ppb);
    let real_yield = u128::from(params.real_yield_ppb);

    // Effective spread for the denominator:
    // - r > 0  → (r − i)   (yield-bearing mode; validation guaranteed r > i)
    // - r == 0 → d (= i)   (deflation-funded mode: inflation_ppb re-read as d)
    let spread = if real_yield == 0 {
        inflation
    } else {
        real_yield - inflation
    };

    // E₀ = ceil( cost · size · repl · (PPB + i)  /  (PPB · spread) )
    let numerator = cost
        .checked_mul(size_repl)
        .and_then(|x| x.checked_mul(PPB + inflation))
        .ok_or(EndowmentError::Overflow)?;
    let denominator = PPB.checked_mul(spread).ok_or(EndowmentError::Overflow)?;
    Ok(ceil_div(numerator, denominator))
}
```

- **Two modes, one formula.** `validate_endowment_params` accepts `r = 0`
  unconditionally (deflation-funded default) and enforces `r > i` only when
  `r > 0` — there is no unconditional `r > i` gate.
- `u128` arithmetic throughout — the worst-case numerator for realistic params is ≈ 6×10²⁴, comfortably within `u128`'s 3.4×10³⁸ ceiling.
- `checked_mul` returns `Err` on overflow instead of panicking.
- `ceil_div` ensures we never *under-fund*, even by 1 base unit.

### Default calibration

| Parameter | Value | Equivalent |
|---|---|---|
| `cost_per_byte_year_ppb` | 200_000 | 2 × 10⁻⁴ base units / byte-year / replica |
| `inflation_ppb` | 20_000_000 | 2.0% / year (worst-case inflation *buffer* when r>0; assumed deflation rate `d` when r=0) |
| `real_yield_ppb` | 0 | **deflation-funded mode** (Kryder's law) — expected/common case |
| `min_replication` | 3 | enforced floor |
| `max_replication` | 32 | enforced ceiling |
| `slots_per_year` | 2_629_800 | ≈ 12-second slots |

Worked example: 1 GB at 3× replication (default r = 0 deflation mode).

```
C₀ = 200_000 × 10⁹ × 3 / 10⁹ = 600_000 base units = 6 × 10⁵ base units per year
    = 0.006 MFN/year (initial cost)

E₀ = 600_000 × (1 + 0.02) / 0.02          // d = inflation_ppb (assumed deflation)
   = 600_000 × 1.02 / 0.02
   = 30_600_000 base units
   = 0.306 MFN
```

So 1 GB at 3× replication endowed for permanence costs **~0.3 MFN** at the default calibration (51× the first-year cost, a very conservative multiple under 2%/yr assumed deflation). This is intentionally Arweave-comparable.

For 1 TB at 3× replication: ~306 MFN.

Because `real_yield_ppb = 0`, there is **no per-endowment yield payout** to operators from the locked principal. Operators are paid from ongoing treasury inflows (90% of priority fees + emission backstop when needed). The large upfront endowment capitalizes the treasury; deflation in real storage costs keeps the commitments solvent.

---

## 5. Per-slot payout to operators

**Intuition.** The endowment is the *principal*. Operators earn the *yield* — paid out slot by slot, every time they successfully prove they're holding the data.

### Formula

[`payout_per_slot`](../mfn-storage/src/endowment.rs):

```text
per_slot_payout_ppb = E₀ × real_yield_ppb / slots_per_year
```

At the default `real_yield_ppb = 0` this component is **zero** for every commitment. Storage operators are compensated from fresh treasury revenue (fees + emission) rather than from yield harvested on individual endowments. The formulas and accumulator remain for compatibility with positive-yield parameter sets and for future upgrades.

(The old 4% example would have produced ~0.465 base units/slot on a 30.6 M endowment; that path is still supported if a future parameter update sets a positive `real_yield_ppb` that beats `inflation_ppb`.)

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
pub struct AccrueArgs<'a> {
    pub size_bytes:       u64,   // size of the upload
    pub replication:      u8,    // declared replication factor
    pub pending_ppb:      u128,  // per-commitment PPB accumulator carried across proofs
    pub last_proven_slot: u64,   // slot of the previous accepted proof
    pub current_slot:     u64,   // this block's slot
    pub params:           &'a EndowmentParams,
}

pub fn accrue_proof_reward(args: AccrueArgs<'_>) -> Result<AccrueResult, EndowmentError> {
    // rewind guard: current_slot < last_proven_slot ⇒ credit 0, keep accumulator
    let required_e = required_endowment(args.size_bytes, args.replication, args.params)?;
    let credited = (args.current_slot - args.last_proven_slot)
        .min(args.params.proof_reward_window_slots);

    // total_ppb = credited · E₀ · real_yield_ppb / slots_per_year   (checked u128)
    let incoming_ppb = u128::from(credited)
        .checked_mul(required_e)
        .and_then(|x| x.checked_mul(u128::from(args.params.real_yield_ppb)))
        .ok_or(EndowmentError::Overflow)?
        / u128::from(args.params.slots_per_year);

    let total_ppb = args.pending_ppb.checked_add(incoming_ppb).ok_or(EndowmentError::Overflow)?;
    let payout = total_ppb / PPB;                        // whole base units flushed
    Ok(AccrueResult { payout, new_pending_ppb: total_ppb - payout * PPB, credited_slots: credited })
}
```

Note the per-slot rate is derived from the **protocol-required** endowment
(`required_endowment`), not from whatever amount the uploader actually
committed — over-payment buys privacy headroom, not extra yield. `apply_block`
calls this whenever it verifies a SPoRA proof, takes `payout`, and adds it to
the block's storage-reward total.

> **Who actually receives this reward?** Each accepted proof carries
> `operator_view_pub` / `operator_spend_pub` on the wire. Settlement mints
> coinbase outputs 1..N to those operator stealth keys (outputs 0 = producer
> subsidy + fee share). A home storage operator is paid directly without also
> winning VRF leader election. See [`ECONOMICS.md § 7`](./ECONOMICS.md#7-storage-operator-economics)
> and [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md).

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

This is the actual logic in [`mfn_consensus::block::apply_block`](../mfn-consensus/src/block/apply.rs).

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
- (positive-yield example) `per_slot_payout_ppb = 3_060_000 × 40_000_000 / 2_629_800 ≈ 46.5 base-units-worth-of-PPB per slot`. At default r=0 this value is 0 for every commitment.
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
    data,               // &[u8]
    endowment_amount,   // u64 — base units locked (computed via required_endowment)
    chunk_size,         // Option<usize> — None ⇒ DEFAULT_CHUNK_SIZE (256 KiB)
    replication,        // u8
    blinding,           // Option<Scalar> — None ⇒ fresh random Pedersen blinding
)?;
// built.commit : StorageCommitment (goes on-chain)
// built.tree   : MerkleTree        (prover keeps, to answer audits)
// built.blinding : Scalar          (prover keeps, to open the endowment)

// Generate a proof for the current block context
let proof: StorageProof = build_storage_proof(
    &built.commit,
    &prev_block_id,     // &[u8; 32]
    slot,               // u32
    data,               // &[u8] — the full file bytes
    &built.tree,
)?;

// Verify a proof
let check: StorageProofCheck = verify_storage_proof(
    &commit,
    &prev_block_id,     // &[u8; 32]
    slot,               // u32
    &proof,
);

// Endowment math
let required: u128 = required_endowment(size_bytes, replication, &params)?;
let per_slot: u128 = payout_per_slot(endowment, params.slots_per_year, &params)?;
let max_bytes: u128 = max_bytes_for_endowment(budget, replication, &params)?;
```

For full type signatures see [`mfn-storage/README.md`](../mfn-storage/README.md).

---

## Apply-block test matrix (M5 storage hardening)

Default CI in `mfn-consensus/tests/block_apply.rs` (`4e8ac41` and later M5 storage commits) pins header binding and payout side-effects:

- **Emit order** — `build_unsealed_header_commits_storage_proof_emit_order`; `storage_proof_root_wrong_emit_order_rejected`.
- **Tamper before payout** — `tampered_storage_proof_root_rejects_before_payout_effects` (treasury / provenance unchanged on reject).
- **Accept path** — `accepted_storage_proof_updates_provenance_and_treasury`; **`dual_distinct_storage_proofs_in_one_block_update_both_entries`** (`9e5c129`); **`dual_distinct_storage_proofs_positive_yield_accrues_both_entries`** (`8d436c9`).
- **Reject paths** — `duplicate_storage_proof_in_one_block_rejected`, `storage_proof_for_unknown_commit_rejected`, `storage_proof_with_wrong_chunk_rejected` (each asserts no storage/treasury mutation on reject, `46454c2`); **`storage_proof_body_tamper_rejects_without_state_change`** (`9e5c129`).
- **Accrual cap** — `storage_proof_accrual_respects_proof_reward_window_at_apply_block` pins the anti-hoarding `proof_reward_window_slots` cap in the `apply_block` path (`e310435`).

Signed-block adversarial coverage: `integration.rs` — `tampered_storage_proof_root_in_signed_block_is_rejected`, `storage_proof_flow_at_genesis_plus_block1`.

---

## See also

- [`PERMANENCE_HARDENING.md`](./PERMANENCE_HARDENING.md) — implementation-level log of shipped permanence hardening (M5.49 shape gate, M7.12 gossip auth, B-11 MFEO opening binding, B2 ChunkV2 Merkle-path gossip) and the specific plans for what remains (range-proof endowment binding, replication accounting, repair, slashing)
- [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) — can normal devices be storage operators? (feasibility vs Arweave-style hardware)
- [`ECONOMICS.md`](./ECONOMICS.md) — full derivation of the endowment formula + parameter sensitivity
- [`PRIVACY.md`](./PRIVACY.md) — the privacy half (which funds this half)
- [`CONSENSUS.md`](./CONSENSUS.md) — how SPoRA proofs are gated by block production
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — full system view
- [`GLOSSARY.md`](./GLOSSARY.md) — terms

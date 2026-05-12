# Privacy Subsystem

> **Audience.** Cryptographers and protocol engineers. Each section opens with a one-paragraph **intuition** that's accessible without formulas, then the full mechanism.
> See [`OVERVIEW.md`](./OVERVIEW.md) for the prose-only version and [`GLOSSARY.md`](./GLOSSARY.md) for term definitions.

---

## What "privacy" means here

A regular Permawrite transaction hides:

1. **Sender identity** — which UTXO is being spent (CLSAG ring signature over decoys).
2. **Receiver identity** — which wallet receives each output (stealth one-time address).
3. **Transferred amounts** — how much MFN moves (Pedersen commitment + Bulletproof range proof).
4. **Wallet linkability across txs** — neither sender nor receiver appears with a stable identifier.

The chain still verifies:

- Inputs balance outputs + fees (Pedersen sum).
- No double-spend (key images are unique).
- No money minted out of thin air (range proofs prove non-negativity).
- Inputs are real on-chain UTXOs (chain-level ring-membership check).

What's **not** hidden:

- **Transaction graph topology.** The mere fact that a transaction happened, and that it had N inputs and M outputs of unrevealed amounts, is public.
- **Block-level timing.** When you broadcast matters; Tor / Dandelion-style mixnet handling is the wallet layer's concern.
- **Fee values.** Fees are public (must be, for the chain to verify the balance equation including fee deduction).

---

## Threat model

We assume the adversary:

- Sees every byte ever published on-chain.
- Controls some fraction of validators (less than the slashing threshold).
- Has cryptographic resources comparable to a state actor — but not breaks of SHA-256 or ed25519's discrete-log problem.
- May attempt to construct malicious transactions, manipulated decoys, equivocating signatures, or counterfeit ring members.
- Can wait an unbounded amount of time (long-range attack assumptions are addressed in [`CONSENSUS.md`](./CONSENSUS.md)).

The privacy properties are computational. They reduce to:

- Hardness of the **discrete log** problem on the ed25519 prime-order subgroup.
- Hardness of **decisional Diffie-Hellman** on that group (for stealth indistinguishability).
- Collision-resistance of **SHA-256** (for the domain-separated hash transcripts).
- Soundness of **Bulletproof inner-product arguments** (for range proofs, also reduces to discrete log).
- Soundness of **Fiat-Shamir** transformations (for the ZK transcripts).

If any of these break, large pieces of the privacy stack break together. None has shown a cryptanalytic weakness in production deployment after a decade.

---

## 1. Pedersen commitments

**Intuition.** A Pedersen commitment is a "sealed envelope" containing a number. The chain can verify that two envelopes hold values that sum to a third envelope's value, *without ever opening any of them*. This is how Permawrite verifies that inputs equal outputs even though both are encrypted.

### The math

Pick two ed25519 generators:

- `G` = the standard ed25519 base point.
- `H = hash_to_point(G)` — a second generator with **unknown discrete log relative to G**, derived deterministically from `G` via try-and-increment hash-to-curve. ([`mfn_crypto::point::generator_h`](../mfn-crypto/src/point.rs).)

A commitment to value `v ∈ ℕ` with blinding `b ∈ 𝔽_L`:

```text
C(v, b) = v·H + b·G
```

Where `L` is the prime order of the ed25519 subgroup.

### Properties

- **Hiding.** Given `C(v, b)`, the value `v` is computationally hidden if `b` is uniformly random (reduces to DDH).
- **Binding.** Once committed, you cannot open `C` to a different `(v', b')` without solving discrete log between `G` and `H`.
- **Homomorphic.**

  ```text
  C(v₁, b₁) + C(v₂, b₂) = C(v₁ + v₂, b₁ + b₂)
  ```

  This is the magic. The chain can add up input and output commitments and check that the sum is zero (or equals `fee · H`, since the fee is public), proving the balance equation **without ever knowing any value**.

### Balance check (RingCT)

For a tx with `n` inputs and `m` outputs:

```text
Σ C_in_i  −  Σ C_out_j  −  fee · H  ==  0
```

If this holds, every value field cancels, leaving only the blinding-factor relationship. The sender constructs blindings such that `Σ b_in − Σ b_out = 0`, which makes the residual term `0·G = 0`.

In code: [`mfn_crypto::pedersen::pedersen_balance`](../mfn-crypto/src/pedersen.rs).

### Why not just encrypt the amount?

Symmetric encryption would let the recipient decrypt — but the chain would have no way to verify the balance equation without seeing decryption. Pedersen commitments give the chain *just enough* algebra to balance-check without seeing values. That's the whole point.

### Range proofs

A naive Pedersen commitment can encode negative numbers (e.g. `v = L − 1`, which is `−1 mod L`). Without a range check, an attacker could mint money by committing one input with a huge value and one output with `v = −1`, balancing the sum.

Every output therefore ships with a **range proof** certifying `v ∈ [0, 2^N − 1]` for some bound `N` (default `N = 64` in Permawrite, matching MFN base units).

We use **Bulletproofs** ([Bünz et al. 2017](https://eprint.iacr.org/2017/1066)) — log-size, no trusted setup, well-audited and battle-tested in Monero since 2018. Module: [`mfn_crypto::bulletproofs`](../mfn-crypto/src/bulletproofs.rs).

Pre-Bulletproofs we also have an O(N) bit-decomposition range proof ([`mfn_crypto::range`](../mfn-crypto/src/range.rs)) used for testing and as a fallback. Bulletproofs are the production path.

---

## 2. Stealth addresses

**Intuition.** Your wallet has a "public address" but every transaction *receives* into a brand-new, one-time, throwaway address derived from your address plus a fresh random number the sender picks. Observers see only the throwaway address. You scan the chain for outputs that "belong to you" using a private view key.

### Dual-key CryptoNote scheme

Each wallet has two keypairs:

- **Spend key** `(s, S = s·G)` — controls who can move funds.
- **View key** `(v, V = v·G)` — controls who can detect incoming payments.

The wallet's published address is the pair `(S, V)`.

### Sending

To send to address `(S, V)`:

1. Sender picks ephemeral scalar `r` and publishes `R = r·G` in the transaction.
2. Sender computes the **shared secret**:

   ```text
   s_shared = hash_to_scalar(r·V)  =  hash_to_scalar(v·R)   (the equality is the receiver's detection trick)
   ```

3. Sender computes the **one-time address**:

   ```text
   P = s_shared·G + S
   ```

4. Sender publishes the output as `(P, commitment, ephemeral R…)`.

The chain stores `P` in its UTXO set. Anyone scanning the chain sees only `P`, a fresh-looking point.

### Receiving

To detect incoming outputs, the receiver scans every new output:

1. Compute `s_shared' = hash_to_scalar(v·R)` using *their* view key and the published `R`.
2. Compute `P' = s_shared'·G + S`.
3. If `P' == P`, this output is for them.

### Spending

To spend the one-time output:

1. Recover the one-time **spend key**:

   ```text
   x = s_shared + s    (mod L)
   ```

   Note `P = x·G`, so `x` is the discrete log of `P`. Only the holder of the view *and* spend keys can compute it.

2. Sign the spending tx with `x` as the secret key (via CLSAG — see § 3).

### Why dual-key (view + spend)?

Separating view and spend keys lets you:

- Hand the view key to your accountant/auditor; they can see your incoming history but can't spend.
- Run a watch-only wallet on a phone while keeping the spend key on a hardware device.

The downside is the receiver must do `O(outputs_per_block)` curve multiplications per block to scan. Modern phone CPUs handle ~10⁴ ops/sec, so a chain doing ~10³ outputs/block scans in real-time with margin.

### Indexed stealth addresses

For wallets that want **multiple receiving addresses from one master keypair** (e.g. for accounting), [`indexed_stealth_address`](../mfn-crypto/src/stealth.rs) derives `(P_i, S_i)` from an index `i` deterministically — sub-addresses without changing the underlying master keys.

---

## 3. CLSAG ring signatures

**Intuition.** When spending, you sign a transaction with your real secret key — but you smear your signature across N other people's public keys, so the verifier can prove that *exactly one* of the N+1 keys signed, while being unable to tell *which one*. CLSAG ("Concise Linkable Spontaneous Anonymous Group" signature) is the modern compact variant Monero deploys.

### Setup

Let `R = {P₀, P₁, …, P_{n−1}}` be a ring of n one-time addresses (one is yours, the others are decoys you picked from chain history). Each `P_i` has an associated Pedersen commitment `C_i` (the hidden amount of that output).

The signer holds the secret key `x` such that `P_π = x·G` for some secret index `π`.

### Key image

Compute the **key image**:

```text
I = x · hash_to_point(P_π)
```

`I` is deterministic in `x` — the same key produces the same image every time. This is what enables single-spend enforcement without revealing the key: the chain records every `I` it's seen; a second appearance is rejected.

### Aggregated challenge

CLSAG's compactness trick is that it bundles the spend-key signature and the commitment-balancing signature into one ring traversal. Define aggregated weights:

```text
μ_P = dhash(CLSAG_AGG_P, ring_data ‖ message)
μ_C = dhash(CLSAG_AGG_C, ring_data ‖ message)
```

The signer effectively signs over a *single* virtual key:

```text
P*_i = μ_P · P_i + μ_C · (C_i − C_pseudo)
```

where `C_pseudo` is a "pseudo-output commitment" the signer constructs so the balance check works (covered below).

### Ring traversal (Schnorr-style)

1. The signer picks a random `α` and computes the "starting" commitment:

   ```text
   T_π = α · hash_to_point(P_π)
   ```

2. For the other ring positions `i ≠ π`, pick random `s_i` and compute the chain of challenges:

   ```text
   c_{i+1} = dhash(CLSAG_RING, …, s_i · G + c_i · P*_i, …)
   ```

3. The signer "closes the ring" by computing `s_π` such that the final challenge equals the starting one:

   ```text
   s_π = α − c_π · x*    (where x* is the virtual aggregated secret)
   ```

The output is `(c_0, s_0, s_1, …, s_{n−1}, I)`.

### Verification

The verifier traverses the ring using the published `(c_0, s_i)` values and checks that the chain loops back to `c_0`. If it does, **someone in the ring signed**, but the verifier learns nothing about which one.

In code: [`mfn_crypto::clsag::clsag_verify`](../mfn-crypto/src/clsag.rs).

### Why CLSAG vs. older LSAG

Monero shipped LSAG ([`lsag.rs`](../mfn-crypto/src/lsag.rs) in this repo) for years; CLSAG was deployed in 2020. CLSAG is:

- **~20% smaller** (single ring traversal instead of two).
- **~10% faster** to verify.
- Same security reduction as LSAG.

Both are implemented in this crate; CLSAG is the production path.

### Decoy realism — gamma age sampling

A ring is only as anonymous as its decoys are *believable*. If your decoys all come from 5 years ago and your real input is from yesterday, statistical analysis can identify the real one by timing.

Monero's mitigation (which we adopt verbatim in [`mfn_crypto::decoy`](../mfn-crypto/src/decoy.rs)) is to sample decoy ages from a **gamma distribution** calibrated to match the empirical age distribution of real spending behavior:

```
age ~ Γ(shape=19.28, scale=1/1.61)    (Monero v0.13 calibration)
```

Most real spends use recent outputs; some use old; the gamma curve matches this. Decoys sampled from the same distribution are statistically indistinguishable from real spends *under the assumption that real-world spending behavior follows the calibration*.

Known weakness: if your actual spending pattern diverges from the calibration (e.g. you always spend the youngest possible output), decoys still come from the calibrated curve and statistical inference can identify you. Tier 3 fixes this by replacing rings entirely with OoM-over-the-whole-UTXO-set (see § 5).

---

## Counterfeit-input attack closed

This is worth calling out explicitly because it was the most dangerous bug fixed in the codebase to date.

### The attack

Before the fix, `apply_block` verified that each CLSAG signature was cryptographically valid, but **it did not verify that ring members existed in the chain's UTXO set**. An attacker could:

1. Construct a CLSAG ring with **1 real UTXO** (their own, with commitment `C_real`) plus **N fabricated members** with completely made-up `(P_fake, C_fake)` pairs.
2. Choose `C_fake` commitments that hide arbitrary values — say, 10⁹ MFN each.
3. Construct a transaction that "spends" the ring (CLSAG signs correctly because they hold the real secret) and produces a single output with commitment `C_out` of value 10⁹ MFN.
4. The Pedersen balance equation passes because the chain only checks the algebraic sum, which the attacker controls via the fake `C_i` values.

**Result:** the attacker mints money out of thin air. Catastrophic.

### The fix

In `apply_block`, before accepting any transaction, every ring member is checked:

```rust
for (ii, inp) in tx.inputs.iter().enumerate() {
    for (ri, (p, c)) in inp.ring.p.iter().zip(inp.ring.c.iter()).enumerate() {
        let key = p.compress().to_bytes();
        match next.utxo.get(&key) {
            Some(entry) if entry.commit == *c => { /* OK */ }
            Some(_) => return BlockError::RingMemberCommitMismatch { … },
            None    => return BlockError::RingMemberNotInUtxoSet  { … },
        }
    }
}
```

Two attack vectors closed:

1. **Fabricated ring member.** `P` doesn't exist in the UTXO set → `RingMemberNotInUtxoSet`.
2. **Real `P` with substituted `C`.** `P` exists but the commitment provided in the ring doesn't match the real one → `RingMemberCommitMismatch`.

Both are tested:
- [`ring_member_not_in_utxo_set_rejected`](../mfn-consensus/src/block.rs)
- [`ring_member_with_wrong_commit_rejected`](../mfn-consensus/src/block.rs)
- The full chain integration test `chain_genesis_block1_block2_with_slashing` was rewritten to use **real genesis-anchored decoys**, confirming honest operation.

### Why it was missed (and why the fix is the right one)

Most Monero-derived implementations gloss over this in their explanation because Monero achieves the same effect via the global output index table — every CLSAG references ring members by *index into the global output list*, so by construction no fake member can be referenced. Our implementation references members by raw `(P, C)`, which is more flexible (and useful for log-size OoM proofs later) but pushes the existence check into consensus. The bug was a missed transition step from raw-tuple references → consensus-level set membership.

The fix is the right one because: (1) it's the smallest reduction of trust surface — we trust only the UTXO set, which `apply_block` already maintains; (2) it preserves the flexibility we need for Tier 3 OoM proofs, which prove *membership in the UTXO accumulator* and so naturally satisfy the same check; (3) it's enforced by the chain, not the wallet, so honest wallets and malicious wallets are treated identically.

---

## 4. Encrypted amount blobs

**Intuition.** The recipient needs to know how much they received. The chain doesn't. So along with each commitment, the sender ships a small encrypted blob the recipient can decrypt to recover the amount + blinding factor.

### Construction

For an output with shared secret `s_shared` (from § 2):

```text
mask_v = dhash(AMT_MASK_V, s_shared)
mask_b = dhash(AMT_MASK_B, s_shared)

enc_v  = value    XOR  mask_v
enc_b  = blinding XOR  mask_b
```

The 16-byte blob `(enc_v, enc_b)` ships with the output. The recipient (who can derive `s_shared`) XORs back to recover `(value, blinding)`, then verifies it's consistent with the published commitment `C = value·H + blinding·G`.

Module: [`mfn_crypto::encrypted_amount`](../mfn-crypto/src/encrypted_amount.rs).

---

## 5. Tier 3: Log-size rings via One-out-of-Many

**Intuition.** Today's CLSAG rings have a fixed small size (16) because every additional ring member adds 32 bytes and another scalar mult. Groth–Kohlweiss "one-out-of-many" proofs let you prove "I know the secret for one of N committed keys" with **logarithmic** size in N. So instead of a ring of 16, you can prove your input is one of the *entire UTXO set*, and the proof is still small.

### Mechanism

[`mfn_crypto::oom`](../mfn-crypto/src/oom.rs) implements the Groth–Kohlweiss commit-product zero-knowledge proof from [Groth–Kohlweiss 2015](https://eprint.iacr.org/2014/764). The proof shape is:

- Commit to your secret index `π` in a way that hides which index.
- Commit to the polynomial coefficients you'd need to multiply with the UTXO list to "select" your index.
- Prove (via inner-product arguments) that the polynomial evaluation collapses correctly.

Proof size: `O(log N · 32 bytes)`. Verification time: `O(N)` group operations (linear in the UTXO set), but with extremely cheap per-element work.

### Triptych vs. Groth–Kohlweiss vs. Lelantus

These are all variants of the same idea:
- **Groth–Kohlweiss (2015)**: the original log-size 1-out-of-N.
- **Triptych (2020)**: Monero's deployment design, generalizing to linkable + N-out-of-N for joint-spend.
- **Lelantus / RingCT 3.0**: alternatives with slightly different efficiency profiles.

Permawrite ships the GK base proof today (tested, working) and will deploy the linkable Triptych extension at Tier 3.

### Why this is the long-term answer

At Tier 3:
- Ring "size" = entire UTXO set (millions, eventually billions of entries).
- An observer trying to identify your real input by elimination needs to rule out the entire history of the chain — strictly stronger than gamma-decoy heuristics.
- Storage / bandwidth: log-size proofs make this affordable.

The tradeoff is verification time. A naive `O(N)` verifier becomes painful when N is large. The mitigation is batch verification + parallelism + an eventual move to *recursive SNARKs* that prove "all rings in this block are valid" in one constant-size proof, gated behind STARK or KZG tooling.

---

## 6. The anonymity-tier progression

Permawrite ships in tiers. Each tier monotonically strengthens privacy without breaking earlier tiers.

| Tier | Status | Ring construction | Range proof | Decoy quality |
|---|---|---|---|---|
| **Tier 1** | ✓ Live | CLSAG, fixed ring size 16 | Bulletproofs (log-size) | Gamma age-distributed |
| **Tier 2** | □ Near-term | CLSAG, ring size 32–64 | Bulletproof+ (smaller transcripts) | Gamma + transaction-graph metadata mitigations |
| **Tier 3** | □ Mid-term | OoM over entire UTXO accumulator | Bulletproof+ | N/A (all UTXOs are "decoys") |
| **Tier 4** | □ Long-term | Recursive SNARK proves all rings in a block | Same SNARK proves all ranges | N/A |

The current code (Tier 1) is what's running in the test suite. The OoM primitive (used at Tier 3) is *already implemented and tested* — see `mfn-crypto/src/oom.rs` — but not yet wired into transactions. The Tier 3 lift is wiring + UTXO-accumulator-membership formulation, not new cryptography.

---

## 7. Privacy interactions with storage permanence

The storage layer doesn't break the privacy layer. A `StorageCommitment` carries:

- `data_root` — content-addressed; reveals only the bytes of the file you uploaded (which you control — encrypt before uploading if needed).
- `size_bytes`, `chunk_size`, `num_chunks`, `replication` — public, but reveal only file metadata, not identity.
- `endowment` — a Pedersen commitment, so the **amount** you paid is amount-private. (The chain enforces the protocol-required minimum, but no observer can tell whether you paid the minimum or 100× the minimum.)

The associated transaction is a normal ring-signed, stealth-addressed, range-proven RingCT tx. Storage uploads inherit full privacy.

**Important caveat:** if you upload plaintext data, *the data itself* is public. Encrypt before upload if the file is sensitive. The chain is not in the business of encrypting your data for you — it would defeat the determinism of the SPoRA proofs.

---

## 8. Public API surface (for builders)

If you're integrating wallet code, the public API in [`mfn-crypto`](../mfn-crypto/src/lib.rs) covers everything in this document. Key entry points:

```rust
// Stealth address
let wallet = stealth_gen(/* ... */)?;
let (output, R) = stealth_send_to(&address, value, &mut rng)?;
let detected = stealth_detect(&wallet, &output)?;

// Pedersen commitments
let commit = pedersen_commit(value, &blinding);
let balanced = pedersen_balance(&inputs, &outputs, fee);

// Ring signature
let sig = clsag_sign(&ring, &secret, &message, &mut rng)?;
let ok = clsag_verify(&ring, &sig, &message)?;

// Range proof
let (proof, output) = bp_prove(value, &blinding, &mut rng)?;
let ok = bp_verify(&commit, &proof)?;

// Decoy selection (gamma)
let decoys = select_gamma_decoys(&utxo_pool, current_height, n_decoys, &mut rng)?;
```

For full type signatures and the wire-format encoding/decoding helpers, see the [`mfn-crypto` crate README](../mfn-crypto/README.md) and the source files linked above.

---

## See also

- [`STORAGE.md`](./STORAGE.md) — how the permanence half works
- [`CONSENSUS.md`](./CONSENSUS.md) — how PoS + slashing works
- [`ECONOMICS.md`](./ECONOMICS.md) — how the fee economics fund storage
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the full system view
- [`GLOSSARY.md`](./GLOSSARY.md) — every term defined

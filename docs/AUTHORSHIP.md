# Authorship claim layer

> **Audience.** Protocol designers, wallet engineers, and anyone asking how Permawrite can stay **anonymous-by-default** for uploads while still supporting an optional, **cryptographically verifiable** “I published this `data_root`” signal for permaweb-style discovery.
>
> **Status.** Normative spec for optional authorship claims. **M2.2.0–M2.2.10** shipped the initial layer; **M2.2.11** tightens guarantees (MFCL v2 + storage binding, keyed index, 256-byte messages) without changing the privacy model.

---

## Problem statement

1. **Financial privacy** uses CLSAG ring signatures: observers should not learn *which* UTXO was spent. That is the right default for money.
2. **Permanent storage** is content-addressed: the chain commits to a `data_root` (Merkle root of chunk hashes) and metadata in [`StorageCommitment`](./STORAGE.md). There is **no** author field inside that commitment by design — `StorageCommitment` stays wire-stable and does not bake identity into permanence.
3. **Permaweb** use cases still need *some* voluntary signal: “this pubkey attests it published or curates this hash,” without forcing every uploader to deanonymize their **spend** keys.

The authorship layer solves (3) without weakening (1) or bloating (2).

---

## Design principles

| Principle | Implication |
|-----------|-------------|
| **Anonymous by default** | Uploads work exactly as today if the user does nothing extra. No author field is added to `StorageCommitment`. |
| **Separate identity key** | Claims use a **Schnorr** signing keypair that is **not** the stealth view/spend key material. Leaking a “publishing pubkey” must not compromise wallet scanning or spending. |
| **Optional, explicit** | A claim is opt-in. Unbound v2 claims (or v1) can still attest to any `data_root`; bound v2 claims require an on-chain storage commitment. |
| **Single native asset** | No second coin for “transparent vs private.” Fees and endowments stay in MFN; claims are metadata, not a new token class. |
| **Header binding** | Each block header carries a `claims_root` (Merkle root over claim leaves in that block) so light clients can verify inclusion the same way as other body roots. The cost is 32 bytes per header forever; the benefit is SPV-style claim inclusion proofs without a separate indexer. |
| **Domain separation** | Every digest uses an MFBN-1 domain tag; new tags are hard-fork boundaries. |
| **One claim per pubkey per root** | Consensus rejects a second claim with the same (`data_root`, `claim_pubkey`). Different pubkeys may still claim the same `data_root` (social resolution). |

---

## Cryptographic objects

### Domain tags (digest input)

```text
AUTHORSHIP_V1 = "MFBN-1/AUTHORSHIP/v1"   // MFCL wire version 1
AUTHORSHIP_V2 = "MFBN-1/AUTHORSHIP/v2"   // MFCL wire version 2
```

Registered in `mfn_crypto::domain` as `AUTHORSHIP_CLAIM_DIGEST` and `AUTHORSHIP_CLAIM_DIGEST_V2`.

### Claim digest

The message signed by Schnorr is a 32-byte digest (not the raw UTF-8 alone).

**MFCL v1** (legacy, still accepted):

```text
claim_digest = dhash(AUTHORSHIP_V1, [
    data_root,            // 32
    claim_pubkey_bytes,   // 32 compressed
    [message_len as u8],
    message,
])
```

**MFCL v2** (default for new claims):

```text
claim_digest = dhash(AUTHORSHIP_V2, [
    data_root,            // 32
    commit_hash,          // 32 — all-zero = unbound bulletin board
    claim_pubkey_bytes,   // 32 compressed
    [message_len as u8],
    message,
])
```

**Signature / verification:** standard protocol Schnorr over `claim_digest` (`mfn_crypto::schnorr`).

### Limits (consensus-enforced)

| Constant | Value | Rationale |
|----------|------:|-----------|
| `MAX_CLAIM_MESSAGE_LEN` | **256** | Short on-chain attestation (handle, license, version). Larger payloads belong off-chain or in the stored file. |
| `MAX_CLAIMS_PER_TX` | **4** | Caps worst-case verification work per transaction. |

---

## Wire format: one claim (`MFCL`)

Claims live in `TransactionWire.extra` (committed in the CLSAG preimage). Each frame is self-delimiting.

### MFCL version 1 (legacy)

```text
MFCL                    // 4 bytes
version                 // u8 = 0x01
data_root               // [u8; 32]
claim_pubkey            // [u8; 32]
message_len             // u8
message                 // message_len bytes
signature               // 64 bytes
```

Length ∈ **[134, 390]** bytes (`message_len` ≤ 256).

### MFCL version 2 (current default)

```text
MFCL                    // 4 bytes
version                 // u8 = 0x02
data_root               // [u8; 32]
commit_hash             // [u8; 32] — see “Storage binding” below
claim_pubkey            // [u8; 32]
message_len             // u8
message                 // message_len bytes
signature               // 64 bytes
```

Length ∈ **[166, 422]** bytes.

**Storage binding.** If `commit_hash == [0u8; 32]`, the claim is an **unbound** attestation (same strength as v1). If `commit_hash != 0`, consensus **must** reject the claim unless `ChainState.storage` already contains that commitment hash and `storage[commit_hash].commit.data_root == claim.data_root`. Claims in the **same transaction** as a new storage output are validated **after** that output is registered, so upload+bundled-claim txs work.

Implementations **must** reject: wrong magic, unknown `version`, `message_len > MAX_CLAIM_MESSAGE_LEN`, malformed point/signature, trailing bytes, or more than `MAX_CLAIMS_PER_TX` frames per tx (after `MFEX` parsing).

### Outer envelope: `MFEX` (normative structured `extra`)

**`MFEX` is the only normative structured-`extra` envelope** for consensus-visible payloads today. Future inner tags extend this container without forking claim parsing.

```text
MFEX                    // 4 bytes
version                 // u8 = 0x01
body                    // concatenation of zero or more MFCL frames
```

If `extra` does **not** start with `MFEX`, consensus treats it as **opaque** (no claims indexed). `extra == []` is valid (no claims).

---

## State and header

### `ChainState` index (full node)

```text
claims: BTreeMap<(data_root, claim_pubkey_bytes), ClaimRecord>
```

At most one live claim per (`data_root`, `claim_pubkey`). Replacing requires a future revocation mechanism (not shipped).

Each `ClaimRecord` stores the full signed `MFCL` claim plus `tx_id`, `height`, `tx_index`, `claim_index`.

### `claims_root` in `BlockHeader`

- Merkle root over **claim leaves** in block order (non-coinbase txs; left-to-right `MFCL` order within `extra`).
- Leaf = `dhash(CLAIM_LEAF, [canonical_MFCL_wire, tx_id, tx_index, claim_index, height])`.
- **Empty block:** `[0u8; 32]` sentinel.

---

## Transaction patterns

### A. Upload + bundled claims

Normal storage upload with optional `MFCL` claims in `extra` (via `MFEX`). Wallets should set `commit_hash` to the upload’s `storage_commitment_hash` for a **bound** claim.

**Privacy — temporal correlation:** Bundling a claim **inside** the upload transaction links the public `claim_pubkey` to that upload event in time (same tx). A **standalone** claim tx (pattern B) breaks that link while still allowing a bound `commit_hash` once the upload is anchored.

**Privacy — keys:** Do not reuse stealth spend/view keys as the claiming key.

### B. Standalone claim tx

Ring-signed spend with claims only in `extra`. Use `commit_hash = 0` for bulletin-board claims, or the real commitment hash after the upload is on-chain.

---

## RPC (node)

`mfnd serve` JSON-RPC methods project `ChainState.claims` (and `storage` for uploads). Claim JSON includes `commit_hash` (hex) as of M2.2.11.

| Method | Purpose |
|--------|---------|
| `get_claims_for` | All claims for a `data_root`. |
| `get_claims_by_pubkey` | Recent claims from one `claim_pubkey`. |
| `list_recent_uploads` | Storage index; optional `include_claims`. |
| `list_recent_claims` | Global claim feed. |
| `list_data_roots_with_claims` | Catalog by recent claim activity. |

---

## Threat model and limitations

- **Not proof of file possession.** Binding `commit_hash` proves the claim refers to an **on-chain anchored upload**, not that the signer holds the preimage bytes.
- **Unbound claims remain weak.** `commit_hash = 0` is intentional for pre-upload or third-party curation signals.
- **No on-chain handle registry.** Human names stay off-chain.
- **Spam:** bounded by tx fees and `MAX_CLAIMS_PER_TX`; duplicate (`data_root`, pubkey) pairs are rejected.
- **Social resolution:** different pubkeys may claim the same `data_root`.

---

## Checkpoints

Chain checkpoints **v3** persist the flat `claims` map. **v2** checkpoints decode into the same in-memory shape (legacy nested map + `claim_submitted` set are not re-encoded).

---

## Implementation entrypoints

| Area | Rust |
|------|------|
| Crypto / wire | [`mfn_crypto::authorship`](../mfn-crypto/src/authorship.rs) |
| Parse `extra` | [`mfn_consensus::extra_codec`](../mfn-consensus/src/extra_codec.rs) |
| Verify + index | [`mfn_consensus::claims`](../mfn-consensus/src/claims.rs), [`apply_block`](../mfn-consensus/src/block.rs) |
| Wallet | [`ClaimingIdentity`](../mfn-wallet/src/claiming.rs), [`Wallet::publish_claim_tx`](../mfn-wallet/src/wallet.rs), [`StorageUploadPlan::authorship_claims`](../mfn-wallet/src/upload.rs) |
| RPC | [`mfnd_serve`](../mfn-node/src/mfnd_serve.rs) |

---

## Cross-references

- [`STORAGE.md`](./STORAGE.md) — `StorageCommitment`, `data_root`, permanence.
- [`PRIVACY.md`](./PRIVACY.md) — CLSAG, stealth keys, what is hidden vs public.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — `apply_block`, header roots, domain separation.
- [`GLOSSARY.md`](./GLOSSARY.md) — **authorship claim**, **MFCL**, **MFEX**, **claims_root**.

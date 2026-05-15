# Authorship claim layer

> **Audience.** Protocol designers, wallet engineers, and anyone asking how Permawrite can stay **anonymous-by-default** for uploads while still supporting an optional, **cryptographically verifiable** “I published this `data_root`” signal for permaweb-style discovery.
>
> **Status.** This document remains the **normative specification** for optional authorship claims (wire tags, digest, limits, header binding). The **M2.2.0–M2.2.10** checklist in [`ROADMAP.md`](./ROADMAP.md) is **implemented in Rust on `main`**: crypto (`mfn_crypto::authorship`), consensus (`mfn_consensus` `claims` / `extra_codec` / `apply_block` / `claims_root` / checkpoint v2), wallet ([`ClaimingIdentity`](../mfn-wallet/src/claiming.rs), [`Wallet::publish_claim_tx`](../mfn-wallet/src/wallet.rs), uploads with [`StorageUploadPlan::authorship_claims`](../mfn-wallet/src/upload.rs)), and read-only discovery on **`mfnd serve`** ([`mfn-node/src/mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs) — **`get_claims_for`**, **`get_claims_by_pubkey`**, **`list_recent_uploads`**, **`list_recent_claims`**, **`list_data_roots_with_claims`**).

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
| **Optional, explicit** | A claim is opt-in. Anyone can post a claim about any `data_root` (even before that root is anchored); the chain does **not** pick a “winner” between competing claims. |
| **Single native asset** | No second coin for “transparent vs private.” Fees and endowments stay in MFN; claims are metadata, not a new token class. |
| **Header binding** | Each block header carries a `claims_root` (Merkle root over claims processed in that block) so light clients can verify inclusion the same way as other body roots. |
| **Domain separation** | Every digest uses an MFBN-1 domain tag; new tags are hard-fork boundaries. |

---

## Cryptographic objects

### Domain tag (digest input)

```text
AUTHORSHIP_V1 = "MFBN-1/AUTHORSHIP/v1"   // exact UTF-8 bytes, no NUL terminator
```

(When implemented, this string is also registered in `mfn_crypto::domain` as a `Domain` constant.)

### Claim digest

The message signed by Schnorr is **not** the user-visible UTF-8 string alone; it is a 32-byte digest:

```text
claim_digest = dhash(AUTHORSHIP_V1, [
    data_root,           // 32 bytes
    claim_pubkey_bytes, // 32 bytes, compressed Edwards encoding
    [message_len_u8],    // single byte, 0..=MAX_CLAIM_MESSAGE_LEN
    message,             // `message_len` bytes (may be empty)
])
```

Where `dhash` is the usual MFBN-1 domain-separated SHA-256 used throughout the codebase ([`PRIVACY.md`](./PRIVACY.md), [`ARCHITECTURE.md`](./ARCHITECTURE.md)).

**Signature:** `SchnorrSignature = schnorr_sign(claim_digest, claiming_keypair)` using the existing curve25519-dalek Schnorr construction in `mfn_crypto::schnorr` (same `R || P || m` transcript as other protocol Schnorr uses, with `m = claim_digest`).

**Verification:** `schnorr_verify(claim_digest, sig, claim_pubkey)`.

The **`claim_pubkey`** in the wire object must equal `claiming_keypair.pub_key` (the verifier checks both equality and signature).

### Limits (consensus-enforced)

| Constant | Value | Rationale |
|----------|------:|-----------|
| `MAX_CLAIM_MESSAGE_LEN` | **128** | Short attestation (handle, license SPDX, version string). Fits in one IPv6-mtu-friendly `extra` segment with other framing. |
| `MAX_CLAIMS_PER_TX` | **4** | Caps worst-case verification work per transaction. |

---

## Wire format: one claim (`MFCL`)

Claims are carried inside `TransactionWire.extra` (opaque bytes already committed in the CLSAG preimage). Each encoded claim is a **fixed-prefix** blob so parsers can scan concatenated payloads.

```text
MFCL                    // 4 bytes: 0x4D 0x46 0x43 0x4C ("MFCL")
version                 // u8, currently 0x01
data_root               // [u8; 32]
claim_pubkey            // [u8; 32], compressed Edwards point
message_len             // u8, 0..=128
message                 // message_len bytes
signature               // 64 bytes (Schnorr: compressed R + little-endian s), exact layout matches encode/decode of Schnorr in mfn-crypto
```

**Total length:** `4 + 1 + 32 + 32 + 1 + message_len + 64` ∈ **[134, 262]** bytes per claim.

Implementations **must** reject:

- Wrong magic, unknown `version`, `message_len > MAX_CLAIM_MESSAGE_LEN`, malformed point, malformed signature encoding, or trailing garbage inside a single `MFCL` frame.
- More than `MAX_CLAIMS_PER_TX` well-formed `MFCL` frames in one transaction’s `extra` (after parsing the optional outer envelope; see below).

### Outer envelope: `MFEX` (optional multi-payload `extra`)

To leave room for future tagged payloads in `extra` without breaking legacy txs (opaque bytes, arbitrary length), normative **`MFEX`** framing applies when **all** of the following hold:

- `extra.len() >= 4` and `extra[0..4] == b"MFEX"`.
- The remainder decodes as a **versioned** list of inner tagged blobs (first ship: only `MFCL` claim segments).

If `extra` does **not** start with `MFEX`, consensus treats the entire `extra` as **opaque** for claim parsing (no claims indexed from that tx). Wallets may still use legacy unconstrained memos at their own risk until they migrate to `MFEX`.

**Legacy rule:** `extra == []` is valid and implies no claims.

---

## State and header

### `ChainState` index (full node)

Normative map:

```text
claims: BTreeMap<[u8; 32] /* data_root */, Vec<ClaimRecord>>
```

Each `ClaimRecord` stores at least: `claim_pubkey`, `message` (bounded copy), `tx_id` (or height+tx index), `block_height`, and a **claim_id** (e.g. `dhash` over canonical record bytes) for idempotent replay: applying the same block twice must not duplicate the same logical claim.

**Ordering:** Vec append order follows **deterministic** tx order within the block (coinbase excluded from claims if coinbase has no claim-bearing `extra`; regular txs in block order; within a tx, `MFCL` segments in left-to-right `extra` order).

### `claims_root` in `BlockHeader`

- `claims_root` is a 32-byte Merkle root over all **ClaimRecord** leaves added in that block (canonical leaf encoding TBD in implementation; domain-separated like other header roots).
- **Empty block** (no claims): use **`[0u8; 32]`** sentinel (same pattern as `bond_root` for empty bond ops).
- `verify_block_body` recomputes the root and compares to `header.claims_root`.

---

## Transaction patterns

### A. Upload + bundled claims

User builds a normal storage upload (RingCT + first output `Some(StorageCommitment)`). Optionally packs one or more `MFCL` blobs inside `extra` (via `MFEX` envelope when multiple payloads exist).

**Privacy note:** CLSAG still hides the ring position; the **claiming pubkey** is public on purpose. Do not reuse wallet stealth keys as the claiming key.

### B. Standalone claim tx

A transaction that spends MFN (ring-hidden as usual) but whose **only** purpose is to publish claims: same `extra` rules, possibly `outputs` paying change only. Useful to attach a claim **after** upload or for a `data_root` not yet on chain.

---

## RPC (node)

`mfnd serve` methods (JSON-RPC 2.0, same TCP line discipline as existing methods) — **M2.2.8** ships direct projections of [`ChainState`](../mfn-consensus/src/block.rs); **M2.2.10** adds **derived** (sorted / flattened) views over the same in-memory indexes:

| Method | Purpose |
|--------|---------|
| `get_claims_for` | Params: `data_root` hex (32 bytes). Returns all indexed claims for that root. |
| `get_claims_by_pubkey` | Params: `claim_pubkey` hex + `limit`. Returns recent claims from that pubkey. |
| `list_recent_uploads` | Params: `limit`, `offset`, optional `include_claims`. Discovery helper over anchored storage + optional claim join. |
| `list_recent_claims` | Params: `limit`, `offset` (JSON object). Flattened global claim feed, newest block height first (same secondary ordering as `get_claims_by_pubkey`). |
| `list_data_roots_with_claims` | Params: `limit`, `offset` (JSON object). Rows: `data_root`, `claim_count`, `max_claim_height`; sorted by `max_claim_height` desc. |

Exact JSON shapes mirror existing `get_block` / object-or-array param conventions.

**Implementation.** **M2.2.8** and **M2.2.10** methods are live on `mfnd serve` in [`mfn-node/src/mfnd_serve.rs`](../mfn-node/src/mfnd_serve.rs): in-memory reads of [`ChainState::claims` / `ChainState::storage`](../mfn-consensus/src/block.rs); see [`ROADMAP.md`](./ROADMAP.md) milestones **M2.2.8** and **M2.2.10**.

---

## Threat model and limitations

- **Claims are not ownership of the preimage.** Anyone can sign “I claim `data_root` X” without proving they possess the file bytes. Binding content possession is a **separate** problem (e.g. reveal-a-challenge, proof-of-storage to a third party, or publishing the file).
- **No on-chain handle registry** in v1. Mapping `claim_pubkey` → human name is intentionally off-chain (websites, DNS, social).
- **Spam:** claims cost transaction fees like any other tx; `MAX_CLAIMS_PER_TX` bounds per-tx work.
- **Social resolution:** multiple claims on the same `data_root` are allowed; readers decide trust.

---

## Implementation milestones (M2.2.0–M2.2.10)

Milestone IDs and ordering live in [`ROADMAP.md`](./ROADMAP.md) under **Milestone series M2.2 — Authorship claim layer**. **M2.2.0–M2.2.10** are complete in this repository (implementation **M2.2.0–M2.2.8** plus **M2.2.9** docs plus **M2.2.10** derived `serve` views).

| Id | Rust entrypoints (non-exhaustive) |
|----|-----------------------------------|
| M2.2.0–M2.2.1 | [`mfn_crypto::authorship`](../mfn-crypto/src/authorship.rs) |
| M2.2.2 | [`mfn_consensus::extra_codec`](../mfn-consensus/src/extra_codec.rs) |
| M2.2.3–M2.2.5 | [`mfn_consensus::claims`](../mfn-consensus/src/claims.rs), [`apply_block` / `claims_root`](../mfn-consensus/src/block.rs), [`verify_block_body`](../mfn-consensus/src/header_verify.rs) |
| M2.2.6 | [`ClaimingIdentity`](../mfn-wallet/src/claiming.rs), [`Wallet::publish_claim_tx`](../mfn-wallet/src/wallet.rs) |
| M2.2.7 | [`StorageUploadPlan::authorship_claims`](../mfn-wallet/src/upload.rs) + [`build_storage_upload`](../mfn-wallet/src/upload.rs) |
| M2.2.8 | [`mfnd_serve`](../mfn-node/src/mfnd_serve.rs) discovery RPCs (`get_claims_for`, `get_claims_by_pubkey`, `list_recent_uploads`) |
| M2.2.9 | Docs + cross-links (this file, [`PORTING.md`](../PORTING.md), overview, roadmap) |
| M2.2.10 | [`mfnd_serve`](../mfn-node/src/mfnd_serve.rs) — `list_recent_claims`, `list_data_roots_with_claims` |

---

## Cross-references

- [`STORAGE.md`](./STORAGE.md) — `StorageCommitment`, `data_root`, permanence.
- [`PRIVACY.md`](./PRIVACY.md) — CLSAG, stealth keys, what is hidden vs public.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — `apply_block`, header roots, domain separation.
- [`GLOSSARY.md`](./GLOSSARY.md) — **authorship claim**, **MFCL**, **MFEX**, **claims_root**.
- [`README.md`](../README.md) — repo map; [`mfn-node/README.md`](../mfn-node/README.md) — `mfnd serve` control plane.

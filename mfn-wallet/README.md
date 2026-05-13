# mfn-wallet

> Permawrite confidential wallet primitives — stealth scanning, owned-UTXO tracking, transfer transaction construction, **and storage upload construction** on top of `mfn-consensus` + `mfn-crypto` + `mfn-storage`.

`mfn-wallet` is the first **consumer-facing** crate in the workspace. Everything below it (consensus, crypto, storage, light client) is concerned with making the chain *correct and verifiable*. The wallet is concerned with making the chain *usable by humans*:

1. **Receive privately.** Scan every block as it lands and find the outputs that pay this wallet, using indexed stealth addresses + the encrypted-amount blob.
2. **Track ownership.** Maintain a local UTXO database keyed by one-time-address. Pre-compute the *key image* for each owned output so cross-device spend detection is O(1).
3. **Send privately.** Build CLSAG-signed transfer transactions by drawing decoys from a gamma-age pool, assembling the ring with the real input at a random slot, and delegating to `mfn_consensus::sign_transaction` for the RingCT ceremony.
4. **Store permanently.** (M2.0.14) Build CLSAG-signed *storage upload* transactions that anchor a `StorageCommitment` over arbitrary bytes in the tx's first output, with a fee whose treasury slice (`fee · fee_to_treasury_bps / 10000`) covers the chain-required upfront endowment. Every reason the mempool's storage gate could reject the tx is surfaced as a typed `WalletError` **before** signing, so the wallet never wastes CLSAG work or leaks input key images on a doomed upload.

Everything here is **pure, deterministic, and IO-free**. The wallet does not own a `Chain`, a `LightChain`, or any database — callers feed it `Block`s and ask for `TransactionWire`s. This keeps the crate WASM-friendly and lets the same primitives back a desktop wallet, a mobile wallet, a backend signer, and the future `mfn-cli wallet` binary.

## Quick start

```rust
use mfn_wallet::{Wallet, TransferRecipient, wallet_from_seed};
use mfn_crypto::seeded_rng;

// Bootstrap a wallet from a 32-byte seed. The seed is the only piece
// of long-term secret — losing it means losing all funds, just like
// every other dual-key blockchain.
let mut alice = Wallet::from_seed(&[0xaa; 32]);
let mut bob   = Wallet::from_seed(&[0xbb; 32]);

// Receive: feed every block the chain hands us to the wallet.
// `Block` is `mfn_consensus::Block`; in practice you'll be getting
// it from `mfn_node::Chain` or `mfn_light::LightChain`.
for block in incoming_blocks {
    alice.ingest_block(&block);
}

// Send: assemble a transfer paying Bob 100_000 atomic units, with
// fee 10_000. `ring_size = 4` picks 3 gamma-aged decoys from the
// chain's UTXO set automatically.
let recipients = vec![TransferRecipient {
    recipient: mfn_consensus::Recipient {
        view_pub: bob.keys().view_pub(),
        spend_pub: bob.keys().spend_pub(),
    },
    value: 100_000,
}];
let mut rng = seeded_rng(0xC0FFEE);
let signed = alice.build_transfer(
    &recipients,
    /* fee = */ 10_000,
    /* ring_size = */ 4,
    chain.state(),
    b"hello bob",
    &mut rng,
)?;

// Broadcast `signed.tx` — Bob will recover it from the next block
// he ingests.
```

### Permanent storage upload (M2.0.14)

```rust
use mfn_wallet::{Wallet, wallet_from_seed};
use mfn_crypto::seeded_rng;

let mut alice = Wallet::from_seed(&[0xaa; 32]);
for block in incoming_blocks { alice.ingest_block(&block); }

// What's the minimum fee that satisfies the chain's UploadUnderfunded
// gate for `data.len()` bytes at replication 3?
let data: &[u8] = b"the cypherpunks write code";
let min_fee = alice.upload_min_fee(data.len() as u64, 3, chain.state())?;

let mut rng = seeded_rng(0xC0FFEE);
let art = alice.build_storage_upload(
    data,
    /* replication = */ 3,
    /* fee = */         min_fee + 1_000,            // tip the producer
    /* anchor_recipient = */ alice.recipient(),     // anchor to self
    /* anchor_value = */ 1_000,                     // tiny self-pay UTXO
    /* chunk_size = */ None,                        // default 256 KiB
    /* ring_size = */ 4,
    chain.state(),
    b"manifesto-v1",
    &mut rng,
)?;

// Broadcast `art.signed.tx` to a mempool.
// Keep `art.built.tree` locally so you can answer SPoRA chunk audits.
// Keep `art.built.blinding` if you might want to open the endowment
// commitment later via `verify_endowment_opening`.
```

## Architecture

```
                       ┌───────────────────────────┐
                       │           Wallet          │
                       │  WalletKeys + UTXO map +  │
                       │       key-image index     │
                       └────┬─────────────┬────────┘
                            │             │
                  ingest_block()   build_transfer()
                            │             │
                            ▼             ▼
                       ┌─────────┐  ┌──────────┐
                       │  scan   │  │  spend   │
                       └────┬────┘  └────┬─────┘
                            │            │
                            ▼            ▼
            ┌───────────────────────────────────────────┐
            │             mfn-consensus                  │
            │  TransactionWire │ sign_transaction │      │
            │  ChainState (UTXO map)                     │
            └───────────────────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────────────────┐
            │              mfn-crypto                    │
            │  StealthWallet │ indexed_stealth_detect    │
            │  decrypt_output_amount │ select_gamma_decoys│
            │  CLSAG │ Bulletproofs                      │
            └───────────────────────────────────────────┘
```

The wallet sits *next to* the chain, never inside it. A full node uses the wallet to track its operator's funds; a light client embeds the same wallet to give end users a non-custodial mobile experience without ever running a full node.

## Modules

| Module          | Purpose                                                                                                              |
|-----------------|----------------------------------------------------------------------------------------------------------------------|
| `keys`          | `WalletKeys` wrapping `StealthWallet`, plus `wallet_from_seed` for deterministic seed-based backups.                 |
| `owned`         | `OwnedOutput` (one-time addr, value, blinding, key image, height, …), `verify_pedersen_open`, `key_image_for_owned`. |
| `scan`          | `scan_transaction` / `scan_block` — turn raw chain bytes into recovered owned outputs (handles coinbase + regular).  |
| `decoy`         | `DecoyPoolBuilder` — assemble the `&[DecoyCandidate<(P, C)>]` slice `select_gamma_decoys` expects.                   |
| `spend`         | `TransferPlan` + `build_transfer` — assemble CLSAG-signed transfer txs.                                              |
| `upload`        | (M2.0.14) `StorageUploadPlan` + `build_storage_upload` + `UploadArtifacts` + `estimate_minimum_fee_for_upload`. Mirrors `spend.rs` but anchors a `StorageCommitment` on the first output and gates every reason the mempool's M2.0.13 storage admission would refuse the tx. |
| `wallet`        | `Wallet` — owns keys + UTXO map + key-image index; convenience methods (`ingest_block`, `build_transfer`, `build_storage_upload`, `recipient`, `upload_min_fee`, …). |
| `error`         | `WalletError` — typed errors flatten `mfn_crypto::CryptoError`, `mfn_consensus::TxBuildError`, `mfn_storage::EndowmentError`, `mfn_storage::SporaError`, plus dedicated `UploadReplicationOutOfRange` / `UploadUnderfunded { fee, treasury_share, burden, min_fee }` / `UploadEndowmentExceedsU64` / `UploadTreasuryRouteDisabled` variants. |

## Soundness — Pedersen-open binding

`decrypt_output_amount` in `mfn-crypto` is **XOR-pad-shaped** — there is no authenticator on the encrypted blob. Decoding succeeds on every 40-byte input and silently yields garbage when the receiver's view key is wrong. An attacker could grind `r_pub` / `enc_amount` values until `indexed_stealth_detect` accidentally hits for our wallet on an output that isn't ours, then watch our wallet rip up real value by trying to spend phantom outputs.

The fix — applied throughout `mfn-wallet`'s scan path — is to verify the on-chain Pedersen commitment opens to the decrypted `(value, blinding)`:

```text
amount_commit ?= value · H + blinding · G
```

Any output that **decrypts** but does **not** Pedersen-open is dropped. The test `scan::tests::scan_pedersen_open_protects_against_grinding` pins this guarantee.

## Tests

- **37 unit tests** covering key derivation, Pedersen-open verification, key-image computation, full scan paths (regular + coinbase), wrong-recipient skip, key-image-based spend detection, coin selection, the wallet lifecycle (`ingest_block`, `mark_spent_by_utxo_key`, `select_inputs`), **plus 11 M2.0.14 upload tests** covering happy-path anchor + change construction, every typed error variant (replication out of range both sides, fee below floor, bps=0, endowment exceeds u64, insufficient funds), `estimate_minimum_fee_for_upload` monotonicity + exact-gate-satisfaction across a 4×4 (size, replication) grid, and Pedersen-blinding round-trip for later `verify_endowment_opening`.

- **5 integration tests** in `tests/end_to_end.rs`:
  - `wallet_round_trip_through_full_chain_and_light_chain` — drives `mfn_node::Chain` + `mfn_light::LightChain` through 4 blocks: 3 coinbase blocks crediting Alice, then a 4th block carrying an Alice→Bob transfer.
  - `wallet_rejects_transfer_when_below_balance` — pins the `InsufficientFunds` error path.
  - **(M2.0.14)** `wallet_storage_upload_through_mempool_producer_and_chain` — Alice's wallet builds an upload → `Mempool::admit` accepts it → producer drains and builds block 4 → `Chain::apply` anchors the commitment, asserting `state.storage[storage_commitment_hash(&art.built.commit)]` is populated with the correct `size_bytes`, `replication`, and `last_proven_height`. LightChain follows in lockstep.
  - **(M2.0.14)** `wallet_storage_upload_rejects_insufficient_funds_before_signing` — coin selection fails before any signing work happens.
  - **(M2.0.14)** `wallet_storage_upload_rejects_fee_too_low_before_signing` — wallet returns `UploadUnderfunded { min_fee }` with the exact actionable retry value.

> Dev-dependencies (`mfn-node`, `mfn-light`, `mfn-bls`) are needed for the integration tests; they live in `[dev-dependencies]` so the regular build closure stays slim.

## What's deferred to later milestones

- **Persistent storage** — the wallet keeps its UTXO map in memory. M2.0.15 candidate: a `WalletStore` trait + RocksDB / sled adapter so wallets survive restarts.
- **CLI / desktop binary** — `mfn-cli wallet send / receive / upload / balance` consumes this crate.
- **WASM bindings** — the crate is pure-Rust + IO-free, so `wasm-pack build --target web` should work today; we'll add a `[features] wasm` story when we ship the first browser wallet.
- **Knapsack coin selection** — current path is greedy largest-first (privacy-conservative). A Knapsack-style selector that prefers same-age inputs would improve plausible deniability when spending older holdings.
- **Storage chunk serving** — `art.built.tree` is the SPoRA prover-side artifact, but the wallet doesn't currently store / serve chunks over the wire to storage operators. That belongs in a future `mfn-storage-operator` daemon (M2.1.x).

## Roadmap line

This crate ships **M2.0.11** (stealth scan + transfer construction) and **M2.0.14** (storage upload construction). See [`docs/M2_WALLET.md`](../docs/M2_WALLET.md) and [`docs/M2_WALLET_UPLOAD.md`](../docs/M2_WALLET_UPLOAD.md) for full design notes.

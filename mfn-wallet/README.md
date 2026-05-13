# mfn-wallet

> Permawrite confidential wallet primitives — stealth scanning, owned-UTXO tracking, and transfer transaction construction on top of `mfn-consensus` + `mfn-crypto`.

`mfn-wallet` is the first **consumer-facing** crate in the workspace. Everything below it (consensus, crypto, storage, light client) is concerned with making the chain *correct and verifiable*. The wallet is concerned with making the chain *usable by humans*:

1. **Receive privately.** Scan every block as it lands and find the outputs that pay this wallet, using indexed stealth addresses + the encrypted-amount blob.
2. **Track ownership.** Maintain a local UTXO database keyed by one-time-address. Pre-compute the *key image* for each owned output so cross-device spend detection is O(1).
3. **Send privately.** Build CLSAG-signed transfer transactions by drawing decoys from a gamma-age pool, assembling the ring with the real input at a random slot, and delegating to `mfn_consensus::sign_transaction` for the RingCT ceremony.

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
| `wallet`        | `Wallet` — owns keys + UTXO map + key-image index; convenience methods (`ingest_block`, `build_transfer`, …).        |
| `error`         | `WalletError` — typed errors flatten `mfn_crypto::CryptoError` + `mfn_consensus::TxBuildError`.                     |

## Soundness — Pedersen-open binding

`decrypt_output_amount` in `mfn-crypto` is **XOR-pad-shaped** — there is no authenticator on the encrypted blob. Decoding succeeds on every 40-byte input and silently yields garbage when the receiver's view key is wrong. An attacker could grind `r_pub` / `enc_amount` values until `indexed_stealth_detect` accidentally hits for our wallet on an output that isn't ours, then watch our wallet rip up real value by trying to spend phantom outputs.

The fix — applied throughout `mfn-wallet`'s scan path — is to verify the on-chain Pedersen commitment opens to the decrypted `(value, blinding)`:

```text
amount_commit ?= value · H + blinding · G
```

Any output that **decrypts** but does **not** Pedersen-open is dropped. The test `scan::tests::scan_pedersen_open_protects_against_grinding` pins this guarantee.

## Tests

- **26 unit tests** covering key derivation, Pedersen-open verification, key-image computation, full scan paths (regular + coinbase), wrong-recipient skip, key-image-based spend detection, coin selection (greedy largest-first), and the wallet lifecycle (`ingest_block`, `mark_spent_by_utxo_key`, `select_inputs`).

- **2 integration tests** in `tests/end_to_end.rs`:
  - `wallet_round_trip_through_full_chain_and_light_chain` — drives `mfn_node::Chain` + `mfn_light::LightChain` through 4 blocks: 3 coinbase blocks crediting Alice, then a 4th block carrying an Alice→Bob transfer. Both wallets and both chains end up in lockstep.
  - `wallet_rejects_transfer_when_below_balance` — pins the `InsufficientFunds` error path.

## What's deferred to later milestones

- **Persistent storage** — the wallet keeps its UTXO map in memory. M2.0.12 candidate: a `WalletStore` trait + RocksDB / sled adapter so wallets survive restarts.
- **CLI / desktop binary** — `mfn-cli wallet send / receive / scan / balance` consumes this crate.
- **WASM bindings** — the crate is pure-Rust + IO-free, so `wasm-pack build --target web` should work today; we'll add a `[features] wasm` story when we ship the first browser wallet.
- **Knapsack coin selection** — current path is greedy largest-first (privacy-conservative). A Knapsack-style selector that prefers same-age inputs would improve plausible deniability when spending older holdings.
- **Mempool integration** — `signed.tx` is wire-ready but `mfn-node` has no mempool yet. Both arrive together when the single-node demo's `MempoolAdmit` API lands.

## Roadmap line

This crate ships **M2.0.11** of the Permawrite roadmap. See [`docs/M2_WALLET.md`](../docs/M2_WALLET.md) for the full design note.

# M2.0.11 — `mfn-wallet`: confidential wallet primitives

| Item                  | Value                                              |
|-----------------------|----------------------------------------------------|
| Crate                 | `mfn-wallet`                                       |
| Milestone             | M2.0.11                                            |
| Roadmap line          | "First consumer-facing crate — humans can use Permawrite." |
| Workspace test delta  | +28 tests (460 → 488 passing)                      |
| External dependencies | `mfn-crypto`, `mfn-consensus`, `mfn-storage`, `curve25519-dalek`, `thiserror` |
| Public API surface    | `Wallet`, `WalletKeys`, `OwnedOutput`, `BlockScan`, `TransferRecipient`, `TransferPlan`, `WalletError`, `DecoyPoolBuilder` |

## Motivation

Up through M2.0.10 the Permawrite stack was provably correct but **unusable**: a `Chain` could apply blocks, a `LightChain` could verify headers + bodies, and the wire codec could round-trip every byte, but no piece of the system could answer the question a human cares about — *"how much money do I have, and how do I send some to someone else?"*

M2.0.11 ships that piece. `mfn-wallet` is the first crate built **for end users**: it consumes the canonical block format, produces canonical transactions, and round-trips through full-node + light-node verification without any IO of its own. The same crate backs a desktop wallet, a future mobile wallet, the planned `mfn-cli wallet` binary, and (eventually) a WASM build that runs in a browser.

## Goals

1. **Receive privately** — given the wallet's view + spend keys, every newly applied block becomes a list of `OwnedOutput`s that pay this wallet.
2. **Track ownership** — maintain a local UTXO map keyed by one-time-address; precompute key images for O(1) cross-device spend detection.
3. **Send privately** — assemble CLSAG-signed `TransactionWire` instances by drawing gamma-aged decoys from the on-chain UTXO set.
4. **Stay verifiable** — the wallet does no consensus checks of its own. Callers pre-verify blocks through `mfn_node::Chain::apply` or `mfn_light::LightChain::apply_block` and only then feed them to `Wallet::ingest_block`.
5. **Stay portable** — pure Rust, no IO, no `Chain` reference, no database. `&Wallet` is `Sync`; the entire crate is WASM-ready.

## Architecture

### Where the wallet sits

```
            ┌──────────────────────────────────────────────────┐
            │                  application                     │
            │   (mfn-cli, desktop UI, mobile UI, WASM, bot)    │
            └────────────────────────┬─────────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │      mfn-wallet     │
                          │   (this milestone)  │
                          └─────────┬───────────┘
                                    │ blocks in, txs out
                ┌───────────────────┼──────────────────┐
                ▼                                     ▼
        ┌──────────────┐                     ┌────────────────┐
        │  mfn-light   │ <- verifies blocks  │   mfn-node     │
        │ LightChain   │                     │     Chain      │
        └──────────────┘                     └────────────────┘
                                                     │
                                                     ▼
                                             ┌────────────────┐
                                             │  mfn-consensus │
                                             └────────────────┘
                                                     │
                                                     ▼
                                             ┌────────────────┐
                                             │   mfn-crypto   │
                                             └────────────────┘
```

The wallet sits **above** consensus and **next to** the chain. It never reaches into a `Chain` or `LightChain` directly; callers explicitly hand it `Block`s.

### Module breakdown

```
mfn-wallet/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs        - crate-level docs + re-exports
│   ├── keys.rs       - WalletKeys + wallet_from_seed (deterministic)
│   ├── owned.rs      - OwnedOutput, verify_pedersen_open, key_image_for_owned
│   ├── scan.rs       - scan_transaction / scan_block
│   ├── decoy.rs      - DecoyPoolBuilder + build_decoy_pool
│   ├── spend.rs      - TransferPlan + build_transfer
│   ├── wallet.rs     - Wallet (state container + lifecycle methods)
│   └── error.rs      - WalletError
└── tests/
    └── end_to_end.rs - full-stack round-trip test
```

## Key design decisions

### 1. Pedersen-open binding defeats grinding attacks

`mfn_crypto::decrypt_output_amount` is XOR-pad-shaped — there is no authenticator on the encrypted blob. Decoding succeeds on every 40-byte input and yields plausible-looking but **garbage** `(value, blinding)` whenever the receiver's view key doesn't match. An attacker who can grind tx-level `r_pub` values can construct outputs that `indexed_stealth_detect` accepts for our wallet on a tx that is *not* ours.

The wallet's scan path closes this hole by demanding the on-chain Pedersen commitment open to the decrypted opening:

```text
out.amount  ?=  value · H + blinding · G
```

Outputs that decrypt but do not Pedersen-open are silently dropped. Pinned by `scan::tests::scan_pedersen_open_protects_against_grinding`.

### 2. Eager key-image computation

Every recovered `OwnedOutput` carries a precomputed key image `I = x · H_p(P)` where `x` is the one-time spend scalar and `P = x · G`. Two consequences:

- **Local double-spend prevention**: after `build_transfer` runs, the wallet locally evicts the consumed UTXO via `mark_spent_by_utxo_key`. A follow-up `build_transfer` cannot select the same UTXO before the prior tx mines.
- **Cross-device spend detection**: when `ingest_block` sees a tx whose `inputs[i].sig.key_image` matches an entry in the wallet's key-image index, it removes the corresponding UTXO. This handles the case where the *same* wallet keys are loaded on a second device that spent first.

Pinned by `wallet::tests::ingest_detects_external_spend_of_owned_utxo`.

### 3. Coinbase shortcut

Coinbase transactions have **deterministic** `r_pub = coinbase_tx_priv(height, spend_pub) · G`. The wallet exploits this in `scan_transaction`:

1. If `tx.inputs.is_empty()` (i.e., coinbase-shaped), the wallet first re-derives its *own* expected `r_pub` for this height.
2. If the derived value doesn't match `tx.r_pub`, the coinbase wasn't paid to us — skip the per-output stealth-detect work entirely.

The shortcut is purely a **performance optimisation** — the binding check is still Pedersen open. Skipping it never grants ownership; only saves work when most blocks pay someone else.

### 4. RNG abstraction matches `mfn-crypto`

`mfn_crypto::select_gamma_decoys` takes a `FnMut() -> f64` returning uniform `[0, 1)`. The wallet's `TransferPlan` reuses this convention:

- Production wallets call `crypto_random` (OS CSPRNG-backed).
- Tests call `seeded_rng(u32)` for deterministic Mulberry32 streams.

The wallet's only RNG use is decoy sampling and `signer_idx` selection; the cryptographic-quality scalars inside `sign_transaction` (tx-level `r`, output blindings) come from `random_scalar` (OS CSPRNG) inside `mfn-consensus` — the wallet never sees those.

### 5. Decoy pool is caller-supplied

Rather than locking the wallet to `ChainState`, decoys are built explicitly via `DecoyPoolBuilder` or the `build_decoy_pool` shortcut. This lets a light wallet build decoys from a smaller "recent-UTXO" subset, lets a custodial wallet build them from a private index, and lets tests pre-seed pools without standing up a chain.

The convenience method `Wallet::build_transfer(recipients, fee, ring_size, chain_state, …)` does the common case: it calls `build_decoy_pool(chain_state, self.owned.values(), None)` automatically, so the wallet never accidentally samples one of its own UTXOs as a decoy.

### 6. Change is implicit

`sign_transaction` requires `Σ inputs.value == Σ outputs.value + fee` exactly. `Wallet::build_transfer` enforces this by appending an implicit change output back to the wallet whenever `Σ inputs > Σ recipients + fee`. The change output is a normal `OutputSpec::ToRecipient` paying our own `(view_pub, spend_pub)`, so it shows up on the next `ingest_block` as a recovered `OwnedOutput`.

### 7. Greedy largest-first coin selection

Initial implementation uses a simple privacy-conservative heuristic: sort owned UTXOs by value descending, take outputs until the sum covers the target. This **minimises the number of inputs** (and therefore key images, ring construction work, and tx size). A future milestone will add Knapsack-style selection that prefers same-age inputs for stronger plausible deniability.

## Public API at a glance

```rust
// Bootstrap.
pub struct WalletKeys { /* … */ }
pub fn wallet_from_seed(seed: &[u8; 32]) -> WalletKeys;

pub struct Wallet { /* … */ }
impl Wallet {
    pub fn from_seed(seed: &[u8; 32]) -> Self;
    pub fn from_keys(keys: WalletKeys) -> Self;

    // Read state.
    pub fn keys(&self) -> &WalletKeys;
    pub fn balance(&self) -> u64;
    pub fn owned_count(&self) -> usize;
    pub fn owned(&self) -> impl Iterator<Item = &OwnedOutput>;
    pub fn scan_height(&self) -> Option<u32>;
    pub fn key_image_bytes(&self) -> HashSet<[u8; 32]>;

    // Mutate state.
    pub fn ingest_block(&mut self, block: &Block) -> BlockScan;
    pub fn mark_spent_by_utxo_key(&mut self, key: &[u8; 32]) -> bool;

    // Coin selection + transfer.
    pub fn select_inputs(&self, target: u64)
        -> Result<(Vec<&OwnedOutput>, u64), WalletError>;
    pub fn build_transfer<R: FnMut() -> f64>(
        &mut self,
        recipients: &[TransferRecipient],
        fee: u64,
        ring_size: usize,
        chain_state: &ChainState,
        extra: &[u8],
        rng: &mut R,
    ) -> Result<SignedTransaction, WalletError>;
}

// Lower-level building blocks (so view-only / read-only callers don't
// need to take a mutable Wallet).
pub fn scan_transaction(tx: &TransactionWire, tx_height: u32,
                        keys: &WalletKeys,
                        owned_key_images: &HashSet<[u8; 32]>) -> TxScan;
pub fn scan_block(block: &Block, keys: &WalletKeys,
                  owned_key_images: &HashSet<[u8; 32]>) -> BlockScan;
pub fn build_transfer<R: FnMut() -> f64>(plan: TransferPlan<'_, R>)
    -> Result<SignedTransaction, WalletError>;
pub fn build_decoy_pool<'a, I>(state: &ChainState, owned: I,
                                real_input_utxo_key: Option<[u8; 32]>)
    -> Vec<DecoyCandidate<RingMember>>
where I: IntoIterator<Item = &'a OwnedOutput>;
```

## Test matrix

| Layer                            | Test                                                             |
|----------------------------------|------------------------------------------------------------------|
| **keys** (4 tests)               | seed determinism · seed independence · view/spend independence · `StealthPubKeys` round-trip |
| **owned** (5 tests)              | Pedersen-open happy path · wrong-value reject · wrong-blinding reject · key-image determinism · key-image variance by spend key · `owned_balance` sum |
| **scan** (7 tests)               | recover payment to us · skip payment to others · find one of many outputs · recover our coinbase · skip others' coinbase · aggregate over a block · key-image marks spent · **Pedersen-open protects against grinding** |
| **wallet** (8 tests)             | ingest coinbase credits us · idempotent on unrelated blocks · two blocks accumulate · `select_inputs` largest-first · `select_inputs` combines multiple outputs · `select_inputs` insufficient-funds error · `mark_spent_by_utxo_key` evicts + idempotent · ingest detects external spend by key-image match |
| **end-to-end** (2 tests)         | full chain + light chain round-trip (3 coinbase blocks + 1 transfer block; balances + tip ids agree) · insufficient-funds rejection through the full `build_transfer` path |

Total **28 new tests**, **0 failures**, **0 regressions**. Workspace total **488 passing, 2 ignored**.

## What this unlocks

1. **`mfn-cli wallet`** — a command-line wallet binary that wraps `Wallet` + a `ChainConfig` or `LightChainConfig`. Becomes the canonical way to receive and send on testnet.
2. **Single-node demo with a real user** — combine `mfn-node` + `mfn-wallet` and you have a working *node* + *wallet* on one machine; the next milestone wires them together via a minimal RPC surface.
3. **WASM browser wallet** — pure-Rust + IO-free means `wasm-pack build --target web` Just Works once we add a `wasm` feature flag.
4. **Mempool design** — having a real wallet that produces `TransactionWire`s forces the next milestone (mempool admit/relay) to deal with a concrete tx supply, not a hypothetical one.

## Open items / follow-ups

- [ ] Persistent storage trait (`WalletStore`) so a wallet survives restarts. Likely M2.0.12.
- [ ] Optional `serde` impls behind a feature flag for caller-side JSON.
- [ ] WASM feature flag + browser wallet PoC.
- [ ] Knapsack coin selection that prefers same-age inputs.
- [ ] Subaddress support (Monero-style sub-account derivation for receiving multiple parallel streams).
- [ ] Mempool admit API in `mfn-node` so the wallet can broadcast.

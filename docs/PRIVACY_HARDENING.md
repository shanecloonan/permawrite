# Privacy Hardening — shipped changes and the remaining work

This document is the **implementation-level** companion to
[`PRIVACY.md`](./PRIVACY.md) (how the current privacy mechanisms work) and
[`F5.md`](./F5.md) (the high-level menu of future privacy/permanence
frontiers). Where `F5.md` says *what* to build and *why*, this file records
**what has actually shipped** and gives the **specific, file-and-function
level** plan for the changes that have not — so the next contributor can pick
an item up without re-deriving the design.

Doctrine reminder (from [`AGENTS.md`](../AGENTS.md)): privacy and permanence
over everything. Every item here either strengthens or leaves untouched ring
policy, endowment enforcement, and SPoRA verification. Anything that changes
consensus requires a version gate and the full M5-style test treatment before
it touches `main`.

Baseline being improved on: consensus-enforced uniform ring-16 CLSAG,
Bulletproof range proofs, stealth one-time addresses, gamma decoy sampling,
Pedersen-committed amounts, public fees, direct P2P tx fanout. Known
weaknesses are catalogued in [`PROBLEMS.md`](./PROBLEMS.md).

---

## Part A — Shipped

### A1. Two-output floor: no single-output transactions (wallet layer)

**Status:** shipped (`mfn-wallet`, reference CLI, WASM browser wallet).

#### The fingerprint this removes

Transaction *amounts* are hidden behind Pedersen commitments, but the
transaction's **output count is public** on the wire
([`TransactionWire`](../mfn-consensus/src/transaction/wire.rs)). A transaction
with a **single output** is therefore a strong fingerprint: with no change
output, it can only be a **no-change sweep** (spending an entire input set) or
an **exact-amount payment**. Both are rare relative to the ordinary "payment +
change back to self" shape, so a one-output transaction visibly stands out and
narrows the set of plausible interpretations an observer must consider. This
is the same leak Monero closed by requiring a minimum of two outputs.

#### What changed

A new constant defines the floor:

```75:89:mfn-wallet/src/lib.rs
/// Minimum CLSAG ring size enforced by reference wallets (matches consensus `min_ring_size`).
pub const WALLET_MIN_RING_SIZE: usize = 16;

/// Minimum number of outputs the reference wallet will place in a
/// value-transfer transaction (privacy floor, Monero-parity).
///
/// A transaction with a single output leaks that it is a no-change
/// sweep or an exact-amount payment — a strong fingerprint that lets an
/// observer distinguish those spends from ordinary "payment + change"
/// transfers and shrinks the plausible-recipient set. The reference
/// wallet therefore never broadcasts a one-output transfer: it pads to
/// two outputs with a zero-value output back to the sender. Output
/// amounts are Pedersen-committed, so the padding output is
/// indistinguishable on-chain from any other output.
pub const WALLET_MIN_TX_OUTPUTS: usize = 2;
```

The enforcement lives at three points, chosen so **every reference caller**
inherits the guarantee:

1. **Universal backstop** — the shared plan-based builder
   [`mfn_wallet::build_transfer`](../mfn-wallet/src/spend.rs). Every reference
   frontend funnels through here (the high-level `Wallet` API, the WASM
   `build_transfer_json`, and the CLI), so padding here catches all of them:

```213:229:mfn-wallet/src/spend.rs
    // Privacy floor (universal backstop for every reference caller —
    // wallet, WASM, CLI): never sign a single-output transfer. A lone
    // output reveals a no-change sweep or exact-amount payment and
    // fingerprints the spend against ordinary "payment + change"
    // transfers. Pad to `WALLET_MIN_TX_OUTPUTS` with zero-value outputs
    // addressed to a recipient already on this tx (no new counterparty is
    // exposed). Output amounts are Pedersen-committed, so the padding is
    // indistinguishable on-chain, and value 0 leaves the balance equation
    // (`Σ inputs == Σ outputs + fee`) untouched. `recipients` is
    // non-empty (checked above), so indexing `[0]` is safe.
    while output_specs.len() < crate::WALLET_MIN_TX_OUTPUTS {
        output_specs.push(OutputSpec::ToRecipient {
            recipient: plan.recipients[0].recipient,
            value: 0,
            storage: None,
        });
    }
```

2. **High-level transfer path** — `Wallet::build_transfer`
   ([`mfn-wallet/src/wallet.rs`](../mfn-wallet/src/wallet.rs), ~line 297).
   This path knows the sender's own keys, so it pads to **self** (a
   change-like output) rather than to the recipient, producing the nicer
   "payment + change" shape. This runs before the backstop, so the backstop is
   a no-op for this path. `Wallet::publish_claim_tx` routes through
   `build_transfer`, so authorship claims are covered too.

3. **Storage-upload builder** — `build_storage_upload`
   ([`mfn-wallet/src/upload.rs`](../mfn-wallet/src/upload.rs), ~line 458). An
   upload with no change is otherwise a single (anchor) output. It pads with a
   zero-value output **to the anchor recipient** — who is already on the tx, so
   no new counterparty is revealed.

#### Why it is safe (consensus-invariant)

- **Balance equation untouched.** A padding output has `value = 0`, so it
  contributes `0` to `Σ outputs`; the RingCT balance check
  `Σ c_pseudo − Σ amount − fee·H == 0` in
  [`verify_transaction`](../mfn-consensus/src/transaction/verify.rs) still
  closes. The builder's pseudo-blinding sum
  ([`build.rs`](../mfn-consensus/src/transaction/build.rs)) already handles an
  arbitrary output count.
- **Valid range proof.** `0 ∈ [0, 2^64)`, so `bp_prove(0, r, TX_RANGE_BITS)`
  produces a valid Bulletproof; the padded tx verifies unchanged under
  `RingPolicy::PRODUCTION`.
- **On-chain indistinguishability.** Because output amounts are
  Pedersen-committed and each output gets a fresh stealth one-time address, a
  zero-value padding output is byte-for-byte the same *shape* as any other
  output. An external observer cannot tell padded outputs from real ones.

#### Coverage matrix

| Caller | Path | Pads to | Covered |
|---|---|---|---|
| `Wallet::build_transfer` | `wallet.rs` → `spend::build_transfer` | self (change-like) | ✅ |
| `Wallet::publish_claim_tx` | → `build_transfer` | self | ✅ |
| `Wallet::build_storage_upload*` | `upload.rs` | anchor recipient | ✅ |
| WASM `build_transfer_json` | `mfn-wasm` → `spend::build_transfer` | recipient[0] | ✅ |
| WASM `build_storage_upload_json` | `mfn-wasm` → `build_storage_upload` | anchor recipient | ✅ |
| CLI `wallet send` / `wallet upload` | `mfn-cli` → wallet API | as above | ✅ |

#### What this change does NOT cover (honest limits)

- ~~**It is a wallet-layer default, not consensus law.**~~ Closed:
  [§B1](#b1-consensus-enforced-minimum-output-count-p5--shipped) lifted the
  floor into `verify_transaction`, so under production uniform-ring params a
  one-output transaction is now a consensus reject network-wide.
- **Input count still leaks when only one UTXO exists.** `tx.inputs.len()` is
  public. Age-band selection
  ([§B2](#b2-age-band-coin-selection--shipped)) stops the input *set* from
  mixing eras; the reference wallet now pads to two inputs when a second
  UTXO is available ([§B15](#b15-canonical-input-count-floor-f7--shipped)).
  Consensus enforces `min_input_count = 2` on the uniform-ring tier (**F7 tail shipped**).
- ~~**Output *ordering* and other wallet-chosen bytes are not yet
  canonicalized**~~ Closed:
  [§B3](#b3-canonical-encoding-conformance-p9--shipped).
- **Fees remain public plaintext** ([§B6](#b6-hidden-fees-p6)).
- **Network origin is unprotected** ([§B7](#b7-dandelion-transaction-relay-p3)).

#### Test coverage

- `mfn-wallet/src/spend.rs`
  - `single_recipient_transfer_is_padded_to_two_outputs` — a no-change
    (exact-amount) transfer is padded to two outputs and verifies under
    `RingPolicy::PRODUCTION`.
  - `transfer_with_change_is_not_over_padded` — a payment+change transfer is
    left at exactly two outputs (the pad only fills up to the floor, never
    beyond).
- `mfn-wallet/src/upload.rs` — `empty_data_zero_burden_zero_min_fee_is_fine`
  updated to assert the anchor+pad two-output result and that the pad carries
  no storage commitment.

#### Verification

Landed on `main` after the local CI mirror (`scripts/ci-check.ps1`): rustfmt,
clippy `-D warnings`, and `cargo test --release`. All Rust suites pass
(`mfn-wallet`, `mfn-consensus`, `mfn-runtime`, `mfn-rpc`,
`mfn-storage-operator`, `mfn-wasm`). The only mirror failures were flaky
`mfnd_smoke` P2P TCP integration tests (port/timing on Windows), unrelated to
output construction.

---

## Part B — Remaining work (specific plans)

Ordered roughly cheapest-and-safest first. Each item names the exact file(s)
and the concrete change. Items marked **consensus** need a version gate and
M5-style proptests. Cross-references to the `F5.md` menu are given as `F5:Pn`.

### B1. Consensus-enforced minimum output count (`F5:P5`) — **shipped**

**Problem.** [§A1](#a1-two-output-floor-no-single-output-transactions-wallet-layer)
was wallet-only; consensus still admitted one-output txs, so the anonymity-set
benefit was not network-wide.

**Shipped.** [`RingPolicy`](../mfn-consensus/src/block/state.rs) gained
`min_output_count: u32` (`PRODUCTION = MIN_TX_OUTPUTS_UNIFORM_TIER = 2`,
`TEST = 0` so existing small-ring test vectors keep passing).
[`verify_transaction`](../mfn-consensus/src/transaction/verify.rs) enforces it
next to the ring-size checks, so the floor guards both mempool admission and
`apply_block` through the shared ingress point. The value is **derived**, not
stored: `ConsensusParams::ring_policy()` engages the floor exactly when the
uniform-ring tier is active (`uniform_ring_size != 0`), which keeps the
checkpoint serialization of `ConsensusParams` unchanged (no codec version
bump) and ties the two uniformity guarantees — ring shape and output-count
shape — together. Coinbase is exempt (verified by `verify_coinbase_outputs`,
never `verify_transaction`).

Tests: `single_output_tx_rejected_when_output_floor_active`,
`two_output_tx_passes_output_floor`, and
`ring_policy_derivation_ties_output_floor_to_uniform_tier` (including
`DEFAULT_CONSENSUS_PARAMS.ring_policy() == RingPolicy::PRODUCTION`) in
`mfn-consensus/src/transaction/tests.rs`. Production-params test fixtures
(`apply_block_proptest`, `emission_simulation`,
`producer_treasury_settlement`, `block_apply`, mempool unit helpers) now emit
the reference two-output shape (change + zero-value pad).

**Effort:** moderate. **Risk:** medium (consensus + test churn).

### B2. Age-band coin selection — **shipped**

**Problem.** `Wallet::select_inputs`
([`mfn-wallet/src/wallet.rs`](../mfn-wallet/src/wallet.rs)) was
largest-first greedy. It minimized input count (good for size), but it
correlated spends over time: it deterministically drained the biggest UTXOs
first, and a tx mixing a very old with a very fresh output advertised a
wallet consolidating across its history.

**Shipped.** `select_inputs` now groups spendable outputs into exponential
age bands (`floor(log2(age + 1))` blocks since confirmation, relative to the
scan height) and spends within one band: if any single band covers the
target it uses the band that does so with the fewest inputs (ties prefer the
newest band — recent outputs are the most plausible spends); only when no
band suffices does it spill across bands, newest-first, draining each band
before touching the next. The signature is unchanged (no RNG parameter —
the selector is deterministic, with equal-value ties broken on UTXO key
bytes so `HashMap` iteration order cannot leak into selection). Tests:
`select_inputs_prefers_one_age_band_over_mixing_eras`,
`select_inputs_prefers_fewest_inputs_across_bands`, plus the pre-existing
coverage/insufficient-funds cases. Pure `mfn-wallet` change, no consensus
impact.

**Shipped (consensus tail).** `RingPolicy.min_input_count`
(`MIN_TX_INPUTS_UNIFORM_TIER = 2`) at `verify_transaction` when the
uniform-ring tier is active — see [§B15](#b15-canonical-input-count-floor-f7--shipped).

**Effort:** moderate (wallet) + moderate (consensus). **Risk:** low.

### B3. Canonical-encoding conformance (`F5:P9`) — **shipped**

**Problem.** Any wallet-controlled byte that differs between implementations
partitions the anonymity set into "users of wallet X": output ordering, change
position, `extra`-field contents, decoy sampling seed handling.

**Shipped (highest-value sub-item).** Output position no longer carries a
change signal: [`spend::build_transfer`](../mfn-wallet/src/spend.rs) — the
universal backstop every reference frontend (wallet, WASM, CLI) funnels
through — Fisher–Yates-shuffles the output specs with the plan RNG after the
two-output pad, so "the last output is the change" no longer holds for any
reference-wallet transaction. One-time addresses are derived from the *final*
index inside `sign_transaction`, so the shuffle is invisible to recipients
and the balance equation. A shuffle (rather than a sort by one-time-address
bytes) is used because the indexed stealth derivation computes the address
*from* the output position — a post-derivation sort would invalidate the
derivation it sorted by. Test:
`output_position_carries_no_change_signal` asserts the change output's
position varies across transactions and every shuffled tx verifies and
scans.

**Shipped (conformance suite).**
[`mfn-wallet/tests/canonical_conformance.rs`](../mfn-wallet/tests/canonical_conformance.rs)
pins the wire-visible choices of `build_transfer` and
`build_storage_upload` — the two constructors every reference frontend
(wallet, WASM, CLI) funnels through, so the suite covers all frontends by
construction: `version == TX_VERSION`; `extra` empty unless the caller
supplies a memo (the wallet injects zero identifying bytes; caller memos
are carried verbatim); every ring exactly `WALLET_MIN_RING_SIZE` — pinned
equal to the consensus production uniform policy so they cannot drift;
outputs at or above the two-output floor; every `enc_amount` a real
ciphertext (never the all-zero decoy sentinel); and byte-canonical wire
form (`encode(decode(encode(tx))) == encode(tx)`). The wire format has no
unlock-time field at all — the strongest form of "remove the field if
unused"; the suite documents that a future timelock field must add a
canonical-default assertion here.

**Shipped (production RNG contract).** [`production_tx_rng`](../mfn-wallet/src/lib.rs)
is the normative OS CSPRNG alias re-exported from `mfn-wallet`; CLI
(`wallet_cmd.rs`), WASM (`transfer_core.rs`, `upload_core.rs`), and the
documented production path all wire it for decoy sampling, signer-slot
selection, and output shuffling. [`seeded_rng`](../mfn-crypto/src/decoy.rs)
is test-only. The conformance suite source-scans every reference frontend
(`reference_frontends_wire_production_tx_rng_not_seeded_rng` in
[`canonical_conformance.rs`](../mfn-wallet/tests/canonical_conformance.rs)).

**Effort:** low–moderate. **Risk:** low.

### B4. Decoy-pool quality — **partial (a shipped)**

**Problem.** Two issues in the wallet decoy path:
- `build_decoy_pool` excluded **all** owned outputs
  ([`mfn-wallet/src/decoy.rs`](../mfn-wallet/src/decoy.rs)). The comment
  conceded this "slightly weakens the anonymity set": your own UTXOs never
  appeared as decoys for others, so an active wallet's outputs were
  under-represented in rings globally.
- `DEFAULT_GAMMA_PARAMS`
  ([`mfn-crypto/src/decoy.rs`](../mfn-crypto/src/decoy.rs)) are Monero's
  empirically-tuned constants; Permawrite's spend-age distribution may differ,
  and the co-height binary-search pick is deterministic within a height bucket.

**Shipped (a).** `build_decoy_pool` now excludes only the real input key(s)
of the current transaction; other owned UTXOs remain eligible decoys.
`Wallet::build_transfer` / storage-upload paths pass `chosen_keys` instead of
`self.owned.values()`. Test: `build_decoy_pool_excludes_only_spent_inputs`.

**Shipped (c).** `select_gamma_decoys` binary-searches the target height, then
picks uniformly among unchosen candidates at that height (`pick_uniform_among_co_height`)
instead of always taking the rightmost index — co-height selection is no longer
deterministic. Test: `select_randomizes_within_co_height_bucket`.

**Remaining.** (b) re-fit gamma shape/scale once mainnet has spend data. Item
retired outright by B8/B9 (membership proofs) for long-term effort vs. endgame.

**Effort:** low (a, c) / research (b). **Risk:** low.

### B5. Drop the LSAG legacy path from release builds (`F5:P8`) — **shipped**

**Problem.** [`mfn-crypto/src/lsag.rs`](../mfn-crypto/src/lsag.rs) predates
CLSAG and is unused in the production tx path, but its presence is accepted
surface area.

**Shipped.** `pub mod lsag` and `pub mod oom` (plus their re-exports) are
now gated behind `#[cfg(any(test, feature = "lsag"))]` /
`#[cfg(any(test, feature = "oom"))]` in
[`mfn-crypto/src/lib.rs`](../mfn-crypto/src/lib.rs), with matching
non-default cargo features in `mfn-crypto/Cargo.toml`. Consequences:

- Dependent crates (consensus, wallet, node, WASM) build `mfn-crypto`
  without `cfg(test)`, so neither module exists in any release binary —
  verified by a clean workspace `clippy --all-targets -D warnings` with no
  dependent referencing the symbols.
- `mfn-crypto`'s own unit tests still compile and run both modules
  (`cargo test -p mfn-crypto` — the `cfg(test)` arm), so the reference
  implementations keep their coverage.
- Anyone who deliberately wants the legacy surface must opt in with
  `--features lsag` / `--features oom`, which cannot happen silently.

**Effort:** low. **Risk:** low.

### B6. Hidden fees (`F5:P6`) — **consensus**

**Problem.** `tx.fee` is public plaintext
([`wire.rs`](../mfn-consensus/src/transaction/wire.rs)) because the balance
check needs `fee·H`. It is the last plaintext amount on every tx and a
fee-fingerprinting vector.

**Plan.** Move to committed fees with a range proof; reveal only the
per-block aggregated fee total for the coinbase check in `apply_block`.
Touches [`pedersen.rs`](../mfn-crypto/src/pedersen.rs) balance helpers and the
coinbase settlement path in
[`emission.rs`](../mfn-consensus/src/emission.rs) /
[`block/apply.rs`](../mfn-consensus/src/block/apply.rs).

**Effort:** high. **Risk:** high (consensus).

### B7. Dandelion++ transaction relay (`F5:P3`) — **shipped**

**Problem.** The single largest uncovered deanonymization surface. On RPC
`submit_tx`, `mfnd` fans the fresh tx to **all peers in parallel**
([`mfn-node/src/p2p_fanout.rs`](../mfn-node/src/p2p_fanout.rs),
`broadcast_fresh_tx`), so the first peers learn the origin node.

**Shipped.** Opt-in Dandelion++ stem/fluff routing in
[`mfn-node/src/dandelion.rs`](../mfn-node/src/dandelion.rs) wired through
[`P2pPeerSet::broadcast_fresh_tx`](../mfn-node/src/p2p_fanout.rs): stem phase
forwards to one epoch-mapped peer; per-hop fluff probability + stem timeout
transition to parallel fan-out. Enable with `mfnd serve --dandelion` or
`MFND_DANDELION=1` (default off — legacy parallel fan-out unchanged for CI).

**Stem wire label.** Stem relays use [`TxStemV1`](../mfn-net/src/frame.rs) (P2P
tag `0x11`); fluff fan-out stays on [`TxV1`](../mfn-net/src/frame.rs) (`0x06`).
Both decode to the same mempool ingress path.

**Rehearsal soak.** Public-devnet mesh scripts accept `--dandelion`
(`start-all`, `soak`, `participant-rehearsal-smoke`); wrappers
[`dandelion-rehearsal-smoke.sh`](../scripts/public-devnet-v1/dandelion-rehearsal-smoke.sh)
/ [`dandelion-soak.sh`](../scripts/public-devnet-v1/dandelion-soak.sh) for
local rehearsal. Nightly/CI default remains off.

**Remaining.** Eclipse-resistance peer diversity — **P31 phase 0–1 shipped**; anchor peers on checkpoints (**F12 phase 0** this push).

**Effort:** high. **Risk:** high (network behavior + CI mesh) — mitigated by opt-in default off.

### B8. Optional Tor/arti transport (`F5:P4`) — network layer

**Problem.** Complements B7. Decoy rings hide *which UTXO* you spent; they do
nothing about a network observer correlating broadcast timing with a home IP.

**Plan.** Optional onion-routed transport (the `arti` crate) for P2P dials and
RPC submission, configured at `mfnd` startup. Opt-in, no consensus impact.

**Phased wiring (research → ship):**

| Phase | Scope | Touch points | Gate |
| --- | --- | --- | --- |
| **B8.0** | Transport trait + env knobs | **`mfn-net::transport`** with `P2pTransportConfig`, `Tcp` default + `Tor` stub; `MFND_P2P_TRANSPORT`, `MFND_TOR_SOCKS5`; `mfnd_p2p_transport=…` harness line | **Shipped** — default `tcp`; CI unchanged |
| **B8.1** | Outbound P2P over SOCKS5 | **`mfn-net::socks5`** CONNECT client; Tor dials via `MFND_TOR_SOCKS5` | **Shipped** — unit test with mock proxy |
| **B8.2** | Inbound hidden service + onion dials | SOCKS5 `ATYP_DOMAIN` connect; `MFND_P2P_ONION` harness; [`TOR_P2P.md`](./TOR_P2P.md) + torrc example; optional `.onion` in [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) | **Shipped** (system Tor HS path; embedded `arti` listener deferred) |
| **B8.3** | Wallet RPC submit path | `mfn-cli` optional `--tor` / `MFN_CLI_RPC_TOR` for `submit_tx` to remote `.onion` RPC; quorum RPC peers mirror Tor mode; WASM deferred | **Shipped** — `tor-rpc-rehearsal-smoke` plan-only in CI |

**Non-goals (testnet):** consensus wire changes, mandatory Tor, or blocking
cleartext P2P — privacy must remain opt-in until eclipse diversity (P31) is
addressed.

**Effort:** moderate–high. **Risk:** medium (dependency weight, dial latency).

**Lane owner:** 5 (privacy surface) + 1 (CI mesh stability).

### B9. View tags for cheap light-client scanning (`F5:P7`) — **shipped**

**Problem.** Light wallets do `O(outputs_per_block)` curve multiplications to
scan. Expensive scanning pushes users toward handing view keys to third-party
scanners — a privacy regression.

**Shipped.** Tx wire **v2** adds a 1-byte `view_tag` per output (after
`enc_amount`, before the storage flag), bound in the CLSAG preimage. Reference
wallet + coinbase builders set tags via
[`indexed_view_tag_from_shared`](../mfn-crypto/src/stealth.rs); the scanner
([`mfn-wallet/src/scan.rs`](../mfn-wallet/src/scan.rs)) skips mismatched tags
before `indexed_stealth_detect` (~256× filter). Legacy **v1** txs (no tag byte)
still decode and verify.

**Effort:** moderate. **Risk:** medium (wire format) — mitigated by dual-version
acceptance at ingress.

### B10. Structural authorship-key firewall (`F5:P10`) — **shipped**

**Problem.** `AUTHORSHIP.md` *advises* not deriving the claiming key from the
stealth seed path, but nothing enforces it — reuse would link financial
activity to a stable public label.

**Shipped.** Three structural layers, no consensus impact:

1. **Canonical derivation in `mfn-crypto`** —
   [`authorship::derive_claiming_keypair`](../mfn-crypto/src/authorship.rs)
   is now the only sanctioned seed → claiming-key path, hash-derived under
   `CLAIMING_KEY_DERIVE_TAG` (`MFW_SEED_CLAIM_V1`, byte-compatible with the
   previous wallet-local derivation so existing identities are unchanged).
   The tag is disjoint from every financial-key domain
   (`MFW_SEED_VIEW_V1`, `MFW_SEED_SPEND_V1`, `MFN-1/stealth-wallet/*`).
2. **Closed constructor** — `ClaimingIdentity`'s only public constructor is
   `from_seed`, which delegates to (1); wallet code *cannot* wrap view/spend
   key material in a claiming identity.
3. **Signing-time rejection** — `Wallet::publish_claim_tx` and
   `build_storage_upload_with_authorship` refuse
   (`WalletError::ClaimKeyReusesWalletKey`) any claiming pubkey equal to the
   wallet's view or spend pubkey, as defense in depth against future
   constructors or foreign frontends.

Tests: cross-domain independence over sample seeds (crypto + wallet layers),
byte-compatibility with the legacy derivation, firewall rejection of
wrapped view/spend keypairs, and acceptance of the supported shared-seed
flow.

**Effort:** low. **Risk:** low.

### B11. Full-chain membership proofs — retire decoy rings (`F5:P2`, `F5:P11`) — **consensus**

**Problem.** Ring-16 caps every spend's anonymity set at 16 and keeps the
gamma-calibration weakness (B4) alive.

**Plan.** The Groth–Kohlweiss One-out-of-Many primitive already exists and is
tested in [`mfn-crypto/src/oom.rs`](../mfn-crypto/src/oom.rs) but is not wired
into transactions. Wiring it (a UTXO-accumulator membership formulation plus a
linkable Triptych-style extension) makes the anonymity set the entire UTXO
history. The endgame (`F5:P11`) is a curve-tree accumulator (FCMP++) with
`O(log N)` proofs and no decoy selection at all. Largest privacy uplift
available; research-grade wiring.

**Effort:** very high. **Risk:** high (consensus + crypto).

### B12. Post-quantum stealth hybrid (`F5:P12`) — **consensus**

**Problem.** Pedersen amounts are information-theoretically hiding, but
stealth-address detection rests on ECDH. On a *permanence* chain, an adversary
archiving today and breaking discrete log later can retroactively link every
historical output to its recipient — the data will still be there.

**Plan.** Hybrid the shared-secret derivation in
[`mfn-crypto/src/stealth.rs`](../mfn-crypto/src/stealth.rs) with an ML-KEM
encapsulation (`s_shared = H(ECDH || ML-KEM secret)`) so unlinkability holds if
*either* assumption survives. Wire-format change; version-gate.

**Effort:** high. **Risk:** high.

### B13. Size-bucketed storage commitments (`F5:P15`) — **shipped**

**Problem.** `size_bytes` is public in every `StorageCommitment`
([`mfn-storage/src/commitment.rs`](../mfn-storage/src/commitment.rs)); exact
file size is a strong fingerprint against known documents.

**Shipped.** Reference uploads pad to the next power-of-two size bucket before
anchoring: [`storage_size_bucket`](../mfn-storage/src/commitment.rs) /
[`pad_to_storage_size_bucket`](../mfn-storage/src/commitment.rs) in
`mfn-storage`; [`build_storage_upload`](../mfn-wallet/src/upload.rs) and
[`estimate_minimum_fee_for_upload`](../mfn-wallet/src/upload.rs) price endowment
on the bucket. Consensus and mempool reject NEW anchors whose declared
`size_bytes` is not a canonical bucket (`validate_storage_commitment_shape`
check 3). `UploadArtifacts.anchored_payload` is what operators persist as
`payload.bin`. On-chain `size_bytes` now reveals at most one bit of length
precision instead of the exact byte count.

**Optional follow-up.** 1.5× step buckets if power-of-two waste is too high.

**Effort:** moderate. **Risk:** medium (endowment pricing).

### B15. Canonical input-count floor (`F7`) — **shipped**

**Problem.** Even with age-band cohesion, a lone input on-chain reveals
that the wallet had a single UTXO large enough to cover the payment — a
fingerprint distinct from the common two-input Monero default shape.

**Shipped.** [`WALLET_MIN_TX_INPUTS`](../mfn-wallet/src/lib.rs) (= 2) and
[`Wallet::select_inputs_for_tx`](../mfn-wallet/src/wallet.rs) pad coin
selection after [`select_inputs`](../mfn-wallet/src/wallet.rs): when a
second spendable UTXO exists, the wallet merges it into the spend and
returns the excess as change. Pad selection prefers the same age band as
the newest chosen input; ties break on smallest value. Applies to
[`build_transfer`](../mfn-wallet/src/wallet.rs),
[`build_storage_upload*`](../mfn-wallet/src/wallet.rs), and
[`publish_claim_tx`](../mfn-wallet/src/wallet.rs) (via `build_transfer`).
Wallets with only one UTXO stay at one input.

**Remaining.** ~~Consensus enforcement of allowed `(inputs, outputs)` shapes
(F7 tail) — network-wide reject or mandatory dummy inputs at
`verify_transaction`.~~ **Shipped (F7 tail):** `RingPolicy.min_input_count`
(`MIN_TX_INPUTS_UNIFORM_TIER = 2`) enforced in `verify_transaction`
whenever the uniform-ring tier is active, mirroring the output floor.
Wallets with only one spendable UTXO cannot broadcast until they hold a
second (fund with multi-output faucet or receive a second payment).

**Tests.** `select_inputs_for_tx_pads_to_two_when_second_utxo_exists`,
`select_inputs_for_tx_single_utxo_cannot_pad`,
`single_input_tx_rejected_when_input_floor_active`,
`two_input_tx_passes_input_floor`,
`ring_policy_derivation_ties_shape_floors_to_uniform_tier`.

**Effort:** moderate (wallet) / high (consensus). **Risk:** medium.

### B14. Note: `list_utxos` RPC exposure (not a fix — a clarification)

The public `list_utxos` RPC
([`mfn-rpc/src/dispatch.rs`](../mfn-rpc/src/dispatch.rs)) returns the entire
UTXO set (one-time addresses + commitments). This looks like a leak but is
**intended** — light/browser wallets need it to build decoy pools, and the
same data is already derivable from public blocks (`get_block_txs`). Removing
it would break light clients without adding privacy. Documented here so it is
not "fixed" by mistake. Private *reads* are a real problem addressed by
`F5:P13` (oblivious retrieval), not by restricting this endpoint.

### P31. Anti-eclipse peer diversity (`F5:P31`) — **phase 0 shipped**

**Problem.** A node whose P2P sessions all sit in one IPv4 /16 learns only
what that neighborhood relays — the fastest path to deanonymizing Dandelion++
stem traffic and partitioning operators from producers.

**Shipped (phase 0).** [`mfn-net::peer_diversity`](../mfn-net/src/peer_diversity.rs)
summarizes live session peers into distinct IPv4 /16, `.onion`, and other-host
buckets. `get_status.p2p` exposes the counts; `mfnd serve` prints
`mfnd_p2p_diversity_policy=min_distinct_prefix16=2` and emits
`mfnd_p2p_diversity_warning` when ≥2 IPv4 session peers share one /16.
Disable warnings with `MFND_P2P_MIN_DISTINCT_PREFIX16=0`.

**Shipped (phase 1).** When diversity is low, `mfnd serve` runs a background
sweep that dials durable peers in **new** /16 buckets (`mfnd_p2p_diversity_redial_start`).
Disable with `MFND_P2P_DIVERSITY_REDIAL=0`.

**Remaining.** Anchor peer lists on checkpoints — **F12 phase 0 shipped** (optional `anchor_peers` in trusted summary + RPC); ASN-aware buckets.

**Effort:** moderate (phase 0–1) / high (full P31). **Risk:** low (metrics + bounded redial).

### P32. Role-separated node topology (`F5:P32`) — **phase 0–2 shipped**

**Problem.** Running validator, storage-operator, and wallet RPC on one internet-facing
host correlates block production, chunk serving, and spend/submit behavior.

**Shipped (phase 0).** [`role_topology.rs`](../mfn-node/src/role_topology.rs) emits
`mfnd_role_topology_warning` when `--produce` / `--committee-vote` shares a public
`--rpc-listen` host with the configured `--p2p-listen` address (and the validator is
a registered storage operator when genesis enables operator registry). Loopback devnet
meshes are unchanged.

**Shipped (phase 1).** [`REFERENCE_TOPOLOGY.md`](./REFERENCE_TOPOLOGY.md) — production
and public-testnet role separation layouts, command templates, anti-patterns;
`reference-topology-rehearsal-smoke` plan gate in `ci-check`.

**Shipped (phase 2).** `vps-role-*.env.example` templates (validator, observer, operator,
wallet) + OPERATORS.md cross-links; rehearsal smoke verifies templates exist.

**Remaining.** Operator-manifest separation (PM23), bind-host lint for observer-only nodes.

**Effort:** low (phase 0–2). **Risk:** low (warn-only + docs).

### F12. Subjective checkpoint web (`F5:F12`) — **phase 0–3 shipped**

**Problem.** Light clients that pin a single RPC tip are vulnerable to eclipse and forged
checkpoints. Independent maintainer attestations provide social redundancy.

**Shipped (phase 0).** `anchor_peers` in trusted summary + `get_light_snapshot`; `--p2p-anchor-summary` boot merge.

**Shipped (phase 1).** [`CHECKPOINT_LOG.md`](./CHECKPOINT_LOG.md) — Schnorr-signed JSONL log;
`mfn-cli checkpoint-log sign|verify`; domain-separated maintainer keys (not wallet seeds).

**Shipped (phase 2).** `wallet light-scan --checkpoint-log FILE` cross-checks post-sync summary
against verified log entries; rejects disagreement at the same `tip_height`.

**Shipped (phase 3).** `mfn-checkpoint-log` shared crate; WASM `checkpointLogVerify` /
`checkpointLogCrossCheck` for browser light wallets (same Schnorr rules as CLI).

**Remaining.** Publish log at TL-8 invite.

**Effort:** moderate (phase 0–3) / high (web fetch). **Risk:** low (opt-in social layer).

---

## Prioritization

| Impact / effort | Items |
|---|---|
| Shipped | **A1** two-output floor (wallet), **B1** consensus min-output floor, **B2** age-band coin selection, **B4** decoy pool quality (a+c), **B5** LSAG/OoM feature-gated, **B10** authorship-key firewall, **B3** conformance + production RNG, **B13** upload size buckets (wallet + consensus), **B7** Dandelion++ (relay + soak + `TxStemV1` wire), **B8** Tor transport (B8.0–B8.3), **B9** view tags (v2 wire + scanner), **B15** two-input floor (wallet + consensus **F7**), **P31** peer diversity (phase 0–1), **P32** role topology (phase 0–2), **F12** checkpoint anchor peers (phase 0) + signed log (phase 1–3) |
| High impact, moderate effort | TL-5 VPS internet soak |
| High impact, high effort | B6 (hidden fees), B11 (membership proofs), B12 (PQ stealth) |
| Network add-ons | B8 (Tor) |

Natural next step: **TL-5** VPS internet soak (lane 7).

---

## See also

- [`PRIVACY.md`](./PRIVACY.md) — how the current privacy mechanisms work
  (includes the *Output-count uniformity* section for A1).
- [`PERMANENCE_HARDENING.md`](./PERMANENCE_HARDENING.md) — the permanence twin
  of this document (shipped storage hardening + remaining permanence plans).
- [`F5.md`](./F5.md) — the broader privacy/permanence frontier menu.
- [`PROBLEMS.md`](./PROBLEMS.md) — the weaknesses these items answer.
- [`ROADMAP.md`](./ROADMAP.md) — where scheduled items live.

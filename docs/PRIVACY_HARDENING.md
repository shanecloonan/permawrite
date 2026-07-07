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
- **Input count still leaks.** `tx.inputs.len()` is public and reveals how
  many UTXOs were consumed. Age-band selection
  ([§B2](#b2-age-band-coin-selection--shipped)) stops the input *set* from
  mixing eras, but canonical N-in shapes remain open (P5 tail).
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

**Remaining.** Input *count* still leaks (`tx.inputs.len()` is public);
canonical N-in shapes are the P5 tail.

**Effort:** moderate. **Risk:** low.

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

### B7. Dandelion++ transaction relay (`F5:P3`) — network layer

**Problem.** The single largest uncovered deanonymization surface. On RPC
`submit_tx`, `mfnd` fans the fresh tx to **all peers in parallel**
([`mfn-node/src/p2p_fanout.rs`](../mfn-node/src/p2p_fanout.rs),
`broadcast_fresh_tx`, always `except_peer = None`), so the first peers learn
the origin node. `PRIVACY.md` explicitly punts network privacy to the wallet
layer.

**Plan.** Implement Dandelion++ stem/fluff routing across `mfn-net` and
[`mfn-node/src/p2p_gossip.rs`](../mfn-node/src/p2p_gossip.rs): a stem phase
that forwards to a single randomly-chosen peer with a per-node epoch mapping,
then a randomized transition to diffusion (fluff). Add stem-phase state and
timers; keep the existing fanout as the fluff transport. This is a substantial
change that touches the rehearsal mesh CI — land it on its own with careful
soak testing.

**Effort:** high. **Risk:** high (network behavior + CI mesh).

### B8. Optional Tor/arti transport (`F5:P4`) — network layer

**Problem.** Complements B7. Decoy rings hide *which UTXO* you spent; they do
nothing about a network observer correlating broadcast timing with a home IP.

**Plan.** Optional onion-routed transport (the `arti` crate) for P2P dials and
RPC submission, configured at `mfnd` startup. Opt-in, no consensus impact.

**Effort:** moderate–high. **Risk:** medium.

### B9. View tags for cheap light-client scanning (`F5:P7`)

**Problem.** Light wallets do `O(outputs_per_block)` curve multiplications to
scan. Expensive scanning pushes users toward handing view keys to third-party
scanners — a privacy regression.

**Plan.** Add a Monero-style 1-byte **view tag** derived from the shared
secret to each output so scanners skip ~99% of work. Lands in
[`mfn-crypto/src/stealth.rs`](../mfn-crypto/src/stealth.rs) and the WASM
light-client scan path; changes the output wire format, so version-gate it.

**Effort:** moderate. **Risk:** medium (wire format).

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

### B13. Size-bucketed storage commitments (`F5:P15`) — **partial (wallet shipped)**

**Problem.** `size_bytes` is public in every `StorageCommitment`
([`mfn-storage/src/commitment.rs`](../mfn-storage/src/commitment.rs)); exact
file size is a strong fingerprint against known documents.

**Shipped (wallet layer).** Reference uploads pad to the next power-of-two
size bucket before anchoring: [`storage_size_bucket`](../mfn-storage/src/commitment.rs)
/ [`pad_to_storage_size_bucket`](../mfn-storage/src/commitment.rs) in
`mfn-storage`; [`build_storage_upload`](../mfn-wallet/src/upload.rs) and
[`estimate_minimum_fee_for_upload`](../mfn-wallet/src/upload.rs) price endowment
on the bucket. On-chain `size_bytes` now reveals at most one bit of length
precision instead of the exact byte count.

**Remaining.** Consensus-mandatory bucketing for non-reference uploaders;
optional 1.5× step buckets if power-of-two waste is too high.

**Effort:** moderate. **Risk:** medium (endowment pricing).

### B14. Note: `list_utxos` RPC exposure (not a fix — a clarification)

The public `list_utxos` RPC
([`mfn-rpc/src/dispatch.rs`](../mfn-rpc/src/dispatch.rs)) returns the entire
UTXO set (one-time addresses + commitments). This looks like a leak but is
**intended** — light/browser wallets need it to build decoy pools, and the
same data is already derivable from public blocks (`get_block_txs`). Removing
it would break light clients without adding privacy. Documented here so it is
not "fixed" by mistake. Private *reads* are a real problem addressed by
`F5:P13` (oblivious retrieval), not by restricting this endpoint.

---

## Prioritization

| Impact / effort | Items |
|---|---|
| Shipped | **A1** two-output floor (wallet), **B1** consensus min-output floor, **B2** age-band coin selection, **B4** decoy pool quality (a+c), **B5** LSAG/OoM feature-gated, **B10** authorship-key firewall, **B3** conformance + production RNG, **B13** upload size buckets (wallet) |
| High impact, moderate effort | B7 (Dandelion++), B9 (view tags), B13 consensus bucket mandate |
| High impact, high effort | B6 (hidden fees), B11 (membership proofs), B12 (PQ stealth) |
| Network add-ons | B8 (Tor) |

Natural next step: **B7** (Dandelion++ relay), then **B9** (view tags).

## See also

- [`PRIVACY.md`](./PRIVACY.md) — how the current privacy mechanisms work
  (includes the *Output-count uniformity* section for A1).
- [`PERMANENCE_HARDENING.md`](./PERMANENCE_HARDENING.md) — the permanence twin
  of this document (shipped storage hardening + remaining permanence plans).
- [`F5.md`](./F5.md) — the broader privacy/permanence frontier menu.
- [`PROBLEMS.md`](./PROBLEMS.md) — the weaknesses these items answer.
- [`ROADMAP.md`](./ROADMAP.md) — where scheduled items live.

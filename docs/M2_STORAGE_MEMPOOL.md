# M2.0.13 — Storage-anchoring transactions in the mempool

| Item                  | Value                                                                |
|-----------------------|----------------------------------------------------------------------|
| Crate                 | `mfn-node` (extends `mempool` module)                                |
| Milestone             | M2.0.13                                                              |
| Roadmap line          | "Permanence transactions can now ride the same submission path."     |
| Workspace test delta  | +10 tests (506 → 516 passing)                                        |
| External dependencies | none new — uses `mfn-storage::{required_endowment, storage_commitment_hash}` |
| API change            | Removed `AdmitError::StorageTxsNotYetSupported`; added `StorageReplicationTooLow`, `StorageReplicationTooHigh`, `EndowmentMathFailed`, `UploadUnderfunded` |

## Motivation

M2.0.12 shipped the mempool, but with one explicit, advertised gap: any transaction with `outputs[i].storage.is_some()` was rejected immediately via a typed `AdmitError::StorageTxsNotYetSupported` variant. That made the privacy half of the chain end-to-end usable (wallet → mempool → producer → chain) while leaving the permanence half entirely disconnected from the submission pipeline.

M2.0.13 closes that gap. The mempool now admits storage-anchoring transactions on the same terms `apply_block` admits them, with the same four typed errors and the same silent-skip semantics for already-anchored data roots. The wallet still doesn't *build* storage uploads (that's M2.0.14), but any tool that does — including the integration tests in this milestone — can now submit them through the standard path.

## Goals

1. **Equivalence with `apply_block`** for storage-anchoring transactions. A storage tx admitted to the mempool is one the chain will accept, modulo the same admit→inclusion races that affect any tx.
2. **Mirror the chain's typed errors** so RPC / log consumers can react with a single switch statement.
3. **Silent-skip the no-op anchors.** Re-anchoring a data root that's already on chain, or doubling up on a root within the same tx, is *not* an error — the chain treats it as a no-op (the original endowment still pays for permanence). The mempool agrees.
4. **No new dependencies.** Use the `mfn-storage` helpers that already ship: `required_endowment`, `storage_commitment_hash`.
5. **Preserve the original mempool semantics.** Storage anchoring is a per-output extension to the existing eight-step admit gate — it slots in between the cross-chain key-image check and the mempool RBF check, after the heavier cryptographic work has confirmed the tx is structurally sound.

## Architecture

### The eight-step admit gate, updated

Step (6) is new. Steps (1)–(5) and (7)–(8) are unchanged from M2.0.12.

| Step | Check | Implementation |
|------|-------|----------------|
| 1    | Reject coinbases (`inputs.is_empty()`)                  | `AdmitError::NoInputs` |
| 2    | Local min-fee policy                                    | `AdmitError::BelowMinFee` |
| 3    | `verify_transaction` (CLSAG + balance + range proofs)   | `AdmitError::TxInvalid` |
| 4    | Ring-membership chain guard against `state.utxo`        | `AdmitError::RingMemberNotInUtxoSet` / `RingMemberCommitMismatch` |
| 5    | Cross-chain double-spend (`state.spent_key_images`)     | `AdmitError::KeyImageAlreadyOnChain` |
| **6**| **Storage-anchoring gate (NEW)**                        | **`StorageReplicationTooLow` / `StorageReplicationTooHigh` / `EndowmentMathFailed` / `UploadUnderfunded`** |
| 7    | Mempool RBF (key-image conflict with strictly higher fee) | `AdmitError::ReplaceTooLow` |
| 8    | Size-cap eviction                                       | `AdmitError::PoolFull` |

### Step (6) in detail

For each output `out` in declaration order:

1. If `out.storage` is `None` → skip.
2. Compute `h = storage_commitment_hash(&sc)`.
3. **Silent skip** if `state.storage.contains_key(&h)` (chain-side dedup) OR `h` was already seen earlier in this same tx (within-tx dedup via a local `HashSet`). Skipped anchors contribute zero burden and produce no error.
4. Otherwise, enforce `state.endowment_params.min_replication ≤ sc.replication ≤ state.endowment_params.max_replication`. Violations produce typed errors.
5. Call `mfn_storage::required_endowment(sc.size_bytes, sc.replication, &state.endowment_params)`. Map an `Err` to `EndowmentMathFailed`.
6. Add the returned `u128` to a running `tx_burden`.

After the loop, if `tx_burden > 0`:

- Compute `treasury_share = u128::from(tx.fee) * u128::from(state.emission_params.fee_to_treasury_bps) / 10_000` (integer division, exactly the same formula `apply_block` uses).
- Require `treasury_share ≥ tx_burden`; otherwise emit `UploadUnderfunded` with all four context fields populated.

### Why these four error names

They mirror `mfn_consensus::BlockError` byte-for-byte: `StorageReplicationTooLow`, `StorageReplicationTooHigh`, `EndowmentMathFailed`, `UploadUnderfunded`. A future RPC layer can map mempool admit-errors to HTTP responses without ever having to translate between two different naming schemes.

### Why silent-skip instead of error on duplicate data roots

The chain itself treats already-anchored and within-tx-duplicate `data_root`s as **silent skips** — the original endowment still pays for permanence, the second anchor is inert. If the mempool errored, the producer could *never* re-include a tx whose data root happened to be anchored a block earlier. That would create a race where a tx that admitted cleanly in block N can never be included from block N+1 onwards, even though the chain *would* still accept it. Silent-skipping in both layers keeps the invariant tight: mempool admit ⇒ chain inclusion path is open.

### What the mempool deliberately does NOT check

These are checks `apply_block` *also* doesn't run; surfacing them in the mempool would create false rejections relative to the chain:

- **Structural commitment validity** (`chunk_size` power-of-two, `num_chunks == ceil(size_bytes / chunk_size)`, `data_root` being a real Merkle root). These surface at SPoRA proof time via `verify_storage_proof`.
- **Endowment opening.** `verify_endowment_opening(commit, value, blinding)` exists in `mfn-storage` but is not called by `apply_block`. The chain enforces the economic relation `treasury_share ≥ Σ required_endowment`, not a cryptographic opening proof.
- **Cross-mempool data-root dedup.** Two pending txs in the mempool that both anchor the same `data_root` are not in conflict — the chain will silently dedupe at inclusion time. No need for mempool-side reconciliation.

## Test matrix

### Unit tests in `mfn-node/src/mempool.rs` (+8 new)

| Test                                                              | Asserts |
|-------------------------------------------------------------------|---------|
| `admit_storage_tx_happy_path`                                     | A well-formed 1 KB / replication-3 / fee=100 tx admits as `Fresh`. |
| `admit_storage_tx_rejects_replication_too_low`                    | `replication=2` against `min=3` → `StorageReplicationTooLow`. |
| `admit_storage_tx_rejects_replication_too_high`                   | `replication=33` against `max=32` → `StorageReplicationTooHigh`. |
| `admit_storage_tx_rejects_underfunded`                            | Same upload, `fee=1` → `UploadUnderfunded`. Treasury share underflows the burden. |
| `admit_storage_tx_silently_skips_already_anchored_root`           | Pre-seeded `state.storage` contains the `data_root` → tx admits with `fee=1` because the burden is zero. |
| `admit_storage_tx_silently_skips_within_tx_duplicate`             | Two outputs anchoring the same `data_root` in one tx → admits cleanly; second doesn't double-count. |
| `admit_storage_tx_mixed_outputs_with_regular_payment`             | A tx with one storage anchor + one plain payment admits when the burden is covered. |
| `admit_storage_tx_burden_scales_with_size`                        | Same fee=100, size=16 KB → `UploadUnderfunded` (burden grows linearly with size × replication). |

### Integration tests in `mfn-node/tests/mempool_integration.rs` (+3 new)

| Test                                                                       | Asserts |
|----------------------------------------------------------------------------|---------|
| `storage_tx_through_full_mempool_producer_chain_pipeline`                  | Mempool admits → `drain` → producer builds block → chain applies → `state.storage[hash]` is populated → `remove_mined` is a no-op (already drained) → re-admission rejected via `KeyImageAlreadyOnChain`. |
| `storage_tx_underfunded_is_rejected_by_mempool_before_producer`            | A 64 KB upload at `fee=100` (insufficient treasury share for the burden) is rejected at admit time. Critical invariant: the mempool catches what the chain catches, so the producer can't accidentally build an `UploadUnderfunded` block. |
| `already_anchored_storage_tx_silently_skips_burden_in_mempool`             | Pre-seeded genesis with the storage commitment → admit a fresh tx anchoring the same `data_root` with `fee=1` → admits because the chain considers the anchor inert. |

## What this unlocks

- **Permanence transactions ride the same wire** as plain transfers — no special-case submission path, no separate storage-tx mempool.
- **The wallet can grow `build_storage_upload(...)` (M2.0.14)** with the confidence that its output will be admissible by both the mempool and the chain.
- **A user-facing CLI / RPC** built on M2.0.12 + M2.0.13 can accept storage uploads using the same `submit_tx` endpoint, with `AdmitError` driving the error-response mapping.
- **The fusion of privacy and permanence is now end-to-end testable** at the submission layer — the same `Mempool::admit` call gates both privacy spends and storage anchors, enforcing the same economic relation (`treasury_share ≥ burden`) the chain enforces at block-application time.

## Risks and notes

- **API break.** The `StorageTxsNotYetSupported` variant of `AdmitError` is gone. Anything pattern-matching that variant fails to compile; the replacement variants are richer (each carries `tx_id_hex` + offsets / counts), which is intentional. The crate is pre-1.0 so this is acceptable.
- **No `Cargo.toml` changes.** `mfn-storage` was already in the dependency closure of `mfn-node`; the new imports are zero-cost.
- **Anchor-then-spend race.** Two pending txs that conflict on key images but both anchor unique data roots still race normally; only one will land. The losing tx is evicted via `remove_mined` and its data root never gets anchored. This is fine — the *real* anchor (with the actual endowment-funded UTXO) wins and pays for permanence.
- **Already-anchored race.** A tx admitted at height N for a not-yet-anchored data root may be included at height N+M, by which time someone else anchored the same root. The chain treats this as a silent skip; the mempool's admit-time burden calculation doesn't get refunded, so the tx pays a slightly larger fee-to-treasury than strictly necessary. The over-payment is at most `Σ required_endowment` for the deduplicated anchors — typically a small fraction of even a modest tx fee — and disappears in the next milestone if the wallet learns to consult the chain before pricing the fee.

## What ships in this commit

- `mfn-node/src/mempool.rs` — step (6) implementation (~80 lines), four new typed errors, 8 new unit tests, replaced placeholder test.
- `mfn-node/tests/mempool_integration.rs` — 3 new integration tests, new genesis helper.
- `docs/M2_STORAGE_MEMPOOL.md` — this document.
- `docs/ROADMAP.md` — milestone status.
- `docs/ARCHITECTURE.md` — crate layout update.
- `README.md` — test count + table refresh.
- `mfn-node/README.md` — modules table, status, test categories.
- `CODEBASE_STATS.md` — regenerated.

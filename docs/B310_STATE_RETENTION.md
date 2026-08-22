# B-310 — Checkpoint prune carve-out (helper, not wired)

**Status:** **B-310** retention inventory + Path A honesty (this unit). **Not** wired into `chain.blocks` / `mfn-store`. **Not** a UTXO drop. **Not** a storage drop.
**Owner:** lane 6 · **Does not change** live Path A disk layout
**Depends on:** M2 chain checkpoints (already on Path A)
**Blocks:** honest **PM8** wiring (drop bodies only; never decoys or SPoRA state)

## Why this exists

CSV / [`PROBLEMS.md` §7](./PROBLEMS.md#7-state-growth-is-fundamentally-linear-with-usage-and-difficult-to-prune): full-node disk grows with both **money** (UTXO + key images + `chain.blocks`) and **data** (storage commitments). If running a node becomes exotic, the operator set shrinks — that is a permanence risk.

[`F5.md` PM8](./F5.md) wants to prune spent *transaction data* behind a finalized checkpoint while **never** pruning storage, endowment, or committed chunks. Privacy makes the money half harder: `apply_block` never removes spent outputs from [`ChainState::utxo`](../mfn-consensus/src/block/state.rs), because those outputs are the CLSAG decoy pool. Dropping them would shrink rings and is a silent privacy downgrade.

This unit names the carve-out in code so PM8 cannot “helpfully” drop the wrong map.

## Target (no privacy/permanence tradeoff)

| Artifact | Retention | Why |
| --- | --- | --- |
| `ChainState.storage` / operators / stats / claims / endowment params | **PermanenceKeep** | SPoRA + authorship-over-`data_root` |
| `ChainState.utxo` / `spent_key_images` / `utxo_tree` | **PrivacyKeep** | Decoys + double-spend |
| Params, treasury, validators, `block_ids` | **ConsensusKeep** | Fork if dropped |
| `chain.blocks` body at height `h` when finalized checkpoint height is `H` | **HistoricalBody** iff `H > 0` and `h < H` | The only PM8 candidate |

[`historical_block_body_may_prune`](../mfn-consensus/src/archive_retention.rs) is that last row. [`storage_may_prune`](../mfn-consensus/src/archive_retention.rs) / [`utxo_may_prune`](../mfn-consensus/src/archive_retention.rs) / [`spent_key_image_may_prune`](../mfn-consensus/src/archive_retention.rs) are `const false`.

[`CHAIN_STATE_FIELD_COUNT`](../mfn-consensus/src/archive_retention.rs) = **24**, matching `ChainState` today. Adding a field without classifying it fails `b310_every_chain_state_field_is_classified` once the count is bumped with a new variant — the inventory is the complexity fail-closed.

### Why not prune Path A this unit?

Deleting `chain.blocks` prefixes changes RPC `get_block`, JOIN replay, archive export, and fraud-proof body witnesses. That is a node-store change (lane 4/7) after the inventory is agreed. Path A keeps the full log.

## Tests (pass in this unit)

- All 24 `ChainState` fields classify; none are `HistoricalBody`.
- Storage / operators / claims / endowment → `PermanenceKeep`; `storage_may_prune() == false`.
- UTXO / key images / utxo tree → `PrivacyKeep`; maps may not prune.
- Bodies: `h < H` with `H > 0` may prune; equal/above/`H == 0` must not.

## Follow-ups (not this unit)

| Id | Item |
| --- | --- |
| **PM8 wire** | `mfn-store` optional drop of `chain.blocks` prefix after a finalized checkpoint, with archive-export still requiring a full log or an explicit archival node role |
| **PM10** | External archive mirrors (already the complementary “keep a copy”) |
| **Tier 3 OoM** | Only then could spent UTXO *membership* change; not a prune of storage |

## See also

- [`PROBLEMS.md` §7](./PROBLEMS.md#7-state-growth-is-fundamentally-linear-with-usage-and-difficult-to-prune)
- [`F5.md` PM8](./F5.md)
- [`DECENTRALIZATION.md`](./DECENTRALIZATION.md)
- [`B308_SPORA_LOTTERY.md`](./B308_SPORA_LOTTERY.md)

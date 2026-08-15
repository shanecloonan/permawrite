# B-268 — Same-chain subsidy activation-height (work package)

**Status:** **B-268b** landed `ee3739e7` (helper + ckpt v12 + apply_block/producer). **B-268c** wires fraud/slash/gossip to overlay at the *contested* height. **B-268d** light slash uses genesis emission + stored schedule; light checkpoint **v2** persists `(H_act, bps)` (v1 decodes inactive). **Not** B-13c enable.
**Owner:** lane 6 (emission helpers + sims) · **Review:** lane 4 (`apply_block` / fraud / producer seal)
**Depends on:** **B-265** genesis `emission` JSON merge · **B-13a** sims · human **B-33** before enable
**Blocks:** honest same-chain **B-13c** on live Path A (JSON alone cannot rewrite checkpoint emission)

## Goal

Enable `subsidy_to_treasury_bps = 1000` from a future tip height `H_act` on Path A
**without** rewriting sealed coinbases, changing `genesis_id`, or flipping
`DEFAULT_EMISSION_PARAMS`.

## Status quo

| Fact | Location |
| --- | --- |
| Params on state; restored from checkpoints | `ChainState.emission_params`; `chain_checkpoint/` |
| Coinbase/treasury use state params as-is | `apply_block` (`block/apply.rs`) |
| Defaults stay at 0 | `DEFAULT_EMISSION_PARAMS` (`emission.rs`) |
| Genesis JSON can merge emission | **B-265** `merge_emission` (`genesis_spec.rs`) |
| Live Path A tip restores checkpoint emission (= 0) | B-265 honesty in `B13_SUBSIDY_FORK_SIGNOFF.md` |
| Checkpoint wire at v11 for subsidy field on base params | `CHAIN_CHECKPOINT_VERSION = 11` |

## Design (recommended)

Keep base `emission_params` **immutable** at bps=0. Add a single-slot schedule on state:

- `subsidy_bps_activation_height: u32` — `0` = inactive
- `subsidy_bps_activation_value: u16` — ignored when height is `0`; B-13c sets `1000`

Helper in `mfn-consensus` emission module:

```rust
fn effective_emission_params(state: &ChainState, height: u32) -> EmissionParams
```

- Copy `state.emission_params`
- If activation height is non-zero and `height >= H_act`, overlay
  `subsidy_to_treasury_bps = subsidy_bps_activation_value`
- Else leave base (Path A: 0)

**Reject:** mutating base `emission_params` inside `apply_block` at `H_act`
(breaks tip-state fraud recompute for heights below `H_act`).
**Reject:** general multi-row fork table for this one lever.

### apply_block / producer / fraud

In `mfn-consensus/src/block/apply.rs`, coinbase/treasury settlement must use
`effective_emission_params(&next, block.header.height)` (not raw
`next.emission_params`) for:

- fee to treasury share (same source of truth; fee bps unchanged)
- `subsidy_treasury_credit`
- `block_coinbase_specs` / producer coinbase

Producer seal paths in `mfn-node` / `mfn-runtime` must mirror the helper at the
proposed height or blocks fail `CoinbaseInvalid`.

Fraud verifiers (`verify_coinbase_amount_fraud_proof`,
`verify_interactive_fraud_proof`) must take **effective** params for
`proof.block.header.height`.

### Checkpoint v12

| Item | Action |
| --- | --- |
| `CHAIN_CHECKPOINT_VERSION` | 11 to **12** |
| Encode | `u32` height + `u16` bps (orthogonal to base emission blob) |
| Decode | v12: read both; v11 and below: default `0,0` then optional known-chain inject |
| Tests | round-trip in `chain_checkpoint/tests.rs` |

### Path A arming (B-13c — not this unit)

Tall-tip nodes restore v11 checkpoints with no schedule. B-13c needs a
**known-chain schedule table** keyed by `genesis_id` (empty until enable):

`PATH_A_SUBSIDY_ACTIVATION: { genesis_id, H_act, bps: 1000 }`

Inject on decode (v11 to v12 defaults) and at genesis apply when schedule is
inactive and `genesis_id` matches. Choose `H_act` well above current tip so all
upgraded nodes agree before the boundary.

Optional: genesis JSON schedule section for fresh/wipe nets (B-265 style).
Never change `DEFAULT_EMISSION_PARAMS`.

## genesis_id / constitution

- Keep Path A `genesis_id` (same-chain).
- Validate **base** emission via constitution; also validate post-activation
  overlay with `validate_emission_params`. **B-268e:** checkpoint decode
  refuses `activation_value > 10000` (chain v12 + light v2).
- One lever only: schedule may change `subsidy_to_treasury_bps`; keep
  `fee_to_treasury_bps = 9000` (**B-20** later).

## Test plan (impl follow-on)

In `mfn-consensus/tests/emission_simulation.rs` (plus a small `apply_block` unit):

1. Boundary identity — base bps=0, `H_act = N`: pre-N matches bps=0; at N first
   subsidy treasury credit; producer coinbase drops by that credit; total mint
   (producer + treasury tranche) unchanged.
2. Fee-drought across boundary — B-13a-style inequality holds post-`H_act`.
3. Checkpoint v12 round-trip + v11 defaults.
4. Fraud/coinbase wrong-era bps fails.
5. Pin `DEFAULT_EMISSION_PARAMS.subsidy_to_treasury_bps == 0` and Path A JSON
   omits `emission` (B-265).

## Explicit non-goals (B-268)

- No **B-13c** enable / no live `H_act` / no OPERATORS announce
- No `DEFAULT_EMISSION_PARAMS` change
- No `fee_to_treasury_bps` change
- No new `genesis_id` / Path B ceremony / wipe
- No multi-parameter governance fork engine
- No rewriting historical blocks

## Sequencing

| Step | Lane | Deliverable |
| --- | --- | --- |
| **B-268** design | 6 | this doc |
| **B-268b** impl | 6 (+4 review) | helper + state + ckpt v12 + sims; wire `apply_block` |
| Human **B-13b** | human | affirm same-chain + activation |
| **B-13c** | 7 + human | set Path A table `H_act` above tip; roll mfnd; announce; B-28 `--mode post` |

## Call-site inventory (for lane 4 Ack / B-268b)

Exact sites that must use `effective_emission_params(state, height)` (or an
equivalent height-aware `&EmissionParams`) once the helper exists. Surveyed
2026-08-06 against tip `463b556d`.

### Consensus — must switch

| File | Site | Notes |
| --- | --- | --- |
| `mfn-consensus/src/block/apply.rs` | ~478, ~485 | fee→treasury using `next.emission_params.fee_to_treasury_bps` |
| `mfn-consensus/src/block/apply.rs` | ~740 | emission passed into slash/evidence path |
| `mfn-consensus/src/block/apply.rs` | ~1069–1115 | settlement: `treasury_fee`, `subsidy_treasury_credit`, `block_coinbase_specs` |
| `mfn-consensus/src/fraud_proof.rs` | `verify_coinbase_amount_fraud_proof` / interactive verify | callers pass **effective** params for *contested* `proof.block.header.height` (**B-268c**) |
| `mfn-consensus/src/slashing.rs` | `verify_invalid_block_evidence` | `SubsidyBpsSchedule.effective(base, evidence.height)` — not applying-block overlay |
| `mfn-node/src/p2p_gossip.rs` | `on_fraud_proof_v1` | `chain.state().effective_emission_params(contested_height)` — not `DEFAULT` |
| `mfn-light/src/chain.rs` | `apply_block` / `apply_trusted_evolution` | **B-268d:** genesis `emission_params` + stored schedule — not `DEFAULT` |
| `mfn-light/src/checkpoint.rs` | encode/decode | **B-268d:** `LIGHT_CHECKPOINT_VERSION` 1→2; persist schedule; v1 → `(0,0)` |

### Producer seal — must mirror apply_block

| File | Site | Notes |
| --- | --- | --- |
| `mfn-node/src/runner.rs` | ~176–212 | `chain.state().emission_params` → `block_coinbase_specs` |
| `mfn-node/src/mfnd_cli.rs` | ~255–291 | same pattern for CLI produce path |

Mismatch between seal and `apply_block` → `CoinbaseInvalid` after `H_act`.

### State / checkpoint — B-268b scaffold

| File | Change |
| --- | --- |
| `mfn-consensus/src/block/state.rs` | add `subsidy_bps_activation_height` / `subsidy_bps_activation_value` (default `0`) |
| `mfn-consensus/src/emission.rs` | add `effective_emission_params` + unit tests (boundary at `H_act`) |
| `mfn-consensus/src/chain_checkpoint/mod.rs` | `CHAIN_CHECKPOINT_VERSION` 11 → 12 |
| `mfn-consensus/src/chain_checkpoint/{encode,decode}.rs` | write/read schedule; v≤11 → `(0,0)` |
| `mfn-consensus/tests/emission_simulation.rs` | boundary + fee-drought-across-activation cases |

### Explicitly out of scope for first land

- Mutating `DEFAULT_EMISSION_PARAMS`
- Arming Path A `PATH_A_SUBSIDY_ACTIVATION` table (**B-13c**)
- Changing `fee_to_treasury_bps`
- `p2p_fanout` / `p2p_gossip` / `archive_export` test fixtures that hardcode
  `DEFAULT_EMISSION_PARAMS` (fine until a test needs post-`H_act` economics)

## One-line summary

Same-chain enable = keep base `emission_params` at bps=0, add checkpointed (v12)
activation `(H_act, 1000)`, compute coinbase/treasury via
`effective_emission_params(state, height)` — never by DEFAULT or historical rewrite.

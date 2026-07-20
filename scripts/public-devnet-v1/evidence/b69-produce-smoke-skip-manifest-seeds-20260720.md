# B-69 — produce-smoke seed isolation (2026-07-20)

## Failure

CI `#29728151679` (B-66 head `cb8f8f3`) **RED** on `windows-latest` only:
`public_devnet_hub_reaches_height_one_within_one_slot_duration` timed out with tips ~700+ and
`saw_sealed=false` — the local mesh dialed published `seed_nodes` and synced the live Hetzner tip.

## Fix

Set `MFN_SKIP_MANIFEST_SEEDS=1` in `spawn_produce_validator` for:
- `mfn-node/tests/three_validator_produce_smoke.rs`
- `mfn-node/tests/three_validator_all_produce_smoke.rs`

Completes **B-29** isolation for default (non-Nightly) GHA produce smokes. Same knob as `start-all` local mesh.
# CI and local verification

GitHub Actions workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)

## Run the same checks locally

```bash
bash scripts/ci-check.sh
```

```powershell
powershell -File scripts/ci-check.ps1
```

This runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features`, `cargo build -p mfn-node --bin mfnd --release`, and `cargo test --workspace --release` with `RUSTFLAGS=-D warnings`, matching CI.

Integration tests in `mfn-cli` spawn the `mfnd` binary; CI must build it explicitly before `cargo test --release`.

## Inspect GitHub failures (no copy-paste)

Requires [GitHub CLI](https://cli.github.com/) and `gh auth login`.

```bash
gh run list --workflow CI --limit 5
gh run view <run-id> --log-failed
```

On Windows:

```powershell
powershell -File scripts/gh-ci-failed.ps1
```

## Why recent pushes failed

Several `main` commits failed **rustfmt** only: code was pushed without `cargo fmt --all`. Clippy and tests were not reached on those runs. Always format before push.

## Slow integration tests (ignored in CI)

Some `mfn-node` tests spawn multi-process `mfnd serve` + P2P block-sync or three-validator `--produce` harnesses. They are marked `#[ignore]` so default CI finishes in minutes instead of hanging on runner networking.

Run them locally before changing P2P or production (stdout readers use bounded timeouts — **M2.3.27**):

```bash
bash scripts/ci-ignored.sh
```

```powershell
powershell -File scripts/ci-ignored.ps1
```

Or directly:

```bash
cargo test -p mfn-node --release -- --ignored --test-threads=1
```

**Nightly:** [`.github/workflows/nightly.yml`](../.github/workflows/nightly.yml) runs the same ignored suite daily on `ubuntu-latest` (60 min cap), plus `mfn-consensus` long emission/`apply_block` sims (`emission_simulation` and `apply_block_proptest` test targets, `--ignored`).

**Emission / treasury (M5.0–M5.7):** default CI runs `mfn-consensus/tests/emission_simulation.rs` (100k-height curve + 10k empty blocks + 512-block storage-proof ledger + validator CLSAG/mixed fee chains + liveness-slash/combined-inflow treasury ledgers). Longer sims, including 64/256-block combined-inflow runs, are `#[ignore]` (nightly).

**Producer treasury settlement (M5 economics):** default CI runs `mfn-consensus/tests/producer_treasury_settlement.rs` — 90/10 fee split, coinbase = emission + producer fee share + storage rewards (+ PPB bonus), treasury drain vs emission backstop, invalid/overpaid coinbase reject without state change, bond burn + fee inflow (`f117ce6`), slash + fee + proof + PPB carry-over (`13616bc`), liveness/bond/combined-inflow treasury loops (`ffe93d5`, `cbecb3b`, `5a8fb83`, `40bfb57`), and five-path equivocation + bond + liveness + fee + proof composition (`dde886e`).

**Validator finality evolution (M5 consensus):** default CI runs `mfn-consensus/tests/validator_finality_evolution.rs` — pre-block `validator_root` / quorum semantics, liveness bitmap + stats atomicity on accept vs reject, bond-root / **slashing_root** / **tx_root** / **storage_proof_root** mismatch reject without state change, validator-root movement on liveness/equivocation slash, **equivocation during unbond delay still zeros stake**, **unbond delay preserves `validator_root`**, **settlement moves successor root**, invalid slash evidence reject without state change, and exit-churn cap deferral (`a97242a`, `267658d`, `4715544`, `b50662f`). `tests/integration.rs` now also covers legacy mixed CLSAG fee + SPoRA forward apply plus two-block treasury identity (`ba04799`, `6422d1a`), validator mixed CLSAG fee + SPoRA forward apply, and validator two-block treasury identity (`30b35c0`, `2063202`).

**SPoRA binding + payout (M5 storage):** default CI runs cases in `mfn-consensus/tests/block_apply.rs` — emit-order `storage_proof_root`, tampered root rejects before payout effects, provenance + treasury on accept, unknown commit / wrong chunk / duplicate proof rejects (`4e8ac41`); **dual distinct proofs payout both entries**, **body tamper rejects without state change** (`9e5c129`); positive-yield dual-proof accrual and `proof_reward_window` cap at `apply_block` (`8d436c9`, `e310435`).

**apply_block proptest (M5.2–M5.8):** default CI runs `mfn-consensus/tests/apply_block_proptest.rs` — 32-case `proptest!` props for empty chains, header tamper rejects (state unchanged), storage-proof chains, alternating empty+SPoRA pairs, bond-register + SPoRA treasury ledger identity, legacy and validator-mode mixed CLSAG fee + SPoRA same-block treasury (`prop_validator_mixed_clsag_fee_and_storage_proof_treasury`, **M5.6**), bond inflow + randomized CLSAG fees + SPoRA outflow (`prop_bond_inflow_random_fee_and_proof_outflow_treasury`, **M5.7**, `dde886e`), and validator combined-inflow randomized fee treasury identity (`prop_validator_combined_inflow_random_fee_treasury`, **M5.8**, `a858e54`); plain `#[test]` for forged-register, duplicate-proof, mixed-block duplicate-proof rollback (`5c5975f`, `dd76d7f`), **legacy mixed reject matrix** — tampered `storage_proof_root`, invalid CLSAG, reject-after-partial-chain preserves tip (`reject_mixed_*_without_state_change`, `0574d69`, `013bf47`), and **M5.6+ validator-mixed reject matrix** — tampered `storage_proof_root`, invalid coinbase, subquorum finality, invalid CLSAG, reject-after-partial-chain preserves tip (`reject_validator_mixed_*_without_state_change`, `prop_reject_after_partial_chain`, `4b82b4c`, `c9db77e`). Deep chains are `#[ignore]` (nightly).

## Why recent pushes failed (tests)

- **`claim_smoke`**: `mfnd serve` must persist `mempool.bytes` on `submit_tx` (fixed in `fix(mfnd): persist mempool on Fresh submit_tx admit`).
- **Hung CI jobs**: unbounded stdout waits in P2P sync tests — now `#[ignore]` in default `cargo test`.

# CI and local verification

GitHub Actions workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)

Manual re-run: **Actions → CI → Run workflow** on `main` (requires `workflow_dispatch`, M2.4.81).

## Run the same checks locally

```bash
bash scripts/ci-check.sh
```

```powershell
powershell -File scripts/ci-check.ps1
```

This runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features`, `cargo build -p mfn-node --bin mfnd --release`, and `cargo test --workspace --release` with `RUSTFLAGS=-D warnings`, matching CI.

**RC helper script smoke (M2.5.24 / M2.5.28):** After workflow UTF-8 validation, ci-check runs [scripts/validate-rc-helper-scripts.ps1](../scripts/validate-rc-helper-scripts.ps1) (and [.sh](../scripts/validate-rc-helper-scripts.sh) on Linux/macOS) to fail closed on UTF-16 RC helpers under `scripts/public-devnet-v1/`, PowerShell parse errors, `bash -n` syntax errors, **agent boards** (`AGENTS.md`, `docs/AGENTS.md`, `3agent.md`), **`docs/STORAGE_ACCESSIBILITY.md`**, and ci-check entrypoint scripts.

Integration tests in `mfn-cli` spawn the `mfnd` binary; CI must build it explicitly before `cargo test --release`.

The public-devnet script checks install `scripts/public-devnet-v1/requirements-release-schema.txt` with `pip --require-hashes` and run the pinned `jsonschema==4.17.3` Draft 2020-12 validator in addition to the dependency-free release-schema validator. A hash mismatch or installed `jsonschema` version mismatch is a release-toolchain failure, not a warning.

Participant rehearsal automation policy: `release-participant-smoke-policy-check.ps1` / `release-participant-smoke-policy-check.sh` fail closed if `.github/workflows/ci.yml` or the local `ci-check` mirrors invoke `participant-rehearsal` / `participant-rehearsal-smoke` without `--plan-only` / `-PlanOnly`. Default CI may validate helper plans and synthetic audit-packet fixtures only. Real-run mesh smokes run in [`.github/workflows/nightly.yml`](../.github/workflows/nightly.yml) and `scripts/ci-ignored.{sh,ps1}` after soak green and Agent 2/3 sign-off (M2.4.67).

## Inspect GitHub failures (no copy-paste)

Requires [GitHub CLI](https://cli.github.com/) and `gh auth login` for direct `gh run` inspection. Exact-commit release polling can also use `GH_TOKEN` / `GITHUB_TOKEN` through `release-ci-watch.ps1` or `release-ci-watch.sh`.

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

Run them locally before changing P2P or production (stdout readers use bounded timeouts â€” **M2.3.27**):

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

**Nightly:** [`.github/workflows/nightly.yml`](../.github/workflows/nightly.yml) runs the same ignored suite daily on `ubuntu-latest` (60 min cap), plus `mfn-consensus` long emission/`apply_block` sims (`emission_simulation` and `apply_block_proptest` test targets, `--ignored`), and real-run `participant-rehearsal-smoke.sh` jobs (10s mesh + observer catch-up; both pass `--archive-evidence`).

**RC Validation After CI (M2.4.77, M2.5.18):** Green **push** CI on `main` auto-dispatches **Nightly** via the `dispatch-nightly-rc` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) with `ref: main` and `inputs.checkout_sha` set to the exact passing commit (**M2.4.83** — GitHub rejects raw commit SHAs as dispatch refs). [`.github/workflows/rc-validation-after-ci.yml`](../.github/workflows/rc-validation-after-ci.yml) remains for **manual** operator re-dispatch (`workflow_dispatch` + optional `ci_head_sha`). Manual **Nightly** dispatch also via `dispatch-rc-workflows.ps1 -Nightly` or Actions UI.

**Linux Soak Audit (M2.4.74, B-05):** [`.github/workflows/linux-soak-audit.yml`](../.github/workflows/linux-soak-audit.yml) — manual `workflow_dispatch` or **auto-dispatch** via `dispatch-linux-soak-rc` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) when no `soak-restart-linux-30s-slot-*.txt` is archived on `main`. 35 min 30s-slot soak with observer restart; artifact upload; PASS transcripts auto-commit with `[skip ci]`. Import fallback: [`import-linux-soak-artifact.ps1`](../scripts/public-devnet-v1/import-linux-soak-artifact.ps1) / [`import-linux-soak-artifact.sh`](../scripts/public-devnet-v1/import-linux-soak-artifact.sh).

**CI Queue Cleanup (M2.4.75):** [`.github/workflows/ci-queue-cleanup.yml`](../.github/workflows/ci-queue-cleanup.yml) cancels stale CI runs on push to reduce runner backlog, but **preserves CI for the triggering commit** (`context.sha`) so the matrix under test is not cancelled (**M2.4.82**). Do not push follow-up commits while CI is in progress — concurrency `cancel-in-progress` aborts the prior matrix.

**Linux test hardening (M2.4.89):** GitHub **CI** runs workspace release tests with `--test-threads=2` on `ubuntu-latest` (4 on macOS/Windows) and retries once after 15s on failure. `mfn-node/tests/stdout_timeout.rs` uses longer GHA deadlines for `mfnd_serve_listening=` (120s) and P2P line prefixes (150s).

**Local CI mirror thread cap (M2.4.90):** `scripts/ci-check.sh` and `scripts/ci-check.ps1` both use `--test-threads=2` on all platforms so heavy M5.36–M5.45 proptest/emission sims do not OOM during local mirrors (Windows was crashing at 4 threads after `8e6b3c1`).

**Workflow UTF-8 guard (M2.4.79):** `scripts/validate-workflow-encoding.{sh,ps1}` runs in local CI mirror and GitHub **CI** scripts job — GitHub Actions rejects UTF-16 workflow YAML.

**Agent board UTF-8 guard (M2.5.26):** `validate-workflow-encoding` also checks `AGENTS.md`, `docs/AGENTS.md`, and `3agent.md` for UTF-16 BOM or null-byte corruption so parallel agent boards stay readable and diffable.

**Agent board UTF-8 guard (M2.5.26, M2.5.27):** the same scripts also fail closed on UTF-16/null-byte corruption in `AGENTS.md`, `docs/AGENTS.md`, `3agent.md`, and `docs/STORAGE_ACCESSIBILITY.md`. M2.5.27 restored `docs/AGENTS.md` to per-lane checklists (it must not duplicate the master board).

**Emission / treasury (M5.0–M5.48):** default CI runs `mfn-consensus/tests/emission_simulation.rs` (100k-height curve + **1M-height curve (M5.47)** + 10k empty blocks + 512-block storage-proof ledger + validator CLSAG/mixed fee chains including **96-block validator CLSAG-only (M5.35)** and **64-block validator mixed CLSAG+SPoRA (M5.34/B-03)** + **384-block legacy mixed fee+proof ledger (M5.39)** + **64-block combined-inflow + PPB + equivocation-PPB combined-inflow ledgers (M5.40)** + **128-block PPB + equivocation combined-inflow ledgers (M5.41)** + **256-block combined-inflow ledger (M5.42)** + **256-block PPB combined-inflow ledger (M5.43)** + **512-block combined-inflow + PPB + equivocation combined-inflow ledgers (M5.44/M5.45)** + **256-block equivocation combined-inflow ledgers (M5.47)** + liveness-slash/combined-inflow treasury ledgers, including 32/64-block equivocation combined-inflow, prefunded treasury backstop coverage, and 16/32-block no-equivocation PPB combined-inflow coverage). **M5.48:** emission `apply_block` deep-sim tier closure — 38 default + 2 nightly `#[ignore]` (2048-block CLSAG fee mix ~13m release; 100k empty `apply_block` ~7m release).

**Producer treasury settlement (M5 economics):** default CI runs `mfn-consensus/tests/producer_treasury_settlement.rs` â€” 90/10 fee split, coinbase = emission + producer fee share + storage rewards (+ PPB bonus), treasury drain vs emission backstop, invalid/overpaid coinbase reject without state change, bond burn + fee inflow (`f117ce6`), slash + fee + proof + PPB carry-over (`13616bc`), liveness/bond/combined-inflow treasury loops (`ffe93d5`, `cbecb3b`, `5a8fb83`, `40bfb57`), five-path equivocation + bond + liveness + fee + proof composition (`dde886e`), bond + liveness + fee + PPB-augmented storage proof composition (`1279cee`), and six-path equivocation + bond + liveness + fee + PPB proof-drain composition (`c880d27`).

**Validator finality evolution (M5 consensus):** default CI runs `mfn-consensus/tests/validator_finality_evolution.rs` â€” pre-block `validator_root` / quorum semantics, liveness bitmap + stats atomicity on accept vs reject, bond-root / **slashing_root** / **tx_root** / **storage_proof_root** / **claims_root** / **storage_root** / **utxo_root** mismatch reject without state change, validator-root movement on liveness/equivocation slash, **equivocation during unbond delay still zeros stake**, **unbond delay preserves `validator_root`**, **settlement moves successor root**, invalid/duplicate slash evidence reject without state change, exit-churn cap deferral/reset, entry-churn cap reject/accept/reset, bond rejection preserving treasury, and bond-op admission rejects for duplicate VRF registration, duplicate unbond enqueue, duplicate unbond after pending exit, below-minimum stake, same-block register-then-unbond, forged/unknown/zombie unbond, and same-block duplicate VRF (`a97242a`, `267658d`, `4715544`, `b50662f`, `7452127`, `ce851f8`, `e10b249`, `ebfa7b0`, `9556053`). `tests/integration.rs` now also covers legacy mixed CLSAG fee + SPoRA forward apply plus two-block treasury identity and legacy tampered-CLSAG / tampered-`storage_proof_root` / duplicate-SPoRA-proof rollback after prior valid history (`ba04799`, `6422d1a`, `d99d424`, `71350e4`, `925561a`), validator mixed CLSAG fee + SPoRA forward apply, validator two-block treasury identity (`30b35c0`, `2063202`), validator-mixed tampered-CLSAG rollback after a prior valid block (`56a53f3`), validator-mixed tampered-`storage_proof_root` rollback after prior valid history (`302f3b7`), validator-mixed invalid-coinbase rollback after prior valid history (`e07d526`), validator-mixed sub-quorum finality rollback after prior valid history (`a09b48c`), and validator-mixed duplicate-SPoRA-proof rollback after prior valid history (`925561a`).

**SPoRA binding + payout (M5 storage):** default CI runs cases in `mfn-consensus/tests/block_apply.rs` â€” emit-order `storage_proof_root`, tampered root rejects before payout effects, provenance + treasury on accept, unknown commit / wrong chunk / duplicate proof rejects (`4e8ac41`); **dual distinct proofs payout both entries**, **body tamper rejects without state change** (`9e5c129`); positive-yield dual-proof accrual and `proof_reward_window` cap at `apply_block` (`8d436c9`, `e310435`).

**apply_block proptest (M5.2–M5.39):** default CI runs `mfn-consensus/tests/apply_block_proptest.rs` — 32-case `proptest!` props for empty chains, header tamper rejects (state unchanged), storage-proof chains, alternating empty+SPoRA pairs, bond-register + SPoRA treasury ledger identity, legacy and validator-mode mixed CLSAG fee + SPoRA same-block treasury (`prop_validator_mixed_clsag_fee_and_storage_proof_treasury`, **M5.6**), bond inflow + randomized CLSAG fees + SPoRA outflow (`prop_bond_inflow_random_fee_and_proof_outflow_treasury`, **M5.7**, `dde886e`), validator combined-inflow randomized fee treasury identity (`prop_validator_combined_inflow_random_fee_treasury`, **M5.8**, `a858e54`), validator equivocation combined-inflow random-fee treasury identity (`prop_validator_equivocation_combined_inflow_random_fee_treasury`, `1ae43ca`), validator combined-inflow random-schedule treasury identity (`prop_validator_combined_inflow_random_schedule_treasury`, **M5.16**, `e9d1c44`), validator combined-inflow random-schedule **no-equivocation** treasury identity (`prop_validator_combined_inflow_random_schedule_no_equivocation_treasury`, **M5.17**, `cf06280`), **M5.33** mixed CLSAG fee + NEW storage upload same-block treasury (`prop_mixed_clsag_fee_and_storage_upload_treasury`), **M5.38** 64-block deep upload chain (`deep_mixed_clsag_fee_and_storage_upload_treasury_64`; **M5.35**), **M5.36** 64-block deep CLSAG+SPoRA chain (`deep_mixed_clsag_fee_and_storage_proof_treasury_64`), **M5.37** 128-block empty chain + 32-block SPoRA proof chain + 32-block validator mixed CLSAG+SPoRA treasury chain (`deep_empty_block_chain_128`, `deep_storage_proof_chain_32`, `deep_validator_mixed_clsag_fee_and_storage_proof_treasury_32`), and **M5.39** alternating bond-register + SPoRA treasury chain through epoch churn cap (`deep_alternating_register_storage_treasury_8`); plain `#[test]` for forged-register, duplicate-proof, mixed-block duplicate-proof rollback (`5c5975f`, `dd76d7f`), **legacy mixed reject matrix** — tampered `storage_proof_root`, invalid CLSAG, reject-after-partial-chain preserves tip (`reject_mixed_*_without_state_change`, `0574d69`, `013bf47`), and **M5.6+ validator-mixed reject matrix** — tampered `storage_proof_root`, invalid coinbase, subquorum finality, invalid CLSAG, reject-after-partial-chain preserves tip (`reject_validator_mixed_*_without_state_change`, `prop_reject_after_partial_chain`, `4b82b4c`, `c9db77e`). All deep proptest chains are in default CI (no `#[ignore]` in this target).

## Why recent pushes failed (tests)

- **`claim_smoke`**: `mfnd serve` must persist `mempool.bytes` on `submit_tx` (fixed in `fix(mfnd): persist mempool on Fresh submit_tx admit`).
- **Hung CI jobs**: unbounded stdout waits in P2P sync tests â€” now `#[ignore]` in default `cargo test`.

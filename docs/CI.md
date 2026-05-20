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

**Emission / treasury (M5.0–M5.3):** default CI runs `mfn-consensus/tests/emission_simulation.rs` (100k-height curve + 10k empty blocks + 512-block storage-proof ledger + 16-block validator CLSAG fee chain with coinbase decrypt + 12-block validator mixed fee+proof with coinbase decrypt + 128-block legacy CLSAG fee chain + 48-block legacy mixed blocks). Longer sims are `#[ignore]` (nightly).

**apply_block proptest (M5.2 / M5.2+ / M5.2++):** default CI runs `mfn-consensus/tests/apply_block_proptest.rs` (32-case `proptest!` for empty chains, header tamper rejects, storage-proof chains, alternating empty+SPoRA pairs, multi-register bond ops in one block; plain `#[test]` for forged-register and duplicate-proof rejects — avoids `proptest!` `$body:block` brace limits). Deep chains are `#[ignore]`.

## Why recent pushes failed (tests)

- **`claim_smoke`**: `mfnd serve` must persist `mempool.bytes` on `submit_tx` (fixed in `fix(mfnd): persist mempool on Fresh submit_tx admit`).
- **Hung CI jobs**: unbounded stdout waits in P2P sync tests — now `#[ignore]` in default `cargo test`.

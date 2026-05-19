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

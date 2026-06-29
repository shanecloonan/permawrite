# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-06-29T00:27:16.740Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 305 |
| Total lines (all scanned source-like files) | 96,205 |
| Non-empty lines | 86,101 |
| UTF-8 bytes (source-like) | 3,899,364 |
| Paths visited (before binary/huge skip) | 324 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 58 | 23,980 | 22,355 |
| `mfn-cli` | 29 | 11,372 | 10,477 |
| `docs` | 36 | 10,878 | 7,710 |
| `mfn-node` | 34 | 8,828 | 8,187 |
| `mfn-crypto` | 23 | 7,292 | 6,565 |
| `mfn-wallet` | 15 | 4,931 | 4,522 |
| `mfn-runtime` | 14 | 4,323 | 4,001 |
| `mfn-light` | 6 | 3,895 | 3,556 |
| `mfn-net` | 11 | 3,573 | 3,274 |
| `mfn-rpc` | 4 | 3,565 | 3,384 |
| `mfn-storage-operator` | 14 | 2,679 | 2,453 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-wasm` | 10 | 2,029 | 1,845 |
| `mfn-storage` | 6 | 2,006 | 1,822 |
| `mfn-store` | 12 | 1,814 | 1,573 |
| `mfn-bls` | 4 | 865 | 757 |
| `scripts` | 10 | 802 | 654 |
| `(root)` | 5 | 739 | 530 |
| `.github` | 2 | 156 | 144 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 202 | 78,793 | 72,920 | 2,871,052 |
| `.md` | 52 | 12,985 | 9,149 | 871,979 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.mjs` | 5 | 697 | 609 | 19,633 |
| `.toml` | 15 | 522 | 439 | 14,676 |
| `.svg` | 3 | 520 | 462 | 35,170 |
| `.sh` | 8 | 287 | 268 | 10,121 |
| `.json` | 11 | 265 | 254 | 7,812 |
| `.yml` | 2 | 156 | 144 | 4,823 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,493 | `mfn-rpc/src/dispatch.rs` |
| 3,029 | `mfn-consensus/tests/integration.rs` |
| 2,394 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 2,290 | `mfn-consensus/tests/block_apply.rs` |
| 2,267 | `docs/ROADMAP.md` |
| 1,952 | `mfn-node/tests/mfnd_smoke.rs` |
| 1,916 | `mfn-cli/src/cli.rs` |
| 1,730 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 1,634 | `mfn-light/src/chain.rs` |
| 1,551 | `mfn-runtime/src/mempool.rs` |
| 1,465 | `mfn-consensus/tests/validator_finality_evolution.rs` |
| 1,372 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,089 | `mfn-light/tests/follow_chain.rs` |
| 986 | `mfn-wallet/src/upload.rs` |
| 982 | `mfn-wallet/src/wallet.rs` |
| 972 | `mfn-node/src/mfnd_cli.rs` |
| 959 | `docs/ARCHITECTURE.md` |
| 921 | `mfn-consensus/src/consensus/engine.rs` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 816 | `mfn-light/src/checkpoint.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

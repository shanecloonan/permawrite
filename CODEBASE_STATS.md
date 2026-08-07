# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-08-07T09:54:27.778Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 1,436 |
| Total lines (all scanned source-like files) | 309,560 |
| Non-empty lines | 283,512 |
| UTF-8 bytes (source-like) | 12,780,498 |
| Paths visited (before binary/huge skip) | 2,260 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 346 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 74 | 135,484 | 129,505 |
| `scripts` | 976 | 59,737 | 53,157 |
| `docs` | 82 | 22,670 | 16,591 |
| `mfn-node` | 41 | 16,014 | 14,847 |
| `mfn-cli` | 33 | 15,979 | 14,778 |
| `mfn-crypto` | 23 | 7,526 | 6,779 |
| `mfn-wallet` | 17 | 6,830 | 6,320 |
| `mfn-net` | 18 | 6,642 | 6,077 |
| `mfn-runtime` | 15 | 5,750 | 5,348 |
| `testnet-frontend` | 29 | 5,126 | 4,731 |
| `mfn-rpc` | 6 | 4,268 | 4,059 |
| `mfn-light` | 6 | 3,991 | 3,645 |
| `mfn-storage-operator` | 15 | 3,389 | 3,118 |
| `mfn-storage` | 6 | 2,990 | 2,755 |
| `mfn-wasm` | 12 | 2,869 | 2,636 |
| `demo` | 12 | 2,528 | 2,338 |
| `mfn-store` | 13 | 2,295 | 2,004 |
| `.github` | 6 | 1,989 | 1,928 |
| `(root)` | 8 | 1,479 | 1,072 |
| `mfn-bls` | 4 | 865 | 757 |
| `mfn-checkpoint-log` | 4 | 707 | 642 |
| `live-testnet-data` | 19 | 276 | 269 |
| `live-testnet-data-divergent-20260720-113211` | 4 | 39 | 39 |
| `live-testnet-data-divergent-20260719-234040` | 4 | 38 | 38 |
| `live-testnet-data-divergent-20260720-033906` | 1 | 9 | 9 |
| `live-testnet-data-divergent-20260720-124203` | 1 | 9 | 9 |
| `live-testnet-data-divergent-20260720-131817` | 1 | 9 | 9 |
| `live-testnet-data-divergent-wave101-20260723-101433` | 1 | 9 | 9 |
| `live-testnet-data-divergent-wave109-20260723-151109` | 1 | 9 | 9 |
| `live-testnet-data-divergent-wave110-20260723-153939` | 1 | 9 | 9 |
| `live-testnet-data-divergent-wave115resume-20260728-234343` | 1 | 9 | 9 |
| `live-testnet-data-divergent-20260720-154342` | 1 | 8 | 8 |
| `live-testnet-data-divergent-wave105-20260723-115958` | 1 | 8 | 8 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 247 | 213,073 | 201,288 | 8,024,449 |
| `.md` | 436 | 40,291 | 28,793 | 2,316,259 |
| `.json` | 524 | 26,509 | 26,224 | 1,341,530 |
| `.sh` | 165 | 17,257 | 15,665 | 631,413 |
| `.js` | 8 | 3,057 | 2,865 | 101,211 |
| `.tsx` | 9 | 2,230 | 2,095 | 78,629 |
| `.mjs` | 8 | 2,213 | 2,038 | 66,307 |
| `.yml` | 7 | 1,992 | 1,930 | 103,773 |
| `.ts` | 12 | 1,660 | 1,500 | 53,933 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 16 | 586 | 495 | 16,975 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 100,489 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 4,958 | `mfn-consensus/tests/integration.rs` |
| 3,885 | `mfn-consensus/tests/block_apply.rs` |
| 3,493 | `mfn-rpc/src/dispatch.rs` |
| 3,248 | `docs/ROADMAP.md` |
| 2,700 | `scripts/public-devnet-v1/user-wallet/validator0-faucet.json` |
| 2,566 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,392 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,326 | `mfn-consensus/tests/emission_simulation.rs` |
| 2,113 | `mfn-runtime/src/mempool.rs` |
| 2,067 | `mfn-cli/src/cli/parse.rs` |
| 2,012 | `mfn-node/src/p2p_fanout.rs` |
| 1,649 | `mfn-light/src/chain.rs` |
| 1,585 | `mfn-consensus/src/fraud_proof.rs` |
| 1,494 | `mfn-cli/src/cli.rs` |
| 1,490 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,426 | `.github/workflows/ci.yml` |
| 1,420 | `mfn-cli/src/wallet_cmd.rs` |
| 1,333 | `docs/F5.md` |
| 1,321 | `mfn-node/src/mfnd_serve.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

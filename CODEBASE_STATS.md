# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-20T23:01:16.585Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 1,101 |
| Total lines (all scanned source-like files) | 199,811 |
| Non-empty lines | 178,649 |
| UTF-8 bytes (source-like) | 8,379,265 |
| Paths visited (before binary/huge skip) | 1,638 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 200 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `scripts` | 640 | 42,091 | 37,335 |
| `mfn-consensus` | 74 | 40,225 | 37,827 |
| `docs` | 80 | 24,076 | 17,595 |
| `mfn-node` | 41 | 16,008 | 14,841 |
| `mfn-cli` | 32 | 15,366 | 14,217 |
| `mfn-crypto` | 23 | 7,526 | 6,779 |
| `mfn-net` | 18 | 6,642 | 6,077 |
| `mfn-wallet` | 16 | 6,212 | 5,731 |
| `mfn-runtime` | 15 | 5,679 | 5,281 |
| `testnet-frontend` | 29 | 5,064 | 4,672 |
| `mfn-rpc` | 6 | 4,268 | 4,059 |
| `mfn-light` | 6 | 3,991 | 3,645 |
| `mfn-storage-operator` | 15 | 3,389 | 3,118 |
| `_lane1-wip` | 4 | 3,328 | 3,085 |
| `mfn-storage` | 6 | 2,990 | 2,755 |
| `mfn-wasm` | 12 | 2,680 | 2,451 |
| `demo` | 12 | 2,528 | 2,338 |
| `mfn-store` | 13 | 2,295 | 2,004 |
| `.github` | 6 | 1,989 | 1,928 |
| `(root)` | 12 | 1,379 | 1,017 |
| `mfn-bls` | 4 | 865 | 757 |
| `mfn-checkpoint-log` | 4 | 707 | 642 |
| `_nightly-b29` | 20 | 392 | 374 |
| `live-testnet-data-divergent-20260720-113211` | 4 | 39 | 39 |
| `live-testnet-data-divergent-20260719-234040` | 4 | 38 | 38 |
| `live-testnet-data` | 1 | 9 | 9 |
| `live-testnet-data-divergent-20260720-033906` | 1 | 9 | 9 |
| `live-testnet-data-divergent-20260720-124203` | 1 | 9 | 9 |
| `live-testnet-data-divergent-20260720-131817` | 1 | 9 | 9 |
| `live-testnet-data-divergent-20260720-154342` | 1 | 8 | 8 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 248 | 119,272 | 110,923 | 4,328,776 |
| `.md` | 289 | 36,032 | 25,846 | 2,164,491 |
| `.sh` | 154 | 16,221 | 14,713 | 590,560 |
| `.json` | 346 | 16,114 | 15,873 | 836,933 |
| `.js` | 8 | 3,057 | 2,865 | 101,209 |
| `.tsx` | 9 | 2,230 | 2,095 | 78,629 |
| `.mjs` | 8 | 2,021 | 1,852 | 59,922 |
| `.yml` | 7 | 1,992 | 1,930 | 103,773 |
| `.ts` | 12 | 1,598 | 1,441 | 52,054 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 16 | 582 | 492 | 16,899 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 5,393 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 4,958 | `mfn-consensus/tests/integration.rs` |
| 3,885 | `mfn-consensus/tests/block_apply.rs` |
| 3,493 | `mfn-rpc/src/dispatch.rs` |
| 3,055 | `docs/ROADMAP.md` |
| 2,700 | `scripts/public-devnet-v1/user-wallet/validator0-faucet.json` |
| 2,566 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,392 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,163 | `mfn-consensus/tests/emission_simulation.rs` |
| 2,113 | `mfn-runtime/src/mempool.rs` |
| 2,109 | `docs/AGENTS_LEDGER.md` |
| 2,043 | `mfn-cli/src/cli/parse.rs` |
| 2,012 | `mfn-node/src/p2p_fanout.rs` |
| 2,012 | `_lane1-wip/p2p_fanout.rs` |
| 1,649 | `mfn-light/src/chain.rs` |
| 1,585 | `mfn-consensus/src/fraud_proof.rs` |
| 1,494 | `mfn-cli/src/cli.rs` |
| 1,426 | `.github/workflows/ci.yml` |
| 1,421 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,333 | `docs/F5.md` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

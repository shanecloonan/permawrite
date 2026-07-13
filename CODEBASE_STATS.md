# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-13T22:04:19.692Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 667 |
| Total lines (all scanned source-like files) | 164,322 |
| Non-empty lines | 146,948 |
| UTF-8 bytes (source-like) | 6,701,754 |
| Paths visited (before binary/huge skip) | 879 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 77 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 71 | 37,895 | 35,626 |
| `scripts` | 284 | 20,892 | 18,501 |
| `docs` | 76 | 20,802 | 15,284 |
| `mfn-node` | 41 | 15,618 | 14,472 |
| `mfn-cli` | 32 | 15,467 | 14,313 |
| `mfn-crypto` | 23 | 7,517 | 6,773 |
| `mfn-net` | 17 | 6,461 | 5,909 |
| `mfn-wallet` | 16 | 6,185 | 5,709 |
| `mfn-runtime` | 15 | 5,534 | 5,143 |
| `mfn-rpc` | 6 | 4,154 | 3,947 |
| `mfn-light` | 6 | 3,991 | 3,645 |
| `mfn-storage-operator` | 15 | 3,328 | 3,059 |
| `mfn-storage` | 6 | 2,990 | 2,755 |
| `mfn-wasm` | 12 | 2,678 | 2,450 |
| `demo` | 12 | 2,528 | 2,338 |
| `(root)` | 8 | 2,470 | 1,735 |
| `mfn-store` | 13 | 2,251 | 1,962 |
| `.github` | 6 | 1,989 | 1,928 |
| `mfn-bls` | 4 | 865 | 757 |
| `mfn-checkpoint-log` | 4 | 707 | 642 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 241 | 113,144 | 105,204 | 4,070,067 |
| `.md` | 170 | 27,872 | 20,081 | 1,710,774 |
| `.sh` | 84 | 11,236 | 10,166 | 405,096 |
| `.json` | 133 | 6,068 | 5,938 | 263,421 |
| `.js` | 7 | 2,030 | 1,902 | 65,944 |
| `.yml` | 7 | 1,992 | 1,930 | 103,773 |
| `.mjs` | 5 | 710 | 620 | 19,973 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 16 | 578 | 488 | 16,687 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,958 | `mfn-consensus/tests/integration.rs` |
| 4,389 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 3,865 | `mfn-consensus/tests/block_apply.rs` |
| 3,429 | `mfn-rpc/src/dispatch.rs` |
| 2,523 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,392 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,371 | `docs/ROADMAP.md` |
| 2,163 | `mfn-consensus/tests/emission_simulation.rs` |
| 2,113 | `mfn-runtime/src/mempool.rs` |
| 2,043 | `mfn-cli/src/cli/parse.rs` |
| 1,863 | `mfn-node/src/p2p_fanout.rs` |
| 1,649 | `mfn-light/src/chain.rs` |
| 1,585 | `mfn-consensus/src/fraud_proof.rs` |
| 1,558 | `mfn-cli/src/wallet_cmd.rs` |
| 1,486 | `mfn-cli/src/cli.rs` |
| 1,426 | `.github/workflows/ci.yml` |
| 1,332 | `docs/F5.md` |
| 1,327 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,321 | `mfn-node/src/mfnd_serve.rs` |
| 1,318 | `mfn-storage/src/spora.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

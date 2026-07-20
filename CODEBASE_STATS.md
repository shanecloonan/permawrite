# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-20T04:07:08.102Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 776 |
| Total lines (all scanned source-like files) | 178,796 |
| Non-empty lines | 159,566 |
| UTF-8 bytes (source-like) | 7,330,743 |
| Paths visited (before binary/huge skip) | 1,016 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 79 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 74 | 39,217 | 36,869 |
| `scripts` | 356 | 26,464 | 23,258 |
| `docs` | 79 | 23,916 | 17,505 |
| `mfn-node` | 41 | 15,781 | 14,621 |
| `mfn-cli` | 32 | 15,366 | 14,217 |
| `mfn-crypto` | 23 | 7,526 | 6,779 |
| `mfn-net` | 18 | 6,642 | 6,077 |
| `mfn-wallet` | 16 | 6,212 | 5,731 |
| `mfn-runtime` | 15 | 5,659 | 5,261 |
| `testnet-frontend` | 29 | 5,064 | 4,672 |
| `mfn-rpc` | 6 | 4,268 | 4,059 |
| `mfn-light` | 6 | 3,991 | 3,645 |
| `mfn-storage-operator` | 15 | 3,389 | 3,118 |
| `mfn-storage` | 6 | 2,990 | 2,755 |
| `mfn-wasm` | 12 | 2,680 | 2,451 |
| `demo` | 12 | 2,528 | 2,338 |
| `mfn-store` | 13 | 2,251 | 1,962 |
| `.github` | 6 | 1,989 | 1,928 |
| `(root)` | 9 | 1,291 | 921 |
| `mfn-bls` | 4 | 865 | 757 |
| `mfn-checkpoint-log` | 4 | 707 | 642 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 245 | 115,025 | 106,968 | 4,165,991 |
| `.md` | 202 | 31,499 | 22,665 | 1,933,081 |
| `.sh` | 120 | 13,791 | 12,468 | 498,540 |
| `.json` | 145 | 6,454 | 6,312 | 279,646 |
| `.js` | 8 | 3,057 | 2,865 | 101,209 |
| `.tsx` | 9 | 2,230 | 2,095 | 78,629 |
| `.yml` | 7 | 1,992 | 1,930 | 103,773 |
| `.mjs` | 8 | 1,876 | 1,711 | 54,902 |
| `.ts` | 12 | 1,598 | 1,441 | 52,054 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 16 | 582 | 492 | 16,899 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,958 | `mfn-consensus/tests/integration.rs` |
| 4,389 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 3,885 | `mfn-consensus/tests/block_apply.rs` |
| 3,493 | `mfn-rpc/src/dispatch.rs` |
| 3,020 | `docs/ROADMAP.md` |
| 2,523 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,392 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,163 | `mfn-consensus/tests/emission_simulation.rs` |
| 2,113 | `mfn-runtime/src/mempool.rs` |
| 2,052 | `docs/AGENTS_LEDGER.md` |
| 2,043 | `mfn-cli/src/cli/parse.rs` |
| 1,946 | `mfn-node/src/p2p_fanout.rs` |
| 1,649 | `mfn-light/src/chain.rs` |
| 1,585 | `mfn-consensus/src/fraud_proof.rs` |
| 1,494 | `mfn-cli/src/cli.rs` |
| 1,426 | `.github/workflows/ci.yml` |
| 1,378 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,333 | `docs/F5.md` |
| 1,324 | `mfn-cli/src/wallet_cmd.rs` |
| 1,321 | `mfn-node/src/mfnd_serve.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

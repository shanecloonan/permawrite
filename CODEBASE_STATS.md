# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-20T07:37:32.616Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 852 |
| Total lines (all scanned source-like files) | 184,918 |
| Non-empty lines | 165,207 |
| UTF-8 bytes (source-like) | 7,653,917 |
| Paths visited (before binary/huge skip) | 1,163 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 110 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 74 | 39,589 | 37,226 |
| `scripts` | 426 | 31,983 | 28,335 |
| `docs` | 80 | 23,998 | 17,556 |
| `mfn-node` | 41 | 15,859 | 14,696 |
| `mfn-cli` | 32 | 15,366 | 14,217 |
| `mfn-crypto` | 23 | 7,526 | 6,779 |
| `mfn-net` | 18 | 6,642 | 6,077 |
| `mfn-wallet` | 16 | 6,212 | 5,731 |
| `mfn-runtime` | 15 | 5,679 | 5,281 |
| `testnet-frontend` | 29 | 5,064 | 4,672 |
| `mfn-rpc` | 6 | 4,268 | 4,059 |
| `mfn-light` | 6 | 3,991 | 3,645 |
| `mfn-storage-operator` | 15 | 3,389 | 3,118 |
| `mfn-storage` | 6 | 2,990 | 2,755 |
| `mfn-wasm` | 12 | 2,680 | 2,451 |
| `demo` | 12 | 2,528 | 2,338 |
| `mfn-store` | 13 | 2,251 | 1,962 |
| `.github` | 6 | 1,989 | 1,928 |
| `(root)` | 9 | 1,295 | 935 |
| `mfn-bls` | 4 | 865 | 757 |
| `mfn-checkpoint-log` | 4 | 707 | 642 |
| `live-testnet-data-divergent-20260719-234040` | 4 | 38 | 38 |
| `live-testnet-data` | 1 | 9 | 9 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 245 | 115,495 | 107,420 | 4,178,476 |
| `.md` | 225 | 32,759 | 23,537 | 2,002,265 |
| `.sh` | 128 | 14,376 | 13,002 | 521,796 |
| `.json` | 190 | 10,219 | 10,054 | 496,547 |
| `.js` | 8 | 3,057 | 2,865 | 101,209 |
| `.tsx` | 9 | 2,230 | 2,095 | 78,629 |
| `.yml` | 7 | 1,992 | 1,930 | 103,773 |
| `.mjs` | 8 | 1,918 | 1,752 | 56,250 |
| `.ts` | 12 | 1,598 | 1,441 | 52,054 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 16 | 582 | 492 | 16,899 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,958 | `mfn-consensus/tests/integration.rs` |
| 4,757 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 3,885 | `mfn-consensus/tests/block_apply.rs` |
| 3,493 | `mfn-rpc/src/dispatch.rs` |
| 3,034 | `docs/ROADMAP.md` |
| 2,700 | `scripts/public-devnet-v1/user-wallet/validator0-faucet.json` |
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
| 1,384 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,333 | `docs/F5.md` |
| 1,324 | `mfn-cli/src/wallet_cmd.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-09T21:42:32.837Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 561 |
| Total lines (all scanned source-like files) | 152,767 |
| Non-empty lines | 136,744 |
| UTF-8 bytes (source-like) | 6,244,567 |
| Paths visited (before binary/huge skip) | 717 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 52 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 70 | 35,361 | 33,209 |
| `docs` | 73 | 19,778 | 14,528 |
| `mfn-cli` | 32 | 15,673 | 14,501 |
| `scripts` | 191 | 15,555 | 13,835 |
| `mfn-node` | 40 | 15,032 | 13,923 |
| `mfn-crypto` | 23 | 7,517 | 6,773 |
| `mfn-net` | 16 | 6,249 | 5,712 |
| `mfn-wallet` | 16 | 6,178 | 5,702 |
| `mfn-runtime` | 14 | 5,147 | 4,784 |
| `mfn-rpc` | 6 | 4,079 | 3,875 |
| `mfn-light` | 6 | 3,974 | 3,628 |
| `mfn-storage-operator` | 14 | 3,247 | 2,988 |
| `mfn-storage` | 6 | 2,990 | 2,755 |
| `mfn-wasm` | 11 | 2,532 | 2,317 |
| `demo` | 12 | 2,481 | 2,295 |
| `mfn-store` | 13 | 2,248 | 1,959 |
| `(root)` | 8 | 2,016 | 1,419 |
| `.github` | 6 | 1,845 | 1,784 |
| `mfn-bls` | 4 | 865 | 757 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 232 | 108,631 | 100,956 | 3,912,857 |
| `.md` | 134 | 25,234 | 18,184 | 1,588,672 |
| `.sh` | 60 | 8,792 | 8,022 | 317,808 |
| `.json` | 97 | 4,334 | 4,240 | 186,113 |
| `.js` | 7 | 1,983 | 1,859 | 64,185 |
| `.yml` | 7 | 1,848 | 1,786 | 93,295 |
| `.mjs` | 5 | 710 | 620 | 19,973 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 15 | 543 | 458 | 15,645 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,939 | `mfn-consensus/tests/integration.rs` |
| 4,359 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 3,765 | `mfn-consensus/tests/block_apply.rs` |
| 3,356 | `mfn-rpc/src/dispatch.rs` |
| 2,486 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,371 | `docs/ROADMAP.md` |
| 2,284 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,142 | `mfn-consensus/tests/emission_simulation.rs` |
| 2,105 | `mfn-runtime/src/mempool.rs` |
| 1,973 | `mfn-cli/src/cli/parse.rs` |
| 1,786 | `mfn-node/src/p2p_fanout.rs` |
| 1,636 | `mfn-light/src/chain.rs` |
| 1,550 | `mfn-cli/src/wallet_cmd.rs` |
| 1,431 | `mfn-cli/src/cli.rs` |
| 1,327 | `docs/F5.md` |
| 1,318 | `mfn-storage/src/spora.rs` |
| 1,303 | `mfn-node/src/mfnd_cli.rs` |
| 1,290 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,282 | `.github/workflows/ci.yml` |
| 1,276 | `mfn-wallet/src/wallet.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

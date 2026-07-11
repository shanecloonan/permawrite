# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-11T19:23:36.572Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 612 |
| Total lines (all scanned source-like files) | 156,949 |
| Non-empty lines | 140,313 |
| UTF-8 bytes (source-like) | 6,412,694 |
| Paths visited (before binary/huge skip) | 793 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 61 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 70 | 35,361 | 33,209 |
| `docs` | 74 | 20,276 | 14,905 |
| `scripts` | 236 | 18,164 | 16,090 |
| `mfn-cli` | 32 | 15,463 | 14,309 |
| `mfn-node` | 40 | 15,098 | 13,985 |
| `mfn-crypto` | 23 | 7,517 | 6,773 |
| `mfn-net` | 16 | 6,249 | 5,712 |
| `mfn-wallet` | 16 | 6,178 | 5,702 |
| `mfn-runtime` | 14 | 5,147 | 4,784 |
| `mfn-rpc` | 6 | 4,079 | 3,875 |
| `mfn-light` | 6 | 3,974 | 3,628 |
| `mfn-storage-operator` | 14 | 3,247 | 2,988 |
| `mfn-storage` | 6 | 2,990 | 2,755 |
| `mfn-wasm` | 12 | 2,677 | 2,449 |
| `demo` | 12 | 2,528 | 2,338 |
| `mfn-store` | 13 | 2,248 | 1,959 |
| `(root)` | 8 | 2,237 | 1,570 |
| `.github` | 6 | 1,945 | 1,884 |
| `mfn-bls` | 4 | 865 | 757 |
| `mfn-checkpoint-log` | 4 | 706 | 641 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 236 | 109,306 | 101,571 | 3,935,630 |
| `.md` | 151 | 26,528 | 19,122 | 1,647,768 |
| `.sh` | 73 | 10,075 | 9,132 | 361,473 |
| `.json` | 113 | 5,086 | 4,976 | 218,052 |
| `.js` | 7 | 2,030 | 1,902 | 65,944 |
| `.yml` | 7 | 1,948 | 1,886 | 101,247 |
| `.mjs` | 5 | 710 | 620 | 19,973 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 16 | 574 | 485 | 16,588 |

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
| 2,043 | `mfn-cli/src/cli/parse.rs` |
| 1,786 | `mfn-node/src/p2p_fanout.rs` |
| 1,636 | `mfn-light/src/chain.rs` |
| 1,558 | `mfn-cli/src/wallet_cmd.rs` |
| 1,486 | `mfn-cli/src/cli.rs` |
| 1,382 | `.github/workflows/ci.yml` |
| 1,327 | `docs/F5.md` |
| 1,320 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,318 | `mfn-storage/src/spora.rs` |
| 1,303 | `mfn-node/src/mfnd_cli.rs` |
| 1,276 | `mfn-wallet/src/wallet.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

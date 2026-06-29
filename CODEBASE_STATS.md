# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-06-29T22:25:22.932Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 326 |
| Total lines (all scanned source-like files) | 110,238 |
| Non-empty lines | 99,049 |
| UTF-8 bytes (source-like) | 4,439,263 |
| Paths visited (before binary/huge skip) | 355 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 67 | 28,714 | 26,860 |
| `mfn-cli` | 29 | 14,529 | 13,433 |
| `docs` | 39 | 11,420 | 8,179 |
| `mfn-node` | 34 | 10,760 | 9,949 |
| `mfn-crypto` | 23 | 7,291 | 6,564 |
| `mfn-wallet` | 15 | 4,933 | 4,524 |
| `mfn-runtime` | 14 | 4,323 | 4,001 |
| `mfn-net` | 11 | 4,144 | 3,780 |
| `mfn-rpc` | 4 | 3,996 | 3,798 |
| `mfn-light` | 6 | 3,895 | 3,556 |
| `scripts` | 18 | 2,992 | 2,561 |
| `mfn-storage-operator` | 14 | 2,830 | 2,591 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-store` | 13 | 2,159 | 1,875 |
| `mfn-wasm` | 10 | 2,031 | 1,847 |
| `mfn-storage` | 6 | 2,005 | 1,821 |
| `mfn-bls` | 4 | 865 | 757 |
| `(root)` | 5 | 683 | 484 |
| `.github` | 2 | 190 | 177 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 212 | 90,043 | 83,456 | 3,259,395 |
| `.md` | 54 | 13,887 | 9,854 | 960,803 |
| `.sh` | 16 | 1,988 | 1,814 | 64,256 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.mjs` | 5 | 706 | 616 | 19,916 |
| `.svg` | 4 | 655 | 581 | 42,170 |
| `.toml` | 15 | 524 | 441 | 14,805 |
| `.json` | 11 | 265 | 254 | 7,812 |
| `.yml` | 2 | 190 | 177 | 6,008 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,589 | `mfn-consensus/tests/integration.rs` |
| 3,922 | `mfn-rpc/src/dispatch.rs` |
| 3,015 | `mfn-cli/src/cli.rs` |
| 2,784 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 2,409 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,318 | `docs/ROADMAP.md` |
| 2,290 | `mfn-consensus/tests/block_apply.rs` |
| 1,975 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,975 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 1,634 | `mfn-light/src/chain.rs` |
| 1,551 | `mfn-runtime/src/mempool.rs` |
| 1,457 | `mfn-cli/src/wallet_cmd.rs` |
| 1,163 | `mfn-node/src/p2p_fanout.rs` |
| 1,089 | `mfn-light/tests/follow_chain.rs` |
| 1,064 | `mfn-node/src/mfnd_serve.rs` |
| 1,042 | `mfn-node/src/mfnd_cli.rs` |
| 1,019 | `mfn-consensus/tests/validator_finality_evolution/bond_ops.rs` |
| 986 | `mfn-wallet/src/upload.rs` |
| 982 | `mfn-wallet/src/wallet.rs` |
| 959 | `docs/ARCHITECTURE.md` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

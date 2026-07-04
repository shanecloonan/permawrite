# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-07-04T14:26:12.704Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 565 |
| Total lines (all scanned source-like files) | 129,329 |
| Non-empty lines | 116,326 |
| UTF-8 bytes (source-like) | 5,262,830 |
| Paths visited (before binary/huge skip) | 792 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 145 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 67 | 29,986 | 28,089 |
| `mfn-cli` | 29 | 14,759 | 13,649 |
| `docs` | 55 | 14,550 | 10,625 |
| `scripts` | 232 | 13,971 | 12,708 |
| `mfn-node` | 34 | 11,958 | 11,064 |
| `mfn-crypto` | 23 | 7,291 | 6,564 |
| `mfn-wallet` | 15 | 4,938 | 4,528 |
| `mfn-net` | 11 | 4,659 | 4,250 |
| `mfn-runtime` | 14 | 4,401 | 4,072 |
| `mfn-rpc` | 4 | 3,997 | 3,799 |
| `mfn-light` | 6 | 3,924 | 3,582 |
| `mfn-storage-operator` | 14 | 2,877 | 2,635 |
| `demo` | 12 | 2,478 | 2,292 |
| `mfn-store` | 13 | 2,159 | 1,875 |
| `mfn-wasm` | 11 | 2,079 | 1,882 |
| `mfn-storage` | 6 | 2,072 | 1,884 |
| `.github` | 5 | 1,513 | 1,463 |
| `mfn-bls` | 4 | 865 | 757 |
| `(root)` | 6 | 820 | 576 |
| `.permawrite-devnet-v1` | 4 | 32 | 32 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 212 | 93,573 | 86,762 | 3,370,693 |
| `.md` | 80 | 17,522 | 12,527 | 1,186,647 |
| `.sh` | 37 | 6,755 | 6,170 | 242,237 |
| `.json` | 199 | 6,061 | 5,870 | 238,988 |
| `.js` | 7 | 1,980 | 1,856 | 64,098 |
| `.yml` | 6 | 1,516 | 1,465 | 79,415 |
| `.mjs` | 5 | 706 | 616 | 19,916 |
| `.svg` | 4 | 692 | 619 | 46,019 |
| `.toml` | 15 | 524 | 441 | 14,817 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 4,922 | `mfn-consensus/tests/integration.rs` |
| 3,923 | `mfn-rpc/src/dispatch.rs` |
| 3,064 | `mfn-cli/src/cli.rs` |
| 2,892 | `mfn-consensus/tests/apply_block_proptest.rs` |
| 2,482 | `mfn-consensus/tests/block_apply.rs` |
| 2,416 | `mfn-node/tests/mfnd_smoke.rs` |
| 2,369 | `docs/ROADMAP.md` |
| 2,232 | `mfn-consensus/tests/producer_treasury_settlement.rs` |
| 2,056 | `mfn-consensus/tests/emission_simulation.rs` |
| 1,850 | `mfn-node/src/p2p_fanout.rs` |
| 1,635 | `mfn-light/src/chain.rs` |
| 1,609 | `mfn-runtime/src/mempool.rs` |
| 1,548 | `mfn-cli/src/wallet_cmd.rs` |
| 1,197 | `mfn-net/src/serve.rs` |
| 1,178 | `.github/workflows/ci.yml` |
| 1,176 | `scripts/public-devnet-v1/OPERATORS.md` |
| 1,094 | `mfn-light/tests/follow_chain.rs` |
| 1,092 | `mfn-node/src/mfnd_cli.rs` |
| 1,081 | `mfn-node/src/mfnd_serve.rs` |
| 1,019 | `mfn-consensus/tests/validator_finality_evolution/bond_ops.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

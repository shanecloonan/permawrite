# Codebase stats

Auto-generated snapshot of this repository (Rust sources, docs, diagrams, and config-like text; `target/`, `.git`, and common binary formats are excluded).

**Generated (UTC):** 2026-05-20T10:16:09.561Z

**Regenerate:** `node scripts/codebase-stats.mjs`

## Summary

| Metric | Value |
| --- | ---: |
| Source-like files scanned | 271 |
| Total lines (all scanned source-like files) | 78,300 |
| Non-empty lines | 69,412 |
| UTF-8 bytes (source-like) | 3,188,165 |
| Paths visited (before binary/huge skip) | 288 |
| Skipped (binary / non-UTF8 / over 4 MiB) | 1 |

## Lines of code by top-level directory

The first path segment (crate name, `docs`, etc.). Only source-like extensions are included.

| Directory | Files | Lines | Non-empty lines |
| --- | ---: | ---: | ---: |
| `mfn-consensus` | 56 | 16,160 | 14,905 |
| `docs` | 35 | 10,678 | 7,569 |
| `mfn-node` | 31 | 8,165 | 7,558 |
| `mfn-crypto` | 23 | 7,292 | 6,565 |
| `mfn-cli` | 22 | 7,035 | 6,466 |
| `mfn-wallet` | 14 | 4,693 | 4,301 |
| `mfn-light` | 6 | 3,895 | 3,556 |
| `mfn-runtime` | 12 | 3,709 | 3,435 |
| `mfn-rpc` | 4 | 3,343 | 3,167 |
| `mfn-net` | 10 | 3,203 | 2,929 |
| `demo` | 12 | 2,394 | 2,210 |
| `mfn-wasm` | 10 | 2,029 | 1,845 |
| `mfn-storage` | 6 | 1,960 | 1,782 |
| `mfn-store` | 10 | 1,491 | 1,284 |
| `mfn-bls` | 4 | 865 | 757 |
| `(root)` | 5 | 738 | 529 |
| `scripts` | 9 | 496 | 412 |
| `.github` | 2 | 154 | 142 |

## Lines of code by file extension

| Extension | Files | Lines | Non-empty lines | Bytes |
| --- | ---: | ---: | ---: | ---: |
| `.rs` | 173 | 61,655 | 56,829 | 2,225,326 |
| `.md` | 50 | 12,474 | 8,797 | 818,099 |
| `.js` | 7 | 1,896 | 1,774 | 59,387 |
| `.mjs` | 5 | 697 | 609 | 19,201 |
| `.svg` | 3 | 520 | 462 | 35,170 |
| `.toml` | 14 | 482 | 405 | 13,315 |
| `.json` | 10 | 238 | 228 | 6,904 |
| `.sh` | 7 | 184 | 166 | 6,166 |
| `.yml` | 2 | 154 | 142 | 4,597 |

## Largest source files (by line count)

| Lines | File |
| ---: | --- |
| 3,273 | `mfn-rpc/src/dispatch.rs` |
| 2,223 | `docs/ROADMAP.md` |
| 1,952 | `mfn-node/tests/mfnd_smoke.rs` |
| 1,684 | `mfn-consensus/tests/block_apply.rs` |
| 1,661 | `mfn-consensus/tests/integration.rs` |
| 1,634 | `mfn-light/src/chain.rs` |
| 1,551 | `mfn-runtime/src/mempool.rs` |
| 1,321 | `mfn-cli/src/cli.rs` |
| 1,089 | `mfn-light/tests/follow_chain.rs` |
| 986 | `mfn-wallet/src/upload.rs` |
| 982 | `mfn-wallet/src/wallet.rs` |
| 959 | `docs/ARCHITECTURE.md` |
| 944 | `mfn-node/src/mfnd_cli.rs` |
| 921 | `mfn-consensus/src/consensus/engine.rs` |
| 870 | `mfn-crypto/src/utxo_tree.rs` |
| 816 | `mfn-light/src/checkpoint.rs` |
| 804 | `mfn-storage/src/spora.rs` |
| 783 | `mfn-consensus/src/block/apply.rs` |
| 753 | `demo/web/main.js` |
| 733 | `mfn-consensus/tests/emission_simulation.rs` |

## Notes

- **Lines** include blank lines and comments; **non-empty** ignores lines that are only whitespace.
- **Source-like** extensions: `.cjs`, `.js`, `.json`, `.jsx`, `.md`, `.mjs`, `.rs`, `.sh`, `.sql`, `.svg`, `.toml`, `.ts`, `.tsx`, `.yaml`, `.yml`.
- **`Cargo.lock`** and other `*.lock` files are excluded so totals emphasize authored source.
- Requires **Node.js** only to regenerate this file; the Rust workspace does not depend on Node for builds.

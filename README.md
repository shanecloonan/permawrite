<div align="center">

# Permawrite

**A novel blockchain that funds permanent storage with fees generated from private transactions.**

*Monero-grade financial privacy fused with Arweave-grade data permanence — in a single chain.*

[![Status](https://img.shields.io/badge/status-controlled_public_devnet-orange)](#status)
[![Unsafe](https://img.shields.io/badge/unsafe-forbidden-blue)](#design-philosophy)
[![Clippy](https://img.shields.io/badge/clippy-clean-brightgreen)](#design-philosophy)
[![License](https://img.shields.io/badge/license-MIT_%2F_Apache--2.0-blue)](#license)

[**Read the overview →**](./docs/OVERVIEW.md) &nbsp;·&nbsp; [**Public devnet →**](./docs/TESTNET.md) &nbsp;·&nbsp; [**Architecture →**](./docs/ARCHITECTURE.md) &nbsp;·&nbsp; [**Privacy & permanence →**](./docs/PRIVACY_AND_PERMANENCE.md) &nbsp;·&nbsp; [**Roadmap →**](./docs/ROADMAP.md)

</div>

---

## What this is

Permawrite is the **Rust implementation** of a new layer-1 blockchain (internally codenamed **MoneyFund Network**, MFBN-1 on the wire) that fuses two things which currently exist only in separate chains:

1. **Financial privacy at least as strong as Monero** — confidential amounts, stealth addresses, decoy-based ring signatures with deniable spending, no public address book, no visible balances.
2. **Data permanence at least as strong as Arweave** — content-addressed uploads anchored on-chain with an upfront endowment that funds storage operators forever, audited every block via succinct random-access proofs.

These two halves aren't bolted together. They **share the economics**: the priority fees paid by privacy transactions flow into the same treasury that funds permanent storage. **Financial privacy is what pays for permanent storage.** Every confidential transaction subsidizes the network's promise to keep data alive in perpetuity.

The full vision and the design rationale live in [**docs/OVERVIEW.md**](./docs/OVERVIEW.md). The whitepaper-grade technical spec lives in [**docs/ARCHITECTURE.md**](./docs/ARCHITECTURE.md).

<p align="center">
  <img src="./docs/img/architecture-stack.svg" alt="Permawrite crate dependency stack: mfn-crypto and mfn-bls form the primitive layer, mfn-storage builds storage proofs on top of mfn-crypto, mfn-consensus is the state machine, mfn-runtime / mfn-store / mfn-rpc / mfn-net / mfn-node compose the daemon, and mfn-wallet / mfn-cli / mfn-storage-operator / mfn-wasm are active devnet-grade client and operator crates." width="100%">
</p>

---

## Documentation map

Three reading paths depending on what you want:

### 🧭 I want to understand what this is

Start here. Plain-language framing before the technical specs.

- [**docs/OVERVIEW.md**](./docs/OVERVIEW.md) — the project, the vision, why it's hard, how it works (intuition first)
- [**docs/PRIVACY_AND_PERMANENCE.md**](./docs/PRIVACY_AND_PERMANENCE.md) — why privacy and permanence are fused here (freedom, incentives, economics)
- [**docs/GLOSSARY.md**](./docs/GLOSSARY.md) — every acronym and term used anywhere in the docs

### 🧮 I want the technical design

Whitepaper-grade specifications. Math, wire formats, hash domains, derivations.

- [**docs/ARCHITECTURE.md**](./docs/ARCHITECTURE.md) — system-wide architecture: layers, data flow, state-transition function
- [**docs/PRIVACY.md**](./docs/PRIVACY.md) — the privacy half: stealth addresses, Pedersen commitments, CLSAG ring signatures, Bulletproof range proofs, decoy selection, the Tier-1/2/3/4 anonymity progression
- [**docs/WALLET_ADDRESSES.md**](./docs/WALLET_ADDRESSES.md) — `mf...` testnet display addresses vs raw mainnet receive keys
- [**docs/STORAGE.md**](./docs/STORAGE.md) — the permanence half: chunking, Merkle commitment, SPoRA per-block challenges, endowment math, the PPB-precision yield accumulator
- [**docs/AUTHORSHIP.md**](./docs/AUTHORSHIP.md) — optional Schnorr-signed claims on `data_root` (anonymous-by-default uploads; separate publishing identity; `MFCL` / `MFEX` wire; header `claims_root`; **`mfnd serve`** discovery **M2.2.8** + derived views **M2.2.10**)
- [**docs/CONSENSUS.md**](./docs/CONSENSUS.md) — the consensus engine: slot-based PoS, stake-weighted VRF leader election, BLS12-381 committee finality, equivocation slashing, liveness slashing
- [**docs/ECONOMICS.md**](./docs/ECONOMICS.md) — hybrid emission, two-sided fee split, treasury settlement, the `E₀ = C₀·(1+i)/(r−i)` permanence derivation

### 🛠 I want to build / contribute

- [**CONTRIBUTING.md**](./CONTRIBUTING.md) — how to set up, what conventions to follow, how the test gate works
- [**CODEBASE_STATS.md**](./CODEBASE_STATS.md) — auto-generated line counts / file breakdown (regenerate via `node scripts/codebase-stats.mjs`)
- [**IMPLEMENTATION_STATUS.md**](./IMPLEMENTATION_STATUS.md) — Rust implementation status and module map
- [**docs/TESTNET.md**](./docs/TESTNET.md) — controlled public-devnet runbook, health checks, launch gates, and recovery guidance
- [**docs/PUBLIC_DEVNET_THREAT_MODEL.md**](./docs/PUBLIC_DEVNET_THREAT_MODEL.md) — release-candidate threat model and residual-risk checklist
- [**SECURITY.md**](./SECURITY.md) — pre-audit security posture and vulnerability disclosure
- [**docs/ROADMAP.md**](./docs/ROADMAP.md) — what's live, what's next, the tier-by-tier rollout

### 📦 I want a specific crate

Each crate has its own README with public API summary, test counts, and links into the deep-dive docs.

- [**`mfn-crypto`**](./mfn-crypto/README.md) — ed25519 + ZK primitives (Schnorr, Pedersen, CLSAG, Bulletproofs, OoM, VRF, UTXO accumulator, Merkle, ...)
- [**`mfn-bls`**](./mfn-bls/README.md) — BLS12-381 signatures, committee aggregation
- [**`mfn-storage`**](./mfn-storage/README.md) — SPoRA storage proofs, endowment math
- [**`mfn-consensus`**](./mfn-consensus/README.md) — block, transaction, coinbase, emission, slashing, state-transition function
- [**`mfn-runtime`**](./mfn-runtime/README.md) — in-process `Chain` + `Mempool` + producer helpers
- [**`mfn-store`**](./mfn-store/README.md) — checkpoint + block-log persistence (`fs` + `redb`)
- [**`mfn-rpc`**](./mfn-rpc/README.md) — JSON-RPC method dispatch (no sockets)
- [**`mfn-net`**](./mfn-net/README.md) — P2P framing, handshakes, post-goodbye gossip
- [**`mfn-node`**](./mfn-node/README.md) — `mfnd` binary: RPC TCP loop + P2P threads
- [**`mfn-light`**](./mfn-light/README.md) — light-client header-chain follower (built on `verify_header`)
- [**`mfn-wallet`**](./mfn-wallet/README.md) — confidential wallet primitives: stealth scanning, owned-UTXO tracking, transfer-tx construction
- [**`mfn-cli`**](./mfn-cli/README.md) — wallet/operator CLI over local files and `mfnd` RPC
- [**`mfn-storage-operator`**](./mfn-storage-operator/README.md) — storage proof operator tooling
- [**`mfn-wasm`**](./mfn-wasm/README.md) — browser-facing wallet, scan, transfer, upload, and verification bindings

---

## Status

**Controlled public-devnet implementation, pre-audit.** Permawrite now has an end-to-end Rust stack: consensus/state transition, persistence, JSON-RPC dispatch, the `mfnd` daemon, P2P handshake/gossip/sync paths, wallet CLI flows, storage-operator tooling, public-devnet scripts, health checks, support bundles, and launch go/no-go guidance. It is still experimental software and not an incentivized or production network.

Release truth is intentionally split into three levels:

| Level | Current status | What it means |
| --- | --- | --- |
| Controlled public devnet | Live in docs/scripts | Operators can run the documented `public_devnet_v1` flow, local mesh, health checks, wallet/storage demos, support bundles, and recovery helpers. |
| Internet-facing experimental testnet | Release-candidate gated | Requires the launch checklist, local CI mirror, ignored/nightly smoke coverage, green GitHub CI, private RPC posture, replaced test keys for non-toy deployments, and named operator watch. |
| Incentivized/adversarial testnet | Not ready | Requires deeper hardening, broader adversarial testing, operational rehearsal, and independent security review. |

Important security posture:

- Permawrite is **pre-audit**. Do not treat any deployment as production custody or production permanence.
- JSON-RPC is a devnet control plane. Keep it loopback-only, VPN/SSH-only, or behind explicit firewall/TLS controls. API keys gate write/admin methods; public read methods remain unauthenticated.
- The public devnet genesis contains public deterministic validator seeds. Replace them before any shared, production-like, incentivized, or non-toy deployment.

High-level crate status:

| Area | Crate(s) | State |
| --- | --- | --- |
| Privacy and consensus primitives | `mfn-crypto`, `mfn-bls`, `mfn-storage`, `mfn-consensus` | Tier-1 privacy, storage proofs, endowment accounting, validator rotation, finality, checkpoint/wire codecs, and protocol vectors are live. |
| Node runtime and persistence | `mfn-runtime`, `mfn-store`, `mfn-node` | `Chain`, `Mempool`, producer helpers, filesystem/`redb` persistence, JSON genesis, `step`, and `serve` are live. |
| RPC and operations | `mfn-rpc`, `mfn-cli`, `scripts/public-devnet-v1` | JSON-RPC method classification, optional API-key enforcement, status diagnostics, RPC DoS guards, public-devnet health checks, CI/preflight helpers, and operator runbooks are live. |
| Networking and light clients | `mfn-net`, `mfn-light` | P2P handshake, gossip, block/light-follow sync hardening, peer hygiene, and light-client verification are live. |
| Wallet, storage, and browser clients | `mfn-wallet`, `mfn-cli`, `mfn-storage-operator`, `mfn-wasm` | Wallet scan/send/upload/claim flows, permanence artifacts, storage-operator proof flows, JSON support records, and WASM packaging are active; UX remains devnet-grade. |

Detailed module-level implementation status lives in [`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md). The controlled public-devnet runbook lives in [`docs/TESTNET.md`](./docs/TESTNET.md), and the launch checklist lives in [`scripts/public-devnet-v1/OPERATORS.md`](./scripts/public-devnet-v1/OPERATORS.md#launch-gono-go-checklist).

---

## How the halves fuse — the economic engine

<p align="center">
  <img src="./docs/img/money-flow.svg" alt="The Permawrite money flow. Emission mints fresh MFN into the coinbase paid to producers. Privacy transactions pay fees that split 90/10 between the storage treasury and the producer. The treasury drains every block to pay storage operators who submit valid SPoRA proofs. Emission acts as a backstop only when the treasury runs short. Operator and producer income re-enters circulation as users pay fees with this MFN, closing the loop." width="100%">
</p>

Every transaction that touches the chain — financial-only or storage-bearing — leaks **fee revenue into the treasury**. The treasury **funds the per-slot yield owed to storage operators** for keeping data alive. There is no "compute layer" to monetize, no oracle to bribe, no separate DA layer to subsidize: **privacy demand pays for permanence**, full stop.

The full mechanics of `apply_block` are illustrated in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md#state-transition-function-apply_block).

---

## Quick start

```bash
# Install Rust if you haven't: https://rustup.rs
git clone https://github.com/shanecloonan/permawrite
cd permawrite

# Build everything
cargo build --release

# Run the full workspace test suite
cargo test --workspace --release

# Lint gate (zero warnings expected)
cargo clippy --workspace --all-targets --release -- -D warnings
cargo fmt --all -- --check

# Local CI mirror used before pushing to main
powershell -File scripts/ci-check.ps1   # Windows
# or: bash scripts/ci-check.sh          # Linux/macOS
```

Tested toolchains: `stable-x86_64-unknown-linux-gnu`, `stable-x86_64-apple-darwin`, `stable-x86_64-pc-windows-gnu`.

> **Windows note.** Use the `*-pc-windows-gnu` toolchain. The MSVC toolchain works but requires Visual Studio Build Tools (`link.exe`); GNU ships its own linker.

---

## Project layout

```
permawrite/
├── README.md                    ← you are here
├── IMPLEMENTATION_STATUS.md                   ← Rust implementation status
├── SECURITY.md                  ← vulnerability disclosure
├── CONTRIBUTING.md              ← contribution guide
├── LICENSE-MIT / LICENSE-APACHE
│
├── docs/                        ← all design documentation
│   ├── OVERVIEW.md              ← project overview (intuition first)
│   ├── ARCHITECTURE.md          ← whitepaper-grade technical spec
│   ├── PRIVACY.md               ← the privacy half (deep dive)
│   ├── STORAGE.md               ← the permanence half (deep dive)
│   ├── CONSENSUS.md             ← the PoS engine (deep dive)
│   ├── ECONOMICS.md             ← tokenomics + endowment derivation
│   ├── ROADMAP.md               ← tier-by-tier rollout
│   └── GLOSSARY.md              ← term reference
│
├── mfn-crypto/                  ← discrete-log cryptography over ed25519
│   ├── README.md
│   ├── src/{scalar,point,hash,codec,domain,
│   │        schnorr,pedersen,stealth,encrypted_amount,
│   │        lsag,clsag,range,bulletproofs,oom,
│   │        vrf,decoy,utxo_tree,merkle,...}.rs
│   └── tests/
│
├── mfn-bls/                     ← BLS12-381 + committee aggregation
│   ├── README.md
│   └── src/sig.rs
│
├── mfn-storage/                 ← SPoRA storage proofs + endowment math
│   ├── README.md
│   └── src/{commitment,spora,endowment}.rs
│
├── mfn-consensus/               ← state-transition function
├── mfn-runtime/                 ← Chain, Mempool, producer helpers
├── mfn-store/                   ← fs/redb persistence, replay, peer/proof pools
├── mfn-rpc/                     ← JSON-RPC dispatch
├── mfn-net/                     ← P2P frames, handshakes, gossip, sync
├── mfn-node/                    ← mfnd daemon composition layer
├── mfn-light/                   ← light-client verification/following
├── mfn-wallet/                  ← stealth scanning, send/upload/claim flows
├── mfn-cli/                     ← operator and wallet CLI
├── mfn-storage-operator/        ← SPoRA operator daemon
└── mfn-wasm/                    ← browser-facing WASM bindings
```

---

## Design philosophy

1. **No `unsafe`.** Enforced at the crate level with `#![forbid(unsafe_code)]`. If a primitive cannot be built safely, we don't ship it.
2. **Constant-time where it matters.** Secret-dependent comparisons use [`subtle`](https://crates.io/crates/subtle). Secret material implements [`zeroize::Zeroize`] on drop.
3. **Established cryptographic libraries where possible.** No hand-rolled curves, no toy SHA. We compose instead of reinventing, while still treating this repository as pre-audit.
4. **Domain separation everywhere.** Every hash carries an MFBN-1 tag. Adding a new tag is a hard fork by design — no accidental cross-domain collisions.
5. **Protocol-owned canonical bytes.** Rust encoders, decoders, docs, and golden vectors define MFBN-1 behavior. Other clients can compare against them, but they do not drive the design.
6. **Production-grade error handling.** No `panic!`/`unwrap` outside of test code. Every fallible operation returns `Result<_, CryptoError>` or the crate-local equivalent.
7. **Determinism is non-negotiable.** Every consensus-critical primitive uses only integer arithmetic, big-endian byte order, and explicit ordering of map/set traversals. The chain MUST replay byte-identically across implementations.

---

## What this is NOT

- **Not audited.** The code is written with production discipline (constant-time where required, no `unsafe`, explicit errors, broad tests), but it has not had third-party cryptographic or operational review.
- **Not a re-implementation of an existing chain.** Permawrite's design — endowment-funded permanent storage rewards, OoM-based log-size ring signatures over the full UTXO set, hybrid emission + fee-treasury tokenomics — is novel. The closest two precedents (Monero for privacy, Arweave for permanence) each only solve one half.
- **Not production or incentivized-testnet ready.** The controlled public-devnet path exists, but any internet-facing release candidate must pass the documented launch gates, keep RPC private or explicitly protected, and replace public test keys for non-toy deployments.
- **Not secure public RPC.** The daemon has devnet RPC guards, but direct internet exposure remains high risk without firewall/VPN/SSH/TLS/rate-limit controls.

---

## License

Dual-licensed under either of:

- **Apache License 2.0** ([LICENSE-APACHE](./LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](./LICENSE-MIT))

at your option. Standard Rust ecosystem dual license.


Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work shall be dual-licensed as above, without any additional terms or conditions.

---

## Security

Please see [SECURITY.md](./SECURITY.md) for the disclosure process. **Do not** open public issues for vulnerabilities.

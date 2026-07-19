# Vibecoding the Gauntlet — How Permawrite Is Actually Built With AI

Permawrite fuses Monero-grade financial privacy with Arweave-grade data permanence in one chain. That is a brutal thing to hand to an AI coding agent. The obvious way to try — open a chat, say *"build the network,"* and keep pasting errors back — collapses almost immediately. This page is the honest answer to the question **"can you vibecode a chain this hard, and if so, how?"**

The short version: **yes, but only because the repository is engineered specifically so that an AI never has to hold the whole thing in its head at once, and never has to debug a distributed system by eyeballing interleaved logs.** Everything below is already in this codebase. This is not aspirational; it is the operating manual for how the project keeps getting built.

The two walls you hit are real:

1. **Context window collapse** — cramming ring signatures, stealth addresses, Pedersen commitments, SPoRA proofs, endowment math, PoS finality, and P2P gossip into one prompt makes the model hallucinate variables, forget consensus rules, and break component A while "fixing" component B.
2. **Emergent network bugs** — when node A rejects node B's block over a subtle storage-proof state discrepancy, there is no single stack trace. Consensus divergence lives *across* processes.

Permawrite beats both with the same underlying move: **turn a giant, entangled reasoning problem into a series of small, bounded, checkable ones.** Below is exactly how.

---

## Wall 1: Context window collapse

You cannot fit "a Monero+Arweave chain" in a context window. So the codebase is built so you never have to. Five mechanisms do the work.

### 1.1 The crate boundary *is* the context boundary

Permawrite is not one program; it is a layered stack of small crates, each with a single responsibility and a hard dependency direction (see the architecture stack diagram in [`README.md`](./README.md)):

| Layer | Crates | What an agent needs in context to work here |
|---|---|---|
| Primitives | `mfn-crypto`, `mfn-bls` | Just the curve/signature math and its domain tags |
| Storage | `mfn-storage` | SPoRA proofs + endowment math, built *on top of* `mfn-crypto` |
| State machine | `mfn-consensus` | The state-transition function; consumes primitives + storage |
| Node | `mfn-runtime`, `mfn-store`, `mfn-rpc`, `mfn-net`, `mfn-node` | Composition, persistence, wire, daemon |
| Clients | `mfn-wallet`, `mfn-cli`, `mfn-storage-operator`, `mfn-wasm` | Consume the daemon's RPC and the crypto crate's builders |

The crucial property: **the dependency arrows only point one way.** When an agent is asked to touch CLSAG decoy selection, the relevant universe is `mfn-crypto/src/decoy.rs` and its tests — *not* the consensus engine, not the P2P layer, not the wallet. The "context window" for that unit of work is a few files, not the whole chain. The cryptographic overhead the user worries about is real, but it is **partitioned**: ring signatures live in `mfn-crypto`, permanence proofs live in `mfn-storage`, and the place they finally meet — `apply_block` — only ever sees their *public interfaces*, never their internals.

This is why the "fusing privacy with permanence requires massive interconnected logic" problem is survivable. The two halves are only interconnected in **one file's worth of orchestration** (`mfn-consensus/src/block/apply.rs`), and that file calls verified primitives rather than reimplementing them.

### 1.2 Durable external memory: the docs *are* the spec

An AI's context window is volatile; it forgets consensus rules between sessions. Permawrite's answer is that the rules do not live in the context window — they live in version-controlled prose the agent re-reads on demand:

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) enumerates **every check `apply_block` performs, in order**, plus the full MFBN-1 wire codec and domain-tag table.
- [`PRIVACY.md`](./PRIVACY.md) and [`STORAGE.md`](./STORAGE.md) are the standalone specs for each half.
- [`CONSENSUS.md`](./CONSENSUS.md), [`ECONOMICS.md`](./ECONOMICS.md), and [`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md) pin the finality, money, and threat-model rules.
- [`GLOSSARY.md`](./GLOSSARY.md) defines every acronym so a fresh agent never has to *infer* what CLSAG, SPoRA, MFEO, or PPB mean.
- The **Cross-cuts table** in [`README.md`](./README.md) maps every feature to `layperson doc → technical doc → exact source file`. An agent that needs to change "hidden amounts" is told, in one row, that the code is `mfn-crypto/src/pedersen.rs`.

The rule of thumb the project actually follows: **before writing code, load the relevant doc section into context, not the whole subsystem.** The doc is a compression of the subsystem that fits.

### 1.3 Canonical bytes and golden vectors pin the truth

When a model hallucinates a variable or a field order, the classic failure is that it *compiles and looks right* but produces bytes that no other node agrees with. Permawrite makes that class of hallucination fail loudly:

- Every consensus-critical hash carries an **MFBN-1 domain tag** (see [`ARCHITECTURE.md § Domain separation`](./ARCHITECTURE.md#domain-separation)). Adding a tag is a deliberate hard fork, so an agent cannot silently invent a new hashing context.
- The wallet ships a **canonical-encoding conformance suite** (`mfn-wallet/tests/canonical_conformance.rs`) that pins transaction version, empty-`extra` defaults, uniform ring-16, the two-output floor, real `enc_amount` ciphertexts, and byte-canonical wire form for both reference transfers and uploads.
- Design pillar #5 in [`README.md`](./README.md) states it directly: *protocol-owned canonical bytes.* Rust encoders/decoders + docs + golden vectors define behavior; anything an agent writes is checked against them.

The effect: a hallucinated field or reordered struct doesn't slip through as a plausible-looking diff — it breaks a conformance test with an exact byte mismatch.

### 1.4 One coherent unit per commit

The most important discipline against context collapse is *scope*. The coordination rules in [`../AGENTS.md`](../AGENTS.md) mandate **"one coherent unit per commit."** Work is decomposed into small, named units (e.g. "B9 phase 2 — tx v2 wire adds 1-byte view_tag per output") that each touch a bounded set of files and land independently.

This is what keeps "fix new thing → break old thing" from happening. A unit that only adds a view-tag byte to the output codec cannot accidentally rewrite decoy selection, because decoy selection is not in its context and not in its diff. Small units also mean small diffs, which means CI failures point at a small suspect surface.

### 1.5 Parallel lanes with explicit ownership, on one board

Permawrite is built by **multiple agents at once**, and the thing that stops them from clobbering each other is the single control board in [`../AGENTS.md`](../AGENTS.md):

- Each **lane** owns an exclusive slice of the system (RC core, RC ops, onboarding, protocol hardening, privacy surface, permanence depth, testnet launch) and is explicitly told what it **does not** own.
- Every unit flows through the same seven-step pipeline — **SYNC → CLAIM → BUILD → PROVE → LAND → VERIFY → CLOSE** — and every agent broadcasts **Done / Doing / Next** before touching code. *"No silent work"* is a written rule, and every check in the pipeline has exactly one named owner (the board's verification matrix).
- Cross-lane dependencies go through a **Cross-lane requests** table, not through one agent reaching into another's files.
- There is exactly **one live board**; history rotates into the append-only [`AGENTS_LEDGER.md`](./AGENTS_LEDGER.md) instead of accreting on the board, so the live state stays small enough to re-read every session and can never drift against a mirror.

This is horizontal scaling for a problem too big for one context window: instead of one agent trying to hold the whole chain, seven lanes each hold a *slice*, and the board is the shared, durable memory that keeps the slices coherent. The board itself is guarded — `ci-check` fails closed on UTF-16/mojibake corruption of `AGENTS.md`, the ledger, and the legacy pointer stubs — so the coordination substrate can't silently rot.

---

## Wall 2: Emergent network bugs

AI is bad at debugging P2P partitions because the bug is not in one process. Permawrite's strategy is to **make consensus divergence impossible to hide and cheap to reproduce**, so that "there's no single stack trace" stops being true.

### 2.1 Determinism turns a distributed bug into a local one

Design pillar #1 (from both [`README.md`](./README.md) and [`ARCHITECTURE.md`](./ARCHITECTURE.md#design-pillars)) is **byte-identical replay**:

> Every consensus-critical primitive uses only integer arithmetic, big-endian byte order, and explicit ordering of map/set traversals. The chain MUST replay byte-identically across implementations.

This is the single most important debugging affordance in the project. If two nodes must produce identical bytes from identical input, then "node A rejected node B's block" is *not* an inscrutable network mystery — it is a **pure-function disagreement** that you can reproduce in a single-process test by feeding the same block to `apply_block`. The whole `mfn-consensus` test corpus exploits this: `apply_block_proptest.rs`, `block_apply.rs`, `producer_treasury_settlement.rs`, and `validator_finality_evolution.rs` reproduce accept/reject/rollback outcomes deterministically, with **no network at all**. The user's exact scenario — "node A rejects node B's block because of a tiny state discrepancy in your storage proofs" — is covered by named tests like *"tampered `storage_proof_root` rejects before payout effects"* that run in milliseconds on one machine.

**The move:** don't debug the partition; reproduce the state transition. Determinism guarantees you can.

### 2.2 Structured, greppable, cross-node logs

When you *do* need the multi-node view, Permawrite does not make you parse prose. The daemon emits **structured, prefixed log lines** designed to be diffed across processes: `mfnd_p2p_listening=`, `mfnd_serve_listening=`, `mfnd_p2p_diversity_warning`, `mfnd_fraud_proof_valid`, `mfnd_pm23_warning`, `mfnd_p2p_tx_fanout_reaches_third_hop_peer`, and many more. Storage-operator proof attempts emit JSON (`prove_attempt_json`).

Because every significant state event is a stable, machine-parseable token, "figure out where consensus diverged" becomes *grep the same needle across every node's log and find the first block height where the tokens disagree* — a task an agent is actually good at, instead of free-form log archaeology.

### 2.3 Reproducible multi-node harnesses, not manual node juggling

You never manually start a mesh and squint at it. The `scripts/public-devnet-v1/` toolchain gives agents deterministic, scripted network topologies:

- `start-all.*` brings up a hub + voters + observer mesh on loopback with health gating (waits for `tip >= 1`, both voters P2P-listening, etc.).
- `soak.*` runs long restart-under-load rehearsals; `participant-rehearsal-smoke.*` runs join/catch-up flows.
- Health checks and `launch-status.*` turn "is the network OK?" into a single JSON verdict instead of a judgment call.

This is how the "emergent bug" gets *caught* in the first place — the same scripted mesh runs in CI and nightly, so a partition-inducing change fails a rehearsal instead of surfacing in production.

### 2.4 Slow/networked tests are quarantined but not abandoned

Multi-process `mfnd serve` + P2P sync tests are marked `#[ignore]` so default CI stays fast, but they run in [`nightly.yml`](../.github/workflows/nightly.yml) and via `scripts/ci-ignored.*` (see [`CI.md`](./CI.md)). Stdout readers use **bounded timeouts** so a hung P2P handshake fails as a clean timeout, not an infinite CI hang. This keeps the fast feedback loop fast *and* keeps the genuinely distributed tests running on a schedule.

### 2.5 Fraud proofs make divergence a first-class protocol object

The deepest answer to "which node is wrong?" is that the protocol answers it for you. The F5 fraud-proof system (see [`FRAUD_PROOFS.md`](./FRAUD_PROOFS.md)) lets a node that detects an invalid block — bad body root, bad coinbase amount, invalid CLSAG, invalid SPoRA, a ring member that isn't a real UTXO — **broadcast a compact proof of exactly what was wrong** (P2P tags `0x13`/`0x14`), recorded in a fraud-contest registry queryable over RPC. Consensus divergence stops being a thing humans reverse-engineer from logs; it becomes a signed, wire-format artifact that names the offending check.

---

## The loop, in practice

Putting both walls together, the actual build loop an agent (or a lane of agents) follows here is:

1. **Claim a small, named unit** on the [`AGENTS.md`](../AGENTS.md) board (Done / Doing / Next).
2. **Load only the relevant doc section + crate** into context — not the whole chain.
3. **Write the unit** against canonical bytes and existing verified primitives; add or extend a deterministic test.
4. **Reproduce any consensus behavior locally** via `apply_block`-level tests — determinism means you don't need a network to trust the change.
5. **Run the local CI mirror** (`scripts/ci-check.*`: rustfmt, clippy `-D warnings`, release tests, wasm, audit) before pushing — see [`CI.md`](./CI.md) and the CI-before-push rule.
6. **Let scripted meshes + nightly soak** catch anything that only shows up across processes; structured logs and fraud proofs localize it if they do.
7. **Update the board**, hand off, repeat.

Each step is individually small enough to fit in a context window and checkable enough that a hallucination fails a test instead of shipping.

---

## Honest limits

Vibecoding this chain is *possible*, not *free*. The same [`PROBLEMS.md`](./PROBLEMS.md) and [`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md) that keep the project honest apply here:

- **This is pre-audit, experimental software.** The scaffolding above catches regressions and divergence; it does **not** substitute for third-party cryptographic and operational review. A green board is not a security proof.
- **The hardest bugs are economic, not syntactic.** The counterfeit-input attack (fabricated ring members inflating balances, closed in `apply_block`) was a *design-level* trap that no amount of context management would have flagged automatically — it took adversarial reasoning. Line-level correctness is necessary, not sufficient.
- **Determinism is a discipline, not a default.** It only holds because every new primitive is held to integer-only, big-endian, explicitly-ordered arithmetic. An agent that reaches for floats or hash-map iteration order breaks the very property this whole strategy depends on — which is exactly why `clippy -D warnings` and the conformance suite exist.

The thesis stands: you can vibecode a Monero-plus-Arweave chain — **not by asking an AI to build the network, but by building a repository in which no single change ever requires understanding the whole network at once.**

---

## Where to read next

- [`README.md`](./README.md) — doc map + the crate-stack diagram + Cross-cuts table
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — every `apply_block` check, in order; MFBN-1 codec; domain tags
- [`CI.md`](./CI.md) — the local mirror, nightly, soak, and ignored-test policy
- [`../AGENTS.md`](../AGENTS.md) — the single control board: lanes, pipeline, verification matrix (the shared memory)
- [`FRAUD_PROOFS.md`](./FRAUD_PROOFS.md) — divergence as a first-class protocol object
- [`PROBLEMS.md`](./PROBLEMS.md) — the limits that no build process erases

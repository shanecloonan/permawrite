# Smart contracts — feasibility assessment

**Scope:** Whether Permawrite should add general-purpose on-chain programmability — deployable code that executes inside consensus, maintains persistent state, and settles value according to rules defined by third parties (the model popularized by Ethereum and replicated across dozens of chains).

**Verdict:** Programmability is **technically achievable in the abstract**, but **not compatible with Permawrite's fused privacy-and-permanence mission without material sacrifices to both**. The implementation cost would dwarf every milestone shipped to date, the economic model has no natural home for unbounded compute state, and the upside does not justify diluting what makes this network distinct. **Permawrite should not add smart contracts.**

See also: [`ARCHITECTURE.md`](./ARCHITECTURE.md) (design pillars, `apply_block`), [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md) (why one chain), [`PRIVACY.md`](./PRIVACY.md) (RingCT constraints), [`GLOSSARY.md`](./GLOSSARY.md) (EVM: not used), [`PROBLEMS.md`](./PROBLEMS.md) (complexity and incentive holes), [`ROADMAP.md`](./ROADMAP.md) (current milestone focus).

---

## 1. What the codebase actually is today

Permawrite is not a "blockchain with storage bolted on." It is a **fixed state-transition function** — a carefully bounded pure function `next_state = apply_block(prev_state, block)` — whose only job is to move confidential value and register irreversible storage commitments under PoS finality.

### 1.1 No execution engine

The [`GLOSSARY`](./GLOSSARY.md) states plainly: **EVM — not used. Permawrite has no general-purpose VM by design.** That is not an omission waiting for a milestone; it is [design pillar 4](./ARCHITECTURE.md#design-pillars): privacy-transaction fees fund permanence, and **there is no separate compute layer to monetize.**

Every block body today contains exactly these executable payloads:

| Section | Role |
|---|---|
| `txs` | RingCT transfers; optional `StorageCommitment` per output; opaque `extra` bytes |
| `bond_ops` | Validator register / unbond |
| `slashings` | Equivocation evidence |
| `storage_proofs` | SPoRA audit responses |

There are no opcodes, no contract addresses, no call frames, no revert semantics, and no metered interpreter loop inside [`apply_block`](../mfn-consensus/src/block/apply.rs). The function validates cryptography, updates UTXO and storage registries, settles treasury flows, and stops.

### 1.2 Transactions are UTXO + ZK, not accounts + scripts

[`TransactionWire`](../mfn-consensus/src/transaction/wire.rs) is a Monero-shaped object: CLSAG ring inputs, Pedersen outputs, Bulletproof range proofs, stealth one-time addresses. Value lives in **outputs**, not **accounts**. The only structured extension beyond money is `TxOutputWire::storage: Option<StorageCommitment>` — a permanence binding, not executable logic.

The `extra` field is preimage-committed metadata (authorship claims, wallet hints). Nodes do not interpret it as code. Nothing in the mempool or verifier dispatches on `extra` contents beyond Merkle inclusion in the claims layer.

### 1.3 WASM exists — off-chain only

[`mfn-wasm`](./M4_WASM.md) compiles wallet, scan, transfer-build, and header-verify helpers for browsers. That WASM runs **in the user's host**, talking to `mfnd` over JSON-RPC. It is a client packaging choice, not an on-chain runtime. Conflating the two is a category error: shipping `wasm32` artifacts for extensions does not imply the chain should execute arbitrary modules at consensus depth.

### 1.4 Determinism is already precious

Permawrite's determinism contract — integer math, canonical MFBN-1 bytes, ordered map iteration, forbidden `unsafe` in workspace code — exists so two independent implementations replay history identically. The counterfeit-input attack closed in M0 is the canonical reminder: **one subtle state-transition bug is economically catastrophic.** A general-purpose VM multiplies that surface by orders of magnitude.

---

## 2. What adding smart contracts would require

"Smart contracts" is not one feature. It is a **platform inside the platform**: language semantics, metering, persistent state, deployment, upgrades, reentrancy rules, event logs, and a wallet UX that understands contract ABIs. Mapped onto this repository, a credible integration would need at least the following.

### 2.1 A consensus-critical virtual machine

Choose a bytecode target (EVM, WASM subset, Move, custom stack machine). Implement:

- Deterministic execution with explicit gas / step limits per block
- Canonical encoding of contract code and state slots
- `CALL` / `DELEGATECALL`-style inter-contract dispatch or an equivalent
- Revert and partial-state rollback semantics that every node agrees on

None of this exists. The closest primitive — SPoRA's `chunk_index = H(prev_block_id, slot, commit_hash) mod num_chunks` — is a **single pure derivation**, not a programmable environment.

### 2.2 A second state tree (or a breaking redesign)

RingCT chains naturally think in **UTXO sets + key images + storage registries**. Contract platforms think in **accounts with nonce-ordered calls and contract storage trie slots.**

Bridging the models is the hard part:

| Approach | Privacy impact | Engineering cost |
|---|---|---|
| **Transparent contract accounts beside RingCT** | High — public contract state, public balances, taint segregation | Medium VM work; breaks "confidentiality by default" |
| **Private contracts (encrypted state + ZK proofs of correct transition)** | Lower on-chain leakage | Very high — new proof system, orders of magnitude beyond Tier 3 OoM roadmap |
| **Covenants / script hooks on UTXOs only** | Moderate — limited expressivity | Medium — still new verifier, still expands `apply_block` |
| **Optimistic rollups / validiums anchored to Permawrite** | Depends on rollup design | External system; not "smart contracts on Permawrite" |

There is no free lunch. Ethereum's account model and Monero's output model were designed for different threat models. Permawrite deliberately chose the latter.

### 2.3 New transaction types and block real estate

Contract deployment, calls, and delegate interactions need wire formats, mempool policy, and Merkle commitments in the header. Block space is already contested among:

- Privacy transfers (heavy CLSAG + Bulletproofs)
- Storage uploads (endowment enforcement)
- SPoRA proofs (permanence audits)
- Bond ops and slashings

Every byte of contract execution competes with proofs that **pay operators to keep bytes alive.** There is no protocol-level reason to prioritize arbitrary compute over SPoRA inclusion.

### 2.4 Economic metering

Ethereum's gas market prices **ephemeral computation**. Permawrite's fee split sends **90% to the storage treasury** to fund decades-long retention ([`ECONOMICS.md`](./ECONOMICS.md)). A contract layer needs:

- Ongoing state rent or one-time capitalizations for **every storage slot forever**, mirroring upload endowments — or acceptance that contract state is second-class and prunable (which contradicts "permanence as consensus invariant")
- A clear answer to who pays validators for re-executing historical contracts on sync
- Protection against compute DoS without weakening light-client assumptions

Bolting Ethereum-style gas onto the existing treasury loop would either starve SPoRA rewards or require a second fee market that splits user attention and dilutes the privacy-to-permanence flywheel.

### 2.5 Wallet, RPC, mempool, light-client, and audit surface

Every layer above `mfn-consensus` assumes **transfer + upload + claim** flows. Contract support implies:

- ABI encoding in `mfn-wallet` / `mfn-cli` / `mfn-wasm`
- Simulation / eth_call equivalents in `mfn-rpc`
- Mempool ordering policy (MEV-sensitive)
- Light clients that either trust contract state roots they cannot verify cheaply or download full execution traces

[`PROBLEMS.md § 8`](./PROBLEMS.md#8-extreme-complexity-and-large-attack-surface) already documents the protocol as composing Monero-grade privacy, Arweave-style permanence, custom PoS, multiple Merkle roots, and PPB yield arithmetic. Adding a VM is not an incremental module; it is a **second product** sharing a genesis hash.

---

## 3. How hard would it be?

Rough orders of magnitude relative to the current workspace (14 crates, M7 posture, green CI on three OSes):

| Workstream | Relative effort | Notes |
|---|---|---|
| Minimal transparent VM (no privacy integration) | **Tier 5+ / multi-year** | New crate, new spec, new golden vectors, new audit |
| Private-contract ZK layer | **Research-grade** | Beyond Tier 4 SNARK aggregation in roadmap |
| UTXO covenants only | **Large fork** | Limited DeFi; still new verifier discipline |
| "Just use `extra` bytes" | **Illusory** | Without consensus execution rules, `extra` is inert data |
| Client-side contracts anchored by timestamp | **Already possible** | Sign claims in `extra`; no chain execution needed |

For calibration: M0–M7 delivered the entire privacy chain, SPoRA, validator rotation, daemon, wallet, operator loop, and WASM bindings across **years of milestone granularity** documented in [`ROADMAP.md`](./ROADMAP.md). A production-grade contract platform is comparable to **building Ethereum again**, except with the additional constraint of not breaking RingCT — which is precisely where the cost explodes.

**Honest difficulty rating:** an order of magnitude harder than the casino-randomness extension analyzed in [`CASINO_RANDOMNESS_FEASIBILITY.md`](./CASINO_RANDOMNESS_FEASIBILITY.md). That proposal reused delayed entropy and treasury math; it still received a "do not prioritize" verdict. Smart contracts require inventing an entire execution economy.

---

## 4. Upside — and why it is insufficient here

### 4.1 What proponents usually want

- Automated escrow, multisig beyond manual CLSAG workflows
- DeFi primitives (AMMs, lending, stablecoins)
- DAOs and on-chain governance
- NFT-like ownership registries (Permawrite already anchors `data_root`; authorship claims cover voluntary attribution)
- Composable apps that keep state synchronized without trusted servers

These are real use cases. They are also **already served** by chains optimized for compute, at the cost of transparency and with permanence models Permawrite explicitly rejects (renewable deals, off-chain pinning, subscription storage).

### 4.2 What Permawrite would gain

- **Developer mindshare** in the EVM ecosystem — at the price of becoming "yet another contract chain," a crowded market with entrenched network effects
- **Treasury inflows** from DeFi fees — speculative, regulator-sensitive, and redundant with the stated thesis that **privacy transaction volume** funds storage ([`PROBLEMS.md § 2`](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume))
- **Expressivity** for apps that need both private cash and permanent blobs — partially achievable today by combining confidential transfers, storage uploads, and signed claims without Turing-complete chain code

### 4.3 What Permawrite would not gain

- Stronger SPoRA guarantees
- Better ring privacy or Tier 3 OoM proofs
- Cheaper endowments or clearer permanence accounting
- Simpler validator or operator economics

Smart contracts are orthogonal to the project's reason for existing. They do not make archival data more durable; they do not make ring signatures more anonymous. They add a third mission — **general computation** — that competes for block space, engineering attention, and narrative clarity.

---

## 5. Privacy: real sacrifices, not cosmetic trade-offs

Permawrite's [design pillar 2](./ARCHITECTURE.md#design-pillars) is **confidentiality by default.** Smart contracts, as the industry implements them, assume the opposite default.

### 5.1 Public state is the norm

Contract storage slots, event logs, and ERC-20-style balances are world-readable. That is a feature for auditors and a bug for whistleblowers, clinics, journalists, and anyone whose [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md) use case requires **funding permanence without a funding confession.** A transparent contract layer reintroduces the exact surveillance graph Permawrite removes from uploads and transfers.

### 5.2 Private contracts do not rescue the default path

Fully private execution (encrypted calldata, ZK proof that a state transition was valid) is an active research area with **no production template** at Monero-grade maturity. Shipping it on Permawrite would delay or derail the Tier 2–4 privacy roadmap ([`ROADMAP.md`](./ROADMAP.md)) while still leaking metadata (gas usage, call timing, contract deployment graph) through the mempool — the same network-layer concerns documented in [`PRIVACY.md`](./PRIVACY.md) and [`SECURITY_CONSIDERATIONS.md`](./SECURITY_CONSIDERATIONS.md).

### 5.3 Fungibility and taint

[`FUNGIBILITY.md`](./FUNGIBILITY.md) explains why traceable ledgers create "clean" and "dirty" coins. A transparent contract sub-protocol would partition the UTXO set into **privacy coins** and **program-interaction coins**, reintroducing merchant discrimination and exchange delisting pressure — the antithesis of a single confidential cash layer.

### 5.4 MEV and ordering

Even with private amounts, **public contract entrypoints** invite ordering games: validators and producers gain extractable value from transaction sequencing. Permawrite's PoS producers already have latency advantages in SPoRA ([`PROBLEMS.md § 6`](./PROBLEMS.md#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race)); adding DeFi-style MEV supercharges centralization pressure without helping storage operators.

### 5.5 Regulatory and reputational coupling

A privacy-preserving ledger plus a on-chain casino or DeFi engine is high scrutiny ([`CASINO_RANDOMNESS_FEASIBILITY.md`](./CASINO_RANDOMNESS_FEASIBILITY.md) § 6.4). Smart contracts amplify that surface: token launches, sanctions evasion narratives, and "mixer with apps" framing — all without improving human-rights-shaped permanence.

**Privacy verdict:** any mainstream smart-contract integration **weakens** Permawrite's core guarantee. A hypothetical private-contract research track might preserve privacy in theory but at a cost and timeline incompatible with the current project — and would still sacrifice simplicity.

---

## 6. Permanence: real sacrifices, not a free compute layer

### 6.1 Two kinds of "storage," one treasury

Permawrite permanence means: **capitalized endowment + on-chain registry + SPoRA audits + operator rewards from the shared treasury.** Contract bytecode and storage slots are also bytes — but they carry **no endowment formula**, no `min_replication`, and no SPoRA challenge tying their retention to economic enforcement.

If contract state is not funded like `StorageCommitment`, it is **not permanent**; it is chain history that full nodes may prune or deprioritize. If it *is* funded like uploads, every contract interaction becomes an endowment-priced capital event — unusably expensive and contrary to how developers expect gas to work.

There is no coherent third option inside the existing permanence equation ([`STORAGE.md`](./STORAGE.md), [`ECONOMICS.md § 1`](./ECONOMICS.md#1-the-permanence-equation-derived)).

### 6.2 Block space is the permanence budget

Blocks must include SPoRA proofs so operators get paid and commitments stay audited. Contract execution consumes the same bounded block body. Under load, producers rationally prefer high-fee contract calls over storage proofs unless consensus **mandates** proof inclusion — another new rule set.

Permanence degrades when audits are crowded out. That is not hypothetical; it is the same resource contention every dual-purpose chain faces, except Permawrite's second purpose is not generic compute but **decades-long byte retention.**

### 6.3 State growth without a retention story

[`PROBLEMS.md § 7`](./PROBLEMS.md#7-state-growth-is-fundamentally-linear-with-usage-and-difficult-to-prune) notes that storage commitments and the privacy UTXO set already force linear state growth. Contract state adds **hot, mutable** trie data with no SPoRA analogue — nobody proves they still store last year's contract slot; they simply replay it from chain history.

Full nodes already bear heavy sync costs. Light clients mitigate verification, not archival obligation for operators holding **user files.** Contract state bloat helps neither.

### 6.4 Misaligned incentives revisited

Storage operators earn from SPoRA on **file commitments**. Validators earn from fees and emission. Contract-heavy networks shift operator attention toward RPC infrastructure and MEV capture, not cold archival. [`PROBLEMS.md § 4`](./PROBLEMS.md#4-producer-and-storage-operator-incentives-are-only-loosely-aligned) already flags loose alignment; smart contracts widen the gap.

**Permanence verdict:** on-chain programmability **diverts** resources and narrative from the endowment + SPoRA model. It does not extend permanence to new data classes; it introduces a second, poorly funded data class that undermines the first.

---

## 7. Could anything smaller work?

Not every "programmable" idea requires a VM. Permawrite already supports **composition without Turing completeness:**

| Mechanism | What it enables | Smart contract needed? |
|---|---|---|
| Confidential transfers | Private payments, escrow via manual multisig workflows | No |
| `StorageCommitment` on outputs | Immutable data anchoring with endowment | No |
| Authorship claims in `extra` | Voluntary signed attribution to `data_root` | No |
| Deterministic `apply_block` checks | Protocol rules, not user code | Already present |
| Client-side WASM (`mfn-wasm`) | Rich wallets, local verification | No — by design |
| Threshold / multisig CLSAG (future) | Shared custody | Wallet feature, not chain VM |

If an application needs arbitrary off-chain logic with on-chain timestamps, it can **hash rules in claims**, settle disputes socially or legally, and use Permawrite for what the chain is good at: **private money and permanent blobs.** That pattern preserves both pillars.

Covenant-style output constraints (Bitcoin-style) remain a theoretical middle ground. They would still be a **consensus fork** with privacy side effects and would not deliver the DeFi ecosystem people usually mean by "smart contracts." The cost/benefit is poor unless a specific, privacy-preserving covenant is identified — none has been proposed for this project.

---

## 8. Structural feasibility summary

| Dimension | Assessment |
|---|---|
| **Technically impossible?** | No — industry has many existence proofs |
| **Compatible with current STF without fork?** | No |
| **Fits existing tx model?** | Poorly — UTXO+RingCT ≠ account+EVM |
| **Preserves confidentiality by default?** | **No** for standard designs |
| **Preserves permanence economics?** | **No** — unfunded state vs endowment registry |
| **Implementation cost vs M0–M7** | **Much larger** than all shipped milestones combined |
| **Strengthens differentiated value?** | **No** — commoditized compute layer |
| **Recommended for Permawrite** | **No** |

---

## 9. Conclusion — do not do this

Permawrite occupies a deliberate niche: **Monero-grade confidential cash and Arweave-shaped permanence in one deterministic chain**, with privacy fees feeding the treasury that pays operators to answer SPoRA challenges. That niche is already at the edge of what a small team can implement and audit.

General-purpose smart contracts are the opposite design bet. They trade transparency and unbounded mutable state for composability — valuable on chains that optimize for compute, hostile to a network whose pillars are **hidden amounts** and **irreversible storage commitments with capitalized liability.**

Adding them would:

1. **Sacrifice privacy** — via public contract state, taint segregation, mempool metadata, and MEV, unless one pursues private-contract cryptography that the roadmap does not schedule and the team should not pretend is near-term.
2. **Sacrifice permanence focus** — by consuming block space, splitting economic attention, and growing state that the endowment/SPoRA apparatus was never built to retain.
3. **Sacrifice engineering focus** — by forcing a multi-year VM program while multi-node testnet, wallet UX, operator bonding, and Tier 2–4 privacy upgrades remain the actual critical path.

The upside — DeFi volume, developer familiarity, "programmable money" marketing — is real on other networks. It is **not worth** converting Permawrite into a third-rate Ethereum clone with extra steps, weaker privacy than Monero, and weaker permanence accounting than the current upload path.

**Determination:** Permawrite **should not** add smart contracts as a protocol feature. Document alternatives (claims, storage bindings, client-side logic, confidential transfers) for application developers. Revisit only if the project explicitly abandons the fused privacy-and-permanence mission — at which point it would be a different chain, not an upgrade to this one.

---

## See also

- [`ARCHITECTURE.md § Design pillars`](./ARCHITECTURE.md#design-pillars) — no compute layer by design
- [`OVERVIEW.md`](./OVERVIEW.md) — why privacy + permanence belong together
- [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md) — fused network rationale
- [`CASINO_RANDOMNESS_FEASIBILITY.md`](./CASINO_RANDOMNESS_FEASIBILITY.md) — smaller protocol extension, same "reject" posture
- [`PROBLEMS.md`](./PROBLEMS.md) — complexity, treasury dependence, state growth
- [`M4_WASM.md`](./M4_WASM.md) — off-chain WASM scope (not on-chain execution)
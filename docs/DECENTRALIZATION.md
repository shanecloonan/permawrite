# Decentralization and hardware

**Question:** What hardware does it take to participate in Permawrite, how does that shape decentralization, and what can be improved without changing the protocol's core architecture?

**Short answer:** Permawrite deliberately splits the network into roles with very different hardware profiles. Validators need always-on, well-connected machines and a bonded stake; storage operators, wallet users, and observers can run on ordinary consumer gear. The architecture already separates consensus security from permanence breadth — future work should widen the operator funnel, not merge those roles back into datacenter-grade requirements.

See also: [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) (storage-operator deep dive), [`ARCHITECTURE.md`](./ARCHITECTURE.md) (design pillars), [`PROBLEMS.md`](./PROBLEMS.md) (honest centralization pressures).

---

## 1. What decentralization means here

Decentralization is not a single knob. For Permawrite it has at least four independent dimensions:

| Dimension | What “decentralized” looks like | Primary lever |
|---|---|---|
| **Consensus** | Many independent validators produce and finalize blocks; no single operator can censor or rewrite history | Validator count, stake distribution, churn policy |
| **Storage** | Many independent operators hold replicas and answer SPoRA audits | Operator count, geographic spread, replication factor |
| **Verification** | Anyone can follow the chain and check proofs without trusting a single RPC | Light clients, public observers, WASM verification |
| **Economics** | Fee and emission flows do not concentrate in one class of participant | Treasury split, direct operator payouts, bond/slash loop |

A network can be decentralized in one dimension and concentrated in another. Permawrite's architecture explicitly trades off between them: validators are **intentionally** more expensive to operate than storage operators, because liveness and finality security are harder problems than holding bytes and answering occasional audits.

---

## 2. Network roles and hardware profiles

Permawrite has five practical participation tiers. Pick the lightest role that matches your goal; you do not need validator hardware to use the chain, store data, or earn storage rewards.

### 2.1 Role summary

| Role | Software | Typical hardware | Uptime | Stake / bond | Decentralization impact |
|---|---|---|---|---|---|
| **Wallet user** | `mfn-cli`, browser WASM (`mfn-wasm`) | Phone, laptop, any device with a browser | Intermittent | None | High user count; privacy and fee demand |
| **Light client** | `mfn-light` (WASM/mobile) | Phone, tablet, low-RAM laptop | Intermittent | None | Trust-minimized verification without full sync |
| **Observer** | `mfnd serve` (no validator env) | Laptop, small VPS, Raspberry Pi class | Medium–high | None | Public RPC, chain health monitoring, P2P relay |
| **Storage operator** | `mfn-storage-operator` + `mfn-cli` | Laptop, NAS, home server, small VPS | Medium (prove window) | **None today** | Direct permanence decentralization |
| **Validator** | `mfnd serve` + `--produce` + validator keys | Dedicated server or reliable VPS | **High** (liveness slashing) | Bond required (M1) | Consensus decentralization |

### 2.2 Wallet user and light client

**Hardware needed:** Any device that can run a wallet or verify headers.

| Resource | Requirement | Notes |
|---|---|---|
| **CPU** | Low | CLSAG/Bulletproof *creation* is heavier than verification; light clients verify, wallets sign |
| **RAM** | ~100–500 MiB for WASM/light follower | No full `ChainState`; header chain + trusted validator set |
| **Disk** | Wallet file + local upload artifacts only | No chain archive required |
| **Network** | Intermittent RPC access | Can use any synced observer's JSON-RPC |

Light clients (`mfn-light`) follow the header chain with cryptographic verification — no RocksDB, no libp2p, no full UTXO tree. This is the path to mobile and in-browser wallets that do not depend on a trusted full node for header authenticity. See [`M2_LIGHT_CHAIN.md`](./M2_LIGHT_CHAIN.md) and [`M2_LIGHT_VALIDATOR_EVOLUTION.md`](./M2_LIGHT_VALIDATOR_EVOLUTION.md).

**Decentralization impact:** Every independent verifier reduces reliance on a single RPC operator. A phone that verifies its own tip is a decentralization win even if it never produces a block.

### 2.3 Observer (full node, non-validating)

**Hardware needed:** A modest always-on machine.

| Resource | Requirement | Notes |
|---|---|---|
| **CPU** | 2+ cores, continuous block verify | `apply_block` per block; no VRF/BLS signing unless producing |
| **RAM** | Grows with chain state | Full `ChainState`: UTXO accumulator, storage registry, validator set, treasury |
| **Disk** | Grows with chain history + optional chunk inbox | State is linear in uploads and privacy activity; no payload bytes unless opted in |
| **Network** | Stable P2P + optional public RPC | Devnet scripts run observers on loopback; production observers often use small VPS |

Observers sync the full chain, serve JSON-RPC, and relay P2P — but they do not sign blocks or carry slashing risk. Public devnet launches a fourth observer alongside three validators ([`TESTNET.md`](./TESTNET.md)).

**Decentralization impact:** Independent observers are the infrastructure layer wallet users and storage operators depend on. Many observers in many jurisdictions make censorship and RPC manipulation harder.

### 2.4 Storage operator

**Hardware needed:** Consumer-grade gear; see [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) for the full assessment.

| Resource | Minimal operator | Full replica operator |
|---|---|---|
| **CPU** | Periodic proof build (~seconds/day) | Same + optional HTTP chunk server |
| **RAM** | Wallet + one file's Merkle tree | Same |
| **Disk** | Payloads the operator chooses to hold | Scales with corpus size, not protocol rules |
| **Uptime** | Must prove within `proof_reward_window_slots` (~1 day default) | Same |
| **Stake** | None today | None today |
| **Network** | Reach **any** synced RPC to submit proofs | HTTP/P2P for replication to peers |

Key architectural facts that keep storage hardware cheap:

1. **Off-chain bytes, on-chain commitment.** Uploads anchor an 81-byte `StorageCommitment`; payloads live wherever the operator stores them.
2. **Lightweight SPoRA proofs.** ~256 KiB of chunk data + `O(log num_chunks)` hashes; microseconds to verify ([`STORAGE.md`](./STORAGE.md)).
3. **Separate role from validator.** No VRF/BLS keys, no block production, no validator bond.
4. **Direct operator payouts.** Accepted proofs mint to the operator's keys — not only to the block producer ([`ECONOMICS.md § 7`](./ECONOMICS.md#7-storage-operator-economics)).
5. **Observer RPC suffices.** An operator can point `mfn-storage-operator` at a public observer; running `mfnd` is optional.

A laptop, always-on NAS, or small VPS is sufficient. The protocol math does not require GPUs, packed mining disks, or specialized recall hardware (contrast with Arweave's mining model — see [`STORAGE_ACCESSIBILITY.md § 1`](./STORAGE_ACCESSIBILITY.md#1-why-arweave-feels-hardware-gated-and-permawrite-does-not)).

**Decentralization impact:** This is the primary lever for permanence decentralization. A healthy network needs **many small holders**, not three datacenters, to satisfy `min_replication = 3` and beyond.

### 2.5 Validator (producer + finality)

**Hardware needed:** The most demanding role.

| Resource | Requirement | Notes |
|---|---|---|
| **CPU** | Continuous block verify + periodic VRF lottery + BLS signing | Every slot: verify incoming blocks; when elected, produce and sign |
| **RAM** | Full chain state | Same as observer, plus validator secrets in process memory |
| **Disk** | Full node store | Grows with chain; optional `chunk-inbox/` for local SPoRA participation |
| **Uptime** | **High** | Liveness slashing after `liveness_max_consecutive_missed` consecutive absences |
| **Network** | Low-latency, stable P2P | Peers must reach you for block propagation and finality votes |
| **Stake** | Bond via `BondOp::Register` | Burned into treasury on registration; slashable during operation and unbond delay |

Validators carry two keypairs (VRF for leader election, BLS for finality) and are subject to equivocation and liveness slashing ([`CONSENSUS.md`](./CONSENSUS.md)). Per-epoch churn caps bound how fast the set can rotate.

**Decentralization impact:** Validator count and stake distribution determine censorship resistance and finality safety. This role will always be more capital- and uptime-intensive than storage — by design.

---

## 3. How hardware shapes decentralization

### 3.1 Intentional role separation

Permawrite's central decentralization bet is **separating roles with different hardware envelopes**:

```text
Validators     →  security + ordering  →  higher uptime, bond, connectivity
Storage ops    →  permanence breadth   →  consumer disk, no bond, periodic prove
Light clients  →  verification access  →  phone-scale RAM, intermittent network
```

Merging storage into validator duties (as Arweave's mining model effectively does) would raise the hardware floor for *everyone who stores data*. Permawrite explicitly rejected that trade: Merkle SPoRA proofs verify in microseconds on every node, which is what makes consumer storage viable without ZK prover GPUs ([`STORAGE.md § Why we don't use ZK SNARKs`](./STORAGE.md#why-we-dont-use-zk-snarks-here-yet)).

**Design principle:** keep validators expensive-enough for security, keep storage operators cheap-enough for breadth.

### 3.2 Centralization pressures (honest)

Hardware accessibility is necessary but not sufficient. Documented pressures that remain:

| Pressure | Mechanism | Hardware angle |
|---|---|---|
| **Validator stake concentration** | Bond-on-register + liveness requirements | Capital barrier, not CPU barrier |
| **SPoRA latency race** | First valid proof to a producer wins | Favors low-latency paths to producers ([`PROBLEMS.md § 6`](./PROBLEMS.md#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race)) |
| **State growth** | Permanent `StorageCommitment` entries + privacy UTXO set | Full nodes need more disk over time ([`PROBLEMS.md § 7`](./PROBLEMS.md#7-state-growth-is-fundamentally-linear-with-usage-and-difficult-to-prune)) |
| **Fee-volume dependence** | Treasury funds storage; fees fund treasury | Economic, not hardware — but low fees mean fewer operators can justify disk |
| **Weak operator defection penalty** | No bonds/slashing for storage operators today | Easy entry, easy exit — good for accessibility, weaker for SLA |
| **Replication floor** | `min_replication = 3` at upload | Needs ≥3 independent operators per file, not 3 machines in one rack |

None of these require abandoning the architecture. They are tuning, packaging, and optional protocol upgrades on top of the existing role split.

### 3.3 Mitigations without weakening privacy or permanence

Each pressure in §3.2 has a **packaging-first** path that preserves absolute privacy and absolute permanence (§8). Protocol changes are optional and deferred unless noted.

| Pressure | Packaging / ops (shipped or partial) | Protocol (deferred) | Declined shortcuts |
|---|---|---|---|
| **Stake concentration** | Public devnet runbooks, prebuilt binaries, validator onboarding docs | Lower bond floor (weakens per-validator security) | Remove validator bonds |
| **SPoRA latency race** | RPC-only operators, many observers, `push-all-chunks` replication breadth | Latency-fair inclusion (Phase C) | Skip SPoRA verification |
| **State growth** | Observer vs validator role docs; light clients avoid full state | Checkpoint distribution (research) | On-chain payloads |
| **Fee-volume dependence** | Privacy UX, WASM wallet path — drives fee demand | — | Subsidize storage by dropping `min_replication` |
| **Weak operator defection** | Bondless entry preserves accessibility; direct operator payouts | Tiered bonding (optional premium tier) | Merge storage into validators |
| **Replication floor** | Manifest `replication_peers`, `push-chunks`, `push-all-chunks` | Erasure-coded replication (research) | Drop `min_replication` |

### 3.3 What good decentralization looks like in practice

A maximally decentralized Permawrite deployment would exhibit:

- **Tens to hundreds of validators** with no single entity above ~15–20% effective stake (aspirational; not a protocol constant).
- **Thousands of storage operators** on home NAS, laptops, and small VPS across many regions — each holding a small slice of the corpus.
- **Many public observers** so wallet users are not captive to one RPC provider.
- **Light-client verification** in every wallet so users do not trust RPC responses for header authenticity.
- **Sustained privacy transaction volume** so the treasury can fund operators without relying solely on tail emission.

---

## 4. Improvements without sacrificing architecture

Everything below preserves the seven design pillars in [`ARCHITECTURE.md`](./ARCHITECTURE.md): determinism, confidentiality, permanence as consensus invariant, privacy-revenue funds permanence, no `unsafe`, audited libraries, hard-fork-by-design.

### 4.1 Product and packaging (no protocol change)

These widen participation by lowering the **skill and friction** barrier, not the hardware floor:

| Improvement | Who benefits | Status / next step |
|---|---|---|
| **Prebuilt release binaries** for `mfnd`, `mfn-cli`, `mfn-storage-operator` | All roles | **Shipped** — tag `v*` triggers [release-binaries workflow](../.github/workflows/release-binaries.yml) |
| **One-command storage daemon** | Storage operators | **Shipped** — `scripts/public-devnet-v1/start-storage-operator.{sh,ps1}`; daemon logs artifact count + `--json` cycles |
| **WASM prove + serve** | Storage operators, wallet users | **Shipped** — `mfn-wasm`: `buildStorageProof`, `verifyStorageProof`, `storageChunkHex` ([Phase B](./STORAGE_ACCESSIBILITY.md#phase-b--consumer-ux-still-no-consensus-change)) |
| **Mobile / PWA wallet** | Wallet users, light operators | **Deferred** — WASM prove path unblocks browser operators; full PWA is product scope |
| **Document RPC-only operator path** | Storage operators | **Shipped** — [`mfn-storage-operator` README](../mfn-storage-operator/README.md), manifest defaults, TESTNET role table |
| **Curated peer lists → discovery registry** | Uploaders, operators | **Partial** — manifest peers + `push-all-chunks`; on-chain registry deferred |

A phone holding artifacts and proving on a schedule is a packaging problem today, not a consensus problem. The protocol math already permits it.

### 4.2 Operational accessibility (no protocol change)

| Improvement | Effect | Status |
|---|---|---|
| **Public observer mesh** | Operators and wallets anywhere can use community RPC without running `mfnd` | **Partial** — manifest `observer_rpc`; community lists deferred |
| **NAT traversal / relay helpers** | Home operators can serve chunks without static IPs | **Partial** — HTTP chunk serve + tunnel runbook ([OPERATORS.md](../scripts/public-devnet-v1/OPERATORS.md#home-chunk-serve-behind-nat)); no in-protocol relay |
| **Erasure-friendly replication UX** | Encourage many partial holders even before protocol-level erasure coding | **Shipped** — `push-chunks`, `push-all-chunks`, manifest `replication_peers` |
| **Regional operator onboarding** | Runbooks, translated docs, low-bandwidth artifact fetch | **Partial** — [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) + TESTNET; translation deferred |

### 4.3 Optional protocol upgrades (architecture-preserving)

These change consensus parameters or inclusion rules but do **not** require merging validator and storage roles, abandoning SPoRA, or moving payloads on-chain:

| Upgrade | Decentralization benefit | Tradeoff |
|---|---|---|
| **Latency-fair proof inclusion** (commit-reveal, VRF-weighted selection, proof pools) | Reduces datacenter advantage in SPoRA races | Added block-space complexity |
| **Tiered operator model** | Bondless “best effort” default + optional bonded “premium” tier with slashing | Higher friction for premium SLA |
| **Erasure-coded replication (research)** | Many nodes store a fraction each; SPoRA attests recoverability | Protocol research; must preserve deterministic verification |
| **Light-client checkpoint distribution** | Cheaper bootstrap for phones | Trust anchor for checkpoint publisher |
| **Lower validator bond floor (parameter change)** | More validator candidates | Weaker per-validator economic security |

Explicitly **deferred** because they would raise hardware floors: aggregated SNARK audits (GPU provers), on-chain payload storage, PoW-style recall mining.

### 4.4 What not to do

Sacrificing the architecture for “cheaper hardware” usually backfires:

- **Merging storage into validator duties** → raises minimum hardware for all storers to validator grade.
- **On-chain payloads** → explodes block size and full-node disk; kills light clients.
- **Eliminating `min_replication`** → reduces disk cost but weakens permanence guarantees.
- **Removing validator bonds** → lowers capital barrier but weakens slash-to-treasury security loop.

---

## 5. Universal hardware truths

Some costs are fundamental to permanent storage networks, not Permawrite-specific:

1. **Disk is proportional to data kept.** Permanence means someone stores the bytes. Consumer accessibility means *many small holders*, not *zero bytes*.
2. **Always-on-ish availability.** SPoRA challenges arrive every block; operators who disappear longer than the anti-hoarding window stop earning ([`STORAGE.md § Anti-hoarding cap`](./STORAGE.md#anti-hoarding-cap-proof_reward_window_slots)).
3. **Validator liveness is stricter than operator liveness.** Consensus slots are continuous; storage proofs are periodic.
4. **Privacy cryptography has a floor.** Ring signatures and Bulletproofs are cheap to verify but not free; Tier 3 OoM proofs add cost that light clients must budget for.
5. **Kryder's law is an economic assumption, not a hardware shortcut.** Deflation-funded permanence (`real_yield_ppb = 0`) assumes storage costs fall over decades — it does not remove today's disk bill.

---

## 6. Recommended priority

Aligned with [`STORAGE_ACCESSIBILITY.md § 5`](./STORAGE_ACCESSIBILITY.md#5-recommended-roadmap-priority-order) and [`ROADMAP.md`](./ROADMAP.md):

### Phase A — Make existing paths obvious
1. ~~Cross-link all role docs~~ **Done** (TESTNET, OPERATORS, CONSENSUS, PROBLEMS → this page).
2. ~~Ship prebuilt binaries~~ **Done** (tag `v*` release workflow).
3. ~~One-command wrappers~~ **Done** (`start-storage-operator.{sh,ps1}`).

### Phase B — Consumer UX
4. ~~WASM prove + serve~~ **Done** (`buildStorageProof`, `verifyStorageProof`, `storageChunkHex`).
5. Mobile light-client wallet with background prove loop — **Deferred** (product scope).
6. Replication discovery — **Partial** (manifest peers + push-all-chunks; on-chain registry deferred).

### Phase C — Fairness tuning (optional forks)
7. Latency-fair SPoRA inclusion.
8. Tiered operator bonding.
9. Erasure-coded replication research.

---

## 7. Conclusion

| Question | Answer |
|---|---|
| **Can normal hardware participate?** | **Yes** — for wallets, observers, and storage operators. Validators need more uptime and stake, by design. |
| **Does hardware gate decentralization today?** | **Partially.** Storage and verification are architecturally consumer-viable; remaining gaps are mobile/PWA product scope and community observer lists — not protocol math. Validator decentralization is primarily a **capital and uptime** question. |
| **Can accessibility improve without architectural sacrifice?** | **Yes.** Prebuilt binaries, WASM/mobile tooling, public observer meshes, and optional fairness upgrades widen participation while preserving role separation, off-chain payloads, and SPoRA audits. |
| **What is the main risk if we fail?** | Not that home users *cannot* run operators — they can today with CLI tools — but that **too few do**, and latency races + fee droughts concentrate rewards on well-connected incumbents. |

The codebase already separates consensus security from permanence breadth. The path to maximal decentralization is to **lower friction for the cheap roles** (storage, wallets, observers) while **keeping the expensive role** (validators) honestly expensive.

---

## See also

- [`STORAGE_ACCESSIBILITY.md`](./STORAGE_ACCESSIBILITY.md) — consumer storage feasibility vs Arweave
- [`TESTNET.md`](./TESTNET.md) — join as observer, wallet user, storage operator, or validator
- [`OVERVIEW.md`](./OVERVIEW.md) — privacy + permanence vision
- [`CONSENSUS.md`](./CONSENSUS.md) — validator requirements, slashing, rotation
- [`ECONOMICS.md`](./ECONOMICS.md) — fee split, treasury, operator payouts
- [`PROBLEMS.md`](./PROBLEMS.md) — latency races, state growth, incentive gaps
- [`scripts/public-devnet-v1/OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) — production runbook
---

## 8. Privacy and permanence gate

**Absolute privacy** and **absolute permanence** are non-negotiable product pillars ([`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md)). Every item in §4 was evaluated against them:

| Criterion | Must hold | Why improvements can still ship |
|---|---|---|
| **Privacy** | Payload bytes stay off-chain; ring/CLSAG/Bulletproof semantics unchanged; no trusted-RPC shortcuts for header or payment verification | Packaging (binaries, WASM, manifests) lowers friction without moving data on-chain or weakening crypto |
| **Permanence** | `min_replication` unchanged; every node verifies SPoRA proofs deterministically; operator-direct payouts preserved | More independent operators on consumer hardware **increases** replica breadth; we do not “cheapen” permanence by dropping replication |
| **Role separation** | Validators remain bond + liveness gated; storage operators remain bondless + periodic prove | Merging roles or putting payloads on-chain would raise hardware floors and break light clients — explicitly declined (§4.4) |

Centralization pressures in §3.2 (SPoRA latency races, state growth, stake concentration, fee-volume dependence) are **honest limits**, not reasons to weaken the pillars. Phase C protocol tuning (latency-fair inclusion, tiered bonding) may reduce races **without** moving payloads on-chain — but each fork must re-pass this gate.

---

## 9. Implementation log

What was assessed, shipped, deferred, or declined (newest first):

| Item | Verdict | Notes |
|---|---|---|
| §3.3 pressure mitigations table + packaging tranche closure | **Shipped** | Maps each centralization pressure to packaging vs protocol vs declined paths |
| Home chunk serve behind NAT (OPERATORS runbook) | **Partial** | Tunnel guidance; no in-protocol relay |
| `push-all-chunks` replication UX | **Shipped** | Push every local upload artifact to manifest `replication_peers` in one command |
| Role-doc cross-links (CONSENSUS, PROBLEMS, OPERATORS) | **Shipped** | See also links to this page from validator pressures and runbook |
| One-command storage operator wrapper | **Shipped** | `start-storage-operator.{sh,ps1}` — manifest + `OBSERVER_RPC` from local devnet or public RPC |
| Daemon startup artifact scan + JSON logs | **Shipped** | `mfn-storage-operator run --json`; startup logs local artifact count |
| Prebuilt release binaries | **Shipped** | `.github/workflows/release-binaries.yml` (tag `v*`) |
| Operator manifest discovery | **Shipped** | `NetworkManifest`, `MFN_OPERATOR_MANIFEST`, `--manifest`, `manifest-info` |
| Operator env defaults | **Shipped** | `MFN_RPC`, `MFN_WALLET`; RPC-only path — no local `mfnd` required |
| WASM prove + verify + chunk serve | **Shipped** | `mfn-wasm`: `buildStorageProof`, `verifyStorageProof`, `storageChunkHex` |
| Document RPC-only operator path | **Shipped** | README, TESTNET role table, OPERATORS permanence sections |
| Erasure-friendly replication UX | **Shipped** | `push-chunks`, `push-all-chunks`, manifest peers; protocol erasure coding deferred |
| Latency-fair SPoRA inclusion | **Deferred** | Protocol change; reduces datacenter latency advantage (Phase C) |
| Tiered operator bonding | **Deferred** | Optional fork; bondless default preserves accessibility |
| Erasure-coded replication | **Deferred** | Research; must preserve deterministic SPoRA verification |
| NAT traversal / relay | **Partial** | OPERATORS tunnel runbook for home chunk serve; no in-protocol relay |
| Mobile / PWA wallet | **Deferred** | Product scope; browser WASM prove unblocks light operators |
| Curated public observer mesh | **Deferred** | Community ops; manifest documents example endpoints |
| Regional operator onboarding | **Deferred** | Runbooks exist in English; translation/low-bandwidth fetch deferred |
| Light-client checkpoint distribution | **Deferred** | Optional fork; trust anchor for checkpoint publisher TBD |
| Lower validator bond floor | **Deferred** | Parameter change; weakens per-validator economic security |
| On-chain payloads | **Declined** | Explodes block size; kills light clients; breaks privacy envelope |
| Merge storage into validator duties | **Declined** | Raises hardware floor for all storers to validator grade |
| Drop `min_replication` | **Declined** | Weakens permanence guarantees |
| Remove validator bonds | **Declined** | Weakens slash-to-treasury security loop |

### 9.1 Packaging tranche status (2026-07)

All **Phase A** items and the core **Phase B** WASM prove path are **shipped** on `main` (commits `bb9600b` → `c1e0373`). No protocol constants were changed; `min_replication`, off-chain payloads, and SPoRA verification remain intact.

**Remaining work** is explicitly out of scope for this tranche: mobile/PWA wallet (product), public observer mesh (community ops), NAT relay (tunnel docs only — see [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md#home-chunk-serve-behind-nat)), and Phase C fairness forks. Re-assess any new proposal against §8 before implementation.

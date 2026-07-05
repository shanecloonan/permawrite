# Consumer-accessible storage — feasibility assessment

**Question:** Can Permawrite make *storing* permanent data accessible to practically anyone with a normal device — not just operators with datacenter-grade hardware, as on Arweave?

**Short answer:** **Yes, with the current architecture.** The protocol was deliberately designed so storage operators hold bytes off-chain and answer lightweight SPoRA audits. No specialized mining hardware, GPU provers, or exotic disk layouts are required. What remains is mostly **product packaging** (mobile/desktop apps, one-click operators), **discovery** (which peers hold which files), and **incentive tuning** (latency fairness, optional bonding tiers) — not a fundamental redesign.

See also: [`STORAGE.md`](./STORAGE.md) (mechanics), [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) (runbook), [`PROBLEMS.md`](./PROBLEMS.md) (honest gaps).

---

## 0. Plain-language verdict (July 2026)

**SPoRA does not need big computers.** That is the important distinction.

| Role | Hardware reality |
|---|---|
| **Storage operator (SPoRA)** | Consumer gear: old laptop, NAS, Raspberry Pi class, small VPS. |
| **Validator (consensus)** | Dedicated server or reliable VPS. |
| **Uploader (wallet user)** | Any device with a browser or CLI. |

Permawrite **separates** storage operators from validators on purpose.

### What you actually need

1. **Disk** for files you choose to hold.
2. **Occasional uptime** for SPoRA proofs.
3. **Network to any synced RPC** (no `mfnd` required).
4. **No stake or bond today** for casual operators.

See [`OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md) for the RPC-only path.

### Easiest path today (devnet)

```text
observer RPC  ->  backfill/fetch artifact  ->  mfn-storage-operator run  ->  coinbase pays operator keys
```

No validator keys, no block production, no specialized hardware.

### Minimum replication

- **Minimum replication** - uploads require >= 3 independent replicas; one person with one disk is not enough for a *new* upload, but anyone can join as replica #2/#3/#4 after backfill.

**Bottom line:** Making storage participation cheap and common is **architecturally solved** and **operationally partial**. The protocol does not force storers onto validator-grade hardware; the remaining work is packaging, discovery, and fair incentives - not a SPoRA rewrite.

---
## 1. Why Arweave feels hardware-gated (and Permawrite does not)

| Dimension | Arweave (mining model) | Permawrite (SPoRA operator model) |
|---|---|---|
| **Work unit** | Pack random chunks into a Merkle block under PoW-like recall; compete on hashrate + packed storage | Read one challenged 256 KiB chunk + Merkle path when audited |
| **Disk profile** | Large, sequentially-packed replica tuned for random access at mining speed | Ordinary files or chunk directories; any HDD/SSD/NVMe |
| **CPU profile** | Sustained hashing + recall during block production | Microseconds of SHA-256 per proof; no GPU unless a future SNARK tier ships |
| **Network** | Must win block races against other miners | Must reach *any* synced RPC to submit proofs; HTTP/P2P for replication |
| **Role coupling** | Miner Γëê storer Γëê block producer | **Storage operator is a separate role** from validator |

Arweave's permanence economics (endowment + deflation) inspired Permawrite, but the **audit primitive differs**. Permawrite chose Merkle SPoRA proofs because they verify in microseconds on every node ([`STORAGE.md § Why we don't use ZK SNARKs`](./STORAGE.md#why-we-dont-use-zk-snarks-here-yet)) — which is exactly what makes consumer hardware viable.

---

## 2. Architectural verdict

### 2.1 Compatible today (no consensus rewrite needed)

These properties are already in the codebase:

1. **Off-chain bytes, on-chain commitment.** Uploads anchor an 81-byte `StorageCommitment`; payloads live in wallet artifacts, `chunk-inbox/`, or any directory the operator chooses ([`STORAGE.md § StorageCommitment`](./STORAGE.md#2-storagecommitment)).

2. **Lightweight proofs.** A `StorageProof` is ~256 KiB of chunk data plus `O(log num_chunks)` hashes. Building and verifying a proof is standard CPU + disk I/O ([`mfn-storage::spora`](../mfn-storage/src/spora.rs)).

3. **Separate operator tooling.** `mfn-storage-operator` polls RPC, builds proofs from local artifacts, and submits via `submit_storage_proof` — no validator keys required ([`mfn-storage-operator/README.md`](../mfn-storage-operator/README.md)).

4. **Replication without re-upload.** Peers backfill via HTTP (`operator backfill`, `uploads fetch-http`) or P2P `ChunkV1` gossip — a home user can hold a replica without ever uploading the original file.

5. **Direct operator payouts (shipped).** Each `StorageProof` carries `operator_view_pub` / `operator_spend_pub`; accepted proofs mint per-operator coinbase outputs (outputs 1..N) drained from the treasury/backstop ([`mfn-consensus::coinbase`](../mfn-consensus/src/coinbase.rs)). A casual storer is paid on-chain without also winning VRF leader election.

6. **Observer-grade RPC suffices for proving.** An operator can point `mfn-storage-operator` at any synced node's JSON-RPC (e.g. a public observer). Running a full `mfnd` is optional — needed only for P2P inbox replication or serving chunks to peers without a separate HTTP server.

7. **Manifest-based onboarding (shipped M6.8).** `public_devnet_v1.manifest.json` carries optional `observer_rpc` and `replication_peers`. Pass `--manifest` (or `MFN_OPERATOR_MANIFEST`) so `mfn-storage-operator` picks default RPC and peer lists for `push-chunks` without hand-typing addresses.

8. **Prebuilt operator binaries (shipped).** The `release-binaries` workflow builds `mfn-storage-operator` alongside `mfnd` and `mfn-cli` for Linux/macOS/Windows on version tags.

### 2.2 What "normal device" means in practice

| Resource | Validator / producer | Storage operator (minimal) | Storage operator (full replica) |
|---|---|---|---|
| **CPU** | Continuous block verify + optional `--produce` | Periodic proof build (~seconds/day) | Same + optional HTTP chunk server |
| **RAM** | Full chain state in memory | Wallet + one file's Merkle tree | Same |
| **Disk** | Full node store + optional inbox | Payloads the operator chooses to hold | Same; scales with corpus size, not protocol rules |
| **Uptime** | High (liveness slashing) | Must prove within `proof_reward_window_slots` (~1 day default) or forfeit accrual | Same |
| **Stake / bonds** | Validator bond required | **None today** (optional future premium tier) | Same |
| **Software** | `mfnd` release binary | `mfn-storage-operator` + `mfn-cli` (release or Rust builds) | Optional `mfnd serve` for P2P inbox |

A laptop, always-on NAS, or small VPS is sufficient. A phone can participate **once** packaged (see §4); the protocol math does not block it.

### 2.3 Hard limits that are universal (not Permawrite-specific)

- **Disk is proportional to data kept.** Permanence means someone must store the bytes somewhere. Consumer accessibility means *many small holders*, not *zero bytes*.
- **`min_replication = 3`.** The chain requires at least three independent replicas at upload time. A healthy network needs many casual operators, not three datacenters.
- **Always-on-ish proving.** SPoRA challenges arrive every block; operators who disappear for longer than the anti-hoarding window stop earning until they return ([`STORAGE.md § Anti-hoarding cap`](./STORAGE.md#anti-hoarding-cap-proof_reward_window_slots)).
- **State growth.** Every upload adds a permanent `StorageEntry` on-chain. Light clients mitigate *verification* cost, not operator disk for payloads ([`PROBLEMS.md § 7`](./PROBLEMS.md#7-state-growth-is-fundamentally-linear-with-usage-and-difficult-to-prune)).

---

## 3. Current implementation status (devnet-ready path)

The lightest end-to-end path that already works on public devnet:

```text
Connect to observer RPC (no validator env)
       Γåô
operator backfill / uploads fetch-http  ΓåÆ  local wallet artifact
       Γåô
mfn-storage-operator run --once  ΓåÆ  submit_storage_proof
       Γåô
Coinbase pays operator_view/spend keys directly
```

Documented step-by-step in [`OPERATORS.md § Permanence operators`](../scripts/public-devnet-v1/OPERATORS.md#permanence-operators-storage--spora--m6--m7) and rehearsed by `participant-rehearsal` smokes.

**Upload path** is already browser-capable via WASM (`buildStorageUpload` in `mfn-wasm`). **Prove path** is WASM-capable via `buildStorageProof` / `verifyStorageProof` / `storageChunkHex` ([`mfn-wasm/README.md`](../mfn-wasm/README.md)); scheduled prove loops and chunk HTTP serving remain CLI/operator or app-layer glue — not consensus gaps.

---

## 4. Remaining gaps before "anyone with a phone"

These are real but not architectural blockers:

| Gap | Severity for consumer storage | Notes |
|---|---|---|
| **Rust CLI packaging** | High (UX) | Release workflow ships binaries on tags; still no app-store storage daemon. |
| **No WASM/mobile prove loop** | Medium (UX) | **Shipped (bindings)** — `mfn-wasm`: `buildStorageProof`, `verifyStorageProof`, `storageChunkHex`; remaining gap is PWA/mobile scheduling + HTTP serve glue. |
| **Proof latency race** | Medium (decentralization) | First valid proof to a producer wins; favors low-latency paths to block producers ([`PROBLEMS.md § 6`](./PROBLEMS.md#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race)). |
| **Partial operator discovery** | Medium (UX) | Manifest `replication_peers` + `manifest-info` subcommand; no DHT-style "who stores commit X?" |
| **No operator bonds (by design today)** | Low friction / weak SLA | Casual entry is easy; defection penalty is weak ([`PROBLEMS.md § 1`](./PROBLEMS.md#1-storage-operators-have-almost-no-skin-in-the-game-no-bonds-or-slashing)). |
| **Treasury depends on privacy fee volume** | Medium (economics) | Storage payouts ultimately flow from fees + emission backstop ([`PROBLEMS.md § 2`](./PROBLEMS.md#2-r--0-default-makes-permanence-heavily-dependent-on-continuous-high-privacy-transaction-volume)). |
| **TESTNET role table wording** | Documentation only | [`TESTNET.md`](./TESTNET.md) lists "synced node plus operator" — RPC-only operators are valid but under-documented until this note. |

---

## 5. Recommended roadmap (priority order)

### Phase A — Make the existing path obvious (no protocol change)

1. **Document the RPC-only operator path** — observer RPC + `mfn-storage-operator`; optional `serve-chunks` for HTTP replication (this document + TESTNET/OPERATORS cross-links).
2. **Ship prebuilt release artifacts** for `mfn-storage-operator` alongside `mfnd` / `mfn-cli` on major platforms (**done** via `.github/workflows/release-binaries.yml`).
3. **One-command "storage daemon" wrapper** — e.g. `mfn-storage-operator run` with sane defaults, auto wallet scan, structured logs (partially exists; polish onboarding).

### Phase B — Consumer UX (still no consensus change)

4. **WASM prove + serve** — **done (bindings)** — `mfn-wasm` exposes `buildStorageProof`, `verifyStorageProof`, and `storageChunkHex` for browser/PWA prove loops; minimal chunk HTTP remains app/operator glue ([`mfn-wasm/README.md`](../mfn-wasm/README.md), [`DECENTRALIZATION.md`](./DECENTRALIZATION.md)).
5. **Mobile/light desktop app** — background prove loop using light-client RPC (`get_storage_challenge`, `submit_storage_proof`); local encrypted artifact store.
6. **Replication discovery** — index of operators willing to replicate (could start as curated peer lists in manifests, evolve to on-chain optional registry).

### Phase C — Incentive fairness (optional protocol upgrades)

7. **Latency-fair proof inclusion** — e.g. commit-reveal, VRF-weighted operator selection, or proof pools that don't pure-race to producers ([`PROBLEMS.md § 6`](./PROBLEMS.md#6-spora-proof-winning-is-a-pure-first-to-publish-latency-race)).
8. **Tiered operator model** — bondless "best effort" replicas (default, low friction) vs bonded "premium" replicas with slashing for SLA-sensitive uploads ([`ECONOMICS.md § 10`](./ECONOMICS.md#10-open-economic-questions)).
9. **Erasure-coded replication (research)** — let many home nodes each store a fraction of a file while SPoRA still attests recoverability; increases operator count without multiplying full-file disk cost.

### Phase D — Only if SNARK tier ships (not planned near-term)

10. **Aggregated SNARK audits** — would shift prover cost up and verifier cost down; explicitly deferred because Merkle proofs keep validators cheap ([`STORAGE.md`](./STORAGE.md)). Consumer storage should *not* depend on this path.

---

## 6. Conclusion

| Question | Answer |
|---|---|
| **Is consumer storage possible with current architecture?** | **Yes.** SPoRA + off-chain payloads + separate operator role + direct operator payouts are exactly the shape needed. |
| **Is it possible at all (even with rewrites)?** | **Yes.** Permanent storage always requires *someone* to store bytes; the design choice is whether that "someone" must be a specialized miner. Permawrite already answered no. |
| **Is it fully realized for "anyone with a normal device" today?** | **Not yet.** A technically capable user can operate on devnet with CLI tools and an observer RPC; mass accessibility still needs packaged apps and browser prove-loop UX on top of shipped WASM bindings. |
| **Does this require abandoning permanence or decentralization?** | **No**, provided the network attracts enough independent operators and sustained fee inflows. The main risks are economic (fee drought) and operational (latency races, weak defection penalties), not hardware impossibility. |
| **Does SPoRA need big computers?** | **No.** Validators do; storage operators do not. Do not conflate the two roles. |

**Design principle to preserve:** keep validators expensive-enough for security, keep storage operators cheap-enough for breadth. The codebase already separates those roles; future work should widen the operator funnel, not merge it back into validator hardware requirements.

---

## See also

- [`OVERVIEW.md § How the permanence half works`](./OVERVIEW.md#how-the-permanence-half-works-no-formulas)
- [`STORAGE.md`](./STORAGE.md) — SPoRA, endowment, apply_block flow
- [`ECONOMICS.md § 7`](./ECONOMICS.md#7-storage-operator-economics) — operator payout accounting
- [`PRIVACY_AND_PERMANENCE.md`](./PRIVACY_AND_PERMANENCE.md) — why one network for both properties
- [ROADMAP.md](./ROADMAP.md) — M6/M7 operator tooling shipped; WASM M4 next steps
- [DECENTRALIZATION.md](./DECENTRALIZATION.md) — hardware profiles for every network role


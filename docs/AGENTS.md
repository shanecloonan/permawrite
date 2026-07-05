# Agent coordination checklists

Master board: [`AGENTS.md`](../AGENTS.md). Release gates: [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md).

When a lane completes a unit, update **all three**: this file, `AGENTS.md`, and the matching `TESTNET_CHECKLIST.md` section (if RC-related).

---

## How lanes talk to each other

```text
AGENTS.md (master)  <─── claim / status / backlog
       │
       ├── docs/AGENTS.md (this file) — per-lane detail
       ├── docs/TESTNET_CHECKLIST.md — RC mirror for lanes 1–3
       └── 3agent.md — alias pointer to lanes 1–3
```

**Cross-lane rules**

- **Request:** add a row to `AGENTS.md` § Cross-lane requests; target lane acknowledges in their section below.
- **Blocker:** if your unit depends on another lane, status = `Blocked on lane N` — do not push partial protocol changes.
- **Observed WIP:** if `git status` shows another lane's files modified, note under your lane but do not stage them.

### Done / Doing / Next (mandatory)

Every lane agent **must** announce all three on every session and keep the boards in sync. See [`AGENTS.md` § Agent announcement protocol](../AGENTS.md#agent-announcement-protocol-mandatory).

| Surface | Done | Doing | Next |
| --- | --- | --- | --- |
| Chat (start + end of unit) | ✓ | ✓ | ✓ |
| `AGENTS.md` current board | ✓ | ✓ | ✓ |
| This file — lane section | ✓ | — | ✓ |
| `3agent.md` (lanes 1–3 only) | ✓ | ✓ | ✓ |

**Per-lane checklist format** — keep these three subsections under every active lane:

```markdown
### Done
- [x] …

### Doing
- [ ] **<unit>** — <concrete current step> (claim base: `<sha>`)

### Next
- [ ] …
```

When **Doing** is empty, set lane status to **Idle** on the master board and list Next as backlog claims only.

---

## Lane 1 — RC core (consensus, networking, GHA)

**Owns:** M2.5.x mesh startup, voter-dial timeouts, Nightly rehearsal stability, Linux soak dispatch.

### Done

- [x] M2.5.8–M2.5.9 — GHA startup polls + `query_tip_height`.
- [x] M2.5.17 — Windows voter hub-dial 600s parity.
- [x] M2.5.19 — GHA hub tip 900s; health 600s; liveness 300s; voter-dial soft-continue.
- [x] M2.4.89 Windows mirror — `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).

### Next

- [ ] Nightly #56 all three jobs green on current RC commit.
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit** workflow).

### Do not start (other lanes)

- M7.10 `push-all-chunks` — lanes 2–3 (landed `c1e0373`).
- M5.31+ ring tests — lane 4 (M5.31-M5.33 landed this commit).

---

## Lane 2 — RC ops (security, RPC, release evidence)

**Owns:** `release-evidence-*`, RC audit dry-run, CI/Nightly auto-dispatch, schema validation gates.

### Done

- [x] M2.5.14–M2.5.18 — evidence refresh + inline Nightly dispatch.
- [x] M2.5.20 — nightly STAGE/start-all log dumps (668044d).
- [x] M2.5.21 — preflight `wasm-opt` + ci-check wasm-pack pkg cleanup (this commit).
- [x] B-05 — Linux soak auto-dispatch + RC audit dry-run Linux evidence hook (this commit).
- [x] M2.5.22 — wasm-pack `wasm-opt=false` (`0dcb1e9`).
- [x] M2.4.89 Windows mirror — `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).
- [x] M7.10 push-all-chunks (`c1e0373` on `main`).
- [x] M6.9 — storage-operator JSON logs + `prove_attempt_json` unit test (this commit).

- [x] M2.4.90 — `ci-check.sh` thread cap parity (this commit).

### Next

- [ ] `release-evidence-refresh-for-head` after green CI + Nightly #56.

### Do not start

- M5 protocol tests — lane 4.

---

## Lane 3 — RC onboarding (wallet, storage, faucet, rehearsal)

**Owns:** Participant/observer rehearsal smokes, faucet/demo scripts, operator onboarding polish, M7.10 UX.

### Done

- [x] M2.5.7–M2.5.16 — smoke evidence pipeline + assert gates.
- [x] M4.7 WASM SPoRA bindings (`778053a`).
- [x] M7.10 — `push-all-chunks` + OPERATORS.md (`c1e0373`).

### Next

- [ ] Nightly #56 participant + observer PASS.

### Do not start

- Wallet README ring examples — lane 5 (done this commit).
- Consensus ring tests — lane 4.

---

## Lane 4 — Protocol hardening (M5 privacy + permanence)

**Owns:** Consensus/mempool privacy guards, mixed CLSAG+SPoRA tests, proptests not covered by RC lanes.

**Doctrine:** Tier 1 production policy only (uniform ring-16). No Tier 2/3/4 until `AGENTS.md` backlog explicitly schedules it.

### Done

- [x] **M5.31** — `consensus_rejects_non_uniform_ring_sizes` + `apply_block_rejects_non_uniform_ring_sizes` (uniform ring-16 across all inputs).
- [x] **M5.32** — `mfn-runtime` mempool `admit_rejects_non_uniform_ring_sizes_across_inputs` (claim B-01).
- [x] **M5.33** — prop_mixed_clsag_fee_and_storage_upload_treasury + 64-block deep chain (claim B-02, 1d4d67c).
- [x] **M5.35** - deep_mixed_clsag_fee_and_storage_upload_treasury_64 in default CI (`9537c7b`).
- [x] **M5.36** - deep_mixed_clsag_fee_and_storage_proof_treasury_64 in default CI (`0dcb1e9`).
- [x] **M5.37** - deep_empty_block_chain_128 + deep_storage_proof_chain_32 + deep_validator_mixed treasury in default CI (`ec8122e`).
- [x] **M5.38** - restore deep_mixed_clsag_fee_and_storage_upload_treasury_64 to default CI (`d3a4f36`).
- [x] **M5.39** - deep_alternating_register_storage_treasury_8 proptest in default CI (35734a5).
- [x] **M5.40** - 64-block combined-inflow + PPB + equivocation-PPB emission sims in default CI (this commit).

### Next

- [ ] Idle - monitor Nightly #56 after M5.39 lands.

### Handoff to lane 3

- Ring-16 is consensus-enforced; wallet/CLI must stay ≥16 (lane 5 documents).

---

## Lane 5 — Privacy surface (wallet, CLI, WASM, docs)

**Owns:** Reference-wallet ring defaults, privacy doc accuracy, “no silent downgrade” UX.

### Done

- [x] **M5.31-docs** — `mfn-wallet/README.md` quick-start uses ring-16 and cites `WALLET_MIN_RING_SIZE`.
- [x] **M5.31-cli** — `mfn-cli wallet` help documents `--ring-size` default 16 (claim B-04).
- [x] **PRIVACY cross-link** — wallet README links uniform-ring policy in [`PRIVACY.md`](./PRIVACY.md).

### Next

- [ ] Monitor Nightly #56 after M5.31/M5.32 land on `main`.

### Do not start

- M7.10 replication — lanes 2–3.
- GHA rehearsal — lane 1.

---

## Lane 6 — Permanence depth (economics, SPoRA, treasury)

**Owns:** Long-run treasury/emission sims, SPoRA payout invariants, operator-bonding research.

### Idle — claim from backlog

- [x] **M5.34 / B-03** — 64-block validator mixed CLSAG+SPoRA emission sim in default CI (`45a118b`).
- [x] B-05 — Linux soak auto-dispatch + workflow evidence commit (this commit; awaiting first PASS transcript).

### Do not start

- RC Nightly fixes — lane 1.
- `push-all-chunks` — lanes 2–3.

---

## Backlog detail (claim → move to lane section)

| ID | Item | Suggested lane | Notes |
| --- | --- | --- | --- |
| B-02 | Proptest CLSAG + storage upload same block | 4 | Done - extends M5.5 |
| B-03 | CI emission sim with privacy fees | 6 | **Done** — 64-block validator mixed |
| B-05 | Linux 30s soak evidence | 2 + 6 | Manual workflow |
| B-06 | Nightly #56 green | 1 | Blocks RC sign-off |

---

## TESTNET_CHECKLIST mirror

RC lanes 1–3 must keep [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md) in sync when they land units. Lanes 4–6 add a one-line note under **Agent coordination** when they ship protocol or privacy-surface changes.

---

## See also

- [`3agent.md`](./3agent.md) — legacy lanes 1–3 pointer
- [`DECENTRALIZATION.md`](./DECENTRALIZATION.md), [`PRIVACY.md`](./PRIVACY.md), [`ROADMAP.md`](./ROADMAP.md)

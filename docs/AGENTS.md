# Agent coordination checklists

Master board: [`AGENTS.md`](../AGENTS.md). Release gates: [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md).

When a lane completes a unit, update **all three**: this file, `AGENTS.md`, and the matching `TESTNET_CHECKLIST.md` section (if RC-related).

---

## How lanes talk to each other

```text
AGENTS.md (master)  <ΓöÇΓöÇΓöÇ claim / status / backlog
       Γöé
       Γö£ΓöÇΓöÇ docs/AGENTS.md (this file) ΓÇö per-lane detail
       Γö£ΓöÇΓöÇ docs/TESTNET_CHECKLIST.md ΓÇö RC mirror for lanes 1ΓÇô3
       ΓööΓöÇΓöÇ 3agent.md ΓÇö alias pointer to lanes 1ΓÇô3
```

**Cross-lane rules**

- **Request:** add a row to `AGENTS.md` ┬º Cross-lane requests; target lane acknowledges in their section below.
- **Blocker:** if your unit depends on another lane, status = `Blocked on lane N` ΓÇö do not push partial protocol changes.
- **Observed WIP:** if `git status` shows another lane's files modified, note under your lane but do not stage them.

### Done / Doing / Next (mandatory)

Every lane agent **must** announce all three on every session and keep the boards in sync. See [`AGENTS.md` ┬º Agent announcement protocol](../AGENTS.md#agent-announcement-protocol-mandatory).

| Surface | Done | Doing | Next |
| --- | --- | --- | --- |
| Chat (start + end of unit) | Γ£ô | Γ£ô | Γ£ô |
| `AGENTS.md` current board | Γ£ô | Γ£ô | Γ£ô |
| This file ΓÇö lane section | Γ£ô | ΓÇö | Γ£ô |
| `3agent.md` (lanes 1ΓÇô3 only) | Γ£ô | Γ£ô | Γ£ô |

**Per-lane checklist format** ΓÇö keep these three subsections under every active lane:

```markdown
### Done
- [x] ΓÇª

### Doing
- [ ] **<unit>** ΓÇö <concrete current step> (claim base: `<sha>`)

### Next
- [ ] ΓÇª
```

When **Doing** is empty, set lane status to **Idle** on the master board and list Next as backlog claims only.

---

## Lane 1 ΓÇö RC core (consensus, networking, GHA)

**Owns:** M2.5.x mesh startup, voter-dial timeouts, Nightly rehearsal stability, Linux soak dispatch.

### Done

- [x] M2.5.8ΓÇôM2.5.9 ΓÇö GHA startup polls + `query_tip_height`.
- [x] M2.5.17 ΓÇö Windows voter hub-dial 600s parity.
- [x] M2.5.19 ΓÇö GHA hub tip 900s; health 600s; liveness 300s; voter-dial soft-continue.
- [x] M2.5.31 - GHA polls 900s; voter soft gate tip>=1; health 900s; nightly jobs 90m; RC Nightly backup dispatch (0e0de4e).
- [x] M2.4.89 Windows mirror ΓÇö `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).

### Next

- [ ] Nightly #57 all three jobs green on ``0e0de4e`` (B-06).
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit** workflow).

### Do not start (other lanes)

- M7.10 `push-all-chunks` ΓÇö lanes 2ΓÇô3 (landed `c1e0373`).
- M5.31+ ring tests ΓÇö lane 4 (M5.31-M5.33 landed e0a7ebd).

---

## Lane 2 ΓÇö RC ops (security, RPC, release evidence)

**Owns:** `release-evidence-*`, RC audit dry-run, CI/Nightly auto-dispatch, schema validation gates.

### Done

- [x] M2.5.14ΓÇôM2.5.18 ΓÇö evidence refresh + inline Nightly dispatch.
- [x] M2.5.20 ΓÇö nightly STAGE/start-all log dumps (668044d).
- [x] M2.5.21 ΓÇö preflight `wasm-opt` + ci-check wasm-pack pkg cleanup (e0a7ebd).
- [x] B-05 ΓÇö Linux soak auto-dispatch + RC audit dry-run Linux evidence hook (e0a7ebd).
- [x] M2.5.22 ΓÇö wasm-pack `wasm-opt=false` (`0dcb1e9`).
- [x] M2.5.24 - `validate-rc-helper-scripts` smoke in `ci-check` (e0a7ebd).
- [x] M2.4.89 Windows mirror ΓÇö `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).
- [x] M7.10 push-all-chunks (`c1e0373` on `main`).
- [x] M7.11 - STORAGE_ACCESSIBILITY.md section 0 (`bb9600b`).
- [x] M6.9 ΓÇö storage-operator JSON logs + `prove_attempt_json` unit test (e0a7ebd).

- [x] M2.4.90 ΓÇö `ci-check.sh` thread cap parity (e0a7ebd).

### Next

- [ ] `release-evidence-refresh-for-head` after green CI + Nightly #56.

### Do not start

- M5 protocol tests ΓÇö lane 4.

---

## Lane 3 ΓÇö RC onboarding (wallet, storage, faucet, rehearsal)

**Owns:** Participant/observer rehearsal smokes, faucet/demo scripts, operator onboarding polish, M7.10 UX.

### Done

- [x] M2.5.7ΓÇôM2.5.16 ΓÇö smoke evidence pipeline + assert gates.
- [x] M4.7 WASM SPoRA bindings (`778053a`).
- [x] M7.10 ΓÇö `push-all-chunks` + OPERATORS.md (`c1e0373`).
- [x] M7.11 - STORAGE_ACCESSIBILITY.md section 0 (`bb9600b`).

### Next

- [ ] Nightly #56 participant + observer PASS.

### Do not start

- Wallet README ring examples ΓÇö lane 5 (done e0a7ebd).
- Consensus ring tests ΓÇö lane 4.

---

## Lane 4 ΓÇö Protocol hardening (M5 privacy + permanence)

**Owns:** Consensus/mempool privacy guards, mixed CLSAG+SPoRA tests, proptests not covered by RC lanes.

**Doctrine:** Tier 1 production policy only (uniform ring-16). No Tier 2/3/4 until `AGENTS.md` backlog explicitly schedules it.

### Done

- [x] **M5.31** ΓÇö `consensus_rejects_non_uniform_ring_sizes` + `apply_block_rejects_non_uniform_ring_sizes` (uniform ring-16 across all inputs).
- [x] **M5.32** ΓÇö `mfn-runtime` mempool `admit_rejects_non_uniform_ring_sizes_across_inputs` (claim B-01).
- [x] **M5.33** ΓÇö prop_mixed_clsag_fee_and_storage_upload_treasury + 64-block deep chain (claim B-02, 1d4d67c).
- [x] **M5.35** - deep_mixed_clsag_fee_and_storage_upload_treasury_64 in default CI (`9537c7b`).
- [x] **M5.36** - deep_mixed_clsag_fee_and_storage_proof_treasury_64 in default CI (`0dcb1e9`).
- [x] **M5.37** - deep_empty_block_chain_128 + deep_storage_proof_chain_32 + deep_validator_mixed treasury in default CI (`ec8122e`).
- [x] **M5.38** - restore deep_mixed_clsag_fee_and_storage_upload_treasury_64 to default CI (`d3a4f36`).
- [x] **M5.39** - deep_alternating_register_storage_treasury_8 proptest in default CI (35734a5).
- [x] **M5.40** - 64-block combined-inflow + PPB + equivocation-PPB emission sims in default CI (`7648ab2`).
- [x] **M5.41** - 128-block PPB + equivocation combined-inflow emission sims in default CI (`c7f90e6`).

### Next

- [ ] Idle - monitor Nightly #56 after M5.43 lands.

### Handoff to lane 3

- Ring-16 is consensus-enforced; wallet/CLI must stay ΓëÑ16 (lane 5 documents).

---

## Lane 5 ΓÇö Privacy surface (wallet, CLI, WASM, docs)

**Owns:** Reference-wallet ring defaults, privacy doc accuracy, ΓÇ£no silent downgradeΓÇ¥ UX.

### Done

- [x] **M5.31-docs** ΓÇö `mfn-wallet/README.md` quick-start uses ring-16 and cites `WALLET_MIN_RING_SIZE`.
- [x] **M5.31-cli** ΓÇö `mfn-cli wallet` help documents `--ring-size` default 16 (claim B-04).
- [x] **PRIVACY cross-link** ΓÇö wallet README links uniform-ring policy in [`PRIVACY.md`](./PRIVACY.md).

### Next

- [ ] Monitor Nightly #56 after M5.31/M5.32 land on `main`.

### Do not start

- M7.10 replication ΓÇö lanes 2ΓÇô3.
- GHA rehearsal ΓÇö lane 1.

---

## Lane 6 ΓÇö Permanence depth (economics, SPoRA, treasury)

**Owns:** Long-run treasury/emission sims, SPoRA payout invariants, operator-bonding research.

### Idle ΓÇö claim from backlog


- [x] **M5.46** - combined-inflow emission CI tier complete (`1232506`).
- [x] **M5.47** - 256-block equivocation combined-inflow + 1M curve in default CI (`db06c78`).
- [x] **M5.48** - emission deep-sim tier closure; 2048 CLSAG + 100k `apply_block` stay nightly (`77f2fe1`).
- [x] **M5.34 / B-03** ΓÇö 64-block validator mixed CLSAG+SPoRA emission sim in default CI (`45a118b`).
- [x] **M5.40** - 64-block combined-inflow + PPB + equivocation-PPB emission sims in default CI (`7648ab2`).
- [x] **M5.41** - 128-block PPB + equivocation combined-inflow emission sims in default CI (`c7f90e6`).
- [x] **M5.42** - 256-block combined-inflow emission sim in default CI (994af36).
- [x] **M5.44** - 512-block combined-inflow emission sim in default CI (3fcb4bc).
- [x] **M5.46** - combined-inflow emission CI tier complete; 2048-block CLSAG fee mix timed nightly-only (~13 min release).
- [x] **M5.47** - 256-block equivocation combined-inflow + 1M-height emission curve in default CI (`db06c78`).
- [x] **M5.45** - 512-block PPB + equivocation combined-inflow emission sims in default CI (66a697a).
- [x] **M5.43** - 256-block PPB combined-inflow emission sim in default CI (7ffcdac).
- [x] B-05 ΓÇö Linux soak auto-dispatch + workflow evidence commit (`9537c7b`; awaiting first PASS transcript).

### Next

- [ ] **Idle** - monitor B-05 Linux soak evidence (lane 2+6) after green CI.
- [ ] B-06 - Nightly #56 all three jobs green (lane 1 RC gate).

### Do not start

- RC Nightly fixes ΓÇö lane 1.
- `push-all-chunks` ΓÇö lanes 2ΓÇô3.

---

## Backlog detail (claim ΓåÆ move to lane section)

| ID | Item | Suggested lane | Notes |
| --- | --- | --- | --- |
| B-02 | Proptest CLSAG + storage upload same block | 4 | Done - extends M5.5 |
| B-03 | CI emission sim with privacy fees | 6 | **Done** ΓÇö 64-block validator mixed |
| B-05 | Linux 30s soak evidence | 2 + 6 | Manual workflow |
| B-06 | Nightly #56 green | 1 | Blocks RC sign-off |

---

## TESTNET_CHECKLIST mirror

RC lanes 1ΓÇô3 must keep [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md) in sync when they land units. Lanes 4ΓÇô6 add a one-line note under **Agent coordination** when they ship protocol or privacy-surface changes.

---

## See also

- [`3agent.md`](./3agent.md) ΓÇö legacy lanes 1ΓÇô3 pointer
- [`DECENTRALIZATION.md`](./DECENTRALIZATION.md), [`PRIVACY.md`](./PRIVACY.md), [`ROADMAP.md`](./ROADMAP.md)

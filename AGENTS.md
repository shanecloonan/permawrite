# Agent Coordination (master board)

Single source of truth for **all** parallel agent lanes (formerly `3agent.md` lanes 1-3, plus overflow lanes 4-6). Release gates: [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md).

**Priority doctrine:** privacy and permanence over everything. UX, ops, and CI serve those guarantees - never weaken ring policy, endowment enforcement, or SPoRA verification.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

---

## Conflict prevention (read before every unit)

1. **Check this table first.** If another lane owns the unit with status `In progress`, do not start it.
2. **Claim before coding.** Set status to `In progress` + note the commit base in [`docs/AGENTS.md`](docs/AGENTS.md).
3. **Do not commit another lane's uncommitted work.** List it under **Observed local work** until it lands on `main`.
4. **One coherent unit per commit.** Run `scripts/ci-check` (Windows: `scripts/ci-check.ps1`) before push.
5. **Do not push while CI is in progress** on `main` - concurrency `cancel-in-progress` aborts the matrix (~70 min on Linux/macOS).
6. **Hand off explicitly.** Update this board + lane checklist + any cross-lane request rows when done.

---

## Agent announcement protocol (mandatory)

Every agent working a lane **must** broadcast **Done / Doing / Next** so simultaneous agents on the same roadmap can coordinate without duplicating work or missing handoffs.

### When to announce

| Trigger | Required action |
| --- | --- |
| **Start of session** | Post Done / Doing / Next before touching code. |
| **Claim a unit** | Update current board + lane section; announce Doing + planned Next. |
| **Mid-unit pivot** | Re-announce if scope, lane, or blockers change. |
| **End of unit** | Move unit to Done; announce Next; update cross-lane requests. |
| **Before push** | Board reflects the exact commit about to land; Next names the follow-up owner. |

### What to include (every announcement)

1. **Done**  -  units landed on `main` (commit hash when known) or explicitly abandoned with reason.
2. **Doing**  -  current lane, unit ID, and concrete step (not just the milestone name).
3. **Next**  -  immediate follow-up after this unit, expected lane owner, and any dependency on another lane.

Use this template in chat **and** mirror it on the boards:

`text
Lane N  -  Done: <completed units + commits>
       Doing: <unit + current step>
       Next:  <follow-up + owner + blockers>
`

### Where to record it

Update **all applicable** surfaces in the same session  -  do not rely on chat alone:

- [`AGENTS.md`](AGENTS.md)  -  current board, cross-lane requests, recently completed.
- [`docs/AGENTS.md`](docs/AGENTS.md)  -  lane Done / Next checklists.
- [`3agent.md`](3agent.md)  -  lanes 1-3 mirror (current board + detailed plans).
- [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md)  -  when RC-related.

### Coordination rules

- **Read before write:** scan every lane's latest Done / Doing / Next before claiming work.
- **No silent work:** if you are coding without a `Doing` row on the board, stop and claim first.
- **Stale boards are blockers:** if your lane's Doing row is >1 session old, refresh or release the claim.
- **Cross-lane visibility:** when Next depends on another lane, add or update a row in ┬º Cross-lane requests.

---

## Lane registry

| Lane | Scope | Owns (exclusive) | Does *not* own |
| --- | --- | --- | --- |
| **1** | RC core | M2.5.x mesh startup, voter-dial timeouts, Nightly rehearsal stability, Linux soak dispatch | M7.10 replication, M5 ring tests |
| **2** | RC ops | `release-evidence-*`, RC audit dry-run, CI/Nightly auto-dispatch, schema validation gates | M5 protocol tests |
| **3** | RC onboarding | Participant/observer rehearsal smokes, faucet/demo scripts, operator onboarding polish, M7.10 UX | Wallet README ring examples (lane 5), consensus ring tests (lane 4) |
| **4** | Protocol hardening | M5 privacy + permanence tests, `apply_block` invariants, ring/SPoRA consensus guards | RC Nightly fixes, `push-all-chunks` |
| **5** | Privacy surface | Wallet/CLI/WASM ring defaults, privacy doc accuracy, no silent downgrade UX | M7.10 replication, GHA rehearsal |
| **6** | Permanence depth | Treasury/emission sims, SPoRA payout invariants, operator-bonding research | RC Nightly, `push-all-chunks` |

Add lanes 7+ in [`docs/AGENTS.md`](docs/AGENTS.md) when needed. Split lanes before they exceed ~2 active units.

---

## CI gate (2026-07-05)

**CI #624** (`0ddafc9`) **FAIL** — macOS release tests at 4 threads; **M2.5.34** macOS `--test-threads=2` fix staged; push after CI completes; **B-06** Nightly #57 follows green CI.

## Current board

| Lane | Current unit | Status | Next handoff |
| --- | --- | --- | --- |
| **1** | M2.5.34 macOS CI test hardening (`--test-threads=2`) | **In progress** - this commit | Nightly #57 after green CI |
| **2** | M2.5.32 repo hygiene + board mojibake guards | **Done** - `a35b7a6` | B-05 soak; release evidence after Nightly #57 |
| **3** | M7.11.2 STORAGE_ACCESSIBILITY Phase B WASM doc sync | **Done** - `0650ad6` | Monitor Nightly #57 (B-06) |
| **4** | M5.39 alternating proptest CI | **Done** - `35734a5` | B-06 Nightly #57 |
| **5** | Wallet README + CLI ring-16 docs | **Done** - on `main` | Monitor Nightly #57 |
| **6** | M5.48 emission deep-sim tier closure | **Done** - `77f2fe1` | B-05 / B-06 monitor |

---

## Backlog (unassigned -> claim in lane section)

| ID | Item | Suggested lane | Privacy / performance |
| --- | --- | --- | --- |
| B-02 | M5.33 - proptest: mixed CLSAG + storage upload same block treasury identity | 4 | Done - extends M5.5 |
| B-03 | Promote one ignored emission sim with CLSAG fee mix to CI | 6 | Done - M5.34/M5.35 (`45a118b`, `9537c7b`) |
| B-05 | Linux 30s soak evidence | 2 + 6 | Dispatch shipped `9537c7b`; awaiting PASS transcript |
| B-06 | Nightly #57 green (all three jobs) | 1 | RC gate (Nightly #56 partial: ignored PASS; participant+observer FAIL ~13m) |

---

## Cross-lane requests

| From | To | Request | Status |
| --- | --- | --- | --- |
| 2 | 1 | Green CI on `main` before Nightly #57 dispatch | Waiting |
| 3 | 1 | Nightly #57 participant + observer PASS | Waiting |
| 4 | 3 | M5.31-M5.33 protocol tests green before next M7.10 UX | **Done** - `d3a4f36` |
| TESTNET | all | Mirror completed units into `docs/TESTNET_CHECKLIST.md` | Ongoing |

---

## Recently completed

- **M2.5.34** (this commit) - macOS CI `--test-threads=2` parity with Linux after CI #624 macOS FAIL (lane 1).
- **DOCS-QA-1** (`5775b07`) - `docs/CODEBASE_IMPROVEMENTS.md` engineering-quality audit (docs-only).
- **M7.11.2** (`0650ad6`) - STORAGE_ACCESSIBILITY Phase B item 4 WASM prove+serve doc sync (lane 3).
- **M2.5.32** (`a35b7a6`) - `.gitignore` debris patterns; board mojibake guard in validate-workflow-encoding; clean `docs/AGENTS.md` rebuild (lane 2).
- **M2.5.31** (`0e0de4e`) - GHA voter-dial/health 900s; nightly rehearsal jobs 90m; soft-continue at tip>=1 + both voters P2P listening (lane 1).
- **M2.5.30** (`2eb8417`) - bash `validate-workflow-encoding` guard path parity with ps1 (lane 2).
- **M2.5.29** (`4bd43f2`) - `-text` gitattributes for boards; `fix-m2527-boards.ps1` UTF-8 repair helper (lane 2).
- **M2.5.27** (`e0a7ebd`) - restore `docs/AGENTS.md` per-lane checklists; sync master board (lane 2).
- **M2.5.26** (`a417f1e`) - UTF-8 guard for agent boards in validate-workflow-encoding (lane 2).
- **M2.5.24** (`001e2c6`) - `validate-rc-helper-scripts` smoke in `ci-check` (lane 2).
- **M7.11** (`bb9600b`) - STORAGE_ACCESSIBILITY.md section 0 (lane 3).
- **M5.48** (`77f2fe1`) - emission deep-sim tier closure (lane 6).
- **M5.47** (`db06c78`) - 256-block equivocation + 1M curve in default CI (lane 6).
- **M5.46** (`1232506`) - combined-inflow emission CI tier complete (lane 6).

---

## Legacy name

The **3agent** board (`3agent.md`) is lanes **1-3** only. It now redirects here so new parallel agents use one registry.

See also: [`docs/ROADMAP.md`](./docs/ROADMAP.md), [`docs/TESTNET.md`](./docs/TESTNET.md), [`scripts/public-devnet-v1/OPERATORS.md`](./scripts/public-devnet-v1/OPERATORS.md).

# AGENTS.md — Permawrite Agent Control Board (the one pipeline)

**This is the single live coordination surface for every agent building Permawrite.** There is exactly one board (this file), one history (the ledger), and one pipeline (§3). If any other file appears to describe agent coordination, it is a pointer stub or a frozen archive — this file wins every disagreement.

**Priority doctrine:** privacy and permanence over everything. UX, ops, and CI serve those guarantees — never weaken ring policy, endowment enforcement, or SPoRA verification to make a unit land faster.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

Why this system exists (and why it is this strict): [`docs/VIBECODING.md`](docs/VIBECODING.md) — parallel lanes with a single durable board are how a chain too big for one context window gets built without agents clobbering each other.

---

## 0. The contract (read before anything else)

1. **2026-07-19 — lane 1 — B-34 restart empty-step CI `#29711605173`** (this commit): All jobs queued ~9.5m with no runner pickup on `e10a8b3`; docs push **without** `[skip ci]` to cancel-in-progress and start a healthy matrix (B-29 parse already on head). Did **not** touch Hetzner (B-15). *Observed local work (not staged):* ROADMAP planning, user-wallet/, ci-docs-*.txt, live-testnet-data/.
2. **One live board.** All claims, status, handoffs, requests, and backlog live in this file only. You never have to update two surfaces, so the board can never drift against itself.
2. **No silent work.** If you are coding without a **Doing** row in §5, stop and claim first.
3. **Read before write.** Scan the whole §5 board + §6 requests before claiming anything.
4. **History is append-only.** Completed work rotates from §8 into [`docs/AGENTS_LEDGER.md`](docs/AGENTS_LEDGER.md); nothing is ever silently deleted.
5. **Everything lands on `main`.** Commit and push every completed unit to `main` (standing user directive). Feature branches are for cloud-agent PR workflows only when the platform requires them.

---

## 1. System map (what lives where)

| Surface | Role | Rule |
| --- | --- | --- |
| **`AGENTS.md`** (this file) | Live board + pipeline + protocol | The only file agents write coordination state to |
| [`docs/AGENTS_LEDGER.md`](docs/AGENTS_LEDGER.md) | Append-only history (rotated sessions + retired-board snapshots) | Append only; never edit or delete |
| [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md) | Release gates (RC hardening checklist) | Check off gates when units land; do not track live work here |
| [`docs/TESTNET_LAUNCH.md`](docs/TESTNET_LAUNCH.md) | Lane 7 TL phase tracker | Lane 7 mirrors TL unit status here |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Strategic phase map L0–L7, critical path, research backlog | External planning + all lanes at SYNC |
| [`3agent.md`](3agent.md), [`docs/3agent.md`](docs/3agent.md), [`docs/AGENTS.md`](docs/AGENTS.md) | Legacy pointer stubs | Redirect here; never add content |
| [`docs/VIBECODING.md`](docs/VIBECODING.md) | Rationale: how AI builds this chain | Context, not state |
| `scripts/validate-workflow-encoding.*`, `scripts/validate-rc-helper-scripts.*` | Board integrity guards | Fail closed on UTF-16/mojibake corruption of this file, the stubs, and the ledger |

---

## 2. Lane registry (who owns what)

A **lane** is a standing role; an **agent** is whoever is currently working that lane. Lanes own exclusive slices so two agents never edit the same subsystem at once.

| Lane | Role | Owns (exclusive) | Does *not* own | Standing verifier duty (§4) |
| --- | --- | --- | --- | --- |
| **1** | RC core | M2.5.x mesh startup, voter-dial timeouts, Nightly rehearsal stability, Linux soak dispatch | M7.10 replication, M5 ring tests | GitHub CI + Nightly on every head |
| **2** | RC ops | `release-evidence-*`, RC audit dry-run, CI/Nightly auto-dispatch, schema validation gates, **this board's integrity** | M5 protocol tests | Release evidence + RC audit dry-run on every green head |
| **3** | RC onboarding | Participant/observer rehearsal smokes, faucet/demo scripts, operator onboarding polish, M7.10 UX | Wallet README ring examples (lane 5), consensus ring tests (lane 4) | Rehearsal evidence (participant + observer PASS transcripts) |
| **4** | Protocol hardening | M5 privacy + permanence tests, `apply_block` invariants, ring/SPoRA consensus guards, fraud/validity proofs | RC Nightly fixes, `push-all-chunks` | Consensus test coverage for every consensus-touching unit (any lane) |
| **5** | Privacy surface | Wallet/CLI/WASM ring defaults, privacy doc accuracy, no-silent-downgrade UX | M7.10 replication, GHA rehearsal | Privacy-doc accuracy vs shipped behavior |
| **6** | Permanence depth | Treasury/emission sims, SPoRA payout invariants, operator-bonding research | RC Nightly, `push-all-chunks` | Emission/treasury identity sims for every economics-touching unit |
| **7** | Testnet launch | Internet-facing go-live ([`docs/TESTNET_LAUNCH.md`](docs/TESTNET_LAUNCH.md)), VPS runbook, `seed_nodes` publication, faucet/observer/front-end ops, launch ceremony | Protocol tests (4/6), CI/Nightly fixes (1), evidence tooling (2) | Launch-blocker honesty (never fake TL completion; `launch-go-no-go` gate) |

Adding lanes 8+: add a row **here** (nowhere else). Split a lane before it exceeds ~2 active units.

---

## 3. The unit pipeline (how every piece of work flows)

Work is decomposed into small, named **units** ("one coherent unit per commit"). Every unit moves through the same seven steps. The step names below are the vocabulary the board uses.

### Step 1 — SYNC (verify the last agent's handoff)

- Read §5 (board), §6 (requests), §8 (session log), and `git log --oneline -15` on `main`.
- **Cross-check:** confirm the board's Done column matches what actually landed (commit hashes exist on `main`; claimed-green CI runs are green via `gh run list`). If the board is stale or wrong, **fix the board first** and note the correction in §8 — a wrong board is a blocker for everyone.
- If another lane's uncommitted files show in `git status`, note them in your §8 entry as *Observed local work* and never stage them.

### Step 2 — CLAIM (announce who's going to do what)

- Pick a unit: your lane's Next cell, a §7 backlog row, or a §6 request addressed to your lane.
- Write your **Doing** cell in §5: unit ID, concrete current step, and the claim base commit (`claim base: <sha>`).
- If the unit needs another lane first, do not start — add/refresh a §6 request row with status `Blocked`.
- Announce **Done / Doing / Next** in chat using the §9 template.

### Step 3 — BUILD (small, bounded, in-lane)

- Load only the relevant doc section + crate into context (see the Cross-cuts table in [`README.md`](README.md)).
- Stay inside your lane's ownership. If the fix genuinely requires another lane's files, stop and file a §6 request instead of reaching across.
- One coherent unit per commit; keep the diff surface small enough that a CI failure points at it.

### Step 4 — PROVE (self-check before anyone else checks you)

- Add or extend a deterministic test for every behavior change (consensus behavior reproduces at `apply_block` level — no network needed).
- Run the local CI mirror — **required before every push**:
  - Linux/macOS: `bash scripts/ci-check.sh`
  - Windows: `powershell -File scripts/ci-check.ps1`
  - Docs/scripts-only diffs may use `--docs-only` / `-DocsOnly`.
- Fix and re-run until green. Never push red.

### Step 5 — LAND (push to main, without killing someone else's CI)

- **Check CI first:** `gh run list --workflow CI --limit 3`. If a run is **in progress** on `main`, do not push Rust — concurrency `cancel-in-progress` aborts the ~30–70 min matrix. Wait for it, or (docs-only commits only) use `[skip ci]`.
- Update **this file in the same commit**: move your unit Doing → Done (with commit subject), set your Next, prepend a §8 session-log entry, and update any §6/§7 rows you resolved.
- Commit with a descriptive message; push to `main`.

### Step 6 — VERIFY (who's checking what — after the push)

- **You (unit owner):** `gh run list --workflow CI --limit 3`; if the new head run failed, `gh run view <run-id> --log-failed` and fix forward on `main` immediately. Never leave red CI for the next agent.
- **Lane 1:** dispatches/verifies Nightly (all three jobs) on protocol-affecting stacks after CI GREEN.
- **Lane 2:** refreshes `release-evidence-<sha>` + RC audit dry-run on the green head when the stack is RC-relevant.
- **Lane 4/6:** confirm consensus/economics test coverage exists for any unit (from any lane) that touched `mfn-consensus`, emission, or treasury paths — file a §6 request if it is missing.
- Record run IDs and verdicts in §5/§8 (e.g. `CI #123456 GREEN`), so the next agent's SYNC can verify without re-deriving.

### Step 7 — CLOSE (hand off explicitly)

- Ensure §5 shows: your Done (with hash), your Next (with expected owner + blockers), and a clean Doing cell (or your next claim).
- If the unit closes a release gate, tick it in [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md) (lane 7 mirrors TL phases into [`docs/TESTNET_LAUNCH.md`](docs/TESTNET_LAUNCH.md)).
- If §8 exceeds 20 entries, cut the oldest ones and append them verbatim to the ledger's *Rotated session-log entries* section (same commit).
- Announce Done / Doing / Next in chat.

---

## 4. Verification matrix (who checks what, when)

Every check below has exactly one owner. "Owner" = the lane on duty; the unit owner is whoever pushed the change.

| Check | Who runs it | When | Evidence recorded where |
| --- | --- | --- | --- |
| Local CI mirror (`scripts/ci-check.*`: fmt, clippy `-D warnings`, release tests, wasm, audit, script smokes, board guards) | **Unit owner** | Before every push | §8 entry ("local ci-check green") |
| GitHub CI full matrix on the exact head | **Unit owner** (watch) + **lane 1** (fix-forward duty if owner is gone) | After every push | §5 CI gate line + §8 (`CI #<run> GREEN`) |
| Nightly (ignored P2P tests + participant + observer jobs) | **Lane 1** | After CI GREEN on protocol-affecting stacks | §8 (`Nightly #<run> GREEN`) |
| Release evidence + RC audit dry-run (`release-evidence-refresh-for-head`, decision `go`) | **Lane 2** | On every green RC-relevant head | §8 + `docs/TESTNET_CHECKLIST.md` |
| Rehearsal smokes (participant/observer/dandelion) + evidence transcripts | **Lane 3** (local/GHA), **lane 7** (VPS/internet) | Before inviting outside users; after onboarding-affecting changes | §8 + archived evidence files |
| Consensus/economics test coverage for cross-lane diffs touching `mfn-consensus`/emission/treasury | **Lane 4** (privacy/consensus), **lane 6** (economics) | SYNC review of landed units | §6 request if coverage is missing |
| Privacy-doc accuracy vs shipped behavior | **Lane 5** | After any privacy-surface unit | §8 |
| Launch gates (`launch-go-no-go`, soak/participant evidence asserts, seed publication) | **Lane 7** | Every TL phase transition | `docs/TESTNET_LAUNCH.md` + §8 |
| Board integrity (UTF-8, mojibake, required files) | **CI, automatically** (`validate-workflow-encoding.*`, `validate-rc-helper-scripts.*`) | Every ci-check + every CI run | CI verdict |
| Previous agent's handoff truthfulness (hashes exist, claimed runs green) | **Next agent at SYNC** | Start of every session | §8 correction note if wrong |
| Human sign-off (release, genesis ceremony, VPS soak) | **Named human** | Release gates in `docs/TESTNET_CHECKLIST.md` | Sign-off manifest / audit packet |

**The chain of custody, in one line:** the unit owner proves locally → CI proves on the head → lane 1 proves overnight/distributed → lane 2 packages the proof → the next agent audits the handoff → a named human signs the release. No step vouches for itself.

---

## 5. Live board (who's doing what — NOW)

> Update this section in the **same commit** as the work it describes. A board row that doesn't match `git log` is a bug; fix it at SYNC.

**CI gate (2026-07-19):** code head = `e10a8b3` (B-29 ps1 parse on `5dc3aa8`); B-16 `49d28f9`; B-30 `2f1b4e2`; B-31 `6f637a4`. **B-34:** cancelling empty-step stall `#29711605173` (~9.5m queued) via this push (no skip-ci). Prior **CI `#29700946945` GREEN** on `b4a3fa7`. **B-29 closes only on Nightly GREEN**. Strategic path: L4 -> **B-13a** -> **B-25**.

| Lane | Done (last landed) | Doing | Next (owner → unit) | Checked by |
| --- | --- | --- | --- | --- |
| **1** RC core | **B-29** `5dc3aa8`+`e10a8b3` + **B-34** restart (this commit) | **Watch successor CI** (claim base: this head) | Nightly re-dispatch when GREEN -> close B-29 | CI/Nightly run IDs in §8 |
| **2** RC ops | R-1–R-4 (`2b655d2`…`dc05c40`) | *Idle* | Release evidence after CI+Nightly GREEN; **B-26** after B-15; help **B-41** | Board + encoding guards |
| **3** Onboarding | **B-15 wave1 outside-in probe** (`live-testnet-probe-20260720-wave1.md`) | **B-15** blocked on **B-41** P2P (claim base: `6f637a4`) | After B-41: full JOIN smoke + assert; then **B-42**; faucet lock until PASS archive | L4 checklist |
| **4** Protocol | F5 4b.1 (`6377812`) | *Idle* | After L4: **B-32** → **B-44** ([PM3](docs/ROADMAP.md#b-44--pm3-work-package-lane-46--after-b-32)) → **B-24** | Lane 1 CI/Nightly |
| **5** Privacy | **B-16** (`49d28f9`) | *Idle* | After B-25: **B-35** / **B-37** / **B-19** | Doc-accuracy duty |
| **6** Permanence | F6 telemetry (`0d1b9ec`) | *Idle* | **Armed:** **B-40** + **B-13a** day-of L4; then **B-33** | Emission sims |
| **7** Testnet launch | **B-31 probe** + **B-30** | *Idle* | **B-41** P2P bind **now** (lane 3 unblocked mfnd-*); **B-42** invite-load; **B-22** human seed; TL-9; later **B-43** | `launch-go-no-go` |

---

## 6. Cross-lane requests (who's waiting on whom)

Rows are `Open` → `Blocked`/`Ack` → `Done`; move `Done` rows older than one session into §8/ledger during CLOSE.

| From | To | Request | Status |
| --- | --- | --- | --- |
| 3 | all | **Do not** restart `faucet-http.service` or run parallel `join-testnet-rehearsal*` on Hetzner during B-15 (faucet lock). **B-41 mfnd P2P bind repair is explicitly allowed** — wave1 outside-in HTTP evidence is landed; full JOIN cannot proceed until seeds accept dials. | **Open** |
| 3 | 7 | **B-15 blocked on B-41:** outside-in local `mfnd` tip=0 / peer_count=0; faucet HTTP PASS (job done ~111s; IP+address cooldown confirmed). Evidence `live-testnet-probe-20260720-wave1.md` | **Blocked** |
| 2 | 1 | Green CI + Nightly on B-15 head before next release-evidence refresh | **Open** |
| planning | 1+3 | **B-29 close:** code `5dc3aa8`; re-dispatch Nightly after CI GREEN — closes only on Nightly GREEN | **Ack** |
| planning | 1 | **B-34:** watch CI `#29711605173` on `e10a8b3` (lineage `#29711500087` on `76d4f04`; escalate via GitHub Status if two restarts stay runner-starved) | **Ack** |
| planning | 3+7 | **B-42:** invite-load smoke before TL-9 — [work package](docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9); after B-15/B-41 | **Open** |
| planning | 2+7 | **B-31:** use ROADMAP work package before TL-9 (RPC/faucet/TLS verify) | **Done** (probe landed; P2P FAIL → B-41) |
| 7 | 2+3+human | **B-41:** fix VPS `vps-bind.env` P2P to `0.0.0.0:1900x`, restart mfnd-* only (not faucet-http), confirm outside dial to seeds — **unblocked by lane 3** (wave1 done; JOIN waiting on this) | **Ack** |
| 7 | human | **B-22:** provide `MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX` (not on VPS); publish near-tip checkpoint (log max tip=3 vs live ~4022) | **Blocked** |
| planning | 1+7 | **B-27:** use ROADMAP work package — TL-5/6 archives insufficient | **Open** |
| planning | 6 | **Arm B-40 + B-13a** the day TL-9/L4 closes — work packages in ROADMAP; do not stay idle | **Open** (fires on L4) |
| TESTNET | all | Mirror completed release-gate units into [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md) | Ongoing |

---

## 7. Backlog (unclaimed — who's going to do what, eventually)

Claim a row by moving it into your §5 Doing cell. Completed backlog rows move to the ledger, not to a "done" pile here.

| ID | Item | Suggested lane | Notes |
| --- | --- | --- | --- |
| B-12 | F5 phase 4b.2 — recursive STARK aggregation over batch-binding circuits | 4 | Follows `6377812`; defer until L4 unless fix-forward |
| B-13 | Parameter fork umbrella: `subsidy_to_treasury_bps = 1000` | 6 | Split into **B-13a** (sims) → **B-13b** (fork policy) → **B-13c** (enable + ops comms). **Not** TL Path B genesis. [`ROADMAP.md` Phase 1](docs/ROADMAP.md#phase-1--permanence-depth-on-the-live-chain-permanence-first) |
| B-13a | Emission/treasury sims at `1000` bps in default CI | 6 | After L4 gate; promote existing unit test to 256–512 block sim |
| B-13b | Fork policy: same-chain enable vs new `genesis_id` | 6+7+human | After B-13a green |
| B-13c | Genesis/manifest update + operator announcement | 7 | After B-13b sign-off |
| B-15 | JOIN_TESTNET outside-in VPS evidence + assert | 3 | Wave1 HTTP probe landed; **PASS archive blocked on B-41** P2P; tooling `02c8df8` |
| B-14 | TL-9 named watchers + invite circulation | 7 | Last open TL phase; blocked on B-15 + B-29 Nightly + B-26/27 (B-30 docs ✓) |
| B-17 | P31 phase 2: ASN-aware peer diversity buckets | 4 | Phase 4 adversarial; after L5 planning |
| B-18 | F15: MFBN-1 VRF variant docs + conformance tests | 4 | Phase 2; [`PROBLEMS.md` §15](docs/PROBLEMS.md) |
| B-19 | F9: decoy-RNG entropy contract + tests | 5 | Phase 3 privacy; after L4 + B-25 unless waived |
| B-20 | F6: producer↔treasury runway fee-shift policy | 6 | Phase 1 permanence; after B-13a |
| B-21 | B7 Dandelion++ internet soak evidence | 1 | Unblocks P16; after L4 |
| B-22 | TL-8 checkpoint log VPS publish verify | 7 | **Blocked:** maintainer signer seed absent on VPS; log tip=3 vs live ~4022 |
| B-23 | F18: privacy/permanence regression gate in ci-check | 2 | Phase 1; after L4 |
| B-24 | Multi-op consensus settlement audit + M5 proptests | 4 | Phase 1; after B3 multi-op internet evidence |
| B-25 | Phase 1 permanence go/no-go (30d soak + treasury bounds) | 7+human | Closes Phase 1 before Tier 2 / Path B value |
| B-26 | R-4 VPS faucet deploy (`vps-update-faucet.sh`) | 2+7 | After B-15 evidence window |
| B-27 | Fresh soak + participant evidence on invite head | 1+7 | Before TL-9; [work package](docs/ROADMAP.md#b-27-work-package--fresh-soakparticipant-on-invite-head) |
| B-28 | Treasury watch + numeric OPERATORS alert thresholds | 2+7 | Phase 1; after B-13c |
| B-29 | Nightly `fund-wallet.sh` WS tip mismatch fix | 1+3 | **Code** `5dc3aa8`; **close** = Nightly GREEN (≠ JOIN) |
| B-30 | Residual-risk owner matrix + halt authority before invites | 7 | **Docs landed** — human name cells at TL-9 sign-off |
| B-31 | Live RPC/faucet threat posture verify | 2+7 | **Probed** — evidence `b31-threat-posture-20260720.md`; RPC PASS; P2P FAIL → B-41; close after B-41+B-26 |
| B-32 | B3 multi-op evidence pack + assert (B-15-style) | 4+7 | Phase 1; [work package](docs/ROADMAP.md#b-32-work-package--multi-op-evidence-arm-day-of-l4) |
| B-33 | B-13b human sign-off checklist | 6+7+human | One-lever + producer budget + telemetry baseline before B-13c |
| B-34 | CI queue/stall watch + cancel/re-dispatch | 1 | Watch `#29711605173`; protocol in ROADMAP (Escalate → GitHub Status) |
| B-35 | F7 consensus input-count padding | 4+5 | Phase 3 privacy; wallet floor shipped |
| B-36 | F10 `f64` purge / CI lint on consensus path | 4 | Phase 1–2; §14 resolved — lint prevents regression |
| B-37 | B6/P6 hidden fees inside balance equation | 4 | Phase 3 privacy; after B-25 |
| B-38 | Repair/soak evidence + assert | 1+7 | Phase 1 permanence |
| B-39 | Phase 2 light-client / FRAUD_PROOFS honesty gate | 4+7 | After F5 4b.2 stack |
| B-40 | First permanence week (arm day-of L4) | 6 | Phase 1; [work package](docs/ROADMAP.md#b-40--first-permanence-week-lane-6--arm-day-of-l4); with **B-13a** |
| B-41 | Repair public P2P binds (`0.0.0.0:1900x`) on Hetzner | 7+2 | Phase 0; **unblocked by lane 3 wave1**; seeds loopback-only (B-31 FAIL); do not restart faucet-http |
| B-42 | Invite-load smoke before TL-9 | 3+7 | Phase 0; [work package](docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9); after B-15/B-41 |
| B-43 | Path B genesis freeze inventory | 7+human | Phase 4 / before L5; [work package](docs/ROADMAP.md#b-43--path-b-genesis-freeze-inventory-lane-7--before-l5) |
| B-44 | PM3 windowed SPoRA lottery work package | 4+6 | Phase 1; after **B-32**; [work package](docs/ROADMAP.md#b-44--pm3-work-package-lane-46--after-b-32) |

---

## 8. Session log (who did what — newest first, max 20 entries)

> One entry per landed unit or board correction: date, lane, unit, commits, verification verdicts. When this list exceeds 20, rotate the oldest entries verbatim into [`docs/AGENTS_LEDGER.md`](docs/AGENTS_LEDGER.md) § Rotated session-log entries.

1. **2026-07-20 — lane 3 — B-15 wave1 outside-in live probe**: Proxy+faucet **PASS** (job `33bb1a52…` done 111s, F7 dual tx, 503 busy, 429 address + IP cooldown); P2P seeds **FAIL** (local mfnd tip=0); checkpoint tip=3; SPoRA last_proven ~1915; front-end ports unreachable; proxy allows `submit_tx` by design. Evidence `live-testnet-probe-20260720-wave1.md`. Unblocked lane-7 **B-41** for mfnd-* only. Full JOIN **Blocked** on B-41. Docs-only `[skip ci]`. *Observed local work (not staged):* `live-testnet-data/`, `user-wallet/`, `ci-docs-*.txt`, other-lane dirty files.
2. **2026-07-19 — planning — B-40/B-42/B-43/B-44 sync**: ROADMAP work packages + critical path; provisional P2P bind renumbered **B-40 → B-41** so **B-40** = first permanence week. Docs-only `[skip ci]`.
3. **2026-07-19 — lane 1 — B-29 parse on main + CI watch claim**: Confirm `e10a8b3`; board tracks **CI `#29711605173`**. Docs-only `[skip ci]`.
4. **2026-07-19 — lane 7 — B-31 threat posture probe**: Evidence `b31-threat-posture-20260720.md` — RPC **PASS**; public P2P **FAIL**. **B-41** + human **B-22**. Docs-only `[skip ci]`.
5. **2026-07-19 — lane 1 — B-29 fund-wallet.ps1 parse fix-forward** (`00c5d33` / `e10a8b3`): PowerShell parse broke validate-rc-helper-scripts.
6. **2026-07-19 — planning — B-27/B-31/B-32 work packages + B-34** (`76d4f04` / `2fd23f1`): CI stall restart `#29711500087`; work packages.
7. **2026-07-19 — planning + lane 7 — B-30 + trajectory** (`2f1b4e2` / `9890864`): B-30 matrix; B-29 close=Nightly.
8. **2026-07-19 — lane 1 — B-29 Nightly WS tip fix** (`5dc3aa8`): empty-UTXO light-sync wiped `scan_height`; fund-wallet `--reset-trusted-summary`. Close = Nightly GREEN.
9. **2026-07-19 — planning — B-29 work package (Nightly ≠ B-15)** (`583bf11`): JOIN does not close B-29. Docs-only `[skip ci]`.
10. **2026-07-19 — planning — L4 invite gates B-26…B-31** (`8254c51`): Nightly RED → B-29. Docs-only `[skip ci]`.
11. **2026-07-19 — lane 5 — B-16 privacy-doc sync** (`49d28f9`): JOIN/TESTNET/PRIVACY/INVITE/OPERATORS + wallet/WASM. Docs-only `[skip ci]`.
12. **2026-07-19 — planning — Phase 1 permanence playbook** (`55c4abc`): **B-25** before Tier 2/Path B. Docs-only `[skip ci]`.
13. **2026-07-19 — lane 3 — B-15 checkpoint light-scan** (`02c8df8` / `73abf77`): JOIN/`fund-wallet-http`.
14. *(older history: see [`docs/AGENTS_LEDGER.md`](docs/AGENTS_LEDGER.md))*

---

## 9. Protocol details (rules + announcement template)

### Hard rules (violations block the board)

1. **One coherent unit per commit.** Small diffs keep CI failures attributable.
2. **Local CI mirror before every push** (`scripts/ci-check.*`); never push red. CI runs rustfmt, clippy `-D warnings`, release tests on three OSes, wasm, cargo-audit, and the script/board guards — see [`docs/CI.md`](docs/CI.md).
3. **Never push Rust while CI is in progress on `main`** (`cancel-in-progress` kills the matrix). Docs-only may use `[skip ci]` when CI is already running.
4. **After pushing, you watch your own CI** (`gh run list --workflow CI --limit 3`; on failure `gh run view <run-id> --log-failed`) and fix forward. Red `main` is a board-wide blocker.
5. **Do not commit another lane's uncommitted work** — note it as *Observed local work* in §8 and leave it.
6. **Stale claims release automatically:** a Doing cell older than one session without progress is fair game — the next agent moves it back to Next and notes the takeover in §8.
7. **Never fake completion.** Empty `seed_nodes` = not internet-facing. Unchecked go/no-go items = no outside invites. A green board is not a security proof (pre-audit).
8. **Board integrity is CI-enforced:** UTF-16/mojibake corruption of this file, the stubs, or the ledger fails `ci-check` and CI. Keep it clean UTF-8.

### Announcement template (chat, start + end of every session)

```text
Lane N — Done:  <units landed on main, with commit hashes / run IDs>
        Doing: <unit ID + concrete current step + claim base sha>
        Next:  <follow-up + expected owner + blockers>
```

Post it at session start (after SYNC), on any mid-unit pivot, and at CLOSE. The same content goes into §5/§8 in the landing commit — chat is for coordination, the board is the record.

### Escalation (things agents must not decide alone)

- Release/testnet sign-off, genesis ceremonies, real-key handling, VPS provisioning: **named human** per [`docs/TESTNET_CHECKLIST.md`](docs/TESTNET_CHECKLIST.md) and [`docs/TESTNET_LAUNCH.md`](docs/TESTNET_LAUNCH.md).
- Weakening any privacy or permanence guarantee (ring policy, endowment enforcement, SPoRA verification, tail emission): **not allowed** — the `mfn_consensus::constitution` fork-legitimacy invariants enforce this at genesis-spec load; propose changes in a design doc first.

---

## See also

- [`docs/ROADMAP.md`](docs/ROADMAP.md) · [`docs/TESTNET.md`](docs/TESTNET.md) · [`scripts/public-devnet-v1/OPERATORS.md`](scripts/public-devnet-v1/OPERATORS.md)
- [`docs/VIBECODING.md`](docs/VIBECODING.md) — why this board is the load-bearing part of building the chain with AI

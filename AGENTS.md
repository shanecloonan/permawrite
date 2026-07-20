# AGENTS.md — Permawrite Agent Control Board (the one pipeline)

**This is the single live coordination surface for every agent building Permawrite.** There is exactly one board (this file), one history (the ledger), and one pipeline (§3). If any other file appears to describe agent coordination, it is a pointer stub or a frozen archive — this file wins every disagreement.

**Priority doctrine:** privacy and permanence over everything. UX, ops, and CI serve those guarantees — never weaken ring policy, endowment enforcement, or SPoRA verification to make a unit land faster.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

Why this system exists (and why it is this strict): [`docs/VIBECODING.md`](docs/VIBECODING.md) — parallel lanes with a single durable board are how a chain too big for one context window gets built without agents clobbering each other.

---

## 0. The contract (read before anything else)

1. **One live board.** All claims, status, handoffs, requests, and backlog live in this file only. You never have to update two surfaces, so the board can never drift against itself.
2. **No silent work.** If you are coding without a **Doing** row in §5, stop and claim first.
3. **Read before write.** Scan the whole §5 board + §6 requests before claiming anything.
4. **History is append-only.** Completed work rotates from §8 into [docs/AGENTS_LEDGER.md](docs/AGENTS_LEDGER.md); nothing is ever silently deleted.
5. **Everything lands on main.** Commit and push every completed unit to main (standing user directive). Feature branches are for cloud-agent PR workflows only when the platform requires them.

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

**CI gate (2026-07-20):** code head = `7ab86ad` (**B-60**). **CI `#29718880625` in_progress** (runners active; rustfmt/clippy green). Live tip ~4190. **B-59** (lane 4 claim) superseded by B-60 for b3 collision harden — release or retarget. **B-29 closes only on Nightly GREEN**. Strategic path: L4 -> **B-40** -> **B-13a** -> **B-25**.

| Lane | Done (last landed) | Doing | Next (owner → unit) | Checked by |
| --- | --- | --- | --- | --- |
| **1** RC core | **B-60** (`7ab86ad`) | **Watch CI `#29718880625`** (claim base: `7ab86ad`) | On GREEN: Nightly -> close B-29 | githubstatus + CI/Nightly |
| **2** RC ops | R-1–R-4 (`2b655d2`…`dc05c40`) | *Idle* | Release evidence after CI+Nightly GREEN; **B-26** after B-15 | Board + encoding guards |
| **3** Onboarding | **B-15 wave14** (`6ead0f0` + addendum: F75–F79, grace upload) | **B-15** JOIN SUMMARY soft path (claim base: this head) | Archive SUMMARY; avoid Hetzner parallel JOIN | L4 checklist |
| **4** Protocol | **B-51** (`e69e603`); **B-48**/`B-45` | *Idle* (B-59 b3 flake covered by **B-60** `7ab86ad`) | After CI GREEN: live **B-32**; then **B-44** -> **B-24** | Lane 1 CI |
| **5** Privacy | **B-16** (`49d28f9`) | *Idle* | **B-50 follow-up:** Rust auto-bootstrap from checkpoint log; After B-25: **B-35** / **B-37** / **B-19** | Doc-accuracy duty |
| **6** Permanence | F6 telemetry (`0d1b9ec`) | *Idle* | **Armed:** **B-40** + **B-13a** day-of L4; then **B-33** | Emission sims |
| **7** Testnet launch | **B-62** prebuild+roll-ready; **B-43** freeze draft; B-61 | *Idle* | On CI GREEN: `assert-vps-roll-ready` then `vps-roll-mfnd --apply` (skip-build if prebuild OK); **B-42** after B-15 PASS | `launch-go-no-go` |

---

## 6. Cross-lane requests (who's waiting on whom)

Rows are `Open` → `Blocked`/`Ack` → `Done`; move `Done` rows older than one session into §8/ledger during CLOSE.

| From | To | Request | Status |
| --- | --- | --- | --- |
| 3 | all | **Do not** run parallel `join-testnet-rehearsal*` on Hetzner during B-15. Prefer not to restart `faucet-http` while `busy`/`pending_jobs` (B-47/B-53/B-56 deploy OK when idle). **Do not** thrash `mfnd-hub` while tip sealing (B-46). **B-45 mfnd roll** after CI GREEN allowed. | **Open** |
| 4 | 7 | **B-45+B-48+B-51:** on main. Roll after CI GREEN; **B-61** CI via gh/API + RPC wait. Never touch `faucet-http` | **Open** (VPS roll) |
| 3 | 7 | **B-15 blocked on B-41:** outside-in local `mfnd` tip=0 / peer_count=0; faucet HTTP PASS. Evidence `live-testnet-probe-20260720-wave1.md` | **Done** (B-41 socat forwards live; seeds dialable) |
| 3 | 7 | **Tip stall + faucet EAGAIN:** tip was stuck **4031**; **B-46** restored production. Wave6: tip **4040+**, alice faucet job **done** 122s (2 txs) — EAGAIN streak broken. Evidence live-testnet-probe-20260720-wave6.md | **Done** |
| 2 | 1 | Green CI + Nightly on B-15 head before next release-evidence refresh | **Open** |
| planning | 1+3 | **B-29 close:** code `5dc3aa8`; re-dispatch Nightly after CI GREEN — closes only on Nightly GREEN | **Ack** |
| planning | 1 | **B-34:** `#29713542820` in_progress on `4d07b7d` (post-outage dispatch) | **Ack** |
| 1 | 7 | Outside-in: observer proxy `ECONNREFUSED 127.0.0.1:18734`; B-15 wave4 reports P2P `:19001` down — repair without faucet restart | **Done** (B-46; tip advancing; proxy OK) |
| 7 | 3 | **B-50:** `--checkpoint-log` does not skip genesis — use `bootstrap-wallet-from-checkpoint-log.sh --apply` (or `.ps1` on Windows — B-52) for receive verify | **Open** |
| 7 | 5 | **B-50 follow-up:** Rust — `light-scan --checkpoint-log` should auto-bootstrap from log max tip (docs honesty landed) | **Open** |
| 3 | 7 | **F54** proxy `get_light_snapshot` TIMEOUT; **F56** Windows no bash for B-50 | **Done** (B-52: heavy timeout 180s + `.ps1` twin) |
| planning | 3+7 | **B-42:** invite-load plan script landed; **live** after B-15 PASS — [work package](docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9) | **Ack** (plan) |
| planning | 2+7 | **B-31:** use ROADMAP work package before TL-9 (RPC/faucet/TLS verify) | **Done** (probe landed; P2P FAIL → B-41) |
| 7 | 2+3+human | **B-41:** public seed reachability | **Done** (socat forwards; do **not** bind mfnd on 0.0.0.0 — hangs) |
| 7 | human | **B-22:** near-tip checkpoint | **Done** (Path A tip **4148** + public seed anchors; seed offline on VPS only) |
| planning | 1+7 | **B-27:** use ROADMAP work package — TL-5/6 archives insufficient | **Open** |
| planning | 6 | **Arm B-40 + B-13a** the day TL-9/L4 closes — work packages in ROADMAP; do not stay idle | **Open** (fires on L4) |
| 3 | 5+7 | **JOIN tall-tip UX:** F68b PASS; F45 soft; F71/F78 pending clear; F74 tip-diff; **F75** need ≥2 UTXOs; **F76** wait owned≥2; **F79** pin≤oldest fund. | **Open** (SUMMARY archive) |
| 3 | 7+4 | **Wave10 F62/F65:** VPS not F62 (chain.blocks 6.3MiB, get_block PASS). F65 last_proven=4071 needs B-45 mfnd roll after CI+B-51. Evidence `b53-…` + wave10 | **Done** (F62 VPS); **Open** (F65→roll) |
| 7 | 3 | **B-53:** faucet `/health` no longer blocks on keepalive lock; use `assert-vps-block-log-health.sh` for F62 checks | **Open** |
| 7 | 1+4 | **CI `#29715111633`:** produce-smoke timeout fixed in B-51 (60s); **b3_legacy** flake = **B-59** (1/num_chunks collision) | **Ack** (B-51); **Open** (B-59) |
| 7 | 3 | **B-22 tip-4173 + B-61:** re-pin / soft light-scan at new log max for SUMMARY | **Open** |
| 7 | 3 | **B-55:** browser UI at `http://5.161.201.73:3000/testnet` (optional; local observer still preferred for JOIN evidence) | **Open** |
| 7 | 3 | **B-56:** faucet keepalive tip-first — fewer hub EAGAIN during B-50 snapshot pin | **Open** |
| 3 | 7 | **F68/F68b:** Windows bootstrap ps1 - temp `.py` TCP snapshot (B-58). Evidence wave12 + `b58-…` | **Done** (B-58) |
| 7 | 3 | **B-59:** wire `join-testnet-rehearsal.sh` light-scan through `light-scan-checkpoint-soft.sh` (F45 tip race) | **Done** (B-60) |
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
| B-15 | JOIN_TESTNET outside-in VPS evidence + assert | 3 | Wave1 landed; B-41 seeds OPEN — full JOIN archive next |
| B-14 | TL-9 named watchers + invite circulation | 7 | Last open TL phase; blocked on B-15 + B-29 Nightly + B-26/27 (B-30 docs ✓) |
| B-17 | P31 phase 2: ASN-aware peer diversity buckets | 4 | Phase 4 adversarial; after L5 planning |
| B-18 | F15: MFBN-1 VRF variant docs + conformance tests | 4 | Phase 2; [`PROBLEMS.md` §15](docs/PROBLEMS.md) |
| B-19 | F9: decoy-RNG entropy contract + tests | 5 | Phase 3 privacy; after L4 + B-25 unless waived |
| B-20 | F6: producer↔treasury runway fee-shift policy | 6 | Phase 1 permanence; after B-13a |
| B-21 | B7 Dandelion++ internet soak evidence | 1 | Unblocks P16; after L4 |
| B-22 | TL-8 checkpoint log VPS publish verify | 7 | **Done** - tip **4173** Path A (entries=10); seed offline on VPS only |
| B-23 | F18: privacy/permanence regression gate in ci-check | 2 | Phase 1; after L4 |
| B-24 | Multi-op consensus settlement audit + M5 proptests | 4 | Phase 1; after B3 multi-op internet evidence |
| B-25 | Phase 1 permanence go/no-go (30d soak + treasury bounds) | 7+human | Closes Phase 1 before Tier 2 / Path B value |
| B-26 | R-4 VPS faucet deploy (`vps-update-faucet.sh`) | 2+7 | After B-15 evidence window |
| B-27 | Fresh soak + participant evidence on invite head | 1+7 | Before TL-9; [work package](docs/ROADMAP.md#b-27-work-package--fresh-soakparticipant-on-invite-head) |
| B-28 | Treasury watch + numeric OPERATORS alert thresholds | 2+7 | Phase 1; after B-13c |
| B-29 | Nightly `fund-wallet.sh` WS tip mismatch fix | 1+3 | **Code** `5dc3aa8`; **close** = Nightly GREEN (≠ JOIN) |
| B-30 | Residual-risk owner matrix + halt authority before invites | 7 | **Docs landed** — human name cells at TL-9 sign-off |
| B-31 | Live RPC/faucet threat posture verify | 2+7 | **P2P+RPC PASS** after B-41/B-46; close after **B-26** R-4 deploy confirm |
| B-32 | B3 multi-op evidence pack + assert (B-15-style) | 4+7 | **Tooling landed**; live pack day-of L4 |
| B-33 | B-13b human sign-off checklist | 6+7+human | One-lever + producer budget + telemetry baseline before B-13c |
| B-34 | CI queue/stall watch + cancel/re-dispatch | 1 | Watch `#29711605173`; protocol in ROADMAP (Escalate → GitHub Status) |
| B-35 | F7 consensus input-count padding | 4+5 | Phase 3 privacy; wallet floor shipped |
| B-36 | F10 `f64` purge / CI lint on consensus path | 4 | **Landed** - scripts fill `54d22d7` hook gap |
| B-37 | B6/P6 hidden fees inside balance equation | 4 | Phase 3 privacy; after B-25 |
| B-38 | Repair/soak evidence + assert | 1+7 | Phase 1 permanence |
| B-39 | Phase 2 light-client / FRAUD_PROOFS honesty gate | 4+7 | After F5 4b.2 stack |
| B-40 | First permanence week (arm day-of L4) | 6 | Phase 1; [work package](docs/ROADMAP.md#b-40--first-permanence-week-lane-6--arm-day-of-l4); with **B-13a** |
| B-41 | Public P2P seed reachability (socat forwards) | 7+2 | **Done** — mfnd :1910x + socat :1900x; EXT 19001–19003 OPEN; tip~4031 |
| B-42 | Invite-load smoke before TL-9 | 3+7 | Plan script landed; **live** after B-15 PASS — [work package](docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9) |
| B-43 | Path B genesis freeze inventory | 7+human | **Draft** — `docs/PATH_B_GENESIS_FREEZE.md`; human cells TBD; no ceremony |
| B-44 | PM3 windowed SPoRA lottery work package | 4+6 | Phase 1; after **B-32**; [work package](docs/ROADMAP.md#b-44--pm3-work-package-lane-46--after-b-32) |
| B-45 | B3 operator-salted challenge/prove/pool path | 4 | **Landed** — unblocks honest multi-op SPoRA on salted genesis; Hetzner mfnd roll = lane 7 |
| B-46 | Tip-stall ops harden: `Wants=` + hub dial extras | 4+7 | **Landed** `4d07b7d` — tip 4031→4034+ |
| B-47 | Faucet EAGAIN harden (health/CLI race) | 7+2 | **Done** (`fe56ca8`) — health lock + runRetry; VPS faucet restarted idle; tip 4047+ |
| B-48 | Soft-ignore EAGAIN for P2P peer quarantine | 4 | **Landed** — soft-fail EAGAIN/WouldBlock in peer quarantine (not os error 111) |
| B-49 | VPS `vps-roll-mfnd.sh` tooling (hub+voters, no faucet) | 7 | **Done** (`284e803`) — live apply after CI GREEN |
| B-50 | Checkpoint-log bootstrap honesty + helper | 7+5 | **Done** (docs+script); Rust auto-bootstrap still follow-up for lane 5 |
| B-51 | No dial/quarantine of ephemeral inbound P2P ports | 4 | **Landed** — durable-only block/fraud dial; skip quarantine for non-durable peers; GHA smoke budget 60s |
| B-52 | Observer proxy heavy RPC timeout + Windows B-50 twin | 7 | **Done** — F54/F56; `PROXY_HEAVY_RPC_TIMEOUT_MS=180000`; `.ps1` twin |
| B-53 | Non-blocking faucet `/health` + VPS block-log assert | 7 | **Done** — F62 VPS cleared |
| B-54 | F67 pin-then-fund (JOIN + fund-wallet-http) | 7 | **Done** — pin before faucet |
| B-55 | Public testnet frontend on VPS `:3000` | 7 | **Done** — Next.js systemd + UFW; http://5.161.201.73:3000/testnet |
| B-56 | Tip-first faucet keepalive (cut snapshot EAGAIN) | 7 | **Done** - tip poll without wallet lock when caught up |
| B-57 | F68 Windows bootstrap ps1 - python TCP snapshot | 7 | **Done** - superseded by B-58 temp `.py` |
| B-58 | F68b Windows bootstrap - temp `.py` not `python -c` | 7 | **Done** - tunnel smoke snapshot_ok+pin tip 4159 |
| B-59 | F45 soft light-scan + tip-4166 ckpt | 7 | **Done** - `light-scan-checkpoint-soft.sh`; Schnorr still hard |
| B-60 | mfnd roll CI+faucet preflight + JOIN F45 wire | 7 | **Done** — B-60.1 closes gh fail-open hole |
| B-61 | Roll CI via public API + hub RPC listen wait + tip-4173 | 7 | **Done** |
| B-62 | VPS mfnd prebuild + assert-vps-roll-ready | 7 | **Done** — no service restart |

---

## 8. Session log (who did what — newest first, max 20 entries)

> One entry per landed unit or board correction: date, lane, unit, commits, verification verdicts. When this list exceeds 20, rotate the oldest entries verbatim into [`docs/AGENTS_LEDGER.md`](docs/AGENTS_LEDGER.md) § Rotated session-log entries.

1. **2026-07-20 — lane 3 — B-15 wave14 addendum** (this commit): grace upload `3e728a8e…` after F78; F79 pin-too-high (dave 90k@4148 vs 1.09M@4050). Board sync to wave14. Evidence wave14.md addendum. `[skip ci]`. *Observed:* probe temps, `user-wallet/`, `live-testnet-data*`, other-lane WIP.
2. **2026-07-20 — lane 3 — B-15 wave14** (`6ead0f0`): frank faucet+upload `90aae951…` last_proven=**4183**; F75–F78. Evidence `live-testnet-probe-20260720-wave14.md`. `[skip ci]`.
3. **2026-07-20 — lane 1 — watch CI `#29718880625`**: B-60 on `7ab86ad` in matrix; tip~4190 outside-in. B-59 claim released (superseded by B-60). Docs-only `[skip ci]`. *Observed local work (not staged):* lane-3 wave14 temps, `user-wallet/`, `live-testnet-data*`.
4. **2026-07-20 — lane 1 — B-60 B3 collision + smoke CI harden** (this commit): `b3_legacy_challenge_rejected_when_enabled` + `b3_rejects_unsalted_proof_when_salted_required` pick non-colliding slots; smoke accepts sealed/proposal log lines under GHA drain races. Targets `#29717107514` RED.
5. **2026-07-20 — lane 3 — B-15 wave13** (`3bb6de7`): F74 wipe+resync; F68b `-Apply` PASS; grace→dave 100k; F71 re-pin. Evidence wave13.md. `[skip ci]`.
2. **2026-07-20 - lane 7 - B-62 prebuild/roll-ready + B-43 freeze draft** (`c90962b`): `vps-prebuild-mfnd` + `assert-vps-roll-ready`; Path B inventory doc (no ceremony). VPS cargo prebuild running (no restarts). `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.
2. **2026-07-20 - lane 7 - B-61 API CI gate + RPC wait + tip-4173** (this commit): `vps-roll-mfnd` uses public Actions API when `gh` missing; wait for hub RPC listen after restart; Path A ckpt tip **4173** (entries=10). No rebuild-roll (CI in flight). `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.
3. **2026-07-20 - lane 7 - B-60.1 gh fail-closed + hub recover** (this commit): missing `gh` now exit 4 (was WARN-continue; caused skip-build roll smoke). Hub replay load ~2-3min after restart — do not thrash. `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.
4. **2026-07-20 - lane 7 - B-60 roll preflight + JOIN F45 wire** (this commit): `vps-roll-mfnd` refuse on red/in-progress CI or busy faucet; `join-testnet-rehearsal` -> `light-scan-checkpoint-soft`. No mfnd apply (CI `#29717107514` in flight; faucet busy). `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.
5. **2026-07-20 — lane 4 — B-59 claim** (this commit): CI `#29715111633` ubuntu flake was `b3_legacy_challenge_rejected_when_enabled` accepting when legacy chunk index collides with operator-salted (p≈1/num_chunks). Fix picks a diverging slot; local PASS. Docs-only `[skip ci]` while `#29717107514` runs — do not cancel. *Observed:* leave bootstrap/JOIN/checkpoint WIP unstaged; VPS still pre-B-48 (ephemeral quarantine until roll).
1. **2026-07-20 — lane 1 — watch CI `#29717107514` (B-51)**: Prior `#29715111633` RED was `public_devnet_hub_reaches_height_one…` tip diverge (not B3 flake on that head). B-51 landed by lane 4 (`e69e603`). Local B3 non-colliding-slot harden staged for after matrix. Docs-only `[skip ci]`.

1. **2026-07-20 — lane 1 — B-51 + B3 CI fix-forward** (this commit): Recovered ephemeral-peer quarantine harden (`note_peer_failure` skips non-durable; block/fraud fanout dials durable only). Hardened `b3_legacy_challenge_rejected_when_enabled` to pick non-colliding slot. Targets CI `#29715111633` RED (`public_devnet_hub_reaches_height_one…` tip diverge). Local focused tests green.

1. **2026-07-20 - lane 7 - board SYNC** (this commit): B-51 confirmed on main (`e69e603`) after B-59 land; prior SYNC note was stale mid-push. Hold mfnd roll for CI GREEN. `[skip ci]`.
6. **2026-07-20 - lane 7 - B-59/F45 soft + B-22 tip-4166** (this commit): `light-scan-checkpoint-soft.sh` soft-pass tip race; Path A ckpt tip **4166** (entries=9). SYNC: B-51 not on origin/main (left lane-4 WIP unstaged). `[skip ci]`. *Observed:* lane-4 `p2p_fanout.rs` / smoke / `block_apply.rs`, lane-3 temps, `user-wallet/`, `live-testnet-data*`.
1. **2026-07-20 - lane 7 - B-58/F68b Windows bootstrap temp `.py`** (this commit): write snapshot/pin helpers to temp files (wave12 F68b). Tunnel smoke: `snapshot_ok` + pin 4159. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs`, lane-3 temps, `user-wallet/`, `live-testnet-data*`.
8. **2026-07-20 - lane 7 - B-22 tip-4159 Path A checkpoint** (this commit): `publish-checkpoint-log.sh --apply` tip **4159** (entries=8); public seed anchors; faucet untouched. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), lane-3 temps, `user-wallet/`, `live-testnet-data*`.
9. **2026-07-20 - lane 7 - B-57/F68 Windows bootstrap TCP snapshot** (this commit): `bootstrap-wallet-from-checkpoint-log.ps1` uses python TCP JSON-RPC for `get_light_snapshot` (PS5.1 strips quotes on mfn-cli `--params`). UTF-8 rewrite. VPS TCP+proxy smoke tip=4148. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), lane-3 evidence temps, `user-wallet/`, `live-testnet-data*`.
10. **2026-07-20 — lane 7 — B-56 tip-first faucet keepalive** (this commit): keepalive polls tip without wallet lock when near tip; full sync only when behind. Cuts EAGAIN vs `get_light_snapshot`. Deploy: restart `faucet-http` when idle. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), lane-3 `bootstrap-wallet-from-checkpoint-log.ps1` / probe temps, `user-wallet/`, `live-testnet-data*`.
11. **2026-07-20 — lane 7 — B-55 testnet frontend** (this commit): systemd `testnet-frontend` on `:3000` + UFW; `vps-start-testnet-frontend.sh`; JOIN/OPERATORS links. Never restarts mfnd/faucet. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 temps, `live-testnet-data*`.
12. **2026-07-20 — lane 7 — B-22 tip-4148 checkpoint** (this commit): Path A signer appended tip **4148** (lag was 13+); public seed anchors; faucet untouched. Noted CI `#29715111633` ubuntu FAIL for lane 4/1. Evidence `b22-checkpoint-tip4148-20260720.md`. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 temps, `live-testnet-data*`.
13. **2026-07-20 — lane 7 — B-54 F67 pin-then-fund** (this commit): JOIN Step 5 + `fund-wallet-http` pin before faucet; rehearsal plan strings; evidence `b54-f67-pin-then-fund-20260720.md`. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 probe temps, `live-testnet-data*`.
14. **2026-07-20 — lane 7 — B-53 faucet health + F62 assert** (this commit): `/health` never awaits wallet lock (`wallet_lock_held`); `assert-vps-block-log-health.sh`; VPS tip~4140 `get_block` PASS / `chain.blocks` 6.3MiB (F62 laptop-only). Deploy: restart `faucet-http` when idle. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 probe temps, `live-testnet-data*`.
15. **2026-07-20 — lane 7 — B-52 F54/F56** (this commit): proxy per-method heavy timeout (180s) for `get_light_snapshot`/`get_block_headers`; Windows `bootstrap-wallet-from-checkpoint-log.ps1`; JOIN note; evidence `b52-proxy-heavy-timeout-ps1-twin-20260720.md`. Deploy: restart `observer-rpc-proxy` only. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 `_write_w10_open.py` / `_wave10-carol-upload.json`, `live-testnet-data/`.
16. **2026-07-20 — lane 7 — B-22 tip-4133 checkpoint** (`90c9c5c`): Path A tip **4133**; public seed anchors.
17. **2026-07-20 — lane 3 — B-15 wave10 open** (`a550ad4`): tip 4131, ckpt lag 74.
18. **2026-07-20 — lane 4 — B-51 claim** (`e236e6a`): ephemeral fanout quarantine.
19. **2026-07-20 — lane 3 — B-15 wave9** (`d3213a5`): SPoRA prove Fresh + pool.
20. **2026-07-20 — lane 3 — B-15 wave8** (`387b6ae`/`334af3d`/`01b390a`).

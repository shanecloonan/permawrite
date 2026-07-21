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

**CI gate (2026-07-21):** Landing **B-100** Path A tip-4851 (full CI). **CI `#29798634416` GREEN** on B-97 `de0d94c`. **B-29 CLOSED**. Strategic path: L4 -> **B-40** -> **B-13a** -> **B-25**.

| Lane | Done (last landed) | Doing | Next (owner → unit) | Checked by |
| --- | --- | --- | --- | --- |
| **1** RC core | **B-93** (`1a2b496`, CI `#29788432236` GREEN); **B-27** (`08f8001`); **B-34** | *Idle* | Participant JOIN half after B-15 SUMMARY (lane 3); leave Hetzner/protocol to 7/4 | CI/Nightly run IDs |
| **2** RC ops | **B-94** spent-debris prune (`598a853`); R-1–R-4 | *Idle* | Release evidence after CI+Nightly GREEN; **B-26** after B-15 | Board + encoding guards |
| **3** Onboarding | **B-15 wave58** (zion last_proven=4823; faucet-F101b; F45 lag=130) | **B-15** formal JOIN archive assert (claim base: this head) | Human/assert SUMMARY; re-pin at ckpt **4851** after B-100 | L4 checklist |
| **4** Protocol | **B-98** slash→op1 asymmetric settle (this commit); **B-95** (`665c166`, CI `#29795731587` GREEN); **B-86** (`9fede5b`/`bef823d`, CI `#29793832972` GREEN); **B-83**/**B-81**/**B-76**/**B-74**/**B-67**/**B-71**/**B-66**/**B-64**/**B-63** | **B-32** live pack — blocked on 2nd host (**B-79** NOT READY) | **B-99** slash→empty both-miss (post-slash prove matrix); after 2 hosts + B-15: `b3-multi-op-*.txt` → **B-44** → full **B-24** | Lane 1 CI |
| **5** Privacy | **B-16** (`49d28f9`) | *Idle* | **B-50 follow-up:** Rust auto-bootstrap from checkpoint log; After B-25: **B-35** / **B-37** / **B-19** | Doc-accuracy duty |
| **6** Permanence | F6 telemetry (`0d1b9ec`) | *Idle* | **Armed:** **B-40** + **B-13a** day-of L4; then **B-33** | Emission sims |
| **7** Testnet launch | **B-100** tip-4851 (this commit; entries=33; lag=0); **B-97** tip-4833 (`de0d94c`); **B-92** | *Idle* | **B-42** after B-15 PASS; real 2nd host for B-32 | `launch-go-no-go` |

---

## 6. Cross-lane requests (who's waiting on whom)

Rows are `Open` → `Blocked`/`Ack` → `Done`; move `Done` rows older than one session into §8/ledger during CLOSE.

| From | To | Request | Status |
| --- | --- | --- | --- |
| 3 | all | **Do not** run parallel `join-testnet-rehearsal*` on Hetzner during B-15. Prefer not to restart `faucet-http` while `busy`/`pending_jobs` (B-47/B-53/B-56 deploy OK when idle). **Do not** thrash `mfnd-hub` while tip sealing (B-46). **B-45 mfnd roll** after CI GREEN allowed. | **Open** |
| 4 | 7 | **B-45+B-48+B-51+B-64:** rolled on Hetzner after **CI `#29725270815` GREEN**; **B-68** peers scrub restored tip | **Done** (VPS roll) |
| 7 | 4 | **B-68 follow-up:** filter ephemeral/0.0.0.0 on `peers.json` load so polluted durable sets cannot recur (ops scrub is not enough) | **Done** (B-71 + B-73 smoke) |
| 4 | 7 | **B-32:** mfnd re-roll with B-71/B-73 binary; then help arm ≥2 distinct-host operators for live multi-op pack (after B-15 JOIN window) | **Ack** — **B-77** rolled; **B-79** arm-ready NOT READY (1 host); need real `MFN_B32_OPERATOR_HOSTS` >=2 |
| 3 | 7 | **B-15 blocked on B-41:** outside-in local `mfnd` tip=0 / peer_count=0; faucet HTTP PASS. Evidence `live-testnet-probe-20260720-wave1.md` | **Done** (B-41 socat forwards live; seeds dialable) |
| 3 | 7 | **Tip stall + faucet EAGAIN:** tip was stuck **4031**; **B-46** restored production. Wave6: tip **4040+**, alice faucet job **done** 122s (2 txs) — EAGAIN streak broken. Evidence live-testnet-probe-20260720-wave6.md | **Done** |
| 2 | 1 | Green CI + Nightly on B-15 head before next release-evidence refresh | **Open** |
| planning | 1+3 | **B-29 close:** seed-isolation `23204cb` + CI GREEN; Nightly `#29727713979` — closes only on Nightly GREEN | **Ack** |
| planning | 1 | **B-34:** `#29713542820` in_progress on `4d07b7d` (post-outage dispatch) | **Done** (tooling landed this commit) |
| 1 | 7 | Outside-in: observer proxy `ECONNREFUSED 127.0.0.1:18734`; B-15 wave4 reports P2P `:19001` down — repair without faucet restart | **Done** (B-46; tip advancing; proxy OK) |
| 7 | 3 | **B-50:** `--checkpoint-log` does not skip genesis — use `bootstrap-wallet-from-checkpoint-log.sh --apply` (or `.ps1` on Windows — B-52) for receive verify | **Open** |
| 7 | 5 | **B-50 follow-up:** Rust — `light-scan --checkpoint-log` should auto-bootstrap from log max tip (docs honesty landed) | **Open** |
| 3 | 7 | **F54** proxy `get_light_snapshot` TIMEOUT; **F56** Windows no bash for B-50 | **Done** (B-52: heavy timeout 180s + `.ps1` twin) |
| planning | 3+7 | **B-42:** invite-load plan script landed; **live** after B-15 PASS — [work package](docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9) | **Ack** (plan) |
| planning | 2+7 | **B-31:** use ROADMAP work package before TL-9 (RPC/faucet/TLS verify) | **Done** (probe landed; P2P FAIL → B-41) |
| 7 | 2+3+human | **B-41:** public seed reachability | **Done** (socat forwards; do **not** bind mfnd on 0.0.0.0 — hangs) |
| 7 | human | **B-22:** near-tip checkpoint | **Done** (Path A tip **4148** + public seed anchors; seed offline on VPS only) |
| planning | 1+7 | **B-27:** use ROADMAP work package — TL-5/6 archives insufficient | **Done** (soak tooling+live PASS `9f5ed4d`) |
| planning | 6 | **Arm B-40 + B-13a** the day TL-9/L4 closes — work packages in ROADMAP; do not stay idle | **Open** (fires on L4) |
| 3 | 5+7 | **JOIN tall-tip UX:** heidi loop PASS (wave15). F45 soft; F75–F80 (owned≥2, pin hygiene, post-pin tip catch-up). SUMMARY draft next. | **Open** (SUMMARY archive) |
| 3 | 7+4 | **Wave10 F62/F65:** VPS not F62 (chain.blocks 6.3MiB, get_block PASS). F65 last_proven=4071 needs B-45 mfnd roll after CI+B-51. Evidence `b53-…` + wave10 | **Done** (F62 VPS); **Done** (mfnd roll + B-68) |
| 7 | 3 | **B-53:** faucet `/health` no longer blocks on keepalive lock; use `assert-vps-block-log-health.sh` for F62 checks | **Open** |
| 7 | 1+4 | **CI `#29715111633`:** produce-smoke timeout fixed in B-51 (60s); **b3_legacy** flake = **B-60** (`7ab86ad`) | **Done** |
| 7 | 3 | **B-22 / B-100 tip-4851:** re-pin / soft light-scan at new log max for SUMMARY (B-97 was 4833) | **Open** |
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
| B-22 | TL-8 checkpoint log VPS publish verify | 7 | **Done** - tip **4262** Path A (entries=11); seed offline on VPS only |
| B-23 | F18: privacy/permanence regression gate in ci-check | 2 | Phase 1; after L4 |
| B-24 | Multi-op consensus settlement audit + M5 proptests | 4 | Phase 1; after B3 multi-op internet evidence |
| B-25 | Phase 1 permanence go/no-go (30d soak + treasury bounds) | 7+human | Closes Phase 1 before Tier 2 / Path B value |
| B-26 | R-4 VPS faucet deploy (`vps-update-faucet.sh`) | 2+7 | After B-15 evidence window |
| B-27 | Fresh soak + participant evidence on invite head | 1+7 | **Soak refreshed** (this commit; tip 4663->4665; Nightly `#29779143837`); participant JOIN half = lane-3 SUMMARY / post-B-15 |
| B-28 | Treasury watch + numeric OPERATORS alert thresholds | 2+7 | Phase 1; after B-13c |
| B-29 | Nightly participant+observer GREEN | 1+3 | **CLOSED** — Nightly #29755942849 GREEN on d248ba2 (B-75 inclusive) |
| B-75 | Nightly observer mesh tip-stall after h1 (EAGAIN) | 1 | **Landed** (this commit) - production_dial_peers + persistable start-all / produce-smoke ports |
| B-30 | Residual-risk owner matrix + halt authority before invites | 7 | **Docs landed** — human name cells at TL-9 sign-off |
| B-31 | Live RPC/faucet threat posture verify | 2+7 | **P2P+RPC PASS** after B-41/B-46; close after **B-26** R-4 deploy confirm |
| B-32 | B3 multi-op evidence pack + assert (B-15-style) | 4+7 | **Tooling + ci-check gate (B-74)**; live pack day-of L4 |
| B-74 | Wire B-32 plan smoke + fixture assert into ci-check | 4 | **Landed** (this commit) — `.sh`/`.ps1` twins; closes ROADMAP CI row for B-32 tooling |
| B-33 | B-13b human sign-off checklist | 6+7+human | One-lever + producer budget + telemetry baseline before B-13c |
| B-34 | CI queue/stall watch + cancel/re-dispatch | 1 | **Landed** (this commit) — `scripts/watch-ci-stall.py` + ci-check plan gate (gate was prematurely wired in B-90; scripts complete it); `--cancel-if-stalled` only when zero progress |
| B-93 | Post-push CI stall watch wrapper (B-34 follow-up) | 1 | **Landed** (this commit) — `scripts/post-push-ci-watch.py` + ci-check plan gate; wired into after-push agent rule |
| B-94 | Spent-debris prune + gitignore tighten (M2.5.39 follow-up) | 2 | **Landed** (this commit) — delete 5 tracked spent one-shots; ignore `_*.py` / lane WIP / nightly dumps / live-testnet-data* / evidence `_*` |

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
| B-65 | VPS lib-cargo-env for non-interactive cargo | 7 | **Done** — prebuild/roll source `~/.cargo/env` |
| B-68 | Scrub ephemeral `peers.json` + wire into `vps-roll-mfnd` | 7 | **Done** — tip stall fix post-roll; load-filter = **B-71** |
| B-69 | Produce-smoke `MFN_SKIP_MANIFEST_SEEDS` (B-29 CI complete) | 7+1 | **Done** — windows `#29728151679` red was public tip sync |
| B-70 | Near-tip Path A checkpoint + peers-clean assert | 7 | **Landed** (`09ca8c4`) — tip **4307** + `assert-vps-peers-clean` |
| B-71 | Persistable peer addr filter (load/save/register) | 4+7 | **Landed** (`09ca8c4`) — closes B-68 follow-up |
| B-73 | B-71 CI fix: persistable listen ports in reconnect smoke | 7 | **Landed** (`5df7cbc`) — CI `#29736528564` GREEN |
| B-77 | B-71 Hetzner mfnd roll + tip-4400 Path A ckpt | 7 | **Landed** (`b1ce264`) |
| B-78 | Docs-equivalent CI roll gate (ancestor GREEN + non-src diff) | 7 | **Landed** (`faa8683`) — `lib-ci-roll-gate.sh` |
| B-79 | B-32 arm-ready inventory + Path A tip-4443 + bootstrap RPC fix | 7 | **Landed** (`2444a04`); NOT READY until 2nd host |
| B-80 | Path A near-tip checkpoint tip-4496 (F45 lag close) | 7 | **Landed** (`24c60b6`); entries=16 |
| B-82 | Path A near-tip checkpoint tip-4532 + B-32 second-host checklist | 7 | **Landed** (`de6a9db`); entries=18 |
| B-84 | Path A near-tip checkpoint tip-4554 + faucet 429 ops note | 7 | **Landed** (`e45c9ec`); **CI `#29764280042` GREEN**; entries=19 |
| B-85 | Auto Path A republish when tip lag >= threshold + tip-4567 | 7 | **Landed** (`a1ac45c`); **CI `#29766146798` GREEN**; entries=20 |
| B-87 | Path A tip-4584 (B-85 live fire on Hetzner lag=17) | 7 | **Landed** (`ed3c51e`); **CI `#29769164562` GREEN**; entries=21 |
| B-88 | VPS B-85 lag timer (30m) + tip-4606 + F107/F108 OPERATORS | 7 | **Landed** (`3a0efff`); **CI `#29771537059` GREEN**; entries=22 |
| B-89 | Path A timer health assert + VPS land helper + tip-4624 | 7 | **Landed** (`a0458bf`); **CI `#29773999207` GREEN**; entries=23 |
| B-90 | Observer proxy tip-align before list_recent_uploads (F105) + tip-4641 | 7 | **Landed** (`89a047b`); CI `#29776397760` cancelled by B-34; re-proved via B-91; entries=24 |
| B-91 | Public-testnet health assert (timer+proxy tip-align+faucet+ckpt lag) + tip-4662 | 7 | **Landed** (`13cdb01`); **CI `#29779275119` GREEN**; entries=25 |
| B-92 | Path A tip-4679 (lag=17 after waves 46-47) + B-91 CI note | 7 | **Landed** (this commit); entries=26 |
| B-97 | Path A tip-4833 land + Windows land-path-a-checkpoint-from-vps.ps1 | 7 | **Landed** (this commit); closes F45 lag~130; exact-tip 4833; entries=32; B-15-safe |
| B-100 | Path A tip-4851 land (post-B-97 lag reopen) | 7 | **Landed** (this commit); entries=33; B-15-safe; health OK |
| B-63 | Multi-op partial-set settlement + coinbase compose (early B-24a) | 4 | **Landed** — coinbase N+1 + 1-of-2 miss identity; not full B-24 |
| B-64 | Settlements soft-skip vs apply hard-reject + producer seal filter | 4 | **Landed** — seal settlement-accepted proofs only; parity tests |
| B-66 | Which-operator prove miss/settle chain (early B-24b) | 4 | **Landed** — op1-only + window-spaced mask chain; not full B-24 |
| B-67 | Multi-op slash while peer settles + treasury identity (early B-24c) | 4 | **Landed** on `f6273cb` (commit subject mislabeled B-70/B-71); not full B-24 |
| B-74 | B-32 multi-op evidence plan gate in ci-check | 4 | **Landed** (`62a9c02`); **CI `#29739903305` GREEN** |
| B-76 | Dual-operator empty-audit slash treasury identity (early B-24d) | 4 | **Landed** (`dc50737`/`5492a07`); covered by **CI `#29753244727` GREEN** |
| B-81 | Full-slash deregister while peer settles (early B-24e) | 4 | **Landed** (`f924a63`); **CI `#29758805553` GREEN** |
| B-83 | Dual settle at miss=cap−1 with no slash (early B-24f) | 4 | **Landed** (`8cfe137`); **CI `#29761692348` GREEN** |
| B-86 | Slash-funded treasury then dual-settle drain (early B-24g) | 4 | **Landed** (`9fede5b`/`bef823d`); **CI `#29793832972` GREEN** |
| B-95 | Slash-funded treasury then asymmetric settle (early B-24h) | 4 | **Landed** (`665c166`); **CI `#29795731587` GREEN**; not full B-24 |
| B-98 | Slash-funded treasury then op1 asymmetric settle (early B-24i) | 4 | **Landed** (this commit); twin of B-95; local release test PASS; full CI |

---

## 8. Session log (who did what — newest first, max 20 entries)

> One entry per landed unit or board correction: date, lane, unit, commits, verification verdicts. When this list exceeds 20, rotate the oldest entries verbatim into [`docs/AGENTS_LEDGER.md`](docs/AGENTS_LEDGER.md) § Rotated session-log entries.

1. **2026-07-21 — lane 7 — B-100 Path A tip-4851** (this commit): force-publish+land after health FAIL lag=18; ckpt **4833→4851** (entries=33); lag 0; `assert-public-testnet-health` + peers-clean OK. B-15-safe. Evidence `b100-path-a-tip4851-20260721.md`. **CI `#29798634416` GREEN** on B-97. Full CI (no skip). *Observed (not staged):* lane-1 B-96 soak WIP, lane-4 B-99/`apply_block_proposals.rs`, JOIN temps.
1. **2026-07-21 — lane 7 — B-97 Path A tip-4833** (this commit): published+landed exact-tip ckpt **4679→4833** (entries=32); lag 130→0; `assert-public-testnet-health` + peers-clean OK; added Windows `land-path-a-checkpoint-from-vps.ps1`. B-15-safe (no faucet/mfnd restart). Evidence `b97-path-a-tip4833-20260721.md`. Prior **CI #29797153366 GREEN** on B-98. Full CI (no skip). *Observed (not staged):* lane-1 B-96 soak WIP, JOIN temps.
1. **2026-07-21 — lane 4 — B-98 slash→op1 asymmetric settle** (this commit): early B-24i `b98_b5_slash_funded_treasury_then_op1_asymmetric_settle_*`; local release test PASS. Prior **CI `#29795731587` GREEN** on B-95. Id avoids lane-1 **B-96** + lane-7 **B-97**. Full CI (no skip). *Observed (not staged):* lane-1 soak pin-assert WIP, lane-7 Path A / ckpt WIP, JOIN temps. Still blocked on 2nd host for live **B-32**.
1. **2026-07-21 — lane 3 — B-15 wave58**: **zion** faucet-F101b permanence **last_proven=4823** (commit `54887d55`); F45 lag=130; claims 32→33. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-21 — lane 4 — B-95 slash→asymmetric settle** (this commit): early B-24h `b95_b5_slash_funded_treasury_then_asymmetric_settle_*`; local debug + `cargo fmt` PASS. Prior **CI `#29793832972` GREEN** on B-86. Full CI (no skip). *Observed (not staged):* JOIN temps. Still blocked on 2nd host for live **B-32**.
1. **2026-07-21 — lane 4 — B-95 slash→asymmetric settle** (this commit): early B-24h `b95_b5_slash_funded_treasury_then_asymmetric_settle_*`; local debug + `cargo fmt` PASS. Prior **CI `#29793832972` GREEN** on B-86. Full CI (no skip). *Observed (not staged):* JOIN temps. Still blocked on 2nd host for live **B-32**.
2. **2026-07-21 — lane 2 — B-94 spent-debris prune** (`598a853`): removed spent one-shots; tightened `.gitignore`. `[skip ci]`. *Observed (not staged):* lane-3 JOIN evidence temps.
3. **2026-07-21 — lane 3 — B-15 wave57**: **yuki** faucet-F101b permanence **last_proven=4808** (commit `99b7e801`); F101b rounds=1; F45 lag=116; claims 31→32. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-21 — lane 3 — B-15 wave56**: **xavier** faucet permanence **last_proven=4794** (commit `7121030f`); F45 lag=107; claims 30→31. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-21 — lane 3 — B-15 wave55**: **wren** faucet permanence **last_proven=4785** (commit `a88d7bcb`); F45 lag=98 (ckpt 4679 frozen); claims 29→30. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-21 — lane 3 — B-15 wave54**: **viv** faucet-retry permanence **last_proven=4763** (commit `aefcaf80`); shell monitor aborted mid-600s wait but runner completed; claims 28→29; F45 lag open=71. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
1. **2026-07-21 — lane 4 — B-86 rustfmt fix-forward** (this commit): **CI `#29791944150` RED** rustfmt only; `cargo fmt --all`; re-push full CI. *Observed (not staged):* JOIN temps.
2. **2026-07-20 — lane 4 — B-86 slash→treasury→dual-settle** (`9fede5b`): early B-24g `b86_b5_slash_funded_*`; local debug PASS; CI `#29791944150` rustfmt RED → fix-forward. Still blocked on 2nd host for live **B-32**.
2. **2026-07-20 — lane 3 — B-15 wave53**: **tess** faucet-retry permanence **last_proven=4749** (commit `e4ae6e05`); F45 lag=58; claims 27→28. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 1 — B-93 post-push CI watch** (this commit): `scripts/post-push-ci-watch.py` (+ wrappers) wraps B-34 stall detect after every push; failure hints `gh-ci-failed`; never cancels healthy `in_progress`. ci-check plan gate + `.cursor/rules/ci-before-push.mdc` + `docs/CI.md`. Local docs-only ci-check OK. Full CI (no skip). *Observed (not staged):* lane-3 JOIN temps, `user-wallet/`, `live-testnet-data*`, lane-4 proptest WIP.
1. **2026-07-20 — lane 3 — B-15 wave52**: **sara** faucet permanence **last_proven=4736** (commit `a900c1d5`); clean first-try faucet; F45 lag=50 (ckpt 4679); claims 26→27. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 3 — B-15 wave51**: **rita** permanence **last_proven=4728** (commit `e5dd4c00`); faucet-retry with **F101b** delayed owned=2; peers skipped; claims 25→26. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 1 — B-27 CI GREEN** (`08f8001`): CI `#29784891780` GREEN. Full CI board pin (no skip). *Observed (not staged):* JOIN temps, `user-wallet/`, lane-4 proptest WIP.
1. **2026-07-20 — lane 3 — B-15 wave50**: **quinn** faucet-retry permanence **last_proven=4709** (commit `ce817776`); 429→600s→PASS; claims 24→25. Proves JOIN path when donor pool owned=1. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 1 — B-27 soak refresh** (this commit): outside-in invite soak PASS tip 4663->4665; evidence `outside-in-invite-soak-20260720T211608Z.txt` + `b27-outside-in-invite-soak-refresh-20260720.md`; soak auto-pins latest green Nightly/CI via `gh`. Pins Nightly `#29779143837` GREEN (all three) + CI `#29777008854`. B-15-safe. Full CI (no skip). *Observed (not staged):* lane-3 JOIN temps, `user-wallet/`, `live-testnet-data*`, lane-4 proptest WIP.
1. **2026-07-20 — lane 3 — B-15 wave49**: **paula** faucet permanence **last_proven=4694** (commit `c054d610`); Path A ckpt=4679; claims 23→24. Donor census all owned=1 → faucet-wait policy. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 3 — B-15 wave48 FUND FAIL**: **owen** unfunded (faucet 429; nora single-send→owen owned=1; kate F106 owned=1). Reinforces wait-for-faucet over peer dual-fund from fresh permanence wallets. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 7 — B-92 Path A tip-4679** (this commit): lag=17 fire → tip-**4679** (entries=26); **CI `#29779275119` GREEN** on B-91. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proposals.rs`, JOIN temps, `user-wallet/`, `live-testnet-data*`, lane-1 soak WIP.
1. **2026-07-20 — lane 3 — B-15 wave47**: **nora** faucet permanence **last_proven=4677** (commit `53bab1a0`); cooldown wait after wave46 fund fail; claims 22→23. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 3 — B-15 wave46 FUND FAIL**: **liam** unfunded for upload (faucet 429; kate single-send→owned=1; iris F106 owned=1). Path A ckpt_max=4662 **lag=0** but hard scan still TIMEOUT. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 1 — B-34 CI GREEN** (c752992): CI #29777008854 GREEN (closes incomplete B-90 wire). Docs board sync [skip ci] while B-91 CI runs. *Observed (not staged):* JOIN temps, user-wallet/, live-testnet-data*, lane-4 proptest WIP.
1. **2026-07-20 — lane 7 — B-91 health assert + tip-4662** (`13cdb01`): `assert-public-testnet-health` + ci-check gate; tip-**4662** (lag=21, entries=25); re-proves B-90 after CI `#29776397760` cancelled by B-34. Prior **CI `#29777008854` GREEN** on B-34. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proptest.rs`, JOIN temps, `user-wallet/`, `live-testnet-data*`.
2. **2026-07-20 — lane 3 — B-15 wave45**: **kate** faucet permanence **last_proven=4661** (commit `8b491ece`) on fresh observer after wave44 wipe; claims 21→22. Wipe restores permanence (again). Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
3. **2026-07-20 — lane 3 — B-15 wave44 FAIL**: **jade** Fresh stayed `local_only` (commit `985a944f`); sticky mempool=1; no proxy_has; claims stayed 21. Breaking 7-PASS streak. Quarantine wipe before wave45 (F108). Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
4. **2026-07-20 — lane 1 — B-34 watch-ci-stall** (`c752992`): CI `#29777008854` GREEN; cancelled B-90 matrix `#29776397760`.
5. **2026-07-20 — lane 7 — B-90 proxy tip-align + tip-4641** (`89a047b`): F105 tip-align; tip-**4641**; CI cancelled by B-34 (code retained).
2. **2026-07-20 — lane 3 — B-15 wave43**: **iris** faucet permanence **last_proven=4636** (commit `39bffdd5`); Path A ckpt_max=4624 (F45 lag=5); claims 20→21; no wipe. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
3. **2026-07-20 — lane 3 — B-15 wave42**: **hank** peer-dual-donor permanence **last_proven=4628** (commit `69b678f3`); faucet 429→gina+frank; F45 lag grew to 15 as tip > ckpt 4606; claims 19→20. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
4. **2026-07-20 — lane 7 — B-89 timer assert + tip-4624** (`a0458bf`): tip-**4624**; **CI `#29773999207` GREEN**. Full CI (no skip).
2. **2026-07-20 — lane 3 — B-15 wave41**: **gina** faucet permanence **last_proven=4620** (commit `8aeb43ec`); Path A ckpt_max=4606 (F45 lag=7); F100/F105 recur; claims 18→19; no wipe. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
3. **2026-07-20 — lane 3 — B-15 wave40**: **frank** peer-dual-donor permanence **last_proven=4611** (commit `8f866ea2`); faucet 429→erin+dana; F100/F105 lag during prove; claims 17→18; no wipe. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
4. **2026-07-20 — lane 7 — B-88 lag timer + tip-4606** (`3a0efff`): timer install + tip-**4606**; **CI `#29771537059` GREEN**. Full CI (no skip).
2. **2026-07-20 — lane 3 — B-15 wave39**: **erin** faucet permanence **last_proven=4602** (commit `8af641cd`); no wipe (mempool clean); claims 16→17. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
3. **2026-07-20 — lane 3 — B-15 wave38**: **dana** peer-dual permanence **last_proven=4594** (commit `8d15b8e5`); faucet 429; mempool gate; claims 15→16; F45 lag=2. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
4. **2026-07-20 — lane 7 — B-87 Path A tip-4584** (`ed3c51e`): tip-**4584**; **CI `#29769164562` GREEN**. Full CI (no skip).
2. **2026-07-20 — lane 3 — B-15 wave37**: 3rd wipe; **cora** faucet permanence **last_proven=4585** (commit `e8da3321`); tip_id+mempool=0 gate; **F108** restart≠clear sticky mempool; claims 14→15. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
3. **2026-07-20 — lane 3 — B-15 wave36**: 2nd wipe OK; **ben** faucet+upload Fresh `d9d6f90e` but **F107** — local mempool stuck=1, proxy_has=false, local_only; claims stayed 14. Next: restart-clear mempool (wave37). Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
4. **2026-07-20 — lane 7 — B-85 near-tip lag gate + tip-4567** (`a1ac45c`): lag-republish tooling + tip-**4567**; **CI `#29766146798` GREEN**. Full CI (no skip).
2. **2026-07-20 — lane 3 — B-15 wave36 open**: 2nd F104 wipe — quarantined `live-testnet-data-divergent-20260720-124203`; fresh mfnd syncing; proxy-prove gate; ben battery next. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
3. **2026-07-20 — lane 3 — B-15 wave35b**: amy faucet+upload Fresh `807b5a5a` but **F104 recur** (local_only, proxy_has=false, mempool=1); wave34 zoe still the latest proxy-prove PASS. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
4. **2026-07-20 — lane 7 — B-84 Path A tip-4554** (`e45c9ec`): exact-tip **4554** (entries=19); **CI `#29764280042` GREEN**; OPERATORS F95/F106. Full CI (no skip).
5. **2026-07-20 — lane 3 — B-15 wave35**: amy fund **FAIL** — faucet 429 (F95); vera/tina owned=1 only (**F106**); ckpt_max advanced to 4532. Recovery wave35b. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 4 — B-83 dual-settle at cap−1 no slash** (this commit): early B-24f `b83_b5_dual_settle_at_cap_minus_one_*`; local debug test PASS. Full CI. *Observed (not staged):* lane-1 B-34 WIP, JOIN/`user-wallet`/`live-testnet-data*`.
2. **2026-07-20 — lane 3 — B-15 wave34**: wipe+resync; **zoe** faucet permanence **last_proven=4533** (commit `4ded4c6d`); proxy-prove gate PASS; F105 proxy index lag; claims 13→14; F45 TIMEOUT. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 7 — B-82 Path A tip-4532** (this commit): waited for **CI `#29758805553` GREEN** (B-81); exact-tip **4532** (entries=18); B-32 second-host arm checklist; peers-clean OK; arm-ready still NOT READY (1 host). No faucet/mfnd restart. Evidence `b82-path-a-tip4532-20260720.md`. Full CI (no skip). *Observed (not staged):* lane-1 B-34 WIP (`watch-ci-stall` in ci-check/ROADMAP), JOIN temps, `user-wallet/`, `live-testnet-data*`.
1. **2026-07-20 - lane 1 - B-27 CI watch** (`45e40d6`): CI #29758129931 cancelled by B-81; scripts ubuntu/windows were GREEN. Watching #29758805553 on f924a63. Docs [skip ci].
1. **2026-07-20 — lane 3 — B-15 wave34 open**: F104 wipe — quarantined divergent `live-testnet-data` → `…-divergent-20260720-113211`; fresh mfnd tip_id match @4525; proxy-prove gate armed; zoe battery running. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
2. **2026-07-20 — lane 3 — B-15 wave33b**: yara faucet+upload **Fresh** `0d2b070b` but prove stuck **local_only**; proxy has=false; claims stayed 13 (**F104**). F45 hard-scan TIMEOUT. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
2. **2026-07-20 - lane 1 - B-27 outside-in invite soak** (this commit): successor soak for systemd-live invite head via public proxy; tip 4501->4503; evidence outside-in-invite-soak-20260720T155203Z.txt + b27-outside-in-invite-soak-20260720.md; ci-check plan gate. Pins Nightly #29755942849 + CI #29753244727. B-15-safe. *Observed (not staged):* JOIN temps, user-wallet/, live-testnet-data*.
1. **2026-07-20 — lane 4 — B-81 full-slash deregister while peer settles** (this commit): early B-24e `b81_b5_full_slash_deregister_*` (code was missing from B-27 board claim — landed here). Local debug test PASS. Full CI. *Observed (not staged):* JOIN/`user-wallet`/`live-testnet-data*`/lane-3 temps.
2. **2026-07-20 — lane 3 — B-15 wave33**: yara permanence **FAIL** — F45 lag=1 after B-80 tip-4496; faucet 429; peer xena/uma **available 0** after pin_clean (**F103**); F97 timeouts. Recovery = wave33b. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
2. **2026-07-20 - lane 1 - B-29 CLOSED** (this commit): Nightly #29755942849 GREEN — participant + observer + ignored P2P/produce all success on d248ba2 (ancestor **B-75** 9d8bd30; **CI #29753244727 GREEN**). Docs board close [skip ci] while B-80 CI in progress.
1. **2026-07-20 — lane 3 — B-15 wave32**: New wallet **xena** faucet permanence **last_proven=4496** (commit `fe091b02`); pin@4400 owned=3 after pin@4443 owned=1 (F101); F45 lag=46; F102 concurrent-runner RPC 10060; claims 12→13. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
2. **2026-07-20 — lane 7 — B-80 Path A tip-4496** (this commit): closed F45 lag after waves 30-31 (4443→**4496** exact tip; entries=16); VPS pulled to `d248ba2`; no faucet/mfnd restart. Evidence `b80-path-a-tip4496-20260720.md`. Prior **CI `#29753244727` GREEN** on B-75. Full CI (no skip). *Observed (not staged):* JOIN temps, `user-wallet/`, `live-testnet-data*`.
1. **2026-07-20 — lane 3 — B-15 wave31**: New wallet **wendy** peer-dual permanence **last_proven=4487** (commit `a0d915d2`); faucet 429 (F95); pin@4443 owned=1 then pin@4400 owned=2 (F101); F45 lag=37; claims 11→12. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
2. **2026-07-20 — lane 3 — B-15 wave30**: New wallet **vera** faucet permanence **last_proven=4479** (commit `b90c135c`); pin@4443; F45 FAIL lag=29 post B-79 tip-4443; claims 10→11; F100 last_proven before tip_id match. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
2. **2026-07-20 - lane 1 - B-75 production_dial + persistable local P2P** (this commit): sealed-block fanout now includes non-persistable advertise via production_dial_peers; persistable local P2P binds in start-all + produce smokes. Full CI. After GREEN: sole Nightly -> close **B-29**.
1. **2026-07-20 - lane 3 - B-15 wave29** (this commit): faucet done; bal timeout @4173/@4262 (**F97**); pin@4400 funded (**F99**); upload bound **last_proven=4466** proxy+claims=10. Evidence wave29.md. *Observed (not staged):* user-wallet/, live-testnet-data*, other-lane dirty files.
1. **2026-07-20 — lane 7 — B-79 B-32 arm-ready + tip-4443** (this commit): `assert-b32-arm-ready.sh` + ci-check plan gate; VPS apply NOT READY (1 host) / synthetic 2-host READY; fixed `${2:-{}}` params bug + Path A bootstrap `RPC="${1:-}"` treating `--apply` as RPC; Path A tip-**4443** (entries=15). Evidence `b79-b32-arm-ready-20260720.md`. Full CI (no skip). *Observed (not staged):* lane-1 B-75 WIP (`p2p_fanout`/produce-smokes/`start-all`/`persistable-listen-lib`), JOIN `user-wallet/`, `live-testnet-data*`, wave temps.
1. **2026-07-20 - lane 3 - B-15 wave28** (`d93ab7b`/`3c1f24d`): **F45 HARD PASS** at tip 4443 (exact-tip Path A attestation; now committed in B-79); sam retrieve OK; tina faucet ~139s; F96 pin-retry; upload bound **last_proven=4452** proxy+claims=9. Evidence wave28.md.
1. **2026-07-20 - lane 3 - B-15 wave27** (this commit): faucet done then balance timeout **F97**; rose->sam #1 PASS / #2 **F98** input-count floor; sam fund_mode=peer; upload bound **last_proven=4430** proxy+claims=8. Evidence wave27.md. *Observed (not staged):* user-wallet/, live-testnet-data*, other-lane dirty files.
1. **2026-07-20 — lane 4 — board SYNC B-76 covered GREEN** (this commit): **CI `#29753244727` GREEN** on B-75 head covers B-76 dual-slash. Arm live **B-32**; blocked on **B-79** 2nd host. Full CI.
2. **2026-07-20 — lane 4 — B-76 dual-op empty-audit slash** (`dc50737`/`5492a07`): early B-24d `b76_b5_dual_operator_slash_*`. Prior CI cancelled by docs concurrency; validated via `#29753244727`.
2. **2026-07-20 - lane 3 - B-15 wave26** (this commit): tip-4400 ckpt verify PASS (entries=13); F45 hard FAIL tip 4404 (pin@4400 insufficient); quinn retrieve OK; rose faucet ~114s; **F96** pin@4173 zero then @4262 funded; upload bound **last_proven=4412** proxy+claims; claims recent=7; F92 headers PASS. Evidence wave26.md. *Observed (not staged):* user-wallet/, live-testnet-data*, other-lane dirty files.
1. **2026-07-20 — lane 1 — B-75 production_dial + persistable local P2P** (this commit): B-71 refused GHA `:0` advertise (≥32768) so sealed-block fanout missed voters (observer tip@1; all-produce diverge). Fix: in-memory `production_dial_peers` for seal/proposal dials; `persistable-listen-lib.sh` + `start-all.sh`/`.ps1` + produce-smoke persistable binds; unit test PASS. Full CI (no skip). After GREEN: sole Nightly → close **B-29**. *Observed (not staged):* lane-3/4 temps, `user-wallet/`, `live-testnet-data*`, `_nightly-*`.
2. **2026-07-20 — lane 7 — B-78 docs-equivalent CI roll gate** (`faa8683`): `lib-ci-roll-gate.sh`; observed lane-1 B-75 WIP (now landed).
3. **2026-07-20 - lane 3 - B-15 wave25** (`03ec40c` / `214454b` board): quinn last_proven=4390; F95. Evidence wave25.md.
4. **2026-07-20 — lane 7 — B-77 B-71 mfnd roll + tip-4400 ckpt** (`b1ce264`): tip-**4400**; Evidence `b77-b71-roll-tip4400-20260720.md`.
5. **2026-07-20 — lane 1 — Nightly `#29738744950` RED (participant GREEN)**: observer tip-stall → **B-75**. Docs-only `[skip ci]`.
6. **2026-07-20 — lane 4 — B-74 B-32 ci-check plan gate** (`62a9c02`): **CI `#29739903305` GREEN**.
2. **2026-07-20 — lane 4 — CI `#29736528564` GREEN + B-32 claim** (`7beb4d4`): stack B-67/B-71/B-73 green; arm **B-32** after B-15 + lane-7 mfnd re-roll. §6 request to lane 7. Docs-only `[skip ci]`.
2. **2026-07-20 - lane 3 - B-15 wave24** (this commit): soak tip **4364** match; F45 hard FAIL (pin@4323 still needs tip attestation); **F92** headers {from_height,to_height} PASS; oscar retrieve OK; patricia faucet ~99s; pin-retry 4323/4262/4173 -> funded; upload bound **last_proven=4362** proxy+claims; claims recent=5; **F93** early challenge unknown commitment; oscar->patricia 50k Fresh; F90 post-upload change. Evidence wave24.md + wave25-open (F94 headers/tip-ahead). *Observed (not staged):* user-wallet/, live-testnet-data*, probe temps.
1. **2026-07-20 - lane 3 - B-15 wave23** (`e3cb07c`): ckpt max **4323** (entries=12); F45 hard FAIL lag~2; nina retrieve OK; nina->oscar peer#1 PASS / peer#2 **F91** RBF; oscar faucet+upload **last_proven=4337**; claims recent=4; **F92** get_block_headers {from_height,to_height}. Evidence wave23.md. *Observed (not staged):* user-wallet/, live-testnet-data*, probe temps.
1. **2026-07-20 — lane 7 — B-73 B-71 reconnect smoke fix** (this commit): `mfnd_p2p_reconnects_saved_peers_on_restart` used OS ephemeral `:0` ports (>=32768) which B-71 correctly refuses to persist -> missing `peers.json` on ubuntu CI `#29734331038`. `reserve_loopback_addr` now picks 19000..32767; export `MIN_EPHEMERAL_PEER_PORT`. Local release smoke PASS. Next: mfnd roll after CI GREEN (prebuild already has B-71 binary). *Observed (not staged):* lane-3 wave23 evidence temps, `user-wallet/`, `live-testnet-data*`, `_ci-ubuntu-fail.log`.
1. **2026-07-20 — lane 1 — Nightly `#29738744950` for B-29** (this commit): B-72 on tip; CI `#29736528564` GREEN. Sole Nightly — do not re-dispatch. Docs-only `[skip ci]`.
2. **2026-07-20 — lane 1 — B-72 support-bundle B-45 wallet** (`f81d654`): Nightly `#29727713979` fund-wallet+permanence PASS; failed challenge without `--wallet`.
2. **2026-07-20 - lane 7 - rustfmt + tip-4323** (`3073177`): fmt-fix B-67; Path A tip-**4323**. *Observed:* left support-bundle WIP unstaged.
1. **2026-07-20 — lane 4 — board SYNC** (this commit): **B-67** on `f6273cb` (subject mislabeled); **B-71/B-70** on `09ca8c4` (lane-3 wave22 commit carried the peers filter + tip-4307). Watching **CI `#29733127733`**. Docs-only `[skip ci]`.
2. **2026-07-20 — lane 4 — B-67** (`f6273cb` body): multi-op slash while peer settles. Prior CI cancelled by docs concurrency.
3. **2026-07-20 - lane 7 - B-68 + B-69**: Hetzner mfnd roll after CI `#29725270815` GREEN; tip stall from ephemeral `peers.json` → scrub + restart (tip 4295+); `scrub-vps-peers-json.sh` wired into `vps-roll-mfnd`. CI `#29728151679` RED (windows produce-smoke synced public tip) → `MFN_SKIP_MANIFEST_SEEDS=1` in produce smokes. Evidence `b68-peers-scrub-mfnd-roll-20260720.md`. *Observed:* leave `apply_block_proptest.rs`, `support-bundle.*`, JOIN temps, `user-wallet/`, `live-testnet-data*` unstaged.
1. **2026-07-20 — lane 3 — B-15 wave20+21** (this commit): wave20 F87/F88/F79/F85; wave21 wipe+resync tip_id match; mike faucet /faucet + upload bound; **last_proven=4304**; proxy listed; claims for PASS. Findings F88b tip_id lag, F89 faucet path. JOIN SUMMARY draft. Evidence wave20.md + wave21.md + B15-JOIN-SUMMARY-DRAFT-20260720.md. *Observed (not staged):* apply_block_proptest.rs, probe temps, user-wallet/, live-testnet-data*.

1. **2026-07-20 - lane 7 - B-68 peers scrub + mfnd roll**: CI `#29725270815` GREEN; `vps-roll-mfnd --skip-build` then tip stall (ephemeral `peers.json`); scrub + restart voters/hub; tip 4295+; tooling `scrub-vps-peers-json.sh`. Evidence `b68-peers-scrub-mfnd-roll-20260720.md`. *Observed:* leave `apply_block_proptest.rs`, JOIN `user-wallet/`, `live-testnet-data*`, lane-3 temps unstaged.
2. **2026-07-20 — lane 4 — B-67 claim** (this commit): multi-op B5 slash while peer settles (early B-24c); local test PASS; land after **CI `#29728151679`**. Docs-only `[skip ci]`.
3. **2026-07-20 — lane 4 — B-66 which-op prove chain** (`cb8f8f3`): `b66_b5_op1_only_*` + window-spaced mask chain vs settle/miss/coinbase. **CI `#29728151679` in_progress**. Not full B-24. *Observed:* leave JOIN/`user-wallet`/`live-testnet-data*` unstaged.
4. **2026-07-20 — lane 1 — CI `#29725270815` GREEN + Nightly `#29727713979`**: B-29 matrix green; Nightly for B-29 close. Docs-only `[skip ci]`.
5. **2026-07-20 - lane 3 - B-15 wave19** (`c36561d`): karl last_proven=4270. `[skip ci]`.
6. **2026-07-20 — lane 4 — B-66 claim** (`aca2c14`): docs-only while CI ran. `[skip ci]`.
7. **2026-07-20 - lane 7 - B-65 cargo env for VPS non-interactive builds** (`938661a`): `lib-cargo-env.sh` for prebuild/roll. `[skip ci]`.
8. **2026-07-20 - lane 7 - B-22 tip-4262 Path A checkpoint** (this commit): closed 89-block ckpt lag (4173→4262); entries=11; faucet/mfnd untouched. Hold rebuild-roll for CI `#29725270815`. `[skip ci]`. *Observed:* `apply_block_proptest.rs` WIP, lane-3 evidence temps, `user-wallet/`, `live-testnet-data*`.
9. **2026-07-20 — lane 4 — board SYNC B-64+B-29 stack** (this commit): B-64 `13a4880` on main; CI `#29725200427` cancelled by B-29 concurrency. Watching `#29725270815` (clippy GREEN). `[skip ci]`.
10. **2026-07-20 - lane 3 - B-15 wave18** (42528d9): judy upload last_proven=4229; F84. Evidence wave18.md. `[skip ci]`.
11. **2026-07-20 — lane 1 — B-29 seed-isolation** (`23204cb`): `MFN_SKIP_MANIFEST_SEEDS` + local `start-all`. Completes dangling `mfnd_cli` call from B-64.
12. **2026-07-20 — lane 4 — B-64 settle/apply seal filter** (`13a4880`): seal settlement-accepted proofs; `b64_*` parity. **CI `#29720670813` GREEN** (B-63).
13. **2026-07-20 — lane 3 — B-15 wave18/17**: tip 4219; ivan JOIN. `[skip ci]`.
14. **2026-07-20 — lane 4 — B-64 claim** (`d3f47bf`): docs-only while `#29720670813` ran. `[skip ci]`.
15. **2026-07-20 — lane 4 — B-63 early B-24a** (`e4369a9`): coinbase N+1 + 1-of-2 miss. **CI `#29720670813` GREEN**.
16. **2026-07-20 — lane 1 — CI `#29718880625` GREEN + Nightly `#29720083660`**: B-60 matrix green on `7ab86ad`; dispatched Nightly for **B-29** close. Docs-only `[skip ci]`.
17. **2026-07-20 — lane 3 — B-15 wave16** (`026eaad`): F81/F82; eve last_proven=**4206**. Evidence wave16.md. `[skip ci]`.
18. **2026-07-20 — lane 3 — B-15 wave15** (`fe96f41`): heidi JOIN; last_proven=**4200**. Evidence wave15.md. `[skip ci]`.

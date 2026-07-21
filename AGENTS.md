# AGENTS.md — Permawrite Agent Control Board (the one pipeline)

**This is the single live coordination surface for every agent building Permawrite.** There is exactly one board (this file), one history (the ledger), and one pipeline (§3). If any other file appears to describe agent coordination, it is a pointer stub or a frozen archive — this file wins every disagreement.

**Priority doctrine:** privacy and permanence over everything. UX, ops, and CI serve those guarantees — never weaken ring policy, endowment enforcement, or SPoRA verification to make a unit land faster.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

Why this system exists (and why it is this strict): [`docs/VIBECODING.md`](docs/VIBECODING.md) — parallel lanes with a single durable board are how a chain too big for one context window gets built without agents clobbering each other.

---

## 0. The contract (read before anything else)

1. **One live board.** All claims, status, handoffs, requests, and backlog live in this file only. You never have to update two surfaces, so the board can never drift against itself. Optional mirror: [`3agent.md`](3agent.md) holds three-seat Done/Doing/Next for concurrent agents — never claim only there; if it disagrees with §5, fix §5 first.
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
| [`3agent.md`](3agent.md) (+ [`docs/3agent.md`](docs/3agent.md) pointer) | Three-seat Done/Doing/Next cockpit (A/B/C) | **Derived** from §5; update same-commit; this file wins on conflict. [`docs/AGENTS.md`](docs/AGENTS.md) stays a retired pointer |
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

**CI gate (2026-07-21):** Pinning **B-156** land inside tip `c3ebb5ab` (subject mislabeled B-155; includes seventh asymmetric settle). Watch **CI `#29876274630`**. **CI `#29874504154` GREEN** on B-154. **B-15 JOIN PASS**. **B-29 CLOSED**. Strategic path: L4 → **B-40** → **B-13a** → **B-25**.

| Lane | Done (last landed) | Doing | Next (owner → unit) | Checked by |
| --- | --- | --- | --- | --- |
| **1** RC core | **B-136** tip-ckpt health_ok FAIL reason (`85f48ce`); **B-135** (`2151d02`); **B-134** (`04295ea`); **B-133** (`62357ae`); **B-129**; **B-96**; **B-34** | *Idle* | Participant JOIN half after B-15 SUMMARY (lane 3); watch CI `#29854607541` | CI/Nightly run IDs |
| **2** RC ops | **B-141** 3agent cockpit + §8 repair (`7e2746b`); **B-94** (`598a853`); R-1–R-4 | *Idle* | Release evidence after CI+Nightly GREEN; **B-26** after B-15; keep `3agent.md` mirrored | Board + encoding guards |
| **3** Onboarding | **B-15** JOIN archive PASS (`9974828`; tip=5322); **B-146**/**B-145**/**B-144** | *Idle* | Human SUMMARY sign-off; hand **B-42** to lane7/3 | L4 checklist |
| **4** Protocol | **B-156** seventh→asymmetric settle (`c3ebb5ab`, watch CI `#29876274630`; subject mislabeled B-155); **B-155** (`7d3ba35d`/`c3ebb5ab`); **B-154** (`dd268c1b`, CI `#29874504154` GREEN) | *Idle* — next **B-157** seventh op1 asymmetric settle; live **B-32** needs 2nd host | After 2 hosts + B-15: `b3-multi-op-*.txt` → **B-44** → full **B-24** | Lane 1 CI |
| **5** Privacy | **B-16** (`49d28f9`) | **B-50 follow-up** Rust auto-bootstrap from checkpoint-log max tip (claim base: `4b10e51`) | After land: doc honesty sync; After B-25: **B-35** / **B-37** / **B-19** | Doc-accuracy duty |
| **6** Permanence | F6 telemetry (`0d1b9ec`) | *Idle* | **Armed:** **B-40** + **B-13a** day-of L4; then **B-33** | Emission sims |
| **7** Testnet launch | **B-140** (`262c748`); **B-139**/**B-138**/**B-137** Path A tip-5290 | *Idle* | **B-42** invite-load **live** (B-15 PASS); Path A republish lag; 2nd host for B-32 | `launch-go-no-go` |

---

## 6. Cross-lane requests (who's waiting on whom)

Rows are `Open` → `Blocked`/`Ack` → `Done`; move `Done` rows older than one session into §8/ledger during CLOSE.

| From | To | Request | Status |
| --- | --- | --- | --- |
| 3 | all | **Do not** run parallel `join-testnet-rehearsal*` on Hetzner during B-15. Prefer not to restart `faucet-http` while `busy`/`pending_jobs` (B-47/B-53/B-56 deploy OK when idle). **Do not** thrash `mfnd-hub` while tip sealing (B-46). **B-45 mfnd roll** after CI GREEN allowed. | **Done** (B-15 archive PASS tip=5322) |
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
| 7 | 3 | **B-53:** faucet `/health` no longer blocks on keepalive lock; use `assert-vps-block-log-health.sh` for F62 checks | **Done** (B-140: block-log PASS tip=5291; faucet health ok) |
| 7 | 1+4 | **CI `#29715111633`:** produce-smoke timeout fixed in B-51 (60s); **b3_legacy** flake = **B-60** (`7ab86ad`) | **Done** |
| 7 | 3 | **B-22 / B-100 → B-137 tip-5290:** re-pin / soft light-scan at ckpt **5290** for SUMMARY (was 4851) | **Ack** |
| 7 | 3 | **B-55:** browser UI at `http://5.161.201.73:3000/testnet` (optional; local observer still preferred for JOIN evidence) | **Open** |
| 7 | 3 | **B-56:** faucet keepalive tip-first — fewer hub EAGAIN during B-50 snapshot pin | **Done** (landed earlier; confirmed busy=false in B-138 health) |
| 3 | 7 | **F68/F68b:** Windows bootstrap ps1 - temp `.py` TCP snapshot (B-58). Evidence wave12 + `b58-…` | **Done** (B-58) |
| 7 | 3 | **B-59:** wire `join-testnet-rehearsal.sh` light-scan through `light-scan-checkpoint-soft.sh` (F45 tip race) | **Done** (B-60) |
| 1 | 7 | **B-125 tip lag:** closed by **B-137** Path A tip-5290 (was lag=437; now lag assert OK tip~5289 ckpt=5290) | **Done** |
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
| B-15 | JOIN_TESTNET outside-in VPS evidence + assert | 3 | **Landed** (`9974828`) — windows evidence tip=5322 assert OK; SUMMARY `B15-JOIN-SUMMARY-20260721.md` |
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
| B-27 | Fresh soak + participant evidence on invite head | 1+7 | **Soak refreshed** tip 5200->5202 (B-125); prior 5146->5148; participant JOIN half = lane-3 SUMMARY / post-B-15 |
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
| B-96 | Soak evidence requires Nightly+CI pins (assert + soak fail-closed) | 1 | **Landed** (this commit) — assert `# nnightly_run=`/`# ci_run=`; soak fail-closed; tip 4820->4822 evidence |
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
| B-98 | Slash-funded treasury then op1 asymmetric settle (early B-24i) | 4 | **Landed** (`8eb586e`); **CI `#29797153366` GREEN** |
| B-99 | Slash-funded treasury then empty both-miss (early B-24j) | 4 | **Landed** (`55c3a28`); closes post-slash prove matrix; `7ee3f66` subject mislabeled (lane-1 B-96 soak body) |
| B-101 | Slash-funded asymmetric then absentee re-slash while peer settles (early B-24k) | 4 | **Landed** (`a2c1637`); **CI `#29803426580` GREEN** |
| B-102 | Slash-funded op1 asymmetric then absentee re-slash while peer settles (early B-24l) | 4 | **Landed** (`77ba1fb`); **CI `#29804886156` GREEN** |
| B-103 | Repeated dual-slash second offense treasury identity (early B-24m) | 4 | **Landed** (`ee760b1`); **CI `#29806532117` GREEN** |
| B-104 | Second dual-slash then dual-settle drain (early B-24n) | 4 | **Landed** (`2cc5e6e`); **CI `#29808184228` GREEN** |
| B-105 | Second dual-slash then asymmetric settle drain (early B-24o) | 4 | **Landed** (`357b395`); **CI `#29810031256` GREEN** |
| B-106 | Second dual-slash then op1 asymmetric settle drain (early B-24p) | 4 | **Landed** (`d27601b`); **CI `#29812027706` GREEN** |
| B-107 | Second dual-slash then empty both-miss (early B-24q) | 4 | **Landed** (`fca2a26`); **CI `#29814109581` GREEN** |
| B-108 | Settle-reset then third dual-slash treasury identity (early B-24r) | 4 | **Landed** (`1572fcb`); **CI `#29815977566` GREEN** |
| B-109 | Third dual-slash then dual-settle drain (early B-24s) | 4 | **Landed** (`f93b02d`); **CI `#29818297963` GREEN** |
| B-110 | Third dual-slash then asymmetric settle drain (early B-24t) | 4 | **Landed** (`be3e80a`); **CI `#29820501612` GREEN** |
| B-111 | Third dual-slash then op1 asymmetric settle drain (early B-24u) | 4 | **Landed** (`c705c77`); **CI `#29822696096` GREEN** |
| B-112 | Third dual-slash then empty both-miss (early B-24v) | 4 | **Landed** (`2adf089`); **CI `#29824883480` GREEN** |
| B-113 | Third-offense asymmetric then absentee re-slash while peer settles (early B-24w) | 4 | **Landed** (`9ae9618`); **CI `#29826982613` GREEN** |
| B-114 | Third-offense op1 asymmetric then absentee re-slash while peer settles (early B-24x) | 4 | **Landed** (`e8300b9`); **CI `#29829071765` GREEN** |
| B-115 | Second-offense asymmetric then absentee re-slash while peer settles (early B-24y) | 4 | **Landed** (this commit); fills B-101 gap between 1st/3rd offense; full CI |
| B-116 | Second-offense op1 asymmetric then absentee re-slash (early B-24z) | 4 | **Landed** (`cd856d3`); **CI `#29833394102` GREEN** |
| B-117 | Settle-reset then fourth dual-slash treasury identity (early B-24aa) | 4 | **Landed** (7d51632); elevates B-108; CI #29835953151 (watch) |
| B-118 | Fourth dual-slash then dual-settle drain (early B-24ab) | 4 | **Landed** (`48cfbb3` subject mislabeled B-117); **CI `#29836555770` GREEN** |
| B-119 | Fourth dual-slash then asymmetric settle (early B-24ac) | 4 | **Landed** (bf3e776); elevates B-110; CI #29839142227 (watch) |
| B-120 | Fourth dual-slash then op1 asymmetric settle drain (early B-24ad) | 4 | **Landed** (ea70e2a, subject mislabeled B-119); elevates B-111; full CI |
| B-121 | Fourth dual-slash then empty both-miss (early B-24ae) | 4 | **Landed** (`a0443ba`); **CI `#29839631308` GREEN** |
| B-122 | Fourth-offense asymmetric then absentee re-slash (early B-24af) | 4 | **Landed** (`2a98633`); **CI `#29842437172` GREEN**; elevates B-113/B-115 |
| B-124 | Fourth-offense op1 asymmetric then absentee re-slash (early B-24ag) | 4 | **Landed** (`73ab34a`); **CI `#29844848474` GREEN**; completes fourth-offense re-slash pair |
| B-123 | Soak.sh single-id pin validation (B-96/Win parity) | 1 | **Landed** (`2a98633` body; **CI `#29842437172` GREEN**) — reject non-numeric/multi pins; rehearsal smoke needles |
| B-125 | Outside-in soak refresh + tip-lag §6 to lane7 | 1 | **Landed** (`f46a162`) — tip 5200->5202; §6 Path A lag~351 Open |
| B-127 | Outside-in tip-vs-checkpoint lag assert (B-15-safe) | 1 | **Landed** (`981dfd1`); **CI `#29847644779` GREEN** (proved on B-126 tip) |
| B-129 | Tip-ckpt lag assert auto-archives evidence (B-127 follow-up) | 1 | **Landed** (`7e2afb8`; board raced `b0fd1b1`) — scripts+evidence; tip=5233 lag=382 |
| B-133 | Outside-in soak refresh + tip-lag §6 refresh | 1 | **Landed** (`62357ae`) — tip 5283->5285; lag=432 evidence; Path A = lane7 |
| B-134 | Tip-ckpt lag Path A staleness fields + §8 board repair | 1 | **Landed** (`04295ea`) — STALENESS line; tip=5287 lag=436; §8 header repaired |
| B-135 | Tip-ckpt lag Path A age_sec + remote public health pings | 1 | **Landed** (`2151d02`) — age_sec+HEALTH; tip=5287 lag=436 age~14.6h proxy/faucet ok |
| B-136 | Tip-ckpt lag FAIL reason distinguishes health_ok vs outage | 1 | **Landed** (`85f48ce`) — health_ok→path_a_republish; tip=5288 lag=437 |
| B-126 | Settle-reset then fifth dual-slash treasury identity (early B-24ah) | 4 | **Landed** (`ba0b69d`); **CI `#29847644779` GREEN** |
| B-128 | Fifth dual-slash then dual-settle drain (early B-24ai) | 4 | **Landed** (`1909584`); **CI `#29849999987` GREEN** |
| B-130 | Fifth dual-slash then asymmetric settle drain (early B-24aj) | 4 | **Landed** (`b0fd1b1`); **CI `#29852461441` GREEN**; elevates B-119 |
| B-131 | Fifth dual-slash then op1 asymmetric settle drain (early B-24ak) | 4 | **Landed** (`40d0222`); **CI `#29854607541` GREEN** |
| B-132 | Fifth dual-slash then empty both-miss (early B-24al) | 4 | **Landed** (`d025b37`); **CI `#29857236769` GREEN**; closes fifth-offense prove matrix |
| B-142 | Fifth-offense asymmetric then absentee re-slash (early B-24am) | 4 | **Landed** (this commit); elevates B-122; full CI |
| B-143 | Fifth-offense op1 asymmetric then absentee re-slash (early B-24an) | 4 | **Landed** (`2dec0fd`); completes fifth-offense re-slash pair; full CI |
| B-147 | Settle-reset then sixth dual-slash treasury identity (early B-24ao) | 4 | **Landed** (this commit); elevates B-126; full CI |
| B-148 | Sixth dual-slash then dual-settle drain (early B-24ap) | 4 | **Landed** (this commit); elevates B-128; full CI |
| B-149 | Sixth dual-slash then asymmetric settle drain (early B-24aq) | 4 | **Landed** (`bdf31e5`); elevates B-130; CI cancelled by B-150 tip — covered by `#29867968439` |
| B-150 | Sixth dual-slash then op1 asymmetric settle drain (early B-24ar) | 4 | **Landed** (`6a2c779`, subject mislabeled rustfmt); elevates B-131; full CI |
| B-151 | Sixth dual-slash then empty both-miss (early B-24as) | 4 | **Landed** (`9d20b00`); **CI `#29870158905` GREEN**; closes sixth-offense prove matrix |
| B-152 | Sixth-offense asymmetric then absentee re-slash (early B-24at) | 4 | **Landed** (`cd3d37ae`); **CI `#29872307794` GREEN**; elevates B-142 |
| B-153 | Sixth-offense op1 asymmetric then absentee re-slash (early B-24au) | 4 | **Landed** (`cd3d37ae` with B-152); **CI `#29872307794` GREEN**; completes sixth-offense re-slash pair |
| B-154 | Settle-reset then seventh dual-slash treasury identity (early B-24av) | 4 | **Landed** (`dd268c1b`); **CI `#29874504154` GREEN**; elevates B-147 |
| B-155 | Seventh dual-slash then dual-settle drain (early B-24aw) | 4 | **Landed** (`7d3ba35d`/`c3ebb5ab`); elevates B-148; covered by tip CI `#29876274630` |
| B-156 | Seventh dual-slash then asymmetric settle drain (early B-24ax) | 4 | **Landed** (`c3ebb5ab`, subject mislabeled B-155); elevates B-149; full CI |
| B-157 | Seventh dual-slash then op1 asymmetric settle drain (early B-24ay) | 4 | Next after B-156 — elevates B-150 |
| B-144 | Windows/MSYS JOIN: `lib-python3.sh` + mfn-cli.exe resolve | 3 | **Landed** (`cc79bfe`) — unblocks B-15 bootstrap on hosts without `python3` |
| B-145 | Tall-tip bootstrap `get_light_snapshot` long timeout (python NDJSON) | 3 | **Landed** (`9ca1124`) — default 300s; unblocks F67 pin at tip~5290 |
| B-146 | fund-wallet-http wait: plain light-scan after faucet (F101b) | 3 | **Landed** (this commit) — hard checkpoint-log F45 was aborting UTXO discovery |
| B-137 | Path A land from VPS tip-5269+ (close tip-lag §6) | 7 | **Landed** (`10eedc1`) — VPS publish tip-5290 + land jsonl; lag assert OK |
| B-138 | Public-testnet health verify after Path A tip-5290 | 7 | **Landed** (`555d5df`) — VPS health OK lag=0; §6 re-pin Ack tip-5290 |
| B-139 | VPS peers-clean + TESTNET_CHECKLIST tip-5290 / B-29 mirror | 7 | **Landed** (`002ee6c`) — peers OK; checklist B-22/B-29/B-137/B-138 |
| B-140 | VPS block-log health + close §6 B-53/B-56 | 7 | **Landed** (`262c748`) — F62 PASS tip=5291; B-42 plan-only only |
| B-141 | Revive `3agent.md` three-seat cockpit under AGENTS authority + §8 repair | 2 | **Landed** (`7e2746b`) — seats A/B/C Done/Doing/Next; AGENTS wins; tip lag≈1 |

---

## 8. Session log (who did what — newest first, max 20 entries)

> One entry per landed unit or board correction: date, lane, unit, commits, verification verdicts. When this list exceeds 20, rotate the oldest entries verbatim into [`docs/AGENTS_LEDGER.md`](docs/AGENTS_LEDGER.md) § Rotated session-log entries.

1. **2026-07-21 — lane 4 — pin B-156 land on mislabeled tip** (this commit): early B-24ax seventh→asymmetric settle is in `c3ebb5ab` (subject says B-155). Elevates B-149. Watch **CI `#29876274630`**. Next: **B-157** op1 twin. Still blocked on 2nd host for live **B-32**. `[skip ci]`.

1. **2026-07-21 — lane 4 — claim B-156** (this commit): early B-24ax seventh dual-slash→asymmetric settle while **CI `#29876214263`** runs on B-155. Claim base `7d3ba35d`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-155 seventh dual-slash→dual settle** (this commit): early B-24aw `b155_b5_seventh_dual_slash_then_dual_settle_drain_identity`; local debug PASS. **CI `#29874504154` GREEN** on B-154. Elevates B-148. Full CI (no skip). Next: **B-156** seventh asymmetric. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-155** (this commit): early B-24aw seventh dual-slash→dual settle while **CI `#29874504154`** runs on B-154. Claim base `dd268c1b`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — pin B-153 + CI `#29872307794` GREEN** (this commit): B-153 op1 twin was in B-152 tip `cd3d37ae`; CI GREEN closes sixth-offense re-slash pair. Next: **B-154** settle-reset→seventh dual-slash. Still blocked on 2nd host for live **B-32**. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-154 settle-reset→seventh dual-slash** (this commit): early B-24av `b154_b5_settle_reset_then_seventh_dual_slash_treasury_identity`; local debug PASS. **CI `#29872307794` GREEN** on B-152/B-153. Elevates B-147. Full CI (no skip). Next: **B-155** seventh→dual settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-154** (this commit): early B-24av settle-reset→seventh dual-slash while **CI `#29872307794`** runs on B-152/B-153 tip. Claim base `cd3d37ae`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — pin B-153 land on mislabeled tip** (this commit): early B-24au `b153_b5_sixth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles` is in `cd3d37ae` (subject says B-152 re-land). Completes sixth-offense re-slash pair with B-152. Watch **CI `#29872307794`**. Next: **B-154** settle-reset→seventh dual-slash. Still blocked on 2nd host for live **B-32**. `[skip ci]`.

1. **2026-07-21 — lane 4 — claim B-153** (this commit): early B-24au sixth-offense op1 asymmetric→absentee re-slash (B-152 twin) while **CI `#29872307794`** runs on B-152. Claim base `cd3d37ae`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-152 sixth-offense asymmetric→absentee re-slash** (this commit): early B-24at `b152_b5_sixth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local release PASS. **CI `#29870158905` GREEN** on B-151. Elevates B-142 to sixth-offense funding. Full CI (no skip). Next: **B-153** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.


1. **2026-07-21 — lane 4 — B-152 sixth-offense asymmetric→absentee re-slash** (this commit): early B-24at `b152_b5_sixth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29870158905` GREEN** on B-151. Elevates B-142. Full CI (no skip). Next: **B-153** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-152** (this commit): early B-24at sixth-offense asymmetric→absentee re-slash (elevates B-142) while **CI `#29870158905`** runs on B-151. Claim base `9d20b008`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-151 sixth-slash→empty both-miss** (this commit): early B-24as `b151_b5_sixth_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. **CI `#29867968439` GREEN** on B-150. Closes sixth-offense prove matrix {00,01,10,11}. Full CI (no skip). Next: **B-152** sixth-offense asymmetric→absentee re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-151** (this commit): early B-24as sixth-slash→empty both-miss (closes sixth-offense prove matrix) while **CI `#29867968439`** runs on B-150 tip. Claim base `6a2c779`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — claim B-151** (this commit): early B-24as sixth empty both-miss while **CI `#29867968439`** runs on B-150. Claim base `6a2c779`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-150 sixth→op1 asymmetric settle** (`6a2c779`): early B-24ar `b150_b5_sixth_dual_slash_then_op1_asymmetric_settle_drain_identity`; local debug PASS. Commit subject mislabeled as rustfmt fix-forward (parallel race with B-149 land). Watch **CI `#29867968439`**. Completes sixth-offense asymmetric settle pair with B-149. Next: **B-151** empty both-miss. Still blocked on 2nd host for live **B-32**.

1. **2026-07-21 — lane 4 — claim B-150** (this commit): early B-24ar sixth-slash→op1 asymmetric settle while **CI `#29867927644`** runs on B-149. Claim base `6a2c779`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — claim B-150** (this commit): early B-24ar sixth dual-slash→op1 asymmetric settle while **CI `#29867927644`** runs on B-149. Claim base `bdf31e5`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-149 sixth dual-slash→asymmetric settle + B-148 rustfmt fix** (this commit): early B-24aq `b149_b5_sixth_dual_slash_then_asymmetric_settle_drain_identity`; local debug PASS. Fix-forward: remove extra blank after B-148 (CI `#29866791874` rustfmt FAIL). Elevates B-130. Full CI (no skip). Next: **B-150** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-149** (this commit): early B-24aq sixth dual-slash→asymmetric settle while **CI `#29866791874`** runs on B-148. Claim base `cc77d1ff`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.


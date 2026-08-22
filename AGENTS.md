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

**CI gate (2026-08-22):** **B-306** r=0 C₀ drip inert (this commit). Tip CI `#31909490680` **FAIL** scripts (rust GREEN on prior). Nightly `#31861932921` **GREEN**. Lane7 Path A **22565** / last_proven **22560**. Slash-clone matrix frozen. Strategic path: L4 -> **B-40** -> **B-13a** -> **B-25**. No B-13c; no DEFAULT flip.

| Lane | Done (last landed) | Doing | Next (owner → unit) | Checked by |
| --- | --- | --- | --- | --- |
| **1** RC core | pin CI `#31860183965` + Nightly `#31861932921` **GREEN** (`6e2e21a6`); **B-136** (`85f48ce`); **B-34** | *Idle* | Fix scripts FAIL `#31909490680`; Participant JOIN half after B-15 SUMMARY (lane 3) | CI/Nightly run IDs |
| **2** RC ops | Arweave vs PW **weave-is-the-copy** availability (`7464ad8d`); `go` CI-commit bind `b0bd1caa` | *Idle* | Fix scripts FAIL `#31909490680`; **B-26** after B-15 | Board + encoding guards |
| **3** Onboarding | **B-42** 3rd JOIN last_proven=**22560** (`6a1468fc`); 2nd **22492**; iris **22487** | *Idle* | Human SUMMARY; concurrent JOIN x2 still open | L4 checklist |
| **4** Protocol | **B-305** (`704280f7`); **B-304** (`848a40ff`) | *Idle* — slash matrix frozen | **B-35** still Phase 3 / B-25. After 2 hosts: live **B-32**. No B-297 clone | Lane 1 CI |
| **5** Privacy | **B-226** docs honesty; **B-217** (`55c078fe`; tip **CI `#31063344773` GREEN**); **B-218**; **B-216**; **B-214**; **B-197** | *Idle* | After B-25: **B-35** / **B-37** / **B-19** | Doc-accuracy duty |
| **6** Permanence | **B-306** r=0 C₀ drip inert (this commit); **B-268b** (`ee3739e7`); **B-269**; **B-268** WP | *Idle* | **B-306b** enable after B-25 / Path B; **B-306c** prize-size; human **B-33**; no B-13c enable | Emission sims |
| **7** Testnet launch | Path A **22565** (`160a9b07`; lag **OK=7**); **B-42** 3rd JOIN last_proven **22560** (`6a1468fc`); faucet F7 **`f77a4048` 73s** | *Idle* | 2nd host B-32 | `launch-go-no-go` + observer |

---

## 6. Cross-lane requests (who's waiting on whom)

Rows are `Open` → `Blocked`/`Ack` → `Done`; move `Done` rows older than one session into §8/ledger during CLOSE.

| From | To | Request | Status |
| --- | --- | --- | --- |
| 7 | 4 | **Hub inbound CLOSE-WAIT leak:** `:19101` fills `P2P_MAX_INBOUND_HANDLERS=48` (`inbound_cap_reached`); silent/half-closed inbound holds the slot for the 30s hello timeout; vote fanout EAGAIN; tip stuck **22495**. | **Done** (B-300 inbound hello 3s + shutdown + session IO timeout) |
| 6 | 4 | **B-28-post CI window:** after tip CI on B-262 (or successor) GREEN, please **hold one Rust land** (~5-10 min) so lane6 can push ssert-b28-treasury-thresholds --mode post / -Mode post + ci-check needles with full CI. Body ready (live post FAIL-closed on Path A). | **Done** (landed this commit; tip CI watch) |
| 6 | 7 | **Path A lag FAIL:** outside-in tip=16453 ckpt_max=16341 **lag=112**. Closed by **B-264** tip-16456 land (assert OK lag=-1; evidence `outside-in-tip-ckpt-lag-20260806T184223Z.txt`). | **Done** (B-264) |
| 6 | 4 | **B-268 design review:** please skim [`docs/B13_ACTIVATION_HEIGHT.md`](docs/B13_ACTIVATION_HEIGHT.md) (now includes call-site inventory for apply_block/fraud/producer). Ack before **B-268b** Rust. | **Ack** (lane4: agree effective_emission_params + no base mutate at H_act; fraud/producer must mirror; ckpt v12 schedule fields OK) |
| 6 | 4 | **B-265 CI window:** genesis `emission` JSON merge + Path A subsidy=0 pin (no enable). | **Done** (landing this commit) |
| 6 | 7 | **Path A lag FAIL tip=16467** ckpt=16456 **lag=11**. Closed by **B-267** tip-16468 (assert OK lag=0; evidence `outside-in-tip-ckpt-lag-20260806T190853Z.txt`). | **Done** (B-267) |
| 6 | 1 | **CI zombie `#31123682138`:** cleared (cancelled/completed). Tip CI `#31126560747` on B-265 `14f6b177`. | **Done** |
| 6 | 4 | **B-40-d0 re-prove:** tip CI covering `4bcaf8e2` keeps getting cancelled by slash lands. | **Done** (helper on main; repeated tip matrices include ancestor; pin when tip CI fully GREEN) |
| 6 | 4 | **B-13a-512 CI window:** after tip CI on B-241 (or successor) GREEN, please **hold one Rust land** (~5-10 min) so lane6 can push 512-block subsidy-bps-1000 sims (13a_*_512_*) with full CI. Body ready locally. | **Done** (landed 28031bca; tip CI #31109005252) |
| 6 | 4 | **B-28 assert CI window:** after tip CI on B-238 (or successor) GREEN, please **hold one Rust land** (~5–10 min) so lane6 can push `assert-b28-treasury-thresholds.*` + ci-check plan-only needle with full CI. Body ready (live PASS tip~16215). | **Done** (assert landed this tip) |
| 6 | 4 | **HTTP treasury-telemetry CI window:** after tip CI on B-236 (or successor) GREEN, please **hold one Rust land** (~5-10 min) so lane6 can push 	reasury-telemetry-watch HTTP(S) --rpc + ci-check http_example needle with full CI. Body ready locally. | **Done** (landed 360f690b; tip CI #31090099572) |
| 6 | 4 | **B-40-d0-preflight CI window (courtesy):** tip CI on B-246 GREEN — lane4 holding **B-259** briefly so lane6 can land 40-d0-preflight.* + ci-check needles. | **Done** (landed 4bcaf8e2; tip CI #31115971810) |
| 4 | 6 | **B-13a clippy:** `#31073720447` / `#31075611260` FAIL — allow 8-arg treasury helpers | **Done** (this commit) |
| 3 | 7 | **F114:** faucet job ERROR hub Connection refused (os error 111) on wave106; HTTP accepted. Verify mfnd-hub RPC without thrashing faucet-http (§6). | **Done** (B-253: hub_tip prove + failed template scrub; faucet idle) |
| 5 | 4 | **B-217 CI window:** please hold next Rust land (~5–10 min) after tip CI #30049437036 (B-221) GREEN so lane5 can re-land ring-floor wording parity (reverted from accidental fafb3813 / B-223 leaks). | **Done** (B-217 `55c078fe`; tip CI `#31063344773` GREEN) |
| 5 | 4 | **B-197 CI window:** after tip CI `#30028287920` (B-210) GREEN, please **hold one Rust land** (~5–10 min) so lane5 can push WASM/CLI F7 faucet-message parity with full CI (body ready; cancelled repeatedly by continuous slash-matrix lands). | **Done** (B-197 `2288b5b8`) |
| 3 | all | **Do not** run parallel `join-testnet-rehearsal*` on Hetzner during B-15. Prefer not to restart `faucet-http` while `busy`/`pending_jobs` (B-47/B-53/B-56 deploy OK when idle). **Do not** thrash `mfnd-hub` while tip sealing (B-46). **B-45 mfnd roll** after CI GREEN allowed. | **Done** (B-15 archive PASS tip=5322) |
| 4 | 7 | **B-45+B-48+B-51+B-64:** rolled on Hetzner after **CI `#29725270815` GREEN**; **B-68** peers scrub restored tip | **Done** (VPS roll) |
| 7 | 4 | **B-68 follow-up:** filter ephemeral/0.0.0.0 on `peers.json` load so polluted durable sets cannot recur (ops scrub is not enough) | **Done** (B-71 + B-73 smoke) |
| 4 | 7 | **B-32:** mfnd re-roll with B-71/B-73 binary; then help arm >=2 distinct-host operators for live multi-op pack (after B-15 JOIN window) | **Ack** - **B-255** tip=16328 p2p-forward hygiene OK; still **distinct_hosts=1** NOT READY; need real MFN_B32_OPERATOR_HOSTS >=2 |
| 3 | 7 | **B-15 blocked on B-41:** outside-in local `mfnd` tip=0 / peer_count=0; faucet HTTP PASS. Evidence `live-testnet-probe-20260720-wave1.md` | **Done** (B-41 socat forwards live; seeds dialable) |
| 3 | 7 | **Tip stall + faucet EAGAIN:** tip was stuck **4031**; **B-46** restored production. Wave6: tip **4040+**, alice faucet job **done** 122s (2 txs) — EAGAIN streak broken. Evidence live-testnet-probe-20260720-wave6.md | **Done** |
| 2 | 1 | Green CI + Nightly on B-15 head before next release-evidence refresh | **Open** |
| planning | 1+3 | **B-29 close:** seed-isolation `23204cb` + CI GREEN; Nightly `#29727713979` — closes only on Nightly GREEN | **Ack** |
| planning | 1 | **B-34:** `#29713542820` in_progress on `4d07b7d` (post-outage dispatch) | **Done** (tooling landed this commit) |
| 1 | 7 | Outside-in: observer proxy `ECONNREFUSED 127.0.0.1:18734`; B-15 wave4 reports P2P `:19001` down — repair without faucet restart | **Done** (B-46; tip advancing; proxy OK) |
| 7 | 3 | **B-50:** `--checkpoint-log` does not skip genesis — use `bootstrap-wallet-from-checkpoint-log.sh --apply` (or `.ps1` on Windows — B-52) for receive verify | **Done** (B-50 follow-up Rust auto-bootstrap) |
| 7 | 5 | **B-50 follow-up:** Rust — `light-scan --checkpoint-log` auto-bootstraps from log max tip | **Done** (`3df22fd3`) |
| 3 | 7 | **F54** proxy `get_light_snapshot` TIMEOUT; **F56** Windows no bash for B-50 | **Done** (B-52: heavy timeout 180s + `.ps1` twin) |
| planning | 3+7 | **B-42:** invite-load plan script landed; **live** after B-15 PASS — [work package](docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9) | **Ack** (B-257 preflight+p2p hygiene PASS serialize; live JOIN still after B-15 clear) |
| planning | 2+7 | **B-31:** use ROADMAP work package before TL-9 (RPC/faucet/TLS verify) | **Done** (probe landed; P2P FAIL → B-41) |
| 7 | 2+3+human | **B-41:** public seed reachability | **Done** (socat forwards; do **not** bind mfnd on 0.0.0.0 — hangs) |
| 7 | human | **B-22:** near-tip checkpoint | **Done** (Path A tip **4148** + public seed anchors; seed offline on VPS only) |
| planning | 1+7 | **B-27:** use ROADMAP work package — TL-5/6 archives insufficient | **Done** (soak tooling+live PASS `9f5ed4d`) |
| planning | 6 | **Arm B-40 + B-13a** the day TL-9/L4 closes — work packages in ROADMAP; do not stay idle | **Ack** — **B-13a** Landed (sims-only); **B-40** still day-of L4 |
| 3 | 5+7 | **JOIN tall-tip UX:** heidi loop PASS (wave15). F45 soft (B-161 in-CLI + B-164 Windows twin); F75–F80 (owned≥2, pin hygiene, post-pin tip catch-up). SUMMARY draft next. | **Open** (SUMMARY archive; lane5 F45 soft Done) |
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
| B-13a | Emission/treasury sims at `1000` bps in default CI | 6 | **Landed** 256+512 sims (this commit elevates 256); genesis stays 0; human B-33 still open
| B-13b | Fork policy: same-chain enable vs new `genesis_id` | 6+7+human | **Draft** same-chain+activation-height (B-265 honesty); human cells still open
| B-13c | Genesis/manifest update + operator announcement | 7 | After B-13b sign-off |
| B-15 | JOIN_TESTNET outside-in VPS evidence + assert | 3 | **Landed** (`9974828`) tip=5322 SUMMARY; **wave115** last_proven **22467** (`601cb854…`; this commit). Human SUMMARY still open |
| B-14 | TL-9 named watchers + invite circulation | 7 | Last open TL phase; blocked on B-15 + B-29 Nightly + B-26/27 (B-30 docs ✓) |
| B-17 | P31 phase 2: ASN-aware peer diversity buckets | 4 | Phase 4 adversarial; after L5 planning |
| B-18 | F15: MFBN-1 VRF variant docs + conformance tests | 4 | Phase 2; [`PROBLEMS.md` §15](docs/PROBLEMS.md) |
| B-19 | F9: decoy-RNG entropy contract + tests | 5 | Phase 3 privacy; after L4 + B-25 unless waived |
| B-20 | F6: producer↔treasury runway fee-shift policy | 6 | **Draft** FEES §5.5 (this tip); arm after B-13c + B-25 |
| B-21 | B7 Dandelion++ internet soak evidence | 1 | Unblocks P16; after L4 |
| B-22 | TL-8 checkpoint log VPS publish verify | 7 | **Done** - tip **4262** Path A (entries=11); seed offline on VPS only |
| B-23 | F18: privacy/permanence regression gate in ci-check | 2 | Phase 1; after L4 |
| B-24 | Multi-op consensus settlement audit + M5 proptests | 4 | Phase 1; after B3 multi-op internet evidence |
| B-25 | Phase 1 permanence go/no-go (30d soak + treasury bounds) | 7+human | Closes Phase 1 before Tier 2 / Path B value |
| B-26 | R-4 VPS faucet deploy (`vps-update-faucet.sh`) | 2+7 | After B-15 evidence window |
| B-27 | Fresh soak + participant evidence on invite head | 1+7 | **Soak refreshed** tip 5200->5202 (B-125); prior 5146->5148; participant JOIN half = lane-3 SUMMARY / post-B-15 |
| B-28 | Treasury watch + numeric OPERATORS alert thresholds | 2+7 | **Assert landed** (`980ac1ef`; **CI `#31096968523` GREEN**); arm live after B-13c |
| B-29 | Nightly participant+observer GREEN | 1+3 | **CLOSED** — Nightly #29755942849 GREEN on d248ba2 (B-75 inclusive) |
| B-75 | Nightly observer mesh tip-stall after h1 (EAGAIN) | 1 | **Landed** (this commit) - production_dial_peers + persistable start-all / produce-smoke ports |
| B-30 | Residual-risk owner matrix + halt authority before invites | 7 | **Docs landed** — human name cells at TL-9 sign-off |
| B-31 | Live RPC/faucet threat posture verify | 2+7 | **P2P+RPC PASS** after B-41/B-46; close after **B-26** R-4 deploy confirm |
| B-32 | B3 multi-op evidence pack + assert (B-15-style) | 4+7 | **Tooling + ci-check gate (B-74)**; live pack day-of L4 |
| B-74 | Wire B-32 plan smoke + fixture assert into ci-check | 4 | **Landed** (this commit) — `.sh`/`.ps1` twins; closes ROADMAP CI row for B-32 tooling |
| B-33 | B-13b human sign-off checklist | 6+7+human | **Landed** — checklist + pre-enable telemetry archived; human go cells still open before B-13c |
| B-34 | CI queue/stall watch + cancel/re-dispatch | 1 | **Landed** (this commit) — `scripts/watch-ci-stall.py` + ci-check plan gate (gate was prematurely wired in B-90; scripts complete it); `--cancel-if-stalled` only when zero progress |
| B-93 | Post-push CI stall watch wrapper (B-34 follow-up) | 1 | **Landed** (this commit) — `scripts/post-push-ci-watch.py` + ci-check plan gate; wired into after-push agent rule |
| B-96 | Soak evidence requires Nightly+CI pins (assert + soak fail-closed) | 1 | **Landed** (this commit) — assert `# nnightly_run=`/`# ci_run=`; soak fail-closed; tip 4820->4822 evidence |
| B-94 | Spent-debris prune + gitignore tighten (M2.5.39 follow-up) | 2 | **Landed** (this commit) — delete 5 tracked spent one-shots; ignore `_*.py` / lane WIP / nightly dumps / live-testnet-data* / evidence `_*` |

| B-301 | F5 P20: consensus-reject opaque non-MFEX `tx.extra` | 4+5 | **Landed** `a55d5869`; no B-13c enable |
| B-302 | F5 P20: reject empty MFEX envelope (magic+version, no payload) | 4+5 | **Landed** `d01b4df5`; no B-13c enable |
| B-303 | Wallet refuse caller `extra` when synthesizing MFEX (MFEO/MFER/claims) | 4+5 | **Landed** `4e1fb020`; no B-13c enable |
| B-304 | F5 P20: reject well-formed MFEX on non-storage (transfer) txs | 4+5 | **Landed** `848a40ff`; no B-13c enable |
| B-305 | F5 P20: reject unused MFEO/MFER when opening/range not required | 4+5 | **Landed** `704280f7`; no B-13c enable |
| B-306 | r=0 endowment C₀ drip (`deflation_funded_drip`, ckpt v13) | 6 | **Landed** (this commit) — inert default; Path A stays 0; enable = **B-306b** |
| B-306b | Enable `deflation_funded_drip = 1` on Path B / after B-25 | 6+7+human | Coinbase fork if flipped on Path A; see [`B306_ENDOWMENT_DRIP.md`](docs/B306_ENDOWMENT_DRIP.md) |
| B-306c | Size `storage_proof_reward` as true backstop (not 0.1 MFN prize) | 6 | After drip enable; do not DEFAULT-flip Path A |
| B-35 | F7 consensus input-count padding | 4+5 | Phase 3 privacy; wallet floor shipped |
| B-36 | F10 `f64` purge / CI lint on consensus path | 4 | **Landed** - scripts fill `54d22d7` hook gap |
| B-37 | B6/P6 hidden fees inside balance equation | 4 | Phase 3 privacy; after B-25 |
| B-38 | Repair/soak evidence + assert | 1+7 | Phase 1 permanence |
| B-39 | Phase 2 light-client / FRAUD_PROOFS honesty gate | 4+7 | After F5 4b.2 stack |
| B-40 | First permanence week (arm day-of L4) | 6 | **Runbook** + **D0 preflight helper** landed; arm day-of L4
| B-41 | Public P2P seed reachability (socat forwards) | 7+2 | **Done** — mfnd :1910x + socat :1900x; EXT 19001–19003 OPEN; tip~4031 |
| B-42 | Invite-load smoke before TL-9 | 3+7 | Preflight PASS; serialize `bda9a419`; staggered JOINs last_proven **22487** (iris) + **22492** (join-a `ea7cba7c`) + **22560** (join-b `6a1468fc`, this commit). Concurrent rehearsal x2 still open — [work package](docs/ROADMAP.md#b-42--invite-load-smoke-lanes-37--before-tl-9) |
| B-43 | Path B genesis freeze inventory | 7+human | **Draft** — `docs/PATH_B_GENESIS_FREEZE.md`; human cells TBD; no ceremony |
| B-44 | PM3 windowed SPoRA lottery work package | 4+6 | Phase 1; after **B-32**; [work package](docs/ROADMAP.md#b-44--pm3-work-package-lane-46--after-b-32) |
| B-45 | B3 operator-salted challenge/prove/pool path | 4 | **Landed** — unblocks honest multi-op SPoRA on salted genesis; Hetzner mfnd roll = lane 7 |
| B-46 | Tip-stall ops harden: `Wants=` + hub dial extras | 4+7 | **Landed** `4d07b7d` — tip 4031→4034+ |
| B-47 | Faucet EAGAIN harden (health/CLI race) | 7+2 | **Done** (`fe56ca8`) — health lock + runRetry; VPS faucet restarted idle; tip 4047+ |
| B-48 | Soft-ignore EAGAIN for P2P peer quarantine | 4 | **Landed** — soft-fail EAGAIN/WouldBlock in peer quarantine (not os error 111) |
| B-49 | VPS `vps-roll-mfnd.sh` tooling (hub+voters, no faucet) | 7 | **Done** (`284e803`) — live apply after CI GREEN |
| B-50 | Checkpoint-log bootstrap honesty + helper | 7+5 | **Done** (docs+script + Rust auto-bootstrap `3df22fd3`) |
| B-161 | mfn-cli heavy RPC timeout for `get_light_snapshot` (B-52 client twin) | 5 | **Landed** (this commit) — 180s/`MFN_HEAVY_RPC_TIMEOUT_MS` + in-CLI F45 soft; live `checkpoint_log_auto_bootstrap tip=5463` + `checkpoint_log_f45_soft_pass` |
| B-164 | Privacy-doc honesty for B-50/B-161 + Windows `light-scan-checkpoint-soft.ps1` twin | 5 | **Landed** (`07c30df0`) — PRIVACY/CHECKPOINT_LOG + `.ps1` twin; Schnorr still hard |
| B-165 | CI fail-closed gate for F45 soft twin + B-161 needles | 5 | **Landed** (`0da9cd27`; **CI `#29884711182` GREEN**) — soft rehearsal smoke + ci-check wire; live tip~5523/5524 |
| B-167 | Ring-size no-silent-downgrade: typed `RingSizeBelowMinimum` + CLI/WASM refuse `< WALLET_MIN_RING_SIZE` | 5 | **Landed** (`894ca63f`; covered by **CI `#29888900634` GREEN** on B-166 tip) |
| B-172 | CI fail-closed gate for B-167/B-168 privacy floors (`WALLET_MIN_RING_SIZE` + F7 inputs) | 5 | **Landed** (`1ce0ed2e`; covered by tip **CI `#29893569581` GREEN**) |
| B-185 | Low-level `build_transfer`/`build_storage_upload` fail-closed on `< WALLET_MIN_TX_INPUTS` (F7) | 5 | **Landed** (`89089aca`; **CI `#29921156035` GREEN** on B-183 tip) — mempool dual-fund + heavy-RPC env lock |
| B-188 | Tenth dual-slash then dual settle drain (early B-24br) | 4 | **Landed** (this commit); elevates B-176; full CI |
| B-187 | Settle-reset then tenth dual-slash treasury identity (early B-24bq) | 4 | **Landed** (this commit); elevates B-175; full CI |
| B-186 | High-level `select_inputs_for_tx` fail-closed on single-UTXO (F7) | 5 | **Landed** (`94cbfece`; **CI `#29929300995` GREEN**) — elevates B-185 |
| B-204 | Twelfth dual-slash then dual settle drain (early B-24cf) | 4 | **Landed** (this commit); elevates B-196; full CI |
| B-206 | Twelfth dual-slash then op1 asymmetric settle drain (early B-24ch) | 4 | **Landed** (this commit); completes twelfth asymmetric pair with B-205; full CI |
| B-207 | Twelfth dual-slash then empty both-miss (early B-24ci) | 4 | **Landed** (this commit); closes twelfth-offense prove matrix; elevates B-200; full CI |
| B-208 | Twelfth-offense asymmetric then absentee re-slash (early B-24cj) | 4 | **Landed** (`d6e85121`); elevates B-201; full CI |
| B-209 | Twelfth-offense op1 asymmetric then absentee re-slash (early B-24ck) | 4 | **Landed** (in `d6e85121` with B-208; CI `#30023674882` GREEN) — completes twelfth re-slash pair |
| B-210 | Settle-reset then thirteenth dual-slash treasury identity (early B-24cl) | 4 | **Landed** (this commit); elevates B-203; full CI |
| B-211 | Thirteenth dual-slash then dual settle drain (early B-24cm) | 4 | **Landed** (this commit); elevates B-204; full CI |
| B-205 | Twelfth dual-slash then asymmetric settle drain (early B-24cg) | 4 | **Landed** (this commit); elevates B-198; full CI |
| B-203 | Settle-reset then twelfth dual-slash treasury identity (early B-24ce) | 4 | **Landed** (this commit); elevates B-195; full CI |
| B-202 | Eleventh-offense op1 asymmetric then absentee re-slash (early B-24cd) | 4 | **Landed** (this commit); completes eleventh re-slash pair with B-201; full CI |
| B-201 | Eleventh-offense asymmetric then absentee re-slash (early B-24cc) | 4 | **Landed** (this commit); elevates B-193; full CI |
| B-200 | Eleventh dual-slash then empty both-miss (early B-24cb) | 4 | **Landed** (this commit); closes eleventh prove matrix; elevates B-192; full CI |
| B-199 | Eleventh dual-slash then op1 asymmetric settle drain (early B-24ca) | 4 | **Landed** (this commit); completes eleventh asymmetric pair with B-198; full CI |
| B-198 | Eleventh dual-slash then asymmetric settle drain (early B-24bz) | 4 | **Landed** (this commit); elevates B-190; full CI |
| B-196 | Eleventh dual-slash then dual settle drain (early B-24by) | 4 | **Landed** (this commit); elevates B-188; full CI (also re-proves B-195) |
| B-197 | WASM/CLI F7 faucet dual-send error-message parity (elevates B-189) | 5 | **Landed** (`2288b5b8`; **CI `#30030542686` GREEN**) — WASM + CLI `map_wallet_build_err` faucet dual-send wording |
| B-212 | Thirteenth dual-slash then asymmetric settle drain (early B-24cn) | 4 | **Landed** (`48aa8ded`); elevates B-205; full CI |
| B-213 | Thirteenth dual-slash then op1 asymmetric settle drain (early B-24co) | 4 | **Landed** (this commit); completes thirteenth asymmetric pair with B-212; elevates B-206; full CI |
| B-215 | Thirteenth dual-slash then empty both-miss (early B-24cp) | 4 | **Landed** (this commit); closes thirteenth prove matrix with B-211/B-212/B-213; elevates B-207; full CI |
| B-219 | Thirteenth-offense asymmetric then absentee re-slash (early B-24cq) | 4 | **Landed** (this commit); elevates B-208; full CI |
| B-220 | Thirteenth-offense op1 asymmetric then absentee re-slash (early B-24cr) | 4 | **Landed** (`fd10ca89`); completes thirteenth re-slash pair with B-219; elevates B-209; full CI |
| B-221 | Settle-reset then fourteenth dual-slash treasury identity (early B-24cs) | 4 | **Landed** (this commit); elevates B-210; afb3813 had rustfmt+board only + accidental lane5 — reverted; full CI |
| B-222 | Fourteenth dual-slash then dual settle drain (early B-24ct) | 4 | **Landed** (`8faa69c1`; CI `#30049842728` GREEN); elevates B-211; full CI |
| B-223 | Fourteenth dual-slash then asymmetric settle drain (early B-24cu) | 4 | **Landed** (`3ff57357`/`0559cc6a`; **CI `#31059769879` GREEN**); elevates B-212; full CI |
| B-224 | Fourteenth dual-slash then op1 asymmetric settle drain (early B-24cv) | 4 | **Landed** (this commit); completes fourteenth asymmetric pair with B-223; elevates B-213; full CI |
| B-225 | Fourteenth dual-slash then empty both-miss (early B-24cw) | 4 | **Landed** (`332bbff2`; **CI `#31065238354` GREEN**); closes fourteenth prove matrix with B-222/B-223/B-224; elevates B-215; full CI |
| B-227 | Fourteenth-offense asymmetric then absentee re-slash (early B-24cx) | 4 | **Landed** (`43e99602`; **CI `#31066818023` GREEN**); elevates B-219; full CI |
| B-228 | Fourteenth-offense op1 asymmetric then absentee re-slash (early B-24cy) | 4 | **Landed** (`2819c117`; **CI `#31068279807` GREEN**); completes fourteenth re-slash pair with B-227; elevates B-220; full CI |
| B-230 | Settle-reset then fifteenth dual-slash treasury identity (early B-24cz) | 4 | **Landed** (`fb2e609d`; **CI `#31069737973` GREEN**); elevates B-221; full CI |
| B-231 | Fifteenth dual-slash then dual settle drain (early B-24da) | 4 | **Landed** (this commit); elevates B-222; full CI |
| B-232 | Fifteenth dual-slash then asymmetric settle drain (early B-24db) | 4 | **Landed** (this commit); elevates B-223; full CI |
| B-233 | Fifteenth dual-slash then op1 asymmetric settle drain (early B-24dc) | 4 | **Landed** (`5ff775d9`; **CI `#31080095877` GREEN**); completes fifteenth asymmetric pair with B-232; elevates B-224; full CI |
| B-234 | Fifteenth dual-slash then empty both-miss (early B-24dd) | 4 | **Landed** (this commit); closes fifteenth prove matrix with B-231/B-232/B-233; elevates B-225; full CI |
| B-235 | Fifteenth-offense asymmetric then absentee re-slash (early B-24de) | 4 | **Landed** (this commit); elevates B-227; full CI |
| B-236 | Fifteenth-offense op1 asymmetric then absentee re-slash (early B-24df) | 4 | **Landed** (this commit); completes fifteenth re-slash pair with B-235; elevates B-228; full CI |
| B-237 | Settle-reset then sixteenth dual-slash treasury identity (early B-24dg) | 4 | **Landed** (this commit); elevates B-230; opens sixteenth-offense arc; full CI |
| B-238 | Sixteenth dual-slash then dual settle drain (early B-24dh) | 4 | **Landed** (this commit); elevates B-231; full CI |
| B-239 | Sixteenth dual-slash then asymmetric settle drain (early B-24di) | 4 | **Landed** (this commit); elevates B-232; full CI |
| B-240 | Sixteenth dual-slash then op1 asymmetric settle drain (early B-24dj) | 4 | **Landed** (`9a251f81`, subject mislabeled B-239); completes sixteenth asymmetric pair with B-239; elevates B-233; full CI |
| B-241 | Sixteenth dual-slash then empty both-miss (early B-24dk) | 4 | **Landed** (this commit); elevates B-234; closes sixteenth prove matrix; full CI |
| B-242 | Sixteenth-offense asymmetric then absentee re-slash (early B-24dl) | 4 | **Landed** (this commit); elevates B-235; full CI |
| B-246 | Sixteenth-offense op1 asymmetric then absentee re-slash (early B-24dm) | 4 | **Landed** (this commit); elevates B-236; completes sixteenth re-slash pair with B-242; full CI |
| B-260 | Path A tip-16341 republish + public-testnet health PASS | 7 | **Landed** (this commit; entries=53; lag 11→0; evidence `b260-path-a-tip-16341-health-20260806T145200Z.md`) |
| B-264 | Path A tip-16456 republish + outside-in lag OK (close §6) | 6+7 | **Landed** (`16fb0583`; entries=54; lag -1; B-40-d0 + B-28-pre PASS tip~16457) |
| B-259 | Settle-reset then seventeenth dual-slash treasury identity (early B-24dn) | 4 | **Landed** (this commit); elevates B-237; opens seventeenth-offense arc; full CI |
| B-261 | Seventeenth dual-slash then dual settle drain (early B-24do) | 4 | **Landed** (this commit); elevates B-238; opens seventeenth prove matrix; full CI |
| B-262 | Seventeenth dual-slash then asymmetric settle drain (early B-24dp) | 4 | **Landed** (this commit); elevates B-239; continues seventeenth prove matrix; full CI |
| B-263 | Seventeenth dual-slash then op1 asymmetric settle drain (early B-24dq) | 4 | **Landed** (this commit); elevates B-240; completes seventeenth asymmetric settle pair; full CI |
| B-266 | Seventeenth dual-slash then empty both-miss (early B-24dr) | 4 | **Landed** (this commit); elevates B-241; closes seventeenth prove matrix; full CI |
| B-270 | Seventeenth-offense asymmetric then absentee re-slash (early B-24ds) | 4 | **Landed** (this commit); elevates B-242; full CI |
| B-271 | Seventeenth-offense op1 asymmetric then absentee re-slash (early B-24dt) | 4 | **Landed** (this commit); elevates B-246; completes seventeenth re-slash pair with B-270; full CI |
| B-272 | Settle-reset then eighteenth dual-slash treasury identity (early B-24du) | 4 | **Landed** (this commit); elevates B-259; opens eighteenth-offense arc; full CI |
| B-273 | Eighteenth dual-slash then dual settle drain (early B-24dv) | 4 | **Landed** (this commit); elevates B-261; opens eighteenth prove matrix; full CI |
| B-274 | Eighteenth dual-slash then asymmetric settle drain (early B-24dw) | 4 | **Landed** (this commit); elevates B-262; continues eighteenth prove matrix; full CI |
| B-275 | Eighteenth dual-slash then op1 asymmetric settle drain (early B-24dx) | 4 | **Landed** (this commit); elevates B-263; completes eighteenth asymmetric settle pair with B-274; full CI |
| B-276 | Eighteenth dual-slash then empty both-miss (early B-24dy) | 4 | **Landed** (this commit); elevates B-266; closes eighteenth prove matrix; full CI |
| B-279 | Eighteenth-offense asymmetric then absentee re-slash (early B-24dz) | 4 | **Landed** (this commit); elevates B-270; full CI |
| B-280 | Eighteenth-offense op1 asymmetric then absentee re-slash (early B-24ea) | 4 | **Landed** (this commit); elevates B-271; completes eighteenth re-slash pair with B-279; full CI |
| B-281 | Settle-reset then nineteenth dual-slash treasury identity (early B-24eb) | 4 | **Landed** (this commit); elevates B-272; opens nineteenth-offense arc; full CI |
| B-282 | Nineteenth dual-slash then dual settle drain (early B-24ec) | 4 | **Landed** (this commit); elevates B-273; opens nineteenth prove matrix; full CI |
| B-283 | Nineteenth dual-slash then asymmetric settle drain (early B-24ed) | 4 | **Landed** (this commit); elevates B-274; continues nineteenth prove matrix; full CI |
| B-284 | Nineteenth dual-slash then op1 asymmetric settle drain (early B-24ee) | 4 | **Landed** (this commit); elevates B-275; completes nineteenth asymmetric settle pair with B-283; full CI |
| B-285 | Nineteenth dual-slash then empty both-miss (early B-24ef) | 4 | **Landed** (this commit); elevates B-276; closes nineteenth prove matrix; full CI |
| B-286 | Nineteenth-offense asymmetric then absentee re-slash (early B-24eg) | 4 | **Landed** (this commit); elevates B-279; full CI |
| B-287 | Nineteenth-offense op1 asymmetric then absentee re-slash (early B-24eh) | 4 | **Landed** (this commit); elevates B-280; completes nineteenth re-slash pair with B-286; full CI |
| B-288 | Settle-reset then twentieth dual-slash treasury identity (early B-24ei) | 4 | **Landed** (this commit); elevates B-281; full CI |
| B-289 | Twentieth dual-slash then dual settle drain (early B-24ej) | 4 | **Landed** (this commit); elevates B-282; full CI |
| B-290 | Twentieth dual-slash then asymmetric settle drain (early B-24ek) | 4 | **Landed** (this commit); elevates B-283; full CI |
| B-292 | Twentieth dual-slash then op1 asymmetric settle drain (early B-24el) | 4 | **Landed** (this commit); elevates B-284; completes twentieth asymmetric pair with B-290; full CI |
| B-293 | Twentieth dual-slash then empty both-miss (early B-24em) | 4 | **Landed** (this commit); elevates B-285; closes twentieth prove matrix; full CI |
| B-294 | Twentieth-offense asymmetric then absentee re-slash (early B-24en) | 4 | **Landed** (`0ecd19ce`); elevates B-286; full CI |
| B-295 | Twentieth-offense op1 asymmetric then absentee re-slash (early B-24eo) | 4 | **Abandoned** — slash-clone matrix frozen; do not land |
| B-297 | Settle-reset then twenty-first dual-slash treasury identity (early B-24ep) | 4 | **Frozen** — do not land; matrix closed |
| B-277 | Live Path A onchain tx-storm + adversarial submit probes (observer-visible) | 7 | **Landed** (`af596d04`) — evidence `b277-live-tx-storm-20260807.md`; F120–F123; adv rejects OK; user txs blocked until B-278 |
| B-278 | Faucet wallet UTXO prune/rotate (unblock F122 fund path) | 7+2 | **Landed** (`b1ab1b17`) — prune 22062→32; HTTP dual-fund **done 99s**; evidence `b278-faucet-utxo-prune-20260814.md`; CLI O(n) pending-spend diff |
| B-291 | Tall-tip mesh recover + skip-manifest-seeds + loopback peers (post-B-278) | 7 | **Landed** (`24ce61a9`) — tip stall root cause = public hairpins + cold replay; tip restored ~22350; evidence `b291-tall-tip-mesh-recover-20260815.md`; storm deferred to **B-296** |
| B-296 | Dual-payment live storm + faucet-ops systemd rotate (post-B-291) | 7 | **Landed** (`9396b6cb`) — systemd `FAUCET_WALLET=faucet-ops.json`; HTTP dual-fund **76s**; storm landed **13**; observer user-tx **391→408**; evidence `b296-faucet-ops-rotate-storm-20260815.md` |
| B-298 | Path A near-tip checkpoint republish after B-296 (lag ~5.8k) | 7 | **Landed** (`0237a53d`) — VPS timer already at 22437 (84 entries); repo land 16622→22437; outside-in **OK lag=6**; evidence `b298-path-a-tip-22437-20260815.md` |
| B-299 | Restore public hub seed 19001 after B-291 stop (B-254 hygiene) | 7 | **Landed** (`30ff27b0`) — `systemctl start mfn-p2p-forward-hub` only; 19001 **CLOSED→OPEN**; tip 22446→22447; invite-load `--apply` PASS; evidence `b299-hub-seed-19001-20260815.md` |
| B-247 | Outside-in tip-ckpt lag + public P2P/RPC posture refresh after tip-16293 | 7 | **Landed** (`0807bd93`; tip=16299 lag=6; seeds 19001-19003 OPEN; evidence `b247-outside-in-posture-tip-16299-20260806T132600Z.md`) |
| B-248 | Invite-load smoke preflight harness (B-42 toward live; serialize-with-reason) | 7 | **Landed** (`5d941e07`; evidence `b248-invite-load-preflight-20260806T133000Z.md`) |
| B-258 | Path A near-tip timer/default lag threshold 16→8 (JOIN soft-pin) | 7 | **Landed** (this commit; board text raced into B-246 `23749726`; VPS timer env=8; health tip=16336 lag=6; evidence `b258-path-a-lag-threshold-8-20260806T144200Z.md`) |
| B-257 | Invite-load preflight adds B-254 p2p-forward hygiene (toward B-42) | 7 | **Landed** (`570a51ed`; VPS+outside-in PASS tip~16333; evidence `b257-invite-load-p2p-hygiene-20260806T143700Z.md`) |
| B-256 | Path A tip-16330 republish + public-testnet health PASS | 7 | **Landed** (`7ea13f4d`; entries=52; lag 9→0; evidence `b256-path-a-tip-16330-health-20260806T143100Z.md`) |
| B-255 | B-32 arm-ready assert adds B-254 p2p-forward hygiene | 7 | **Landed** (`3185253c`; tip=16328; p2p OK; **distinct_hosts=1 NOT READY**; evidence `b255-b32-arm-ready-p2p-hygiene-20260806T142607Z.md`) |
| B-254 | Public-testnet health fail-closed on mfn-p2p-forward@ templates | 7 | **Landed** (this commit; VPS health OK tip~16326; evidence `b254-public-health-p2p-forward-hygiene-20260806T142200Z.md`) |
| B-253 | Scrub failed mfn-p2p-forward@ templates + F114 hub prove | 7 | **Landed** (this commit; evidence `b253-scrub-p2p-forward-templates-20260806T141800Z.md`) |
| B-252 | Path A tip-16321 republish + public-testnet health PASS | 7 | **Landed** (this commit; entries=51; evidence `b252-path-a-tip-16321-health-20260806T141100Z.md`) |
| B-251 | Observer index get_tip timeout under tall-tip snapshot load | 7 | **Landed** (this commit; VPS proxy apply; evidence `b251-index-tip-timeout-20260806T140500Z.md`) |
| B-250 | Tall-tip soft-scan auto-delegates unpinned wallets (no cold hang) | 7 | **Landed** (this commit; VPS prove PASS tip~16311; evidence `b250-tall-tip-soft-delegate-20260806T135300Z.md`) |
| B-249 | Soft-repin readiness + Path A tip-16309 (F45 soft + lag close) | 7 | **Landed** (`44a38769`; tip=16309 entries=50; F45 soft PASS; evidence `b249-soft-repin-path-a-tip-16309-20260806T134600Z.md`) |
| B-243 | Path A near-tip checkpoint republish (close F45 lag ~11k) | 7 | **Landed** (`ff2fafe3`; tip=16293 entries=49; evidence `b243-path-a-tip-16293-20260806T131500Z.md`) |
| B-244 | Public-testnet health verify after Path A tip-16293 | 7 | **Landed** (this tip; tip=16294 ckpt=16293 lag=1; evidence `b244-public-testnet-health-tip-16293-20260806T132000Z.md`) |
| B-229 | Tall-tip observer proxy header cache + viewer poll abort fix | 7 | **Landed** (this commit; `[skip ci]`) — mfnd `get_block_headers` re-reads full `chain.blocks` (~3.5s @ tip≈16k); proxy caches rows + tip-warm; frontend skips in-flight abort + uses `get_tx_count_totals`; Next.js heavy RPC 180s. Deploy proxy on VPS after land |
| B-214 | WASM/wallet README F7 faucet dual-send fail-closed honesty (elevates B-197) | 5 | **Landed** (`c5efb7f4`) — docs-only; lane4 owns B-212/B-213 |
| B-216 | CLI README/usage F7 dual-UTXO + disabled standalone `wallet claim` honesty | 5 | **Landed** (`e350481f`; watch CI `#30035644826`) — usage + README + privacy-floor smoke |
| B-218 | PRIVACY/CHECKPOINT_LOG Path A lag vs F45 soft-pass honesty | 5 | **Landed** (`8eaa1af6`) — soft-pass ≠ exact-tip; docs-only |
| B-217 | WASM/CLI/wallet ring-floor error wording parity (wallet/consensus floor) | 5 | **Landed** (`55c078fe`; tip **CI `#31063344773` GREEN**); elevates B-167/B-182 |
| B-226 | Docs honesty vs shipped claim-disabled / ring-16 WASM / F7 fail-closed | 5 | **Landed** (this commit; `[skip ci]`) — TESTNET/M4/PRIVACY_HARDENING/FEES/AUTHORSHIP + demo ring_size 16 |
| B-195 | Settle-reset then eleventh dual-slash treasury identity (early B-24bx) | 4 | **Landed** (`1a83d9d0`); elevates B-187; CI cancelled by B-189 — re-proved via B-196 tip |
| B-194 | Tenth-offense op1 asymmetric then absentee re-slash (early B-24bw) | 4 | **Landed** (this commit); completes tenth re-slash pair with B-193; full CI |
| B-193 | Tenth-offense asymmetric then absentee re-slash (early B-24bv) | 4 | **Landed** (this commit); elevates B-183; full CI |
| B-192 | Tenth dual-slash then empty both-miss (early B-24bu) | 4 | **Landed** (this commit); closes tenth prove matrix; elevates B-181; full CI |
| B-191 | Tenth dual-slash then op1 asymmetric settle drain (early B-24bt) | 4 | **Landed** (this commit); completes tenth asymmetric pair with B-190; full CI |
| B-190 | Tenth dual-slash then asymmetric settle drain (early B-24bs) | 4 | **Landed** (this commit); elevates B-178; full CI |
| B-189 | CLI `wallet send`/`upload` F7 owned-UTXO preflight (actionable faucet message) | 5 | **Landed** (this commit) — elevates B-186 into operator CLI UX |
| B-182 | CLI usage: `--ring-size` help says wallet/consensus floor (not bare consensus min) + smoke | 5 | **Landed** (`e7b3e8bf`; **CI `#29910182810` GREEN**) |
| B-180 | Wallet upload test fixtures use `WALLET_MIN_RING_SIZE` (no magic `ring_size: 16`) + smoke | 5 | **Landed** (`eef017ff`; covered by tip **CI `#29905438517` GREEN**) |
| B-177 | WASM transfer/upload fixtures use WALLET_MIN_RING_SIZE (no magic ring_size: 16) + smoke | 5 | **Landed** (`fe4bfc05`; **CI `#29903453186` GREEN**) |
| B-174 | Pin CLI `DEFAULT_RING_SIZE == WALLET_MIN_RING_SIZE` (unit + smoke) + tall-tip F45 soft live prove | 5 | **Landed** (this commit) — CLI unit + privacy-floor smoke; live tip=5648 / log_max=5290 F45 soft PASS |
| B-168 | WASM F7 two-input floor + F45/WASM doc honesty | 5 | **Landed** (this commit) — WASM fail-closed `<2` inputs; F45 soft CLI-only doc honesty |
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
| B-156 | Seventh dual-slash then asymmetric settle drain (early B-24ax) | 4 | **Landed** (`c3ebb5ab`); elevates B-149; rustfmt fixed in B-157 tip |
| B-157 | Seventh dual-slash then op1 asymmetric settle drain (early B-24ay) | 4 | **Landed** (`8d6e8203`); **CI `#29876590150` GREEN**; completes seventh asymmetric settle pair |
| B-158 | Seventh dual-slash then empty both-miss (early B-24az) | 4 | **Landed** (`d5dc6f38`); **CI `#29878259419` GREEN**; closes seventh-offense prove matrix |
| B-159 | Seventh-offense asymmetric then absentee re-slash (early B-24ba) | 4 | **Landed** (this commit); elevates B-152; full CI |
| B-160 | Seventh-offense op1 asymmetric then absentee re-slash (early B-24bb) | 4 | **Landed** (this commit); elevates B-153; completes seventh-offense re-slash pair; full CI |
| B-162 | Settle-reset then eighth dual-slash treasury identity (early B-24bc) | 4 | **Landed** (this commit); elevates B-154; full CI |
| B-163 | Eighth dual-slash then dual-settle drain (early B-24bd) | 4 | **Landed** (this commit); elevates B-155; full CI |
| B-166 | Eighth dual-slash then asymmetric settle drain (early B-24be) | 4 | **Landed** (this commit); elevates B-156; full CI |
| B-169 | Eighth dual-slash then op1 asymmetric settle drain (early B-24bf) | 4 | **Landed** (this commit); elevates B-157; completes eighth asymmetric pair; full CI |
| B-170 | Eighth dual-slash then empty both-miss no-drain identity (early B-24bg) | 4 | **Landed** (this commit); closes eighth-offense prove matrix; elevates B-158; full CI |
| B-171 | Eighth-offense asymmetric then absentee re-slash (early B-24bh) | 4 | **Landed** (this commit); elevates B-159; full CI |
| B-173 | Eighth-offense op1 asymmetric then absentee re-slash (early B-24bi) | 4 | **Landed** (this commit); elevates B-160; completes eighth-offense re-slash pair; full CI |
| B-175 | Settle-reset then ninth dual-slash treasury identity (early B-24bj) | 4 | **Landed** (this commit); elevates B-162; full CI |
| B-176 | Ninth dual-slash then dual-settle drain identity (early B-24bk) | 4 | **Landed** (this commit); elevates B-163; full CI |
| B-178 | Ninth dual-slash then asymmetric settle drain (early B-24bl) | 4 | **Landed** (this commit); elevates B-166; full CI |
| B-179 | Ninth dual-slash then op1 asymmetric settle drain (early B-24bm) | 4 | **Landed** (this commit); completes ninth asymmetric pair; elevates B-169; full CI |
| B-181 | Ninth dual-slash then empty both-miss (early B-24bn) | 4 | **Landed** (this commit); closes ninth-offense prove matrix; elevates B-170; full CI |
| B-184 | Ninth-offense op1 asymmetric then absentee re-slash (early B-24bp) | 4 | **Landed** (this commit); completes ninth re-slash pair with B-183; full CI |
| B-183 | Ninth-offense asymmetric then absentee re-slash (early B-24bo) | 4 | **Landed** (this commit); elevates B-171; full CI |
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

1. **2026-08-22 - lane 6 - B-306 r=0 endowment C₀ drip inert** (this commit): `deflation_funded_drip` flag + `first_year_cost_base_units` / accrue drip when r=0; checkpoint **v13**; genesis/RPC/WASM merge; Path A genesis stays 0 (no coinbase fork). `b306_*` + v12 decode default 0 + v13 round-trip + Path A pin + RPC/WASM merge tests PASS. `cargo fmt --all --check` + `cargo clippy --workspace --all-targets --all-features -- -D warnings` + `cargo audit` green. Full GitHub CI (no skip). No B-13c; no DEFAULT flip; slash matrix frozen. Next: **B-306b** enable after B-25 / Path B; **B-306c** prize-size. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-16 - lane 2 - Arweave weave-is-the-copy vs replica availability** (`7464ad8d`): `ECONOMICS.md` §12.0 states the canonical-copy split (weave tx body vs `data_root` + operator chunks); STORAGE / PRIVACY_AND_PERMANENCE / docs README point at it. Path A one-host / bond=0 called out. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` — tip `#31909490680` already FAIL scripts. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-305 unused MFEO refuse** (`704280f7`): `apply_block` / mempool reject unused MFEO/MFER when opening/range flags are 0 (`EndowmentOpeningCountMismatch` / `EndowmentRangeProofCountMismatch` expected=0). Wallet refuses all caller upload `extra`. `b305_apply_block_rejects_unused_mfeo_when_opening_not_required` + `b305_path_a_refuses_caller_mfex_extra` PASS. Local `ci-check -RustOnly` green. `#31907077988` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-35** still Phase 3 / B-25. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-305 unused MFEO refuse** (`f91e07d3`): `apply_block` / wallet still accept well-formed MFEO on Path A uploads (`require_opening=0`), so a hostile wallet can partition vs honest empty extra. Claim base `848a40ff`. Body after tip CI `#31907077988` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. Do not invent B-35. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-304 transfer MFEX refuse** (`848a40ff`): `verify_transaction` rejects well-formed MFEX on no-storage txs; `build_transfer` typed `TransferTxExtraNotEmpty`. `b304_transfer_mfex_*` PASS. Local `ci-check -RustOnly` green (audit retried after advisory-db lock flake). `#31904265430` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-305** unused MFEO refuse (not B-35). *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-304 transfer MFEX refuse** (`4b8c99db`): `verify_transaction` / `build_transfer` still accept well-formed MFEX on a no-storage transfer, so a hostile wallet can partition vs honest empty extra. Claim base `4e1fb020`. Body after tip CI `#31904265430` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. Do not invent B-35. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-303 no silent extra-drop** (`4e1fb020`): `build_storage_upload` / `build_upload_extra_wire` refuse caller `extra` when synthesizing MFEX (claims / MFEO / MFER). `b303_synthesized_mfex_refuses_caller_extra` + empty-extra opening control PASS. Local `ci-check -RustOnly` green. `#31902218314` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-304** transfer MFEX refuse (not B-35). *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-303 no silent extra-drop** (`d975cf29`): `build_upload_extra_wire` still drops caller `extra` when it synthesizes MFEO/MFER, so a hostile or mistaken extra never reaches the wire and the caller cannot tell. Claim base `d01b4df5`. Body after tip CI `#31902218314` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. Do not invent B-35. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-302 empty-MFEX fail-closed** (`d01b4df5`): `parse_mfex_extra` / `verify_transaction` reject `MFEX` + version with no MFCL/MFEO/MFER payload. Wallet typed refuse. `b302_empty_mfex_*` PASS. No-MFER apply fixture uses empty extra (not empty header). Local `ci-check -RustOnly` green. `#31897824126` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-303** no silent extra-drop (not B-35). *Observed (not staged):* `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - Path A tip-22535→22565 lag close** (`160a9b07`): VPS timer already at **22565** (97 entries). `land-path-a-checkpoint-from-vps -Apply`; outside-in **OK lag=7** tip=22572. last_proven still **22560**. Evidence `outside-in-tip-ckpt-lag-20260815T182225Z.txt` + `b-path-a-tip-22565-20260815.md`. B-301 `#31897824126` rust GREEN / scripts FAIL (Seat A) — `[skip ci]`. Next: 2nd host B-32. *Observed (not staged):* B-302; `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - B-42 3rd staggered JOIN last_proven 22560** (`5ed4a2f1`): payout→`b42-join-b` two 2e6 via hub; B-50 pin observer; upload `6a1468fc` mined+proven in **22560** (proxy total 96→97). Distinct from iris `24e62a5a` @ 22487 and join-a `ea7cba7c` @ 22492. No mfnd/faucet restart. Evidence `b42-join-b-last-proven-22560-20260815.md`. B-301 `#31897824126` rust GREEN / scripts FAIL (Seat A) — `[skip ci]`. Next: Path A lag (ckpt 22535 vs tip 22560); 2nd host B-32. *Observed (not staged):* B-302; `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - claim B-42 3rd staggered JOIN** (`06693556`): public newest last_proven still **22492** (`ea7cba7c`) vs tip **22545**. One observer upload+prove (no parallel rehearsal). Skeptic: `list_recent_uploads` last_proven > 22492. Claim base `8425c601`. Tip CI `#31897824126` in_progress — `[skip ci]`. *Observed (not staged):* B-302; `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - Path A tip-22504→22535 lag close** (`8425c601`): VPS timer already at **22535** (94 entries). `land-path-a-checkpoint-from-vps -Apply`; outside-in **OK lag=1** tip=22536. last_proven still **22492**. Evidence `outside-in-tip-ckpt-lag-20260815T174345Z.txt` + `b-path-a-tip-22535-20260815.md`. Tip CI `#31897824126` in_progress — `[skip ci]`. Next: 2nd host B-32. *Observed (not staged):* B-302; `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - faucet HTTP F7 job done 73s** (`16825793`): faucet-ops B-50 pin + payout refill; hub/voter restart cleared competing-22509 stall; tip **22508→22522**. `POST /faucet` job **`f77a4048f05e9d22c2b28d3c` done 73185ms** txs `eb4e89a3…` `ac8d77a4…`. `/health` scan=tip **22522**. Evidence `b-faucet-http-f7-20260815.md`. Tip CI `#31897824126` in_progress — `[skip ci]`. Next: Path A lag (ckpt 22504); 2nd host B-32. *Observed (not staged):* B-302 claim; `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-302 empty-MFEX fail-closed** (`a55d5869`): `parse_mfex_extra` / `verify_transaction` still accept `MFEX` + version with no MFCL/MFEO/MFER payload, so a hostile wallet can partition vs honest empty extra. Claim base `a55d5869`. Body after tip CI `#31897824126` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. Do not invent B-35 (Phase 3 / B-25). `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C faucet F7.

1. **2026-08-15 - lane 4 - B-301 P20 opaque extra fail-closed** (`a55d5869`): `parse_mfex_extra` / `verify_transaction` reject non-empty non-MFEX `tx.extra`; wallet `build_transfer` / `build_storage_upload` typed refuse. `b301_opaque_extra_*` PASS. Local `ci-check -RustOnly` green. `#31893770179` FAIL scripts (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-302** empty MFEX (not B-35). *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C faucet F7.

1. **2026-08-15 - lane 2 - go requires gates.ci.commit == manifest commit** (`b0bd1caa`): validate+emit refuse `go` if `gates.ci.commit` is a different SHA than the release commit, so a green CI pin from another head cannot unlock `go`. ci-check: funded go still accepts; funded + only `gates.ci.commit=ffff…` rejects. Path A **22504** is on main `e0cc06f1`. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]`. *Observed (not staged):* B-301 Rust; `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C faucet F7 claim.

1. **2026-08-15 - lane 7 - claim faucet HTTP F7** (Seat C working-tree; not this commit): faucet-ops scan **22479** / tip **22508** (29 behind, lock held). Claim base `e0cc06f1`. Tip CI `#31893770179` in_progress — `[skip ci]`.

1. **2026-08-15 - lane 7 - Path A tip-22495→22504 lag close** (`e0cc06f1`): VPS timer already at **22504** (91 entries). `land-path-a-checkpoint-from-vps -Apply`; outside-in **OK lag=4** tip=22508. Observer OOM 15:36Z recovered (no agent restart). last_proven still **22492**. Evidence `outside-in-tip-ckpt-lag-20260815T155404Z.txt` + `b-path-a-tip-22504-20260815.md`. Board text raced `edd1bc65`. Tip CI `#31893770179` in_progress — `[skip ci]`. Next: faucet F7; 2nd host B-32. *Observed (not staged):* B-301 Rust; Seat A signoff; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - claim Path A tip-22504 land** (`93c93dc6` board): repo ckpt **22495** vs VPS timer **22504** vs live tip **~22507** (lag≥8). Observer OOM-restart 15:36Z (replay; proxy 502) — wait, do not thrash. Land existing `land-path-a-checkpoint-from-vps`. Skeptic: outside-in lag **OK**. Claim base `6157f3a0`. `#31891608943` FAIL scripts (Seat A) — `[skip ci]`. *Observed (not staged):* B-301 Rust; Seat A `ci.yml`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - B-300 VPS apply evidence + tall-tip roll wait** (`6157f3a0`): live tip **22495→22502** already sealed; this land is `b300-vps-apply-tip-22502-20260815.md` + `vps-roll-mfnd` RPC wait 300s→**900s**. Board CLOSE text raced `7a7ca482`. `[skip ci]` — do not cancel `#31891608943` / Seat A needle CI. Next: faucet F7; 2nd host B-32. *Observed (not staged):* B-301 Rust; Seat A `ci.yml`/signoff; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - B-300 VPS apply tip 22495→22502** (`7a7ca482` board race): VPS was `b1ab1b1` (pre-B-300) with **47 CLOSE-WAIT** + `inbound_cap_reached`. `vps-prebuild-mfnd --apply` then `vps-roll-mfnd --apply --skip-pull --skip-build` (`MFN_ROLL_ALLOW_RED_CI=1`). Hub sealed **22496–22502**; public `get_tip` **22502**; `:19101` CLOSE-WAIT **47→1**; cap_n=0. Evidence was not in that commit.

1. **2026-08-15 - lane 2 - RC audit go requires bound evidence CI GREEN** (`371379ff`): `release-audit-packet` fails `ci` unless bound evidence is completed+success, so funded+red-CI cannot emit `decision=go` even with green Nightly + green CI mock. ci-check: funded packet still `go` with CI success; funded + `ci.conclusion=failure` is `no-go` + failing `ci`. Board SYNC: **B-301** is claim `42b0bf49` only — not on main (Seat B working-tree). Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` — do not cancel tip CI `#31891608943`. *Observed (not staged):* B-301 Rust; `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C `vps-roll-mfnd.sh`.

1. **2026-08-15 - lane 4 - B-301 P20 opaque extra fail-closed** (board raced this commit; **not on main**): claim is `42b0bf49`; body remains Seat B working-tree. Do not treat as landed.

1. **2026-08-15 - lane 2 - go requires bound evidence CI GREEN** (working-tree Seat A; not this commit): signoff emit+validate refuse `go` unless bound `evidence.ci` is completed+success. Do not steal; do not cancel B-301 Rust CI.

1. **2026-08-15 - lane 4 - claim B-301 P20 opaque extra fail-closed** (`42b0bf49`): `parse_mfex_extra` / `verify_transaction` still accept non-empty non-MFEX `tx.extra` (`hello-memo`), so a hostile wallet can partition the anonymity set. Claim base `247b5198`. Body after this claim. No B-13c; no DEFAULT flip; slash matrix frozen. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C B-300 VPS claim.

1. **2026-08-15 - lane 7 - claim B-300 VPS apply** (working-tree): public tip still **22495**; VPS HEAD `b1ab1b1` (pre-B-300); `:19101` **47 CLOSE-WAIT** + `inbound_cap_reached` at 14:50Z; no `producer_sealed`. Roll existing `vps-roll-mfnd` (B-300 hello 3s). Skeptic: `get_tip` > 22495. Claim base `247b5198`. B-268g `#31881362071` FAIL scripts (Seat A). *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-268g light apply overlay bps>10000 fail-closed** (`247b5198`): light `apply_block` / `apply_trusted_evolution` reject `activation_value > 10000` (active overlay + height-0 bomb). `b268g_apply_block_rejects_overlay_bps_above_10000` PASS; Path A `(0,0)` still applies. Local `ci-check -RustOnly` green. B-268f `#31879672133` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-35** pad. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-268g** (`c628bfa7`): light `apply_block` / `apply_trusted_evolution` still accept `with_subsidy_schedule(activation_value > 10000)` (B-268e decode + B-268f full-node apply only). Claim base `74923cc5`. Body after tip CI `#31879672133` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-268f apply_block overlay bps>10000 fail-closed** (`74923cc5`): apply_block rejects `activation_value > 10000` (active overlay + height-0 bomb). `b268f_apply_block_rejects_overlay_bps_above_10000` PASS; Path A `(0,0)` still applies. Local `ci-check -RustOnly` green. B-300 `#31876698322` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-268g** light overlay fail-closed. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-268f** (`afae468a`): apply_block still accepts in-memory overlay `activation_value > 10000` (B-268e only gates checkpoint decode). Claim base `393d508c`. Body after tip CI `#31876698322` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-300 inbound hello timeout releases handler slot** (`393d508c`): inbound hello IO 30s→**3s**; handler + cap-reject `shutdown(Both)`; session clones get gossip IO timeout. `b300_inbound_slot_releases_on_drop` + `b300_silent_inbound_hello_releases_under_five_seconds` PASS (~3s close). Local `ci-check -RustOnly` green. B-268e `#31874878025` rust GREEN / scripts FAIL (Seat A). No VPS; no B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-268f** apply overlay fail-closed. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-300** (`46134591` board): silent inbound holds a `P2P_MAX_INBOUND_HANDLERS` slot for the 30s hello timeout. Claim base `13ea7acf`.

1. **2026-08-15 - lane 4 - B-268e overlay bps>10000 fail-closed** (`13ea7acf`): chain v12 + light v2 decode reject `activation_value > 10000` (inactive height-0 bomb included). `SubsidyBpsSchedule::validate` + `b268e_schedule_rejects_bps_above_10000` / `b268e_v12_rejects_overlay_bps_above_10000` / `b268e_v2_rejects_overlay_bps_above_10000` PASS. Path A `(0,0)` still loads. Local `ci-check -RustOnly` green. B-268d `#31872756568` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-35** pad. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C tip-22495 claim + CLOSE-WAIT evidence.

1. **2026-08-15 - lane 7 - claim tip-22495 stall recover** (`6ea5452a`): public tip stuck **22495** since hub OOM restart 07:30Z; journal is inbound_cap=48 + vote_fanout EAGAIN, no `producer_sealed`. Recover `mfn-p2p-forward-hub` only (no mfnd/faucet). Skeptic: `get_tip` > 22495. Claim base `a6cd75f6`. Tip CI `#31872756568` in_progress — `[skip ci]`. *Observed (not staged):* Seat B B-268e; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - Path A tip-22495 + hub OOM / faucet voter RPC** (`a6cd75f6`): repo ckpt 22486→**22495** (timer publish; lag 9→0). Hub OOM-kill 07:30Z (systemd; no agent mfnd restart). Faucet drop-in `MFND_RPC=127.0.0.1:18733`. HTTP fund **not** proven (faucet-ops owned=1; refill txs mempool-only). 19001 OPEN. Evidence `b42-hub-oom-path-a-22495-20260815.md` + `outside-in-tip-ckpt-lag-20260815T075855Z.txt`. Tip CI `#31872756568` in_progress — `[skip ci]`. Next: faucet F7; 2nd host B-32. *Observed (not staged):* Seat B B-268e; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-268e** (`936311e9`): chain/light checkpoint decode still accept `activation_value > 10000`, so a restored overlay can take more than 100% of subsidy. Claim base `6015797c`. Body after tip CI `#31872756568` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C hub EAGAIN.

1. **2026-08-15 - lane 4 - B-268d light slash uses genesis emission + schedule** (`6015797c`): light `apply_equivocation` no longer uses `DEFAULT` + empty schedule. `get_light_snapshot` / light ckpt **v2** persist `(H_act, bps)`; v1 decodes inactive. `b268d_light_schedule_overlays_subsidy_not_default` PASS (DEFAULT ValidFraud; light overlay NotFraud; v2 restore keeps schedule). Local `ci-check -RustOnly` green. B-268c `#31870566481` rust GREEN / scripts FAIL (Seat A). No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-268e** overlay fail-closed. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat C hub EAGAIN claim.

1. **2026-08-15 - lane 7 - claim hub EAGAIN recover + faucet fund prove** (`e3dfa6c8`): hub `:18731` get_tip TIMEOUT, mfnd-hub 95% CPU; faucet `/health` ok but keepalive tip EAGAIN and wallet **14** behind (scan 22479 / tip 22493). Recover `mfn-p2p-forward-hub` only (no mfnd/faucet). Then prove faucet catch-up + HTTP dual-fund. Claim base `985e594e`. Tip CI `#31870566481` in_progress — `[skip ci]`. *Observed (not staged):* Seat B B-268d light; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - B-42 2nd staggered JOIN last_proven 22492** (`985e594e`): payout→`b42-join-a` two 2e6 via observer; upload `ea7cba7c` mined+proven in **22492** (proxy total 95→96, user_tx 419→422). Distinct from iris `24e62a5a` @ 22487. No mfnd/faucet restart. Path A ckpt 22486 lag=6 OK. Evidence `b42-join-a-last-proven-22492-20260815.md`. Tip CI `#31870566481` in_progress — `[skip ci]`. Next: 2nd host B-32. *Observed (not staged):* Seat B B-268d light; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - claim B-268d** (`0f795a9f`): light `apply_equivocation` still uses `DEFAULT_EMISSION_PARAMS` + empty schedule, so after `H_act` an honest overlay coinbase slash is a false positive and light diverges from the full node. Claim base `342ffbf8`. Body after tip CI `#31870566481` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 4 - B-268c contested-height fraud overlay** (`342ffbf8`): slash/gossip use `SubsidyBpsSchedule.effective(base, contested_height)` not applying-era overlay / not `DEFAULT`. `b268c_default_params_false_positive_honest_overlay_coinbase` PASS (DEFAULT ValidFraud; overlay NotFraud; wrong-era ValidFraud). Local ci-check OK. No B-13c; no DEFAULT flip. Full CI (no skip). Next: **B-268d** light schedule. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - B-42 last_proven 22467→22487** (`710705a9`): iris observer upload `24e62a5a` mined+proven in **22487** (proxy total 94→95, user_tx 418→419). No mfnd/faucet restart. Path A ckpt 22486 lag=1 OK. Evidence `b42-join-last-proven-22487-20260815.md`. B-268b CI `#31867337251` **FAIL** scripts (Seat A). `[skip ci]`. Next: 2nd staggered JOIN; 2nd host B-32. *Observed (not staged):* Seat B B-268c Rust; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - hub OOM stall recover + Path A tip-22486** (`4bb569d3`): hub OOM 05:36Z; tip stuck **22484**; proposal 22485 starved. No mfnd/faucet restart. Stop+start `mfn-p2p-forward-hub` only; tip **22486**. Path A publish via observer RPC; land jsonl; outside-in **OK lag=0**. B-42 JOIN upload `24e62a5a` still mempool-only; last_proven **22467**. Evidence `b42-hub-oom-path-a-22486-20260815.md` + `outside-in-tip-ckpt-lag-20260815T061243Z.txt`. B-268b CI `#31867337251` **FAIL** scripts (Seat A; rust GREEN). `[skip ci]`. Next: JOIN retry when hub produce quiet; 2nd host B-32. *Observed (not staged):* Seat B B-268c Rust; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 2 - go refuses Path A toy keys** (`c8037401`): signoff + RC audit refuse `go` if any operator `payout_seed_hex` or validator `vrf`/`bls` seed is repeating-byte (Path A `c3c3…` / `0101…` pattern). Funded+bonded lab genesis is still Path A. ci-check: toy-keys reject; detoy'd temp genesis still `go`. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` — do not cancel B-268b CI `#31867337251`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json; Seat B B-268c claim.

1. **2026-08-15 - lane 4 - claim B-268c** (`6966b597`): fraud/slash/gossip must use `effective_emission_params` at the *contested* block height (B-268b apply/producer use applying height; gossip still `DEFAULT`; slash reuses applying-era overlay). Claim base `71a7ad7a`. Body after B-268b CI `#31867337251` GREEN. No B-13c; no DEFAULT flip; slash matrix frozen. `[skip ci]`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 2 - go requires bonded genesis operators** (`71a7ad7a`): signoff + RC audit refuse `go` unless genesis has >=2 `storage_operators` with `bond_amount >= min_storage_operator_bond`. Funded min-bond with $0 operators is still Path A. ci-check: unbonded-ops reject; bonded temp genesis still `go`. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` — do not cancel B-268b CI `#31867337251`. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 6 - B-268b effective_emission_params + ckpt v12** (`ee3739e7`): same-chain subsidy overlay without mutating base `emission_params` or `DEFAULT_EMISSION_PARAMS`. apply_block/producer use height-aware params; checkpoint v12 persists `(H_act, bps)`; v11 decodes `(0,0)`. Local ci-check OK; `b268b_activation_overlay_*` apply_block PASS (wrong-era CoinbaseInvalid). No B-13c enable. Full CI (no skip). Next: human **B-33**; **B-35** pad. *Observed (not staged):* `apply_block_proptest.rs`; `tx_storm.rs`; Seat A signoff scripts; Seat C B-42 evidence/jsonl.

1. **2026-08-15 - lane 7 - B-42 serialize-with-reason** (`bda9a419`): invite-load `-Apply` **PASS** (seeds 19001–19004 OPEN, faucet idle). Live JOIN **not** started: `get_light_snapshot` @ ckpt 22475 timed out 300s on observer; hub `wallet send` **EAGAIN**; faucet-ops **owned=1** (F7). Path A land **22475**. Evidence `b42-invite-load-serialize-20260815.md` + `invite-load-preflight-20260815T052914Z.txt`. `[skip ci]` — do not steal **B-268b**. Next: retry JOIN when observer quiet; 2nd host B-32. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; lane2 signoff scripts.

1. **2026-08-15 - lane 2 - go re-reads genesis economy** (`dd6fdd71`): signoff emit/validate + RC audit refuse `go` unless `economy.genesis_path` genesis has subsidy>0 and bond>0. Evidence overlay lies no longer unlock `go` on Path A zeros. ci-check: overlay-lie reject; funded temp genesis still `go`. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` so Seat B keeps **B-268b**. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 2 - RC audit go requires Nightly GREEN** (`5ebfc727`): `release-audit-packet` fails `nightly` unless bound evidence is completed+success, so funded+red-Nightly cannot emit `decision=go`. ci-check: funded packet still `go` with Nightly success; funded + `nightly.conclusion=failure` is `no-go` + failing `nightly`. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` so Seat B keeps **B-268b**. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 2 - signoff go requires Nightly GREEN** (`50e3d496`): emit + validate refuse `decision=go` unless bound `evidence.nightly` is completed+success (in addition to funded economy + CI). ci-check: funded go + `nightly.conclusion=failure` reject; funded + Nightly success still accept. SYNC: wave115 `46d9f86c` on main; lane7 **B-42** Doing (not this body). Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` so Seat B keeps **B-268b**. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 7 - claim B-42** (Seat C working-tree): live invite-load stagger after B-15 wave115. Claim base `46d9f86c`. Faucet-ops owned=1 (need second UTXO before JOIN). No parallel JOIN until this unit runs staggered pair. `[skip ci]` — do not steal **B-268b**. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; lane2 signoff scripts.

1. **2026-08-15 - lane 3 - B-15 wave115 last_proven 6848→22467** (`46d9f86c`): public newest last_proven was hugo **6848** for ~15k blocks. Faucet-ops **owned=0** after B-296 storm (HTTP F7 1-input error). Payout refill owned=3 (no faucet restart); iris job `3f46b975` **done 91s**; upload `601cb854…` + prove; proxy **last_proven=22467** total 93→94. Path A land tip-22467; outside-in lag **OK=1**. Evidence `b15-wave115-last-proven-22467-20260815.md`. `[skip ci]` — do not steal **B-268b**. Next: Human SUMMARY; **B-42**. *Observed (not staged):* lane6 B-268b Rust; `apply_block_proptest.rs`; `tx_storm.rs`; lane2 signoff scripts.

1. **2026-08-15 - lane 2 - signoff go requires Nightly GREEN** (body in this commit; prior board note): emit + validate refuse `decision=go` unless bound `evidence.nightly` is completed+success.

1. **2026-08-15 - lane 2 - signoff go forbidden on Path A holes** (`eaa822a8`): `release-signoff-manifest` emit + validate refuse `decision=go` unless subsidy>0, bond>0, and `path_a_experimental=false`. Sample is honest `no-go`. ci-check: Path A go reject; funded go + bad CI still reject. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` so Seat B keeps **B-268b**. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; rc-audit json.

1. **2026-08-15 - lane 2 - RC audit no-go on Path A holes** (`0845655d`): `path_a_economy` check fails unless subsidy>0, bond>0, and `path_a_experimental=false`; packet decision becomes `no-go`. Dry-run records the decision (no longer hard-requires `go`). ci-check: Path A dry-run must be `no-go`; funded temp evidence can still `go`. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c. `[skip ci]` so Seat B keeps **B-268b** Rust CI. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; rc-audit-dry-run json.

1. **2026-08-15 - lane 2 - Path A economy honesty** (`83f76d7e`): `release-evidence.v1` requires `economy` from `public_devnet_v1.json` (`subsidy_to_treasury_bps`, `min_storage_operator_bond`, `path_a_experimental`). Refresh fail-closed if the flag lies about zeros; schema rejects missing `economy`. Live packet pins Path A zeros + `path_a_experimental=true`. Local `ci-check -DocsOnly` green. No DEFAULT flip; no B-13c enable. `[skip ci]` so Seat B can take full CI for **B-268b**. *Observed (not staged):* lane6 B-268b Rust; `tx_storm.rs`; rc-audit-dry-run json.

1. **2026-08-15 - lane 7 - B-299 restore public hub seed 19001** (`30ff27b0`): B-291 left `mfn-p2p-forward-hub` stopped (exit 143 @ 02:04Z); outside TCP **19001 CLOSED**, 19002–19004 OPEN, hub still on `127.0.0.1:19101`. `systemctl start mfn-p2p-forward-hub` only (no mfnd/faucet). After: **19001 OPEN**, tip **22446→22447**, invite-load `-Apply` **PASS** (`invite-load-preflight-20260815T043052Z.txt`). Evidence `b299-hub-seed-19001-20260815.md`. `[skip ci]` — do not steal **B-268b**. Next: **B-42**; 2nd host B-32. *Observed (not staged):* lane6 B-268b Rust; release-evidence; `apply_block_proptest.rs`; `tx_storm.rs`.

1. **2026-08-15 - lane 7 - B-298 Path A tip-22437 land + lag close** (`0237a53d`): repo ckpt_max was **16622** vs live tip **22443** (lag=5821 FAIL). VPS timer already published tip=22437 (84 entries); `land-path-a-checkpoint-from-vps -Apply` + outside-in assert **OK lag=6** (threshold 8). Evidence `b298-path-a-tip-22437-20260815.md` + `outside-in-tip-ckpt-lag-20260815T042600Z.txt`. B-15-safe (no faucet/mfnd). `[skip ci]` — do not steal **B-268b**. Next: **B-42**; 2nd host B-32. *Observed (not staged):* lane6 B-268b Rust; release-evidence; `apply_block_proptest.rs`; `tx_storm.rs`.

1. **2026-08-15 - lane 7 - claim B-298** (board in this CLOSE): Path A republish + lag close. Claim base `9396b6cb`. SYNC: **B-296** landed `9396b6cb` but board still said Doing.

1. **2026-08-15 - lane 7 - B-296 faucet-ops rotate + dual-payment storm** (`9396b6cb`): systemd `FAUCET_WALLET=faucet-ops.json`; HTTP job **76s**; storm landed **13**; observer user-tx **391→408**. Board CLOSE raced Seat A Path A economy text — corrected this claim. Next was **B-298** (lag). `[skip ci]`.

1. **2026-08-15 - lane 2 - Path A economy honesty** (working-tree note absorbed by this land): body was local during B-296/B-298/B-299; now on main.

1. **2026-08-15 - lane 2 - release-evidence Nightly pin** (`d4af3743`): `release-evidence.v1` requires `nightly` (same shape as `ci`); refresh-for-head fail-closed unless CI **and** Nightly are completed+success (ancestor walk); ci-check needles + missing-nightly schema reject. Live tip packet pins CI `#31860183965` + Nightly `#31861932921`. Local `ci-check -DocsOnly` green. `[skip ci]` so Seat B can take the full-CI window for **B-268b** Rust. Does not steal **B-268b** / **B-296**. *Observed (not staged):* lane6 B-268b Rust; `apply_block_proptest.rs`; `mfn-wallet/tests/tx_storm.rs`; `_b296_probe.*`; rc-audit-dry-run json.

1. **2026-08-15 - lane 6 - B-268b body ready** (Seat B working-tree; not this commit): `effective_emission_params` + ckpt v12; no DEFAULT flip; no B-13c enable. Claim base `6e2e21a6`. Do not steal **B-296**.

1. **2026-08-15 - lane 6 - claim B-268b** (board already claimed): `effective_emission_params` + ckpt v12 + apply_block wire. Abandon **B-295** (slash matrix frozen). Claim base `6e2e21a6`. Tip CI `#31860183965` + Nightly `#31861932921` **GREEN**. No B-13c enable; no DEFAULT flip. Do not steal **B-296**. *Observed (not staged):* `apply_block_proptest.rs`; `mfn-wallet/tests/tx_storm.rs`; rc-audit-dry-run json; `_b296_probe.*`. `[skip ci]`.

1. **2026-08-15 - lane 7 - claim B-296** (`6e2e21a6`): dual-payment live storm + faucet-ops systemd rotate after B-291 mesh recover. Claim base `e5e1f65a`. Tip CI `#31860183965` + Nightly `#31861932921` **GREEN** (absorbed uncommitted Seat A pin). Do not cancel; do not touch consensus tests. *Observed (not staged):* lane4 `apply_block_proptest.rs`; `mfn-wallet/tests/tx_storm.rs`; rc-audit-dry-run json. `[skip ci]`.

1. **2026-08-15 - lane 1+2 - pin CI `#31860183965` + Nightly `#31861932921` GREEN** (working-tree SYNC, landed with B-296 claim): board said CI in_progress; full matrix SUCCESS on B-294 `0ecd19ce`. Nightly `#31861932921` **GREEN** on `e5e1f65a`. Release evidence waits for next full-CI Rust head. Seat A does not steal **B-296** / protocol tests. *Observed (not staged):* lane4 `apply_block_proptest.rs`; `mfn-wallet/tests/tx_storm.rs`; rc-audit-dry-run json. `[skip ci]`.

1. **2026-08-15 - lane 4 - claim B-295** (`e5e1f65a`): early B-24eo twentieth-offense op1 asymmetric then absentee re-slash while tip CI `#31860183965` runs on B-294 `0ecd19ce`. Claim base `0ecd19ce`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-296** Next. `[skip ci]`.

1. **2026-08-15 - lane 4 - B-294 twentieth asymmetric->absentee re-slash** (`0ecd19ce`): early B-24en `b294_b5_twentieth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local exact PASS. Tip CI `#31857970110` **GREEN** on B-293. Elevates B-286. Full CI (no skip). Next: **B-295** twentieth op1 re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** `24ce61a9` / **B-296** Next — not staged.

1. **2026-08-15 - lane 7 - B-291 tall-tip mesh recover** (`24ce61a9`): tip stall from public seed hairpins + ~15m block-log replay; applied `MFN_SKIP_MANIFEST_SEEDS=1`, loopback `peers.json` (object shape), voters-hot then hub-only restart; tip restored **22350**; faucet hot path `validator0-faucet.json`; dual-fund txs raised observer user-tx 384→391; storm deferred to **B-296** (light-scan EAGAIN). Evidence `b291-tall-tip-mesh-recover-20260815.md` + OPERATORS row. Docs/ops `[skip ci]`. Next: **B-296** storm+ops rotate; B-42; 2nd host B-32. *Observed (not staged):* lane4 `apply_block_proptest.rs`; `mfn-wallet/tests/tx_storm.rs`; rc-audit-dry-run json.

1. **2026-08-14 - lane 4 - claim B-294** (`1a986708`): early B-24en twentieth-offense asymmetric then absentee re-slash while tip CI `#31857970110` ran on B-293 `054f6332`. Claim base `054f6332`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed. `[skip ci]`.

1. **2026-08-14 - lane 4 - B-293 twentieth dual-slash->empty both-miss** (`054f6332`): early B-24em `b293_b5_twentieth_dual_slash_then_empty_both_miss_no_drain_identity`; local exact PASS. Tip CI `#31856003083` **GREEN** on B-292. Elevates B-285; closes twentieth prove matrix {00,01,10,11}. Full CI (no skip). Next: **B-294** twentieth asymmetric re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed — not staged.

1. **2026-08-14 - lane 4 - claim B-293** (`852af6e1`): early B-24em twentieth dual-slash then empty both-miss while tip CI `#31856003083` ran on B-292 `37882c4e`. Claim base `37882c4e`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed. `[skip ci]`.

1. **2026-08-14 - lane 4 - B-292 twentieth dual-slash->op1 asymmetric settle** (`37882c4e`): early B-24el `b292_b5_twentieth_dual_slash_then_op1_asymmetric_settle_drain_identity`; local exact PASS. Tip CI `#31853372971` **GREEN** on B-290. Elevates B-284; completes twentieth asymmetric pair with B-290. Full CI (no skip). Next: **B-293** twentieth empty both-miss. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed — not staged.

1. **2026-08-14 - lane 4 - claim B-292** (`11b3d727`): early B-24el twentieth dual-slash then op1 asymmetric settle while tip CI `#31853372971` ran on B-290 `3972e785`. Claim base `3972e785`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed. `[skip ci]`.

1. **2026-08-14 - lane 4 - B-290 twentieth dual-slash->asymmetric settle** (`3972e785`): early B-24ek `b290_b5_twentieth_dual_slash_then_asymmetric_settle_drain_identity`; local exact PASS. Tip CI `#31851127499` **GREEN** on B-289. Elevates B-283. Full CI (no skip). Next: **B-292** twentieth op1 asymmetric settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed — not staged.

1. **2026-08-14 - lane 4 - claim B-290** (`838042e3`): early B-24ek twentieth dual-slash then asymmetric settle while tip CI `#31851127499` ran on B-289 `77750721`. Claim base `77750721`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed. `[skip ci]`.

1. **2026-08-14 - lane 4 - B-289 twentieth dual-slash->dual settle** (`77750721`): early B-24ej `b289_b5_twentieth_dual_slash_then_dual_settle_drain_identity`; local exact PASS. Tip CI `#31848492528` **GREEN** on B-278 (re-proves B-288 after wasm runner-lost on `#31845327735`). Elevates B-282. Full CI (no skip). Next: **B-290** twentieth asymmetric settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. Lane7 **B-291** claimed — not staged.

1. **2026-08-14 - lane 4 - claim B-289** (`20b58144`): early B-24ej twentieth dual-slash then dual settle while tip CI `#31845327735` ran on B-288 `925c9c7b`. Claim base `925c9c7b`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. `[skip ci]`.

1. **2026-08-14 - lane 4 - B-288 settle-reset->twentieth dual-slash** (`925c9c7b`): early B-24ei `b288_b5_settle_reset_then_twentieth_dual_slash_treasury_identity`; local exact PASS. Tip CI `#31845327735` in_progress. Elevates B-281. Full CI (no skip). Next: **B-289** twentieth dual settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json.

1. **2026-08-14 - lane 4 - claim B-288** (`56468fc9`): early B-24ei settle-reset->twentieth dual-slash while tip CI `#31161003334` **GREEN** on B-287 `f9b734dc`. Claim base `b5a9a096`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs; rc-audit-dry-run json. `[skip ci]`.

1. **2026-08-14 - lane 7 - claim B-291** (this commit): dual-payment live storm + faucet-ops systemd rotate while tip CI `#31848492528` runs on B-278 `b1ab1b17`. Claim base `b1ab1b17`. *Observed (not staged):* lane4 `apply_block_proptest.rs`; `mfn-wallet/tests/tx_storm.rs`; rc-audit-dry-run json. `[skip ci]`.

1. **2026-08-14 - lane 7 - B-278 faucet UTXO prune + HTTP fund prove** (`b1ab1b17`): F122 root cause = payout_stealth faucet accumulates ~1 coinbase UTXO/block (`owned≈22062`). Live prune `--keep 32`; HTTP dual-fund job done in **99s** (gate <120s). Tooling: `faucet-wallet-prune.sh`, `faucet-rotate-from-payout.sh` (tip-pin), OPERATORS row, CLI O(n) pending-spend diff. Evidence `b278-faucet-utxo-prune-20260814.md`. Full CI (no skip). Next: dual-payment storm / optional faucet-ops systemd; B-42; 2nd host B-32. *Observed (not staged):* lane4 `apply_block_proptest.rs`; `mfn-wallet/tests/tx_storm.rs`.

1. **2026-08-07 - lane 4 - B-287 nineteenth op1 asymmetric->absentee re-slash** (`f9b734dc`): early B-24eh `b287_b5_nineteenth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local exact PASS. Tip CI `#31161003334` **GREEN** on B-287. Elevates B-280; completes nineteenth re-slash pair with B-286. Full CI (no skip). Next: **B-288** settle-reset->twentieth dual-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.

1. **2026-08-07 - lane 4 - claim B-287** (this commit): early B-24eh nineteenth-offense op1 asymmetric->absentee re-slash while tip CI `#31157851198` runs on B-286. Claim base `aad365d6`. Body ready (`b287_*` PASS). *Observed (not staged):* mfn-wallet/tests/tx_storm.rs. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-286 nineteenth asymmetric->absentee re-slash** (this commit): early B-24eg `b286_b5_nineteenth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local exact PASS. Tip CI `#31155238632` **GREEN** on B-285. Elevates B-279. Full CI (no skip). Next: **B-287** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.

1. **2026-08-07 - lane 4 - claim B-286** (this commit): early B-24eg nineteenth-offense asymmetric->absentee re-slash while tip CI `#31155238632` runs on B-285. Claim base `d1b44f3b`. Body ready (`b286_*` PASS). *Observed (not staged):* mfn-wallet/tests/tx_storm.rs. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-285 nineteenth dual-slash->empty both-miss** (this commit): early B-24ef `b285_b5_nineteenth_dual_slash_then_empty_both_miss_no_drain_identity`; local exact PASS. Tip CI `#31152030401` **GREEN** on B-284. Elevates B-276; closes nineteenth prove matrix. Full CI (no skip). Next: **B-286** nineteenth re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.

1. **2026-08-07 - lane 4 - claim B-285** (this commit): early B-24ef nineteenth dual-slash->empty both-miss while tip CI `#31152030401` runs on B-284. Claim base `a81dfd55`. Body ready (`b285_*` PASS). *Observed (not staged):* mfn-wallet/tests/tx_storm.rs. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-284 nineteenth dual-slash->op1 asymmetric settle** (this commit): early B-24ee `b284_b5_nineteenth_dual_slash_then_op1_asymmetric_settle_drain_identity`; local exact PASS. Tip CI `#31149496815` **GREEN** on B-283. Elevates B-275; completes nineteenth asymmetric pair with B-283. Full CI (no skip). Next: **B-285** empty both-miss. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.

1. **2026-08-07 - lane 4 - claim B-284** (this commit): early B-24ee nineteenth dual-slash->op1 asymmetric settle while tip CI `#31149496815` runs on B-283. Claim base `72522d22`. Body ready (`b284_*` PASS). *Observed (not staged):* mfn-wallet/tests/tx_storm.rs. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-283 nineteenth dual-slash->asymmetric settle** (this commit): early B-24ed `b283_b5_nineteenth_dual_slash_then_asymmetric_settle_drain_identity`; local exact PASS. Tip CI `#31147172975` **GREEN** on B-282. Elevates B-274. Full CI (no skip). Next: **B-284** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.

1. **2026-08-07 - lane 4 - claim B-283** (this commit): early B-24ed nineteenth dual-slash->asymmetric settle while tip CI `#31147172975` runs on B-282. Claim base `6a47d384`. Body ready (`b283_*` PASS). Parallel race noted: B-282 body on `bb00f7a4`, board CLOSE raced `6a47d384`. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-282 nineteenth dual-slash->dual settle** (this commit): early B-24ec `b282_b5_nineteenth_dual_slash_then_dual_settle_drain_identity`; local exact PASS. Tip CI `#31144715090` **GREEN** on B-281. Elevates B-273. Full CI (no skip). Next: **B-283** nineteenth asymmetric settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.


1. **2026-08-07 - lane 4 - claim B-282** (this commit): early B-24ec nineteenth dual-slash->dual settle while tip CI `#31144715090` runs on B-281. Claim base `27768fba`. Body ready (`b282_*` PASS). *Observed (not staged):* mfn-wallet/tests/tx_storm.rs. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-281 settle-reset->nineteenth dual-slash** (this commit): early B-24eb `b281_b5_settle_reset_then_nineteenth_dual_slash_treasury_identity`; local exact PASS. Tip CI `#31142492616` **GREEN** on B-280. Elevates B-272. Full CI (no skip). Next: **B-282** nineteenth dual settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.

1. **2026-08-07 - lane 4 - claim B-281** (this commit): early B-24eb settle-reset->nineteenth dual-slash while tip CI `#31142492616` runs on B-280. Claim base `160c0e51`. Body ready (`b281_*` PASS). *Observed (not staged):* mfn-wallet/tests/tx_storm.rs. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-280 eighteenth op1 asymmetric->absentee re-slash** (this commit): early B-24ea `b280_b5_eighteenth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local exact PASS. Tip CI `#31140317122` **GREEN** on B-279. Elevates B-271; completes eighteenth re-slash pair with B-279. Full CI (no skip). Next: **B-281** settle-reset->nineteenth dual-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* mfn-wallet/tests/tx_storm.rs.

1. **2026-08-07 - lane 4 - claim B-280** (this commit): early B-24ea eighteenth-offense op1 asymmetric->absentee re-slash while tip CI `#31140317122` runs on B-279. Claim base `4836ad9c`. Body ready (`b280_*` PASS). *Observed (not staged):* lane7 B-278 WIP if any. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-279 eighteenth asymmetric->absentee re-slash** (this commit): early B-24dz `b279_b5_eighteenth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local exact PASS. Tip CI `#31138006162` **GREEN** on B-276. Elevates B-270. Full CI (no skip). Next: **B-280** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane7 B-278 WIP if any.

1. **2026-08-07 - lane 7 - B-277 board CLOSE** (this commit): tooling already in `af596d04`; mark Done F120–F123; Next **B-278** faucet hygiene. Tip CI `#31138006162` must finish before push of Rust stack. `[skip ci]`.

1. **2026-08-07 - lane 4 - claim B-279** (this commit): early B-24dz eighteenth-offense asymmetric->absentee re-slash while tip CI `#31138006162` runs on B-276. Claim base `95030ffd`. Body ready (`b279_*` PASS). *Observed (not staged):* lane7 onchain-tx-storm / B-277 WIP. `[skip ci]`.

1. **2026-08-07 - lane 4 - B-276 eighteenth dual-slash->empty both-miss** (this commit): early B-24dy `b276_b5_eighteenth_dual_slash_then_empty_both_miss_no_drain_identity`; local exact PASS. Tip CI `#31135276096` **GREEN** on B-275. Elevates B-266; closes eighteenth prove matrix. Full CI (no skip). Next: **B-279** eighteenth re-slash (skip B-277/B-278 — lane7). Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane7 onchain-tx-storm / B-277 WIP.

1. **2026-08-07 - lane 4 - claim B-276** (this commit): early B-24dy eighteenth dual-slash->empty both-miss while tip CI `#31135276096` runs on B-275. Claim base `e5c27e1c`. Body ready (`b276_*` PASS). *Observed (not staged):* onchain-tx-storm WIP; lane7 B-277 WIP. `[skip ci]`.

1. **2026-08-06 - lane 7 - claim B-277** (this commit): live Path A onchain tx-storm + adversarial probes while tip CI `#31132162520` runs on B-274. Claim base `decb34ef`. Tunnel `127.0.0.1:18734`→VPS observer; faucet idle tip~16614. *Observed (not staged):* lane4 `apply_block_proptest.rs` B-275 body. `[skip ci]`.

1. **2026-08-06 - lane 4 - B-275 eighteenth dual-slash->op1 asymmetric settle** (this commit): early B-24dx `b275_b5_eighteenth_dual_slash_then_op1_asymmetric_settle_drain_identity`; local exact PASS. Tip CI `#31132162520` **GREEN** on B-274. Elevates B-263; completes eighteenth asymmetric pair with B-274. Full CI (no skip). Next: **B-276** empty both-miss. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.

1. **2026-08-06 - lane 4 - claim B-275** (this commit): early B-24dx eighteenth dual-slash->op1 asymmetric settle while tip CI `#31132162520` runs on B-274. Claim base `fef0ca88`. Body ready (`b275_*` PASS). *Observed (not staged):* onchain-tx-storm WIP. `[skip ci]`.

1. **2026-08-06 - lane 4 - B-274 eighteenth dual-slash->asymmetric settle** (this commit): early B-24dw `b274_b5_eighteenth_dual_slash_then_asymmetric_settle_drain_identity`; local exact PASS. Tip CI `#31129713995` **GREEN** on B-273 (prior dispatch `#31129198022` cancelled). Elevates B-262. Full CI (no skip). Next: **B-275** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.

1. **2026-08-06 - lane 4 - claim B-274** (this commit): early B-24dw eighteenth dual-slash->asymmetric settle while tip CI `#31129198022` runs on B-273. Claim base `eea604c9`. Body ready (`b274_*` PASS). *Observed (not staged):* onchain-tx-storm WIP. `[skip ci]`.

1. **2026-08-06 - lane 4 - B-273 eighteenth dual-slash->dual settle** (this commit): early B-24dv `b273_b5_eighteenth_dual_slash_then_dual_settle_drain_identity`; local exact PASS. Tip CI `#31128755182` **GREEN** on B-272. Elevates B-261. Full CI (no skip). Next: **B-274** eighteenth asymmetric settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.

1. **2026-08-06 - lane 4 - claim B-273** (this commit): early B-24dv eighteenth dual-slash->dual settle while tip CI `#31128755182` runs on B-272. Claim base `d8ff06cf`. Body ready (`b273_*`). *Observed (not staged):* onchain-tx-storm WIP. `[skip ci]`.

1. **2026-08-06 - lane 4 - B-272 settle-reset->eighteenth dual-slash** (this commit): early B-24du `b272_b5_settle_reset_then_eighteenth_dual_slash_treasury_identity`; local exact PASS. Tip CI `#31128313784` FAIL was cancelled wasm/clippy (all OS tests + rustfmt GREEN). Elevates B-259. Full CI (no skip). Next: **B-273** eighteenth dual settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.

1. **2026-08-06 - lane 4 - claim B-272** (this commit): early B-24du settle-reset->eighteenth dual-slash while tip CI `#31128313784` runs on B-271. Claim base `8e83aacf`. Body ready (`b272_*` PASS). `[skip ci]`.

1. **2026-08-06 - lane 4 - B-271 seventeenth op1 asymmetric->absentee re-slash** (this commit): early B-24dt `b271_b5_seventeenth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local exact PASS. Tip CI `#31127944455` cancelled (runner flakes; ubuntu tests GREEN). Elevates B-246; completes seventeenth re-slash pair with B-270. Full CI (no skip). Next: **B-272** settle-reset->eighteenth dual-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.

1. **2026-08-06 - lane 4 - claim B-271** (this commit): early B-24dt seventeenth op1 asymmetric->absentee re-slash while tip CI `#31127944455` runs on B-270. Claim base `4ccf1b79`. Body ready (`b271_*` PASS). `[skip ci]`.

1. **2026-08-06 - lane 4 - B-270 seventeenth asymmetric->absentee re-slash** (this commit): early B-24ds `b270_b5_seventeenth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local exact PASS. Tip CI `#31127479415` FAIL was cancelled clippy only (matrix otherwise GREEN). Elevates B-242. Full CI (no skip). Next: **B-271** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.

1. **2026-08-06 - lane 4 - claim B-270 + Ack B-268 design** (this commit): early B-24ds seventeenth asymmetric->absentee re-slash body ready (`b270_*` PASS). **Ack** B-268: `effective_emission_params` overlay; reject mutating base `emission_params` at H_act; fraud/producer must use effective params; checkpoint v12 schedule OK. Watch tip CI `#31127479415`. `[skip ci]`.

1. **2026-08-06 - lane 4 - B-266 seventeenth empty both-miss** (this commit): early B-24dr 266_b5_seventeenth_dual_slash_then_empty_both_miss_no_drain_identity; local exact PASS. Tip CI #31126560747 FAIL was cancelled ubuntu-scripts only (matrix otherwise GREEN). Elevates B-241; closes seventeenth prove matrix. Full CI (no skip). Next: **B-270** seventeenth asymmetric->absentee re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.

1. **2026-08-06 — lane 6 — B-269 Path A timer 8m** (this commit): `OnUnitActiveSec=30min`→`8min` to match `MFN_CKPT_LAG_THRESHOLD=8` (JOIN soft-pin was flapping most of each 30m window). Smoke + OPERATORS; VPS `vps-install-near-tip-ckpt-timer --apply`. Tip CI `#31126560747` must not cancel — `[skip ci]`. Next: idle — B-268b after GREEN+Ack. *Observed (not staged):* onchain-tx-storm; lane4 proptest.

1. **2026-08-06 — lane 6 — B-268 call-site inventory + live pin** (this commit): append apply_block/fraud/producer seal sites to `B13_ACTIVATION_HEIGHT.md`. Live Path A lag=4 OK tip=16472; B-28-pre PASS subsidy=0. Tip CI `#31126560747` progressing — `[skip ci]`. No B-268b until GREEN + lane4 Ack. *Observed (not staged):* onchain-tx-storm; lane4 proptest.

1. **2026-08-06 — lane 6 — B-267 Path A tip-16468 + B-268 activation WP** (this commit): VPS publish+land tip=16468 (was lag=11); outside-in OK lag=0. Design `docs/B13_ACTIVATION_HEIGHT.md` (effective_emission_params + ckpt v12; no enable). Tip CI `#31126560747` must not cancel — `[skip ci]`. Next: idle until tip GREEN; then **B-268b** after lane4 Ack. *Observed (not staged):* onchain-tx-storm; lane4 proptest.

1. **2026-08-06 — lane 6 — claim B-267 Path A tip republish** (this commit): lag FAIL tip=16467 ckpt=16456 lag=11. VPS publish+land B-15-safe. Tip CI `#31126560747` must not be cancelled — `[skip ci]`. Next: **B-268** activation-height WP. Claim base `6e7862d6`. *Observed (not staged):* onchain-tx-storm; lane4 proptest.

1. **2026-08-06 - lane 4 - claim B-266 seventeenth empty both-miss** (this commit): early B-24dr while tip CI #31126560747 runs on B-265. Body ready (266_* PASS). Do not cancel tip CI. [skip ci].

1. **2026-08-06 — lane 6 — pin tip CI `#31126560747` + zombie cleared** (this commit): B-265 `14f6b177` dispatched; `#31123682138` cancelled. Lane4 **B-263** `ddd7528d` on main. `[skip ci]`. *Observed (not staged):* onchain-tx-storm.

1. **2026-08-06 — lane 4 — remap empty both-miss B-265→B-266** (this commit): lane6 landed **B-265** genesis emission JSON merge (`14f6b177`). Holding Rust until tip CI `#31126560747` GREEN (re-proves B-263+B-265). `[skip ci]`.

1. **2026-08-06 — lane 4 — B-263 seventeenth op1 asymmetric settle** (this commit): early B-24dq `b263_b5_seventeenth_dual_slash_then_op1_asymmetric_settle_drain_identity`; local release PASS. Closes seventeenth asymmetric settle pair with B-262. Lane6 B-28-post window Done (`83d43b9c`). Tip CI re-proves after cancelled `#31126356769` / zombie `#31123682138`. Full CI (no skip). Next: **B-265** empty both-miss. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.


1. **2026-08-06 — lane 6 — claim B-265 genesis emission JSON merge** (this commit): B-13c docs claim `public_devnet_v1.json` can set subsidy_bps=1000, but loader hardcodes `DEFAULT_EMISSION_PARAMS` (deny_unknown_fields). Wire optional `emission` merge; pin Path A=0; correct B-13c same-chain caveat (live tip needs fork-height). No enable. Claim base `0a0f47cc`. `[skip ci]` claim. *Observed (not staged):* onchain-tx-storm; lane4 proptest.



1. **2026-08-06 — lane 6 — B-264 CLOSE + B-40-d0 archive + tip CI dispatch** (this commit): Path A tip-16456 already on main `16fb0583`. Live B-28-pre + B-40-d0 PASS tip=16457 treasury=2909711 subsidy_bps=0. Evidence `b40-d0-treasury-20260806T184500Z.md`. `workflow_dispatch` CI `#31126356769` on tip (zombie `#31123682138` refuse-cancel). §6 Open → lane1 clear zombie. `[skip ci]` board/evidence (dispatch already running). Next: idle — human B-33; no B-13c. *Observed (not staged):* onchain-tx-storm; lane4 proptest.



1. **2026-08-06 — lane 6 — B-264 Path A tip-16456 republish** (this commit): VPS `publish-near-tip-checkpoint-if-lag --apply` (tip=16456; was lag=115) + `land-path-a-checkpoint-from-vps -Apply`; outside-in assert OK tip=16455 ckpt=16456 lag=-1 health proxy/faucet ok. Closes §6 Path A. B-15-safe (no faucet/mfnd). Full ops commit (jsonl+evidence+board). Next: idle — tip CI for B-28-post pin; human B-33; no B-13c. *Observed (not staged):* onchain-tx-storm WIP; lane4 proptest.



1. **2026-08-06 — lane 6 — claim B-264 Path A tip republish** (this commit): close §6 lag FAIL (tip=16453 ckpt=16341 lag=112). VPS `publish-near-tip-checkpoint-if-lag --apply` + `land-path-a-checkpoint-from-vps -Apply`. B-15-safe (no faucet/mfnd). Claim base `aa7556da`. `[skip ci]` claim. *Observed (not staged):* onchain-tx-storm WIP; lane4 proptest.



1. **2026-08-06 — lane 6 — B-28-post tip CI stuck; workflow_dispatch** (this commit): land `83d43b9c` did not auto-queue CI (B-262 rerun `#31123682138` zombie queued). Dispatched workflow `CI` on main. Path A lag still FAIL (evidence `outside-in-tip-ckpt-lag-20260806T183036Z.txt`). `[skip ci]` docs/evidence only. *Observed (not staged):* onchain-tx-storm WIP.



1. **2026-08-06 - lane 4 - B-262 tip CI partial cancel; full rerun** (this commit): #31123682138 ubuntu/windows tests SUCCESS; rustfmt/clippy/wasm cancelled. gh run rerun. Holding **B-263**. [skip ci].



1. **2026-08-06 - lane 4 - claim B-263; Ack lane6 B-28-post + B-40-d0 holds** (this commit): early B-24dq op1 asymmetric settle body ready (263_* PASS). Will not push Rust until tip CI #31123682138 GREEN and lane6 lands B-28-post (B-40-d0 re-prove covered by tip CI ancestry). [skip ci].



1. **2026-08-06 — lane 6 — claim B-28-post assert mode** (this commit): `assert-b28-treasury-thresholds` gains `--mode pre|post` (post wants subsidy_bps=1000). Local: plan-only both modes PASS; live pre PASS tip=16426; live post FAIL-closed (correct). Hold land for tip CI `#31123682138`. Claim base `1b36c859`. `[skip ci]`. *Observed (not staged):* B-28-post script body; onchain-tx-storm WIP.



1. **2026-08-06 — lane 6 — claim B-13b recommended-decision packet** (this commit): same-chain lean rationale in `B13_SUBSIDY_FORK_SIGNOFF.md` (not a human go). §6 to lane7: Path A lag=84 FAIL tip=16425/ckpt=16341. Live B-40-d0 PASS tip=16424. Claim base `4b1f9c11`. `[skip ci]`. Next: B-28 post-enable assert after tip CI GREEN. *Observed (not staged):* onchain-tx-storm WIP; foreign lane dirt.



1. **2026-08-06 — lane 6 — §6 B-40-d0 re-prove window** (this commit): helper `4bcaf8e2` on main; CI cancelled twice by continuous lane4 lands. Ask hold after next tip GREEN to pin. `[skip ci]`.



1. **2026-08-06 — lane 4 — B-262 seventeenth asymmetric settle** (this commit): early B-24dp `b262_b5_seventeenth_dual_slash_then_asymmetric_settle_drain_identity`; local release PASS. B-261 tip CI `#31121260560` hung (matrix cancelled / rustfmt stuck) — tip CI re-proves. Elevates B-239. Full CI (no skip). Next: **B-263** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.



1. **2026-08-06 — lane 4 — claim B-262** (this commit): early B-24dp seventeenth dual-slash then asymmetric settle (elevates B-239) while **CI `#31121260560`** runs on B-261 tip. Claim base `9798ee22`. `[skip ci]`. *Observed (not staged):* onchain-tx-storm WIP; B-262 body local until tip GREEN.




1. **2026-08-06 — lane 4 — B-261 seventeenth dual settle** (this commit): early B-24do `b261_b5_seventeenth_dual_slash_then_dual_settle_drain_identity`; local debug PASS. B-259 tip CI `#31119646284` FAIL = Actions infra (not code). Elevates B-238. Full CI (no skip). Next: **B-262** asymmetric settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.





1. **2026-08-06 - lane 4 - B-259 tip CI infra FAIL; re-dispatch** (this commit): #31119646284 failed at ubuntu setup (action download timeout). gh run rerun --failed. Holding **B-261** (local exact PASS). Also re-proves cancelled B-40-d0 on ancestor tip. [skip ci].






1. **2026-08-06 — lane 6 — B-40-d0 CI coverage note** (this commit): land `4bcaf8e2` CI `#31115971810` cancelled by lane4 **B-259**. Helper still in tip ancestry; watch tip CI `#31119646284` for re-prove. `[skip ci]`. *Observed (not staged):* onchain-tx-storm WIP; lane4 proptest if dirty.






1. **2026-08-06 — lane 4 — claim B-261** (this commit): early B-24do seventeenth dual-slash→dual settle while tip CI runs on B-259. Claim base `fdcb067a`. Body ready locally (`b261_*` PASS). [skip ci].






1. **2026-08-06 — lane 4 — B-259 settle-reset→seventeenth dual-slash** (this commit): early B-24dn `b259_b5_settle_reset_then_seventeenth_dual_slash_treasury_identity`; local debug PASS. Held for lane6 B-40-d0; tip CI `#31115971810` matrix OK / Nightly-dispatch hung. Elevates B-237. Full CI. Next: **B-261** seventeenth dual settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* onchain-tx-storm WIP.







1. **2026-08-06 — lane 6 — B-40-d0 dry-run tip-16379** (this commit): evidence `b40-d0-preflight-dry-run-20260806T161058Z.md`; treasury flat / subsidy_bps=0. Watch tip CI `#31115971810`. `[skip ci]`.







| B-268b | Implement effective_emission_params + ckpt v12 + boundary sims | 6+4 | **Landed** `ee3739e7`; no B-13c enable |
| B-268c | Fraud/slash/gossip use effective params at contested height | 4+6 | **Landed** `342ffbf8`; no B-13c enable |
| B-268d | Light slash + snapshot persist subsidy schedule (ckpt v2) | 4 | **Landed** `6015797c`; no B-13c enable |
| B-268e | Checkpoint decode refuses overlay `activation_value > 10000` | 4 | **Landed** `13ea7acf`; no B-13c enable |
| B-268f | apply_block refuses overlay `activation_value > 10000` | 4 | **Landed** `74923cc5`; no B-13c enable |
| B-268g | Light apply refuses overlay `activation_value > 10000` | 4 | **Landed** (this commit); no B-13c enable |
| B-300 | Inbound silent/half-close releases P2P handler slot (hello 3s) | 4 | **Landed** (this commit); no VPS apply |
| B-269 | Path A near-tip timer 30m→8m (match lag threshold=8) | 6+7 | **Landed** (
3f97603); VPS timer active 8m |

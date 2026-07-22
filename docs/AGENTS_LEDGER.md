# Agent Ledger (append-only archive)

This file is the **permanent, append-only history** of the multi-agent build. The **live** coordination surface is exactly one file: [`AGENTS.md`](../AGENTS.md). When the live board's Session log exceeds its cap, the oldest entries are cut from the board and appended here under § Rotated session-log entries. Nothing in this file is ever edited or deleted — only appended.

Contents:

1. **§ Rotated session-log entries** — entries rotated out of the live board (newest rotation first).
2. **§ Snapshot: AGENTS.md master board (retired 2026-07-19)** — the full pre-consolidation master board, including the long "Recently completed" record.
3. **§ Snapshot: docs/AGENTS.md per-lane checklists (retired 2026-07-19)** — the full pre-consolidation per-lane Done/Doing/Next checklists.
4. **§ Snapshot: 3agent.md session history (retired 2026-07-19)** — the full lanes 1–3 session-by-session history.

These snapshots are frozen verbatim. Status words like "Doing" or "this push" inside them refer to the moment each unit was worked, not to anything current. For current state, read [`AGENTS.md`](../AGENTS.md).

---

## Rotated session-log entries

### Rotation 2026-07-21 B-159-land

1. **2026-07-21 — lane 4 — B-152 sixth-offense asymmetric→absentee re-slash** (this commit): early B-24at `b152_b5_sixth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29870158905` GREEN** on B-151. Elevates B-142. Full CI (no skip). Next: **B-153** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-152** (this commit): early B-24at sixth-offense asymmetric→absentee re-slash (elevates B-142) while **CI `#29870158905`** runs on B-151. Claim base `9d20b008`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-151 sixth-slash→empty both-miss** (this commit): early B-24as `b151_b5_sixth_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. **CI `#29867968439` GREEN** on B-150. Closes sixth-offense prove matrix {00,01,10,11}. Full CI (no skip). Next: **B-152** sixth-offense asymmetric→absentee re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.



### Rotation 2026-07-21 B-159-claim

1. **2026-07-21 — lane 4 — claim B-151** (this commit): early B-24as sixth-slash→empty both-miss (closes sixth-offense prove matrix) while **CI `#29867968439`** runs on B-150 tip. Claim base `6a2c779`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.



### Rotation 2026-07-21 B-158-land

1. **2026-07-21 — lane 4 — claim B-151** (this commit): early B-24as sixth empty both-miss while **CI `#29867968439`** runs on B-150. Claim base `6a2c779`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-150 sixth→op1 asymmetric settle** (`6a2c779`): early B-24ar `b150_b5_sixth_dual_slash_then_op1_asymmetric_settle_drain_identity`; local debug PASS. Commit subject mislabeled as rustfmt fix-forward (parallel race with B-149 land). Watch **CI `#29867968439`**. Completes sixth-offense asymmetric settle pair with B-149. Next: **B-151** empty both-miss. Still blocked on 2nd host for live **B-32**.

1. **2026-07-21 — lane 4 — claim B-150** (this commit): early B-24ar sixth-slash→op1 asymmetric settle while **CI `#29867927644`** runs on B-149. Claim base `6a2c779`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — claim B-150** (this commit): early B-24ar sixth dual-slash→op1 asymmetric settle while **CI `#29867927644`** runs on B-149. Claim base `bdf31e5`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-149 sixth dual-slash→asymmetric settle + B-148 rustfmt fix** (this commit): early B-24aq `b149_b5_sixth_dual_slash_then_asymmetric_settle_drain_identity`; local debug PASS. Fix-forward: remove extra blank after B-148 (CI `#29866791874` rustfmt FAIL). Elevates B-130. Full CI (no skip). Next: **B-150** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-149** (this commit): early B-24aq sixth dual-slash→asymmetric settle while **CI `#29866791874`** runs on B-148. Claim base `cc77d1ff`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.



### Rotation 2026-07-21 B-155-land (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 4 — B-148 sixth dual-slash→dual settle** (this commit): early B-24ap `b148_b5_sixth_dual_slash_then_dual_settle_drain_identity`; local debug PASS. **CI `#29864361735` GREEN** on B-147. Elevates B-128. Full CI (no skip). Next: **B-149** sixth-slash→asymmetric settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.


### Rotation 2026-07-21 B-156-claim

1. **2026-07-21 — lane 4 — claim B-148** (this commit): early B-24ap sixth dual-slash→dual settle while **CI `#29864361735`** runs on B-147. Claim base `97dd712`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.



### Rotation 2026-07-21 B-155-land

1. **2026-07-21 — lane 4 — claim B-148** (this commit): early B-24ap sixth-slash→dual settle while **CI `#29864361735`** runs on B-147. Claim base `97dd712`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.




### Rotation 2026-07-21 B-155-claim

1. **2026-07-21 — lane 4 — B-147 settle-reset→sixth dual-slash** (this commit): early B-24ao `b147_b5_settle_reset_then_sixth_dual_slash_treasury_identity`; local debug PASS. **CI `#29862082733` GREEN** on B-143. Elevates B-126. Full CI (no skip). Next: **B-148** sixth-slash→dual settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-147** (this commit): early B-24ao settle-reset→sixth dual-slash while **CI `#29862082733`** runs on B-143. Claim base `2dec0fd`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.



### Rotation 2026-07-21 B-154-land

1. **2026-07-21 — lane 4 — B-143 fifth-offense op1 asymmetric→absentee re-slash** (this commit): early B-24an `b143_b5_fifth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI #29859782849 GREEN** on B-142. Completes fifth-offense re-slash pair. Full CI (no skip). Next: **B-147** settle-reset→sixth dual-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 join-testnet-rehearsal-smoke/.



### Rotation 2026-07-21 B-153-pin (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 3 — B-146 fund-wait plain light-scan** (this commit): post-faucet wait no longer uses hard `--checkpoint-log` (F45 abort → owned=0 timeout). B-15 JOIN had faucet done + txs; manual scan → balance=1e6 owned=2. Evidence `b146-fund-wait-plain-light-scan-20260721.md`. Resume permanence + archive. `[skip ci]` — B-132 CI `#29857236769`.

- 1. **2026-07-21 — lane 3 — B-15 JOIN archive PASS** (this commit): `join-testnet-rehearsal-windows-20260721T191340Z.txt` tip=5322; `assert-join-testnet-rehearsal-evidence` OK; permanence commitment `a2b15268…`. SUMMARY `B15-JOIN-SUMMARY-20260721.md`. Unblocks **B-42**. Built on B-144/B-145/B-146. `[skip ci]` — B-132 CI `#29857236769` may still be in flight. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP; smoke wallets under join-testnet-rehearsal-smoke/.

- 1. **2026-07-21 — lane 1/3 — pin B-15 + CI `#29857236769` GREEN** (this commit): B-15 head `9974828`; B-132 tip CI GREEN on `d025b37`. `[skip ci]`.


### Rotation 2026-07-21 B-153-claim

1. **2026-07-21 — lane 4 — claim B-143** (this commit): early B-24an fifth-offense op1 asymmetric→absentee re-slash (B-142 twin) while **CI `#29859782849`** runs on B-142. Claim base `360481f`. *Observed (not staged):* lane-3 JOIN smoke dir. `[skip ci]`.



### Rotation 2026-07-21 B-152-land

1. **2026-07-21 — lane 4 — claim B-143** (this commit): early B-24an fifth-offense op1 asymmetric→absentee re-slash (B-142 twin) while **CI `#29859782849`** runs on B-142. Claim base `360481f`. *Observed (not staged):* lane-3 JOIN smoke dir. `[skip ci]`.



### Rotation 2026-07-21 B-152-claim

1. **2026-07-21 — lane 4 — B-142 fifth-offense asymmetric→absentee re-slash** (this commit): early B-24am `b142_b5_fifth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29857236769` GREEN** on B-132. Full CI (no skip). Next: **B-143** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 JOIN smoke dir.



### Rotation 2026-07-21 B-151-land

1. **2026-07-21 — lane 3 — B-145 tall-tip bootstrap snapshot timeout** (`9ca1124`): `bootstrap-wallet-from-checkpoint-log` uses python NDJSON fetch with `MFN_BOOTSTRAP_SNAPSHOT_TIMEOUT_SECS` (default 300) — measured ~145s for tip-5290 vs mfn-cli 30s I/O. Evidence `b145-bootstrap-long-timeout-snapshot-20260721.md`. B-15 JOIN re-run next. `[skip ci]` — B-132 CI `#29857236769` in flight.

1. **2026-07-21 — lane 3 — B-144 Windows JOIN python3 resolve** (`cc79bfe`): `lib-python3.sh` (`mfn_require_python3` + `mfn_resolve_release_bin`); wired into bootstrap / light-scan-soft / join-testnet-rehearsal. B-15 blocked on fresh observer sync (corrupt `chain.blocks` quarantine) tip catch-up to ~5306. Evidence `b144-windows-join-python3-resolve-20260721.md`. `[skip ci]` — B-132 CI `#29857236769` in flight.



### Rotation 2026-07-21 B-150-land (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 3 — claim B-15 formal JOIN capture** (this commit): Seat C / 3agent — start local observer sync then `join-testnet-rehearsal` against public faucet+proxy; Path A tip-5290 ready (lag~8). Claim base `92f1f31`. `[skip ci]` — B-132 CI `#29857189652` in flight. Respect §6: no parallel JOIN; faucet idle at claim.

- 1. **2026-07-21 — lane 4 — claim B-142** (this commit): early B-24am fifth-offense asymmetric→absentee re-slash while **CI `#29857189652`** runs on B-132. Claim base `7b5f3ef`. *Observed (not staged):* lane-1/7 tip-ckpt/Path A residual if any. `[skip ci]`.

- 1. **2026-07-21 — lane 4 — claim B-142** (this commit): early B-24am fifth-offense asymmetric→absentee re-slash (elevates B-122; IDs B-133–B-141 taken by other lanes) while **CI `#29857236769`** runs on B-132 tip. Claim base `d025b37`. *Observed (not staged):* lane-1 tip-ckpt lag scripts/evidence. `[skip ci]`.


### Rotation 2026-07-21 B-150-claim

1. **2026-07-21 — lane 4 — B-132 fifth-slash→empty both-miss** (this commit): early B-24al `b132_b5_fifth_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. **CI `#29854607541` GREEN** on B-131. Closes fifth-offense prove matrix {00,01,10,11}. Full CI (no skip). Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-1 tip-ckpt lag WIP.



### Rotation 2026-07-21 B-149-land

1. **2026-07-21 — lane 4 — B-132 fifth-slash→empty both-miss** (`7b5f3ef`): early B-24al `b132_b5_fifth_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. Closes fifth-offense prove matrix {00,01,10,11} with B-128/B-130/B-131. Full CI (no skip) after **CI `#29854607541` GREEN** on B-131. Still blocked on 2nd host for live **B-32**. *Observed:* 3agent cockpit B-141 live.



### Rotation 2026-07-21 B-149-claim

1. **2026-07-21 — lane 2 — B-141 3agent cockpit + §8 repair** (`7e2746b`): Revived `3agent.md` as three-seat Done/Doing/Next cockpit (A=RC/CI, B=Protocol/Privacy, C=Testnet/Onboarding) under AGENTS authority; updated §1 system map + §0 contract note; repaired mangled §8 header (B-140/B-139/B-138 splice). Outside-in tip=5291 ckpt=5290 lag=1. Evidence `b141-3agent-session-cockpit-20260721.md`. B-15-safe. `[skip ci]` — B-131 CI `#29854607541` may still be in flight; `gh` rate-limited at SYNC. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.



### Rotation 2026-07-21 B-148-land

1. **2026-07-21 — lane 7 — B-140 block-log health + §6 B-53/B-56** (this commit): VPS `assert-vps-block-log-health` PASS tip=5291; tip advancing; `invite-load-smoke-rehearsal --plan-only` PASS (live B-42 after B-15). Closed §6 B-53/B-56. Evidence `vps-block-log-health-20260721T181400Z.txt` + `b140-block-log-health-section6-20260721.md`. B-15-safe. `[skip ci]` — B-131 CI `#29854607541` in flight. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.



### Rotation 2026-07-21 B-148-claim (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 7 — B-138 public-testnet health post-B-137** (this commit): VPS `assert-public-testnet-health --apply` OK (timer success, proxy+faucet ok, tip=5290 ckpt=5290 lag=0). Evidence `public-testnet-health-20260721T181000Z.txt` + `b138-public-testnet-health-post-b137-20260721.md`. §6 B-22/B-100 → Ack tip-5290 for lane3 SUMMARY. B-15-safe. `[skip ci]` — B-131 CI `#29854607541` in flight. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.

- 1. **2026-07-21 — lane 7 — B-139 peers-clean + checklist tip-5290** (this commit): VPS `assert-vps-peers-clean` OK; mirrored **B-137** tip-5290 + **B-138** health + **B-29 CLOSED** into `docs/TESTNET_CHECKLIST.md`. Evidence `vps-peers-clean-20260721T181200Z.txt` + `b139-peers-clean-checklist-tip5290-20260721.md`. B-15-safe. `[skip ci]` — B-131 CI `#29854607541` in flight. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.


### Rotation 2026-07-21 B-147-land (from live AGENTS.md §8)

1. **2026-07-21 — lane 7 — B-137 Path A tip-5290 land** (this commit): VPS timer active; `publish-near-tip-checkpoint-if-lag --apply` → tip=5290 entries=48; `land-path-a-checkpoint-from-vps -Apply`; tip-ckpt lag assert OK (tip=5289 ckpt=5290). Closes §6 B-125 tip lag. Evidence `b137-path-a-land-tip5290-20260721.md`. B-15-safe. `[skip ci]` — B-131 CI `#29854607541` in flight. Also repaired mangled §7/§8. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.

1. **2026-07-21 — lane 7 — claim B-137** (this commit): Path A land from VPS (timer active; remote ckpt tip=5269 vs local 4851) while **CI `#29854607541`** runs on B-131. Also repair mangled §7/§8. Claim base `713473b`. `[skip ci]`. B-15-safe (scp jsonl only; no faucet/mfnd). *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.



### Rotation 2026-07-21 B-143-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 1 — claim B-134** (this commit): Path A staleness fields on tip-ckpt lag assert + repair corrupted §8 header while **CI `#29854607541`** runs on B-131. Claim base `1a66566`. `[skip ci]`. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.


### Rotation 2026-07-21 B-142 (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 1 — B-133 outside-in soak refresh tip-5285** (`62357ae`): live soak PASS 5283->5285; evidence `outside-in-invite-soak-20260721T175511Z.txt` + `b133-outside-in-soak-refresh-20260721-tip5285.md`; pins Nightly `#29852343531` + CI `#29852461441`. Tip-ckpt lag FAIL tip=5283 ckpt=4851 lag=432 (`outside-in-tip-ckpt-lag-20260721T175543Z.txt`). §6 lag refresh to lane7. B-15-safe. `[skip ci]` — B-131 CI `#29854607541` in flight. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.
- 1. **2026-07-21 — lane 1 — claim B-133** (`63b62c9`): outside-in soak refresh + tip-lag §6 refresh while **CI `#29854607541`** runs on B-131. Claim base `878c919`. `[skip ci]`. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.
- 1. **2026-07-21 — lane 4 — claim B-132** (this commit): early B-24al fifth-slash→empty both-miss (closes fifth-offense prove matrix) while **CI `#29854607541`** runs on B-131. Claim base `40d0222`. *Observed (not staged):* lane-1 B-129 tip-ckpt lag scripts/evidence. `[skip ci]`.


### Rotation 2026-07-21 B-142-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-131 fifth-slash→op1 asymmetric settle** (this commit): early B-24ak `b131_b5_fifth_dual_slash_then_op1_asymmetric_settle_drain_identity`; local debug PASS. **CI `#29852461441` GREEN** on B-130. Completes fifth-offense asymmetric settle pair. Full CI (no skip). Next: **B-132** empty both-miss. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-1 B-129 tip-ckpt lag WIP.
- **2026-07-21 — lane 4 — claim B-131** (this commit): early B-24ak fifth-slash→op1 asymmetric settle (B-130 twin) while **CI `#29852461441`** runs on B-130. Claim base `b0fd1b1`. *Observed (not staged):* lane-1 B-129 tip-ckpt lag scripts/evidence. `[skip ci]`.
- **2026-07-21 — lane 4 — B-130 fifth-slash→asymmetric settle** (this commit): early B-24aj `b130_b5_fifth_dual_slash_then_asymmetric_settle_drain_identity`; local debug PASS. **CI `#29849999987` GREEN** on B-128. Full CI (no skip). Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-1 B-129 tip-ckpt lag scripts/evidence. Next: **B-131** op1 twin.


### Rotation 2026-07-21 B-132 (from live AGENTS.md §8)

- **2026-07-21 — lane 1 — B-129 tip-ckpt lag auto-evidence** (this commit): scripts+evidence land — `--apply`/`-Apply` archives `evidence/outside-in-tip-ckpt-lag-*.txt` (disable `--no-archive`/`-NoArchive`); rehearsal smokes updated. Live FAIL tip=5233 ckpt_max=4851 lag=382. Evidence `outside-in-tip-ckpt-lag-20260721T161508Z.txt` + `b129-tip-ckpt-lag-auto-evidence-20260721.md`. Pins **B-127** via **CI `#29847644779` GREEN**. Board text raced into `b0fd1b1`; scripts land here. B-15-safe. `[skip ci]` so as not to cancel **CI `#29854607541`** on B-131; next full-CI tip proves scripts. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.
- **2026-07-21 — lane 4 — claim B-130** (this commit): early B-24aj fifth-slash→asymmetric settle (skip B-129 lane1) while **CI `#29849999987`** runs on B-128. Claim base `1909584`. *Observed (not staged):* lane-1 B-129 tip-ckpt lag scripts/evidence. `[skip ci]`.


### Rotation 2026-07-21 B-132-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — claim B-124** (this commit): early B-24ag fourth-offense op1 asymmetric→absentee re-slash (B-122 twin; skip B-123 — lane1 soak id) while **CI `#29842437172`** runs on B-122. Claim base `2a98633`. Note: B-122 commit also carried lane1 B-123 soak.sh pin-harden WIP (unintended staging). `[skip ci]`.


### Rotation 2026-07-21 B-131 (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 4 — B-122 fourth-offense asymmetric→absentee re-slash** (this commit): early B-24af `b122_b5_fourth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29839631308` GREEN** on B-121. Full CI (no skip). Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-1 soak WIP. Next id **B-124** (B-123 taken by lane1).


### Rotation 2026-07-21 B-131-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 1 — board SYNC B-123/B-122 race** (this commit): **B-123** soak.sh single-id pin harden rode into tip 2a98633 under a B-122 subject (shared-tree race). Code on main; watching CI #29842437172. Docs correction [skip ci].
- **2026-07-21 — lane 1 — B-123 soak.sh single-id pin harden** (2a98633 body): bash rejects non-numeric nnightly_run/ci_run (Win Get-MfnGreenRunId parity); smoke needles for B-123 + assert space-safe pin anchors. Subject line wrongly says B-122.


### Rotation 2026-07-21 B-130 (from live AGENTS.md §8)

- **2026-07-21 — lane 1 — claim B-123** (this commit): soak.sh single-id pin harden (bash parity with Win Get-MfnGreenRunId) while **CI #29839631308** runs on B-121. Claim base b0371b0. [skip ci]. *Observed (not staged):* lane-4 pply_block_proptest.rs WIP.


### Rotation 2026-07-21 B-130-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — claim B-122** (this commit): early B-24af fourth-offense asymmetric→absentee re-slash while **CI `#29839631308`** runs on B-121. Claim base `a0443ba`. *Observed (not staged):* lane-1 outside-in soak scripts/evidence. `[skip ci]`.
- **2026-07-21 — lane 4 — B-121 fourth-slash→empty both-miss** (this commit): early B-24ae `b121_b5_fourth_dual_slash_then_empty_both_miss_*`; closes fourth-offense matrix {00,01,10,11}. Local debug PASS. **CI `#29839404798` GREEN** on prior tip. Full CI (no skip). Still blocked on 2nd host for live **B-32**.


### Rotation 2026-07-21 B-128 (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — claim B-121** (this commit): early B-24ae fourth-slash→empty both-miss while **CI #29839404798** runs on tip. Claim base c55c097. Local debug PASS ready. *Observed (not staged):* lane-1 soak scripts/evidence. [skip ci].
- **2026-07-21 — lane 4 — B-120 fourth-slash→op1 asymmetric** (ea70e2a): early B-24ad b120_b5_fourth_dual_slash_then_op1_asymmetric_settle_* landed under mislabeled B-119 subject; local debug PASS. Board correction. Full CI #29839404798. Still blocked on 2nd host for live **B-32**. [skip ci].


### Rotation 2026-07-21 B-128-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-119 fourth-slash→asymmetric settle** (this commit): early B-24ac `b119_b5_fourth_dual_slash_then_asymmetric_settle_*`; local debug PASS. **CI `#29836555770` GREEN** on prior tip. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-120** (this commit): early B-24ad fourth-slash→op1 asymmetric settle (B-119 twin) while **CI `#29839142227`** runs on B-119. Claim base `bf3e776`. *Observed (not staged):* lane-1 outside-in soak scripts/evidence. `[skip ci]`.


### Rotation 2026-07-21 B-126 (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 4 — B-119 fourth-slash→asymmetric settle** (this commit): early B-24ac `b119_b5_fourth_dual_slash_then_asymmetric_settle_drain_identity`; local debug PASS. **CI `#29836555770` GREEN** on B-118. Full CI (no skip). Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-1 outside-in soak scripts/evidence.
- 1. **2026-07-21 — lane 4 — claim B-119** (this commit): early B-24ac fourth-slash→asymmetric settle while **CI `#29836555770`** runs on B-118. Claim base `5b99063`. *Observed (not staged):* lane-1 outside-in soak scripts/evidence. `[skip ci]`.
- 1. **2026-07-21 — lane 4 — claim B-119** (this commit): early B-24ac fourth-slash→asymmetric settle while **CI #29836555770** runs on tip. Claim base 5b99063. Local debug PASS staged. *Observed (not staged):* lane-1 soak scripts/evidence. [skip ci].
- 1. **2026-07-21 — lane 4 — B-118 fourth-slash→dual settle** (48cfbb3): early B-24ab b118_b5_fourth_dual_slash_then_dual_settle_* landed under mislabeled B-117 subject; local debug PASS. Board correction. Full CI #29836555770. Still blocked on 2nd host for live **B-32**. [skip ci].
- 1. **2026-07-21 — lane 4 — claim B-118** (this commit): early B-24ab fourth-slash→dual settle while **CI `#29835953151`** runs on B-117. Claim base `7d51632`. *Observed (not staged):* lane-1 outside-in soak scripts/evidence. `[skip ci]`.


### Rotation 2026-07-21 B-124 (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 4 — B-117 settle-reset→fourth dual-slash** (this commit): early B-24aa `b117_b5_settle_reset_then_fourth_dual_slash_treasury_identity`; local debug PASS. **CI `#29833394102` GREEN** on B-116. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- 1. **2026-07-21 — lane 1 — claim B-27 soak refresh** (this commit): outside-in invite soak at live tip~5145 while **CI #29833394102** runs on B-116. Claim base f943802. B-15-safe (public proxy only). [skip ci]. *Observed (not staged):* lane-4 pply_block_proptest.rs WIP.
- 1. **2026-07-21 — lane 4 — claim B-117** (this commit): early B-24aa settle-reset→fourth dual-slash while **CI `#29833394102`** runs on B-116. Claim base `cd856d3`. `[skip ci]`.


### Rotation 2026-07-21 B-124-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-116 second-offense op1 asymmetric→absentee re-slash** (this commit): early B-24z `b116_b5_second_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29831106571` GREEN** on B-115. Completes second-offense asymmetric re-slash pair. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-116** (this commit): early B-24z second-offense op1 asymmetric→absentee re-slash (B-115 twin) while **CI `#29831106571`** runs on B-115. Claim base `ba47f6c`. `[skip ci]`.


### Rotation 2026-07-21 B-122 (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-115 second-offense asymmetric→absentee re-slash** (this commit): early B-24y `b115_b5_second_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29829071765` GREEN** on B-114. Fills second-offense B-101 gap. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-115** (this commit): early B-24y second-offense asymmetric→absentee re-slash while **CI `#29829071765`** runs on B-114. Claim base `e8300b9`. `[skip ci]`.
- **2026-07-21 — lane 4 — B-114 third-offense op1 asymmetric→absentee re-slash** (this commit): early B-24x `b114_b5_third_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29826982613` GREEN** on B-113. Completes third-offense asymmetric re-slash pair. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-114** (this commit): early B-24x third-offense op1 asymmetric→absentee re-slash while **CI `#29826982613`** runs on B-113. Claim base `9ae9618`. `[skip ci]`.


### Rotation 2026-07-21 B-122-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-113 third-offense asymmetric→absentee re-slash** (this commit): early B-24w `b113_b5_third_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29824883480` GREEN** on B-112. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-113** (this commit): early B-24w third-offense asymmetric→absentee re-slash while **CI `#29824883480`** runs on B-112. Claim base `2adf089`. `[skip ci]`.
- **2026-07-21 — lane 4 — B-112 third-slash→empty both-miss** (this commit): early B-24v `b112_b5_third_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. **CI `#29822696096` GREEN** on B-111. Closes third-offense prove matrix {00,01,10,11}. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-112** (this commit): early B-24v third-slash→empty both-miss while **CI `#29822696096`** runs on B-111. Claim base `c705c77`. `[skip ci]`.
- **2026-07-21 — lane 4 — B-111 third-slash→op1 asymmetric settle** (this commit): early B-24u `b111_b5_third_dual_slash_then_op1_asymmetric_settle_drain_identity`; local debug PASS. **CI `#29820501612` GREEN** on B-110. Completes third-offense asymmetric settle pair. Full CI (no skip). Still blocked on 2nd host for live **B-32**.


### Rotation 2026-07-21 B-120-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — claim B-111** (this commit): early B-24u third-slash→op1 asymmetric while **CI `#29820501612`** runs on B-110. Claim base `be3e80a`. `[skip ci]`.


### Rotation 2026-07-21 B-119 (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 4 — B-110 third-slash→asymmetric settle** (this commit): early B-24t `b110_b5_third_dual_slash_then_asymmetric_settle_drain_identity`; local debug PASS. **CI `#29818297963` GREEN** on B-109. Full CI (no skip). Next: **B-111** op1 twin. Still blocked on 2nd host for live **B-32**.


### Rotation 2026-07-21 B-119-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — claim B-110** (this commit): early B-24t third-slash→asymmetric settle while **CI `#29818297963`** runs on B-109. Claim base `f93b02d`. `[skip ci]`.
- **2026-07-21 — lane 4 — B-109 third-slash→dual-settle** (this commit): early B-24s `b109_b5_third_dual_slash_then_dual_settle_drain_identity`; local debug PASS. **CI `#29815977566` GREEN** on B-108. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-109** (this commit): early B-24s third-slash→dual-settle while **CI `#29815977566`** runs on B-108. Claim base `1572fcb`. `[skip ci]`.


### Rotation 2026-07-21 B-118-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-108 settle-reset→third dual-slash** (this commit): early B-24r `b108_b5_settle_reset_then_third_dual_slash_treasury_identity`; local debug PASS (requires post-settle proof-window advance). **CI `#29814109581` GREEN** on B-107. Full CI (no skip). Still blocked on 2nd host for live **B-32**.


### Rotation 2026-07-21 B-117 (from live AGENTS.md §8)

- 1. **2026-07-21 — lane 4 — claim B-108** (this commit): early B-24r settle-reset→third dual-slash while **CI `#29814109581`** runs on B-107. Claim base `fca2a26`. `[skip ci]`.
- 1. **2026-07-21 — lane 4 — B-107 second-slash→empty both-miss** (this commit): early B-24q `b107_b5_second_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. **CI `#29812027706` GREEN** on B-106. Closes second-offense prove matrix {00,01,10,11}. Full CI (no skip). Still blocked on 2nd host for live **B-32**.


### Rotation 2026-07-21 B-117-claim (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — claim B-107** (this commit): early B-24q second-slash→empty both-miss while **CI `#29812027706`** runs on B-106. Claim base `d27601b`. `[skip ci]`.


### Rotation 2026-07-21 B-116 (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-106 second-slash→op1 asymmetric settle** (this commit): early B-24p `b106_b5_second_dual_slash_then_op1_asymmetric_settle_drain_identity`; local debug PASS. **CI `#29810031256` GREEN** on B-105. Full CI (no skip). Next: **B-107** empty both-miss. Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-106** (this commit): early B-24p second-slash→op1 asymmetric settle while **CI `#29810031256`** runs on B-105. Claim base `357b395`. `[skip ci]`.


### Rotation 2026-07-21 B-115 (from live AGENTS.md §8)

- **2026-07-21 — lane 4 — B-105 second-slash→asymmetric settle** (this commit): early B-24o `b105_b5_second_dual_slash_then_asymmetric_settle_drain_identity`; local debug PASS. **CI `#29808184228` GREEN** on B-104. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-105** (this commit): early B-24o second-slash→asymmetric settle while **CI `#29808184228`** runs on B-104. Claim base `2cc5e6e`. `[skip ci]`.
- **2026-07-21 — lane 4 — B-104 second-slash→dual-settle** (this commit): early B-24n `b104_b5_second_dual_slash_then_dual_settle_drain_identity`; local debug PASS. **CI `#29806532117` GREEN** on B-103. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — claim B-104** (this commit): early B-24n second dual-slash→dual-settle while **CI `#29806532117`** runs on B-103. Claim base `ee760b1`. `[skip ci]`.
- **2026-07-21 — lane 4 — B-103 repeated dual-slash 2nd offense** (this commit): early B-24m `b103_b5_repeated_dual_slash_second_offense_treasury_identity`; local debug PASS. **CI `#29804886156` GREEN** on B-102. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — B-102 op1 asymmetric→absentee re-slash** (this commit): early B-24l `b102_b5_slash_funded_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local debug test PASS. **CI `#29803426580` GREEN** on B-101. Full CI (no skip). Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — B-101 asymmetric→absentee re-slash** (this commit): early B-24k `b101_b5_slash_funded_asymmetric_then_absentee_reslash_while_peer_settles`; local debug test PASS. **CI `#29801574290` GREEN** on prior tip. Full CI (no skip). *Observed (not staged):* lane-5 bootstrap WIP. Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — board SYNC B-99/B-96 race** (this commit): **B-99** code is `55c3a28`; tip `7ee3f66` also carried lane-1 **B-96** soak under a mislabeled B-99 subject (shared-tree race). Docs correction `[skip ci]`.
- **2026-07-21 — lane 1 — B-96 soak pin-assert** (`7ee3f66` body): assert requires `# nightly_run=`/`# ci_run=`; soak fail-closed without pins; live soak PASS tip 4820->4822; evidence `b96-outside-in-invite-soak-pin-assert-20260721.md`. Subject line wrongly says B-99.
- **2026-07-21 — lane 4 — B-99 slash→empty both-miss** (`55c3a28`): early B-24j `b99_b5_slash_funded_treasury_then_empty_both_miss_*`; closes post-slash prove matrix. Prior **CI `#29800034125` GREEN** on B-100. Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 5 — B-50 follow-up claim** (`726ee78`): claim Rust auto-bootstrap for `light-scan --checkpoint-log` from log max tip. `[skip ci]`.
- **2026-07-21 — lane 7 — B-100 Path A tip-4851** (this commit): force-publish+land after health FAIL lag=18; ckpt **4833→4851** (entries=33); lag 0; `assert-public-testnet-health` + peers-clean OK. B-15-safe. Evidence `b100-path-a-tip4851-20260721.md`. **CI `#29798634416` GREEN** on B-97. Full CI (no skip). *Observed (not staged):* lane-1 B-96 soak WIP, lane-4 B-99/`apply_block_proposals.rs`, JOIN temps.
- **2026-07-21 — lane 7 — B-97 Path A tip-4833** (this commit): published+landed exact-tip ckpt **4679→4833** (entries=32); lag 130→0; `assert-public-testnet-health` + peers-clean OK; added Windows `land-path-a-checkpoint-from-vps.ps1`. B-15-safe (no faucet/mfnd restart). Evidence `b97-path-a-tip4833-20260721.md`. Prior **CI #29797153366 GREEN** on B-98. Full CI (no skip). *Observed (not staged):* lane-1 B-96 soak WIP, JOIN temps.
- **2026-07-21 — lane 4 — B-98 slash→op1 asymmetric settle** (this commit): early B-24i `b98_b5_slash_funded_treasury_then_op1_asymmetric_settle_*`; local release test PASS. Prior **CI `#29795731587` GREEN** on B-95. Id avoids lane-1 **B-96** + lane-7 **B-97**. Full CI (no skip). *Observed (not staged):* lane-1 soak pin-assert WIP, lane-7 Path A / ckpt WIP, JOIN temps. Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 3 — B-15 wave58**: **zion** faucet-F101b permanence **last_proven=4823** (commit `54887d55`); F45 lag=130; claims 32→33. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-21 — lane 4 — B-95 slash→asymmetric settle** (this commit): early B-24h `b95_b5_slash_funded_treasury_then_asymmetric_settle_*`; local debug + `cargo fmt` PASS. Prior **CI `#29793832972` GREEN** on B-86. Full CI (no skip). *Observed (not staged):* JOIN temps. Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 4 — B-95 slash→asymmetric settle** (this commit): early B-24h `b95_b5_slash_funded_treasury_then_asymmetric_settle_*`; local debug + `cargo fmt` PASS. Prior **CI `#29793832972` GREEN** on B-86. Full CI (no skip). *Observed (not staged):* JOIN temps. Still blocked on 2nd host for live **B-32**.
- **2026-07-21 — lane 2 — B-94 spent-debris prune** (`598a853`): removed spent one-shots; tightened `.gitignore`. `[skip ci]`. *Observed (not staged):* lane-3 JOIN evidence temps.
- **2026-07-21 — lane 3 — B-15 wave57**: **yuki** faucet-F101b permanence **last_proven=4808** (commit `99b7e801`); F101b rounds=1; F45 lag=116; claims 31→32. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-21 — lane 3 — B-15 wave56**: **xavier** faucet permanence **last_proven=4794** (commit `7121030f`); F45 lag=107; claims 30→31. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-21 — lane 3 — B-15 wave55**: **wren** faucet permanence **last_proven=4785** (commit `a88d7bcb`); F45 lag=98 (ckpt 4679 frozen); claims 29→30. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-21 — lane 3 — B-15 wave54**: **viv** faucet-retry permanence **last_proven=4763** (commit `aefcaf80`); shell monitor aborted mid-600s wait but runner completed; claims 28→29; F45 lag open=71. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-21 — lane 4 — B-86 rustfmt fix-forward** (this commit): **CI `#29791944150` RED** rustfmt only; `cargo fmt --all`; re-push full CI. *Observed (not staged):* JOIN temps.
- **2026-07-20 — lane 4 — B-86 slash→treasury→dual-settle** (`9fede5b`): early B-24g `b86_b5_slash_funded_*`; local debug PASS; CI `#29791944150` rustfmt RED → fix-forward. Still blocked on 2nd host for live **B-32**.
- **2026-07-20 — lane 3 — B-15 wave53**: **tess** faucet-retry permanence **last_proven=4749** (commit `e4ae6e05`); F45 lag=58; claims 27→28. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 1 — B-93 post-push CI watch** (this commit): `scripts/post-push-ci-watch.py` (+ wrappers) wraps B-34 stall detect after every push; failure hints `gh-ci-failed`; never cancels healthy `in_progress`. ci-check plan gate + `.cursor/rules/ci-before-push.mdc` + `docs/CI.md`. Local docs-only ci-check OK. Full CI (no skip). *Observed (not staged):* lane-3 JOIN temps, `user-wallet/`, `live-testnet-data*`, lane-4 proptest WIP.
- **2026-07-20 — lane 3 — B-15 wave52**: **sara** faucet permanence **last_proven=4736** (commit `a900c1d5`); clean first-try faucet; F45 lag=50 (ckpt 4679); claims 26→27. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave51**: **rita** permanence **last_proven=4728** (commit `e5dd4c00`); faucet-retry with **F101b** delayed owned=2; peers skipped; claims 25→26. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 1 — B-27 CI GREEN** (`08f8001`): CI `#29784891780` GREEN. Full CI board pin (no skip). *Observed (not staged):* JOIN temps, `user-wallet/`, lane-4 proptest WIP.
- **2026-07-20 — lane 3 — B-15 wave50**: **quinn** faucet-retry permanence **last_proven=4709** (commit `ce817776`); 429→600s→PASS; claims 24→25. Proves JOIN path when donor pool owned=1. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 1 — B-27 soak refresh** (this commit): outside-in invite soak PASS tip 4663->4665; evidence `outside-in-invite-soak-20260720T211608Z.txt` + `b27-outside-in-invite-soak-refresh-20260720.md`; soak auto-pins latest green Nightly/CI via `gh`. Pins Nightly `#29779143837` GREEN (all three) + CI `#29777008854`. B-15-safe. Full CI (no skip). *Observed (not staged):* lane-3 JOIN temps, `user-wallet/`, `live-testnet-data*`, lane-4 proptest WIP.
- **2026-07-20 — lane 3 — B-15 wave49**: **paula** faucet permanence **last_proven=4694** (commit `c054d610`); Path A ckpt=4679; claims 23→24. Donor census all owned=1 → faucet-wait policy. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave48 FUND FAIL**: **owen** unfunded (faucet 429; nora single-send→owen owned=1; kate F106 owned=1). Reinforces wait-for-faucet over peer dual-fund from fresh permanence wallets. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-92 Path A tip-4679** (this commit): lag=17 fire → tip-**4679** (entries=26); **CI `#29779275119` GREEN** on B-91. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proposals.rs`, JOIN temps, `user-wallet/`, `live-testnet-data*`, lane-1 soak WIP.
- **2026-07-20 — lane 3 — B-15 wave47**: **nora** faucet permanence **last_proven=4677** (commit `53bab1a0`); cooldown wait after wave46 fund fail; claims 22→23. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave46 FUND FAIL**: **liam** unfunded for upload (faucet 429; kate single-send→owned=1; iris F106 owned=1). Path A ckpt_max=4662 **lag=0** but hard scan still TIMEOUT. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 1 — B-34 CI GREEN** (c752992): CI #29777008854 GREEN (closes incomplete B-90 wire). Docs board sync [skip ci] while B-91 CI runs. *Observed (not staged):* JOIN temps, user-wallet/, live-testnet-data*, lane-4 proptest WIP.
- **2026-07-20 — lane 7 — B-91 health assert + tip-4662** (`13cdb01`): `assert-public-testnet-health` + ci-check gate; tip-**4662** (lag=21, entries=25); re-proves B-90 after CI `#29776397760` cancelled by B-34. Prior **CI `#29777008854` GREEN** on B-34. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proptest.rs`, JOIN temps, `user-wallet/`, `live-testnet-data*`.
- **2026-07-20 — lane 3 — B-15 wave45**: **kate** faucet permanence **last_proven=4661** (commit `8b491ece`) on fresh observer after wave44 wipe; claims 21→22. Wipe restores permanence (again). Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave44 FAIL**: **jade** Fresh stayed `local_only` (commit `985a944f`); sticky mempool=1; no proxy_has; claims stayed 21. Breaking 7-PASS streak. Quarantine wipe before wave45 (F108). Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 1 — B-34 watch-ci-stall** (`c752992`): CI `#29777008854` GREEN; cancelled B-90 matrix `#29776397760`.
- **2026-07-20 — lane 7 — B-90 proxy tip-align + tip-4641** (`89a047b`): F105 tip-align; tip-**4641**; CI cancelled by B-34 (code retained).
- **2026-07-20 — lane 3 — B-15 wave43**: **iris** faucet permanence **last_proven=4636** (commit `39bffdd5`); Path A ckpt_max=4624 (F45 lag=5); claims 20→21; no wipe. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave42**: **hank** peer-dual-donor permanence **last_proven=4628** (commit `69b678f3`); faucet 429→gina+frank; F45 lag grew to 15 as tip > ckpt 4606; claims 19→20. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-89 timer assert + tip-4624** (`a0458bf`): tip-**4624**; **CI `#29773999207` GREEN**. Full CI (no skip).
- **2026-07-20 — lane 3 — B-15 wave41**: **gina** faucet permanence **last_proven=4620** (commit `8aeb43ec`); Path A ckpt_max=4606 (F45 lag=7); F100/F105 recur; claims 18→19; no wipe. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave40**: **frank** peer-dual-donor permanence **last_proven=4611** (commit `8f866ea2`); faucet 429→erin+dana; F100/F105 lag during prove; claims 17→18; no wipe. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-88 lag timer + tip-4606** (`3a0efff`): timer install + tip-**4606**; **CI `#29771537059` GREEN**. Full CI (no skip).
- **2026-07-20 — lane 3 — B-15 wave39**: **erin** faucet permanence **last_proven=4602** (commit `8af641cd`); no wipe (mempool clean); claims 16→17. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave38**: **dana** peer-dual permanence **last_proven=4594** (commit `8d15b8e5`); faucet 429; mempool gate; claims 15→16; F45 lag=2. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-87 Path A tip-4584** (`ed3c51e`): tip-**4584**; **CI `#29769164562` GREEN**. Full CI (no skip).
- **2026-07-20 — lane 3 — B-15 wave37**: 3rd wipe; **cora** faucet permanence **last_proven=4585** (commit `e8da3321`); tip_id+mempool=0 gate; **F108** restart≠clear sticky mempool; claims 14→15. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave36**: 2nd wipe OK; **ben** faucet+upload Fresh `d9d6f90e` but **F107** — local mempool stuck=1, proxy_has=false, local_only; claims stayed 14. Next: restart-clear mempool (wave37). Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-85 near-tip lag gate + tip-4567** (`a1ac45c`): lag-republish tooling + tip-**4567**; **CI `#29766146798` GREEN**. Full CI (no skip).
- **2026-07-20 — lane 3 — B-15 wave36 open**: 2nd F104 wipe — quarantined `live-testnet-data-divergent-20260720-124203`; fresh mfnd syncing; proxy-prove gate; ben battery next. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave35b**: amy faucet+upload Fresh `807b5a5a` but **F104 recur** (local_only, proxy_has=false, mempool=1); wave34 zoe still the latest proxy-prove PASS. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-84 Path A tip-4554** (`e45c9ec`): exact-tip **4554** (entries=19); **CI `#29764280042` GREEN**; OPERATORS F95/F106. Full CI (no skip).
- **2026-07-20 — lane 3 — B-15 wave35**: amy fund **FAIL** — faucet 429 (F95); vera/tina owned=1 only (**F106**); ckpt_max advanced to 4532. Recovery wave35b. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 4 — B-83 dual-settle at cap−1 no slash** (this commit): early B-24f `b83_b5_dual_settle_at_cap_minus_one_*`; local debug test PASS. Full CI. *Observed (not staged):* lane-1 B-34 WIP, JOIN/`user-wallet`/`live-testnet-data*`.
- **2026-07-20 — lane 3 — B-15 wave34**: wipe+resync; **zoe** faucet permanence **last_proven=4533** (commit `4ded4c6d`); proxy-prove gate PASS; F105 proxy index lag; claims 13→14; F45 TIMEOUT. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-82 Path A tip-4532** (this commit): waited for **CI `#29758805553` GREEN** (B-81); exact-tip **4532** (entries=18); B-32 second-host arm checklist; peers-clean OK; arm-ready still NOT READY (1 host). No faucet/mfnd restart. Evidence `b82-path-a-tip4532-20260720.md`. Full CI (no skip). *Observed (not staged):* lane-1 B-34 WIP (`watch-ci-stall` in ci-check/ROADMAP), JOIN temps, `user-wallet/`, `live-testnet-data*`.
- **2026-07-20 - lane 1 - B-27 CI watch** (`45e40d6`): CI #29758129931 cancelled by B-81; scripts ubuntu/windows were GREEN. Watching #29758805553 on f924a63. Docs [skip ci].
- **2026-07-20 — lane 3 — B-15 wave34 open**: F104 wipe — quarantined divergent `live-testnet-data` → `…-divergent-20260720-113211`; fresh mfnd tip_id match @4525; proxy-prove gate armed; zoe battery running. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave33b**: yara faucet+upload **Fresh** `0d2b070b` but prove stuck **local_only**; proxy has=false; claims stayed 13 (**F104**). F45 hard-scan TIMEOUT. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
- **2026-07-20 - lane 1 - B-27 outside-in invite soak** (this commit): successor soak for systemd-live invite head via public proxy; tip 4501->4503; evidence outside-in-invite-soak-20260720T155203Z.txt + b27-outside-in-invite-soak-20260720.md; ci-check plan gate. Pins Nightly #29755942849 + CI #29753244727. B-15-safe. *Observed (not staged):* JOIN temps, user-wallet/, live-testnet-data*.
- **2026-07-20 — lane 4 — B-81 full-slash deregister while peer settles** (this commit): early B-24e `b81_b5_full_slash_deregister_*` (code was missing from B-27 board claim — landed here). Local debug test PASS. Full CI. *Observed (not staged):* JOIN/`user-wallet`/`live-testnet-data*`/lane-3 temps.
- **2026-07-20 — lane 3 — B-15 wave33**: yara permanence **FAIL** — F45 lag=1 after B-80 tip-4496; faucet 429; peer xena/uma **available 0** after pin_clean (**F103**); F97 timeouts. Recovery = wave33b. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
- **2026-07-20 - lane 1 - B-29 CLOSED** (this commit): Nightly #29755942849 GREEN — participant + observer + ignored P2P/produce all success on d248ba2 (ancestor **B-75** 9d8bd30; **CI #29753244727 GREEN**). Docs board close [skip ci] while B-80 CI in progress.
- **2026-07-20 — lane 3 — B-15 wave32**: New wallet **xena** faucet permanence **last_proven=4496** (commit `fe091b02`); pin@4400 owned=3 after pin@4443 owned=1 (F101); F45 lag=46; F102 concurrent-runner RPC 10060; claims 12→13. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
- **2026-07-20 — lane 7 — B-80 Path A tip-4496** (this commit): closed F45 lag after waves 30-31 (4443→**4496** exact tip; entries=16); VPS pulled to `d248ba2`; no faucet/mfnd restart. Evidence `b80-path-a-tip4496-20260720.md`. Prior **CI `#29753244727` GREEN** on B-75. Full CI (no skip). *Observed (not staged):* JOIN temps, `user-wallet/`, `live-testnet-data*`.
- **2026-07-20 — lane 3 — B-15 wave31**: New wallet **wendy** peer-dual permanence **last_proven=4487** (commit `a0d915d2`); faucet 429 (F95); pin@4443 owned=1 then pin@4400 owned=2 (F101); F45 lag=37; claims 11→12. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
- **2026-07-20 — lane 3 — B-15 wave30**: New wallet **vera** faucet permanence **last_proven=4479** (commit `b90c135c`); pin@4443; F45 FAIL lag=29 post B-79 tip-4443; claims 10→11; F100 last_proven before tip_id match. Honor §6. *Observed local work (not staged):* wallets, live-testnet-data, other-lane dirty files.
- **2026-07-20 - lane 1 - B-75 production_dial + persistable local P2P** (this commit): sealed-block fanout now includes non-persistable advertise via production_dial_peers; persistable local P2P binds in start-all + produce smokes. Full CI. After GREEN: sole Nightly -> close **B-29**.
- **2026-07-20 - lane 3 - B-15 wave29** (this commit): faucet done; bal timeout @4173/@4262 (**F97**); pin@4400 funded (**F99**); upload bound **last_proven=4466** proxy+claims=10. Evidence wave29.md. *Observed (not staged):* user-wallet/, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 7 — B-79 B-32 arm-ready + tip-4443** (this commit): `assert-b32-arm-ready.sh` + ci-check plan gate; VPS apply NOT READY (1 host) / synthetic 2-host READY; fixed `${2:-{}}` params bug + Path A bootstrap `RPC="${1:-}"` treating `--apply` as RPC; Path A tip-**4443** (entries=15). Evidence `b79-b32-arm-ready-20260720.md`. Full CI (no skip). *Observed (not staged):* lane-1 B-75 WIP (`p2p_fanout`/produce-smokes/`start-all`/`persistable-listen-lib`), JOIN `user-wallet/`, `live-testnet-data*`, wave temps.
- **2026-07-20 - lane 3 - B-15 wave28** (`d93ab7b`/`3c1f24d`): **F45 HARD PASS** at tip 4443 (exact-tip Path A attestation; now committed in B-79); sam retrieve OK; tina faucet ~139s; F96 pin-retry; upload bound **last_proven=4452** proxy+claims=9. Evidence wave28.md.
- **2026-07-20 - lane 3 - B-15 wave27** (this commit): faucet done then balance timeout **F97**; rose->sam #1 PASS / #2 **F98** input-count floor; sam fund_mode=peer; upload bound **last_proven=4430** proxy+claims=8. Evidence wave27.md. *Observed (not staged):* user-wallet/, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 4 — board SYNC B-76 covered GREEN** (this commit): **CI `#29753244727` GREEN** on B-75 head covers B-76 dual-slash. Arm live **B-32**; blocked on **B-79** 2nd host. Full CI.
- **2026-07-20 — lane 4 — B-76 dual-op empty-audit slash** (`dc50737`/`5492a07`): early B-24d `b76_b5_dual_operator_slash_*`. Prior CI cancelled by docs concurrency; validated via `#29753244727`.
- **2026-07-20 - lane 3 - B-15 wave26** (this commit): tip-4400 ckpt verify PASS (entries=13); F45 hard FAIL tip 4404 (pin@4400 insufficient); quinn retrieve OK; rose faucet ~114s; **F96** pin@4173 zero then @4262 funded; upload bound **last_proven=4412** proxy+claims; claims recent=7; F92 headers PASS. Evidence wave26.md. *Observed (not staged):* user-wallet/, live-testnet-data*, other-lane dirty files.
- **2026-07-20 — lane 1 — B-75 production_dial + persistable local P2P** (this commit): B-71 refused GHA `:0` advertise (≥32768) so sealed-block fanout missed voters (observer tip@1; all-produce diverge). Fix: in-memory `production_dial_peers` for seal/proposal dials; `persistable-listen-lib.sh` + `start-all.sh`/`.ps1` + produce-smoke persistable binds; unit test PASS. Full CI (no skip). After GREEN: sole Nightly → close **B-29**. *Observed (not staged):* lane-3/4 temps, `user-wallet/`, `live-testnet-data*`, `_nightly-*`.
- **2026-07-20 — lane 7 — B-78 docs-equivalent CI roll gate** (`faa8683`): `lib-ci-roll-gate.sh`; observed lane-1 B-75 WIP (now landed).
- **2026-07-20 - lane 3 - B-15 wave25** (`03ec40c` / `214454b` board): quinn last_proven=4390; F95. Evidence wave25.md.
- **2026-07-20 — lane 7 — B-77 B-71 mfnd roll + tip-4400 ckpt** (`b1ce264`): tip-**4400**; Evidence `b77-b71-roll-tip4400-20260720.md`.
- **2026-07-20 — lane 1 — Nightly `#29738744950` RED (participant GREEN)**: observer tip-stall → **B-75**. Docs-only `[skip ci]`.
- **2026-07-20 — lane 4 — B-74 B-32 ci-check plan gate** (`62a9c02`): **CI `#29739903305` GREEN**.
- **2026-07-20 — lane 4 — CI `#29736528564` GREEN + B-32 claim** (`7beb4d4`): stack B-67/B-71/B-73 green; arm **B-32** after B-15 + lane-7 mfnd re-roll. §6 request to lane 7. Docs-only `[skip ci]`.
- **2026-07-20 - lane 3 - B-15 wave24** (this commit): soak tip **4364** match; F45 hard FAIL (pin@4323 still needs tip attestation); **F92** headers {from_height,to_height} PASS; oscar retrieve OK; patricia faucet ~99s; pin-retry 4323/4262/4173 -> funded; upload bound **last_proven=4362** proxy+claims; claims recent=5; **F93** early challenge unknown commitment; oscar->patricia 50k Fresh; F90 post-upload change. Evidence wave24.md + wave25-open (F94 headers/tip-ahead). *Observed (not staged):* user-wallet/, live-testnet-data*, probe temps.
- **2026-07-20 - lane 3 - B-15 wave23** (`e3cb07c`): ckpt max **4323** (entries=12); F45 hard FAIL lag~2; nina retrieve OK; nina->oscar peer#1 PASS / peer#2 **F91** RBF; oscar faucet+upload **last_proven=4337**; claims recent=4; **F92** get_block_headers {from_height,to_height}. Evidence wave23.md. *Observed (not staged):* user-wallet/, live-testnet-data*, probe temps.
- **2026-07-20 — lane 7 — B-73 B-71 reconnect smoke fix** (this commit): `mfnd_p2p_reconnects_saved_peers_on_restart` used OS ephemeral `:0` ports (>=32768) which B-71 correctly refuses to persist -> missing `peers.json` on ubuntu CI `#29734331038`. `reserve_loopback_addr` now picks 19000..32767; export `MIN_EPHEMERAL_PEER_PORT`. Local release smoke PASS. Next: mfnd roll after CI GREEN (prebuild already has B-71 binary). *Observed (not staged):* lane-3 wave23 evidence temps, `user-wallet/`, `live-testnet-data*`, `_ci-ubuntu-fail.log`.
- **2026-07-20 — lane 1 — Nightly `#29738744950` for B-29** (this commit): B-72 on tip; CI `#29736528564` GREEN. Sole Nightly — do not re-dispatch. Docs-only `[skip ci]`.
- **2026-07-20 — lane 1 — B-72 support-bundle B-45 wallet** (`f81d654`): Nightly `#29727713979` fund-wallet+permanence PASS; failed challenge without `--wallet`.
- **2026-07-20 - lane 7 - rustfmt + tip-4323** (`3073177`): fmt-fix B-67; Path A tip-**4323**. *Observed:* left support-bundle WIP unstaged.
- **2026-07-20 — lane 4 — board SYNC** (this commit): **B-67** on `f6273cb` (subject mislabeled); **B-71/B-70** on `09ca8c4` (lane-3 wave22 commit carried the peers filter + tip-4307). Watching **CI `#29733127733`**. Docs-only `[skip ci]`.
- **2026-07-20 — lane 4 — B-67** (`f6273cb` body): multi-op slash while peer settles. Prior CI cancelled by docs concurrency.
- **2026-07-20 - lane 7 - B-68 + B-69**: Hetzner mfnd roll after CI `#29725270815` GREEN; tip stall from ephemeral `peers.json` → scrub + restart (tip 4295+); `scrub-vps-peers-json.sh` wired into `vps-roll-mfnd`. CI `#29728151679` RED (windows produce-smoke synced public tip) → `MFN_SKIP_MANIFEST_SEEDS=1` in produce smokes. Evidence `b68-peers-scrub-mfnd-roll-20260720.md`. *Observed:* leave `apply_block_proptest.rs`, `support-bundle.*`, JOIN temps, `user-wallet/`, `live-testnet-data*` unstaged.
- **2026-07-20 — lane 3 — B-15 wave20+21** (this commit): wave20 F87/F88/F79/F85; wave21 wipe+resync tip_id match; mike faucet /faucet + upload bound; **last_proven=4304**; proxy listed; claims for PASS. Findings F88b tip_id lag, F89 faucet path. JOIN SUMMARY draft. Evidence wave20.md + wave21.md + B15-JOIN-SUMMARY-DRAFT-20260720.md. *Observed (not staged):* apply_block_proptest.rs, probe temps, user-wallet/, live-testnet-data*.
- **2026-07-20 - lane 7 - B-68 peers scrub + mfnd roll**: CI `#29725270815` GREEN; `vps-roll-mfnd --skip-build` then tip stall (ephemeral `peers.json`); scrub + restart voters/hub; tip 4295+; tooling `scrub-vps-peers-json.sh`. Evidence `b68-peers-scrub-mfnd-roll-20260720.md`. *Observed:* leave `apply_block_proptest.rs`, JOIN `user-wallet/`, `live-testnet-data*`, lane-3 temps unstaged.
- **2026-07-20 — lane 4 — B-67 claim** (this commit): multi-op B5 slash while peer settles (early B-24c); local test PASS; land after **CI `#29728151679`**. Docs-only `[skip ci]`.
- **2026-07-20 — lane 4 — B-66 which-op prove chain** (`cb8f8f3`): `b66_b5_op1_only_*` + window-spaced mask chain vs settle/miss/coinbase. **CI `#29728151679` in_progress**. Not full B-24. *Observed:* leave JOIN/`user-wallet`/`live-testnet-data*` unstaged.
- **2026-07-20 — lane 1 — CI `#29725270815` GREEN + Nightly `#29727713979`**: B-29 matrix green; Nightly for B-29 close. Docs-only `[skip ci]`.
- **2026-07-20 - lane 3 - B-15 wave19** (`c36561d`): karl last_proven=4270. `[skip ci]`.
- **2026-07-20 — lane 4 — B-66 claim** (`aca2c14`): docs-only while CI ran. `[skip ci]`.
- **2026-07-20 - lane 7 - B-65 cargo env for VPS non-interactive builds** (`938661a`): `lib-cargo-env.sh` for prebuild/roll. `[skip ci]`.
- **2026-07-20 - lane 7 - B-22 tip-4262 Path A checkpoint** (this commit): closed 89-block ckpt lag (4173→4262); entries=11; faucet/mfnd untouched. Hold rebuild-roll for CI `#29725270815`. `[skip ci]`. *Observed:* `apply_block_proptest.rs` WIP, lane-3 evidence temps, `user-wallet/`, `live-testnet-data*`.
- **2026-07-20 — lane 4 — board SYNC B-64+B-29 stack** (this commit): B-64 `13a4880` on main; CI `#29725200427` cancelled by B-29 concurrency. Watching `#29725270815` (clippy GREEN). `[skip ci]`.
- **2026-07-20 - lane 3 - B-15 wave18** (42528d9): judy upload last_proven=4229; F84. Evidence wave18.md. `[skip ci]`.
- **2026-07-20 — lane 1 — B-29 seed-isolation** (`23204cb`): `MFN_SKIP_MANIFEST_SEEDS` + local `start-all`. Completes dangling `mfnd_cli` call from B-64.
- **2026-07-20 — lane 4 — B-64 settle/apply seal filter** (`13a4880`): seal settlement-accepted proofs; `b64_*` parity. **CI `#29720670813` GREEN** (B-63).
- **2026-07-20 — lane 3 — B-15 wave18/17**: tip 4219; ivan JOIN. `[skip ci]`.
- **2026-07-20 — lane 4 — B-64 claim** (`d3f47bf`): docs-only while `#29720670813` ran. `[skip ci]`.
- **2026-07-20 — lane 4 — B-63 early B-24a** (`e4369a9`): coinbase N+1 + 1-of-2 miss. **CI `#29720670813` GREEN**.
- **2026-07-20 — lane 1 — CI `#29718880625` GREEN + Nightly `#29720083660`**: B-60 matrix green on `7ab86ad`; dispatched Nightly for **B-29** close. Docs-only `[skip ci]`.
- **2026-07-20 — lane 3 — B-15 wave16** (`026eaad`): F81/F82; eve last_proven=**4206**. Evidence wave16.md. `[skip ci]`.
- **2026-07-20 — lane 3 — B-15 wave15** (`fe96f41`): heidi JOIN; last_proven=**4200**. Evidence wave15.md. `[skip ci]`.


### Rotation 2026-07-20 B-68 (from live AGENTS.md §8)

- **2026-07-20 — lane 4 — B-63 claim** (`45fa611`): docs-only while `#29718880625` ran. `[skip ci]`.

- **2026-07-20 — lane 3 — B-15 wave14 addendum** (`e9aad18`): grace upload `3e728a8e…` after F78; F79 pin-too-high. Evidence wave14.md addendum. `[skip ci]`.

- **2026-07-20 — lane 3 — B-15 wave14** (`6ead0f0`): frank faucet+upload `90aae951…` last_proven=**4183**; F75–F78. Evidence `live-testnet-probe-20260720-wave14.md`. `[skip ci]`.

- **2026-07-20 — lane 1 — watch CI `#29718880625`**: B-60 on `7ab86ad` in matrix; tip~4190 outside-in. B-59 claim released (superseded by B-60). Docs-only `[skip ci]`. *Observed local work (not staged):* lane-3 wave14 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 — lane 1 — B-60 B3 collision + smoke CI harden** (this commit): `b3_legacy_challenge_rejected_when_enabled` + `b3_rejects_unsalted_proof_when_salted_required` pick non-colliding slots; smoke accepts sealed/proposal log lines under GHA drain races. Targets `#29717107514` RED.

- **2026-07-20 — lane 3 — B-15 wave13** (`3bb6de7`): F74 wipe+resync; F68b `-Apply` PASS; grace→dave 100k; F71 re-pin. Evidence wave13.md. `[skip ci]`.

- **2026-07-20 - lane 7 - B-62 prebuild/roll-ready + B-43 freeze draft** (`c90962b`): `vps-prebuild-mfnd` + `assert-vps-roll-ready`; Path B inventory doc (no ceremony). VPS cargo prebuild running (no restarts). `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 - lane 7 - B-61 API CI gate + RPC wait + tip-4173** (this commit): `vps-roll-mfnd` uses public Actions API when `gh` missing; wait for hub RPC listen after restart; Path A ckpt tip **4173** (entries=10). No rebuild-roll (CI in flight). `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 - lane 7 - B-60.1 gh fail-closed + hub recover** (this commit): missing `gh` now exit 4 (was WARN-continue; caused skip-build roll smoke). Hub replay load ~2-3min after restart — do not thrash. `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 - lane 7 - B-60 roll preflight + JOIN F45 wire** (this commit): `vps-roll-mfnd` refuse on red/in-progress CI or busy faucet; `join-testnet-rehearsal` -> `light-scan-checkpoint-soft`. No mfnd apply (CI `#29717107514` in flight; faucet busy). `[skip ci]`. *Observed:* `block_apply.rs` WIP, lane-3 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 — lane 4 — B-59 claim** (this commit): CI `#29715111633` ubuntu flake was `b3_legacy_challenge_rejected_when_enabled` accepting when legacy chunk index collides with operator-salted (p≈1/num_chunks). Fix picks a diverging slot; local PASS. Docs-only `[skip ci]` while `#29717107514` runs — do not cancel. *Observed:* leave bootstrap/JOIN/checkpoint WIP unstaged; VPS still pre-B-48 (ephemeral quarantine until roll).

- **2026-07-20 — lane 1 — watch CI `#29717107514` (B-51)**: Prior `#29715111633` RED was `public_devnet_hub_reaches_height_one…` tip diverge (not B3 flake on that head). B-51 landed by lane 4 (`e69e603`). Local B3 non-colliding-slot harden staged for after matrix. Docs-only `[skip ci]`.

- **2026-07-20 — lane 1 — B-51 + B3 CI fix-forward** (this commit): Recovered ephemeral-peer quarantine harden (`note_peer_failure` skips non-durable; block/fraud fanout dials durable only). Hardened `b3_legacy_challenge_rejected_when_enabled` to pick non-colliding slot. Targets CI `#29715111633` RED (`public_devnet_hub_reaches_height_one…` tip diverge). Local focused tests green.

- **2026-07-20 - lane 7 - board SYNC** (this commit): B-51 confirmed on main (`e69e603`) after B-59 land; prior SYNC note was stale mid-push. Hold mfnd roll for CI GREEN. `[skip ci]`.

- **2026-07-20 - lane 7 - B-59/F45 soft + B-22 tip-4166** (this commit): `light-scan-checkpoint-soft.sh` soft-pass tip race; Path A ckpt tip **4166** (entries=9). SYNC: B-51 not on origin/main (left lane-4 WIP unstaged). `[skip ci]`. *Observed:* lane-4 `p2p_fanout.rs` / smoke / `block_apply.rs`, lane-3 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 - lane 7 - B-58/F68b Windows bootstrap temp `.py`** (this commit): write snapshot/pin helpers to temp files (wave12 F68b). Tunnel smoke: `snapshot_ok` + pin 4159. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs`, lane-3 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 - lane 7 - B-22 tip-4159 Path A checkpoint** (this commit): `publish-checkpoint-log.sh --apply` tip **4159** (entries=8); public seed anchors; faucet untouched. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), lane-3 temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 - lane 7 - B-57/F68 Windows bootstrap TCP snapshot** (this commit): `bootstrap-wallet-from-checkpoint-log.ps1` uses python TCP JSON-RPC for `get_light_snapshot` (PS5.1 strips quotes on mfn-cli `--params`). UTF-8 rewrite. VPS TCP+proxy smoke tip=4148. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), lane-3 evidence temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 — lane 7 — B-56 tip-first faucet keepalive** (this commit): keepalive polls tip without wallet lock when near tip; full sync only when behind. Cuts EAGAIN vs `get_light_snapshot`. Deploy: restart `faucet-http` when idle. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), lane-3 `bootstrap-wallet-from-checkpoint-log.ps1` / probe temps, `user-wallet/`, `live-testnet-data*`.

- **2026-07-20 — lane 7 — B-55 testnet frontend** (this commit): systemd `testnet-frontend` on `:3000` + UFW; `vps-start-testnet-frontend.sh`; JOIN/OPERATORS links. Never restarts mfnd/faucet. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 temps, `live-testnet-data*`.

- **2026-07-20 — lane 7 — B-22 tip-4148 checkpoint** (this commit): Path A signer appended tip **4148** (lag was 13+); public seed anchors; faucet untouched. Noted CI `#29715111633` ubuntu FAIL for lane 4/1. Evidence `b22-checkpoint-tip4148-20260720.md`. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 temps, `live-testnet-data*`.

- **2026-07-20 — lane 7 — B-54 F67 pin-then-fund** (this commit): JOIN Step 5 + `fund-wallet-http` pin before faucet; rehearsal plan strings; evidence `b54-f67-pin-then-fund-20260720.md`. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 probe temps, `live-testnet-data*`.

- **2026-07-20 — lane 7 — B-53 faucet health + F62 assert** (this commit): `/health` never awaits wallet lock (`wallet_lock_held`); `assert-vps-block-log-health.sh`; VPS tip~4140 `get_block` PASS / `chain.blocks` 6.3MiB (F62 laptop-only). Deploy: restart `faucet-http` when idle. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 probe temps, `live-testnet-data*`.

- **2026-07-20 — lane 7 — B-52 F54/F56** (this commit): proxy per-method heavy timeout (180s) for `get_light_snapshot`/`get_block_headers`; Windows `bootstrap-wallet-from-checkpoint-log.ps1`; JOIN note; evidence `b52-proxy-heavy-timeout-ps1-twin-20260720.md`. Deploy: restart `observer-rpc-proxy` only. `[skip ci]`. *Observed local work (not staged):* lane-4 `p2p_fanout.rs` / `block_apply.rs` (B-51), `user-wallet/`, lane-3 `_write_w10_open.py` / `_wave10-carol-upload.json`, `live-testnet-data/`.

- **2026-07-20 — lane 7 — B-22 tip-4133 checkpoint** (`90c9c5c`): Path A tip **4133**; public seed anchors.

- **2026-07-20 — lane 3 — B-15 wave10 open** (`a550ad4`): tip 4131, ckpt lag 74.

- **2026-07-20 — lane 4 — B-51 claim** (`e236e6a`): ephemeral fanout quarantine.


### Rotation 2026-07-20 (from live `AGENTS.md` §8)

- **2026-07-19 — planning — Phase 1 permanence playbook** (`55c4abc`): **B-25** before Tier 2/Path B. Docs-only `[skip ci]`.
- **2026-07-19 — lane 3 — B-15 checkpoint light-scan** (`02c8df8` / `73abf77`): JOIN/`fund-wallet-http`.

---

1. **2026-07-21 — lane 1 — B-27 soak refresh tip-5148 + Win pin fix** (this commit): live soak PASS 5146->5148; evidence `outside-in-invite-soak-20260721T132129Z.txt` + `b27-outside-in-invite-soak-refresh-20260721-tip5148.md`; pins Nightly `#29833331135` + CI `#29831106571`. Fixed PowerShell `gh --jq` pin mangling via `Get-MfnGreenRunId`/`ConvertFrom-Json`; assert single numeric pin (CRLF-safe). B-15-safe. `[skip ci]` — lane-4 full-CI queue thrash; scripts gate proves on next non-skip matrix. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.

1. **2026-07-21 — lane 4 — B-124 fourth-offense op1 asymmetric→absentee re-slash** (this commit): early B-24ag `b124_b5_fourth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29842437172` GREEN** on B-122. Completes fourth-offense re-slash pair with B-122. Full CI (no skip). Next: **B-126** settle-reset→fifth dual-slash. Still blocked on 2nd host for live **B-32**.

1. **2026-07-21 — lane 1 — B-125 soak refresh tip-5202** (this commit): live soak PASS 5200->5202; evidence `outside-in-invite-soak-20260721T150909Z.txt` + `b125-outside-in-invite-soak-refresh-20260721-tip5202.md`; pins Nightly `#29838974900` + CI `#29839631308`. §6 tip-lag handoff to lane7 (ckpt 4851, lag~351). B-15-safe. `[skip ci]` — B-122 CI in flight; scripts jobs already GREEN (B-123 proved). *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.

1. **2026-07-21 — lane 1 — claim B-125** (this commit): outside-in soak refresh tip~5199 + §6 tip-lag handoff to lane7 (ckpt 4851, lag~348) while **CI `#29842437172`** runs on B-122 (proves B-123). Claim base `a1577f6`. `[skip ci]`. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.

1. **2026-07-21 — lane 4 — claim B-126** (this commit): early B-24ah settle-reset→fifth dual-slash while **CI `#29844848474`** runs on B-124. Claim base `73ab34a`. `[skip ci]`.

1. **2026-07-21 — lane 1 — B-123 CI GREEN** (`2a98633`): CI `#29842437172` GREEN (public-devnet scripts ubuntu/windows + full matrix). Proves soak.sh single-id pin harden + Win Get-MfnGreenRunId path. Board pin only `[skip ci]` — B-124 CI in flight.

1. **2026-07-21 — lane 1 — claim B-127** (this commit): outside-in tip-ckpt lag assert tooling while **CI `#29844848474`** runs on B-124. Claim base `428af13`. `[skip ci]`. *Observed (not staged):* none this claim.

1. **2026-07-21 — lane 4 — claim B-128** (this commit): early B-24ai fifth-slash→dual-settle while **CI `#29847644779`** runs on B-126. Claim base `ba0b69d`. *Observed (not staged):* lane-1 B-127 residual if any. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-126 settle-reset→fifth dual-slash** (this commit): early B-24ah `b126_b5_settle_reset_then_fifth_dual_slash_treasury_identity`; local debug PASS. **CI `#29844848474` GREEN** on B-124. Full CI (no skip). Next: **B-128** fifth-slash dual-settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-1 B-127 tip-ckpt lag scripts/ci-check.

1. **2026-07-21 — lane 1 — B-127 outside-in tip-ckpt lag assert** (this commit): `assert-outside-in-tip-ckpt-lag.{sh,ps1}` + rehearsal smokes; ci-check plan gate. Live probe FAIL tip=5215 ckpt_max=4851 lag=364 (expected until lane7 Path A). Evidence `outside-in-tip-ckpt-lag-20260721T154019Z.txt` + `b127-outside-in-tip-ckpt-lag-assert-20260721.md`. B-15-safe. Full CI (no skip). **CI `#29844848474` GREEN** on B-124 prior. *Observed (not staged):* lane-4 `apply_block_proptest.rs` WIP.

1. **2026-07-21 — lane 4 — claim B-128** (this commit): early B-24ai fifth-slash→dual settle (B-127 is lane1 ops) while **CI `#29847644779`** runs on B-126. Claim base `ba0b69d`. `[skip ci]`.


1. **2026-07-21 — lane 4 — claim B-153** (this commit): early B-24au sixth-offense op1 asymmetric→absentee re-slash (B-152 twin) while **CI `#29872307794`** runs on B-152. Claim base `cd3d37ae`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-152 sixth-offense asymmetric→absentee re-slash** (this commit): early B-24at `b152_b5_sixth_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local release PASS. **CI `#29870158905` GREEN** on B-151. Elevates B-142 to sixth-offense funding. Full CI (no skip). Next: **B-153** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-154** (this commit): early B-24av settle-reset→seventh dual-slash while **CI `#29872307794`** runs on B-152/B-153 tip. Claim base `cd3d37ae`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — pin B-153 land on mislabeled tip** (this commit): early B-24au `b153_b5_sixth_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles` is in `cd3d37ae` (subject says B-152 re-land). Completes sixth-offense re-slash pair with B-152. Watch **CI `#29872307794`**. Next: **B-154** settle-reset→seventh dual-slash. Still blocked on 2nd host for live **B-32**. `[skip ci]`.

1. **2026-07-21 — lane 5 — B-50 follow-up Rust auto-bootstrap** (this commit): `light-scan --checkpoint-log` pins from log max tip via `get_light_snapshot` when wallet lacks a light checkpoint; prints `checkpoint_log_auto_bootstrap tip=…`; unit tests + JOIN/PRIVACY/CHECKPOINT_LOG honesty. Closes §6 7→5. Prior **CI `#29876590150` GREEN** on B-157. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proposals.rs`, lane-3 join-testnet-rehearsal-smoke/.
1. **2026-07-21 — lane 4 — claim B-158** (this commit): early B-24az seventh-slash→empty both-miss while **CI `#29876590150`** runs on B-157. Claim base `8d6e8203`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-157 seventh-slash→op1 asymmetric settle + B-156 rustfmt fix** (this commit): early B-24ay `b157_b5_seventh_dual_slash_then_op1_asymmetric_settle_drain_identity`; local release PASS. Fix-forward: remove extra blanks after B-156 (CI `#29876274630` rustfmt FAIL). Completes seventh-offense asymmetric settle pair. Full CI (no skip). Next: **B-158** seventh empty both-miss. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-157** (this commit): early B-24ay seventh-slash→op1 asymmetric settle while **CI `#29876274630`** runs on B-155/B-156 tip. Claim base `c3ebb5ab`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — pin B-156 land on mislabeled tip** (this commit): early B-24ax seventh→asymmetric settle is in `c3ebb5ab` (subject says B-155). Elevates B-149. Watch **CI `#29876274630`**. Next: **B-157** op1 twin. Still blocked on 2nd host for live **B-32**. `[skip ci]`.

1. **2026-07-21 — lane 4 — claim B-156** (this commit): early B-24ax seventh dual-slash→asymmetric settle while **CI `#29876214263`** runs on B-155. Claim base `7d3ba35d`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-155 seventh dual-slash→dual settle** (this commit): early B-24aw `b155_b5_seventh_dual_slash_then_dual_settle_drain_identity`; local debug PASS. **CI `#29874504154` GREEN** on B-154. Elevates B-148. Full CI (no skip). Next: **B-156** seventh asymmetric. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-155** (this commit): early B-24aw seventh dual-slash→dual settle while **CI `#29874504154`** runs on B-154. Claim base `dd268c1b`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 4 — pin B-153 + CI `#29872307794` GREEN** (this commit): B-153 op1 twin was in B-152 tip `cd3d37ae`; CI GREEN closes sixth-offense re-slash pair. Next: **B-154** settle-reset→seventh dual-slash. Still blocked on 2nd host for live **B-32**. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-154 settle-reset→seventh dual-slash** (this commit): early B-24av `b154_b5_settle_reset_then_seventh_dual_slash_treasury_identity`; local debug PASS. **CI `#29872307794` GREEN** on B-152/B-153. Elevates B-147. Full CI (no skip). Next: **B-155** seventh→dual settle. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — claim B-159** (this commit): early B-24ba seventh asymmetric→absentee re-slash while tip **CI `#29878259419`** runs on B-158/B-50. Claim base `d5dc6f38`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.


1. **2026-07-21 — lane 4 — B-158 seventh→empty both-miss** (this commit): early B-24az `b158_b5_seventh_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. **CI `#29876590150` GREEN** on B-157. Closes seventh-offense prove matrix {00,01,10,11}. Full CI (no skip). Next: **B-159** seventh-offense asymmetric→absentee re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 4 — B-158 seventh-slash→empty both-miss** (this commit): early B-24az `b158_b5_seventh_dual_slash_then_empty_both_miss_no_drain_identity`; local debug PASS. **CI `#29876590150` GREEN** on B-157. Closes seventh-offense prove matrix {00,01,10,11}. Full CI (no skip). Next: **B-159** seventh-offense asymmetric→absentee re-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-5 B-50 WIP + lane-3 `join-testnet-rehearsal-smoke/`.

1. **2026-07-21 — lane 5 — claim B-161** (this commit): heavy `get_light_snapshot` CLI I/O timeout (B-52 client twin; live prove saw ~65s snapshot vs 30s CLI abort). Claim base `65e19cbe`. Pin B-50 Done=`3df22fd3`. Watch tip **CI `#29878259419`**. *Observed (not staged):* lane-4 `apply_block_proposals.rs`, lane-3 join-testnet-rehearsal-smoke/. `[skip ci]`.

1. **2026-07-21 — lane 5 — B-161 heavy CLI snapshot timeout + F45 soft** (this commit): `get_light_snapshot` uses 180s/`MFN_HEAVY_RPC_TIMEOUT_MS`; in-CLI F45 soft-pass after Schnorr log verify; persist pin on mid-scan failure. Live needles `checkpoint_log_auto_bootstrap tip=5463` + `checkpoint_log_f45_soft_pass` (tip~5474). Fix-forward: prior `872f1ee1` was evidence-only after concurrent wipe. **CI `#29878259419` GREEN** on B-158/B-50. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proposals.rs`, lane-3 join-testnet-rehearsal-smoke/.

1. **2026-07-21 — lane 4 — claim B-160** (this commit): early B-24bb seventh-offense op1 asymmetric→absentee re-slash (B-159 twin) while **CI `#29879858576`** runs on B-159. Claim base `7ef832a7`. *Observed (not staged):* lane-5 B-161 evidence; lane-3 JOIN smoke. `[skip ci]`.

1. **2026-07-21 — lane 4 — B-159 seventh-offense asymmetric→absentee re-slash** (this commit): early B-24ba `b159_b5_seventh_offense_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29878259419` GREEN** on B-158. Elevates B-152. Full CI (no skip). Next: **B-160** op1 twin. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-5 B-161 WIP; lane-3 JOIN smoke.

1. **2026-07-21 — lane 4 — B-160 seventh-offense op1 asymmetric→absentee re-slash** (this commit): early B-24bb `b160_b5_seventh_offense_op1_asymmetric_then_absentee_reslash_while_peer_settles`; local debug PASS. **CI `#29879940201` GREEN** on B-161 (B-159 `#29879858576` cancelled by concurrency). Elevates B-153; completes seventh-offense re-slash pair with B-159. Full CI (no skip). Next: **B-162** settle-reset→eighth dual-slash. Still blocked on 2nd host for live **B-32**. *Observed (not staged):* lane-3 JOIN smoke; lane-5 residual if any.

1. **2026-07-21 — lane 4 — claim B-162** (this commit): early B-24bc settle-reset→eighth dual-slash while **CI `#29881759838`** runs on B-160. Claim base `4b0781a1`. *Observed (not staged):* lane-3 smoke. `[skip ci]`.

1. **2026-07-21 — lane 4 — claim B-162** (this commit): early B-24bc settle-reset→eighth dual-slash while **CI `#29881759838`** runs on B-160. Claim base `4b0781a1`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

1. **2026-07-21 — lane 5 — JOIN F45 doc honesty (B-161/B-165)** (this commit): align JOIN_TESTNET F45 paragraph with in-CLI soft-pass + Windows twin + B-165 CI gate. [skip ci] while **CI #29884711182** runs on B-165. *Observed (not staged):* lane-4 pply_block_proposals.rs, lane-3 JOIN smoke.

1. **2026-07-21 — lane 5 — B-165 F45 soft rehearsal CI gate** (this commit): `light-scan-checkpoint-soft-rehearsal-smoke.sh`/`.ps1` + bootstrap smoke needles + ci-check wire. Local plan-only PASS. Live prove tip=5523 auto-bootstrap + F45 soft. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proposals.rs`, lane-3 JOIN smoke.
1. **2026-07-21 — lane 5 — B-164 privacy-doc honesty + Windows F45 soft twin** (this commit): PRIVACY/CHECKPOINT_LOG document B-161 heavy timeout + in-CLI F45 soft; add `light-scan-checkpoint-soft.ps1`; soft.sh notes B-161. Full CI (no skip). *Observed (not staged):* lane-4 `apply_block_proposals.rs`, lane-3 JOIN smoke.

1. **2026-07-21 — lane 5 — claim B-164** (this commit): privacy-doc honesty for B-161 + Windows `light-scan-checkpoint-soft.ps1` twin while tip **CI `#29882509412`** runs on B-161. Claim base `3113229f`. *Observed (not staged):* lane-4 `apply_block_proposals.rs`, lane-3 JOIN smoke. `[skip ci]`.

1. **2026-07-21 — lane 5 — B-161 heavy CLI snapshot timeout + F45 soft** (this commit): get_light_snapshot uses 180s/MFN_HEAVY_RPC_TIMEOUT_MS; in-CLI F45 soft-pass; persist pin on mid-scan failure. Fix-forward after 872f1ee1 evidence-only wipe. Full CI (no skip). *Observed (not staged):* lane-4 pply_block_proposals.rs, lane-3 join-testnet-rehearsal-smoke/.

1. **2026-07-21 — lane 4 — claim B-162** (this commit): early B-24bc settle-reset→eighth dual-slash while **CI `#29881759838`** runs on B-160. Claim base `4b0781a1`. *Observed (not staged):* lane-3 `join-testnet-rehearsal-smoke/`. `[skip ci]`.

## Snapshot: AGENTS.md master board (retired 2026-07-19)

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

```text
Lane N - Done: <completed units + commits>
       Doing: <unit + current step>
       Next:  <follow-up + owner + blockers>
```

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
- **Cross-lane visibility:** when Next depends on another lane, add or update a row in § Cross-lane requests.

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
| **7** | Testnet launch | Internet-facing go-live (`docs/TESTNET_LAUNCH.md`), VPS runbook, `seed_nodes` publication, launch ceremony | Protocol tests (4/6), CI/Nightly fixes (1), evidence tooling (2) |

Add lanes 8+ in [`docs/AGENTS.md`](docs/AGENTS.md) when needed. Split lanes before they exceed ~2 active units.

---

## CI gate (2026-07-14)

**Head:** F5 phase 4b.1 Winterfell (this push). Prior **CI `#29301681465` GREEN** on `946341c`; **Nightly `#29302920403` GREEN**.

## Current board

| Lane | Current unit | Status | Next handoff |
| --- | --- | --- | --- |
| **1** | F5 4b.1 CI/Nightly | **Doing** — this push | Nightly dispatch after GREEN |
| **2** | Release evidence | **Doing** — refresh on 4b.1 head | Human sign-off packet |
| **4** | F5 phase 4b.1 Winterfell | **Done** — this push | Recursive aggregation (4b.2) |
| **6** | F6 telemetry subsidy field | **Done** — `0d1b9ec` | Parameter fork `1000` bps (TL-7 Path B) |
| **7** | Front-matter + JOIN_TESTNET | **Done** — `4b137bc` | TL-9 named watchers; share invite |

---

## Backlog (unassigned -> claim in lane section)

| ID | Item | Suggested lane | Privacy / performance |
| --- | --- | --- | --- |
| B-02 | M5.33 - proptest: mixed CLSAG + storage upload same block treasury identity | 4 | Done - extends M5.5 |
| B-03 | Promote one ignored emission sim with CLSAG fee mix to CI | 6 | Done - M5.34/M5.35 (`45a118b`, `9537c7b`) |
| B-05 | Linux 30s soak evidence | 2 + 6 | **Done** - soak `#29040052424` PASS max_height=48 (`cf99ae5`) |
| B-06 | Nightly #63 green (all three jobs) | 1 | **Done** - run `28792429191` on `85e5870` stack |
| B-07 | God-file splits (`dispatch.rs`, `cli.rs`, `p2p_fanout.rs`) | 1 + 4 | **Done** - M2.5.46 `p2p_fanout`; M2.5.52–53 dispatch + `cli/parse.rs` |
| B-08 | P2P production `unwrap`/`expect` audit (`mfn-net`, `mfn-node`) | 4 | **Done** - M2.5.47–48 + M2.5.55 light-chain test |
| B-09 | ps1/sh dedup generator or shared timeout constants | 2 | **Done** - M2.5.43 `rehearsal-poll-timeouts.*` |
| B-10 | Workspace dep hoist + RUSTSEC-2026-0190 anyhow path | 6 | **Done** - M2.5.56 anyhow 1.0.103; M2.5.45 hoisted deps |
| B-11 | Bind `StorageCommitment.endowment` Pedersen opening to `required_endowment` in consensus (range proof or opening reveal; today only the fee-share gate is enforced) | 4 + 6 | **Done** — phase 1 + proptests + public devnet genesis enable |

---

## Cross-lane requests

| From | To | Request | Status |
| --- | --- | --- | --- |
| 2 | 1 | Green CI on M2.5.43–45 stack before Nightly #62 dispatch | **Done** - CI #636 |
| 3 | 1 | Nightly #63 participant + observer PASS | **Done** - run `28792429191` |
| 4 | 3 | M5.31-M5.33 protocol tests green before next M7.10 UX | **Done** - `d3a4f36` |
| 7 | 1 | Green CI on head before TL-2 release-evidence refresh | **Done** — CI `#28924060054` on `e7d74f7` |
| TESTNET | all | Mirror completed units into `docs/TESTNET_CHECKLIST.md` | Ongoing |

---

## Recently completed

- **CI `#29298069061` GREEN** (`e385390`) - RC core (lane 1): F5 phase 4a validity proof wire + launch-status v8; full matrix pass.
- **F5 phase 4a validity proof wire** (`e385390`) - protocol (lanes 4+7): apply-block replay witness in `mfn-consensus`; P2P tag `0x14`; launch-status v8; validity-proof-rehearsal-smoke plan gate.
- **F5 phase 4 SNARK/STARK research** (`c2d46f3`) - protocol (lane 4): `FRAUD_PROOFS.md` § Phase 4 design — wire/fork gate, STARK-first 4a recommendation, acceptance tests.
- **CI `#29294927626` GREEN** (`105ea22`) - RC core (lane 1): F5 phase 1c stack + genesis header v3 rehearsal smoke.
- **F5 phase 1c integration tests** (`69c0531`) - protocol (lane 4): `invalid_block_slash_zeros_producer_on_coinbase_fraud` + same-height reject.
- **launch-status v7 + F5 phase 1c design** (8b72294) - testnet launch (lane 7) + protocol (lane 4): `software_ready` pin parse + `fraud_proof` block; `InvalidBlockSlashEvidence` spec in `FRAUD_PROOFS.md`.
- **CI `#29284954973` GREEN** (`c9549e3`) - RC core (lane 1): TL-5 software-ready pin board sync.
- **Nightly `#29284893108` GREEN** (`7c7d2ad`) - RC core (lane 1): all three jobs on Nightly board-sync head.
- **Nightly `#29282656932` GREEN** (`fd8bad7`) - RC core (lane 1): all three jobs re-dispatch after F5 closure docs.
- **TL-5 software-ready pin refresh** (this push) - testnet launch (lane 7): `TESTNET_LAUNCH.md` pin `85dad78` (F5+F6 stack); CI `#29278386048` + Nightly `#29280436031` GREEN.
- **CI `#29282756390` GREEN** (`7c7d2ad`) - RC core (lane 1): docs board sync on Nightly `#29280436031` closure.
- **Nightly `#29280436031` GREEN** (`85dad78`) - RC core (lane 1): all three jobs on F5 phase 1b complete stack.
- **F5 phase 1b complete** (`85dad78`) - protocol (lane 4): fraud contest registry + `list_fraud_contests` RPC + mfnd TCP smokes; CI `#29278386048` GREEN; release evidence RC audit **go**.
- **F5 phase 1b fraud contest registry** (`17ac4fc`) - protocol (lane 4): `fraud_contest.rs` + gossip record + RPC `list_fraud_contests`.
- **Nightly `#29267729234` GREEN** (`5a1b221`) - RC core (lane 1): all three jobs on F6 stack.
- **CI `#29268143470` GREEN** (`3043596`) - RC core (lane 1): docs board sync; ancestor CI for `ff4491b` `[skip ci]`.
- **Release evidence `ff4491b`** - RC ops (lane 2): F6 stack closure + RC audit dry-run **go**.
- **F6 phase 2 subsidy tail split** (`bb94c5c`) - permanence (lane 6): `subsidy_to_treasury_bps` + checkpoint v11; treasury credit in `apply_block`.
- **F6 telemetry subsidy field** (`0d1b9ec`) - permanence (lane 6): `treasury-telemetry-watch` exposes `subsidy_to_treasury_bps`; ci-check plan gate.
- **TL-5 VPS provision handoff** (`ed8743f`) - testnet launch (lane 7): `VPS_PROVISION.md` software-ready pin + rehearsal smoke gates.
- **Nightly `#29260743960` GREEN** (`b6b2fdd`) - RC core (lane 1): all three jobs on revert head after `90431fb` checkpoint decode abort.
- **Revert stack CI GREEN** (`b6b2fdd`) - RC ops (lane 2): revert incomplete checkpoint-v11 decode (`90431fb`); CI `#29258397993` GREEN; release evidence `b6b2fdd` RC audit **go**; Nightly `#29260743960` dispatched.
- **Nightly GREEN + TL-5 software-ready pin** - RC core (lane 1) + testnet launch (lane 7): Nightly `#29257619888` GREEN on `ba6fdce`; `TESTNET_LAUNCH.md` software-ready pin; `VPS_PROVISION.md` TL-5 soak handoff.
- **F5 phase 3b + serve fix GREEN** (`5f3947e`, `ba6fdce`) - protocol (lane 4) + RC (lane 1): ring-membership UTXO fraud wire v3 kind=3; `mfnd_fraud_proof_producer_slash_hint` ops log; CI `#29255412319` GREEN; release evidence `ba6fdce` RC audit **go**.
- **F5 fraud-proof phase 3b** (`5f3947e`) - protocol (lane 4): wire v3 `RingMemberUtxo` parent UTXO witness; `fraud_proof_producer_slash_hint`.
- **F5 stack Nightly GREEN** — `#29236857495` on `ffc7b04` + `#29238738502` on `536d2a6`; RC core (lane 1) all three jobs.
- **F5 phase 3 board + CI** (`536d2a6`) - RC ops (lane 2): TESTNET_CHECKLIST phase 3; CI `#29236938900` GREEN; release evidence `536d2a6` RC audit **go**.
- **F5 fraud-proof phase 3** (`ffc7b04`) - protocol (lane 4): wire v3 invalid CLSAG + invalid SPoRA; gossip admission; CI `#29234849464` GREEN; release evidence `ffc7b04` RC audit **go**.
- **macOS RPC oversized-line CI fix** (`9d1710f`) - RC core (lane 1): drain oversized request through newline before JSON-RPC reject; fixes `mfnd_serve_rejects_oversized_rpc_line` on macOS; CI `#29230074495` GREEN; Nightly `#29232188307` GREEN; release evidence `9d1710f` RC audit **go**.
- **Board sync `f3e5236`** - RC ops (lane 2): 3agent F5 phase 1 Done row; release evidence `f3e5236` RC audit **go**.
- **F5 fraud-proof phase 1** (`bd6d4d9`) - protocol (lane 4): P2P tag `0x13` recv/send/fanout; `mfnd_fraud_proof_valid` log; CI `#29221315455` GREEN; slash deferred.
- **F5 fraud-proof UTF-8 smoke fix** (`fa2aab2`) - CI `#29212422570` GREEN; Nightly `#29213250847` GREEN.
- **F5 fraud-proof phase 0** (`0039732`) - body-root fraud verify + tag `0x13`.
- **genesis-header-version-rehearsal-smoke** (`22549d7`) - Path A v1 pin + Path B `header_version:2` doc gate in ci-check.

- **Genesis BLS PoP tooling + TL-9 assert** (`83b82dd`) - testnet launch (lane 7) + protocol (lane 4): `genesis-validator-bls-pop.*` + rehearsal smoke; `launch-go-no-go` uses assert scripts; `vps-execution-checklist` tl5/tl6 assert steps; `docs/interop/VRF_MFBN1.md`.
- **TL-9 checkpoint Schnorr verify** (`d04afed`) - testnet launch (lane 7): `launch-go-no-go` Schnorr-verifies checkpoint log when `seed_nodes >= 3`.
- **vps-internet-soak-evidence-rehearsal-smoke** (`78d236c`) - testnet launch (lane 7): ci-check gate for assert + launch-status fixture.
- **P32 phase 4e** (`b4cab93`) - privacy surface (lane 5): observer template `MFND_PM23_HARD_FAIL=1`.
- **TL-5 soak evidence assert** (`1aff0df`) - testnet launch (lane 7): `assert-vps-internet-soak-evidence.*` + fixture; `launch-status` detects `soak: SUMMARY status=PASS`; ci-check negative gate.
- **P32 phase 4d** (`4a429e4`) - privacy surface (lane 5): `MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1` on operator VPS template; `mfn-storage-operator` aborts on validator seed env; rehearsal smokes gate all role templates.
- **Nightly `#29175519794` GREEN** (`4a429e4`) - RC core (lane 1): all three jobs on P32 4d stack.
- **CI `#29174819450` GREEN** (`4a429e4`) - P32 phase 4d storage-operator PM23 hard-fail; full matrix pass (~28m).
- **launch-status v5** (`cf2c05d`) - testnet launch (lane 7): `execution_checklist` block links `vps-execution-checklist.v2`; ceremony plan adds checkpoint log + invite path.
- **publish-checkpoint-log-rehearsal-smoke + PM23 phase 4b** (`638f260`) - lanes 5+7: TL-8 checkpoint publish plan gate; `mfnd_pm23_warning` + optional `MFND_PM23_HARD_FAIL=1`.
- **vps-preflight + testnet-invite rehearsal smokes** (`9da922a`) - testnet launch (lane 7): plan-only CI gates on VPS preflight docs and TESTNET_INVITE.md packet.
- **Board sync `648676b`** - RC ops (lane 2): CI `#29088674668` GREEN; release evidence refresh on docs-only head.
- **Nightly `#29088007044` GREEN** (`09edd8a`) - RC core (lane 1): all three jobs on board-sync stack.
- **Board sync `09edd8a`** - RC ops (lane 2): CI `#29086333628` GREEN; release evidence refresh on docs-only head.
- **Nightly `#29085709944` GREEN** (`fac313a`) - RC core (lane 1): all three jobs on TL-7/TL-8 + F12 demo board-sync stack.
- **Board sync `fac313a`** - RC ops (lane 2): CI `#29084142605` GREEN; TL-2 gate closed on docs-only head.
- **Release evidence `05e2772`** - RC ops (lane 2): RC audit dry-run **go** on CI `#29082197263` GREEN head.
- **TL-7/TL-8 + F12 demo web phase 5** (`05e2772`) - testnet launch + onboarding (lanes 3+5+7): `publish-seed-nodes-rehearsal-smoke`, `vps-launch-ceremony-rehearsal-smoke`, `demo-web-f12-rehearsal-smoke`; demo/web checkpoint log verify + cross-check UI; CI `#29082197263` GREEN.
- **Nightly `#29081319938` GREEN** (`4688735`) - RC core (lane 1): all three jobs on TL-5/TL-6 VPS rehearsal stack.
- **TL-5/TL-6 VPS rehearsal smokes** (`4688735`) - testnet launch (lane 7): `vps-internet-soak-rehearsal-smoke` + `vps-participant-rehearsal-rehearsal-smoke` plan gates in ci-check + GHA; CI `#29079154415` GREEN.
- **Nightly `#29077379017` GREEN** (`3067bf9`) - RC core (lane 1): all three jobs on launch-go-no-go stack.
- **CI launch-go-no-go bash fix** (`3067bf9`) - RC core (lane 1): capture non-zero exit from `launch-go-no-go.sh` in rehearsal smoke; CI `#29075258454` GREEN.
- **launch-go-no-go-rehearsal-smoke** (`bbc57a1`) - testnet launch (lane 7): plan-only CI gate on pre-launch `launch-go-no-go.v1` JSON + TL-9 command in vps-execution-checklist.
- **F6 Arweave durability comparison** (`bff1b70`) - permanence depth (lane 6): `ECONOMICS.md` §12 permanence durability vs Arweave.
- **F6 tail split approved (docs)** (`9a2673a`) - permanence depth (lane 6): `FEES.md` §5.4 approves 10% subsidy tail → treasury for next parameter fork (implementation deferred).
- **Nightly `#29071784488` GREEN** (`808529a`) - RC core (lane 1): all three jobs on PM23/F6 stack.
- **CI `#29068155204` GREEN** (`808529a`) - RC core (lane 1): PM23/F6/treasury-telemetry rehearsal smokes; full matrix pass.
- **P32 phase 4a / PM23** (`808529a`) - privacy surface (lane 5): `pm23-operator-manifest-rehearsal-smoke` plan gate for operator-manifest separation on role env templates + docs.
- **F6 treasury telemetry watch** (`808529a`) - permanence depth (lane 6): `treasury-telemetry-watch.*` read-only `get_chain_params` helper for FEES.md §5 revisit triggers.
- **launch-status rehearsal smoke** (`808529a`) - testnet launch (lane 7): dedicated `launch-status-rehearsal-smoke.*` wired into ci-check + GHA.
- **F6 fee economics docs** (`d4a5114`) - permanence depth (lane 6): [`FEES.md`](docs/FEES.md) plain-language fee breakdown (90/10 split, upload endowment gate); 2026-07 parameter review (keep current fees; reject tail→treasury split for now); `ECONOMICS.md` §3/§7/§8/§10 sync to shipped operator-direct payout.
- **CI `#29066731152` GREEN** (`6b884ea`) - RC ops (lane 1+2): launch-status v4 GHA gh-token fix; full matrix pass.
- **Release evidence `6b884ea`** - RC ops (lane 2): launch-status v4 stack + RC audit dry-run **go** on CI `#29066731152`.
- **launch-status v4** (`895ac1e`) - testnet launch (lane 7): TL-8 checkpoint log tracking (`entry_count`, `published`, optional `verify`); `launch-go-no-go` requires non-empty log when `seed_nodes >= 3`; ci-check + GHA smoke on `launch-status.v4` schema.
- **P32 phase 2** (`db58ae1`) - privacy surface (lane 5): `vps-role-*.env.example` role-separated VPS templates; OPERATORS.md + `reference-topology-rehearsal-smoke` template gate.
- **F12 phase 4** (`5965525`) - protocol surface (lanes 4+6): `checkpoint-log cross-check` CLI; `publish-checkpoint-log.*` TL-8 operator tooling; live rehearsal smoke.
- **F12 phase 3** (`5d78329`) - protocol surface (lanes 4+6): `mfn-checkpoint-log` shared crate; WASM `checkpointLogVerify` / `checkpointLogCrossCheck` parity with CLI cross-check.
- **F12 phase 2** (`10e606e`) - privacy surface (lanes 4+5): `wallet light-scan --checkpoint-log`; `cross_check_summary_against_checkpoint_log`; rejects log disagreement at same `tip_height`.
- **F12 phase 1** (`50782a3`) - privacy surface (lanes 4+5): `mfn-cli checkpoint-log sign|verify`; [`CHECKPOINT_LOG.md`](docs/CHECKPOINT_LOG.md); plan-only rehearsal in ci-check.
- **B-05 Linux soak refresh** (`cf99ae5`) - RC core (lanes 1+2): soak `#29040052424` PASS max_height=48 on F12/wasm stack (`3b19e7c`); evidence `soak-restart-linux-30s-slot-20260709T185101Z.txt`.
- **P32 reference topology** (`85f3512`) - privacy surface (lanes 4+5): `REFERENCE_TOPOLOGY.md` + plan-only rehearsal in CI; CI `#29040315598` GREEN; Nightly `#29040048884` GREEN; release evidence RC audit **go** (`f6bc358`).
- **F12 checkpoint anchor peers** (`0cf73c6`) - privacy surface (lanes 4+5): `anchor_peers` in trusted summary + `--p2p-anchor-summary`; CI `#29036301962` GREEN after wasm-pack fix (`3b19e7c`).
- **Nightly `#29042017113` GREEN** - RC core (lane 1): all three jobs on P32.1 stack (`85f3512`).
- **P32 reference topology doc** (`85f3512`) - privacy surface (lanes 4+5): [`REFERENCE_TOPOLOGY.md`](docs/REFERENCE_TOPOLOGY.md) + plan-only rehearsal smoke in ci-check.
- **F12 checkpoint anchor peers** (`0cf73c6`) - privacy surface (lanes 4+5): `anchor_peers` in trusted summary + `get_light_snapshot`; `--p2p-anchor-summary` boot merge.
- **P31 diversity redial phase 1** (`571e0bf`) - privacy surface (lanes 4+5): `peer_diversity_redial_candidates` + background sweep; CI `#29028631457` GREEN; release evidence RC audit **go**.
- **Nightly `#29025637498` GREEN** - RC core (lane 1): all three jobs on P32 stack (`f76991a`); auto-dispatched after CI `#29023541155`.
- **Release evidence `f76991a`** - RC ops (lane 2): P32 stack + RC audit dry-run **go** on CI `#29023541155`.
- **P32 role topology lint** (`f76991a`) - privacy surface (lanes 4+5): `mfnd_role_topology_warning` when validator + public RPC (+ operator) share advertised host.
- **P31 peer diversity phase 0** (`d3cc1be`) - privacy surface (lanes 4+5): `mfn-net::peer_diversity` /16 bucket metrics; `get_status.p2p` diversity fields; `mfnd_p2p_diversity_warning`.
- **B8.3 tor-rpc rehearsal smoke** (`1ad2dce`) - onboarding (lane 3): plan-only `tor-rpc-rehearsal-smoke` in CI/ci-check; dispatch jobs `continue-on-error` on runner starvation.
- **B8.3 wallet RPC Tor** (`5e540b3`) - privacy surface (lanes 4+5): `mfn-cli --tor` / `MFN_CLI_RPC_TOR` for onion JSON-RPC; quorum RPC peers mirror Tor mode; [`TOR_P2P.md`](docs/TOR_P2P.md) § B8.3.
- **M4.8 / B1 phase 2e** (`bbe1d9f`) - permanence + privacy (lanes 4+5+6): WASM upload merges live `get_chain_params.endowment`; RPC exposes MFER flags; demo web forwards policy; CI `#28999593529` GREEN.
- **MFER participant rehearsal** (lane 3) — Windows smoke PASS on `bbe1d9f`; evidence `participant-rehearsal-no-observer-windows-20260709T070005Z.txt`.
- **B1 phase 2d** (`2958cfa`) - permanence (lanes 4+6): public devnet `require_endowment_range_proof: 1` (same `genesis_id`); forged-blinding reject test; CI `#28995960877` GREEN.
- **B1 phase 2c** (`ba53a15`) - permanence (lanes 4+6): wallet MFEX v3 `MFER` builder; `build_endowment_surplus_range_proof` in mfn-storage; wallet unit test.
- **B1 phase 2b** (`c084537`) - permanence (lanes 4+6): MFEX v3 + `MFER` surplus range proofs; `apply_block` + mempool verify; M5 accept/reject + treasury proptest.
- **B1 phase 2a** (`76b5f8f`) - permanence (lanes 4+6): inert `require_endowment_range_proof`; checkpoint **v10**; mutual exclusion with MFEO; [`B1_ENDOWMENT_RANGE_PROOF.md`](docs/B1_ENDOWMENT_RANGE_PROOF.md).
- **B5 phase 5c** (`8bdb4ab`) - permanence (lanes 4+6): operator bond slash to treasury when `consecutive_missed_audits >= operator_audit_missed_cap`; zero-bond deregister; clippy fix for 5b CI `#28977215094`; full matrix CI `#28979369780` GREEN.
- **F7 mfnd fanout tail** (`b70b3ec`) - RC core (lane 1): `mfnd_p2p_tx_fanout_reaches_third_hop_peer` expects `applied=2` after two-block F7 fixture; closes Nightly ignored-P2P job on `#28928716414`.
- **F7 fund-wallet tail** (`dc22cb7`) - RC onboarding (lane 3): `fund-wallet` top-up sends until `owned_count >= 2`; closes rehearsal `input count 1` upload rejects on `#28928716414`.
- **TL-3 release evidence** (lane 7) — `release-evidence-46677ad` + RC audit dry-run `go` on CI `#28924060054` (`e7d74f7`); TL-2 gate closed.
- **TL-2 CI GREEN** (`e7d74f7`) — lane 7: mempool F7 two-input pad; CI `#28924060054` full matrix pass (~48m).
- **F7 mfnd_smoke tail** (`0825385`) - RC core (lane 1): `synth_decoy_one_step_signed_transfer_fixture` steps 2 blocks so wallet owns ≥2 UTXOs before two-input transfer; closes CI `#28919128030` mempool/P2P admit failures.
- **F7 settlement test tail** (`996f60f`) - permanence (lane 6): `producer_treasury_settlement.rs` two-input companion pad across genesis + all `sign_self_transfer` call sites; closes CI `#28917267975` failure on `fee_only_block_credits_treasury_ninety_percent`.
- **F7 consensus tail** (`3933cf0`) - protocol (lanes 4+5): `RingPolicy.min_input_count` (`MIN_TX_INPUTS_UNIFORM_TIER = 2`) at `verify_transaction` when uniform-ring tier active; mirrors output floor; conformance + spend tests use two inputs under production policy.
- **B2 ChunkV2** (`20954b0`) - permanence (lanes 4+6): Merkle-path chunk gossip tag `0x12`; `validate_gossip_chunk_v2` + `on_chunk_v2`; fan-out/operator push emit proofs; inbound `ChunkV1` retained for mesh compatibility.
- **Release evidence `96462aa`** - RC ops (lane 2): pre-B2 stack evidence + RC audit dry-run go on CI `28885223488` (`0d28e4f`); refresh after B2 CI green.
- **Nightly #28889931523 GREEN** - RC core (lane 1): all three jobs on B-11/B7 stack (`b1072e3`); auto-dispatched after CI `#28885223488`.
- **CI #28885223488 GREEN** (`0d28e4f`) - B7 dandelion rehearsal evidence commit; full matrix pass.
- **B7 dandelion rehearsal** (this commit) - privacy (lanes 3+5): Windows `dandelion-rehearsal-smoke` PASS with MFEO upload on B-11 genesis; evidence `participant-rehearsal-no-observer-dandelion-windows-20260707T171612Z.txt`; archive filenames tag `-dandelion`.
- **Nightly #28884769330 GREEN** - RC core (lane 1): all three jobs on B-11 stack (`0fee187`).
- **CI #28879533724 GREEN** (`0fee187`) - B-11 public devnet MFEO enable; full matrix pass.
- **B-11 public devnet enable** (`0fee187`) - permanence (lanes 4+6): genesis spec `endowment` section; `require_endowment_opening: 1` in `public_devnet_v1.json` (same `genesis_id`); proptest clippy fix.
- **B-11 proptests** (`9f0a0aa`) - permanence (lane 4): `require_endowment_opening=1` — `prop_mfeo_opening_storage_upload_treasury` + reject without `MFEO`.
- **Release evidence `837069a`** (`0a7e326`) - RC ops (lane 2): `release-evidence-refresh-for-head` + RC audit dry-run go on CI `28871239057`.
- **CI #28871239057 GREEN** (`837069a`) - RC ops (lane 2 gate): full matrix after B-11/B7/B9/F7 stack; ends CI churn from parallel pushes.
- **F7/B15** (`837069a`) - privacy surface (lane 5): canonical two-input wallet floor — `WALLET_MIN_TX_INPUTS` + `select_inputs_for_tx` pad real UTXOs into reference transfers/uploads when a second spendable output exists; same-band preference; single-UTXO wallets unchanged.
- **B-05 Linux soak PASS** (`28851202993` on `8ccda5d`) - RC core (lane 1): 35m / 30s-slot soak — 8 iterations, max_height=48, observer restart; evidence `soak-restart-linux-30s-slot-20260707T083949Z.txt`.
- **M2.5.65 (GHA converge)** (`8ccda5d`) - RC core (lane 1): soak GHA converge soft gate + `MFN_HEALTH_MIN_P2P_SESSIONS=0` when `get_status` reports null sessions; soak `28850304866` passed hub_produced then failed converge.
- **M2.5.65** (`76cc778`) - RC core (lane 1): soak WARMUP health-check — `query_get_status_compat_line` prefers mfn-cli `status` (real `p2p.session_count`) over tip synthesis that returned null sessions.
- **B7 (stem wire label)** (`dc8b53b`) - privacy surface (lane 5): `TxStemV1` P2P tag `0x11` for Dandelion++ stem relays; fluff stays on `TxV1` (`0x06`); recv path accepts both.
- **B7 (rehearsal soak)** (`e2f3f63`) - privacy surface (lane 5): `--dandelion` on `start-all` / `soak` / `participant-rehearsal-smoke` (default off); `dandelion-rehearsal-smoke` + `dandelion-soak` wrappers; mesh asserts `mfnd_dandelion=enabled` when enabled.
- **B9 (phase 2)** (`366dfaf`) - privacy surface (lane 5): tx v2 wire adds 1-byte `view_tag` per output (consensus-bound in preimage); reference wallet/coinbase set tags on send; scanner skips ~256× mismatches before stealth-detect; legacy v1 txs still decode/verify.
- **B9 (phase 1)** (`d0d0bfb`) - privacy surface (lane 5): `indexed_view_tag` / `indexed_view_tag_from_shared` in `mfn-crypto` stealth (F5-P7 prep for wire + scanner).
- **B7 (phase 2)** (this commit) - privacy surface (lane 5): `MFND_DANDELION=1` env + `--dandelion` CLI parse tests.
- **B7 (phase 1)** (`1cc9ead`) - privacy surface (lane 5): Dandelion++ stem/fluff tx relay — `dandelion.rs` + opt-in `mfnd serve --dandelion`.
- **B13 authorship + GHA timing** (`5d5cf64`–`934cc2f`) - privacy surface (lane 5): MFCL claim preview uses padded bucket payload; WASM parity (`7821099`); `GITHUB_ACTIONS` hub-timing budget for three-validator smoke; **CI #28838850432 GREEN**.
- **B13 spora fix** (`96fe808`) - revert auto-pad inside `build_storage_commitment`; bucket padding at wallet/WASM/consensus only.
- **B13 test parity** (`e98ff4f`) - mfn-node chunk/archive tests use canonical bucket payloads.
- **B13 (consensus)** (`3d8574c`) - privacy surface (lane 5): consensus-mandatory upload size buckets — `validate_storage_commitment_shape` rejects NEW anchors whose `size_bytes` is not a canonical power-of-two bucket; CLI persists `UploadArtifacts.anchored_payload`; legacy artifact rebuild pads raw payloads.
- **B13 (wallet)** (`4712811`) - privacy surface (lane 5): upload size buckets — reference uploads pad to next power-of-two before anchoring; on-chain `size_bytes` is the bucket; endowment priced on bucket (`storage_size_bucket` / `pad_to_storage_size_bucket`).
- **M2.5.64** (`c5e69f6` + `c7420a2`) - RC ops (lanes 1+2): Linux soak bootstrap pre-builds `mfnd` + `mfn-cli` (workflow `cargo build` + `soak.sh` → `start-all.sh --no-build`); `start-all` invokes child scripts via `bash` and fails fast when hub PID exits before P2P listen; `mfn-cli` required for `query_tip_height` during `hub_tip_wait`.
- **B3 phase 2** (`7a427fa`) - permanence hardening (lanes 4+6): `apply_block` operator-salted replication accounting; `operator_salted_challenges` flag (default off); checkpoint v5; four `block_apply` tests.
- **B4(c)** (`297df7c`) - privacy surface (lane 5): `select_gamma_decoys` picks uniformly among unchosen decoys at the target height instead of always taking the rightmost binary-search index; co-height selection no longer deterministic.
- **B4(a)** (`b402db3`) - privacy surface (lane 5): `build_decoy_pool` excludes only real input keys; other owned UTXOs remain eligible decoys (B4 / `PRIVACY_HARDENING.md`).
- **F5-PM9** (`eaecece`) - permanence depth (lane 6, docs-only): `docs/PQ_MIGRATION.md` — committed consensus-versioned PQ migration path (retroactive-privacy hybrid first, operator-key hybrid second, research-gated CLSAG successor third) + wire-format headroom audit proving each phase is a soft fork today.
- **F5-P9** (`1c9d578`) - privacy surface (lane 5): canonical-encoding conformance suite closes B3 — pins tx version, empty-`extra` default, uniform ring-16 (== consensus production policy), two-output floor, real `enc_amount` ciphertexts, and byte-canonical wire form for reference transfers + uploads; all frontends covered by construction via the two pinned constructors.
- **F5-PM10** (`b260033`) - permanence depth (lane 6): self-verifying chain+chunk archive — `mfnd archive-export --archive-dir DIR` (canonical block log + Merkle-verified chunk sets + `manifest.json`), `mfnd archive-verify` replays from the genesis spec through the full consensus STF and re-derives chunk Merkle roots offline. Archive reuses `mfn-store` fs formats so it doubles as a cold-start bootstrap.
- **F5:B3** (`d7ee698`) - privacy surface (lane 5): reference wallets shuffle output order with the plan RNG in `spend::build_transfer` — "last output is change" no longer holds for any reference tx; position-distribution test added.
- **F5-PM13** (`df70b9c`) - permanence governance (lanes 4+6): `mfn_consensus::constitution` fork-legitimacy invariants (`tail_emission > 0`, uniform rings >= 16, well-formed endowment pricing) enforced on every operator-supplied genesis spec via `GenesisSpecError::Constitution`.
- **F5-P10** (`3789e39`) - privacy surface (lane 5): structural authorship-key firewall — canonical `derive_claiming_keypair` in `mfn-crypto` (byte-compatible with the wallet-local derivation), closed `ClaimingIdentity` constructor, and signing-time `ClaimKeyReusesWalletKey` rejection when a claim pubkey collides with wallet view/spend keys.
- **F5-P8** (`23c14d6`) - privacy surface (lane 5): `mfn_crypto::lsag` (pre-CLSAG legacy) and unwired `oom` compile only under `cfg(test)` or non-default `lsag`/`oom` features — release binaries accept CLSAG only. `PRIVACY_HARDENING.md` §B5 marked shipped.
- **M5.49 + M7.12** (`890a56c`) - permanence hardening (lane 4): consensus + mempool reject storage commitments with inconsistent geometry (`chunk_size` power-of-two, `num_chunks == ceil(size/chunk)`); chunk-inbox gossip writes authenticated against anchored commitments (unknown-commit reject, index/length gate, single-chunk `data_root` verify, no overwrite of held bytes); chunk fan-out verifies the inbox Merkle root against `data_root` before replicating.
- **M2.5.60** (`49c8fb2`) - `clippy::unwrap_used`/`expect_used` warn gate on non-test `mfn-net` + `mfn-node`; delete one-off repair scripts `fix-m2527-boards.ps1` + `write-agents-boards-utf8.ps1` (lane 4).
- **M2.5.59** (`b1c8e6a`) - fix `powershell -NoProfile -File` invoke for resolve-schema-python; archive dry-run staging; `.gitignore` debris patterns (lane 2).
- **M2.5.58** (`c0e73eb`) - `resolve-schema-python.ps1`; wire release-schema scripts + ci-check (lane 2).
- **M2.5.57** (`3e994b9`) - DOCS-QA-2 audit closure; debris purge; gitignore test logs (lane 2).
- **M2.5.56** (`6fe1b18`) - B-10: pin workspace `anyhow` 1.0.103 (RUSTSEC-2026-0190); lane 6.
- **M2.5.55** (`6fe1b18`) - light-chain `EvolutionFailed` integration test; mempool test cleanup; lane 4.
- **M2.5.53** (`bd76bde`) - B-07: restore `cli/parse.rs`; hoist `mod parse` before `run_cli`; lane 4.
- **M2.5.52** (`2904ea3`) - B-07: extract `mfn-rpc/src/dispatch/rpc_params.rs` + `rpc_method_meta.rs` from `dispatch.rs` (~620 lines); lane 4.
- **M2.5.51** (`0d9646a`) - start-all GHA `hub_tip_wait` uses `MFN_POLL_HUB_MAX` (900s); observer catchup soft gate (lag <= 2); ps1 health_check tip>=1 fast path (lane 1).
- **M2.5.50** (`dbf6067`; code `6216aec`) - mfnd early `mfnd_p2p_listening`; POST_START timeout export; participant smoke ps1 parity (lane 1).
- **M2.5.49** (`8650543`) - GHA soft-continue on mesh health + hub_liveness when hub tip>=1 (lane 1).
- **M2.5.48** (`040d31d`) - on-disk debris purge; light-follow quorum `expect` removal (lane 4).
- **M2.5.46–47** (`2b33ced`; code `1152e16`) - B-07 `p2p_peer_quarantine` + `p2p_reconnect_plan` split from `p2p_fanout`; B-08 mfnd `runner`/`mfnd_cli` expect removal; `mfnd_serve` import fix (lane 4).
- **M2.5.43–45** (`b945f73`) - `rehearsal-poll-timeouts.*`; mfnd_serve P2P expect removal; workspace dep hoist; evidence gitignore (lanes 2/4/6).
- **M2.5.39–42** (`4a1862b`) - debris purge via `git clean -X`; mojibake guard + STORAGE_ACCESSIBILITY fix; ci-check `-DocsOnly`/`-RustOnly` + venv cache; frame/chunk decode without panic (lane 2).
- **M2.5.38** (`843e055`) - mfn-cli health probe; GHA voter-dial both-listening soft gate (lane 1).
- **M2.5.37** (`12df02d`) - start-all GHA tip>=1 gate; query_rpc_json_line TCP RPC; hub_liveness 900s (lane 1).
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

---

## Snapshot: docs/AGENTS.md per-lane checklists (retired 2026-07-19)

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
- [x] M2.5.31 - GHA polls 900s; voter soft gate tip>=1; health 900s; nightly jobs 90m; RC Nightly backup dispatch (e0de4e).
- [x] M2.5.34 - macOS CI `--test-threads=2` parity (15fd4c7).
- [x] M2.5.37 - start-all tip>=1; TCP RPC health; hub_liveness 900s (12df02d).
- [x] M2.5.38 - mfn-cli health probe; voter-dial both-listening soft gate (843e055).
- [x] M2.5.49 (`8650543`) - GHA participant smoke soft-continue mesh health + hub_liveness at tip>=1.
- [x] M2.5.50 (`dbf6067`; code `6216aec`) - early P2P listen; POST_START timeout export; participant smoke ps1 parity.
- [x] M2.5.51 (`0d9646a`) - start-all GHA hub_tip_wait uses MFN_POLL_HUB_MAX; observer catchup soft gate.
- [x] M2.4.89 Windows mirror — `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).
- [x] M2.5.66 — `vps_export_binds` set -e abort on loopback mesh; `vps-bind-lib-smoke.sh` in CI (`759f5d1`).

### Done

- [x] M2.5.65 — soak WARMUP health-check uses mfn-cli `status` for P2P session counts (`76cc778`).
- [x] M2.5.65 — GHA converge soft gate + `MFN_HEALTH_MIN_P2P_SESSIONS=0` (`8ccda5d`; intermediate soak `28850304866` converge FAIL → final PASS `28851202993`).
- [x] **B-05 Linux soak PASS** — soak `28851202993` on `8ccda5d` (max_height=48, 8 iterations).
- [x] **CI smoke fixes** — reference-topology grep case + F12 smokes in GHA (`e705718`); bash grep `--` for `--checkpoint-log` needle (`35c4c7f`).

### Next

- [x] **Nightly #63** all three green (`28792429191` on `85e5870` stack; B-06 gate closed).
- [x] Monitor green CI after B13 tail — **CI #28838850432 GREEN** on `934cc2f`.
- [x] **Nightly #64** all three green (`28841761235` on `934cc2f` stack).
- [x] **Nightly #28889931523** all three green on B-11/B7 stack (`b1072e3`).
- [x] **CI #28871239057 GREEN** on `837069a` (B-11 + B7 + B9 + F7/B15 stack).
- [x] Release evidence refresh on green CI (lane 2) — `release-evidence-96462aa` (this commit).
- [x] Nightly re-dispatch after M2.5.66 — **Nightly #28968584904** all three green (~7m; closes `start_mesh_fail`).
- [x] **F5 phase 3 stack Nightly** — `#29236857495` on `ffc7b04` + `#29238738502` on `536d2a6` all three green.
- [x] **F5 phase 3b Nightly** — `#29257619888` GREEN on `ba6fdce` (all three jobs).
- [x] **CI `#29255412319` GREEN** — F5 phase 3b + serve slash-hint (`ba6fdce`).
- [x] **F5 stack RC gates** — CI `#29278386048` + `#29284954973` GREEN; Nightly `#29280436031` / `#29284893108` / `#29286801623` GREEN; functional pin `85dad78`.

### Do not start (other lanes)

- M7.10 `push-all-chunks` — lanes 2–3 (landed `c1e0373`).
- M5.31+ ring tests — lane 4 (M5.31-M5.33 landed `aae3097`).

---

## Lane 2 — RC ops (security, RPC, release evidence)

**Owns:** `release-evidence-*`, RC audit dry-run, CI/Nightly auto-dispatch, schema validation gates.

### Done

- [x] M2.5.14–M2.5.18 — evidence refresh + inline Nightly dispatch.
- [x] M2.5.20 — nightly STAGE/start-all log dumps (668044d).
- [x] M2.5.21 — preflight `wasm-opt` + ci-check wasm-pack pkg cleanup (`aae3097`).
- [x] B-05 — Linux soak auto-dispatch + RC audit dry-run Linux evidence hook (`aae3097`).
- [x] M2.5.22 — wasm-pack `wasm-opt=false` (`0dcb1e9`).
- [x] M2.5.30 - bash validate-workflow-encoding guard path parity (`2eb8417`).
- [x] M2.5.32 - `.gitignore` debris; board mojibake guard; clean docs/AGENTS rebuild (`a35b7a6`).
- [x] M2.5.39-42 - DOCS-QA-2: git clean -X debris purge; ci-check `-DocsOnly`/`-RustOnly`; mojibake guard; frame/chunk decode (`4a1862b`).
- [x] M2.5.43-45 - shared `rehearsal-poll-timeouts.*`; mfnd_serve P2P expect removal; workspace dep hoist (`b945f73`).
- [x] M2.4.89 Windows mirror — `ci-check.ps1` `--test-threads=2` (`8e6b3c1`).
- [x] M7.10 push-all-chunks (`c1e0373` on `main`).
- [x] M7.11 - STORAGE_ACCESSIBILITY.md section 0 (`bb9600b`).
- [x] M7.11.2 - STORAGE_ACCESSIBILITY Phase B item 4 WASM prove+serve doc sync (`0650ad6`).
- [x] M6.9 — storage-operator JSON logs + `prove_attempt_json` unit test (`aae3097`).

- [x] M2.4.90 — `ci-check.sh` thread cap parity (`aae3097`).

- [x] **Release evidence refresh** — `release-evidence-96462aa` + RC audit dry-run go (CI `28885223488` on `0d28e4f`).

- [x] **Release evidence refresh** — `release-evidence-1c633e7` + RC audit dry-run **go** (CI `#28968642140` on `89f3498`).

- [x] **Release evidence refresh** — `release-evidence-b16cb49` + RC audit dry-run **go** (CI `#29055006785` on `b16cb49`).
- [x] **Release evidence refresh** — `release-evidence-5a1b221` + RC audit dry-run **go** (CI `#29264586158` on F6 stack).

### Next

- [x] Idle — RC gates green on B4 stack; periodic B-05 soak re-run is maintenance only.

### Do not start

- M5 protocol tests — lane 4.

---

## Lane 3 — RC onboarding (wallet, storage, faucet, rehearsal)

**Owns:** Participant/observer rehearsal smokes, faucet/demo scripts, operator onboarding polish, M7.10 UX.

### Done

- [x] M2.5.7–M2.5.16 — smoke evidence pipeline + assert gates.
- [x] M4.7 WASM SPoRA bindings (`778053a`).
- [x] M7.10 — `push-all-chunks` + OPERATORS.md (`c1e0373`).
- [x] M7.11 - STORAGE_ACCESSIBILITY.md section 0 (`bb9600b`).
- [x] M7.11.2 - STORAGE_ACCESSIBILITY Phase B item 4 WASM prove+serve doc sync (`0650ad6`).

### Done (continued)

- [x] **Nightly #63** all three green (`28792429191`; B-06 closed).
- [x] **Nightly #64** all three green (`28841761235` on `934cc2f`).
- [x] **B8.3 tor-rpc rehearsal** — plan-only `tor-rpc-rehearsal-smoke` in CI + ci-check (`1ad2dce`).

### Next

- [x] **TL-6 VPS participant rehearsal** — Hetzner `5.161.201.73` PASS (`vps-participant-rehearsal-observer-linux-20260714T030600Z.txt`).

### Do not start

- Wallet README ring examples — lane 5 (done `aae3097`).
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
- [x] **M5.40** - 64-block combined-inflow + PPB + equivocation-PPB emission sims in default CI (`7648ab2`).
- [x] **M5.41** - 128-block PPB + equivocation combined-inflow emission sims in default CI (`c7f90e6`).
- [x] **M2.5.46** (`2b33ced`; code `1152e16`) - split `p2p_peer_quarantine` + `p2p_reconnect_plan` from `p2p_fanout` (B-07 partial).
- [x] **M2.5.47** (`2b33ced`) - mfnd `runner`/`mfnd_cli` production `expect` removal (B-08 partial).

- [x] **M2.5.48** (40d31d) - on-disk debris purge; light-follow quorum `expect` removal (B-08).
- [x] **M2.5.52** (`2904ea3`) - B-07: extract `dispatch/rpc_params.rs` + `rpc_method_meta.rs` from `dispatch.rs`.
- [x] **M2.5.55** (6fe1b18) - light-chain EvolutionFailed integration test; mempool test dead_code cleanup.
- [x] **M2.5.53** (`bd76bde`) - B-07: extract `cli/parse.rs` from `cli.rs`; restore + hoist `mod parse`.
- [x] **M2.5.60** - B-08 lock-in: `clippy::unwrap_used`/`expect_used` warn gate on non-test `mfn-net` + `mfn-node`; delete one-off repair scripts.
- [x] **M5.49 + M7.12** (`890a56c`) - permanence hardening: `validate_storage_commitment_shape` consensus + mempool gate (`chunk_size` power-of-two, `num_chunks == ceil(size/chunk)`); chunk-inbox gossip authenticated against anchored commitments (unknown-commit reject, index/length gate, single-chunk data_root verify, no overwrite of held bytes); fan-out verifies inbox Merkle root against `data_root` before replicating.
- [x] **F15 MFBN-1 interop doc** — `docs/interop/VRF_MFBN1.md` + header_verify utxo_root quorum lag exports (`83b82dd`)

- [x] **M2.5.61** (`1603e43`) - fix M2.5.50 stdout-order regression: `mfnd serve` prints `mfnd_p2p_listening=` before `mfnd_serve_listening=`, so sequential prefix reads in `mfnd_smoke` consumed the P2P line and hung (`mfnd_p2p_reconnects_saved_peers_on_restart`, `mfnd_rpc_get_light_follow_p2p_fetches_from_peer_listener` — Windows ci-check red twice). New `read_stdout_lines_with_prefixes_any_order` harness helper; all `--p2p-listen` spawns collect startup announcements order-independently. First green CI matrix since M2.5.50 (run `28774283620`).
- [x] **DOCS-PH-1** - `docs/PERMANENCE_HARDENING.md`: implementation-level log of shipped permanence hardening (M5.49 shape gate, M7.12 gossip auth + fan-out verify, M2.5.61 CI trustworthiness) with code citations and test inventory, plus file-and-function-level plans for the remainder — B-11 endowment binding (opening-reveal vs range-proof designs), ChunkV2 Merkle-path gossip, replication accounting via operator-salted challenges, proactive repair sweep, bonding + slashing, inbox quota. Cross-linked from `docs/README.md`, `STORAGE.md`, `PRIVACY_HARDENING.md`.

- [x] **B-11 phase 1** — `MFEO` wire + `apply_block`/mempool Pedersen opening verify; `require_endowment_opening` param (`3511346`).
- [x] **B-11 proptests** — `prop_mfeo_opening_storage_upload_treasury` + reject without `MFEO` (`9f0a0aa`).
- [x] **B-11 public devnet enable** — genesis spec `endowment` section + `require_endowment_opening: 1` in `public_devnet_v1.json` (same `genesis_id`; operators must sync byte-identical JSON).
- [x] **B2 ChunkV2** (`20954b0`) — Merkle-path chunk gossip tag `0x12`; `validate_gossip_chunk_v2` + `on_chunk_v2`; fan-out/operator push emit proofs; inbound `ChunkV1` retained.
- [x] **F7 consensus tail** (this commit) — `RingPolicy.min_input_count` at `verify_transaction` (with lane 5).
- [x] **F5 fraud-proof phase 1b** (`85dad78`) — `FraudContestRegistry` + RPC `list_fraud_contests`; CI `#29278386048` GREEN.
- [x] **F5 phase 1c design** — `InvalidBlockSlashEvidence` spec in `FRAUD_PROOFS.md` (8b72294).
- [x] **F5 phase 1c integration tests** — `invalid_block_slash_zeros_producer_on_coinbase_fraud` + same-height reject (`69c0531`).
- [x] **F5 phase 1c genesis_spec v3** — `accepts_header_version_three` + rejects v4 (`be9c760`).
- [x] **F5 phase 4 research** — SNARK/STARK validity proof design in `FRAUD_PROOFS.md` § Phase 4 (`c2d46f3`).
- [x] **F5 phase 4a** — apply-block replay witness + P2P tag `0x14` + launch-status v8 (e385390; CI #29298069061 GREEN).
- [x] **F5 phase 4b** — STARK digest-stub witness kind 2 + domain-separated circuit digest + launch-status v9 (`8f814cf`; `946341c`).
- [ ] **F5 phase 4b.1** — Winterfell batch-binding STARK + witness kind 3 + launch-status v10 (**Doing** — this push).

### Next

- [ ] **F5 phase 4b.1** — Winterfell tx+coinbase+SPoRA batch circuit.

- [x] **B3 phase 1** — operator-salted SPoRA challenge derivation (`mfn-storage`; `eea59aa`).
- [x] **B3 phase 2** — per-operator proof slots + `apply_block` wire (checkpoint v5; flag off on public genesis).
- [x] **B3 phase 3a** — operator registry in chain state + `require_registered_operators` gate (checkpoint v6; genesis off).
- [x] **B3 phase 3b** — `StorageOperatorOp::Register` Schnorr wire + bond escrow (checkpoint v7 `min_storage_operator_bond`).
- [x] **B3 phase 3c** — genesis spec `storage_operators` seeding + public devnet enable.
- [x] **M5.50** — B3 duplicate-operator + replication-cap reject proptests (this push).
- [x] **B4 phase 1** — proactive repair sweep in `mfnd` (`89f3498`).

### Next

- [x] **B5 phase 5a** — inert slash params + checkpoint v8 + [`B5_OPERATOR_SLASHING.md`](./B5_OPERATOR_SLASHING.md) (`e81d33e`).
- [x] **B5 phase 5b** — retained bond + `storage_operator_stats` + checkpoint v9 (`643a224`).

- [x] **B5 phase 5c** — slash execution → treasury + zero-bond deregister (`8bdb4ab`).

### Next

- [x] **B5 phase 5d** — M5.51 proptests + public devnet slash params (`1485e67`; CI `#28983986309` GREEN).

### Next

- [x] **B7 (permanence inbox quota)** — `MFND_CHUNK_INBOX_MAX_BYTES` gossip disk cap (`930b166`; CI `#28986986012` GREEN).

### Next

- [x] **B1 phase 2a** — inert `require_endowment_range_proof` + checkpoint v10 (`76b5f8f`).
- [x] **B1 phase 2b** — MFEX v3 + `MFER` wire; `apply_block` + mempool verify (`c084537`).
- [x] **B1 phase 2c** — wallet builds `MFER` on upload (`ba53a15`).
- [x] **B1 phase 2c tail** — reject forged `MFER` consensus test (`reject_upload_with_forged_mfer_when_endowment_range_proof_required`).
- [x] **B1 phase 2d** — public devnet flip to `require_endowment_range_proof: 1` (`2958cfa`; CI `#28995960877` GREEN).
- [x] **B1 phase 2e** — WASM upload merges live `get_chain_params.endowment`; RPC exposes endowment policy flags (`bbe1d9f`; CI `#28999593529` GREEN).

### Handoff to lane 3

- Ring-16 is consensus-enforced; wallet/CLI must stay ≥16 (lane 5 documents).

---

## Lane 5 — Privacy surface (wallet, CLI, WASM, docs)

**Owns:** Reference-wallet ring defaults, privacy doc accuracy, “no silent downgrade” UX.

### Done

- [x] **M5.31-docs** — `mfn-wallet/README.md` quick-start uses ring-16 and cites `WALLET_MIN_RING_SIZE`.
- [x] **M5.31-cli** — `mfn-cli wallet` help documents `--ring-size` default 16 (claim B-04).
- [x] **PRIVACY cross-link** — wallet README links uniform-ring policy in [`PRIVACY.md`](./PRIVACY.md).
- [x] **F5-P8** (`23c14d6`) — `lsag` + unwired `oom` gated behind `cfg(test)` / non-default cargo features; release binaries accept CLSAG only (`PRIVACY_HARDENING.md` §B5 shipped).
- [x] **F5-P10** (`3789e39`) — structural authorship-key firewall: canonical `derive_claiming_keypair` in `mfn-crypto`, closed `ClaimingIdentity` constructor, signing-time `ClaimKeyReusesWalletKey` rejection (`PRIVACY_HARDENING.md` §B10 shipped).
- [x] **F5-PM13** (`df70b9c`) — `mfn_consensus::constitution` fork-legitimacy invariants enforced at genesis-spec load (`tail_emission > 0`, uniform rings >= 16, endowment pricing well-formed).
- [x] **F5:B3 (output ordering)** (`d7ee698`) — `spend::build_transfer` shuffles output specs with the plan RNG; change position carries no signal (`PRIVACY_HARDENING.md` §B3).
- [x] **F5-P9 (conformance suite)** (`1c9d578`) — `mfn-wallet/tests/canonical_conformance.rs` pins version / empty-extra / uniform ring-16 / output floor / enc_amount / byte-canonical encoding for transfers + uploads; closes §B3.
- [x] **F5-P5/B1 (consensus output floor)** (`d583ea4`) — `RingPolicy.min_output_count` = 2 under the uniform-ring tier (derived, no codec change); enforced in `verify_transaction`; closes §B1.
- [x] **B2 (age-band coin selection)** (`85e5870`) — `Wallet::select_inputs` spends within one exponential age band (fewest inputs, newest-band ties, cohesive spill); closes §B2.
- [x] **B3 tail (production RNG contract)** (`4a4a9f1`) — `production_tx_rng` alias; CLI/WASM wired; conformance source-scan; closes §B3.
- [x] **B4(a) decoy pool** (`b402db3`) — `build_decoy_pool` excludes only spent input keys; unspent owned outputs eligible.
- [x] **B4(c) co-height randomization** (`297df7c`) — `select_gamma_decoys` uniform pick within height bucket.
- [x] **B13 (wallet size buckets)** (`4712811`) — power-of-two pad in `build_storage_upload`; closes §B13 wallet layer.
- [x] **B13 (consensus size buckets)** (`3d8574c`) — reject non-bucket `size_bytes`; artifact saves padded payload.
- [x] **B7 (Dandelion++ phase 1)** (`1cc9ead`) — opt-in `--dandelion` stem/fluff relay.
- [x] **B7 (phase 2)** — `MFND_DANDELION=1` env + CLI parse tests.
- [x] **B9 (view tags phase 1)** — `indexed_view_tag` in `mfn-crypto` stealth.
- [x] **B9 (view tags phase 2)** — tx v2 wire + wallet encode + scanner skip (~256× filter); legacy v1 accepted.
- [x] **B7 (rehearsal evidence)** — Windows `dandelion-rehearsal-smoke` PASS on B-11 MFEO genesis; `-dandelion` evidence archive tag.
- [x] **B7 (rehearsal soak)** — `--dandelion` on mesh scripts (default off); `dandelion-rehearsal-smoke` / `dandelion-soak` wrappers.
- [x] **B7 (stem wire label)** — `TxStemV1` tag `0x11` on stem relay; fluff on `TxV1`.
- [x] **F7/B15 (two-input wallet floor)** — `WALLET_MIN_TX_INPUTS` + `select_inputs_for_tx`; pad to two real inputs when possible.
- [x] **F7 consensus tail** (this commit) — `RingPolicy.min_input_count` at `verify_transaction` (with lane 4).

### Next

- [x] **F12 phase 2** — `wallet light-scan --checkpoint-log`; cross-check vs signed JSONL log (`10e606e`).
- [x] **F12 phase 3** — `mfn-checkpoint-log` crate; WASM `checkpointLogVerify` / `checkpointLogCrossCheck` (`5d78329`).
- [x] **F12 phase 4** — `checkpoint-log cross-check`; `publish-checkpoint-log.*`; live rehearsal smoke (`5965525`).
- [x] **F5 fraud-proof phase 0** (`0039732`) — body-root fraud verify + P2P tag `0x13` + [`FRAUD_PROOFS.md`](../FRAUD_PROOFS.md).
- [x] **F5 fraud-proof phase 1** (`bd6d4d9`) — gossip fan-out + verify + `mfnd_fraud_proof_valid`; slash deferred.
- [x] **F5 fraud-proof phase 2** (`12e7353`) — coinbase amount fraud wire v2 + `verify_interactive_fraud_proof`.
- [x] **F5 fraud-proof phase 3** (`ffc7b04`) — invalid CLSAG + invalid SPoRA wire v3; `verify_tx_fraud_proof`.
- [x] **F5 fraud-proof phase 3b** (`5f3947e`, `ba6fdce`) — ring-membership UTXO witness; `TxFraudKind::RingMemberUtxo`; producer slash ops hook.
- [x] **F5 fraud-proof phase 1b** (`85dad78`) — `FraudContestRegistry` + RPC `list_fraud_contests` + mfnd TCP smokes; CI `#29278386048` GREEN.
- [x] **F12 phase 5b** — `demo-web-f12-rehearsal-smoke --live` CLI + WASM crypto path (this push).
- [x] **P32 phase 2** — `vps-role-*.env.example` templates + OPERATORS.md cross-links (`db58ae1`).
- [x] **P32 phase 3** — observer loopback-RPC hint when P2P is public (`7d39f4c`).
- [x] **P32 phase 4a** — PM23 operator-manifest separation plan-only rehearsal smoke (this push).
- [x] **P32 phase 4c** — VPS templates default `MFND_PM23_HARD_FAIL=1`; preflight warns when unset on public IP (`a91fbe3`).
- [x] **P32 phase 4d** — operator template `MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1`; storage-operator aborts on validator seed env (`4a429e4`).
- [x] **P32 phase 4e** — observer template `MFND_PM23_HARD_FAIL=1` (`b4cab93`).
- [x] **vps-provision-rehearsal-smoke** — TL-5 VPS_PROVISION.md plan gate (`a91fbe3`).
- [x] **TL-5 software-ready pin** — `TESTNET_LAUNCH.md` pin `85dad78` (F5+F6 stack; CI `#29278386048` + Nightly `#29280436031` GREEN).
- [x] **F12 phase 5b demo live** — `demo-web-f12-rehearsal-smoke --live` (`8b4f0ee`).
- [x] **TL-5** — Hetzner internet soak PASS `max_height=59` (lane 7; this push).

### Done (recent)

- [x] **F12 phase 1** — `checkpoint-log sign|verify`; [`CHECKPOINT_LOG.md`](../CHECKPOINT_LOG.md); ci-check rehearsal (`50782a3`).

### Do not start

- M7.10 replication — lanes 2–3.
- GHA rehearsal — lane 1.

---

## Lane 6 — Permanence depth (economics, SPoRA, treasury)

### Done
- [x] **F5-PM9** — `docs/PQ_MIGRATION.md`: committed consensus-versioned PQ migration path + wire-format headroom audit (soft fork today).
- [x] **F5-PM10** — self-verifying chain+chunk archive: `mfnd archive-export` / `archive-verify` (`mfn-node/src/archive_export.rs`); replay-from-genesis + chunk Merkle re-derivation, no live network.
- [x] **M2.5.59** - debris gitignore (*.utf8.bak, docs/*.test.md); resolve-schema-python invoke via powershell -NoProfile -File.
- [x] **M2.5.58** (c0e73eb) - resolve-schema-python.ps1 wired into ci-check + release scripts.
- [x] **M2.5.57** (`3e994b9`) - debris purge + DOCS-QA-2 closure.
- [x] **M2.5.56** (6fe1b18) - B-10: anyhow 1.0.103 clears RUSTSEC-2026-0190.


**Owns:** Long-run treasury/emission sims, SPoRA payout invariants, operator-bonding research.

### Idle — claim from backlog


- [x] **M5.46** - combined-inflow emission CI tier complete (`1232506`).
- [x] **M5.47** - 256-block equivocation combined-inflow + 1M curve in default CI (`db06c78`).
- [x] **M5.48** - emission deep-sim tier closure; 2048 CLSAG + 100k `apply_block` stay nightly (77f2fe1).
- [x] **M5.34 / B-03** — 64-block validator mixed CLSAG+SPoRA emission sim in default CI (`45a118b`).
- [x] **M5.40** - 64-block combined-inflow + PPB + equivocation-PPB emission sims in default CI (`7648ab2`).
- [x] **M5.41** - 128-block PPB + equivocation combined-inflow emission sims in default CI (`c7f90e6`).
- [x] **M5.42** - 256-block combined-inflow emission sim in default CI (994af36).
- [x] **M5.44** - 512-block combined-inflow emission sim in default CI (3fcb4bc).
- [x] **M5.46** - combined-inflow emission CI tier complete; 2048-block CLSAG fee mix timed nightly-only (~13 min release).
- [x] **M5.45** - 512-block PPB + equivocation combined-inflow emission sims in default CI (66a697a).
- [x] **M5.43** - 256-block PPB combined-inflow emission sim in default CI (7ffcdac).
- [x] B-05 — Linux soak auto-dispatch + workflow evidence commit (`9537c7b`; PASS `28851202993` / `234f0a8`).

### Next

- [x] B-05 — Linux soak PASS transcript archived (`28851202993` / `234f0a8`).
- [x] B-06 — Nightly #63 all three jobs green (`28792429191` on `85e5870` stack; lane 1 RC gate closed).
- [x] **B2 ChunkV2** (this commit) — Merkle-path chunk gossip with lane 4.
- [x] **B4** — proactive repair sweep with lane 4 (`89f3498`).
- [x] **B7 (permanence inbox quota)** — chunk-inbox disk cap (`930b166`).
- [x] **B5 phase 5a** — inert slash params + checkpoint v8 (`e81d33e`).
- [x] **B5 phase 5b** — retained bond + miss stats + checkpoint v9 (`643a224`).
- [x] **B5 phase 5c** — slash → treasury + zero-bond deregister (`8bdb4ab`; CI `#28979369780` GREEN).

### Next

- [x] **B5 phase 5d** — M5.51 proptests + public devnet slash params (with lane 4).

### Next

- [x] **B1 phase 2a** — inert `require_endowment_range_proof` + checkpoint v10 (`76b5f8f`).
- [x] **B1 phase 2b** — MFEX v3 + `MFER` wire; `apply_block` + mempool verify (`c084537`).
- [x] **B1 phase 2c** — wallet builds `MFER` on upload (`ba53a15`).
- [x] **B1 phase 2c tail** — reject forged `MFER` consensus test (with lane 4).
- [x] **B1 phase 2d** — public devnet flip to `require_endowment_range_proof: 1` (`2958cfa`; CI `#28995960877` GREEN).
- [x] **B1 phase 2e** — WASM upload merges live `get_chain_params.endowment`; RPC exposes endowment policy flags (`bbe1d9f`; CI `#28999593529` GREEN).
- [x] **F6 fee economics docs** (`d4a5114`) — [`FEES.md`](./FEES.md) plain-language fee breakdown + 2026-07 parameter review; `ECONOMICS.md` §3/§7/§8/§10 sync.
- [x] **F6 tail split approved (docs)** (`9a2673a`) — `FEES.md` §5.4: 10% subsidy tail → treasury for next parameter fork.
- [x] **F6 phase 2 subsidy tail split (consensus)** (this push) — `subsidy_to_treasury_bps`, checkpoint v11, `subsidy_treasury_credit`, `apply_block` credit, RPC exposure.
- [x] **F6 Arweave durability comparison** (`bff1b70`) — `ECONOMICS.md` §12 vs Arweave permanence model.
- [x] **F6 treasury telemetry watch** (`808529a`) — `treasury-telemetry-watch.*` read-only helper.
- [x] **F6 telemetry subsidy field** (this push) — `subsidy_to_treasury_bps` in treasury-telemetry-watch + ci-check plan gate.

### Next

- [ ] Idle — watch testnet treasury telemetry for fee-drought revisit triggers ([`FEES.md § 5`](./FEES.md#5-parameter-review-2026-07-should-fees-rise-and-should-the-tail-feed-the-treasury); helper: `treasury-telemetry-watch.*`).

- RC Nightly fixes — lane 1.
- `push-all-chunks` — lanes 2–3.

---

## Backlog detail (claim → move to lane section)

| ID | Item | Suggested lane | Notes |
| B-06 | Nightly #63 green | 1 | After M2.5.49-58 stack `c0e73eb` (CI #669) |
| B-02 | Proptest CLSAG + storage upload same block | 4 | Done - extends M5.5 |
| B-03 | CI emission sim with privacy fees | 6 | **Done** — 64-block validator mixed |
| B-05 | Linux 30s soak evidence | 2 + 6 | **Done** — soak `28851202993` PASS (`234f0a8`) |
| B-06 | Nightly #63 after M2.5.57 | 1 | M2.5.49-57 stack on `3e994b9` |

---

## Lane 7 — Testnet launch (internet-facing go-live)

**Owns:** [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md) TL phases, VPS deployment runbook, `seed_nodes` publication, launch ceremony tracking, `launch-status.*`.

**Does not own:** M5/F7 protocol (lane 4), release-evidence generators (lane 2), Nightly/CI fixes (lane 1).

### Done

- [x] **TL-1** — charter + [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md) + `launch-status` (`8661106`)
- [x] **TL-2** — green CI `#28924060054` on `e7d74f7` (F7 mempool two-input pad)
- [x] **TL-3** — `release-evidence-46677ad` + RC audit dry-run `go` (CI `#28924060054`)

- [x] **TL-4** — single-VPS runbook (`2f77eb4`: `vps-start-all.sh`, `VPS_SINGLE_BOX_LAUNCH.md`)
- [x] **TL-5 tooling** — `vps-preflight.sh`, `vps-internet-soak.sh`, `soak.sh --vps` (`5a74d57`)

- [x] **TL-6 tooling** — `vps-participant-rehearsal.sh`, `participant-rehearsal-smoke.sh --vps` (`ef3cbc4`)
- [x] **TL-7–TL-9 tooling** — `TESTNET_GENESIS_CEREMONY.md`, `publish-seed-nodes.*`, `launch-go-no-go.*` (`03de79a`)
- [x] **TL-8 invite packet** — [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) + `launch-status.v2` (`a0bf55f`)
- [x] **VPS provision + ceremony** — [`VPS_PROVISION.md`](./VPS_PROVISION.md) + `vps-launch-ceremony.*` (`0a700a5`)
- [x] **TL-5 local RC** — `launch-status.v3` + local MFER rehearsals PASS (no-observer + observer Windows evidence)
- [x] **launch-status v3** — local RC gates + `permanence-demo.sh` log-lock parity
- [x] **launch-status v5** — execution_checklist block + TL-5 next_action via vps-execution-checklist.v2 (this push)
- [x] **launch-status v6** — treasury_telemetry + role_templates blocks (this push)
- [x] **launch-status v7** — `software_ready` pin parse + `fraud_proof` block (this push)
- [x] **vps-role-templates-rehearsal-smoke** — plan gate on all four role env templates (this push)
- [x] **vps-execution-checklist-rehearsal-smoke** — ci-check gate on TL-5/TL-6 preflight checklist (`8a49f7e`)
- [x] **launch-go-no-go-rehearsal-smoke** — ci-check gate on TL-9 pre-launch go/no-go JSON (`bbc57a1`)
- [x] **vps-internet-soak-rehearsal-smoke** — TL-5 soak docs + script wiring gate (this push)
- [x] **assert-vps-internet-soak-evidence** — TL-5 transcript audit gate + launch-status soak PASS fix (`1aff0df`)
- [x] **vps-internet-soak-evidence-rehearsal-smoke** — assert + launch-status fixture gate (this push)
- [x] **assert-vps-participant-rehearsal-evidence** — TL-6 transcript audit + launch-status fixture gate (`11a2d07`)
- [x] **genesis-validator-bls-pop** — Path B ceremony PoP compute/verify helper + ci-check rehearsal smoke (`83b82dd`)
- [x] **genesis-header-version-rehearsal-smoke** — Path A v1 pin + Path B header_version: 2 doc gate (this push)
- [x] **launch-go-no-go assert hardening** — TL-5/TL-6 evidence via assert scripts in TL-9 gate (`83b82dd`)
- [x] **vps-execution-checklist tl5/tl6 assert** — ordered VPS path includes assert steps (`83b82dd`)
- [x] **vps-participant-rehearsal-rehearsal-smoke** — TL-6 participant wrapper + evidence gate (`4688735`)
- [x] **publish-seed-nodes-rehearsal-smoke** — TL-8 fixture dry-run + doc gate (`05e2772`)
- [x] **vps-launch-ceremony-rehearsal-smoke** — TL-7 ceremony TL-5..TL-9 ordering gate (`05e2772`)
- [x] **F12 phase 5 demo web** — checkpoint log UI + `demo-web-f12-rehearsal-smoke.*` (`05e2772`)
- [x] **F12 phase 5b + TL-9 Schnorr gate** — live demo smoke (`8b4f0ee`) + `launch-go-no-go` crypto verify (`d04afed`)
- [x] **vps-execution-checklist v2** — TL-7/TL-8 publish + invite commands in checklist JSON (`c1f9597`)
- [x] **testnet-invite-rehearsal-smoke** — TL-8 invite packet doc gate (`9da922a`; wired `c1f9597`)
- [x] **TL-5 execution checklist** — `vps-execution-checklist.*` (`759f5d1`).

### Doing

- [ ] *(idle — next is TL-9 named watchers)*

### Next

- [x] **TL-5 execution** — Hetzner `5.161.201.73` soak PASS `max_height=59` (`ba2ec08`).
- [x] **TL-6 execution** — participant rehearsal PASS (`ba2ec08`).
- [x] **TL-7** — Path A toy keys (`tl7-genesis-signoff-path-a-20260714.txt`).
- [x] **TL-8** — `seed_nodes` + checkpoint log published (`11eabbd`).
- [x] **Front-matter + JOIN_TESTNET** — experimental testnet rebrand + [`JOIN_TESTNET.md`](./JOIN_TESTNET.md) (`4b137bc`).
- [ ] **TL-9** — named watchers + share [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) / [`JOIN_TESTNET.md`](./JOIN_TESTNET.md)

### Do not start

- B3 replication accounting — lanes 4+6.
- F7 / consensus tail — lanes 4+5.

---

## TESTNET_CHECKLIST mirror

RC lanes 1–3 must keep [`TESTNET_CHECKLIST.md`](./TESTNET_CHECKLIST.md) in sync when they land units. Lanes 4–6 add a one-line note under **Agent coordination** when they ship protocol or privacy-surface changes. Lane 7 mirrors TL units into [`TESTNET_LAUNCH.md`](./TESTNET_LAUNCH.md).

---

## See also

- [`3agent.md`](./3agent.md) — legacy lanes 1–3 pointer
- [`DECENTRALIZATION.md`](./DECENTRALIZATION.md), [`PRIVACY.md`](./PRIVACY.md), [`ROADMAP.md`](./ROADMAP.md)

---

## Snapshot: 3agent.md session history (retired 2026-07-19)

# 3agent (legacy name — lanes 1–3)

> **Unified coordination:** [`AGENTS.md`](./AGENTS.md) (master board) and [`docs/AGENTS.md`](./docs/AGENTS.md) (per-lane checklists).
> Lanes **4–6** are overflow lanes.

## 3-agent checklist (live)

| Agent / lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | CI `#29301681465` + Nightly `#29302920403` GREEN on `946341c` | **Doing** — monitor 4b.1 CI | Nightly dispatch after GREEN |
| **2** RC ops | `release-evidence-e385390` | **Done** | Refresh evidence on 4b.1 head |
| **3** Onboarding | checklist v2 + TL-5/6 evidence `ba2ec08` | **Done** | TL-7 genesis sign-off |
| **4** Protocol | F5 phase 4b `946341c` | **Doing** — phase 4b.1 Winterfell | phase 4b.2 recursive aggregation |
| **5** Privacy | P32 4e + F12 live | **Done** | TL-5 VPS soak (human) |
| **6** Permanence | F6 telemetry `0d1b9ec` | **Done** | Parameter fork `1000` bps (TL-7 Path B) |
| **7** Testnet | TL-5/TL-6 Hetzner evidence `ba2ec08` | **Done** | Human TL-7 genesis ceremony |

---

## Session — 2026-07-14 (F5 phase 4b.1 Winterfell STARK)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 phase 4b.1** | **Doing** — this push | Winterfell batch-binding AIR + witness kind `3` + launch-status v10 |
| **CI #29301681465** | **Done** — GREEN | 4b stack on `946341c` |
| **Nightly #29302920403** | **Done** — GREEN | dispatched on 4b head |
| **TL-5/TL-6** | **Done** — `ba2ec08` | Hetzner `5.161.201.73` soak + participant evidence archived |

**Lane 4 — Doing:** Winterfell circuit **Next:** 4b.2 recursive aggregation  
**Lane 1 — Next:** Nightly on 4b.1 after CI GREEN  
**Lane 7 — Next:** TL-7 genesis sign-off (human)

---

## Session — 2026-07-13 (F5 phase 4a validity proof wire)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 phase 4a** | **Done** — `e385390` | apply-block replay witness; P2P tag `0x14`; launch-status v8 |
| **CI #29298069061** | **Done** — GREEN | full matrix on `e385390` |

**Lane 1 — Doing:** Nightly dispatch **Next:** pin refresh after GREEN  
**Lane 4 — Done:** phase 4a wire **Next:** phase 4b STARK backend

---

## Session — 2026-07-14 (F5 phase 4a validity proof wire)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 phase 4a** | **Doing** — this push | `validity_proof` replay witness + P2P tag `0x14` + mfnd gossip verify |
| **Nightly #29296433903** | **Done** — GREEN | F5 1c stack on `105ea22` |
| **TL-5** | **Waiting** — human | VPS internet soak |

**Lane 4 — Doing:** phase 4a wire **Next:** phase 4b STARK spike  
**Lane 1 — Done:** Nightly GREEN **Next:** pin refresh after this push CI

---

## Session — 2026-07-13 (F5 phase 1c CI fix + phase 4 research)

| Unit | Status | Notes |
| --- | --- | --- |
| **genesis_spec v3 fix** | **Done** — `be9c760` | `accepts_header_version_three`; rejects v4 |
| **rehearsal smoke gate** | **Done** — `105ea22` | genesis-header-version-rehearsal-smoke needles |
| **F5 phase 4 research** | **Done** — this push | SNARK/STARK validity proof design in `FRAUD_PROOFS.md` |
| **CI #29294927626** | **Done** — GREEN | Nightly `#29296433903` in progress |

**Lane 1 — Doing:** Nightly `#29296433903` **Next:** pin refresh after GREEN  
**Lane 4 — Done:** phase 4 research doc **Next:** phase 4a prototype spike

---

## Session — 2026-07-13 (F5 phase 1c on-chain producer slash)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 phase 1c** | **Done** — this push | Tagged `SlashEvidence` + `InvalidBlockEvidence` + `apply_block` stake zero (`HEADER_VERSION_FRAUD_SLASH`=3) |
| **launch-status fraud_proof 1c** | **Done** — this push | `on_chain_producer_slash: shipped` |
| **TL-5** | **Waiting** — human | VPS internet soak |

**Lane 4 — Done:** phase 1c impl **Next:** F5 phase 4 SNARK research  
**Lane 7 — Done:** launch-status 1c pin **Next:** human TL-5 VPS soak

---

## Session — 2026-07-13 (F5 phase 1b fraud contests)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 phase 1b** | **Done** — `17ac4fc` | `FraudContestRegistry` + `list_fraud_contests` RPC |
| **method_count fix** | **Done** — `543374f`/`7b0587c` | CI `#29270900030` + `#29274921666` (len assert) |
| **F5 complete** | **Done** — `85dad78` | CI `#29278386048` + Nightly `#29280436031` GREEN |
| **TL-5** | **Waiting** — human | VPS internet soak |

**Lane 4 — Done:** F5 phase 1b contest registry **Next:** on-chain producer slash  
**Lane 7 — Waiting:** human TL-5 VPS soak

---

## Session — 2026-07-13 (F6 stack CI GREEN + TL-5 pin)

| Unit | Status | Notes |
| --- | --- | --- |
| **F6 + telemetry CI** | **Done** — `#29264586158` | GREEN on `5a1b221` |
| **Release evidence** | **Done** — `release-evidence-5a1b221` | RC audit **go** |
| **Software-ready pin** | **Done** — `TESTNET_LAUNCH.md` | Pin `5a1b221`; Nightly `#29267729234` GREEN |

**Lane 1 — Done:** CI `#29264586158` + Nightly `#29267729234` GREEN **Next:** soak maintenance  
**Lane 2 — Done:** release-evidence-5a1b221 go **Next:** human sign-off packet  
**Lane 7 — Waiting:** human TL-5 VPS soak (do not skip)

---

## Session — 2026-07-13 (TL-5 software-ready pin + Nightly GREEN)

| Unit | Status | Notes |
| --- | --- | --- |
| **Nightly F5 3b** | **Done** — `#29257619888` | GREEN on `ba6fdce` (all three jobs) |
| **Incomplete F6 decode** | **Aborted** — `b6b2fdd` | `90431fb` referenced missing `subsidy_to_treasury_bps`; reverted |
| **F6 phase 2 consensus** | **Done** — this push | Full `subsidy_to_treasury_bps` stack + checkpoint v11 + settlement test |
| **TL-5 handoff** | **Doing** — this push | `TESTNET_LAUNCH` software-ready pin + `VPS_PROVISION` TL-5 soak section + provision smoke needles |

**Lane 1 — Done:** Nightly `#29257619888` **Next:** watch revert CI `#29258397993`  
**Lane 7 — Done:** software-ready pin published **Next:** human TL-5 (do not skip)  
**Lane 6 — Aborted:** partial F6 decode — leave docs-only until full EmissionParams lands

---

## Session — 2026-07-13 (F5 phase 3b serve slash-hint fix)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 phase 3b serve fix** | **Done** — `ba6fdce` | `mfnd_fraud_proof_producer_slash_hint` via gossip-label parse; CI `#29255412319` GREEN |
| **Release evidence** | **Done** — `release-evidence-ba6fdce` | RC audit **go**; Nightly `#29257619888` dispatched |

**Lane 1 — Done:** CI green on phase 3b stack **Next:** Nightly watch  
**Lane 4 — Done:** phase 3b complete **Next:** F5 phase 4 research / human TL-5  
**Lane 6 — Observed:** incomplete local FEES/emission/checkpoint WIP — leave for owning agent

---

## Session — 2026-07-13 (F5 phase 3b ring-membership fraud)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 fraud-proof phase 3b** | **Done** — `5f3947e` | wire v3 kind=3 ring UTXO witness + `fraud_proof_producer_slash_hint` |

**Lane 4 — Done:** phase 3b ring-membership **Next:** F5 phase 4 research

---

## Session — 2026-07-13 (F5 phase 3 CLSAG + SPoRA fraud)

| Unit | Status | Notes |
| --- | --- | --- |
| **macOS RPC CI fix** | **Done** — `9d1710f` | drain oversized RPC line; CI `#29230074495` GREEN |
| **F5 fraud-proof phase 3** | **Done** — `ffc7b04` | wire v3 invalid CLSAG + invalid SPoRA; CI `#29234849464` GREEN; Nightly `#29236857495` GREEN |

**Lane 1 — Done:** Nightly `#29238738502` on `536d2a6` **Next:** soak maintenance

**Lane 4 — Done:** phase 3 CLSAG/SPoRA (`ffc7b04`) **Next:** phase 3b ring-membership witnesses

---

## Session — 2026-07-13 (F5 phase 2 coinbase amount fraud)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 fraud-proof phase 2** | **Done** — `12e7353` | coinbase wire v2 + `verify_interactive_fraud_proof`; CI `#29225657744` red macOS RPC |

**Lane 4 — Done:** phase 2 coinbase (`12e7353`) **Next:** phase 3 CLSAG witnesses

---

## Session — 2026-07-13 (F5 phase 1 gossip fan-out)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 fraud-proof phase 1** | **Done** — `bd6d4d9` | P2P tag `0x13` recv/send/fanout; CI `#29221315455` GREEN |
| **F5 UTF-8 smoke fix** | **Done** — `fa2aab2` | CI `#29212422570` GREEN; Nightly `#29213250847` GREEN |

**Lane 4 — Done:** phase 1 gossip (`bd6d4d9`) **Next:** phase 2 coinbase fraud

---

## Session — 2026-07-12 (F5 UTF-8 smoke fix)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 fraud-proof phase 0** | **Done** — `0039732` | body-root verify + tag `0x13` |
| **fraud-proof-rehearsal-smoke UTF-8** | **Done** — `fa2aab2` | rewrite `.sh`/`.ps1` as UTF-8; CI `#29212422570` GREEN; Nightly `#29213250847` GREEN |

**Lane 1 — Done:** CI + Nightly green **Next:** soak maintenance

**Lane 2 — Done:** release evidence `fa2aab2` RC audit **go** **Next:** human sign-off

**Lane 4 — Done:** F5 phase 0 **Next:** gossip phase 1

---

## Session — 2026-07-12 (F5 fraud-proof phase 0 + header_version smoke)

| Unit | Status | Notes |
| --- | --- | --- |
| **F5 fraud-proof phase 0** | **This push** | body-root verify + P2P tag `0x13` + rehearsal smoke |
| **genesis-header-version-rehearsal-smoke** | **Done** — `22549d7` | Path A v1 + Path B v2 doc gate |

**Lane 4 — Doing:** F5 fraud-proof phase 0 **Next:** push after CI `#29210840888` green; phase 1 gossip

---

## Session — 2026-07-12 (genesis header_version rehearsal)

| Unit | Status | Notes |
| --- | --- | --- |
| **header_version genesis threading** | **Done** — `dbad44d` | PROBLEMS §12 genesis-threaded; CI `#29209302385` in progress |
| **genesis-header-version-rehearsal-smoke** | **Done** — `22549d7` | Path A v1 pin + Path B v2 doc gate |

**Lane 4+7 — Doing:** rehearsal smoke **Next:** human TL-5 VPS soak after CI green

---

## Session — 2026-07-12 (TL-6 participant evidence assert)

| Unit | Status | Notes |
| --- | --- | --- |
| **assert-vps-participant-rehearsal-evidence** | **Done** — `11a2d07` | TL-6 transcript audit + launch-status fixture gate |

**Lane 7 — Done:** software path complete **Next:** human TL-5 VPS soak

---

| Unit | Status | Notes |
| --- | --- | --- |
| **vps-internet-soak-evidence-rehearsal-smoke** | **Done** — `78d236c` | assert + launch-status fixture gate (fixes ci-check) |
| **TL-9 checkpoint Schnorr** | **Done** — `d04afed` | `launch-go-no-go` verifies JSONL when seeds>=3 |
| **F12 demo live** | **Done** — `8b4f0ee` | `--live` sign + CLI + wasm checkpoint_log_core |

**Lane 5 — Done:** P32 4e + F12 live **Next:** human VPS rehearsal

**Lane 7 — Done:** software path **Next:** human TL-5 VPS soak

---

## Session — 2026-07-11 (P32 phase 4b PM23 + TL-8 checkpoint publish rehearsal)

| Unit | Status | Notes |
| --- | --- | --- |
| **P32 phase 4b** | **This push** | `mfnd_pm23_warning` + `mfn_storage_operator_pm23_warning`; `MFND_PM23_HARD_FAIL=1` |
| **publish-checkpoint-log-rehearsal-smoke** | **This push** | doc cross-links + plan-only gate in ci-check + GHA |

**Lane 5 — Doing:** PM23 runtime lint **Next:** hard-fail default on VPS (research)

**Lane 7 — Doing:** TL-8 checkpoint publish rehearsal **Next:** human TL-5 VPS soak

---

| Unit | Status | Notes |
| --- | --- | --- |
| **vps-execution-checklist v2** | **Done** — `c1f9597` | TL-7/TL-8 commands; ci-check + GHA wiring; CI `#29165580894` GREEN |
| **vps-preflight-rehearsal-smoke** | **Done** — wired in `c1f9597` | ci-check + GHA gates (scripts from `9da922a`) |
| **testnet-invite-rehearsal-smoke** | **Done** — wired in `c1f9597` | ci-check + GHA gates (scripts from `9da922a`) |

**Lane 1 — Done:** CI `#29165580894` GREEN **Next:** Nightly on head

**Lane 2 — Done:** release evidence `c1f9597` RC audit **go** **Next:** human sign-off

**Lane 7 — Done:** TL-8 software gates **Next:** human TL-5 VPS soak

---

## Session — 2026-07-10 (TL-8 invite + checklist v2)

| Unit | Status | Notes |
| --- | --- | --- |
| **testnet-invite-rehearsal-smoke** | **Done** — `9da922a` | TESTNET_INVITE.md genesis + privacy gates |
| **vps-preflight-rehearsal-smoke** | **Done** — `9da922a` | TL-5 preflight docs + script wiring gate |
| **vps-execution-checklist v2** | **Done** — `c1f9597` | TL-7/TL-8 publish + invite commands in checklist JSON |

---

| Unit | Status | Notes |
| --- | --- | --- |
| **Board sync** | **Done** — `648676b` | Nightly `#29090091058` GREEN; CI `#29088674668` GREEN; release evidence refresh |

**Lane 1 — Done:** Nightly `#29090091058` GREEN **Next:** soak maintenance

**Lane 2 — Done:** release evidence `648676b` RC audit **go** **Next:** human sign-off packet

---

## Session — 2026-07-10 (board sync 09edd8a)

| Unit | Status | Notes |
| --- | --- | --- |
| **Board sync** | **Done** — `09edd8a` | Nightly `#29088007044` GREEN; CI `#29086333628` GREEN; release evidence refresh |

**Lane 1 — Done:** Nightly `#29088007044` GREEN **Next:** soak maintenance

**Lane 2 — Done:** release evidence `09edd8a` RC audit **go** **Next:** human sign-off packet

---

## Session — 2026-07-10 (TL-7/TL-8 rehearsal + F12 demo web)

| Unit | Status | Notes |
| --- | --- | --- |
| **publish-seed-nodes-rehearsal-smoke** | **Done** — `05e2772` | fixture dry-run via `vps-bind.env.example` + doc gates |
| **vps-launch-ceremony-rehearsal-smoke** | **Done** — `05e2772` | `vps-launch-ceremony.sh --plan-only` TL-5..TL-9 ordering gate |
| **F12 phase 5 demo web** | **Done** — `05e2772` | `checkpointLogVerify` / `checkpointLogCrossCheck` UI in `demo/web` |
| **demo-web-f12-rehearsal-smoke** | **Done** — `05e2772` | ci-check + GHA wiring gate; CI `#29082197263` GREEN |

**Lane 1 — Done:** Nightly `#29085709944` GREEN on `fac313a` **Next:** soak maintenance

**Lane 2 — Done:** release evidence `fac313a` RC audit **go** **Next:** human sign-off packet

**Lane 7 — Done:** TL-7/TL-8 software gates **Next:** human TL-5 VPS soak

---

| Unit | Status | Notes |
| --- | --- | --- |
| **TL-5 soak rehearsal** | **Done** — `4688735` | `vps-internet-soak-rehearsal-smoke.*` — docs + script wiring gate |
| **TL-6 participant rehearsal** | **Done** — `4688735` | `vps-participant-rehearsal-rehearsal-smoke.*` — wrapper + evidence pattern gate |

**Lane 1 — Done:** Nightly `#29081319938` GREEN on `4688735` stack

---

## Session — 2026-07-10 (TL-9 launch-go-no-go rehearsal smoke)

| Unit | Status | Notes |
| --- | --- | --- |
| **launch-go-no-go-rehearsal-smoke** | **Done** — `bbc57a1` | plan-only CI gate on pre-launch `launch-go-no-go.v1` JSON |

**Lane 1 — Done:** Nightly `#29077379017` GREEN **Next:** human VPS TL-5 soak (lane 7)

---

## Session — 2026-07-10 (checklist rehearsal + F6 economics tail)

| Unit | Status | Notes |
| --- | --- | --- |
| **vps-execution-checklist-rehearsal-smoke** | **Done** — `8a49f7e` | ci-check + GHA gate on checklist v1 JSON + OPERATORS links |
| **F6 tail split (docs)** | **Done** — `9a2673a` | `FEES.md` §5.4 approves 10% subsidy tail → treasury |
| **F6 Arweave comparison** | **Done** — `bff1b70` | `ECONOMICS.md` §12 durability comparison |

**Lane 1 — Doing:** CI `#29073823035` **Next:** release evidence + Nightly on green

---

## Session — 2026-07-10 (TL-5 VPS execution checklist v2)

| Unit | Status | Notes |
| --- | --- | --- |
| **TL-5 checklist v2** | **Done** — `f6f7e22` | checkpoint-log warning; treasury-telemetry + PM23 rehearsal; OPERATORS.md |

---

## Session — 2026-07-10 (P32 phase 4a PM23 + F6 treasury telemetry)

| Unit | Status | Notes |
| --- | --- | --- |
| **P32 phase 4a** | **Done** — `808529a` | `pm23-operator-manifest-rehearsal-smoke`; role env separation gate |
| **F6 telemetry** | **Done** — `808529a` | `treasury-telemetry-watch.*`; `launch-status-rehearsal-smoke` v4 |

**Lane 1 — Doing:** Nightly `#29071784488` on `808529a` **Next:** soak maintenance

---

## Session — 2026-07-10 (OPERATORS + VPS checklist TL-8 hints)

| Unit | Status | Notes |
| --- | --- | --- |
| **OPERATORS cross-links** | **This push** | launch-status, vps-execution-checklist, treasury-telemetry, PM23 rehearsal |
| **vps-execution-checklist** | **This push** | TL-8 checkpoint log warning when TL-6 evidence present; treasury/PM23 command hints |

**Lane 7 — Done:** checklist polish **Next:** TL-5 VPS soak (human)

---

## Session — 2026-07-10 (P32 phase 4a PM23 + F6 treasury telemetry)

| Unit | Status | Notes |
| --- | --- | --- |
| **launch-status v4** | **Done** — `895ac1e` | TL-8 checkpoint log entry count + verify; launch-go-no-go gate |
| **GHA gh fix** | **Done** — `6b884ea` | `GH_TOKEN` from `GITHUB_TOKEN`; suppress gh stderr on Windows GHA |

**Lane 1 — Next:** Nightly dispatch on `6b884ea` stack

---

## Session — 2026-07-10 (P32 phase 3 + F6 fee economics + CI fix)

| Unit | Status | Notes |
| --- | --- | --- |
| **P32 phase 3** | **Done** — `7d39f4c` | `observer_loopback_rpc_hint_warning`; `mfnd_serve` startup hint |
| **F6 fee docs** | **Done** — `d4a5114` | [`FEES.md`](docs/FEES.md); `ECONOMICS.md` operator-direct payout sync |
| **CI fix** | **Done** — `35c4c7f` | grep `--` for `--checkpoint-log` needle in bash smoke |

**Lane 1 — Done:** CI `#29064435999` GREEN **Next:** Nightly on `6b884ea` after `#29066731152`

---

## Session — 2026-07-10 (F12 phase 4 — TL-8 publish tooling + live rehearsal)

| Unit | Status | Notes |
| --- | --- | --- |
| **F12 phase 4** | **Done** — `5965525` | `checkpoint-log cross-check`; `publish-checkpoint-log.*`; live rehearsal smoke |

**Lane 4+6 — Done:** F12 phase 4 **Next:** TL-8 `--apply` on VPS after TL-7

---

## Session — 2026-07-09 (F12 phase 3 — WASM checkpoint log parity)

| Unit | Status | Notes |
| --- | --- | --- |
| **F12 phase 3** | **Done** — `5d78329` | `mfn-checkpoint-log`; WASM `checkpointLogVerify` / `checkpointLogCrossCheck` |

**Lane 4+6 — Done:** F12 phase 3 **Next:** TL-8 publish signed log at invite

---

## Session — 2026-07-09 (P32 phase 2 — VPS role env templates)

| Unit | Status | Notes |
| --- | --- | --- |
| **P32 phase 2** | **Done** — `db58ae1` | `vps-role-*.env.example`; OPERATORS.md cross-links; rehearsal smoke template gate |

**Lane 5 — Done:** P32 phase 2 **Next:** TL-5 VPS internet soak (human)

---

## Session — 2026-07-09 (F12 phase 2 — light-scan log cross-check)

| Unit | Status | Notes |
| --- | --- | --- |
| **F12 phase 2** | **Done** — `10e606e` | `wallet light-scan --checkpoint-log`; `cross_check_summary_against_checkpoint_log` |

**Lane 4+5 — Done:** F12 phase 2 **Next:** WASM light client parity / TL-8 log publish

---

## Session — 2026-07-09 (F12 phase 2 — light-scan log cross-check)

| Unit | Status | Notes |
| --- | --- | --- |
| **F12 phase 2** | **Done** — `10e606e` | `wallet light-scan --checkpoint-log`; `cross_check_summary_against_checkpoint_log`; docs + rehearsal smoke |

**Lane 4+5 — Done:** F12 phase 2 **Next:** TL-5 VPS soak (human) / WASM light client parity

---

## Session — 2026-07-09 (F12.1 — signed checkpoint log)

| Unit | Status | Notes |
| --- | --- | --- |
| **F12 phase 1** | **This push** | `checkpoint_log.rs`; `mfn-cli checkpoint-log sign|verify`; [`CHECKPOINT_LOG.md`](docs/CHECKPOINT_LOG.md) |

**Lane 4+5 — Doing:** F12.1 **Next:** wallet light-scan log cross-check (phase 2)

---

## Session — 2026-07-09 (F12 phase 1 — signed checkpoint log)

| Unit | Status | Notes |
| --- | --- | --- |
| **F12 phase 1** | **This push** | `mfn-cli checkpoint-log sign|verify`; [`CHECKPOINT_LOG.md`](docs/CHECKPOINT_LOG.md); `checkpoint-log-rehearsal-smoke.*` in ci-check |

**Lane 4+5 — Doing:** F12 phase 1 **Next:** light-scan log compare (phase 2)

---

## Session — 2026-07-09 (P32.1 — reference topology doc)

| Unit | Status | Notes |
| --- | --- | --- |
| **P32 phase 1** | **Done** — `85f3512` | [`REFERENCE_TOPOLOGY.md`](docs/REFERENCE_TOPOLOGY.md); `reference-topology-rehearsal-smoke.{sh,ps1}`; ci-check + DECENTRALIZATION cross-link |

**Lane 4+5 — Done:** P32.1 **Next:** F12 signed checkpoint log phase 1 (research) or TL-5 VPS

---

## Session — 2026-07-09 (F12 — checkpoint anchor peers phase 0)

| Unit | Status | Notes |
| --- | --- | --- |
| **F12 phase 0** | **Done** — `0cf73c6` | `anchor_peers` in trusted summary + `get_light_snapshot`; `checkpoint_anchor_peer_candidates`; `--p2p-anchor-summary`; harness `mfnd_p2p_anchor_peers_merged` |

**Lane 4+5 — Done:** F12 phase 0 **Next:** P32 reference topology doc

---

## Session — 2026-07-09 (P31.1 — diversity redial)

| Unit | Status | Notes |
| --- | --- | --- |
| **P31 phase 1** | **Done** — `571e0bf` | `peer_diversity_redial_candidates`; `spawn_peer_diversity_redial_loop`; `MFND_P2P_DIVERSITY_REDIAL`; harness `mfnd_p2p_diversity_redial_start` |

**Lane 4+5 — Done:** P31.1 **Next:** F12 checkpoint anchor peers

---

## Session — 2026-07-09 (P32 — role topology lint phase 0)

| Unit | Status | Notes |
| --- | --- | --- |
| **P32 phase 0** | **Done** — `f76991a` | `role_topology.rs`; `mfnd_role_topology_warning` when validator + public RPC (+ operator) colocate; loopback RPC exempt |

**Lane 4+5 — Done:** P32 phase 0 **Next:** reference topology doc

---

## Session — 2026-07-09 (P31 — peer diversity phase 0)

| Unit | Status | Notes |
| --- | --- | --- |
| **P31 phase 0** | **Done** — `d3cc1be` | `mfn-net::peer_diversity`; `get_status.p2p` diversity fields; `mfnd_p2p_diversity_warning`; env `MFND_P2P_MIN_DISTINCT_PREFIX16` |

**Lane 4+5 — Done:** P31 phase 0 **Next:** automatic redial on low diversity

| Unit | Status | Notes |
| --- | --- | --- |
| **B8.3** | **Done** — `5e540b3` | `mfn-cli --tor` / `MFN_CLI_RPC_TOR`; quorum RPC peers mirror Tor mode; cleartext rejects `.onion` without `--tor`; [`TOR_P2P.md`](docs/TOR_P2P.md) § B8.3 |

**Lane 4+5 — Done:** B8.3 **Next:** embedded `arti` listener (research)

---

## Session — 2026-07-09 (B8.2 — onion P2P)

| Unit | Status | Notes |
| --- | --- | --- |
| **B8.2** | **Done** — `b845d22` | SOCKS5 domain connect; `MFND_P2P_ONION`; CI `#29016552175` matrix green (workflow cancelled on dispatch runner starvation) |
| **Nightly `#29013333776`** | **Dispatched** | checkout `759f5d1` (pre-B8.2) |
| **CI `#29011529403`** | **GREEN** | `759f5d1` fmt + checklist |

**Lane 4+6 — Done:** B8.2 **Next:** B8.3 wallet submit `--tor`  
**Lane 7 — Next:** TL-5 VPS soak (blocked on human VPS provision)

---

| Unit | Status | Notes |
| --- | --- | --- |
| **B8.1** | **Done** — `b6eba33` | `mfn-net::socks5` CONNECT client; Tor transport routes via `MFND_TOR_SOCKS5` |
| **mfnd serve** | **This push** | Tor warning when SOCKS5 must be reachable |

**Lane 4+6 — Doing:** B8.1 **Next:** B8.2 inbound hidden service  
**Lane 1 — Doing:** CI after push **Next:** Nightly dispatch  
**Lane 7 — Blocked:** VPS provision for TL-5

---

| Unit | Status | Notes |
| --- | --- | --- |
| **B8.0** | **Done** — `419e38a` | `mfn-net::transport`; `MFND_P2P_TRANSPORT` / `MFND_TOR_SOCKS5`; Tor stub returns Unsupported |
| **mfnd serve** | **This push** | `mfnd_p2p_transport=…` harness line on P2P enable |
| **Nightly dispatch** | **This push** | `dispatch-rc-workflows.sh` resolves short SHA → full `git rev-parse` |

**Lane 4+6 — Doing:** B8.0 **Next:** B8.1 SOCKS5 outbound dial  
**Lane 1 — Doing:** CI on push **Next:** Nightly with full SHA  
**Lane 7 — Blocked:** VPS provision for TL-5

---

| Unit | Status | Notes |
| --- | --- | --- |
| **vps-preflight** | **Done** — `375f4d0` | Validates `require_endowment_range_proof=1` + `mfn-storage-operator` binary |
| **launch-go-no-go.ps1** | **Done** — `375f4d0` | Local MFER rehearsal WARN parity with bash |
| **B8 plan** | **Done** — `375f4d0` | Phased B8.0–B8.3 table in `PRIVACY_HARDENING.md` |
| **RC evidence** | **Done** — `19dc111` | `release-evidence-19dc111` + RC audit **go** |

**Lane 7 — Doing:** VPS preflight hardening **Next:** TL-5 execution (human VPS)  
**Lane 4+6 — Doing:** B8 research plan **Next:** B8.0 transport trait skeleton  
**Lane 1 — Doing:** Nightly dispatch **Next:** soak maintenance

---

| Unit | Status | Notes |
| --- | --- | --- |
| **launch-status v4** | **Done** — `895ac1e` | TL-8 checkpoint log tracking + go/no-go gate when seed_nodes published |
| **launch-status v3** | **Done** — prior push | Local MFER rehearsal gates, release evidence, RC audit go; phase → "local RC complete — provision VPS" |
| **permanence-demo.sh** | **Done** | `stop_orphan_chunk_servers` + `remove_stale_log` parity with `.ps1` |
| **launch-go-no-go** | **Done** | WARN when TL-5/TL-6 missing but local MFER rehearsals PASS |
| **CI `#29005580975`** | **GREEN** | `daa8e8e` board sync on `main` |

**Lane 7 — Done:** launch-status v4 (`895ac1e`) **Next:** TL-5 VPS execution (human provision)  
**Lane 1 — Doing:** CI on `daa8e8e` **Next:** push Lane 7 ops after green  
**Lane 3 — Done:** local rehearsals **Next:** TL-6 on VPS

---

## Session — 2026-07-09 (M4.8 tail — WASM MFER integration test)

| Unit | Status | Notes |
| --- | --- | --- |
| **M4.8 tail** | **Done** — `b3f56a6` | `wasm_storage_upload_attaches_mfer_when_range_proof_required`; observer rehearsal evidence |
| **Observer rehearsal** | **Done** | `participant-rehearsal-observer-windows-20260709T080708Z.txt` |
| **Ops `7dba698`** | **Done** | CI cancelled by concurrent push; superseded by `b3f56a6` |

**Lane 4+6 — Doing:** M4.8 tail **Next:** push after CI green  
**Lane 3 — Doing:** observer MFER rehearsal

---

## Session — 2026-07-09 (M4.8 / B1 2e — WASM MFER + rehearsal evidence)

| Unit | Status | Notes |
| --- | --- | --- |
| **M4.8 / B1 2e** | **Done** — `bbe1d9f` | WASM upload merges live endowment flags; CI `#28999593529` GREEN |
| **MFER rehearsal** | **Done** | `participant-rehearsal-no-observer-windows-20260709T070005Z.txt`; upload+prove+support-bundle PASS |
| **Demo log-lock fix** | **This push** | `permanence-demo.ps1` stale-log + orphan chunk-server cleanup |

**Lane 3 — Done:** MFER rehearsal **Next:** TL-6 VPS  
**Lane 2 — Doing:** release evidence on `bbe1d9f`

---

## Session — 2026-07-09 (B1 phase 2d — public devnet MFER flip)

| Unit | Status | Notes |
| --- | --- | --- |
| **B1 phase 2d** | **Done** — `2958cfa` | `require_endowment_range_proof: 1`; same `genesis_id`; forged-blinding reject test |
| **B1 CI #28995960877** | **GREEN** | Full matrix on `2958cfa` (~35m); soak + Nightly dispatch queued |
| **B1 track** | **Complete** | 2a param → 2b wire → 2c wallet → 2d devnet enable |

**Lane 4+6 — Done:** B1 **Next:** RC evidence (lane 2)  
**Lane 1 — Doing:** Nightly on `2958cfa` **Next:** soak maintenance  
**Lane 3 — Doing:** MFER participant-rehearsal smoke evidence

---

## Session — 2026-07-08 (B1 phase 2c — wallet MFER proof build)

| Unit | Status | Notes |
| --- | --- | --- |
| **B1 phase 2c** | **Done** — `ba53a15` | wallet MFEX v3 + `build_endowment_surplus_range_proof`; unit test |
| **B1 CI #28992802103** | **In progress** | 2c matrix on `ba53a15` |
| **B1 2b** | **Done** — `c084537` | CI `#28989926744` GREEN |

**Lane 4+6 — Done:** B1 2c `ba53a15` **Doing:** forged MFER reject test **Next:** B1 2d devnet flip  
**Lane 1 — Doing:** CI `#28992802103` **Next:** Nightly after green

---

## Session — 2026-07-08 (B7 chunk-inbox disk quota)

| Unit | Status | Notes |
| --- | --- | --- |
| **B7 inbox quota** | **Done** — `930b166` | `MFND_CHUNK_INBOX_MAX_BYTES`; LRU evict incomplete dirs; protect complete sets |
| **CI #28986986012** | **In progress** | Pushed; awaiting full matrix |

**Lane 4+6 — Done:** B5 `1485e67` **Doing:** B7 CI **Next:** B1 opening reveal  
**Lane 1 — Done:** CI `#28983986309` **Doing:** CI on B7 **Next:** Nightly dispatch

---

## Session — 2026-07-08 (B5 phase 5d — M5.51 + public devnet slash enable)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5d** | **Done** — `1485e67` | M5.51 proptests; devnet cap=48 slash=250; CI `#28983986309` GREEN |
| **Nightly #28980876807** | **GREEN** | All 3 jobs on `8bdb4ab` stack |
| **Local CI** | **GREEN** | `ci-check.ps1` on `1485e67` |

**Lane 4+6 — Done:** B5 complete **Doing:** push **Next:** B6 size buckets  
**Lane 1 — Done:** Nightly `#28980876807` **Doing:** CI on 5d push **Next:** soak maintenance

---

## Session — 2026-07-08 (B5 phase 5c — slash → treasury + deregister)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5c** | **Done** — `8bdb4ab` | Auto-slash on miss cap; treasury credit; zero-bond deregister |
| **CI #28979369780** | **GREEN** | `8bdb4ab` full matrix (~31m) |

**Lane 4+6 — Done:** B5 5c `8bdb4ab` **Doing:** — **Next:** B5 5d M5 proptests + devnet  
**Lane 1 — Done:** CI `#28979369780` **Doing:** Nightly dispatch **Next:** soak maintenance

---

## Session — 2026-07-08 (B5 phase 5c — slash execution + clippy fix)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5c** | **This push** | Slash on miss cap → treasury; zero-bond deregister; clippy `or_default` |
| **CI #28977215094** | **FAIL** | clippy on `643a224` — fixed locally |

**Lane 4+6 — Done:** B5 5b `643a224` **Doing:** 5c push **Next:** B5 5d devnet enable  
**Lane 1 — Doing:** CI re-run on 5c head **Next:** Nightly dispatch

---

## Session — 2026-07-08 (B5 phase 5b — retained bond + miss stats)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5b** | **This push** | Retained register bond; `StorageOperatorStats`; checkpoint **v9**; pre-proof stale challenge gate |
| **CI #28977215094** | **In progress** | `643a224` B5 5b stack |

**Lane 4+6 — Done:** B5 5a `e81d33e` **Doing:** B5 5b push **Next:** B5 5c slash → treasury  
**Lane 1 — Done:** full RC stack **Doing:** CI on B5 stack **Next:** Nightly re-dispatch

---

## Session — 2026-07-08 (B5 phase 5a — inert slash params + checkpoint v8)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5a** | **This push** | `operator_audit_missed_cap` + `operator_slash_bps` in `EndowmentParams`; checkpoint **v8**; [`B5_OPERATOR_SLASHING.md`](docs/B5_OPERATOR_SLASHING.md) |
| **CI** | **Pending** | Local `ci-check.ps1` before push |
| **Nightly** | **Pending** | Re-dispatch after green CI |

**Lane 4+6 — Done:** B4 `89f3498`, Nightly `#28970179853` **Doing:** B5 phase 5a push **Next:** B5 phase 5b retained bond + miss accounting  
**Lane 1 — Done:** full RC stack green **Doing:** CI on B5 push **Next:** Nightly re-dispatch

| Unit | Status | Notes |
| --- | --- | --- |
| **B4 phase 1** | **Done** — `89f3498` | `p2p_repair_sweep.rs`; stale inbox re-fan-out; `MFND_REPAIR_*` env |
| **CI #28966851917** | **GREEN** | `0ede433` M2.5.66 + M5.50 (~28m) |
| **CI #28968642140** | **GREEN** | `89f3498` B4 (~26m) |
| **Nightly #28968584904** | **GREEN** | All 3 jobs on `0ede433` M2.5.66 stack (~7m) |
| **Nightly #28970179853** | **GREEN** | All 3 jobs on B4 stack (`89f3498` ancestor) |
| **Release evidence** | **Done** | `release-evidence-1c633e7` + RC audit **go** |

---

## Session — 2026-07-08 (B5 operator slashing — phase 5a design)

| Unit | Status | Notes |
| --- | --- | --- |
| **B5 phase 5a** | **In progress** | `docs/B5_OPERATOR_SLASHING.md`: retained escrow, miss stats, checkpoint v8 sketch, griefing |
| **Critical gap** | **Documented** | B3 register burns bond to treasury — 5b must change to slashable collateral |
| **CI #28970409945** | **In progress** | `f804ac1` OPERATORS + board sync (docs-only) |

**Lane 4+6 — Done:** B4 `89f3498` **Doing:** B5 phase 5a design **Next:** B5 phase 5b retained escrow  
**Lane 1 — Done:** dual Nightly GREEN **Doing:** monitor CI `#28970409945` **Next:** idle

---

## Session — 2026-07-08 (B4 proactive repair sweep)

| Unit | Status | Notes |
| --- | --- | --- |
| **M2.5.66** | **Done** — `0ede433` | `vps_export_binds` if/fi; hub bind defaults; `vps-bind-lib-smoke.sh` in CI |
| **M5.50** | **Done** — `0ede433` | `prop_b3_duplicate_operator_rejects_after_prefix` + replication-cap reject tests |
| **CI #28966851917** | **In progress** | `0ede433` matrix |
| **Nightly #28962813486** | **FAIL** | Pre-M2.5.66 `start_mesh_fail`; re-dispatch after green CI |

**Lane 1 — Done:** root-cause **Doing:** push M2.5.66 **Next:** Nightly green  
**Lane 4+6 — Done:** 3c `65aea81` **Doing:** M5.50 push **Next:** B4 repair sweep

---

| Unit | Status | Notes |
| --- | --- | --- |
| **Root cause** | **Found** | `[[ -n ... ]] && export` in `vps_export_binds` aborts `start-all` under `set -e` when VPS binds unset |
| **Fix** | **This push** | `if/fi` exports + hub bind defaults in `start-all`; `vps-bind-lib-smoke.sh` |
| **Nightly #28961041302** | **FAIL** | `start_mesh_fail` ~1s — no v0.log (exit before hub launch) |
| **B3 phase 3c** | **Done** — `65aea81` | Genesis operator seeding + public devnet enable |

**Lane 1 — Done:** root-cause **Doing:** CI + push **Next:** Nightly re-dispatch

---

## Session — 2026-07-08 (B3 phase 3c — genesis operator seeding)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3c** | **Done** — `65aea81` | Genesis `storage_operators[]`; `apply_genesis` seed; public devnet B3 flags; rehearsal replica seed |
| **CI #28952620476** | **In progress** | `8b4e163` matrix (monitor lane 1) |
| **Board sync** | **Done** — `567da3d` local | Push after CI green |

**Lane 4+6 — Done:** 3b `8b4e163` **Doing:** 3c genesis seeding **Next:** M5 proptest duplicate-operator reject

---

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **Done** — `8b4e163` | `StorageOperatorOp::Register`; Schnorr; `bond_section_merkle_root`; checkpoint **v7**; mesh startup fix |
| **Local CI** | **GREEN** | `ci-check.ps1` run2 ~54m |
| **GitHub CI** | **In progress** | `#28952620476` on `8b4e163` |
| **B3 phase 3c** | **Next** | Genesis spec operator seeding + devnet enable |

**Lane 4+6 — Done:** 3b **Doing:** — **Next:** 3c genesis seeding

---

## Session — 2026-07-08 (B3 phase 3b — CI gate + push)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **In progress** — local CI | `StorageOperatorOp::Register`; Schnorr spend-key auth; `bond_section_merkle_root`; checkpoint **v7**; block wire 5th section |
| **Codec tests** | **Done** | `block_codec_*` updated for 311-byte empty block; legacy decode at `header+4` |
| **B3 phase 3c** | **Next** | Genesis spec operator seeding + devnet enable |
| **Nightly #28940474074** | **FAIL** | `start_mesh_fail` (~1s) — lane 1 follow-up after push |

**Lane 4+6 — Done:** codec fix **Doing:** `ci-check.ps1` **Next:** commit + push + 3c

---

## Session — 2026-07-08 (B3 phase 3b — StorageOperatorOp register wire)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **Done** — this push | `StorageOperatorOp::Register`; Schnorr spend-key auth; `bond_section_merkle_root`; checkpoint **v7** |
| **B3 tests** | **Done** | `b3_storage_operator_register_wire_accepted` + duplicate reject |
| **B3 phase 3c** | **Next** | Genesis spec operator seeding + devnet enable |

**Lane 4+6 — Done:** B3 phase 3b **Doing:** CI + push **Next:** genesis seeding (3c)

---

## Session — 2026-07-08 (B3 phase 3b — StorageOperatorRegister wire + bond_root)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3b** | **This push** | `StorageOperatorOp::Register` Schnorr wire; `bond_section_merkle_root`; `apply_storage_operator_ops`; checkpoint **v7** (`min_storage_operator_bond`); block wire section; 2× `block_apply` register tests |
| **Nightly #28940474074** | **FAIL** | `start_mesh_fail` (~1s) — hub exit before v0.log; investigate lane 1 (not F7 fund-wallet) |
| **Release evidence** | **Done** — `1b6caba` + RC audit **go** | Refresh again after 3b CI green |

**Lane 4+6 — Done:** 3a `99754b8` **Doing:** 3b push + CI **Next:** genesis operator seeding (3c)

---

## Session — 2026-07-08 (B3 phase 3a — operator registry + apply_block gate)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 3a** | **Done** — `99754b8` | `require_registered_operators`; `storage_operators` map; checkpoint **v6**; `StorageProofUnregisteredOperator`; 2× `block_apply` registry tests |
| **CI #28935445273** | **GREEN** | Full matrix ~1h30m on `99754b8` |
| **B3 phase 3b** | **Next** | Signed `StorageOperatorRegister` + bond escrow wire |

**Lane 4+6 — Done:** B3 phase 3a **Doing:** push + CI **Next:** operator register bond op (3b)

---

## Session — 2026-07-08 (CI script fix + B3 M5.40 proptest)

| Unit | Status | Notes |
| --- | --- | --- |
| **Ubuntu scripts CI** | **Fix** — this push | `participant-rehearsal-smoke.sh` plan flow `start-all` not `start-all.sh` |
| **M5.41** | **Done** — this push | `prop_b3_two_operator_proof_chain_treasury` (1–8 blocks) |
| **B3 phase 3 design** | **Seed** | Operator registry sketch in `PERMANENCE_HARDENING.md` |

**Lane 4+6 — Done:** M5.41 proptest **Next:** operator registry wire

---

## Session — 2026-07-08 (B3 treasury settlement + clippy fix)

| Unit | Status | Notes |
| --- | --- | --- |
| **Clippy** | **Fix** — this push | `manual-range-patterns` in checkpoint decode (`3..=5`) |
| **B3 treasury** | **Done** — this push | `storage_proof_operator_settlements` mirrors `apply_block`; proptest treasury identity |
| **CI #28933248309** | **Failed** clippy | Superseded by this push |

**Lane 4+6 — Done:** B3 treasury mirror **Doing:** — **Next:** operator bonding registry

---

## Session — 2026-07-08 (B3 phase 2 — apply_block replication accounting)

| Unit | Status | Notes |
| --- | --- | --- |
| **B3 phase 2** | **Done** — this push | `operator_salted_challenges` flag; per-operator dedup; replication cap; payout split; checkpoint v5 |
| **B3 tests** | **Done** | 4× `block_apply` B3 tests; clippy + fmt green |
| **CI** | **Monitor** | Prior `#28930546797` on `eea59aa`; this push dispatches new matrix |

**Lane 4+6 — Done:** B3 phase 2 **Doing:** — **Next:** operator bonding registry + M5 proptests

---


| Unit | Status | Notes |
| --- | --- | --- |
| **TL-5 scripts** | **Done** — `5a74d57` | `vps-preflight.sh`, `vps-internet-soak.sh`, `soak.sh --vps`, `vps-bind-lib.sh` |
| **TL-5 execution** | **Blocked** | Requires provisioned Linux VPS + `vps-bind.env` |
| **CI** | **Monitor** | Push `5a74d57` stack (`b70b3ec`/`dc22cb7`/`5a74d57`) |

**Lane 7 — Done:** TL-1–TL-5 tooling **Doing:** await VPS **Next:** `vps-internet-soak.sh` + archive evidence

---

## Session — 2026-07-08 (F7 fund-wallet top-up → Nightly rehearsal fix)

| Gate | Status | Notes |
| --- | --- | --- |
| **fund-wallet F7** | **Done** — `dc22cb7` | `--min-owned-count 2` default; top-up until `owned_count>=2` |
| **CI #28929146881** | **In progress** | `dc22cb7` — closes Nightly upload 1-input failure |
| **CI #28924060054** | **GREEN** | `e7d74f7` full F7 test tail |

**Lanes 1+3 — Done:** CI green, TL-4 VPS `2f77eb4` **Doing:** fund-wallet F7 top-up **Next:** push → Nightly re-dispatch → TL-5 VPS soak

---

| Unit | Status | Notes |
| --- | --- | --- |
| **CI #28924060054** | **GREEN** | `e7d74f7` — full matrix ~48m; closes TL-2 |
| **TL-3 evidence** | **Done** | `release-evidence-46677ad` + RC audit dry-run `go` |
| **TL-4 VPS runbook** | **Done** — `2f77eb4` | `vps-start-all.sh`, `VPS_SINGLE_BOX_LAUNCH.md`, P2P bind env |

**Lane 7 — Done:** TL-1–TL-4 **Doing:** *(idle — VPS provision)* **Next:** TL-5 internet soak

---

## Session — 2026-07-08 (F7 mempool tail → CI `#28924060054`)

| Gate | Status | Notes |
| --- | --- | --- |
| **mempool F7** | **Done** — `e7d74f7` | `mfn-runtime` test helpers: companion pad + two-input `signed_tx` / `signed_storage_tx` |
| **CI #28924060054** | **GREEN** | `e7d74f7` — full matrix pass |
| **Prior CI #28921758809** | **Cancelled** | `0825385` — superseded by mempool fix push |

**Lanes 1–3 — Done:** mempool `e7d74f7`, CI `#28924060054` GREEN, TL-3 evidence **Doing:** TL-4 VPS (lane 7) **Next:** Nightly (lane 1) → TL-5 soak (lane 7) → B3 (lanes 4+6)

---

## Session — 2026-07-08 (F7 mfnd_smoke tail → CI `#28921758809`)

| Gate | Status | Notes |
| --- | --- | --- |
| **mfnd_smoke F7** | **Done** — `0825385` | `synth_decoy_*` fixture: `step --blocks 2` → two UTXOs → two-input transfer |
| **CI #28921758809** | **In progress** | `0825385` — clippy/rustfmt/audit/wasm/scripts GREEN; matrix tests running |
| **Prior CI #28919128030** | **Failed** | `996f60f` — 5 mfnd_smoke mempool/P2P tests: 1-input txs rejected |

**Lanes 1–3 — Done:** settlement `996f60f`, mfnd_smoke `0825385` **Doing:** CI monitor `#28921758809` **Next:** release evidence (lane 2) → Nightly (lane 1) → B3 (lanes 4+6)

---

## Session — 2026-07-08 (F7 settlement tail → CI `#28919128030`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 settlement tests** | **Done** — `996f60f` | `producer_treasury_settlement.rs` two-input pad recycle across all call sites |
| **CI #28919128030** | **In progress** | `996f60f` — clippy/rustfmt/scripts GREEN; matrix tests running |
| **Prior CI #28917267975** | **Failed** | `a6aebab` — settlement still 1-input (fixed by `996f60f`) |

**Lanes 1–3 — Done:** F7 settlement `996f60f`, TL-1 charter `8661106` **Doing:** CI monitor `#28919128030` **Next:** release evidence (lane 2) → Nightly (lane 1) → B3 (lanes 4+6)

---

## Session — 2026-07-08 (Lane 7 TL-2 — mempool F7 two-input pad)

| Unit | Status | Notes |
| --- | --- | --- |
| **TL-2 mempool fix** | **Done** — `e7d74f7` | `mfn-runtime` test helpers: companion pad + two-input `signed_tx` |
| **CI #28924060054** | **In progress** | `e7d74f7` full matrix |
| **Prior** | **Done** | `996f60f` settlement + `0825385` mfnd_smoke |

**Lane 7 — Done:** TL-1 (`8661106`), mempool `e7d74f7` **Doing:** TL-2 CI monitor **Next:** TL-3 release evidence on green head

---

## Session — 2026-07-08 (Lane 7 testnet launch — TL-1)

| Unit | Status | Notes |
| --- | --- | --- |
| **Lane 7 charter** | **Done** — `8661106` | `docs/TESTNET_LAUNCH.md`, `launch-status.*`, `.cursor/rules/lane-7-testnet-launch.mdc` |
| **TL-2** | **In progress** | CI `#28919128030` on `996f60f` must green before release-evidence refresh |

**Lane 7 — Done:** TL-1 **Doing:** TL-2 CI monitor **Next:** TL-3 release evidence + RC audit dry-run

---

## Session — 2026-07-08 AM (F7 stack CI `#28917267975` on `a6aebab`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 full test tail** | **Done** — `a6aebab` | smoke `81849c8` + proptest `4a320ad` + block_apply `668cf17` + clippy fix |
| **CI #28917267975** | **In progress** | clippy/rustfmt/audit/wasm/scripts **GREEN**; matrix tests running |
| **Prior CI #28915985296** | **Failed** | pre-`4a320ad` single-input proptests (fixed) |

### RC push hold

**Active** — monitor CI `#28917267975`; lane 2 evidence after green.

### Next priority

**Lane 1:** CI green → optional Nightly on head. **Lane 2:** release evidence refresh. **Lane 4+6:** B3 replication accounting.

---

## Session — 2026-07-07 PM (F7 block_apply pad inputs → CI `#28917060257`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 block_apply** | **Done** — `668cf17` | `block_apply.rs` companion pad for ring + storage shape tests |
| **F7 proptest tail** | **Done** — `4a320ad` | `apply_block_proptest` + `emission_simulation` two-input recycle |
| **F7 smoke/wallet** | **Done** — `81849c8` | Two-block fund + `owned_count>=2` poll |
| **CI #28917060257** | **In progress** | `668cf17` full matrix |

### RC push hold

**Active** — monitor CI `#28917060257`; no pushes until green.

### Next priority

**Lane 2:** release evidence on green head. **Lane 4+6:** B3 replication accounting.

---

## Session — 2026-07-07 PM (F7 proptest + emission sim two-input alignment)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 proptest tail** | **This commit** | `apply_block_proptest` + `emission_simulation` recycle companion pad input (F7 floor) |
| **F7 smoke/wallet** | **Done** — `81849c8` | Two-block fund + `owned_count>=2` poll before upload |
| **CI #28915985296** | **Monitor** | Prior push `81849c8`; proptest fix follows |

### RC push hold

**Lift after green** — one proptest commit landing now; wait for matrix on head before further pushes.

### Next priority

**Lane 2:** release evidence on green head. **Lane 4+6:** B3 replication accounting.

---

## Session — 2026-07-07 PM (F7 auto-fanout wallet sync → CI `#28915985296`)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 wallet sync** | **Done** — `81849c8` | `f7_wallet_fund.rs` polls `owned_count>=2` before auto-fanout upload |
| **CI #28915800187** | **Cancelled** | Superseded by `81849c8` push |
| **CI #28915985296** | **In progress** | `81849c8` full matrix |

### RC push hold

**Active** — monitor CI `#28915985296`; no code pushes until green.

### Next priority

**Lane 2:** release evidence on `81849c8` after green. **Lane 6:** B3 replication accounting seed.

---

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 smoke fund** | **Done** — `7a68cc5` | `FUND_WALLET_BLOCKS=2` across mfn-cli smokes |
| **F7 smoke heights** | **Done** — `b00b7dd` | `last_proven_height=4` in chunk/operator smokes |
| **CI #28915800187** | **In progress** | `b00b7dd` full matrix (rustfmt/clippy green) |
| **B2 + F7 stack** | **Done** | `20954b0` + `3933cf0` on `main` |

### RC push hold

**Active** — no code pushes while CI `#28915800187` runs (`cancel-in-progress`).

### Next priority

**Lane 1:** Nightly dispatch after CI green. **Lane 2:** release evidence on `b00b7dd`. **Lane 6:** B3 replication accounting seed.

---

## Session — 2026-07-07 PM (F7 consensus min-input floor)

| Gate | Status | Notes |
| --- | --- | --- |
| **F7 tail** | **Done** — `3933cf0` | `RingPolicy.min_input_count = 2` at `verify_transaction` (uniform tier) |
| **B2 ChunkV2** | **Done** | `20954b0` on `main` |
| **CI #28915343380** | **Failed** — `last_proven_height` off-by-one | **Fixed** — `b00b7dd` |
| **CI #28915800187** | **Superseded** | Cancelled by `b00b7dd` push |

### RC push hold

**Active** — monitor CI on `b00b7dd` (F7 smoke height tail fix).

### Next priority

**Lane 2:** release evidence refresh on `3933cf0` after green CI. **Lane 6:** B3 replication accounting.

---

## Session — 2026-07-07 PM (B2 ChunkV2 Merkle-path gossip)

| Gate | Status | Notes |
| --- | --- | --- |
| **B2 ChunkV2** | **This commit** | `0x12` Merkle-proven chunk gossip; fan-out + operator push emit v2; v1 inbound still accepted |
| **CI / Nightly / RC** | **GREEN** | Prior stack on `96462aa` |
| **Release evidence** | **Done** | `96462aa` + RC audit dry-run **go** |

### RC push hold

**Lifted** until CI on this commit completes.

### Next priority (lane 4+5)

**F7 consensus tail** — `min_input_count` enforcement at `verify_transaction`.

---

## Session — 2026-07-07 PM (revisions — B-11 doc accuracy + gate sync)

| Gate | Status | Notes |
| --- | --- | --- |
| **CI / Nightly / RC** | **GREEN** | No open failures on `96462aa` stack |
| **Release evidence** | **Done** | `96462aa` + RC audit dry-run **go** |
| **Doc fix** | **This commit** | `STORAGE.md` + `PERMANENCE_HARDENING.md` §A6/B1: MFEO opening shipped; stale lane checkboxes cleared |
| **B-11 + B7 stack** | **Done** | MFEO genesis + dandelion rehearsal PASS |

### RC push hold

**Lifted** — full matrix + Nightly green on B-11/B7 stack.

---

## Session — 2026-07-07 (RC stack complete → F7 tail next)

| Gate | Status | Notes |
| --- | --- | --- |
| **Release evidence** | **Done** | `44b25b6` + RC audit dry-run **go** |
| **Nightly #28889931523** | **GREEN** | All three jobs on `b1072e3` stack |
| **CI #28885223488** | **GREEN** | `0d28e4f` B7 dandelion rehearsal evidence |
| **B-11 MFEO** | **Done** | Public devnet genesis `require_endowment_opening: 1` |
| **B-05 soak** | **Done** | `28851202993` max_height=48 |

### RC push hold

**Lifted** — full matrix + Nightly green on B-11/B7 stack.

### Next priority (lane 4+5)

**F7 consensus tail** — `min_input_count` enforcement at `verify_transaction` (network-wide Monero-default tx shape closure).

---

## Session — 2026-07-07 (B7 dandelion rehearsal → CI GREEN on `0d28e4f`)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #28889931523** | **GREEN** | All three jobs on `b1072e3` stack |
| **CI #28885223488** | **GREEN** | Run on `0d28e4f` (B7 dandelion evidence) |
| **CI #28879533724** | **GREEN** | Run on `0fee187` (B-11 public devnet MFEO) |
| **Nightly #28884769330** | **GREEN** | All three jobs on B-11 stack |
| **Release evidence** | **Done** | `1bbc3af` + RC audit go |
| **B7 dandelion rehearsal** | **Done** | `0d28e4f` — Windows PASS with MFEO upload |

### RC push hold

**Lifted** — full matrix green on B-11 + B7 evidence stack.

---

## Session — 2026-07-07 (B-11 public devnet enable → CI on stack)

| Gate | Status | Notes |
| --- | --- | --- |
| **CI #726** | **GREEN** | Run `28871239057` on `837069a` (full matrix) |
| **Nightly #65** | **GREEN** | Run `28877033241` on `837069a` (all three jobs) |
| **B-11 proptests** | **Done** | `9f0a0aa` — MFEO opening + reject without `MFEO` |
| **B-11 public devnet** | **This commit** | `require_endowment_opening: 1` in genesis JSON + spec parser |
| **Release evidence** | **Done** | `837069a` artifacts + ancestor CI lookup fix |

### RC push hold

**Lifted** — CI `28871239057` GREEN; Nightly `28877033241` GREEN.

---

## Session — 2026-07-07 (B-05 soak PASS → release evidence refresh)

| Gate | Status | Notes |
| --- | --- | --- |
| **B-05 Linux soak** | **PASS** | Soak `28851202993` max_height=48 (`234f0a8`) |
| **CI #720** | **In progress** | Run `28853929754` on `234f0a8` |
| **Nightly #63/#64** | **GREEN** | `28792429191` / `28841761235` |
| **B13 stack** | **Done** | `934cc2f` — CI #28838850432 GREEN |

### RC push hold

**Active** — CI `28853929754` in progress on `234f0a8`. Lane 2 runs `release-evidence-refresh-for-head -RunRcAuditDryRun` after green.

---

## Session — 2026-07-06 (B-06 closed → B13 + B7 CI fix)

| Gate | Status | Notes |
| --- | --- | --- |
| **Nightly #63** | **GREEN** | Run `28792429191` (all three jobs) |
| **B-06** | **Done** | CI `1603e43` + Nightly participant/observer PASS |
| **B13 wallet** | **Done** | `4712811` — size buckets on upload |
| **B13 consensus** | **Done** | `3d8574c` — bucket gate + `anchored_payload` artifacts |
| **M2.5.64 soak** | **Done** | `c5e69f6` — workflow pre-build + `start-all --no-build` |
| **B7 Dandelion++** | **Done** | `1cc9ead` — opt-in `--dandelion` (default off) |
| **B13 spora fix** | **Done** | `96fe808` — revert auto-pad in `build_storage_commitment`; test parity `e98ff4f` |
| **B13 authorship** | **Done** | `5d5cf64` CLI/wallet + `7821099` WASM — padded preview for MFCL `data_root` |
| **GHA hub timing** | **Done** | `934cc2f` — `GITHUB_ACTIONS` detection for 20s mesh budget |
| **Nightly #64** | **GREEN** | Run `28841761235` on `934cc2f` stack (auto-dispatched) |
| **B-05 Linux soak** | **Done** | Soak `28851202993` PASS max_height=48 (`234f0a8`) |

### RC push hold

**Lifted.** CI #28838850432 GREEN on `934cc2f`.

---

## Lanes 1–3 — Done / Doing / Next

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **1** RC core | Nightly green; smoke fixes `7a68cc5`/`b00b7dd` | **Monitor** CI `#28915800187` | Nightly after green |
| **2** RC ops | F7+B2 on `main` | **Waiting** — evidence after CI green | Human sign-off packet |
| **3** RC onboarding | B7 dandelion PASS; Nightly green | — | Idle |

---

## Lanes 4–6 snapshot

| Lane | Done | Doing | Next |
| --- | --- | --- | --- |
| **4** Protocol | F7 `3933cf0` + B2 `20954b0` | — | B3 replication accounting |
| **5** Privacy | F7 consensus tail (`3933cf0`) | — | B8 Tor transport (research) |
| **6** Permanence | B2 (`20954b0`) | — | B3 replication accounting |

---

## B-06 checklist

- [x] Nightly #62 executed (FAIL ~16.3m)
- [x] M2.5.49–61 on `main`
- [x] **Nightly #63** all three green (`28792429191`)
- [x] B13 wallet + consensus on `main`
- [x] M2.5.64 soak bootstrap (`c5e69f6`)
- [x] B7 Dandelion++ phase 1 (`1cc9ead`)
- [x] Green CI on B13 stack (CI #28838850432 on `934cc2f`)
- [x] Nightly #64 green (`28841761235`)
- [x] B-05 Linux soak evidence (soak `28851202993` PASS, `234f0a8`)

---

Update [`AGENTS.md`](./AGENTS.md) for cross-lane detail.

# Live public testnet probe - wave 76 findings (2026-07-22) — UPLOAD FAIL (F112 tooling)

**Lane:** 3 (onboarding / B-15)
**UTC window:** ~14:36Z–14:48Z (~12 min)
**Prior:** wave75 sage last_proven=5901
**Tip close:** **5908** (matched)
**Mode:** faucet-F101b OK → upload CLI argv corrupted; **permanence_public FAIL**

## Executive verdict

| Gate | Result |
| --- | --- |
| Faucet | **done** ~290s (slow F109 band) |
| F110 / F101b | **PASS** owned=2 @ pin 5887 |
| Pre-upload tip_id + mem=0 | **PASS** |
| Upload | **rc=1** `unknown option --mestroy` |
| Prove | not attempted |
| F45 lag | **612** (ckpt 5290) — first lag>600 |
| **permanence_public** | **FAIL** (tooling) |

## Findings

### F112 — naive string rename `sage`→`troy` corrupted `--message`

Wave76 runner was cloned from wave75 by replacing the wallet name `sage` with `troy`. The substring `sage` appears inside CLI flag `--message`, producing `--mestroy`. Upload failed immediately; wallet was funded and still has owned=2 locally.

**JOIN / ops fix:** when cloning probe runners, replace wallet tokens with word boundaries (or template placeholders). Never do global replace of short name fragments. Fixed runners for wave76–78 rebuilt from wave74 with `\b` boundaries; `--message` verified present.

### F45 lag **612** — crossed 600

Path A still 5290. Soft JOIN only; Path A republish urgency high.

### F109 still holds

Faucet ~290s — keep 100×5s poll budget.

## Artifacts

- `_wave76-results.json` (troy_funded=true; troy_upload_rc=1)
- fixed `_wave76_run.py` / `_wave77_run.py` / `_wave78_run.py` (gitignored `_`)

## Follow-up

- Re-run permanence with fixed runner (wave76b/troy retry or wave77 vela).


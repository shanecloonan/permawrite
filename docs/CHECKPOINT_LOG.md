# Signed checkpoint log (F12 phase 1)

Social redundancy for light-client weak subjectivity: maintainers and witnesses publish **Schnorr-signed** trusted-summary entries in an append-only JSONL log. Wallets cross-check P2P tips against multiple independent signatures before pinning.

See [`REFERENCE_TOPOLOGY.md`](./REFERENCE_TOPOLOGY.md) for role separation and [`F5.md` §F12](./F5.md) for roadmap context.

---

## Wire format

One JSON object per line (JSONL). Fields:

| Field | Description |
|---|---|
| `version` | Must be `1` |
| `signer_id` | Human label (e.g. `permawrite-maintainer-1`) |
| `published_at` | UTC timestamp (`{unix_secs}Z` in phase 1) |
| `summary` | Same object as `get_light_snapshot.summary` / `export-trusted-summary` |
| `checkpoint_hex` | Optional full checkpoint for offline verify |
| `signer_pk_hex` | 32-byte compressed Edwards point (hex) |
| `signature_hex` | 64-byte Schnorr signature (hex) |

Signing key derivation: `hash_to_scalar("MFN:checkpoint-log-signer:v1" || seed32)` — **not** a wallet spend seed.

---

## CLI

```bash
# Sign a trusted summary and append to the community log
export MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX=<64-char hex>
mfn-cli checkpoint-log sign \
  --summary trusted-summary.json \
  --signer-id permawrite-maintainer-1 \
  --signer-seed-hex "$MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX" \
  --append checkpoints.jsonl

# Verify all entries
mfn-cli checkpoint-log verify checkpoints.jsonl
mfn-cli checkpoint-log verify checkpoints.jsonl --json

# Cross-check a trusted summary file against the log (without light-scan)
mfn-cli checkpoint-log cross-check \
  --summary trusted-summary.json \
  --log checkpoints.jsonl
```

### TL-8 operator publish (phase 4)

After TL-7 sign-off, append a signed entry from the observer/validator RPC tip:

```bash
export MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX=<64-char hex>   # production maintainer seed
bash scripts/public-devnet-v1/publish-checkpoint-log.sh --rpc 127.0.0.1:18734 --apply
# default log: mfn-node/testdata/public_devnet_v1.checkpoints.jsonl
```

Dry-run first (no `--apply`) to preview RPC + log path.

### Local rehearsal (test-only seed)

CI and local smoke use a **non-production** rehearsal maintainer seed:

```bash
export MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
bash scripts/public-devnet-v1/checkpoint-log-rehearsal-smoke.sh --live
```

Never reuse the rehearsal seed for a public testnet maintainer key.

Publish verified `checkpoints.jsonl` alongside release artifacts and link from [`TESTNET_INVITE.md`](./TESTNET_INVITE.md) after TL-8.

---

## Browser / WASM (phase 3)

After light sync in a browser wallet, cross-check the evolved summary against a fetched JSONL log using the same Schnorr rules as the CLI (`mfn-checkpoint-log` crate):

```javascript
import init, { checkpointLogVerify, checkpointLogCrossCheck } from "./pkg/mfn_wasm.js";

await init();
const verify = JSON.parse(checkpointLogVerify(logJsonl));
const cross = JSON.parse(checkpointLogCrossCheck(summaryJson, logJsonl));
// cross.matched === true when ≥1 signer agrees at tip_height
```

WASM exports: `checkpointLogVerify`, `checkpointLogCrossCheck` (`wasm-full` feature).

---

## Light client usage (phase 2)

After sync, wallets can cross-check the evolved checkpoint against a published log. On a fresh wallet, `light-scan --checkpoint-log` also auto-bootstraps from the log max tip (**B-50 follow-up**) before scanning the remaining delta:

```bash
mfn-cli --rpc HOST:PORT wallet light-scan \
  --checkpoint-log checkpoints.jsonl
```

Behavior:

1. Verify every JSONL line (Schnorr + optional checkpoint agreement).
2. Require ≥1 valid entry whose weak-subjectivity fields match the post-sync summary at `tip_height`.
3. Reject when entries exist at the same height but none agree (social consensus disagreement).
4. Print `checkpoint_log=matched` and `checkpoint_log_signers=` on success.

Phase 1 manual flow (still supported):

1. Fetch P2P/RPC `get_light_snapshot`.
2. Compare `summary` against ≥1 valid entry in the published log with matching weak-subjectivity fields.
3. Prefer entries from distinct `signer_id` values when heights tie.
4. Reject tips that disagree with every trusted log entry at the same height.

import init, {
  walletAddressFromSeedHex,
  claimPubkeyFromSeedHex,
  storageUploadPreview,
  uploadMinFee,
  buildStorageUpload,
  buildTransferJson,
  scanBlockHex,
  scanBlockTxsHex,
  lightChainVerifyHeader,
  lightChainApplyEvolution,
  lightChainBootstrapCheckpoint,
  lightChainCheckpointSummary,
  lightChainWeakSubjectivity,
  lightFollowQuorum,
  checkpointLogVerify,
  checkpointLogCrossCheck,
} from "./pkg/mfn_wasm.js";
import { mfndRpc } from "./rpc-client.js";
import {
  applyBlockScan,
  clearTrustedSummary,
  emptyWalletSync,
  loadLightCheckpoint,
  loadWalletSync,
  saveLightCheckpoint,
  saveWalletSync,
  syncBlockRange,
  totalBalance,
} from "./wallet-sync.js";
import {
  assertRpcSummaryMatchesCheckpoint,
  deriveTrustedSummaryFromCheckpoint,
  formatTrustedSummaryLines,
  loadTrustedSummaryObject,
  normalizeTrustedSummary,
  importTrustedSummaryFromTextareaIfPresent,
  parseTrustedSummaryJson,
  saveTrustedSummaryObject,
} from "./trusted-summary-pins.js";
import {
  fetchRelayCheckpointSummary,
  fetchRelayTlsSpki,
} from "./light-relay-client.js";
import {
  assertExpectedRelayTlsSpki,
  clearTrustedRelayPins,
  isHttpsRelayUrl,
  saveTrustedRelayPins,
} from "./trusted-relay-pins.js";

const DEMO_SEED = "42".repeat(32);

let wasmReady = false;
/** @type {{ tx_hex: string, tx_id: string } | null} */
let lastBuiltTx = null;
/** @type {import("./wallet-sync.js").WalletSyncState} */
let walletSync = emptyWalletSync();

async function ensureWasm() {
  if (!wasmReady) {
    await init();
    wasmReady = true;
  }
}

function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el;
}

function seedOrDemo() {
  const raw = $("seed").value.trim().replace(/^0x/i, "");
  if (!raw) return DEMO_SEED;
  if (raw.length !== 64 || !/^[0-9a-fA-F]+$/.test(raw)) {
    throw new Error("seed must be 64 hex characters");
  }
  return raw.toLowerCase();
}

function show(outId, text) {
  $(outId).textContent = text;
}

function rpcUrl() {
  return $("rpc-url").value.trim();
}

function quorumRpcUrls() {
  const el = document.getElementById("sync-quorum-urls");
  const raw = el?.value?.trim() ?? "";
  if (!raw) return [];
  return raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
}

function quorumP2pPeers() {
  const el = document.getElementById("sync-quorum-p2p");
  const raw = el?.value?.trim() ?? "";
  if (!raw) return [];
  return raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
}

function lightRelayUrls() {
  const el = document.getElementById("sync-light-relays");
  const raw = el?.value?.trim() ?? "";
  if (!raw) return [];
  return raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
}

/** @returns {Record<string, string>} normalized relay URL → expected SPKI hex */
function expectedRelayTlsSpki() {
  const el = document.getElementById("sync-relay-tls-spki");
  const raw = el?.value?.trim() ?? "";
  if (!raw) return {};
  const out = {};
  for (const part of raw.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const url = part.slice(0, eq).trim();
    const hex = part.slice(eq + 1).trim().replace(/^0x/i, "").toLowerCase();
    if (url && hex) out[url.replace(/\/$/, "").toLowerCase()] = hex;
  }
  return out;
}

function syncWasmOpts() {
  const relays = lightRelayUrls();
  return {
    lightChainVerifyHeader,
    lightChainApplyEvolution,
    lightChainBootstrapCheckpoint,
    lightChainCheckpointSummary,
    lightChainWeakSubjectivity,
    lightFollowQuorum,
    quorumRpcUrls: quorumRpcUrls(),
    quorumP2pPeers: quorumP2pPeers(),
    lightRelayUrls: relays.length > 0 ? relays : undefined,
  };
}

/** @returns {{ imported: false } | { imported: true, summary: object }} */
function importTrustedSummaryOnSyncIfPresent(seed) {
  return importTrustedSummaryFromTextareaIfPresent(
    seed,
    $("sync-trusted-summary-json").value,
    {
      checkpointHex: loadLightCheckpoint(seed) || undefined,
      lightChainWeakSubjectivity,
    },
  );
}

function ownedKeyImagesFromTextarea() {
  const raw = $("owned-ki").value.trim();
  if (!raw) return [];
  return raw
    .split(/\r?\n/)
    .map((l) => l.trim().replace(/^0x/i, ""))
    .filter((l) => l.length > 0);
}

function refreshSyncStatus() {
  const el = document.getElementById("sync-status");
  if (!el) return;
  el.textContent = `last scanned height: ${walletSync.lastScannedHeight} · ${walletSync.inputs.length} UTXOs · balance ${totalBalance(walletSync)}`;
}

function applyWalletSyncToPlans() {
  $("owned-ki").value = walletSync.ownedKeyImages.join("\n");
  const transfer = JSON.parse($("transfer-plan").value || "{}");
  transfer.inputs = walletSync.inputs;
  transfer.current_height = walletSync.lastScannedHeight;
  transfer.exclude_one_time_addrs_hex = walletSync.inputs.map((o) => o.one_time_addr_hex);
  $("transfer-plan").value = JSON.stringify(transfer, null, 2);
  const upload = JSON.parse($("upload-plan").value || "{}");
  upload.inputs = walletSync.inputs;
  upload.current_height = walletSync.lastScannedHeight;
  upload.exclude_one_time_addrs_hex = walletSync.inputs.map((o) => o.one_time_addr_hex);
  $("upload-plan").value = JSON.stringify(upload, null, 2);
  refreshSyncStatus();
}

function persistWalletSync() {
  saveWalletSync(seedOrDemo(), walletSync);
  applyWalletSyncToPlans();
}

function mergeRecoveredIntoPlan(scanJson) {
  const scan = JSON.parse(scanJson);
  applyBlockScan(walletSync, scan);
  persistWalletSync();
  const recovered = [];
  for (const tx of scan.txs || []) {
    for (const o of tx.recovered || []) {
      recovered.push(o);
    }
  }
  return { scan, recovered };
}

const SAMPLE_UPLOAD_PLAN = {
  inputs: [],
  anchor: { view_pub_hex: "", spend_pub_hex: "", value: 1000 },
  replication: 3,
  fee: 0,
  ring_size: 4,
  current_height: 0,
  decoy_utxos: [],
  exclude_one_time_addrs_hex: [],
  fee_to_treasury_bps: 9000,
  change_recipients: [],
  extra_hex: "",
  message_hex: "",
};

const SAMPLE_PLAN = {
  inputs: [],
  recipients: [
    {
      view_pub_hex: "",
      spend_pub_hex: "",
      value: 1000,
    },
  ],
  fee: 100,
  ring_size: 4,
  current_height: 0,
  decoy_utxos: [],
  exclude_one_time_addrs_hex: [],
  extra_hex: "",
};

document.addEventListener("DOMContentLoaded", () => {
  $("seed").value = DEMO_SEED;
  $("transfer-plan").value = JSON.stringify(SAMPLE_PLAN, null, 2);
  $("upload-plan").value = JSON.stringify(SAMPLE_UPLOAD_PLAN, null, 2);
  walletSync = loadWalletSync(seedOrDemo());
  applyWalletSyncToPlans();
  refreshSyncStatus();

  $("seed").addEventListener("change", () => {
    walletSync = loadWalletSync(seedOrDemo());
    refreshSyncStatus();
    applyWalletSyncToPlans();
  });
  $("seed").addEventListener("blur", () => {
    walletSync = loadWalletSync(seedOrDemo());
    refreshSyncStatus();
    applyWalletSyncToPlans();
  });

  $("btn-address").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const json = walletAddressFromSeedHex(seedOrDemo());
      const addr = JSON.parse(json);
      show("wallet-out", JSON.stringify(addr, null, 2));
      const plan = JSON.parse($("transfer-plan").value || "{}");
      plan.recipients[0].view_pub_hex = addr.view_pub;
      plan.recipients[0].spend_pub_hex = addr.spend_pub;
      $("transfer-plan").value = JSON.stringify(plan, null, 2);
      const upload = JSON.parse($("upload-plan").value || "{}");
      upload.anchor = upload.anchor || {};
      upload.anchor.view_pub_hex = addr.view_pub;
      upload.anchor.spend_pub_hex = addr.spend_pub;
      $("upload-plan").value = JSON.stringify(upload, null, 2);
    } catch (e) {
      show("wallet-out", String(e));
    }
  });

  $("btn-claim-pk").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const pk = claimPubkeyFromSeedHex(seedOrDemo());
      show("wallet-out", `claim_pubkey=${pk}`);
    } catch (e) {
      show("wallet-out", String(e));
    }
  });

  $("btn-preview").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const file = $("file").files?.[0];
      if (!file) throw new Error("choose a file first");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const rep = Number($("replication").value);
      if (!Number.isInteger(rep) || rep < 1 || rep > 255) {
        throw new Error("replication must be 1–255");
      }
      const json = storageUploadPreview(bytes, rep);
      show("storage-out", JSON.stringify(JSON.parse(json), null, 2));
    } catch (e) {
      show("storage-out", String(e));
    }
  });

  async function runSync(fromHeight, toHeight) {
    await ensureWasm();
    const seed = seedOrDemo();
    const trustedImport = importTrustedSummaryOnSyncIfPresent(seed);
    const summary = await syncBlockRange({
      rpcUrl: rpcUrl(),
      seedHex: seed,
      fromHeight,
      toHeight,
      state: walletSync,
      rpc: mfndRpc,
      scanBlockTxsHex,
      ...syncWasmOpts(),
      onProgress: (h) => {
        show("sync-out", `scanning height ${h}…`);
      },
    });
    persistWalletSync();
    const out = trustedImport.imported
      ? { trusted_summary_import: trustedImport.summary, ...summary }
      : summary;
    show("sync-out", JSON.stringify(out, null, 2));
  }

  $("btn-sync-ready").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const seed = seedOrDemo();
      const trustedImport = importTrustedSummaryOnSyncIfPresent(seed);
      show("sync-out", "fetching chain params…");
      const [params, tip] = await Promise.all([
        mfndRpc(rpcUrl(), "get_chain_params", {}),
        mfndRpc(rpcUrl(), "get_tip", {}),
      ]);
      const applied = applyChainParamsToPlans(params);
      const tipH = tip.tip_height != null ? Number(tip.tip_height) : 0;
      let syncSummary = { skipped: true, reason: "no blocks" };
      if (tipH >= 1) {
        const from = walletSync.lastScannedHeight + 1;
        if (from <= tipH) {
          show("sync-out", `syncing blocks ${from}…${tipH}…`);
          syncSummary = await syncBlockRange({
            rpcUrl: rpcUrl(),
            seedHex: seedOrDemo(),
            fromHeight: from,
            toHeight: tipH,
            state: walletSync,
            rpc: mfndRpc,
            scanBlockTxsHex,
            ...syncWasmOpts(),
            onProgress: (h) => {
              show("sync-out", `scanning height ${h}…`);
            },
          });
          persistWalletSync();
        } else {
          syncSummary = {
            skipped: true,
            reason: "already at tip",
            tip_height: tipH,
            ...(trustedImport.imported
              ? { trusted_summary_import: trustedImport.summary }
              : {}),
          };
          refreshSyncStatus();
        }
      }
      show("sync-out", "loading decoy pool…");
      const decoys = await loadDecoysFromNode(tipH >= 1 ? tipH : null);
      applyWalletSyncToPlans();
      show(
        "sync-out",
        JSON.stringify(
          {
            chain_params: {
              fee_to_treasury_bps: applied.fee_to_treasury_bps,
              min_replication: applied.min_replication,
              max_replication: applied.max_replication,
              treasury_base_units: params.treasury_base_units,
            },
            sync: syncSummary,
            ...(trustedImport.imported && !syncSummary.trusted_summary_import
              ? { trusted_summary_import: trustedImport.summary }
              : {}),
            decoys,
            wallet: {
              last_scanned_height: walletSync.lastScannedHeight,
              utxo_count: walletSync.inputs.length,
              balance: totalBalance(walletSync),
            },
          },
          null,
          2,
        ),
      );
    } catch (e) {
      show("sync-out", String(e));
    }
  });

  $("btn-sync-catch-up").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const seed = seedOrDemo();
      const tip = await mfndRpc(rpcUrl(), "get_tip", {});
      const tipH = tip.tip_height != null ? Number(tip.tip_height) : 0;
      if (tipH < 1) {
        show("sync-out", "chain has no blocks yet (run mfnd step)");
        return;
      }
      const from = walletSync.lastScannedHeight + 1;
      if (from > tipH) {
        const trustedImport = importTrustedSummaryOnSyncIfPresent(seed);
        if (trustedImport.imported) {
          show(
            "sync-out",
            JSON.stringify(
              {
                skipped: true,
                reason: "already at tip",
                tip_height: tipH,
                trusted_summary_import: trustedImport.summary,
              },
              null,
              2,
            ),
          );
        } else {
          show("sync-out", `already synced through tip (${tipH})`);
        }
        refreshSyncStatus();
        return;
      }
      await runSync(from, tipH);
    } catch (e) {
      show("sync-out", String(e));
    }
  });

  $("btn-sync-range").addEventListener("click", async () => {
    try {
      const from = Number($("sync-from").value);
      if (!Number.isInteger(from) || from < 1) {
        throw new Error("sync-from must be a positive integer");
      }
      let to = $("sync-to").value.trim();
      let toHeight;
      if (!to) {
        const tip = await mfndRpc(rpcUrl(), "get_tip", {});
        toHeight = Number(tip.tip_height);
        if (!toHeight || toHeight < 1) {
          throw new Error("chain has no blocks yet");
        }
      } else {
        toHeight = Number(to);
        if (!Number.isInteger(toHeight) || toHeight < 1) {
          throw new Error("sync-to must be a positive integer");
        }
      }
      await runSync(from, toHeight);
    } catch (e) {
      show("sync-out", String(e));
    }
  });

  $("btn-pin-relays").addEventListener("click", async () => {
    try {
      const seed = seedOrDemo();
      const relays = lightRelayUrls();
      if (relays.length === 0) {
        show("sync-out", "enter light relay URLs first");
        return;
      }
      const summaries = {};
      const tlsSpki = {};
      const expectedSpki = expectedRelayTlsSpki();
      for (const base of relays) {
        summaries[base] = await fetchRelayCheckpointSummary(base);
        if (isHttpsRelayUrl(base)) {
          const live = await fetchRelayTlsSpki(base);
          const norm = base.replace(/\/$/, "").toLowerCase();
          assertExpectedRelayTlsSpki(
            base,
            expectedSpki[norm] || expectedSpki[base.toLowerCase()],
            live,
          );
          tlsSpki[base] = live;
        }
      }
      saveTrustedRelayPins(seed, relays, summaries, tlsSpki);
      const digests = relays.map(
        (r) => `${r} → ${summaries[r].checkpoint_digest}`,
      );
      const spkiLines = Object.entries(tlsSpki).map(
        ([r, h]) => `${r} → tls spki ${h.slice(0, 16)}…`,
      );
      show(
        "sync-out",
        `pinned ${relays.length} relay URL(s) + checkpoint summaries:\n${digests.join("\n")}` +
          (spkiLines.length ? `\n${spkiLines.join("\n")}` : ""),
      );
    } catch (e) {
      show("sync-out", String(e));
    }
  });

  $("btn-reset-relay-pins").addEventListener("click", () => {
    clearTrustedRelayPins(seedOrDemo());
    show("sync-out", "cleared trusted relay pins (next sync will TOFU)");
  });

  $("btn-export-trusted-summary").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const seed = seedOrDemo();
      const pinOnExport = document.getElementById("sync-export-pin-summary")?.checked;
      const checkpointHex = loadLightCheckpoint(seed);
      let summary;
      let source;
      if (checkpointHex) {
        summary = deriveTrustedSummaryFromCheckpoint(
          checkpointHex,
          lightChainCheckpointSummary,
        );
        source = "local light checkpoint (WASM)";
      } else {
        const tip = await mfndRpc(rpcUrl(), "get_tip", {});
        const height = Number(
          walletSync.lastScannedHeight || tip.tip_height || 0,
        );
        const snap = await mfndRpc(rpcUrl(), "get_light_snapshot", { height });
        if (!snap?.summary) {
          throw new Error(`get_light_snapshot at ${height} returned no summary`);
        }
        summary = normalizeTrustedSummary(snap.summary);
        if (snap.checkpoint_hex && lightChainCheckpointSummary) {
          const derived = deriveTrustedSummaryFromCheckpoint(
            snap.checkpoint_hex,
            lightChainCheckpointSummary,
          );
          assertRpcSummaryMatchesCheckpoint(summary, derived);
        }
        source = `RPC get_light_snapshot at height ${height}`;
      }
      $("sync-trusted-summary-json").value = JSON.stringify(summary, null, 2);
      if (pinOnExport) {
        saveTrustedSummaryObject(seed, summary);
      }
      show(
        "sync-out",
        `exported trusted summary from ${source}\n` +
          formatTrustedSummaryLines(summary) +
          (pinOnExport ? "\n(pinned in localStorage)" : ""),
      );
    } catch (e) {
      show("sync-out", String(e));
    }
  });

  $("btn-import-trusted-summary").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const seed = seedOrDemo();
      const raw = $("sync-trusted-summary-json").value;
      const summary = parseTrustedSummaryJson(raw);
      const checkpointHex = loadLightCheckpoint(seed);
      if (checkpointHex && lightChainWeakSubjectivity) {
        const ws = JSON.parse(
          lightChainWeakSubjectivity(JSON.stringify(summary), checkpointHex),
        );
        if (!ws.ok || !ws.agrees) {
          throw new Error(
            ws.error ||
              "trusted summary disagrees with wallet light checkpoint (import aborted)",
          );
        }
      }
      saveTrustedSummaryObject(seed, summary);
      show(
        "sync-out",
        `imported trusted summary (tip_height=${summary.tip_height})\n` +
          `checkpoint_digest=${summary.checkpoint_digest}\n` +
          (checkpointHex
            ? "verified against local light checkpoint"
            : "no local checkpoint yet; sync will check on next run"),
      );
    } catch (e) {
      show("sync-out", String(e));
    }
  });

  $("btn-show-trusted-summary").addEventListener("click", () => {
    try {
      const seed = seedOrDemo();
      const summary = loadTrustedSummaryObject(seed);
      if (!summary) {
        show("sync-out", "no trusted summary pinned for this seed");
        return;
      }
      $("sync-trusted-summary-json").value = JSON.stringify(summary, null, 2);
      show("sync-out", formatTrustedSummaryLines(summary));
    } catch (e) {
      show("sync-out", String(e));
    }
  });

  $("btn-clear-trusted-summary").addEventListener("click", () => {
    clearTrustedSummary(seedOrDemo());
    $("sync-trusted-summary-json").value = "";
    show("sync-out", "cleared trusted summary pin (sync will not weak-subjectivity gate)");
  });

  $("btn-sync-reset").addEventListener("click", () => {
    walletSync = emptyWalletSync();
    persistWalletSync();
    saveLightCheckpoint(seedOrDemo(), "");
    clearTrustedRelayPins(seedOrDemo());
    clearTrustedSummary(seedOrDemo());
    $("sync-trusted-summary-json").value = "";
    show("sync-out", "wallet, checkpoint, relay pins, and trusted summary cleared");
  });

  async function checkpointLogText() {
    const pasted = $("checkpoint-log-jsonl").value.trim();
    if (pasted) return pasted;
    throw new Error("paste checkpoint log JSONL or use Fetch log URL");
  }

  $("btn-checkpoint-log-fetch").addEventListener("click", async () => {
    try {
      const url = $("checkpoint-log-url").value.trim();
      if (!url) throw new Error("set a log URL");
      const res = await fetch(url);
      if (!res.ok) throw new Error(`fetch ${url}: HTTP ${res.status}`);
      const text = await res.text();
      $("checkpoint-log-jsonl").value = text.trim();
      show("checkpoint-log-out", `fetched ${text.trim().split("\n").filter(Boolean).length} line(s) from ${url}`);
    } catch (e) {
      show("checkpoint-log-out", String(e));
    }
  });

  $("btn-checkpoint-log-verify").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const logJsonl = await checkpointLogText();
      const out = checkpointLogVerify(logJsonl);
      show("checkpoint-log-out", out);
    } catch (e) {
      show("checkpoint-log-out", String(e));
    }
  });

  $("btn-checkpoint-log-cross-check").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const logJsonl = await checkpointLogText();
      const raw = $("sync-trusted-summary-json").value.trim();
      if (!raw) throw new Error("paste trusted summary JSON in Wallet sync first");
      const summary = parseTrustedSummaryJson(raw);
      const out = checkpointLogCrossCheck(JSON.stringify(summary), logJsonl);
      show("checkpoint-log-out", out);
    } catch (e) {
      show("checkpoint-log-out", String(e));
    }
  });

  $("btn-scan-block").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const blockHex = $("block-hex").value.trim();
      if (!blockHex) throw new Error("paste block wire hex");
      const owned = ownedKeyImagesFromTextarea();
      const json = scanBlockHex(seedOrDemo(), blockHex, owned);
      const { scan, recovered } = mergeRecoveredIntoPlan(json);
      show(
        "scan-out",
        JSON.stringify(
          {
            height: scan.height,
            recovered: recovered.length,
            gross_received: scan.gross_received,
          },
          null,
          2,
        ),
      );
    } catch (e) {
      show("scan-out", String(e));
    }
  });

  function syncDecoysToUpload(plan) {
    const upload = JSON.parse($("upload-plan").value || "{}");
    upload.decoy_utxos = plan.decoy_utxos || [];
    upload.current_height = plan.current_height ?? upload.current_height;
    upload.exclude_one_time_addrs_hex = plan.exclude_one_time_addrs_hex || [];
    $("upload-plan").value = JSON.stringify(upload, null, 2);
  }

  function applyChainParamsToPlans(params) {
    const bps = params.emission?.fee_to_treasury_bps ?? 9000;
    const transfer = JSON.parse($("transfer-plan").value || "{}");
    const upload = JSON.parse($("upload-plan").value || "{}");
    upload.fee_to_treasury_bps = bps;
    if (params.endowment) {
      upload.endowment = { ...params.endowment };
    }
    const minRep = params.endowment?.min_replication;
    const maxRep = params.endowment?.max_replication;
    if (minRep != null && maxRep != null) {
      let rep = Number($("replication").value);
      if (!Number.isInteger(rep)) rep = minRep;
      rep = Math.max(minRep, Math.min(maxRep, rep));
      $("replication").value = String(rep);
      upload.replication = rep;
    }
    $("transfer-plan").value = JSON.stringify(transfer, null, 2);
    $("upload-plan").value = JSON.stringify(upload, null, 2);
    return { fee_to_treasury_bps: bps, min_replication: minRep, max_replication: maxRep };
  }

  async function loadDecoysFromNode(tipHeight) {
    const utxoPage = await mfndRpc(rpcUrl(), "list_utxos", { limit: 10000, offset: 0 });
    const plan = JSON.parse($("transfer-plan").value || "{}");
    if (tipHeight != null) {
      plan.current_height = tipHeight;
    }
    plan.decoy_utxos = (utxoPage.utxos || []).map((u) => ({
      height: u.height,
      one_time_addr_hex: u.one_time_addr_hex,
      commit_hex: u.commit_hex,
    }));
    const owned = new Set(
      (plan.inputs || []).map((i) => i.one_time_addr_hex?.toLowerCase()).filter(Boolean),
    );
    plan.exclude_one_time_addrs_hex = [...owned];
    $("transfer-plan").value = JSON.stringify(plan, null, 2);
    syncDecoysToUpload(plan);
    return { decoy_count: plan.decoy_utxos.length, total: utxoPage.total };
  }

  $("btn-upload-min-fee").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const file = $("file").files?.[0];
      if (!file) throw new Error("choose a file first");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const rep = Number($("replication").value);
      const upload = JSON.parse($("upload-plan").value || "{}");
      const bps = upload.fee_to_treasury_bps ?? 9000;
      const feeJson = uploadMinFee(bytes.length, rep, bps);
      const minFee = JSON.parse(feeJson);
      upload.fee = minFee;
      $("upload-plan").value = JSON.stringify(upload, null, 2);
      show("upload-out", `min_fee=${minFee}`);
    } catch (e) {
      show("upload-out", String(e));
    }
  });

  $("btn-build-upload").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const file = $("file").files?.[0];
      if (!file) throw new Error("choose a file first");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const plan = JSON.parse($("upload-plan").value || "{}");
      const msg = $("upload-message").value;
      plan.message_hex = msg ? [...new TextEncoder().encode(msg)].map((b) => b.toString(16).padStart(2, "0")).join("") : "";
      plan.replication = Number($("replication").value);
      const json = buildStorageUpload(seedOrDemo(), bytes, JSON.stringify(plan));
      lastBuiltTx = JSON.parse(json);
      $("tx-hex-override").value = lastBuiltTx.tx_hex;
      show("upload-out", JSON.stringify(lastBuiltTx, null, 2));
    } catch (e) {
      show("upload-out", String(e));
    }
  });

  $("btn-submit-upload").addEventListener("click", async () => {
    try {
      const override = $("tx-hex-override").value.trim().replace(/^0x/i, "");
      const txHex = override || lastBuiltTx?.tx_hex;
      if (!txHex) throw new Error("build an upload tx first");
      const result = await mfndRpc(rpcUrl(), "submit_tx", { tx_hex: txHex });
      show("upload-out", JSON.stringify(result, null, 2));
    } catch (e) {
      show("upload-out", String(e));
    }
  });

  $("btn-load-decoys").addEventListener("click", async () => {
    try {
      const tip = await mfndRpc(rpcUrl(), "get_tip", {});
      const tipH = tip.tip_height != null ? Number(tip.tip_height) : null;
      const decoys = await loadDecoysFromNode(tipH);
      applyWalletSyncToPlans();
      show(
        "transfer-out",
        `loaded ${decoys.decoy_count} decoys (total on chain: ${decoys.total ?? "?"})`,
      );
    } catch (e) {
      show("transfer-out", String(e));
    }
  });

  $("btn-transfer").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const plan = $("transfer-plan").value.trim();
      if (!plan) throw new Error("paste a transfer plan JSON");
      const json = buildTransferJson(plan);
      lastBuiltTx = JSON.parse(json);
      $("tx-hex-override").value = lastBuiltTx.tx_hex;
      show("transfer-out", JSON.stringify(lastBuiltTx, null, 2));
    } catch (e) {
      show("transfer-out", String(e));
    }
  });

  $("btn-submit-tx").addEventListener("click", async () => {
    try {
      const override = $("tx-hex-override").value.trim().replace(/^0x/i, "");
      const txHex = override || lastBuiltTx?.tx_hex;
      if (!txHex) throw new Error("build a transfer first or paste tx_hex");
      const result = await mfndRpc(rpcUrl(), "submit_tx", { tx_hex: txHex });
      show("transfer-out", JSON.stringify(result, null, 2));
    } catch (e) {
      show("transfer-out", String(e));
    }
  });

  $("btn-tip").addEventListener("click", async () => {
    try {
      const result = await mfndRpc(rpcUrl(), "get_tip", {});
      show("rpc-out", JSON.stringify(result, null, 2));
    } catch (e) {
      show("rpc-out", String(e));
    }
  });

  $("btn-mempool").addEventListener("click", async () => {
    try {
      const result = await mfndRpc(rpcUrl(), "get_mempool", {});
      show("rpc-out", JSON.stringify(result, null, 2));
    } catch (e) {
      show("rpc-out", String(e));
    }
  });
});

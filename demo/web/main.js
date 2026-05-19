import init, {
  walletAddressFromSeedHex,
  claimPubkeyFromSeedHex,
  storageUploadPreview,
  uploadMinFee,
  buildStorageUpload,
  buildTransferJson,
  scanBlockHex,
} from "./pkg/mfn_wasm.js";
import { mfndRpc } from "./rpc-client.js";

const DEMO_SEED = "42".repeat(32);

let wasmReady = false;
/** @type {{ tx_hex: string, tx_id: string } | null} */
let lastBuiltTx = null;

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

function ownedKeyImagesFromTextarea() {
  const raw = $("owned-ki").value.trim();
  if (!raw) return [];
  return raw
    .split(/\r?\n/)
    .map((l) => l.trim().replace(/^0x/i, ""))
    .filter((l) => l.length > 0);
}

function mergeRecoveredIntoPlan(scanJson) {
  const scan = JSON.parse(scanJson);
  const plan = JSON.parse($("transfer-plan").value || "{}");
  const recovered = [];
  for (const tx of scan.txs || []) {
    for (const o of tx.recovered || []) {
      recovered.push(o);
    }
  }
  if (recovered.length > 0) {
    plan.inputs = recovered;
  }
  if (scan.height != null) {
    plan.current_height = Number(scan.height);
  }
  const owned = new Set(
    recovered.map((o) => o.one_time_addr_hex?.toLowerCase()).filter(Boolean),
  );
  plan.exclude_one_time_addrs_hex = [...owned];
  $("transfer-plan").value = JSON.stringify(plan, null, 2);
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

  $("btn-scan-block").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const blockHex = $("block-hex").value.trim();
      if (!blockHex) throw new Error("paste block wire hex");
      const owned = ownedKeyImagesFromTextarea();
      const json = scanBlockHex(seedOrDemo(), blockHex, owned);
      const { scan, recovered } = mergeRecoveredIntoPlan(json);
      const upload = JSON.parse($("upload-plan").value || "{}");
      if (recovered.length > 0) {
        upload.inputs = recovered;
      }
      $("upload-plan").value = JSON.stringify(upload, null, 2);
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
      const [tip, utxoPage] = await Promise.all([
        mfndRpc(rpcUrl(), "get_tip", {}),
        mfndRpc(rpcUrl(), "list_utxos", { limit: 10000, offset: 0 }),
      ]);
      const plan = JSON.parse($("transfer-plan").value || "{}");
      if (tip.tip_height != null) {
        plan.current_height = Number(tip.tip_height);
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
      show(
        "transfer-out",
        `loaded ${plan.decoy_utxos.length} decoys (total on chain: ${utxoPage.total ?? "?"})`,
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

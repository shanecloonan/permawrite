import init, {
  walletAddressFromSeedHex,
  claimPubkeyFromSeedHex,
  storageUploadPreview,
  buildTransferJson,
} from "./pkg/mfn_wasm.js";
import { mfndRpc } from "./rpc-client.js";

const DEMO_SEED = "42".repeat(32);

let wasmReady = false;

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

  $("btn-load-decoys").addEventListener("click", async () => {
    try {
      const url = $("rpc-url").value.trim();
      const [tip, utxoPage] = await Promise.all([
        mfndRpc(url, "get_tip", {}),
        mfndRpc(url, "list_utxos", { limit: 10000, offset: 0 }),
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
      show("transfer-out", JSON.stringify(JSON.parse(json), null, 2));
    } catch (e) {
      show("transfer-out", String(e));
    }
  });

  $("btn-tip").addEventListener("click", async () => {
    try {
      const url = $("rpc-url").value.trim();
      const result = await mfndRpc(url, "get_tip", {});
      show("rpc-out", JSON.stringify(result, null, 2));
    } catch (e) {
      show("rpc-out", String(e));
    }
  });
});

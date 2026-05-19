import init, {
  walletAddressFromSeedHex,
  claimPubkeyFromSeedHex,
  storageUploadPreview,
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

document.addEventListener("DOMContentLoaded", () => {
  $("seed").value = DEMO_SEED;

  $("btn-address").addEventListener("click", async () => {
    try {
      await ensureWasm();
      const json = walletAddressFromSeedHex(seedOrDemo());
      show("wallet-out", JSON.stringify(JSON.parse(json), null, 2));
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

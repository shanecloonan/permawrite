#!/usr/bin/env node
/**
 * Lane 7: public-safe HTTP → TCP JSON-RPC bridge for a dedicated observer.
 *
 *   MFND_RPC=127.0.0.1:18734 PROXY_HOST=0.0.0.0 PROXY_PORT=8787 \
 *     node scripts/public-devnet-v1/observer-rpc-proxy.mjs
 *
 * Browses POST JSON-RPC to /rpc. Only public-safe methods are forwarded.
 *
 * Also maintains an in-process index of per-height tx counts + a get_block_txs
 * response cache so browser wallet scans and the explore "user transactions"
 * counter do not re-fetch the whole chain through Vercel on every visit.
 */

import http from "node:http";
import net from "node:net";

const MFND_RPC = process.env.MFND_RPC ?? "127.0.0.1:18734";
const LISTEN_HOST = process.env.PROXY_HOST ?? "0.0.0.0";
const LISTEN_PORT = Number(process.env.PROXY_PORT ?? "8787");
const MAX_BODY = Number(process.env.PROXY_MAX_BODY_BYTES ?? String(2 * 1024 * 1024));
const RPC_TIMEOUT_MS = Number(process.env.PROXY_RPC_TIMEOUT_MS ?? "30000");
const INDEX_INTERVAL_MS = Number(process.env.PROXY_INDEX_INTERVAL_MS ?? "500");
const INDEX_CONCURRENCY = Number(process.env.PROXY_INDEX_CONCURRENCY ?? "32");
const INDEX_BURST = Number(process.env.PROXY_INDEX_BURST ?? "128");
const RANGE_MAX = Number(process.env.PROXY_TXS_RANGE_MAX ?? "32");

const PUBLIC_SAFE = new Set([
  "get_block",
  "get_block_header",
  "get_block_evolution",
  "get_block_headers",
  "get_block_txs",
  "get_block_txs_range",
  "get_tx_count_totals",
  "get_chain_params",
  "get_claims_by_pubkey",
  "get_claims_for",
  "get_checkpoint",
  "get_light_checkpoint_summary",
  "get_light_follow",
  "get_light_snapshot",
  "get_mempool",
  "get_mempool_tx",
  "get_proof_pool",
  "get_storage_challenge",
  "get_status",
  "get_tip",
  "list_data_roots_with_claims",
  "list_fraud_contests",
  "list_methods",
  "list_recent_claims",
  "list_recent_uploads",
  "list_utxos",
  // Browser wallet submit (testnet only). Rate-limit separately if abused.
  "submit_tx",
]);

/** Proxy-synthesized methods (not forwarded to mfnd). */
const PROXY_LOCAL = new Set(["get_tx_count_totals", "get_block_txs_range"]);

const [mfndHost, mfndPortStr] = MFND_RPC.split(":");
const mfndPort = Number(mfndPortStr ?? "18734");

/** @type {Map<number, { all: number, user: number }>} */
const txCountByHeight = new Map();
/** @type {Map<number, string>} raw JSON-RPC result object as string (just the result) */
const txsResultByHeight = new Map();
let indexedTip = 0;
let indexBusy = false;
let indexErrors = 0;

function tcpLineRpc(line) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: mfndHost, port: mfndPort }, () => {
      socket.write(line.endsWith("\n") ? line : `${line}\n`);
    });
    let buf = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("mfnd RPC timeout"));
    }, RPC_TIMEOUT_MS);
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buf += chunk;
      if (buf.includes("\n")) {
        clearTimeout(timer);
        socket.end();
        resolve(buf.trim());
      }
    });
    socket.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    socket.on("end", () => {
      clearTimeout(timer);
      if (buf) resolve(buf.trim());
    });
  });
}

async function mfndCall(method, params, id = 1) {
  const line = await tcpLineRpc(
    JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  );
  const obj = JSON.parse(line);
  if (obj.error) {
    throw new Error(obj.error.message || `RPC error ${obj.error.code}`);
  }
  return obj.result;
}

function readLeb128(bytes, off) {
  let value = 0;
  let shift = 0;
  let i = off;
  while (i < bytes.length) {
    const b = bytes[i];
    value |= (b & 0x7f) << shift;
    i++;
    if ((b & 0x80) === 0) return { value, next: i };
    shift += 7;
    if (shift > 35) return null;
  }
  return null;
}

/** Coinbase-shaped iff wire inputs length is 0. */
function isCoinbaseTxHex(hex) {
  const raw = String(hex || "")
    .replace(/\s+/g, "")
    .toLowerCase();
  if (raw.length < 2 + 64 + 16 || raw.length % 2 !== 0) return false;
  try {
    const bytes = new Uint8Array(raw.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
    }
    let off = 0;
    while (off < bytes.length && bytes[off] & 0x80) off++;
    off++; // version
    off += 32; // r_pub
    off += 8; // fee
    if (off >= bytes.length) return false;
    const extraLen = readLeb128(bytes, off);
    if (!extraLen) return false;
    off = extraLen.next + extraLen.value;
    const inputs = readLeb128(bytes, off);
    return inputs != null && inputs.value === 0;
  } catch {
    return false;
  }
}

function countUserTxs(txs) {
  let user = 0;
  for (const item of txs || []) {
    if (!item || typeof item !== "object") continue;
    if (typeof item.tx_hex === "string") {
      if (!isCoinbaseTxHex(item.tx_hex)) user++;
    } else if (typeof item.tx_index === "number" && item.tx_index !== 0) {
      user++;
    }
  }
  return user;
}

function rememberBlockTxs(height, result) {
  const txs = Array.isArray(result?.txs) ? result.txs : [];
  txCountByHeight.set(height, { all: txs.length, user: countUserTxs(txs) });
  txsResultByHeight.set(height, JSON.stringify(result));
  if (height > indexedTip) indexedTip = height;
}

async function fetchAndCacheHeight(height) {
  if (txsResultByHeight.has(height)) return;
  const result = await mfndCall("get_block_txs", { height });
  rememberBlockTxs(height, result);
}

async function mapPool(items, concurrency, fn) {
  if (items.length === 0) return;
  let next = 0;
  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    async () => {
      while (true) {
        const i = next++;
        if (i >= items.length) return;
        await fn(items[i]);
      }
    },
  );
  await Promise.all(workers);
}

async function indexTick() {
  if (indexBusy) return;
  indexBusy = true;
  try {
    const tip = await mfndCall("get_tip", {});
    const tipH = Number(tip?.tip_height ?? 0);
    if (tipH < 1) return;

    // Prefer filling near tip first (explore + fresh wallets), then older gaps.
    const missing = [];
    for (let h = tipH; h >= 1 && missing.length < INDEX_BURST; h--) {
      if (!txCountByHeight.has(h)) missing.push(h);
    }
    if (missing.length === 0) {
      indexedTip = tipH;
      return;
    }
    await mapPool(missing, INDEX_CONCURRENCY, async (h) => {
      try {
        await fetchAndCacheHeight(h);
      } catch (e) {
        indexErrors += 1;
        if (indexErrors <= 5 || indexErrors % 50 === 0) {
          console.error(`index height ${h}:`, e instanceof Error ? e.message : e);
        }
      }
    });
    indexedTip = tipH;
  } catch (e) {
    indexErrors += 1;
    if (indexErrors <= 5 || indexErrors % 50 === 0) {
      console.error("index tip:", e instanceof Error ? e.message : e);
    }
  } finally {
    indexBusy = false;
  }
}

function summarizeTotals(tipHeight) {
  let totalUser = 0;
  let covered = 0;
  for (let h = 1; h <= tipHeight; h++) {
    const c = txCountByHeight.get(h);
    if (c) {
      totalUser += c.user;
      covered++;
    }
  }
  return {
    tip_height: tipHeight,
    covered_heights: covered,
    total_user_tx_count: covered > 0 ? totalUser : 0,
    complete: tipHeight > 0 && covered === tipHeight,
    indexed_tip: indexedTip,
    cache_entries: txCountByHeight.size,
  };
}

async function handleGetTxCountTotals() {
  let tipH = indexedTip;
  try {
    const tip = await mfndCall("get_tip", {});
    tipH = Number(tip?.tip_height ?? tipH);
  } catch {
    // use indexed tip
  }
  return summarizeTotals(tipH);
}

async function handleGetBlockTxsRange(params) {
  const from = Number(params?.from_height ?? params?.from ?? 0);
  const to = Number(params?.to_height ?? params?.to ?? 0);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from < 1 || to < from) {
    throw Object.assign(new Error("invalid from_height/to_height"), {
      code: -32602,
    });
  }
  if (to - from + 1 > RANGE_MAX) {
    throw Object.assign(
      new Error(`range exceeds max ${RANGE_MAX} heights`),
      { code: -32602 },
    );
  }
  const heights = [];
  for (let h = from; h <= to; h++) heights.push(h);
  await mapPool(heights, INDEX_CONCURRENCY, async (h) => {
    await fetchAndCacheHeight(h);
  });
  const blocks = heights.map((h) => {
    const raw = txsResultByHeight.get(h);
    const result = raw ? JSON.parse(raw) : { height: h, txs: [] };
    const counts = txCountByHeight.get(h) || { all: 0, user: 0 };
    return {
      height: h,
      block_id: result.block_id,
      txs: result.txs || [],
      tx_count: counts.all,
      user_tx_count: counts.user,
    };
  });
  return { from_height: from, to_height: to, blocks };
}

async function handleGetBlockTxs(params, id) {
  const height = Number(params?.height);
  if (!Number.isFinite(height) || height < 1) {
    const line = await tcpLineRpc(
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        method: "get_block_txs",
        params,
      }),
    );
    return line;
  }
  if (!txsResultByHeight.has(height)) {
    await fetchAndCacheHeight(height);
  }
  const result = JSON.parse(txsResultByHeight.get(height));
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

const server = http.createServer(async (req, res) => {
  cors(res);

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url === "/health" && req.method === "GET") {
    const totals = summarizeTotals(indexedTip);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        backend: MFND_RPC,
        index: totals,
        index_errors: indexErrors,
      }),
    );
    return;
  }

  if (req.url !== "/rpc" || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end(
      "POST /rpc with JSON-RPC body (public-safe methods only)\nGET /health\n",
    );
    return;
  }

  try {
    const body = await readBody(req);
    let msg;
    try {
      msg = JSON.parse(body);
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        }) + "\n",
      );
      return;
    }
    const method = typeof msg?.method === "string" ? msg.method : "";
    const id = msg?.id ?? null;
    if (!PUBLIC_SAFE.has(method)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id,
          error: {
            code: -32601,
            message: `method not allowed on public observer proxy: ${method || "(missing)"}`,
          },
        }) + "\n",
      );
      return;
    }

    let line;
    if (method === "get_tx_count_totals") {
      const result = await handleGetTxCountTotals();
      line = JSON.stringify({ jsonrpc: "2.0", id, result });
    } else if (method === "get_block_txs_range") {
      try {
        const result = await handleGetBlockTxsRange(msg.params || {});
        line = JSON.stringify({ jsonrpc: "2.0", id, result });
      } catch (e) {
        line = JSON.stringify({
          jsonrpc: "2.0",
          id,
          error: {
            code: e?.code ?? -32000,
            message: e instanceof Error ? e.message : String(e),
          },
        });
      }
    } else if (method === "get_block_txs") {
      line = await handleGetBlockTxs(msg.params || {}, id);
    } else if (method === "list_methods") {
      const upstream = await tcpLineRpc(JSON.stringify(msg));
      try {
        const obj = JSON.parse(upstream);
        if (Array.isArray(obj.result)) {
          for (const m of PROXY_LOCAL) {
            if (!obj.result.includes(m)) obj.result.push(m);
          }
          line = JSON.stringify(obj);
        } else {
          line = upstream;
        }
      } catch {
        line = upstream;
      }
    } else {
      line = await tcpLineRpc(JSON.stringify(msg));
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(line.endsWith("\n") ? line : `${line}\n`);
  } catch (e) {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(String(e));
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `observer-rpc-proxy http://${LISTEN_HOST}:${LISTEN_PORT}/rpc -> tcp://${MFND_RPC} (cache+index)`,
  );
  void indexTick();
  setInterval(() => {
    void indexTick();
  }, INDEX_INTERVAL_MS);
});

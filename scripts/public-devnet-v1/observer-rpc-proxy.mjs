#!/usr/bin/env node
/**
 * Lane 7: public-safe HTTP → TCP JSON-RPC bridge for a dedicated observer.
 *
 *   MFND_RPC=127.0.0.1:18734 PROXY_HOST=0.0.0.0 PROXY_PORT=8787 \
 *     node scripts/public-devnet-v1/observer-rpc-proxy.mjs
 *
 * Browses POST JSON-RPC to /rpc. Only public-safe methods are forwarded.
 */

import http from "node:http";
import net from "node:net";

const MFND_RPC = process.env.MFND_RPC ?? "127.0.0.1:18734";
const LISTEN_HOST = process.env.PROXY_HOST ?? "0.0.0.0";
const LISTEN_PORT = Number(process.env.PROXY_PORT ?? "8787");
const MAX_BODY = Number(process.env.PROXY_MAX_BODY_BYTES ?? "65536");

const PUBLIC_SAFE = new Set([
  "get_block",
  "get_block_header",
  "get_block_evolution",
  "get_block_headers",
  "get_block_txs",
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

const [mfndHost, mfndPortStr] = MFND_RPC.split(":");
const mfndPort = Number(mfndPortStr ?? "18734");

function tcpLineRpc(line) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: mfndHost, port: mfndPort }, () => {
      socket.write(line.endsWith("\n") ? line : `${line}\n`);
    });
    let buf = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("mfnd RPC timeout"));
    }, 15_000);
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
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, backend: MFND_RPC }));
    return;
  }

  if (req.url !== "/rpc" || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("POST /rpc with JSON-RPC body (public-safe methods only)\nGET /health\n");
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
    if (!PUBLIC_SAFE.has(method)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: msg?.id ?? null,
          error: {
            code: -32601,
            message: `method not allowed on public observer proxy: ${method || "(missing)"}`,
          },
        }) + "\n",
      );
      return;
    }
    const line = await tcpLineRpc(JSON.stringify(msg));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(line.endsWith("\n") ? line : `${line}\n`);
  } catch (e) {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(String(e));
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `observer-rpc-proxy http://${LISTEN_HOST}:${LISTEN_PORT}/rpc -> tcp://${MFND_RPC} (public-safe only)`,
  );
});

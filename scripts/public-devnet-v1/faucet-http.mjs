#!/usr/bin/env node
/**
 * Rate-limited public testnet faucet HTTP API.
 *
 * Holds operator faucet wallet keys server-side only. Frontend calls:
 *   POST /faucet  { "address": "mf…", "amount"?: number }
 *
 * Env:
 *   FAUCET_WALLET   path to wallet.json (default /root/testnet-wallets/validator0-faucet.json)
 *   MFN_CLI         path to mfn-cli binary
 *   MFND_RPC        loopback RPC with submit_tx (default 127.0.0.1:18731)
 *   PROXY_HOST / PROXY_PORT  listen (default 0.0.0.0:8788)
 *   FAUCET_AMOUNT   atomic units per claim half (two sends; default 500000)
 *   FAUCET_FEE      fee per send (default 10000)
 *   FAUCET_COOLDOWN_MS  per-address cooldown (default 6h)
 */

import http from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const LISTEN_HOST = process.env.PROXY_HOST ?? "0.0.0.0";
const LISTEN_PORT = Number(process.env.PROXY_PORT ?? "8788");
const MFND_RPC = process.env.MFND_RPC ?? "127.0.0.1:18731";
const MFN_CLI =
  process.env.MFN_CLI ?? "/root/permawrite/target/release/mfn-cli";
const FAUCET_WALLET =
  process.env.FAUCET_WALLET ??
  "/root/testnet-wallets/validator0-faucet.json";
const AMOUNT = Number(process.env.FAUCET_AMOUNT ?? "500000");
const FEE = Number(process.env.FAUCET_FEE ?? "10000");
const RING = Number(process.env.FAUCET_RING_SIZE ?? "16");
const COOLDOWN_MS = Number(process.env.FAUCET_COOLDOWN_MS ?? String(6 * 3600_000));
const MAX_BODY = 8192;

/** @type {Map<string, number>} */
const lastClaim = new Map();
/** @type {Map<string, number>} */
const lastIpClaim = new Map();
let busy = false;

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
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

function run(bin, args, timeoutMs = 180_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`timeout: ${bin} ${args.join(" ")}`));
    }, timeoutMs);
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(
          new Error(
            `${bin} exited ${code}: ${(stderr || stdout).trim().slice(0, 800)}`,
          ),
        );
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length) return xff.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

function validAddress(addr) {
  if (typeof addr !== "string") return false;
  const a = addr.trim();
  if (!a.startsWith("mf")) return false;
  if (a.length !== 2 + 136) return false; // 68 bytes hex
  return /^mf[0-9a-fA-F]+$/.test(a);
}

async function fundAddress(address, amount) {
  if (!fs.existsSync(FAUCET_WALLET)) {
    throw new Error(`faucet wallet missing: ${FAUCET_WALLET}`);
  }
  if (!fs.existsSync(MFN_CLI)) {
    throw new Error(`mfn-cli missing: ${MFN_CLI}`);
  }

  await run(MFN_CLI, [
    "--rpc",
    MFND_RPC,
    "--wallet",
    FAUCET_WALLET,
    "wallet",
    "scan",
  ]);

  const txIds = [];
  // Two sends so recipient meets the F7 two-input floor for later transfers.
  for (let i = 0; i < 2; i++) {
    const { stdout } = await run(MFN_CLI, [
      "--rpc",
      MFND_RPC,
      "--wallet",
      FAUCET_WALLET,
      "wallet",
      "send",
      address,
      String(amount),
      "--fee",
      String(FEE),
      "--ring-size",
      String(RING),
      "--json",
    ]);
    const start = stdout.indexOf("{");
    const end = stdout.lastIndexOf("}");
    if (start < 0 || end <= start) {
      throw new Error(`faucet send returned no JSON: ${stdout.slice(0, 200)}`);
    }
    const parsed = JSON.parse(stdout.slice(start, end + 1));
    txIds.push(parsed.tx_id || parsed.txId || null);
    // brief pause so mempool/UTXO selection can rotate if needed
    await new Promise((r) => setTimeout(r, 1500));
    await run(MFN_CLI, [
      "--rpc",
      MFND_RPC,
      "--wallet",
      FAUCET_WALLET,
      "wallet",
      "scan",
    ]);
  }

  return {
    ok: true,
    address,
    amount_per_send: amount,
    sends: 2,
    total_amount: amount * 2,
    fee_per_send: FEE,
    tx_ids: txIds,
  };
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
    res.end(
      JSON.stringify({
        ok: true,
        rpc: MFND_RPC,
        wallet: path.basename(FAUCET_WALLET),
        amount_per_send: AMOUNT,
        sends: 2,
        cooldown_ms: COOLDOWN_MS,
      }),
    );
    return;
  }

  if (req.url !== "/faucet" || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("POST /faucet {address}\nGET /health\n");
    return;
  }

  try {
    const raw = await readBody(req);
    let body;
    try {
      body = JSON.parse(raw || "{}");
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "invalid json" }));
      return;
    }

    const address = String(body.address || "").trim();
    if (!validAddress(address)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "invalid mf address" }));
      return;
    }

    const amount = Number(body.amount ?? AMOUNT);
    if (!Number.isFinite(amount) || amount < 10_000 || amount > AMOUNT) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          ok: false,
          error: `amount must be between 10000 and ${AMOUNT}`,
        }),
      );
      return;
    }

    const now = Date.now();
    const ip = clientIp(req);
    const prevAddr = lastClaim.get(address.toLowerCase()) || 0;
    const prevIp = lastIpClaim.get(ip) || 0;
    if (now - prevAddr < COOLDOWN_MS) {
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          ok: false,
          error: "address cooldown — try again later",
          retry_after_ms: COOLDOWN_MS - (now - prevAddr),
        }),
      );
      return;
    }
    if (now - prevIp < Math.min(COOLDOWN_MS, 30 * 60_000)) {
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          ok: false,
          error: "ip cooldown — try again later",
        }),
      );
      return;
    }

    if (busy) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "faucet busy — retry shortly" }));
      return;
    }

    busy = true;
    try {
      const result = await fundAddress(address, amount);
      lastClaim.set(address.toLowerCase(), Date.now());
      lastIpClaim.set(ip, Date.now());
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
    } finally {
      busy = false;
    }
  } catch (e) {
    busy = false;
    console.error("faucet error", e);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        ok: false,
        error: e instanceof Error ? e.message : String(e),
      }),
    );
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `faucet-http http://${LISTEN_HOST}:${LISTEN_PORT}/faucet -> ${MFND_RPC} wallet=${FAUCET_WALLET}`,
  );
});

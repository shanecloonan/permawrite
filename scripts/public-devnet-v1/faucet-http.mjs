#!/usr/bin/env node
/**
 * Rate-limited public testnet faucet HTTP API (async jobs).
 *
 * Holds operator faucet wallet keys server-side only. Frontend:
 *   POST /faucet  { "address": "mf…" }  → 202 { job_id, status:"pending" }
 *   GET  /faucet/job?id=<job_id>        → { status, result | error }
 *   GET  /health
 *
 * Why async: Vercel serverless aborts long upstream waits (~60–170s). Claims can
 * take longer when mfn-cli is slow; the proxy must return immediately and poll.
 *
 * Env:
 *   FAUCET_WALLET, MFN_CLI, MFND_RPC, PROXY_HOST, PROXY_PORT
 *   FAUCET_AMOUNT, FAUCET_FEE, FAUCET_RING_SIZE, FAUCET_COOLDOWN_MS
 *   FAUCET_SEND_TIMEOUT_MS (default 300000)
 *   FAUCET_KEEPALIVE_MS (default 45000) — background wallet scan so send
 *     never has to catch up thousands of producer coinbase blocks at once
 *   FAUCET_SYNC_BEHIND (default 8) — max blocks_behind before a claim forces sync
 */

import http from "node:http";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { URL } from "node:url";

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
// Public testnet: short cooldown so F7 (2-UTXO) top-ups stay usable after a send.
const COOLDOWN_MS = Number(
  process.env.FAUCET_COOLDOWN_MS ?? String(15 * 60_000),
);
const SEND_TIMEOUT_MS = Number(process.env.FAUCET_SEND_TIMEOUT_MS ?? "300000");
const KEEPALIVE_MS = Number(process.env.FAUCET_KEEPALIVE_MS ?? "45000");
const SYNC_BEHIND = Number(process.env.FAUCET_SYNC_BEHIND ?? "8");
const SYNC_TIMEOUT_MS = Number(
  process.env.FAUCET_SYNC_TIMEOUT_MS ?? String(Math.max(SEND_TIMEOUT_MS, 240_000)),
);
const MAX_BODY = 8192;
const JOB_TTL_MS = 30 * 60_000;

/** @type {Map<string, number>} */
const lastClaim = new Map();
/** @type {Map<string, number>} */
const lastIpClaim = new Map();
/** @type {Map<string, object>} */
const jobs = new Map();
let busy = false;
/** Last successful wallet status — served by /health while a claim holds the lock. */
let lastWalletStatus = null;
/** Serialize wallet scan/send so keepalive/health never races a claim. */
let walletLock = Promise.resolve();

function withWalletLock(fn) {
  const prev = walletLock;
  let release;
  walletLock = new Promise((r) => {
    release = r;
  });
  return prev
    .catch(() => {})
    .then(fn)
    .finally(() => release());
}

function isTransientCliError(err) {
  const m = String(err?.message || err);
  return /os error 11|Resource temporarily unavailable|EAGAIN|Connection refused|os error 111|ECONNREFUSED/i.test(
    m,
  );
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function json(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(obj));
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

function run(bin, args, timeoutMs = SEND_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`timeout after ${timeoutMs}ms: ${bin} ${args.join(" ")}`));
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

/** Retry hub RPC blips (EAGAIN / refused) — common under concurrent mfn-cli. */
async function runRetry(bin, args, timeoutMs = SEND_TIMEOUT_MS, attempts = 4) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      return await run(bin, args, timeoutMs);
    } catch (e) {
      last = e;
      if (!isTransientCliError(e) || i === attempts - 1) throw e;
      const delay = 400 * (i + 1);
      console.warn(
        `faucet cli retry ${i + 1}/${attempts} in ${delay}ms:`,
        String(e.message || e).slice(0, 160),
      );
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw last;
}

/** TCP peer only — never trust X-Forwarded-For for rate-limit bypass decisions. */
function peerIp(req) {
  return req.socket.remoteAddress || "unknown";
}

function isLoopbackIp(ip) {
  if (!ip) return false;
  const n = ip.toLowerCase();
  return (
    n === "127.0.0.1" ||
    n === "::1" ||
    n === "localhost" ||
    n.startsWith("::ffff:127.0.0.1")
  );
}

async function walletStatus() {
  const { stdout } = await runRetry(
    MFN_CLI,
    ["--rpc", MFND_RPC, "--wallet", FAUCET_WALLET, "wallet", "status", "--json"],
    30_000,
  );
  const start = stdout.indexOf("{");
  const end = stdout.lastIndexOf("}");
  if (start < 0 || end <= start) {
    throw new Error(`wallet status returned no JSON: ${stdout.slice(0, 200)}`);
  }
  const parsed = JSON.parse(stdout.slice(start, end + 1));
  lastWalletStatus = parsed;
  return parsed;
}

async function syncWallet(reason) {
  const t0 = Date.now();
  await runRetry(
    MFN_CLI,
    ["--rpc", MFND_RPC, "--wallet", FAUCET_WALLET, "wallet", "scan"],
    SYNC_TIMEOUT_MS,
  );
  const st = await walletStatus().catch(() => null);
  console.log(
    `faucet wallet sync (${reason}) ${Date.now() - t0}ms` +
      (st
        ? ` tip=${st.tip_height} scan=${st.scan_height} behind=${st.blocks_behind}`
        : ""),
  );
  return st;
}

async function ensureWalletReady(reason) {
  let st;
  try {
    st = await walletStatus();
  } catch (e) {
    console.warn("faucet wallet status failed; forcing sync", e);
    return syncWallet(`${reason}:status-failed`);
  }
  const behind = Number(st.blocks_behind ?? 0);
  if (st.sync_needed || behind > SYNC_BEHIND) {
    return syncWallet(`${reason}:behind=${behind}`);
  }
  return st;
}

async function getTipHeight() {
  const { stdout } = await runRetry(
    MFN_CLI,
    ["--rpc", MFND_RPC, "tip"],
    15_000,
  );
  const m = stdout.match(/tip_height=(\d+)/);
  return m ? Number(m[1]) : 0;
}

/** Wait for at least one new block so the faucet wallet can rescan spent inputs. */
async function waitTipAdvance(fromHeight, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const h = await getTipHeight();
    if (h > fromHeight) {
      return h;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(
    `tip did not advance from ${fromHeight} within ${timeoutMs}ms`,
  );
}

function validAddress(addr) {
  if (typeof addr !== "string") return false;
  const a = addr.trim();
  if (!a.startsWith("mf")) return false;
  if (a.length !== 2 + 136) return false;
  return /^mf[0-9a-fA-F]+$/.test(a);
}

function pruneJobs() {
  const now = Date.now();
  for (const [id, job] of jobs) {
    if (now - (job.createdAt || 0) > JOB_TTL_MS) jobs.delete(id);
  }
}

async function fundAddress(address, amount) {
  if (!fs.existsSync(FAUCET_WALLET)) {
    throw new Error(`faucet wallet missing: ${FAUCET_WALLET}`);
  }
  if (!fs.existsSync(MFN_CLI)) {
    throw new Error(`mfn-cli missing: ${MFN_CLI}`);
  }

  return withWalletLock(async () => {
    const t0 = Date.now();
    // Producer faucet accrues a coinbase every block. If scan_height falls
    // thousands behind tip, each `wallet send` light-sync times out. Catch up
    // explicitly first (keepalive usually keeps this near zero).
    await ensureWalletReady("claim");

    const txIds = [];
    let tipBefore = await getTipHeight();
    // Two sends so recipient meets the F7 two-input floor for later transfers.
    // Rescan + wait for a block between sends — back-to-back spends reuse stale
    // UTXOs and mempool rejects with "key image already spent on chain".
    for (let i = 0; i < 2; i++) {
      if (i > 0) {
        try {
          await waitTipAdvance(tipBefore);
        } catch (e) {
          console.warn("faucet between-send tip wait:", e.message);
        }
        await syncWallet("between-fund-sends");
      }
      const { stdout } = await runRetry(MFN_CLI, [
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
      tipBefore = await getTipHeight();
    }

    return {
      ok: true,
      address,
      amount_per_send: amount,
      sends: 2,
      total_amount: amount * 2,
      fee_per_send: FEE,
      tx_ids: txIds,
      duration_ms: Date.now() - t0,
    };
  });
}

const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/health" && req.method === "GET") {
    pruneJobs();
    // Never spawn mfn-cli while a claim holds the wallet lock — concurrent CLI
    // against hub RPC was the B-15 wave4/5 EAGAIN (os error 11) failure mode.
    let wallet = lastWalletStatus;
    const statusCached = busy;
    if (!busy) {
      try {
        wallet = await withWalletLock(() => walletStatus());
      } catch {
        wallet = lastWalletStatus;
      }
    }
    json(res, 200, {
      ok: true,
      rpc: MFND_RPC,
      wallet: path.basename(FAUCET_WALLET),
      amount_per_send: AMOUNT,
      sends: 2,
      cooldown_ms: COOLDOWN_MS,
      busy,
      pending_jobs: [...jobs.values()].filter(
        (j) => j.status === "pending" || j.status === "running",
      ).length,
      async: true,
      keepalive_ms: KEEPALIVE_MS,
      send_timeout_ms: SEND_TIMEOUT_MS,
      wallet_scan_height: wallet?.scan_height ?? null,
      wallet_tip_height: wallet?.tip_height ?? null,
      wallet_blocks_behind: wallet?.blocks_behind ?? null,
      wallet_sync_needed: wallet?.sync_needed ?? null,
      wallet_status_cached: statusCached,
    });
    return;
  }

  if (
    (url.pathname === "/faucet/job" || url.pathname.startsWith("/faucet/job/")) &&
    req.method === "GET"
  ) {
    pruneJobs();
    const id =
      url.searchParams.get("id") ||
      url.pathname.replace(/^\/faucet\/job\/?/, "") ||
      "";
    if (!id) {
      json(res, 400, { ok: false, error: "missing job id" });
      return;
    }
    const job = jobs.get(id);
    if (!job) {
      json(res, 404, { ok: false, error: "unknown job id" });
      return;
    }
    if (job.status === "done") {
      json(res, 200, {
        ok: true,
        status: "done",
        job_id: id,
        ...job.result,
      });
      return;
    }
    if (job.status === "error") {
      json(res, 200, {
        ok: false,
        status: "error",
        job_id: id,
        error: job.error || "faucet failed",
      });
      return;
    }
    json(res, 200, {
      ok: true,
      status: job.status,
      job_id: id,
      age_ms: Date.now() - job.createdAt,
    });
    return;
  }

  if (url.pathname !== "/faucet" || req.method !== "POST") {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end(
      "POST /faucet {address} → {job_id}\nGET /faucet/job?id=\nGET /health\n",
    );
    return;
  }

  try {
    pruneJobs();
    const raw = await readBody(req);
    let body;
    try {
      body = JSON.parse(raw || "{}");
    } catch {
      json(res, 400, { ok: false, error: "invalid json" });
      return;
    }

    const address = String(body.address || "").trim();
    if (!validAddress(address)) {
      json(res, 400, { ok: false, error: "invalid mf address" });
      return;
    }

    const amount = Number(body.amount ?? AMOUNT);
    if (!Number.isFinite(amount) || amount < 10_000 || amount > AMOUNT) {
      json(res, 400, {
        ok: false,
        error: `amount must be between 10000 and ${AMOUNT}`,
      });
      return;
    }

    const now = Date.now();
    const peer = peerIp(req);
    const prevAddr = lastClaim.get(address.toLowerCase()) || 0;
    const prevIp = lastIpClaim.get(peer) || 0;
    if (now - prevAddr < COOLDOWN_MS) {
      json(res, 429, {
        ok: false,
        error: "address cooldown — try again later",
        retry_after_ms: COOLDOWN_MS - (now - prevAddr),
      });
      return;
    }
    if (
      !isLoopbackIp(peer) &&
      now - prevIp < Math.min(COOLDOWN_MS, 30 * 60_000)
    ) {
      json(res, 429, {
        ok: false,
        error: "ip cooldown — try again later",
      });
      return;
    }

    if (busy) {
      json(res, 503, {
        ok: false,
        error: "faucet busy — retry shortly",
      });
      return;
    }

    // Reserve busy before returning so two concurrent POSTs don't double-start.
    busy = true;
    const jobId = crypto.randomBytes(12).toString("hex");
    const job = {
      id: jobId,
      status: "pending",
      address,
      amount,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      result: null,
      error: null,
    };
    jobs.set(jobId, job);

    setImmediate(async () => {
      job.status = "running";
      job.updatedAt = Date.now();
      try {
        const result = await fundAddress(address, amount);
        lastClaim.set(address.toLowerCase(), Date.now());
        lastIpClaim.set(peer, Date.now());
        job.status = "done";
        job.result = result;
        job.updatedAt = Date.now();
      } catch (e) {
        job.status = "error";
        job.error = e instanceof Error ? e.message : String(e);
        job.updatedAt = Date.now();
        console.error("faucet job error", jobId, e);
      } finally {
        busy = false;
      }
    });

    json(res, 202, {
      ok: true,
      status: "pending",
      job_id: jobId,
      poll_path: `/faucet/job?id=${jobId}`,
      note: "Poll until status is done or error",
    });
  } catch (e) {
    busy = false;
    console.error("faucet error", e);
    json(res, 500, {
      ok: false,
      error: e instanceof Error ? e.message : String(e),
    });
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `faucet-http (async) http://${LISTEN_HOST}:${LISTEN_PORT}/faucet -> ${MFND_RPC} wallet=${FAUCET_WALLET} keepalive=${KEEPALIVE_MS}ms`,
  );
  // Catch up immediately, then keep scan_height near tip so claims stay fast.
  void withWalletLock(() => ensureWalletReady("startup")).catch((e) =>
    console.error("faucet startup sync failed", e),
  );
  if (KEEPALIVE_MS > 0) {
    setInterval(() => {
      if (busy) return;
      void withWalletLock(() => ensureWalletReady("keepalive")).catch((e) =>
        console.error("faucet keepalive sync failed", e),
      );
    }, KEEPALIVE_MS);
  }
});

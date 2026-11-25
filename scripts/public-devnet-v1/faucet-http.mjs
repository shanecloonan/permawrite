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
/**
 * Atomic units in each of the two recipient outputs.
 * Total credited = AMOUNT * OUTPUTS. Default 5_000_000 * 2 = 10_000_000,
 * about 1_000 send-fees (fee 10_000) so a fresh wallet can do ~50 sends
 * and still pay a storage upload.
 */
const AMOUNT = Number(process.env.FAUCET_AMOUNT ?? "5000000");
const OUTPUTS = 2;
const PAYOUT_WALLET =
  process.env.FAUCET_PAYOUT_WALLET ??
  "/root/testnet-wallets/validator0-faucet.json";
/** Per output on a faucet self-refill. Two outputs clear the F7 floor in one block. */
const TOPUP_PER_OUTPUT = Number(
  process.env.FAUCET_TOPUP_PER_OUTPUT ?? "100000000",
);
const PAYOUT_PRUNE_AT = 64;
const PAYOUT_PRUNE_KEEP = 32;
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
/** True while keepalive/claim/status holds the wallet CLI lock (B-53). */
let walletLockHeld = false;
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
    .then(async () => {
      walletLockHeld = true;
      try {
        return await fn();
      } finally {
        walletLockHeld = false;
        release();
      }
    });
}

/** Client-facing text. Server paths and raw mfn-cli stderr stay in the log. */
function friendlyCliFailure(detail) {
  const text = String(detail || "");
  if (/owned UTXO count|F7 privacy floor/i.test(text)) {
    return "The faucet is short a second spendable coin and is refilling. Try again in a minute.";
  }
  if (/timeout/i.test(text)) {
    return "The faucet took too long to confirm. Try again in a minute.";
  }
  if (/key image already spent/i.test(text)) {
    return "The faucet was already spending those coins. Try again in a minute.";
  }
  return "The faucet could not complete the transfer. Try again in a minute.";
}

function cliFailure(detail) {
  const err = new Error(friendlyCliFailure(detail));
  err.detail = String(detail || "");
  return err;
}

function isTransientCliError(err) {
  const m = String(err?.detail || err?.message || err);
  return /os error 11|Resource temporarily unavailable|EAGAIN|Connection refused|os error 111|ECONNREFUSED/i.test(
    m,
  );
}

function publicError(e) {
  const msg = e instanceof Error ? e.message : String(e);
  if (/\/(?:root|home|opt|usr|var|tmp)\b|mfn-cli|exited \d|target\/release/i.test(msg)) {
    console.error("faucet sanitized client error:", msg);
    return friendlyCliFailure(msg);
  }
  return msg;
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
      console.error(
        `faucet cli timeout after ${timeoutMs}ms: ${bin} ${args.join(" ")}`,
      );
      reject(new Error(`timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      console.error("faucet cli spawn error", bin, e);
      reject(cliFailure(String(e?.message || e)));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        const detail = (stderr || stdout).trim().slice(0, 800);
        console.error(
          `faucet cli exit ${code}: ${bin} ${args.join(" ")}\n${detail}`,
        );
        reject(cliFailure(detail));
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

function samePath(a, b) {
  try {
    return fs.realpathSync(a) === fs.realpathSync(b);
  } catch {
    return a === b;
  }
}

/**
 * Drop a bloated payout cache to the largest N coins. scan_height stays
 * put so a later scan does not resurrect the pruned history (B-278).
 */
function pruneOwnedFile(walletPath, keep) {
  let w;
  try {
    w = JSON.parse(fs.readFileSync(walletPath, "utf8"));
  } catch (e) {
    console.error("faucet prune read failed", e);
    return;
  }
  const owned = Array.isArray(w.owned_outputs) ? w.owned_outputs : [];
  if (owned.length <= PAYOUT_PRUNE_AT) return;
  const backup = `${walletPath}.bak-prePrune-${new Date()
    .toISOString()
    .replace(/[:.]/g, "")}`;
  fs.copyFileSync(walletPath, backup);
  const before = owned.length;
  owned.sort((a, b) => Number(b?.value || 0) - Number(a?.value || 0));
  w.owned_outputs = owned.slice(0, keep);
  w.pending_spent_utxo_keys = [];
  fs.writeFileSync(walletPath, `${JSON.stringify(w, null, 2)}\n`);
  console.log(
    `faucet prune ${path.basename(walletPath)} ${before}->${keep} backup=${path.basename(backup)}`,
  );
}

async function cliJson(args, timeoutMs) {
  const { stdout } = await runRetry(MFN_CLI, args, timeoutMs);
  const start = stdout.indexOf("{");
  const end = stdout.lastIndexOf("}");
  if (start < 0 || end <= start) {
    console.error("faucet cli returned no JSON", stdout.slice(0, 200));
    throw new Error("The faucet could not read its wallet. Try again in a minute.");
  }
  return JSON.parse(stdout.slice(start, end + 1));
}

async function ownedCount(walletPath) {
  const parsed = await cliJson(
    ["--rpc", MFND_RPC, "--wallet", walletPath, "wallet", "status", "--json"],
    60_000,
  );
  if (walletPath === FAUCET_WALLET) lastWalletStatus = parsed;
  return Number(parsed.owned_count_cached ?? parsed.owned_count ?? 0);
}

async function walletAddress(walletPath) {
  const { stdout } = await runRetry(
    MFN_CLI,
    ["--wallet", walletPath, "wallet", "address"],
    20_000,
  );
  const m = stdout.match(/address=(mf[0-9a-fA-F]+)/);
  if (!m) {
    console.error("faucet address output", stdout.slice(0, 200));
    throw new Error("The faucet could not read its address. Try again in a minute.");
  }
  return m[1];
}

/**
 * The hot faucet wallet does not receive coinbase. Each old send spent two
 * inputs and returned one change output, so the UTXO count fell by one until
 * a send saw owned count 1 and refused. Refill from the validator payout
 * (or wait for one coinbase if the faucet IS that wallet) before paying users.
 */
async function ensureFaucetFloat() {
  let owned = await ownedCount(FAUCET_WALLET);
  if (owned >= OUTPUTS) return owned;
  console.warn(
    `faucet owned=${owned} below F7 floor ${OUTPUTS}; refilling before the user send`,
  );
  const selfPay = !fs.existsSync(PAYOUT_WALLET) || samePath(PAYOUT_WALLET, FAUCET_WALLET);
  if (!selfPay) {
    pruneOwnedFile(PAYOUT_WALLET, PAYOUT_PRUNE_KEEP);
    const addr = await walletAddress(FAUCET_WALLET);
    const total = TOPUP_PER_OUTPUT * OUTPUTS;
    await runRetry(MFN_CLI, [
      "--rpc",
      MFND_RPC,
      "--wallet",
      PAYOUT_WALLET,
      "wallet",
      "send",
      addr,
      String(total),
      "--outputs",
      String(OUTPUTS),
      "--fee",
      String(FEE),
      "--ring-size",
      String(RING),
      "--json",
    ]);
  }
  owned = await waitUntilOwned(OUTPUTS, selfPay ? "coinbase-floor" : "post-topup");
  if (owned < OUTPUTS) {
    throw new Error(
      "The faucet is short a second spendable coin and is refilling. Try again in a minute.",
    );
  }
  return owned;
}

/** Rescan across new blocks until the faucet wallet shows `min` coins. */
async function waitUntilOwned(min, reason, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  let owned = await ownedCount(FAUCET_WALLET);
  while (owned < min && Date.now() < deadline) {
    const tip = await getTipHeight();
    const left = deadline - Date.now();
    try {
      await waitTipAdvance(tip, Math.min(45_000, Math.max(1_000, left)));
    } catch (e) {
      console.warn(`faucet ${reason} tip wait:`, e.message);
      break;
    }
    await syncWallet(reason);
    owned = await ownedCount(FAUCET_WALLET);
  }
  return owned;
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
    console.error("faucet wallet missing", FAUCET_WALLET);
    throw new Error("The faucet is not ready. Try again in a minute.");
  }
  if (!fs.existsSync(MFN_CLI)) {
    console.error("mfn-cli missing", MFN_CLI);
    throw new Error("The faucet is not ready. Try again in a minute.");
  }

  return withWalletLock(async () => {
    const t0 = Date.now();
    // Producer faucet accrues a coinbase every block. If scan_height falls
    // thousands behind tip, each `wallet send` light-sync times out. Catch up
    // explicitly first (keepalive usually keeps this near zero).
    await ensureWalletReady("claim");
    // One transaction, two outputs. Two back-to-back sends spent the
    // faucet down to a single change output, then the second send died
    // on the F7 floor and the user received nothing.
    await ensureFaucetFloat();
    const total = amount * OUTPUTS;
    const parsed = await cliJson(
      [
        "--rpc",
        MFND_RPC,
        "--wallet",
        FAUCET_WALLET,
        "wallet",
        "send",
        address,
        String(total),
        "--outputs",
        String(OUTPUTS),
        "--fee",
        String(FEE),
        "--ring-size",
        String(RING),
        "--json",
      ],
      SEND_TIMEOUT_MS,
    );
    const txId = parsed.tx_id || parsed.txId || null;

    return {
      ok: true,
      address,
      amount_per_send: amount,
      sends: OUTPUTS,
      output_count: OUTPUTS,
      total_amount: total,
      fee_per_send: FEE,
      tx_ids: txId ? [txId] : [],
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
    // B-53: never await the wallet lock on /health. Keepalive sync holds the
    // lock for several seconds; awaiting made curl --max-time 5 time out and
    // also serialized another mfn-cli onto hub (EAGAIN for light-snapshot).
    // Serve lastWalletStatus immediately; refresh in background when free.
    const wallet = lastWalletStatus;
    const statusCached = busy || walletLockHeld || wallet == null;
    if (!busy && !walletLockHeld) {
      void withWalletLock(() => walletStatus()).catch(() => {});
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
      wallet_lock_held: walletLockHeld,
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
        job.error = publicError(e);
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
      error: publicError(e),
    });
  }
});

/**
 * B-56: tip-first keepalive. When the faucet wallet is near tip, only poll
 * chain tip (no wallet lock / no wallet scan). Full ensureWalletReady under
 * the lock only when behind > SYNC_BEHIND. Cuts hub EAGAIN storms that broke
 * concurrent get_light_snapshot during B-15.
 */
async function keepaliveTick() {
  if (busy || walletLockHeld) return;
  let tip = 0;
  try {
    tip = await getTipHeight();
  } catch (e) {
    console.warn("faucet keepalive tip failed", e);
    return;
  }
  const scan = Number(lastWalletStatus?.scan_height ?? 0);
  const behind = Math.max(0, tip - scan);
  if (
    lastWalletStatus &&
    !lastWalletStatus.sync_needed &&
    behind <= SYNC_BEHIND
  ) {
    lastWalletStatus = {
      ...lastWalletStatus,
      tip_height: tip,
      blocks_behind: behind,
      sync_needed: behind > 0,
    };
    return;
  }
  await withWalletLock(() =>
    ensureWalletReady(`keepalive:behind=${behind}`),
  );
}

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `faucet-http (async) http://${LISTEN_HOST}:${LISTEN_PORT}/faucet -> ${MFND_RPC} wallet=${FAUCET_WALLET} keepalive=${KEEPALIVE_MS}ms tip-first`,
  );
  // Catch up immediately, then keep scan_height near tip so claims stay fast.
  void withWalletLock(() => ensureWalletReady("startup")).catch((e) =>
    console.error("faucet startup sync failed", e),
  );
  if (KEEPALIVE_MS > 0) {
    setInterval(() => {
      void keepaliveTick().catch((e) =>
        console.error("faucet keepalive sync failed", e),
      );
    }, KEEPALIVE_MS);
  }
});

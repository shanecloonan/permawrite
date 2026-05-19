/**
 * Incremental light-wallet sync over mfnd JSON-RPC (**M4.7**, **M4.9**).
 *
 * Verifies header linkage via `get_block_headers`, scans txs via `get_block_txs`
 * + WASM `scanBlockTxsHex` (avoids full `block_hex` per height).
 */

import { syncHeaderRange } from "./header-sync.js";

const STORAGE_PREFIX = "permawrite-wallet-sync:";

/** @typedef {{ lastScannedHeight: number, ownedKeyImages: string[], inputs: object[], lastTipBlockId?: string }} WalletSyncState */

/** @returns {WalletSyncState} */
export function emptyWalletSync() {
  return { lastScannedHeight: 0, ownedKeyImages: [], inputs: [] };
}

/**
 * @param {WalletSyncState} state
 * @param {object} scan parsed scanBlockHex JSON (block-level)
 */
export function applyBlockScan(state, scan) {
  const byAddr = new Map(
    state.inputs.map((o) => [o.one_time_addr_hex.toLowerCase(), o]),
  );
  const kiSet = new Set(state.ownedKeyImages.map((k) => k.toLowerCase()));

  for (const tx of scan.txs || []) {
    for (const ki of tx.spent_key_images || []) {
      const k = ki.toLowerCase();
      kiSet.add(k);
      state.inputs = state.inputs.filter(
        (o) => o.key_image_hex.toLowerCase() !== k,
      );
    }
    for (const o of tx.recovered || []) {
      const addr = o.one_time_addr_hex.toLowerCase();
      if (!byAddr.has(addr)) {
        state.inputs.push(o);
        byAddr.set(addr, o);
      }
      const ik = o.key_image_hex.toLowerCase();
      kiSet.add(ik);
    }
  }

  state.ownedKeyImages = [...kiSet];
  if (scan.height != null) {
    state.lastScannedHeight = Math.max(state.lastScannedHeight, Number(scan.height));
  }
  return state;
}

/** @param {WalletSyncState} state */
export function totalBalance(state) {
  return state.inputs.reduce((s, o) => s + Number(o.value || 0), 0);
}

/**
 * @param {string} seedHex
 * @returns {WalletSyncState}
 */
export function loadWalletSync(seedHex) {
  try {
    const raw = localStorage.getItem(STORAGE_PREFIX + seedHex);
    if (!raw) return emptyWalletSync();
    const parsed = JSON.parse(raw);
    return {
      lastScannedHeight: Number(parsed.lastScannedHeight) || 0,
      ownedKeyImages: Array.isArray(parsed.ownedKeyImages) ? parsed.ownedKeyImages : [],
      inputs: Array.isArray(parsed.inputs) ? parsed.inputs : [],
      lastTipBlockId:
        typeof parsed.lastTipBlockId === "string" ? parsed.lastTipBlockId : undefined,
    };
  } catch {
    return emptyWalletSync();
  }
}

/**
 * @param {string} seedHex
 * @param {WalletSyncState} state
 */
export function saveWalletSync(seedHex, state) {
  localStorage.setItem(STORAGE_PREFIX + seedHex, JSON.stringify(state));
}

/**
 * Scan blocks `fromHeight`…`toHeight` inclusive via header verify + tx-only RPC + WASM.
 *
 * @param {object} opts
 * @param {string} opts.rpcUrl
 * @param {string} opts.seedHex
 * @param {number} opts.fromHeight
 * @param {number} opts.toHeight
 * @param {WalletSyncState} opts.state
 * @param {(height: number) => void} [opts.onProgress]
 * @param {(url: string, method: string, params: object) => Promise<object>} opts.rpc
 * @param {(seed: string, height: number, txHexes: string[], keyImages: string[]) => string} opts.scanBlockTxsHex
 * @param {boolean} [opts.verifyHeaders=true]
 * @param {string} [opts.validatorsJson]
 * @param {string} [opts.consensusJson]
 * @param {(headerHex: string, validatorsJson: string, consensusJson: string) => string} [opts.verifyHeaderHex]
 * @param {(headerHex: string) => string} [opts.blockIdFromHeaderHex]
 */
export async function syncBlockRange({
  rpcUrl,
  seedHex,
  fromHeight,
  toHeight,
  state,
  onProgress,
  rpc,
  scanBlockTxsHex,
  verifyHeaders = true,
  validatorsJson,
  consensusJson,
  verifyHeaderHex,
  blockIdFromHeaderHex,
}) {
  if (fromHeight < 1) {
    throw new Error("fromHeight must be ≥ 1 (genesis is not in block log)");
  }
  if (toHeight < fromHeight) {
    throw new Error("toHeight must be ≥ fromHeight");
  }

  let headerSummary = null;
  if (verifyHeaders) {
    headerSummary = await syncHeaderRange({
      rpcUrl,
      fromHeight,
      toHeight,
      rpc,
      anchorBlockId: fromHeight > 1 ? state.lastTipBlockId : undefined,
      validatorsJson,
      consensusJson,
      verifyHeaderHex,
      blockIdFromHeaderHex,
      onProgress: (from, to) => {
        if (onProgress) onProgress(from);
        void to;
      },
    });
    if (headerSummary.tip_block_id) {
      state.lastTipBlockId = headerSummary.tip_block_id;
    }
  }

  let blocksOk = 0;
  let recoveredThisRun = 0;
  for (let h = fromHeight; h <= toHeight; h++) {
    if (onProgress) onProgress(h);
    const body = await rpc(rpcUrl, "get_block_txs", { height: h });
    const txHexes = (body.txs || []).map((t) => t.tx_hex).filter(Boolean);
    const scanJson = scanBlockTxsHex(
      seedHex,
      h,
      txHexes,
      state.ownedKeyImages,
    );
    const scan = JSON.parse(scanJson);
    const before = state.inputs.length;
    applyBlockScan(state, scan);
    recoveredThisRun += state.inputs.length - before;
    if (body.block_id) {
      state.lastTipBlockId = body.block_id;
    }
    blocksOk += 1;
  }
  return {
    blocksOk,
    fromHeight,
    toHeight,
    recoveredThisRun,
    balance: totalBalance(state),
    utxoCount: state.inputs.length,
    headers: headerSummary,
  };
}

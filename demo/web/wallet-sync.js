/**
 * Incremental light-wallet sync over mfnd JSON-RPC (**M4.7**).
 *
 * Fetches `get_block` for each height, runs WASM `scanBlockHex`, tracks
 * owned outputs and key images for spend detection across blocks.
 */

const STORAGE_PREFIX = "permawrite-wallet-sync:";

/** @typedef {{ lastScannedHeight: number, ownedKeyImages: string[], inputs: object[] }} WalletSyncState */

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
 * Scan blocks `fromHeight`…`toHeight` inclusive via RPC + WASM.
 *
 * @param {object} opts
 * @param {string} opts.rpcUrl
 * @param {string} opts.seedHex
 * @param {number} opts.fromHeight
 * @param {number} opts.toHeight
 * @param {WalletSyncState} opts.state
 * @param {(height: number) => void} [opts.onProgress]
 * @param {(url: string, method: string, params: object) => Promise<object>} opts.rpc
 * @param {(seed: string, blockHex: string, keyImages: string[]) => string} opts.scanBlockHex
 */
export async function syncBlockRange({
  rpcUrl,
  seedHex,
  fromHeight,
  toHeight,
  state,
  onProgress,
  rpc,
  scanBlockHex,
}) {
  if (fromHeight < 1) {
    throw new Error("fromHeight must be ≥ 1 (genesis is not in block log)");
  }
  if (toHeight < fromHeight) {
    throw new Error("toHeight must be ≥ fromHeight");
  }
  let blocksOk = 0;
  let recoveredThisRun = 0;
  for (let h = fromHeight; h <= toHeight; h++) {
    if (onProgress) onProgress(h);
    const block = await rpc(rpcUrl, "get_block", { height: h });
    const hex = block.block_hex;
    if (!hex) throw new Error(`get_block height ${h}: missing block_hex`);
    const scanJson = scanBlockHex(seedHex, hex, state.ownedKeyImages);
    const scan = JSON.parse(scanJson);
    const before = state.inputs.length;
    applyBlockScan(state, scan);
    recoveredThisRun += state.inputs.length - before;
    blocksOk += 1;
  }
  return {
    blocksOk,
    fromHeight,
    toHeight,
    recoveredThisRun,
    balance: totalBalance(state),
    utxoCount: state.inputs.length,
  };
}

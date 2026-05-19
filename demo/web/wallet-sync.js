/**
 * Incremental light-wallet sync over mfnd JSON-RPC (**M4.7**–**M4.11**).
 *
 * Per block: hash linkage batch, BLS header verify against evolving checkpoint,
 * tx scan via `get_block_txs`, validator-set evolution via `get_block_evolution`.
 */

import { syncHeaderRange, verifyHeaderChain } from "./header-sync.js";

const STORAGE_PREFIX = "permawrite-wallet-sync:";
const CHECKPOINT_PREFIX = "permawrite-light-checkpoint:";

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

export function loadLightCheckpoint(seedHex) {
  return localStorage.getItem(CHECKPOINT_PREFIX + seedHex);
}

export function saveLightCheckpoint(seedHex, checkpointHex) {
  localStorage.setItem(CHECKPOINT_PREFIX + seedHex, checkpointHex);
}

function evolutionJsonFromRpc(page) {
  const slashings = (page.slashings || []).map((s) => s.evidence_hex).filter(Boolean);
  const bond_ops = (page.bond_ops || []).map((b) => b.op_hex).filter(Boolean);
  return JSON.stringify({ slashings, bond_ops });
}

/**
 * @param {object} opts
 * @param {string} opts.rpcUrl
 * @param {string} opts.seedHex
 * @param {number} opts.fromHeight
 * @param {number} opts.toHeight
 * @param {WalletSyncState} opts.state
 * @param {(height: number) => void} [opts.onProgress]
 * @param {(url: string, method: string, params: object) => Promise<object>} opts.rpc
 * @param {(seed: string, height: number, txHexes: string[], keyImages: string[]) => string} opts.scanBlockTxsHex
 * @param {(checkpointHex: string, headerHex: string) => string} opts.lightChainVerifyHeader
 * @param {(checkpointHex: string, headerHex: string, evolutionJson: string) => string} opts.lightChainApplyEvolution
 * @param {(trustJson: string) => string} [opts.lightChainBootstrapCheckpoint]
 * @param {string} [opts.initialCheckpointHex]
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
  lightChainVerifyHeader,
  lightChainApplyEvolution,
  lightChainBootstrapCheckpoint,
  initialCheckpointHex,
}) {
  if (fromHeight < 1) {
    throw new Error("fromHeight must be ≥ 1 (genesis is not in block log)");
  }
  if (toHeight < fromHeight) {
    throw new Error("toHeight must be ≥ fromHeight");
  }

  const headerPage = await rpc(rpcUrl, "get_block_headers", {
    from_height: fromHeight,
    to_height: toHeight,
  });
  const link = verifyHeaderChain(
    headerPage.headers || [],
    headerPage.genesis_id,
    fromHeight > 1 ? state.lastTipBlockId : undefined,
  );
  if (!link.ok) {
    throw new Error(link.error || "header linkage failed");
  }

  let checkpoint =
    initialCheckpointHex ||
    loadLightCheckpoint(seedHex) ||
    null;
  if (!checkpoint) {
    if (!lightChainBootstrapCheckpoint) {
      throw new Error("missing light checkpoint; pass lightChainBootstrapCheckpoint");
    }
    const params = await rpc(rpcUrl, "get_chain_params", {});
    checkpoint = lightChainBootstrapCheckpoint(JSON.stringify(params));
    saveLightCheckpoint(seedHex, checkpoint);
  }

  const headerByHeight = new Map(
    (headerPage.headers || []).map((row) => [Number(row.height), row]),
  );

  let blocksOk = 0;
  let recoveredThisRun = 0;
  let evolutionSteps = 0;

  for (let h = fromHeight; h <= toHeight; h++) {
    if (onProgress) onProgress(h);
    const row = headerByHeight.get(h);
    if (!row?.header_hex) {
      throw new Error(`missing header for height ${h}`);
    }

    const verify = JSON.parse(
      lightChainVerifyHeader(checkpoint, row.header_hex),
    );
    if (!verify.ok) {
      throw new Error(verify.error || `header verify failed at height ${h}`);
    }
    const rpcId = String(row.block_id).toLowerCase();
    const localId = String(verify.block_id).toLowerCase();
    if (localId !== rpcId) {
      throw new Error(`block_id mismatch at height ${h}`);
    }

    const body = await rpc(rpcUrl, "get_block_txs", { height: h });
    const txHexes = (body.txs || []).map((t) => t.tx_hex).filter(Boolean);
    const scanJson = scanBlockTxsHex(seedHex, h, txHexes, state.ownedKeyImages);
    const scan = JSON.parse(scanJson);
    const before = state.inputs.length;
    applyBlockScan(state, scan);
    recoveredThisRun += state.inputs.length - before;

    const evoPage = await rpc(rpcUrl, "get_block_evolution", { height: h });
    const evoJson = evolutionJsonFromRpc(evoPage);
    const evolved = JSON.parse(
      lightChainApplyEvolution(checkpoint, row.header_hex, evoJson),
    );
    if (!evolved.ok) {
      throw new Error(evolved.error || `evolution failed at height ${h}`);
    }
    checkpoint = evolved.checkpoint_hex;
    saveLightCheckpoint(seedHex, checkpoint);
    state.lastTipBlockId = evolved.tip_block_id;
    evolutionSteps += 1;
    blocksOk += 1;
  }

  return {
    blocksOk,
    fromHeight,
    toHeight,
    recoveredThisRun,
    balance: totalBalance(state),
    utxoCount: state.inputs.length,
    headers: {
      headersOk: (headerPage.headers || []).length,
      tip_block_id: link.tip_block_id,
    },
    evolutionSteps,
    checkpoint_hex: checkpoint,
  };
}

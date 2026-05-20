/**
 * Incremental light-wallet sync over mfnd JSON-RPC (**M4.7**–**M4.11**).
 *
 * Per block: hash linkage batch, BLS header verify against evolving checkpoint,
 * tx scan via `get_block_txs`, validator-set evolution via batched `get_light_follow`.
 */

import { syncHeaderRange, verifyHeaderChain } from "./header-sync.js";
import { fetchLightRelayFollowPage } from "./light-relay-client.js";
import { assertRelayUrlsTrusted } from "./trusted-relay-pins.js";

const STORAGE_PREFIX = "permawrite-wallet-sync:";
const CHECKPOINT_PREFIX = "permawrite-light-checkpoint:";
const TRUSTED_SUMMARY_PREFIX = "permawrite-light-trusted-summary:";

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

export function loadTrustedSummary(seedHex) {
  return localStorage.getItem(TRUSTED_SUMMARY_PREFIX + seedHex);
}

export function saveTrustedSummary(seedHex, summaryJson) {
  localStorage.setItem(TRUSTED_SUMMARY_PREFIX + seedHex, summaryJson);
}

/**
 * @param {string} rpcUrl
 * @param {number} fromHeight
 * @param {number} toHeight
 * @param {(url: string, method: string, params: object) => Promise<object>} rpc
 * @param {string[]} [quorumRpcUrls] optional extra RPC bases (same path as primary)
 * @param {string[]} [quorumP2pPeers] optional HOST:PORT peers via `get_light_follow_p2p`
 * @param {string[]} [lightRelayUrls] dedicated relays (M4.16–M4.17); ≥2 = multi-relay quorum
 */
async function fetchLightFollowWithQuorum(
  rpcUrl,
  fromHeight,
  toHeight,
  rpc,
  quorumRpcUrls,
  quorumP2pPeers,
  lightRelayUrls,
) {
  const params = { from_height: fromHeight, to_height: toHeight };
  const localPage = await rpc(rpcUrl, "get_light_follow", params);
  const batches = [localPage];

  const extraUrls = (quorumRpcUrls || []).filter((u) => u && u !== rpcUrl);
  const extraPages = await Promise.all(
    extraUrls.map((url) => rpc(url, "get_light_follow", params)),
  );
  batches.push(...extraPages);

  const p2pPeers = (quorumP2pPeers || []).filter(Boolean);
  const relays = [...new Set((lightRelayUrls || []).filter(Boolean))];

  if (relays.length >= 2 && p2pPeers.length >= 2) {
    const relayPages = await Promise.all(
      relays.map((base) =>
        fetchLightRelayFollowPage(base, p2pPeers, fromHeight, toHeight),
      ),
    );
    batches.push(...relayPages);
  } else if (relays.length === 1 && p2pPeers.length >= 2) {
    const relayPage = await fetchLightRelayFollowPage(
      relays[0],
      p2pPeers,
      fromHeight,
      toHeight,
    );
    batches.push(relayPage);
  } else if (relays.length > 0 && p2pPeers.length < 2) {
    throw new Error(
      "light relay URLs require at least 2 quorum P2P peers (HOST:PORT)",
    );
  } else if (p2pPeers.length > 0) {
    const p2pPages = await Promise.all(
      p2pPeers.map((peer) =>
        rpc(rpcUrl, "get_light_follow_p2p", { peer, ...params }),
      ),
    );
    batches.push(...p2pPages);
  }

  return { primary: localPage, batches };
}

function evolutionJsonFromRpc(page) {
  const slashings = (page.slashings || []).map((s) => s.evidence_hex).filter(Boolean);
  const bond_ops = (page.bond_ops || []).map((b) => b.op_hex).filter(Boolean);
  return JSON.stringify({ slashings, bond_ops });
}

function evolutionJsonFromFollowRow(row) {
  if (!row) {
    return JSON.stringify({ slashings: [], bond_ops: [] });
  }
  return evolutionJsonFromRpc(row);
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
 * @param {(batchesJson: string) => string} [opts.lightFollowQuorum]
 * @param {(trustedSummaryJson: string, checkpointHex: string) => string} [opts.lightChainWeakSubjectivity]
 * @param {(checkpointHex: string) => string} [opts.lightChainCheckpointSummary]
 * @param {string[]} [opts.quorumRpcUrls]
 * @param {string[]} [opts.quorumP2pPeers]
 * @param {string[]} [opts.lightRelayUrls]
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
  lightFollowQuorum,
  lightChainWeakSubjectivity,
  lightChainCheckpointSummary,
  quorumRpcUrls,
  quorumP2pPeers,
  lightRelayUrls,
  initialCheckpointHex,
}) {
  if (fromHeight < 1) {
    throw new Error("fromHeight must be ≥ 1 (genesis is not in block log)");
  }
  if (toHeight < fromHeight) {
    throw new Error("toHeight must be ≥ fromHeight");
  }

  const relayTrust =
    lightRelayUrls && lightRelayUrls.length > 0
      ? assertRelayUrlsTrusted(seedHex, lightRelayUrls)
      : null;

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
    const resumeHeight = Number(state.lastScannedHeight) || 0;
    if (resumeHeight > 0) {
      const snap = await rpc(rpcUrl, "get_light_snapshot", {
        height: resumeHeight,
      });
      checkpoint = snap.checkpoint_hex;
      if (!checkpoint) {
        throw new Error(
          `get_light_snapshot at height ${resumeHeight} returned no checkpoint_hex`,
        );
      }
      saveLightCheckpoint(seedHex, checkpoint);
      if (lightChainCheckpointSummary && snap.summary) {
        saveTrustedSummary(seedHex, JSON.stringify(snap.summary));
      }
    } else if (lightChainBootstrapCheckpoint) {
      const params = await rpc(rpcUrl, "get_chain_params", {});
      checkpoint = lightChainBootstrapCheckpoint(JSON.stringify(params));
      saveLightCheckpoint(seedHex, checkpoint);
    } else {
      throw new Error("missing light checkpoint; pass lightChainBootstrapCheckpoint");
    }
  }

  if (lightChainWeakSubjectivity && checkpoint) {
    const trustedRaw = loadTrustedSummary(seedHex);
    if (trustedRaw) {
      const ws = JSON.parse(
        lightChainWeakSubjectivity(trustedRaw, checkpoint),
      );
      if (!ws.ok || !ws.agrees) {
        throw new Error(
          ws.error ||
            "weak-subjectivity checkpoint mismatch (trusted summary vs local/RPC checkpoint)",
        );
      }
    }
  }

  const headerByHeight = new Map(
    (headerPage.headers || []).map((row) => [Number(row.height), row]),
  );

  const { primary: followPage, batches: followBatches } =
    await fetchLightFollowWithQuorum(
      rpcUrl,
      fromHeight,
      toHeight,
      rpc,
      quorumRpcUrls,
      quorumP2pPeers,
      lightRelayUrls,
    );
  if (lightFollowQuorum && followBatches.length > 1) {
    const quorum = JSON.parse(
      lightFollowQuorum(JSON.stringify({ batches: followBatches })),
    );
    if (!quorum.ok) {
      throw new Error(quorum.error || "light-follow quorum failed");
    }
  }
  const followByHeight = new Map(
    (followPage.rows || []).map((row) => [Number(row.height), row]),
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

    const evoJson = evolutionJsonFromFollowRow(followByHeight.get(h));
    const evolved = JSON.parse(
      lightChainApplyEvolution(checkpoint, row.header_hex, evoJson),
    );
    if (!evolved.ok) {
      throw new Error(evolved.error || `evolution failed at height ${h}`);
    }
    checkpoint = evolved.checkpoint_hex;
    saveLightCheckpoint(seedHex, checkpoint);
    if (lightChainCheckpointSummary) {
      const summaryJson = lightChainCheckpointSummary(checkpoint);
      saveTrustedSummary(seedHex, summaryJson);
    }
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
    relay_trust: relayTrust
      ? { tofu: relayTrust.tofu, pinned_relays: relayTrust.pinned }
      : undefined,
  };
}

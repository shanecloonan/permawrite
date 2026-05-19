/**
 * Header-chain sync for browser light wallets (**M4.9**).
 *
 * Fetches compact headers via `get_block_headers` and verifies `prev_block_id`
 * linkage back to `genesis_id` before downloading transaction bodies.
 */

/**
 * @param {object[]} headers RPC header rows (`height`, `block_id`, `prev_block_id`)
 * @param {string} genesisId 64-hex genesis block id
 * @param {string} [anchorBlockId] when the batch does not start at height 1, the
 *   parent block id at `from_height - 1`
 */
export function verifyHeaderChain(headers, genesisId, anchorBlockId) {
  const genesis = genesisId.toLowerCase();
  let prevId = anchorBlockId ? anchorBlockId.toLowerCase() : null;
  for (const row of headers) {
    const height = Number(row.height);
    const blockId = String(row.block_id).toLowerCase();
    const prevBlockId = String(row.prev_block_id).toLowerCase();
    const expectedPrev =
      height === 1 ? genesis : prevId;
    if (expectedPrev == null) {
      return {
        ok: false,
        error: `height ${height}: missing anchor (sync from height 1 or pass anchorBlockId)`,
      };
    }
    if (prevBlockId !== expectedPrev) {
      return {
        ok: false,
        error: `height ${height}: prev_block_id mismatch (got ${prevBlockId}, expected ${expectedPrev})`,
      };
    }
    prevId = blockId;
  }
  return { ok: true, tip_block_id: prevId };
}

/**
 * Fetch and verify headers for `fromHeight`…`toHeight` inclusive.
 *
 * @param {object} opts
 * @param {string} opts.rpcUrl
 * @param {number} opts.fromHeight
 * @param {number} opts.toHeight
 * @param {(url: string, method: string, params: object) => Promise<object>} opts.rpc
 * @param {string} [opts.anchorBlockId]
 * @param {(from: number, to: number) => void} [opts.onProgress]
 */
export async function syncHeaderRange({
  rpcUrl,
  fromHeight,
  toHeight,
  rpc,
  anchorBlockId,
  onProgress,
}) {
  if (fromHeight < 1) {
    throw new Error("fromHeight must be ≥ 1");
  }
  if (toHeight < fromHeight) {
    throw new Error("toHeight must be ≥ fromHeight");
  }
  const BATCH = 512;
  let headersOk = 0;
  let lastTipBlockId = anchorBlockId ?? null;
  for (let start = fromHeight; start <= toHeight; start += BATCH) {
    const end = Math.min(toHeight, start + BATCH - 1);
    if (onProgress) onProgress(start, end);
    const page = await rpc(rpcUrl, "get_block_headers", {
      from_height: start,
      to_height: end,
    });
    const genesisId = page.genesis_id;
    if (!genesisId) throw new Error("get_block_headers: missing genesis_id");
    const anchor =
      start === fromHeight && fromHeight > 1 ? lastTipBlockId ?? anchorBlockId : lastTipBlockId;
    const check = verifyHeaderChain(page.headers || [], genesisId, anchor ?? undefined);
    if (!check.ok) {
      throw new Error(check.error || "header chain verification failed");
    }
    headersOk += (page.headers || []).length;
    lastTipBlockId = check.tip_block_id;
  }
  return {
    headersOk,
    fromHeight,
    toHeight,
    tip_block_id: lastTipBlockId,
  };
}

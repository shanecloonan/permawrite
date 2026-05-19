/**
 * Header-chain sync for browser light wallets (**M4.9**, **M4.10**).
 *
 * Fetches compact headers via `get_block_headers`, verifies hash linkage, then
 * optionally runs WASM BLS finality verification + locally recomputed `block_id`.
 */

/**
 * @param {object[]} headers RPC header rows (`height`, `block_id`, `prev_block_id`, `header_hex`)
 * @param {string} genesisId 64-hex genesis block id
 * @param {string} [anchorBlockId] when the batch does not start at height 1
 */
export function verifyHeaderChain(headers, genesisId, anchorBlockId) {
  const genesis = genesisId.toLowerCase();
  let prevId = anchorBlockId ? anchorBlockId.toLowerCase() : null;
  for (const row of headers) {
    const height = Number(row.height);
    const blockId = String(row.block_id).toLowerCase();
    const prevBlockId = String(row.prev_block_id).toLowerCase();
    const expectedPrev = height === 1 ? genesis : prevId;
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
 * WASM BLS verify each header and confirm RPC `block_id` matches recomputed id.
 *
 * @param {object[]} headers
 * @param {string} validatorsJson JSON array from `get_chain_params.validators`
 * @param {string} consensusJson JSON object from `get_chain_params.consensus`
 * @param {(headerHex: string, validatorsJson: string, consensusJson: string) => string} verifyHeaderHex
 * @param {(headerHex: string) => string} [blockIdFromHeaderHex]
 */
export function verifyHeadersCryptographic(
  headers,
  validatorsJson,
  consensusJson,
  verifyHeaderHex,
  blockIdFromHeaderHex,
) {
  let verified = 0;
  for (const row of headers) {
    const headerHex = row.header_hex;
    if (!headerHex) {
      return { ok: false, error: `height ${row.height}: missing header_hex` };
    }
    const result = JSON.parse(verifyHeaderHex(headerHex, validatorsJson, consensusJson));
    if (!result.ok) {
      return {
        ok: false,
        error: `height ${row.height}: ${result.error || "header verify failed"}`,
      };
    }
    const rpcId = String(row.block_id).toLowerCase();
    const localId = result.block_id?.toLowerCase();
    if (localId && localId !== rpcId) {
      return {
        ok: false,
        error: `height ${row.height}: block_id mismatch (rpc ${rpcId}, local ${localId})`,
      };
    }
    if (blockIdFromHeaderHex) {
      const recomputed = blockIdFromHeaderHex(headerHex).toLowerCase();
      if (recomputed !== rpcId) {
        return {
          ok: false,
          error: `height ${row.height}: blockIdFromHeaderHex mismatch (rpc ${rpcId}, wasm ${recomputed})`,
        };
      }
    }
    verified += 1;
  }
  return { ok: true, verified };
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
 * @param {string} [opts.validatorsJson]
 * @param {string} [opts.consensusJson]
 * @param {(headerHex: string, validatorsJson: string, consensusJson: string) => string} [opts.verifyHeaderHex]
 * @param {(headerHex: string) => string} [opts.blockIdFromHeaderHex]
 * @param {(from: number, to: number) => void} [opts.onProgress]
 */
export async function syncHeaderRange({
  rpcUrl,
  fromHeight,
  toHeight,
  rpc,
  anchorBlockId,
  validatorsJson,
  consensusJson,
  verifyHeaderHex,
  blockIdFromHeaderHex,
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
  let cryptoVerified = 0;
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
    const headers = page.headers || [];
    const anchor =
      start === fromHeight && fromHeight > 1 ? lastTipBlockId ?? anchorBlockId : lastTipBlockId;
    const link = verifyHeaderChain(headers, genesisId, anchor ?? undefined);
    if (!link.ok) {
      throw new Error(link.error || "header chain linkage failed");
    }
    if (verifyHeaderHex && validatorsJson && consensusJson) {
      const crypto = verifyHeadersCryptographic(
        headers,
        validatorsJson,
        consensusJson,
        verifyHeaderHex,
        blockIdFromHeaderHex,
      );
      if (!crypto.ok) {
        throw new Error(crypto.error || "header cryptographic verify failed");
      }
      cryptoVerified += crypto.verified;
    }
    headersOk += headers.length;
    lastTipBlockId = link.tip_block_id;
  }
  return {
    headersOk,
    cryptoVerified,
    fromHeight,
    toHeight,
    tip_block_id: lastTipBlockId,
  };
}

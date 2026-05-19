/**
 * POST one JSON-RPC 2.0 object to the local HTTP→TCP proxy (see `demo/proxy/rpc-proxy.mjs`).
 *
 * @param {string} proxyUrl e.g. http://127.0.0.1:8787/rpc
 * @param {string} method mfnd method name
 * @param {object} params JSON-RPC params object
 * @returns {Promise<object>} JSON-RPC result field
 */
export async function mfndRpc(proxyUrl, method, params) {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    method,
    params,
    id: 1,
  });
  const res = await fetch(proxyUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  if (!res.ok) {
    throw new Error(`proxy HTTP ${res.status}: ${await res.text()}`);
  }
  const line = (await res.text()).trim();
  const msg = JSON.parse(line);
  if (msg.error) {
    throw new Error(`${msg.error.code}: ${msg.error.message}`);
  }
  return msg.result;
}

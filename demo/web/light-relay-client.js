/**
 * HTTP client for dedicated light-follow relays (**M4.16**–**M4.21**).
 */

/**
 * @param {string} relayBase
 * @returns {Promise<object>} weak-subjectivity summary from relay backend tip
 */
export async function fetchRelayCheckpointSummary(relayBase) {
  const url = relayBase.replace(/\/$/, "");
  const res = await fetch(`${url}/checkpoint-summary`);
  if (!res.ok) {
    throw new Error(
      `light relay ${url} checkpoint-summary HTTP ${res.status}: ${await res.text()}`,
    );
  }
  const summary = await res.json();
  if (!summary?.checkpoint_digest) {
    throw new Error(`light relay ${url} returned invalid checkpoint summary`);
  }
  return summary;
}

/**
 * @param {string} relayBase HTTPS relay only
 * @returns {Promise<string>} lowercase hex SHA-256 of TLS SPKI
 */
export async function fetchRelayTlsSpki(relayBase) {
  const url = relayBase.replace(/\/$/, "");
  const res = await fetch(`${url}/relay-spki`);
  if (!res.ok) {
    throw new Error(
      `light relay ${url} relay-spki HTTP ${res.status}: ${await res.text()}`,
    );
  }
  const body = await res.json();
  const hex = String(body?.spki_sha256 ?? "").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`light relay ${url} returned invalid relay-spki`);
  }
  return hex.toLowerCase();
}

/**
 * @param {string} relayBase e.g. http://127.0.0.1:8790
 * @param {string[]} peers HOST:PORT list (≥2 for relay quorum)
 * @param {number} fromHeight
 * @param {number} toHeight
 * @returns {Promise<object>} get_light_follow_quorum_p2p-shaped page
 */
export async function fetchLightRelayFollowPage(
  relayBase,
  peers,
  fromHeight,
  toHeight,
) {
  const url = relayBase.replace(/\/$/, "");
  const res = await fetch(`${url}/light-follow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      peers,
      from_height: fromHeight,
      to_height: toHeight,
    }),
  });
  if (!res.ok) {
    throw new Error(`light relay ${url} HTTP ${res.status}: ${await res.text()}`);
  }
  const page = await res.json();
  if (!page?.rows) {
    throw new Error(`light relay ${url} returned no rows`);
  }
  return page;
}

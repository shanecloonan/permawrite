/**
 * HTTP client for dedicated light-follow relays (**M4.16**–**M4.17**).
 */

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

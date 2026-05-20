/**
 * Trust-on-first-use pins for light-relay HTTPS endpoints (**M4.18**–**M4.21**).
 */

const TRUSTED_RELAYS_PREFIX = "permawrite-trusted-relay-urls:";

/** @param {string} url */
export function normalizeRelayUrl(url) {
  return url.trim().replace(/\/$/, "").toLowerCase();
}

/**
 * @typedef {{ urls: string[], summaries: Record<string, object>, tls_spki: Record<string, string> }} RelayPinRecord
 */

/** @param {string} url */
export function isHttpsRelayUrl(url) {
  return normalizeRelayUrl(url).startsWith("https://");
}

/** @param {string} hex */
function normSpki(hex) {
  return String(hex ?? "")
    .trim()
    .replace(/^0x/i, "")
    .toLowerCase();
}

/**
 * @param {unknown} parsed
 * @returns {RelayPinRecord | null}
 */
function parsePinRecord(parsed) {
  if (Array.isArray(parsed)) {
    return {
      urls: parsed.map((u) => String(u).toLowerCase()),
      summaries: {},
      tls_spki: {},
    };
  }
  if (parsed && typeof parsed === "object" && Array.isArray(parsed.urls)) {
    const summaries =
      parsed.summaries && typeof parsed.summaries === "object"
        ? Object.fromEntries(
            Object.entries(parsed.summaries).map(([k, v]) => [
              normalizeRelayUrl(k),
              v,
            ]),
          )
        : {};
    const tls_spki =
      parsed.tls_spki && typeof parsed.tls_spki === "object"
        ? Object.fromEntries(
            Object.entries(parsed.tls_spki).map(([k, v]) => [
              normalizeRelayUrl(k),
              normSpki(v),
            ]),
          )
        : {};
    return {
      urls: parsed.urls.map((u) => String(u).toLowerCase()),
      summaries,
      tls_spki,
    };
  }
  return null;
}

/**
 * @param {string} seedHex
 * @returns {RelayPinRecord | null}
 */
export function loadTrustedRelayPins(seedHex) {
  try {
    const raw = localStorage.getItem(TRUSTED_RELAYS_PREFIX + seedHex);
    if (!raw) return null;
    return parsePinRecord(JSON.parse(raw));
  } catch {
    return null;
  }
}

/**
 * @param {string} seedHex
 * @param {string[]} urls
 * @param {Record<string, object>} [summaries] keyed by normalized relay URL
 * @param {Record<string, string>} [tlsSpki] keyed by normalized relay URL (HTTPS only)
 */
export function saveTrustedRelayPins(
  seedHex,
  urls,
  summaries = {},
  tlsSpki = {},
) {
  const normalized = [...new Set(urls.map(normalizeRelayUrl))].sort();
  const prev = loadTrustedRelayPins(seedHex);
  const mergedSummaries = { ...(prev?.summaries || {}) };
  for (const [k, v] of Object.entries(summaries)) {
    mergedSummaries[normalizeRelayUrl(k)] = v;
  }
  const mergedTlsSpki = { ...(prev?.tls_spki || {}) };
  for (const [k, v] of Object.entries(tlsSpki)) {
    mergedTlsSpki[normalizeRelayUrl(k)] = normSpki(v);
  }
  const record = {
    urls: normalized,
    summaries: mergedSummaries,
    tls_spki: mergedTlsSpki,
  };
  localStorage.setItem(TRUSTED_RELAYS_PREFIX + seedHex, JSON.stringify(record));
}

/** @param {string} seedHex */
export function clearTrustedRelayPins(seedHex) {
  localStorage.removeItem(TRUSTED_RELAYS_PREFIX + seedHex);
}

/**
 * @param {object} a
 * @param {object} b
 */
function summariesEqual(a, b) {
  const keys = [
    "genesis_id",
    "tip_height",
    "tip_block_id",
    "validator_count",
    "validator_set_root",
    "checkpoint_digest",
  ];
  for (const k of keys) {
    const av = String(a[k] ?? "").toLowerCase();
    const bv = String(b[k] ?? "").toLowerCase();
    if (av !== bv) return false;
  }
  return true;
}

/**
 * @param {string} seedHex
 * @param {string[]} urls
 * @param {(relayBase: string) => Promise<object>} fetchSummary
 */
export async function verifyRelayCheckpointSummaries(seedHex, urls, fetchSummary) {
  const record = loadTrustedRelayPins(seedHex);
  if (!record) return { checked: 0, pinned: false };
  const relays = [...new Set((urls || []).filter(Boolean).map(normalizeRelayUrl))];
  let checked = 0;
  for (const relay of relays) {
    const pinned = record.summaries[relay];
    if (!pinned) continue;
    const live = await fetchSummary(relay);
    if (!summariesEqual(pinned, live)) {
      throw new Error(
        `relay ${relay} checkpoint summary mismatch (weak-subjectivity). ` +
          "Re-pin after verifying the operator, or reset relay pins.",
      );
    }
    checked += 1;
  }
  return { checked, pinned: true };
}

/**
 * @param {string} seedHex
 * @param {string[]} urls
 * @param {(relayBase: string) => Promise<string>} fetchSpki returns lowercase hex sha256
 */
export async function verifyRelayTlsSpki(seedHex, urls, fetchSpki) {
  const record = loadTrustedRelayPins(seedHex);
  if (!record) return { checked: 0, pinned: false };
  const relays = [...new Set((urls || []).filter(Boolean).map(normalizeRelayUrl))];
  let checked = 0;
  for (const relay of relays) {
    if (!isHttpsRelayUrl(relay)) continue;
    const pinned = record.tls_spki[relay];
    if (!pinned) continue;
    const live = normSpki(await fetchSpki(relay));
    if (live !== pinned) {
      throw new Error(
        `relay ${relay} TLS SPKI mismatch. ` +
          "Verify with node demo/proxy/relay-tls-spki.mjs out-of-band, then re-pin.",
      );
    }
    checked += 1;
  }
  return { checked, pinned: true };
}

/**
 * @param {string} relay
 * @param {string} expectedHex out-of-band SPKI sha256 (optional)
 * @param {string} liveHex from GET /relay-spki
 */
export function assertExpectedRelayTlsSpki(relay, expectedHex, liveHex) {
  const expected = normSpki(expectedHex);
  if (!expected) return;
  const live = normSpki(liveHex);
  if (live !== expected) {
    throw new Error(
      `relay ${relay} TLS SPKI does not match expected out-of-band value`,
    );
  }
}

/**
 * TOFU on first relay use; thereafter every configured relay must be pinned.
 *
 * @param {string} seedHex
 * @param {string[]} urls
 * @returns {{ tofu: boolean, pinned: string[] }}
 */
export function assertRelayUrlsTrusted(seedHex, urls) {
  const relays = [...new Set((urls || []).filter(Boolean).map(normalizeRelayUrl))];
  if (relays.length === 0) {
    return { tofu: false, pinned: loadTrustedRelayPins(seedHex)?.urls || [] };
  }
  const record = loadTrustedRelayPins(seedHex);
  if (!record) {
    saveTrustedRelayPins(seedHex, relays);
    return { tofu: true, pinned: relays };
  }
  const pinnedSet = new Set(record.urls);
  const unknown = relays.filter((r) => !pinnedSet.has(r));
  if (unknown.length > 0) {
    throw new Error(
      `untrusted light relay URL(s): ${unknown.join(", ")}. ` +
        "Use Pin relay URLs after verifying operators, or Reset relay pins to TOFU again.",
    );
  }
  return { tofu: false, pinned: record.urls };
}

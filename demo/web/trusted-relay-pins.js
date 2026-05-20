/**
 * Trust-on-first-use pins for light-relay HTTPS endpoints (**M4.18**).
 */

const TRUSTED_RELAYS_PREFIX = "permawrite-trusted-relay-urls:";

/** @param {string} url */
export function normalizeRelayUrl(url) {
  return url.trim().replace(/\/$/, "").toLowerCase();
}

/**
 * @param {string} seedHex
 * @returns {string[] | null} sorted normalized URLs, or null if never pinned
 */
export function loadTrustedRelayPins(seedHex) {
  try {
    const raw = localStorage.getItem(TRUSTED_RELAYS_PREFIX + seedHex);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    return parsed.map((u) => String(u).toLowerCase());
  } catch {
    return null;
  }
}

/**
 * @param {string} seedHex
 * @param {string[]} urls
 */
export function saveTrustedRelayPins(seedHex, urls) {
  const normalized = [...new Set(urls.map(normalizeRelayUrl))].sort();
  localStorage.setItem(TRUSTED_RELAYS_PREFIX + seedHex, JSON.stringify(normalized));
}

/** @param {string} seedHex */
export function clearTrustedRelayPins(seedHex) {
  localStorage.removeItem(TRUSTED_RELAYS_PREFIX + seedHex);
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
    return { tofu: false, pinned: loadTrustedRelayPins(seedHex) || [] };
  }
  const pinned = loadTrustedRelayPins(seedHex);
  if (!pinned) {
    saveTrustedRelayPins(seedHex, relays);
    return { tofu: true, pinned: relays };
  }
  const pinnedSet = new Set(pinned);
  const unknown = relays.filter((r) => !pinnedSet.has(r));
  if (unknown.length > 0) {
    throw new Error(
      `untrusted light relay URL(s): ${unknown.join(", ")}. ` +
        "Use Pin relay URLs after verifying operators, or Reset relay pins to TOFU again.",
    );
  }
  return { tofu: false, pinned };
}

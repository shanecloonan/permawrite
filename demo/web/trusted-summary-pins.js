/**
 * Weak-subjectivity summary pins in localStorage (**M4.22**–**M4.24**).
 * Same JSON shape as `get_light_snapshot.summary` / `mfn-cli` export.
 */

import { loadTrustedSummary, saveTrustedSummary } from "./wallet-sync.js";

const SUMMARY_KEYS = [
  "genesis_id",
  "tip_height",
  "tip_block_id",
  "validator_count",
  "validator_set_root",
  "checkpoint_digest",
];

/** @param {string} hex */
export function normSummaryHex(hex) {
  return String(hex ?? "")
    .trim()
    .replace(/^0x/i, "")
    .toLowerCase();
}

/**
 * @param {unknown} obj
 * @returns {object} normalized summary object
 */
export function normalizeTrustedSummary(obj) {
  if (!obj || typeof obj !== "object") {
    throw new Error("trusted summary must be a JSON object");
  }
  const raw = /** @type {Record<string, unknown>} */ (obj);
  for (const k of SUMMARY_KEYS) {
    if (raw[k] == null || raw[k] === "") {
      throw new Error(`trusted summary missing field: ${k}`);
    }
  }
  const tipHeight = Number(raw.tip_height);
  if (!Number.isInteger(tipHeight) || tipHeight < 0) {
    throw new Error("trusted summary tip_height must be a non-negative integer");
  }
  const validatorCount = Number(raw.validator_count);
  if (!Number.isFinite(validatorCount) || validatorCount < 0) {
    throw new Error("trusted summary validator_count must be a non-negative number");
  }
  for (const k of [
    "genesis_id",
    "tip_block_id",
    "validator_set_root",
    "checkpoint_digest",
  ]) {
    const t = normSummaryHex(String(raw[k]));
    if (!/^[0-9a-f]+$/.test(t)) {
      throw new Error(`trusted summary field ${k} is not hex`);
    }
  }
  return {
    genesis_id: normSummaryHex(String(raw.genesis_id)),
    tip_height: tipHeight,
    tip_block_id: normSummaryHex(String(raw.tip_block_id)),
    validator_count: validatorCount,
    validator_set_root: normSummaryHex(String(raw.validator_set_root)),
    checkpoint_digest: normSummaryHex(String(raw.checkpoint_digest)),
  };
}

/**
 * @param {string} raw JSON text
 * @returns {object}
 */
export function parseTrustedSummaryJson(raw) {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("paste trusted summary JSON (from mfn-cli export-trusted-summary)");
  }
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch (e) {
    throw new Error(`invalid JSON: ${e}`);
  }
  return normalizeTrustedSummary(parsed);
}

/**
 * @param {string} seedHex
 * @returns {object | null}
 */
export function loadTrustedSummaryObject(seedHex) {
  const raw = loadTrustedSummary(seedHex);
  if (!raw) return null;
  return normalizeTrustedSummary(JSON.parse(raw));
}

/**
 * @param {string} seedHex
 * @param {object} summary
 */
export function saveTrustedSummaryObject(seedHex, summary) {
  const normalized = normalizeTrustedSummary(summary);
  saveTrustedSummary(seedHex, JSON.stringify(normalized));
  return normalized;
}

export { clearTrustedSummary } from "./wallet-sync.js";

/**
 * @param {object} a
 * @param {object} b
 */
export function trustedSummariesEqual(a, b) {
  const left = normalizeTrustedSummary(a);
  const right = normalizeTrustedSummary(b);
  return SUMMARY_KEYS.every((k) => {
    if (k === "tip_height" || k === "validator_count") {
      return left[k] === right[k];
    }
    return normSummaryHex(String(left[k])) === normSummaryHex(String(right[k]));
  });
}

/**
 * @param {object} summary
 * @returns {string}
 */
export function formatTrustedSummaryLines(summary) {
  const s = normalizeTrustedSummary(summary);
  return SUMMARY_KEYS.map((k) => `${k}=${s[k]}`).join("\n");
}

/**
 * Derive summary from a light checkpoint hex via WASM (**M4.23**).
 *
 * @param {string} checkpointHex
 * @param {(checkpointHex: string) => string} lightChainCheckpointSummary
 */
export function deriveTrustedSummaryFromCheckpoint(
  checkpointHex,
  lightChainCheckpointSummary,
) {
  if (!checkpointHex?.trim()) {
    throw new Error("no light checkpoint; sync first or paste a checkpoint");
  }
  const raw = lightChainCheckpointSummary(checkpointHex.trim());
  return normalizeTrustedSummary(JSON.parse(raw));
}

/**
 * Ensure RPC-embedded summary matches checkpoint-derived (**M3.14** parity).
 *
 * @param {object} rpcSummary
 * @param {object} derived
 */
export function assertRpcSummaryMatchesCheckpoint(rpcSummary, derived) {
  if (!trustedSummariesEqual(rpcSummary, derived)) {
    throw new Error(
      "get_light_snapshot.summary disagrees with checkpoint-derived summary",
    );
  }
}

/**
 * Pin textarea JSON before sync when non-empty (**M4.24** — CLI `light-scan --import-trusted-summary`).
 *
 * @param {string} seedHex
 * @param {string} textareaRaw
 * @param {object} [opts]
 * @param {string} [opts.checkpointHex]
 * @param {(trustedSummaryJson: string, checkpointHex: string) => string} [opts.lightChainWeakSubjectivity]
 * @returns {{ imported: false } | { imported: true, summary: object }}
 */
export function importTrustedSummaryFromTextareaIfPresent(
  seedHex,
  textareaRaw,
  opts = {},
) {
  const trimmed = String(textareaRaw ?? "").trim();
  if (!trimmed) {
    return { imported: false };
  }
  const summary = parseTrustedSummaryJson(trimmed);
  const checkpointHex = opts.checkpointHex?.trim();
  if (checkpointHex && opts.lightChainWeakSubjectivity) {
    const ws = JSON.parse(
      opts.lightChainWeakSubjectivity(JSON.stringify(summary), checkpointHex),
    );
    if (!ws.ok || !ws.agrees) {
      throw new Error(
        ws.error ||
          "trusted summary disagrees with wallet light checkpoint (sync import aborted)",
      );
    }
  }
  saveTrustedSummaryObject(seedHex, summary);
  return { imported: true, summary };
}

/**
 * Check block headers on this device before a balance is shown.
 * A failed or missing check hides the balance. The server's word is not enough.
 */

export type HeaderCheck =
  | { ok: true; checked: number; tipBlockId: string }
  | { ok: false; checked: number; error: string };

export type HeaderVerifier = (
  checkpointHex: string,
  headerHex: string,
) => string | Promise<string>;

type Verdict = { ok?: boolean; error?: string; block_id?: string };

export async function verifyHeadersLocally(
  checkpointHex: string,
  headerHexes: string[],
  verify: HeaderVerifier,
): Promise<HeaderCheck> {
  const checkpoint = checkpointHex.trim();
  if (!checkpoint) {
    return { ok: false, checked: 0, error: "no checkpoint to check headers against" };
  }
  const headers = headerHexes.map((h) => h.trim()).filter(Boolean);
  if (headers.length === 0) {
    return { ok: false, checked: 0, error: "no header bytes were returned to check" };
  }
  let tipBlockId = "";
  for (let i = 0; i < headers.length; i++) {
    let raw: string;
    try {
      raw = await verify(checkpoint, headers[i]!);
    } catch (e) {
      return {
        ok: false,
        checked: i,
        error: e instanceof Error ? e.message : "header check failed",
      };
    }
    let verdict: Verdict;
    try {
      verdict = JSON.parse(raw) as Verdict;
    } catch {
      return { ok: false, checked: i, error: "header check was not readable" };
    }
    if (verdict.ok !== true) {
      return {
        ok: false,
        checked: i,
        error: verdict.error || "a header was not accepted",
      };
    }
    if (verdict.block_id) tipBlockId = verdict.block_id;
  }
  return { ok: true, checked: headers.length, tipBlockId };
}

/** Balance is visible only after a local header check succeeded. */
export function balanceAfterHeaderCheck(
  check: HeaderCheck | null,
  atomic: number,
): number | null {
  if (!check || !check.ok) return null;
  if (!Number.isFinite(atomic) || atomic < 0) return null;
  return atomic;
}

export function headerHexesFromRpc(raw: unknown): string[] {
  const rows = Array.isArray(raw)
    ? raw
    : raw && typeof raw === "object" && Array.isArray((raw as { headers?: unknown }).headers)
      ? (raw as { headers: unknown[] }).headers
      : raw && typeof raw === "object"
        ? [raw]
        : [];
  const out: string[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const hex = (row as { header_hex?: unknown }).header_hex;
    if (typeof hex === "string" && hex.trim()) out.push(hex.trim());
  }
  return out;
}

export function checkpointHexFromRpc(raw: unknown): string {
  if (!raw || typeof raw !== "object") return "";
  const hex = (raw as { checkpoint_hex?: unknown }).checkpoint_hex;
  return typeof hex === "string" ? hex.trim() : "";
}

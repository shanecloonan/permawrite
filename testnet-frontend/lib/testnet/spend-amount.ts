/**
 * Spend amounts for the browser wallet.
 *
 * A bare whole number is atomic units, so old values keep their meaning.
 * `1.5` and `1.5mfn` are coins. 1 MFN = 100000000 atomic units.
 * Extra decimal places are refused instead of rounded.
 */

export const ATOMIC_PER_MFN = 100_000_000;

export type SpendAmount = {
  atomic: number;
  /** Shown before the person sends. */
  label: string;
};

export function formatMfn(atomic: number): string {
  if (!Number.isSafeInteger(atomic) || atomic < 0) {
    throw new Error("Amount does not fit.");
  }
  const whole = Math.floor(atomic / ATOMIC_PER_MFN);
  const frac = atomic % ATOMIC_PER_MFN;
  return `${whole}.${String(frac).padStart(8, "0")} MFN`;
}

export function parseSpendAmount(raw: string): SpendAmount {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Enter an amount. 1mfn is one coin. A bare whole number is atomic units.");
  }
  if (trimmed.startsWith("-") || trimmed.startsWith("+")) {
    throw new Error("Amount cannot be negative.");
  }
  const lower = trimmed.toLowerCase();
  let body = lower;
  let unit: "atomic" | "mfn";
  if (lower.endsWith("mfn")) {
    body = lower.slice(0, -3).trim();
    unit = "mfn";
  } else if (lower.endsWith("atomic")) {
    body = lower.slice(0, -6).trim();
    unit = "atomic";
  } else if (lower.includes(".")) {
    unit = "mfn";
  } else {
    unit = "atomic";
  }
  if (!body) {
    throw new Error("Enter an amount. 1mfn is one coin. A bare whole number is atomic units.");
  }
  const atomic = unit === "atomic" ? parseAtomic(body) : parseMfn(body);
  if (atomic < 1) {
    throw new Error("Amount must be at least 1 atomic unit.");
  }
  const label =
    unit === "atomic"
      ? `${atomic} atomic units = ${formatMfn(atomic)}. A bare whole number is not a whole coin. Type 1mfn for one coin.`
      : `${formatMfn(atomic)} = ${atomic} atomic units.`;
  return { atomic, label };
}

function parseAtomic(body: string): number {
  if (body.includes(".")) {
    throw new Error("Atomic amounts are whole numbers. Use 1.5mfn when you mean coins.");
  }
  if (!/^[0-9]+$/.test(body)) {
    throw new Error("Amount is not a number. Use atomic units, or a coin amount like 1.5mfn.");
  }
  const value = Number(body);
  if (!Number.isSafeInteger(value)) {
    throw new Error("That amount is larger than this page can send.");
  }
  return value;
}

function parseMfn(body: string): number {
  const parts = body.split(".");
  if (parts.length > 2 || !parts.every((part) => part === "" || /^[0-9]+$/.test(part))) {
    throw new Error("Amount is not a number. Use atomic units, or a coin amount like 1.5mfn.");
  }
  const [whole = "", frac = ""] = parts;
  if (frac.length > 8) {
    throw new Error(
      "Use at most 8 decimal places. Extra digits would change what you send. 1 MFN = 100000000 atomic units.",
    );
  }
  const wholeUnits = whole === "" ? 0 : Number(whole);
  if (!Number.isSafeInteger(wholeUnits)) {
    throw new Error("That amount is larger than this page can send.");
  }
  const padded = frac.padEnd(8, "0");
  const fracUnits = padded === "" ? 0 : Number(padded);
  const atomic = wholeUnits * ATOMIC_PER_MFN + fracUnits;
  if (!Number.isSafeInteger(atomic)) {
    throw new Error("That amount is larger than this page can send.");
  }
  return atomic;
}

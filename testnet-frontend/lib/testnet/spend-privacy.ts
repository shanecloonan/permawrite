/**
 * Private spend defaults for the browser wallet.
 * The largest legal ring is chosen. A smaller ring is refused.
 * A public fee is refused when the header hides fees.
 * Below that header, a hidden fee is not pretended.
 */

export type SpendChoice = {
  ringSize: number;
  hiddenFee: boolean;
};

export function headerVersionFromHex(headerHex: string): number {
  const t = headerHex.trim().replace(/^0x/i, "");
  if (t.length < 2 || t.length % 2 !== 0) {
    throw new Error("Refusing to send: header bytes were not returned.");
  }
  const first = Number.parseInt(t.slice(0, 2), 16);
  if (!Number.isFinite(first) || (first & 0x80) !== 0 || (first & 0x7f) === 0) {
    throw new Error("Refusing to send: header version could not be read.");
  }
  return first & 0x7f;
}

export function chooseBrowserSpend(opts: {
  headerVersion: number;
  decoyCandidates: number;
  explicitRing?: number | null;
  publicFee?: boolean;
}): SpendChoice {
  const version = opts.headerVersion;
  if (!Number.isInteger(version) || version < 1) {
    throw new Error("Refusing to send: header version is not known.");
  }
  if (version >= 6) {
    if (opts.publicFee) {
      throw new Error(
        "Refusing a public fee. This header hides fees, and a public fee would stand out.",
      );
    }
    throw new Error(
      "Refusing to send. This header hides fees, and this page cannot sign a hidden fee yet.",
    );
  }
  if (opts.publicFee === false && version < 6) {
    // Default path: a public fee is the only legal fee below header v6.
  }

  let ring: number;
  if (version < 5) {
    if (opts.explicitRing != null && opts.explicitRing !== 16) {
      throw new Error(
        `Refusing ring ${opts.explicitRing}. This header allows only ring 16. A smaller ring will not be substituted.`,
      );
    }
    ring = 16;
  } else {
    const pool = opts.decoyCandidates + 1;
    const largest = pool >= 64 ? 64 : pool >= 32 ? 32 : 0;
    if (largest === 0) {
      throw new Error(
        "Refusing to send. Not enough decoys for ring 32. A smaller ring will not be substituted.",
      );
    }
    if (opts.explicitRing != null) {
      if (opts.explicitRing !== 32 && opts.explicitRing !== 64) {
        throw new Error(
          `Refusing ring ${opts.explicitRing}. This header allows 32 or 64. A smaller ring will not be substituted.`,
        );
      }
      if (opts.explicitRing > largest) {
        throw new Error(
          `Refusing ring ${opts.explicitRing}. Not enough decoys, and a smaller ring will not be substituted.`,
        );
      }
      ring = opts.explicitRing;
    } else {
      ring = largest;
    }
  }
  return { ringSize: ring, hiddenFee: false };
}

export function firstHeaderHex(raw: unknown): string {
  const rows = Array.isArray(raw)
    ? raw
    : raw &&
        typeof raw === "object" &&
        Array.isArray((raw as { headers?: unknown }).headers)
      ? (raw as { headers: unknown[] }).headers
      : [raw];
  for (const row of rows) {
    if (
      row &&
      typeof row === "object" &&
      typeof (row as { header_hex?: unknown }).header_hex === "string" &&
      (row as { header_hex: string }).header_hex.trim()
    ) {
      return (row as { header_hex: string }).header_hex.trim();
    }
  }
  throw new Error("Refusing to send: the node did not return header bytes.");
}

export function requireTwoOutputs(count: number): void {
  if (count < 2) {
    throw new Error(
      "Refusing to send. A payment needs two outputs. A one-output payment will not be sent.",
    );
  }
}

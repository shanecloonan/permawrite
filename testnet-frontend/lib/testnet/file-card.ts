/**
 * Local backup card for a file a person wants stored.
 *
 * The wallet seed does not contain file bytes. The card is the thing they
 * keep: name, size, and SHA-256. Matching a file against the card checks
 * their copy. It does not prove the network still has the bytes.
 */

export type FileCard = {
  version: 1;
  filename: string;
  bytes: number;
  sha256: string;
  note: string;
};

export const FILE_CARD_NOTE =
  "The wallet seed does not contain this file. Keep this card and your own copy of the bytes. Matching a file against the card checks your copy, not the network.";

const SHA256_HEX = /^[0-9a-f]{64}$/;

export function makeFileCard(
  filename: string,
  bytes: number,
  sha256: string,
): FileCard {
  const name = filename.trim();
  if (!name || name.includes("/") || name.includes("\\")) {
    throw new Error("Use a plain file name, not a path.");
  }
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new Error("The file is empty.");
  }
  const hash = sha256.trim().toLowerCase();
  if (!SHA256_HEX.test(hash)) {
    throw new Error("SHA-256 must be 64 hex characters.");
  }
  return {
    version: 1,
    filename: name,
    bytes,
    sha256: hash,
    note: FILE_CARD_NOTE,
  };
}

export function parseFileCard(raw: string): FileCard {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("That file is not a backup card.");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new Error("That file is not a backup card.");
  }
  const card = parsed as Partial<FileCard>;
  if (card.version !== 1) {
    throw new Error("This card is from a different version. Download a new one.");
  }
  if (typeof card.filename !== "string" || typeof card.sha256 !== "string") {
    throw new Error("That file is not a backup card.");
  }
  if (typeof card.bytes !== "number") {
    throw new Error("That file is not a backup card.");
  }
  return makeFileCard(card.filename, card.bytes, card.sha256);
}

export type CardCheck =
  | { ok: true; message: string }
  | { ok: false; message: string };

/** Compare a file the person still has with a card they kept. */
export function checkFileAgainstCard(
  card: FileCard,
  filename: string,
  bytes: number,
  sha256: string,
): CardCheck {
  const name = filename.trim();
  const hash = sha256.trim().toLowerCase();
  if (name !== card.filename) {
    return {
      ok: false,
      message: `This file is named ${name}. The card is for ${card.filename}.`,
    };
  }
  if (bytes !== card.bytes) {
    return {
      ok: false,
      message: `This file is ${bytes} bytes. The card recorded ${card.bytes}.`,
    };
  }
  if (hash !== card.sha256) {
    return {
      ok: false,
      message:
        "The contents do not match the card. This is a different file, or it was edited.",
    };
  }
  return {
    ok: true,
    message:
      "This file matches the card. That checks your copy. It does not prove the network still has the bytes, and the wallet seed still does not contain them.",
  };
}

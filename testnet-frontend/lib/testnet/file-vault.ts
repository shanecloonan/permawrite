/**
 * Encrypt a file in the browser, name it by the ciphertext hash, and
 * decrypt that same copy later. The plaintext is not stored.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export const FILE_VAULT_PREFIX = "pw-file-vault:";

export type SealedFile = {
  content_id: string;
  name: string;
  kdf: "pbkdf2-sha256";
  iterations: number;
  salt_b64: string;
  iv_b64: string;
  ciphertext_b64: string;
  commitment_hash?: string;
  data_root?: string;
};

type Store = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(text: string): Uint8Array<ArrayBuffer> {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function asBuffer(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(bytes.byteLength);
  out.set(bytes);
  return out;
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function sealFile(
  name: string,
  bytes: Uint8Array,
  passphrase: string,
  iterations = 210_000,
): Promise<SealedFile> {
  if (!passphrase) throw new Error("passphrase is required");
  if (!name.trim()) throw new Error("file name is required");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, asBuffer(salt), iterations);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: asBuffer(iv) },
      key,
      asBuffer(bytes),
    ),
  );
  return {
    content_id: bytesToHex(sha256(ct)),
    name: name.trim(),
    kdf: "pbkdf2-sha256",
    iterations,
    salt_b64: bytesToB64(salt),
    iv_b64: bytesToB64(iv),
    ciphertext_b64: bytesToB64(ct),
  };
}

export async function openFile(
  sealed: SealedFile,
  passphrase: string,
): Promise<Uint8Array> {
  if (!passphrase) throw new Error("passphrase is required");
  const key = await deriveKey(
    passphrase,
    b64ToBytes(sealed.salt_b64),
    sealed.iterations,
  );
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(sealed.iv_b64) },
      key,
      b64ToBytes(sealed.ciphertext_b64),
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error("passphrase does not open this file");
  }
}

export function saveSealedFile(sealed: SealedFile, store: Store): void {
  const json = JSON.stringify(sealed);
  if (json.includes("plaintext")) {
    throw new Error("refusing to store plaintext");
  }
  store.setItem(FILE_VAULT_PREFIX + sealed.content_id, json);
}

export function loadSealedFile(contentId: string, store: Store): SealedFile | null {
  const raw = store.getItem(FILE_VAULT_PREFIX + contentId.trim());
  if (!raw) return null;
  const parsed = JSON.parse(raw) as SealedFile;
  if (parsed.content_id !== contentId.trim() || !parsed.ciphertext_b64) {
    throw new Error("stored file is not readable");
  }
  return parsed;
}

export function ciphertextBytes(sealed: SealedFile): Uint8Array<ArrayBuffer> {
  return b64ToBytes(sealed.ciphertext_b64);
}

/** Attach the storage commitment of the ciphertext, when the page can build one. */
export function withCommitment(
  sealed: SealedFile,
  previewJson: string,
): SealedFile {
  const preview = JSON.parse(previewJson) as {
    commitment_hash?: string;
    data_root?: string;
  };
  if (!preview.commitment_hash || !preview.data_root) {
    throw new Error("storage preview did not include a commitment");
  }
  return {
    ...sealed,
    commitment_hash: preview.commitment_hash,
    data_root: preview.data_root,
  };
}

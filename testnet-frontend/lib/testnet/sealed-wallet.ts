/**
 * Passphrase seal for a 32-byte wallet seed kept in browser storage.
 * PBKDF2-HMAC-SHA256 then AES-GCM. The seed is not stored in the clear.
 */

export const BROWSER_PBKDF2_ITERATIONS = 210_000;
export const SEALED_WALLET_KEY = "pw-sealed-wallet";

export type SealedWallet = {
  kdf: "pbkdf2-sha256";
  iterations: number;
  salt_b64: string;
  iv_b64: string;
  ciphertext_b64: string;
};

type Store = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
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

export async function sealSeed(
  seed: Uint8Array,
  passphrase: string,
  iterations = BROWSER_PBKDF2_ITERATIONS,
): Promise<SealedWallet> {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  if (!passphrase) throw new Error("passphrase is required");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, asBuffer(salt), iterations);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuffer(iv) }, key, asBuffer(seed)),
  );
  return {
    kdf: "pbkdf2-sha256",
    iterations,
    salt_b64: bytesToB64(salt),
    iv_b64: bytesToB64(iv),
    ciphertext_b64: bytesToB64(ct),
  };
}

export async function openSeed(
  sealed: SealedWallet,
  passphrase: string,
): Promise<Uint8Array> {
  if (sealed.kdf !== "pbkdf2-sha256") {
    throw new Error("unsupported wallet seal");
  }
  if (!passphrase) throw new Error("passphrase is required");
  const key = await deriveKey(
    passphrase,
    asBuffer(b64ToBytes(sealed.salt_b64)),
    sealed.iterations,
  );
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: asBuffer(b64ToBytes(sealed.iv_b64)) },
      key,
      asBuffer(b64ToBytes(sealed.ciphertext_b64)),
    );
    const seed = new Uint8Array(plain);
    if (seed.length !== 32) throw new Error("sealed wallet is not a seed");
    return seed;
  } catch {
    throw new Error("passphrase does not open this wallet");
  }
}

export function saveSealedWallet(sealed: SealedWallet, store: Store): void {
  const json = JSON.stringify(sealed);
  if (json.includes("seed_hex")) {
    throw new Error("refusing to store a seed in the clear");
  }
  store.setItem(SEALED_WALLET_KEY, json);
}

export function loadSealedWallet(store: Store): SealedWallet | null {
  const raw = store.getItem(SEALED_WALLET_KEY);
  if (!raw) return null;
  const parsed = JSON.parse(raw) as SealedWallet;
  if (parsed.kdf !== "pbkdf2-sha256" || !parsed.ciphertext_b64) {
    throw new Error("stored wallet seal is not readable");
  }
  return parsed;
}

export function forgetSealedWallet(store: Store): void {
  store.removeItem(SEALED_WALLET_KEY);
}

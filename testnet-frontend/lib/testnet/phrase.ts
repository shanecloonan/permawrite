/**
 * 24-word recovery phrase (BIP-39 English, 256-bit entropy).
 * The words are the seed. A bad checksum is an error.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { BIP39_ENGLISH } from "./bip39-english.mjs";

export function phraseFromSeed(seed: Uint8Array): string {
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  const checksum = sha256(seed)[0]!;
  const bits = new Uint8Array(33);
  bits.set(seed);
  bits[32] = checksum;
  const words: string[] = [];
  let acc = 0;
  let accBits = 0;
  for (const byte of bits) {
    acc = (acc << 8) | byte;
    accBits += 8;
    while (accBits >= 11) {
      accBits -= 11;
      const idx = (acc >> accBits) & 0x7ff;
      const word = BIP39_ENGLISH[idx];
      if (!word) throw new Error("word index out of range");
      words.push(word);
      acc &= (1 << accBits) - 1;
    }
  }
  if (words.length !== 24) {
    throw new Error(`phrase must be 24 words (got ${words.length})`);
  }
  return words.join(" ");
}

export function seedFromPhrase(phrase: string): Uint8Array {
  const words = phrase.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length !== 24) {
    throw new Error(`a recovery phrase is 24 words (got ${words.length})`);
  }
  let acc = 0;
  let accBits = 0;
  const bytes: number[] = [];
  for (const word of words) {
    const idx = BIP39_ENGLISH.indexOf(word);
    if (idx < 0) {
      throw new Error(`unknown recovery word: ${word}`);
    }
    acc = (acc << 11) | idx;
    accBits += 11;
    while (accBits >= 8) {
      accBits -= 8;
      bytes.push((acc >> accBits) & 0xff);
      acc &= (1 << accBits) - 1;
    }
  }
  if (bytes.length !== 33) {
    throw new Error("recovery phrase did not decode");
  }
  const seed = Uint8Array.from(bytes.slice(0, 32));
  const expect = sha256(seed)[0]!;
  if (bytes[32] !== expect) {
    throw new Error("recovery phrase checksum does not match");
  }
  return seed;
}

export function seedHexFromPhrase(phrase: string): string {
  return bytesToHex(seedFromPhrase(phrase));
}

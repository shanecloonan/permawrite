import assert from "node:assert/strict";
import test from "node:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  forgetSealedWallet,
  loadSealedWallet,
  openSeed,
  saveSealedWallet,
  sealSeed,
} from "./sealed-wallet.ts";

test("a sealed wallet opens only with the same passphrase", async () => {
  const seed = new Uint8Array(32).fill(9);
  const sealed = await sealSeed(seed, "correct horse", 1_000);
  const opened = await openSeed(sealed, "correct horse");
  assert.deepEqual(opened, seed);
  await assert.rejects(openSeed(sealed, "wrong"), /passphrase/);
  const stored = JSON.stringify(sealed);
  assert.equal(stored.includes(bytesToHex(seed)), false);
});

test("local storage keeps the seal and not the seed", async () => {
  const mem = new Map();
  const store = {
    getItem: (k) => mem.get(k) ?? null,
    setItem: (k, v) => mem.set(k, v),
    removeItem: (k) => mem.delete(k),
  };
  const seed = new Uint8Array(32).fill(3);
  saveSealedWallet(await sealSeed(seed, "desk lamp", 1_000), store);
  const loaded = loadSealedWallet(store);
  assert.ok(loaded);
  assert.deepEqual(await openSeed(loaded, "desk lamp"), seed);
  forgetSealedWallet(store);
  assert.equal(loadSealedWallet(store), null);
});

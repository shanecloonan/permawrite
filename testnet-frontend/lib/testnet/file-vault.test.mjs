import assert from "node:assert/strict";
import test from "node:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  loadSealedFile,
  openFile,
  saveSealedFile,
  sealFile,
  withCommitment,
} from "./file-vault.ts";

test("encrypt, store by content id, and decrypt the same bytes", async () => {
  const plain = new TextEncoder().encode("hello file");
  const sealed = await sealFile("note.txt", plain, "lamp", 1_000);
  assert.equal(sealed.content_id.length, 64);
  assert.equal(JSON.stringify(sealed).includes(bytesToHex(plain)), false);
  const mem = new Map();
  const store = {
    getItem: (k) => mem.get(k) ?? null,
    setItem: (k, v) => mem.set(k, v),
  };
  saveSealedFile(sealed, store);
  const loaded = loadSealedFile(sealed.content_id, store);
  assert.ok(loaded);
  assert.deepEqual(await openFile(loaded, "lamp"), plain);
  await assert.rejects(openFile(loaded, "nope"), /passphrase/);
  assert.equal(loadSealedFile("0".repeat(64), store), null);
});

test("a storage preview is attached to the sealed file", async () => {
  const sealed = await sealFile("a.bin", new Uint8Array([1, 2, 3]), "lamp", 1_000);
  const withPreview = withCommitment(
    sealed,
    JSON.stringify({ commitment_hash: "ab", data_root: "cd" }),
  );
  assert.equal(withPreview.commitment_hash, "ab");
  assert.equal(withPreview.content_id, sealed.content_id);
});

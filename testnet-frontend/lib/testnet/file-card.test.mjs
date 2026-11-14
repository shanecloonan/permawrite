import assert from "node:assert/strict";
import test from "node:test";
import {
  checkFileAgainstCard,
  makeFileCard,
  parseFileCard,
} from "./file-card.ts";

const HASH = "ab".repeat(32);

test("card records the hash and says the seed is not the file", () => {
  const card = makeFileCard("notes.txt", 12, HASH);
  assert.equal(card.sha256, HASH);
  assert.match(card.note, /seed does not contain/);
  const again = parseFileCard(JSON.stringify(card));
  assert.equal(again.filename, "notes.txt");
});

test("a matching file is your copy, not a network proof", () => {
  const card = makeFileCard("notes.txt", 12, HASH);
  const result = checkFileAgainstCard(card, "notes.txt", 12, HASH.toUpperCase());
  assert.equal(result.ok, true);
  assert.match(result.message, /does not prove the network/);
});

test("a different hash is refused", () => {
  const card = makeFileCard("notes.txt", 12, HASH);
  const result = checkFileAgainstCard(card, "notes.txt", 12, "cd".repeat(32));
  assert.equal(result.ok, false);
  assert.match(result.message, /do not match/);
});

test("a path is not a file name", () => {
  assert.throws(() => makeFileCard("../notes.txt", 12, HASH), /plain file name/);
});

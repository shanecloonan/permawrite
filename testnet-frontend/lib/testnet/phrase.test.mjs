import assert from "node:assert/strict";
import test from "node:test";
import { phraseFromSeed, seedFromPhrase, seedHexFromPhrase } from "./phrase.ts";

const ZERO_PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

test("32 zero bytes are the published 24-word phrase", () => {
  const phrase = phraseFromSeed(new Uint8Array(32));
  assert.equal(phrase, ZERO_PHRASE);
  assert.equal(seedHexFromPhrase(phrase), "0".repeat(64));
});

test("a swapped word is refused", () => {
  const words = ZERO_PHRASE.split(" ");
  words[1] = "zoo";
  assert.throws(() => seedFromPhrase(words.join(" ")), /checksum/);
});

test("round trip keeps the seed", () => {
  const seed = new Uint8Array(32).fill(0x7f);
  const back = seedFromPhrase(phraseFromSeed(seed));
  assert.deepEqual(back, seed);
});

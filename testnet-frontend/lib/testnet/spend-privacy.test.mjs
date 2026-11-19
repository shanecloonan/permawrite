import assert from "node:assert/strict";
import test from "node:test";
import {
  chooseBrowserSpend,
  headerVersionFromHex,
  requireTwoOutputs,
} from "./spend-privacy.ts";

test("header version is the first varint byte", () => {
  assert.equal(headerVersionFromHex("01aa"), 1);
  assert.equal(headerVersionFromHex("05"), 5);
  assert.throws(() => headerVersionFromHex("80"), /version/);
});

test("path A uses ring 16 and refuses a smaller ring", () => {
  const choice = chooseBrowserSpend({ headerVersion: 1, decoyCandidates: 100 });
  assert.equal(choice.ringSize, 16);
  assert.equal(choice.hiddenFee, false);
  assert.throws(
    () =>
      chooseBrowserSpend({
        headerVersion: 1,
        decoyCandidates: 100,
        explicitRing: 8,
      }),
    /will not be substituted/,
  );
});

test("header v5 uses the largest ring that fits and refuses a shrink", () => {
  assert.equal(
    chooseBrowserSpend({ headerVersion: 5, decoyCandidates: 63 }).ringSize,
    64,
  );
  assert.equal(
    chooseBrowserSpend({ headerVersion: 5, decoyCandidates: 31 }).ringSize,
    32,
  );
  assert.throws(
    () => chooseBrowserSpend({ headerVersion: 5, decoyCandidates: 10 }),
    /smaller ring/,
  );
});

test("a hidden-fee header is refused until the page can sign one", () => {
  assert.throws(
    () => chooseBrowserSpend({ headerVersion: 6, decoyCandidates: 80 }),
    /hidden fee/,
  );
});

test("one output is refused", () => {
  assert.throws(() => requireTwoOutputs(1), /two outputs/);
  requireTwoOutputs(2);
});

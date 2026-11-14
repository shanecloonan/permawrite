import assert from "node:assert/strict";
import test from "node:test";
import { parseSpendAmount } from "./spend-amount.ts";

test("a bare integer stays atomic and is labeled as less than a coin", () => {
  const amount = parseSpendAmount("100000");
  assert.equal(amount.atomic, 100000);
  assert.match(amount.label, /0\.00100000 MFN/);
  assert.match(amount.label, /not a whole coin/);
});

test("1mfn is one coin, not one atomic unit", () => {
  const amount = parseSpendAmount("1mfn");
  assert.equal(amount.atomic, 100_000_000);
  assert.match(amount.label, /1\.00000000 MFN/);
});

test("extra decimal places are refused", () => {
  assert.throws(
    () => parseSpendAmount("1.000000001mfn"),
    /8 decimal places/,
  );
});

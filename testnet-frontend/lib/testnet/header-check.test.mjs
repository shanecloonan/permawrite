import assert from "node:assert/strict";
import test from "node:test";
import {
  balanceAfterHeaderCheck,
  checkpointHexFromRpc,
  headerHexesFromRpc,
  verifyHeadersLocally,
} from "./header-check.ts";

test("a bad header hides the balance", async () => {
  const check = await verifyHeadersLocally("aa", ["01", "02"], (cp, header) => {
    assert.equal(cp, "aa");
    if (header === "02") return JSON.stringify({ ok: false, error: "bad signature" });
    return JSON.stringify({ ok: true, block_id: "11" });
  });
  assert.equal(check.ok, false);
  if (!check.ok) assert.match(check.error, /bad signature/);
  assert.equal(balanceAfterHeaderCheck(check, 50), null);
});

test("accepted headers reveal the balance and the tip id", async () => {
  const check = await verifyHeadersLocally("cc", ["01"], () =>
    JSON.stringify({ ok: true, block_id: "abc" }),
  );
  assert.equal(check.ok, true);
  if (check.ok) assert.equal(check.tipBlockId, "abc");
  assert.equal(balanceAfterHeaderCheck(check, 50), 50);
  assert.equal(balanceAfterHeaderCheck(null, 50), null);
});

test("missing header bytes are a refusal", async () => {
  const check = await verifyHeadersLocally(
    checkpointHexFromRpc({ checkpoint_hex: "dd" }),
    headerHexesFromRpc({ headers: [{ height: 1 }] }),
    () => {
      throw new Error("should not be called");
    },
  );
  assert.equal(check.ok, false);
});

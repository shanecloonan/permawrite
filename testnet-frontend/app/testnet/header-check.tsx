"use client";

import { useState } from "react";
import {
  balanceAfterHeaderCheck,
  checkpointHexFromRpc,
  headerHexesFromRpc,
  verifyHeadersLocally,
  type HeaderCheck,
} from "@/lib/testnet/header-check";
import { getRpcProxyUrl, rpcCall } from "@/lib/testnet/rpc";
import { loadMfnWasm, loadSession, loadSync, totalBalance } from "@/lib/testnet/wasm-wallet";

type Props = { rpcProxyUrl?: string | null };

/**
 * Fetch the tip headers and check them with the local WASM light client
 * before showing a balance.
 */
export default function HeaderCheck({ rpcProxyUrl }: Props) {
  const proxy = getRpcProxyUrl(rpcProxyUrl) || "/api/testnet/rpc";
  const [check, setCheck] = useState<HeaderCheck | null>(null);
  const [busy, setBusy] = useState(false);

  async function onCheck() {
    setBusy(true);
    setCheck(null);
    try {
      const snapshot = await rpcCall<unknown>(proxy, "get_light_snapshot", {});
      const tip = await rpcCall<{ tip_height?: number; height?: number }>(
        proxy,
        "get_tip",
        {},
      );
      const tipHeight = Number(tip.tip_height ?? tip.height ?? 0);
      const from = Math.max(1, tipHeight - 2);
      const rawHeaders = await rpcCall<unknown>(proxy, "get_block_headers", {
        from_height: from,
        to_height: tipHeight,
      });
      const wasm = await loadMfnWasm();
      const verify = (
        wasm as { lightChainVerifyHeader?: (c: string, h: string) => string }
      ).lightChainVerifyHeader;
      if (!verify) {
        setCheck({
          ok: false,
          checked: 0,
          error: "this page build cannot check headers locally",
        });
        return;
      }
      setCheck(
        await verifyHeadersLocally(
          checkpointHexFromRpc(snapshot),
          headerHexesFromRpc(rawHeaders),
          (checkpoint, header) => verify(checkpoint, header),
        ),
      );
    } catch (e) {
      setCheck({
        ok: false,
        checked: 0,
        error: e instanceof Error ? e.message : "header check failed",
      });
    } finally {
      setBusy(false);
    }
  }

  const session = typeof window === "undefined" ? null : loadSession();
  const atomic = session ? totalBalance(loadSync(session.seedHex)) : 0;
  const shown = balanceAfterHeaderCheck(check, atomic);

  return (
    <section className="space-y-2 rounded-xl border border-[var(--pw-line)] bg-[var(--pw-surface)]/40 px-4 py-4">
      <p className="text-sm font-semibold text-[var(--pw-ink)]">
        Balance after a local header check
      </p>
      <p className="text-[11px] text-[var(--pw-faint)]">
        The page checks the tip headers with the light client in this browser.
        The balance stays hidden until that check accepts them.
      </p>
      <button
        type="button"
        onClick={() => void onCheck()}
        disabled={busy}
        className="inline-flex h-10 items-center rounded-md bg-[var(--pw-accent)] px-4 text-sm font-semibold text-[#0a1210] disabled:opacity-60"
      >
        {busy ? "Checking…" : "Check headers"}
      </button>
      {check && !check.ok && (
        <p className="text-sm text-red-300">{check.error}</p>
      )}
      {check?.ok && (
        <p className="text-sm text-[var(--pw-ink)]">
          {check.checked} header{check.checked === 1 ? "" : "s"} accepted.
          Balance {shown === null ? "hidden" : shown.toLocaleString()} atomic
          units.
        </p>
      )}
    </section>
  );
}

"use client";

import { useCallback, useState } from "react";
import { phraseFromSeed, seedFromPhrase } from "@/lib/testnet/phrase";
import {
  forgetSealedWallet,
  loadSealedWallet,
  openSeed,
  saveSealedWallet,
  sealSeed,
} from "@/lib/testnet/sealed-wallet";
import { walletFromSeed } from "@/lib/testnet/wallet-keys";

type OpenWallet = {
  address: string;
  viewPubHex: string;
  spendPubHex: string;
};

/**
 * Create or restore a wallet from 24 words and keep the seed sealed in
 * local storage. The address is derived on this device.
 */
export default function BrowserWallet() {
  const [phrase, setPhrase] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [opened, setOpened] = useState<OpenWallet | null>(null);
  const [freshWords, setFreshWords] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const store = typeof window === "undefined" ? null : window.localStorage;

  const show = useCallback((seed: Uint8Array) => {
    const wallet = walletFromSeed(seed);
    setOpened({
      address: wallet.address,
      viewPubHex: wallet.viewPubHex,
      spendPubHex: wallet.spendPubHex,
    });
    setFreshWords(null);
    setPhrase("");
    setPassphrase("");
    setError(null);
  }, []);

  const onCreate = useCallback(async () => {
    if (!store) return;
    if (!passphrase) {
      setError("Choose a passphrase before creating a wallet.");
      return;
    }
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    const words = phraseFromSeed(seed);
    saveSealedWallet(await sealSeed(seed, passphrase), store);
    setFreshWords(words);
    show(seed);
    setFreshWords(words);
  }, [passphrase, show, store]);

  const onRestore = useCallback(async () => {
    if (!store) return;
    try {
      if (!passphrase) throw new Error("passphrase is required");
      const seed = seedFromPhrase(phrase);
      saveSealedWallet(await sealSeed(seed, passphrase), store);
      show(seed);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not restore");
    }
  }, [passphrase, phrase, show, store]);

  const onUnlock = useCallback(async () => {
    if (!store) return;
    try {
      const sealed = loadSealedWallet(store);
      if (!sealed) throw new Error("no sealed wallet is stored on this browser");
      show(await openSeed(sealed, passphrase));
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not unlock");
    }
  }, [passphrase, show, store]);

  const onForget = useCallback(() => {
    if (store) forgetSealedWallet(store);
    setOpened(null);
    setFreshWords(null);
    setError(null);
  }, [store]);

  return (
    <section className="space-y-3 rounded-xl border border-[var(--pw-line)] bg-[var(--pw-surface)]/40 px-4 py-4">
      <div>
        <p className="text-sm font-semibold text-[var(--pw-ink)]">
          Wallet on this device
        </p>
        <p className="mt-0.5 text-[11px] text-[var(--pw-faint)]">
          24 words restore the same address. The seed stays sealed in this
          browser. Nothing is sent to a server.
        </p>
      </div>
      {freshWords && (
        <p className="break-words rounded-md border border-[var(--pw-line)] px-3 py-2 text-sm text-[var(--pw-ink)]">
          Write these words down. They are shown once. {freshWords}
        </p>
      )}
      {opened && (
        <p className="break-all text-[11px] text-[var(--pw-muted)]">
          Address {opened.address}
        </p>
      )}
      <label className="block text-[11px] text-[var(--pw-muted)]">
        24 words, to restore
        <textarea
          value={phrase}
          onChange={(e) => setPhrase(e.target.value)}
          rows={3}
          className="mt-1 w-full rounded-md border border-[var(--pw-line)] bg-transparent px-2 py-1 text-sm text-[var(--pw-ink)]"
        />
      </label>
      <label className="block text-[11px] text-[var(--pw-muted)]">
        Passphrase
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="mt-1 w-full rounded-md border border-[var(--pw-line)] bg-transparent px-2 py-1 text-sm text-[var(--pw-ink)]"
        />
      </label>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => void onCreate()}
          className="inline-flex h-10 items-center rounded-md bg-[var(--pw-accent)] px-4 text-sm font-semibold text-[#0a1210]"
        >
          Create wallet
        </button>
        <button
          type="button"
          onClick={() => void onRestore()}
          className="inline-flex h-10 items-center rounded-md border border-[var(--pw-line)] px-4 text-sm text-[var(--pw-ink)]"
        >
          Restore words
        </button>
        <button
          type="button"
          onClick={() => void onUnlock()}
          className="inline-flex h-10 items-center rounded-md border border-[var(--pw-line)] px-4 text-sm text-[var(--pw-ink)]"
        >
          Unlock
        </button>
        <button
          type="button"
          onClick={onForget}
          className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--pw-muted)]"
        >
          Forget
        </button>
      </div>
      {error && <p className="text-sm text-red-300">{error}</p>}
    </section>
  );
}

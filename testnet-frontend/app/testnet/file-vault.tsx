"use client";

import { useState } from "react";
import {
  ciphertextBytes,
  loadSealedFile,
  openFile,
  saveSealedFile,
  sealFile,
  withCommitment,
} from "@/lib/testnet/file-vault";
import { loadMfnWasm } from "@/lib/testnet/wasm-wallet";

/**
 * Pick a file, encrypt it, and later decrypt it by the content id.
 * The id is the hash of the ciphertext. The plaintext stays on this device.
 */
export default function FileVault() {
  const [passphrase, setPassphrase] = useState("");
  const [contentId, setContentId] = useState("");
  const [lookupId, setLookupId] = useState("");
  const [commitment, setCommitment] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onFile(file: File | undefined) {
    if (!file) return;
    setError(null);
    setStatus(null);
    try {
      if (!passphrase) throw new Error("Choose a passphrase first.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      let sealed = await sealFile(file.name, bytes, passphrase);
      try {
        const wasm = await loadMfnWasm();
        const preview = (
          wasm as { storageUploadPreview?: (d: Uint8Array, r: number) => string }
        ).storageUploadPreview;
        if (preview) {
          sealed = withCommitment(sealed, preview(ciphertextBytes(sealed), 1));
        }
      } catch {
        // The content id still names the ciphertext when the preview cannot run.
      }
      saveSealedFile(sealed, window.localStorage);
      setContentId(sealed.content_id);
      setCommitment(sealed.commitment_hash ?? null);
      setStatus(`Sealed ${file.name}. Share the content id, not the file.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not seal the file");
    }
  }

  async function onOpen() {
    setError(null);
    try {
      const sealed = loadSealedFile(lookupId.trim(), window.localStorage);
      if (!sealed) throw new Error("no file with that content id is stored here");
      const opened = await openFile(sealed, passphrase);
      const plain = new Uint8Array(opened.byteLength);
      plain.set(opened);
      const blob = new Blob([plain]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = sealed.name;
      a.click();
      URL.revokeObjectURL(url);
      setStatus(`Decrypted ${sealed.name}.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not open the file");
    }
  }

  return (
    <section className="space-y-3 rounded-xl border border-[var(--pw-line)] bg-[var(--pw-surface)]/40 px-4 py-4">
      <div>
        <p className="text-sm font-semibold text-[var(--pw-ink)]">
          Encrypt a file
        </p>
        <p className="mt-0.5 text-[11px] text-[var(--pw-faint)]">
          The content id is the hash of the ciphertext. Opening it decrypts
          the copy stored under that id on this browser. The file bytes are
          not uploaded in the clear.
        </p>
      </div>
      <label className="block text-[11px] text-[var(--pw-muted)]">
        Passphrase
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="mt-1 w-full rounded-md border border-[var(--pw-line)] bg-transparent px-2 py-1 text-sm text-[var(--pw-ink)]"
        />
      </label>
      <input
        type="file"
        onChange={(e) => void onFile(e.target.files?.[0])}
        className="text-sm text-[var(--pw-ink)]"
      />
      {contentId && (
        <p className="break-all text-[11px] text-[var(--pw-muted)]">
          Content id {contentId}
          {commitment ? ` · commitment ${commitment}` : ""}
        </p>
      )}
      <label className="block text-[11px] text-[var(--pw-muted)]">
        Content id to open
        <input
          value={lookupId}
          onChange={(e) => setLookupId(e.target.value)}
          className="mt-1 w-full rounded-md border border-[var(--pw-line)] bg-transparent px-2 py-1 text-sm text-[var(--pw-ink)]"
        />
      </label>
      <button
        type="button"
        onClick={() => void onOpen()}
        className="inline-flex h-10 items-center rounded-md bg-[var(--pw-accent)] px-4 text-sm font-semibold text-[#0a1210]"
      >
        Decrypt
      </button>
      {status && <p className="text-sm text-[var(--pw-ink)]">{status}</p>}
      {error && <p className="text-sm text-red-300">{error}</p>}
    </section>
  );
}

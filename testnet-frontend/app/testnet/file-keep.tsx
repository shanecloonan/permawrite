"use client";

import { useState } from "react";
import {
  checkFileAgainstCard,
  makeFileCard,
  parseFileCard,
  type FileCard,
} from "@/lib/testnet/file-card";

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function readFile(file: File): Promise<{ bytes: Uint8Array; sha256: string }> {
  const buffer = new Uint8Array(await file.arrayBuffer());
  return { bytes: buffer, sha256: await sha256Hex(buffer) };
}

export default function FileKeep() {
  const [card, setCard] = useState<FileCard | null>(null);
  const [saved, setSaved] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<FileCard | null>(null);

  async function onPick(file: File | undefined) {
    setError(null);
    setMessage(null);
    setSaved(false);
    if (!file) return;
    try {
      const { bytes, sha256 } = await readFile(file);
      setCard(makeFileCard(file.name, bytes.byteLength, sha256));
    } catch (err) {
      setCard(null);
      setError(err instanceof Error ? err.message : "Could not read that file.");
    }
  }

  function downloadCard() {
    if (!card) return;
    const blob = new Blob([JSON.stringify(card, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${card.filename}.permawrite-card.json`;
    link.click();
    URL.revokeObjectURL(url);
    setSaved(true);
    setMessage(
      "Card downloaded. Keep it with your copy of the file. The wallet seed does not contain the bytes.",
    );
  }

  async function onLoadCard(file: File | undefined) {
    setError(null);
    setMessage(null);
    if (!file) return;
    try {
      setLoaded(parseFileCard(await file.text()));
    } catch (err) {
      setLoaded(null);
      setError(err instanceof Error ? err.message : "Could not read that card.");
    }
  }

  async function onCheck(file: File | undefined) {
    if (!loaded || !file) return;
    setError(null);
    try {
      const { bytes, sha256 } = await readFile(file);
      const result = checkFileAgainstCard(
        loaded,
        file.name,
        bytes.byteLength,
        sha256,
      );
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not check that file.");
    }
  }

  return (
    <div className="space-y-3 border-t border-[var(--pw-line)] pt-3">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--pw-faint)]">
        Keep a file
      </p>
      <p className="text-xs leading-relaxed text-[var(--pw-muted)]">
        A wallet seed restores money, not files. Make a backup card before you
        rely on the network. The card never leaves this browser until you
        download it.
      </p>
      <input
        type="file"
        onChange={(event) => void onPick(event.target.files?.[0])}
        className="block w-full text-xs text-[var(--pw-muted)]"
      />
      {card ? (
        <div className="space-y-2 text-xs text-[var(--pw-muted)]">
          <p>
            {card.filename} · {card.bytes} bytes
          </p>
          <p className="break-all font-mono text-[11px] text-[var(--pw-code-ink)]">
            {card.sha256}
          </p>
          <button
            type="button"
            onClick={downloadCard}
            className="inline-flex h-9 items-center rounded-md border border-[var(--pw-accent)]/40 bg-[var(--pw-accent-soft)] px-3 text-xs font-semibold text-[var(--pw-accent)]"
          >
            Download backup card
          </button>
          {saved ? (
            <p>
              You have a local card. Matching a file against it later checks
              your copy. It does not ask the network, and it does not put the
              file in the seed.
            </p>
          ) : (
            <p>Download the card before you close this tab.</p>
          )}
        </div>
      ) : null}
      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--pw-faint)]">
          Check a card
        </p>
        <input
          type="file"
          accept="application/json,.json"
          onChange={(event) => void onLoadCard(event.target.files?.[0])}
          className="block w-full text-xs text-[var(--pw-muted)]"
        />
        {loaded ? (
          <input
            type="file"
            onChange={(event) => void onCheck(event.target.files?.[0])}
            className="block w-full text-xs text-[var(--pw-muted)]"
          />
        ) : null}
      </div>
      {message ? (
        <p className="text-xs leading-relaxed text-[var(--pw-muted)]">{message}</p>
      ) : null}
      {error ? <p className="text-xs leading-relaxed text-red-300/90">{error}</p> : null}
    </div>
  );
}

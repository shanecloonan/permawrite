# Permawrite testnet frontend

Standalone Next.js app for the experimental public testnet status page and
browser wallet (generate / faucet / scan / send).

Vendored from the Cloonan Group site route `/testnet` so the protocol repo
carries the same UI without depending on that monorepo.

## Run locally

```bash
cd testnet-frontend
npm install
npm run dev
```

Open [http://localhost:3000/testnet](http://localhost:3000/testnet).

## Upstream RPC / faucet

Same-origin API routes bridge to the public mesh:

| Route | Default upstream |
| --- | --- |
| `POST /api/testnet/rpc` | `http://5.161.201.73:8787/rpc` |
| `POST /api/testnet/faucet` | `http://5.161.201.73:8788/faucet` |

Override with env:

- `MFND_RPC_PROXY_UPSTREAM` / `MFND_OBSERVER_RPC_URL`
- `MFND_FAUCET_UPSTREAM`
- `NEXT_PUBLIC_MFND_RPC_PROXY_URL` (browser-facing proxy path; default `/api/testnet/rpc`)

Static mesh pins live in [`public/testnet/config.json`](public/testnet/config.json).
Browser wallet crypto uses `public/testnet/pkg` (`mfn-wasm` wasm-full build).

## Layout

```text
app/testnet/          # page UI
app/api/testnet/      # rpc + faucet HTTPS bridges
lib/testnet/          # rpc helper, wallet keys, wasm sync
public/testnet/       # config.json + mfn_wasm pkg
```

Rebuild wasm into `public/testnet/pkg` from the repo root when bindings change:

```bash
wasm-pack --log-level warn build mfn-wasm --target web \
  --out-dir testnet-frontend/public/testnet/pkg --release --features wasm-full
```

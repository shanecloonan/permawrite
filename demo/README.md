# Permawrite demos

## Web WASM demo (M4.1)

Browser UI for `mfn-wasm` wallet address derivation, claiming pubkey, and storage commitment preview.

### Build WASM bindings

```bash
./scripts/build-wasm-demo.sh
# Windows:
# pwsh scripts/build-wasm-demo.ps1
```

Output lands in `demo/web/pkg/` (gitignored).

### Run locally

1. Serve static files:

   ```bash
   cd demo/web && python -m http.server 8080
   ```

2. Open http://127.0.0.1:8080/

### Optional: chain RPC from the browser

Browsers cannot speak TCP to `mfnd serve` directly. Use the dev proxy:

```bash
# terminal 1
mfnd serve --rpc-listen 127.0.0.1:18731 ...

# terminal 2
node demo/proxy/rpc-proxy.mjs
```

Then click **get_tip** in the demo page (proxy default `http://127.0.0.1:8787/rpc`).

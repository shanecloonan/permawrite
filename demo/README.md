# Permawrite demos

## Web WASM demo (M4)

Browser UI for `mfn-wasm`: wallet keys, storage preview + **permanence upload** tx build, block scan, CLSAG transfer build, and mempool submit via `mfnd serve` RPC.

### Build WASM bindings

```bash
./scripts/build-wasm-demo.sh
# Windows:
# pwsh scripts/build-wasm-demo.ps1
```

Uses `--features wasm-full` (scan + transfer signing). Output: `demo/web/pkg/` (gitignored).

### Run locally

1. Serve static files:

   ```bash
   cd demo/web && python -m http.server 8080
   ```

2. Open http://127.0.0.1:8080/

### Chain + RPC (full transfer path)

Browsers cannot speak TCP to `mfnd` directly. Use the dev proxy:

```bash
# terminal 1 — chain with decoys (example devnet spec)
cargo run -p mfn-node --bin mfnd -- serve \
  --data-dir /tmp/permawrite-demo \
  --genesis mfn-node/testdata/devnet_one_validator.json \
  --rpc-listen 127.0.0.1:18731

# terminal 2 — produce blocks so coinbase UTXOs exist
cargo run -p mfn-node --bin mfnd -- step \
  --data-dir /tmp/permawrite-demo \
  --genesis mfn-node/testdata/devnet_one_validator.json \
  --blocks 3

# terminal 3 — HTTP → TCP JSON-RPC proxy
node demo/proxy/rpc-proxy.mjs
```

In the demo page:

1. Set wallet seed (must match a validator payout wallet if scanning coinbase).
2. **Catch up to tip** (wallet sync) — or manually paste **block hex** → **scanBlockHex**.
3. **Load decoys from node** → fills `decoy_utxos`.
4. **Build transfer** → **Submit to mempool** → **get_mempool** to confirm `tx_id`.

**Storage upload path:** choose a file → **Min fee** → **Build upload tx** (anchors data with optional authorship message) → **Submit upload**.

Proxy default: `http://127.0.0.1:8787/rpc`. P2P light-follow quorum (M4.15): `POST http://127.0.0.1:8787/p2p/light-follow` with `{"peer":"127.0.0.1:18732","from_height":1,"to_height":1}` (peer must expose `--p2p-listen`).

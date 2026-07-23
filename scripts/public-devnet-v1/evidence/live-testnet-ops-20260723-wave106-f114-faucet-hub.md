# Ops note — wave106 F114 faucet hub Connection refused (2026-07-23)

**Symptom:** faucet job error `mfn-cli exited 1: io: Connection refused (os error 111)` after wave105 wipe resync density.

**Lane 3 action:** document only; **no** faucet-http restart (§6); no Hetzner JOIN.

**Ask lane 7:** verify hub RPC listen / mfnd-hub health on VPS; repair without unnecessary faucet restart if worker can recover.

**Peer note:** nora/kate bal TIMEOUT + insufficient owned — peer fallback not reliable after dense spend.

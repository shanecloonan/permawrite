# B-28 pre + Path A health after B-267/B-268 (2026-08-06)

Lane 6 permanence. Tip CI `#31126560747` still progressing on B-265 `14f6b177`.

## Results

| Check | Result |
| --- | --- |
| Path A lag | tip=16472 ckpt=16468 **lag=4** (threshold 8) OK — evidence `outside-in-tip-ckpt-lag-20260806T191550Z.txt` |
| B-28 pre | tip=16472 treasury=2909711 fee_bps=9000 **subsidy_bps=0** PASS |
| B-268 | design + call-site inventory in `docs/B13_ACTIVATION_HEIGHT.md` — no enable |
| Hard lock | no B-13c; no B-268b Rust until tip CI GREEN + lane4 Ack |

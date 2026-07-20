# B-32 second distinct-host arm checklist (lane 7 ops)

B-79 `assert-b32-arm-ready --apply` stays NOT READY until `MFN_B32_OPERATOR_HOSTS` lists >=2 public hosts.
Single-box Hetzner (hub+v1+v2 on one IP) does **not** count as multi-op diversity.

## Required

1. Second machine with public IP != `5.161.201.73`, running release `mfnd` on same genesis.
2. Seeded from published Path A checkpoint log + `seed_nodes`.
3. Operator wallet bonded / proving path available for B3 multi-op pack (lane 4 script).
4. Export: `MFN_B32_OPERATOR_HOSTS=5.161.201.73,<second-ip>` then `assert-b32-arm-ready.sh --apply` -> READY.
5. Lane 4 runs live `b3-multi-op` pack; archive `b3-multi-op-*.txt`.

## Do not

- Fake READY with loopback/RFC5549/docs hosts.
- Restart faucet or thrash hub during B-15 JOIN capture.

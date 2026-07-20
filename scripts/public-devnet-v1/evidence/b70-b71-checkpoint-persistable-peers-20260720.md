# B-70 / B-71 — tip-4307 checkpoint + persistable peers filter (2026-07-20)

## B-70 ops

- Scrubbed re-polluted `peers.json` (again included `0.0.0.0:55124` + dynamic ports) without mfnd restart (B-15 tip healthy).
- Published Path A checkpoint tip **4307** (entries=12), anchors `5.161.201.73:19001–19003`.
- Added `assert-vps-peers-clean.sh`; wired into `vps-roll-mfnd.sh` after scrub.

## B-71 protocol/ops harden (closes §6 7→4)

- `mfn_store::is_persistable_peer_addr` rejects unspecified/multicast/port0/ports>=32768 on load+save.
- `P2pPeerSet::register` falls back to ephemeral for non-persistable advertise/dial keys.

## Note

CI `#29731004262` (B-69) was cancelled by lane 3 docs push `b8ca79b`; B-69/B-71 covered by follow-up CI on this head.
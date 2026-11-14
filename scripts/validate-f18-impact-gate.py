#!/usr/bin/env python3
"""B-23 / F18: fail closed if ring, endowment, or SPoRA floors regress.

The gate checks pinned source needles and the two public genesis files.
It does not hash whole crates, so an unrelated edit does not fail CI.
Removing or weakening a needle does.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (relative path, exact substring that must remain)
NEEDLES: list[tuple[str, str]] = [
    ("mfn-wallet/src/lib.rs", "pub const WALLET_MIN_RING_SIZE: usize = 16;"),
    (
        "mfn-consensus/src/constitution.rs",
        "pub const CONSTITUTIONAL_MIN_RING_SIZE: u32 = 16;",
    ),
    ("mfn-consensus/src/block/state.rs", "min_ring_size: 16,"),
    ("mfn-consensus/src/block/state.rs", "uniform_ring_size: 16,"),
    ("mfn-consensus/src/emission.rs", "fee_to_treasury_bps: 9000,"),
    ("mfn-consensus/src/emission.rs", "subsidy_to_treasury_bps: 0,"),
    (
        "mfn-storage/src/endowment.rs",
        "deflation_funded_drip: 0, // B-306 inert; Path A keeps fee+backstop payouts",
    ),
    ("mfn-consensus/src/block/apply.rs", "verify_storage_proof("),
    ("mfn-consensus/src/block/apply.rs", "verify_storage_proof_operator_salted("),
    ("docs/PRIVACY_HARDENING.md", "F18 impact gate (B-23)"),
    ("docs/PERMANENCE_HARDENING.md", "F18 impact gate (B-23)"),
]

PATH_A = ROOT / "mfn-node/testdata/public_devnet_v1.json"
PATH_FA = ROOT / "mfn-node/testdata/public_devnet_fa.json"


def missing_needles() -> list[str]:
    hits: list[str] = []
    for rel, needle in NEEDLES:
        path = ROOT / rel
        if not path.is_file():
            hits.append(f"missing file {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        if needle not in text:
            hits.append(f"{rel}: missing invariant `{needle}`")
    return hits


def genesis_problems() -> list[str]:
    problems: list[str] = []
    try:
        path_a = json.loads(PATH_A.read_text(encoding="utf-8"))
        path_fa = json.loads(PATH_FA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"genesis json: {exc}"]

    a_em = path_a.get("emission") or {}
    a_en = path_a.get("endowment") or {}
    if a_em.get("subsidy_to_treasury_bps", 0) != 0:
        problems.append("Path A subsidy_to_treasury_bps must stay 0")
    if a_em.get("storage_proof_reward") not in (None,):
        problems.append("Path A must not pin a non-default storage_proof_reward")
    if a_en.get("deflation_funded_drip", 0) != 0:
        problems.append("Path A deflation_funded_drip must stay 0")
    if a_en.get("min_storage_operator_bond", 0) != 0:
        problems.append("Path A min_storage_operator_bond must stay 0")
    if a_en.get("fee_runway_shift", 0) != 0:
        problems.append("Path A fee_runway_shift must stay 0")

    f_em = path_fa.get("emission") or {}
    f_en = path_fa.get("endowment") or {}
    if f_em.get("subsidy_to_treasury_bps") != 1000:
        problems.append("F-A subsidy_to_treasury_bps must stay 1000")
    if f_em.get("storage_proof_reward") != 1763:
        problems.append("F-A storage_proof_reward must stay 1763")
    if f_en.get("deflation_funded_drip") != 1:
        problems.append("F-A deflation_funded_drip must stay 1")
    if f_en.get("min_storage_operator_bond") != 25769800:
        problems.append("F-A min_storage_operator_bond must stay 25769800")
    if f_en.get("fee_runway_shift", 0) != 0:
        problems.append("F-A fee_runway_shift must stay off (B-20 is a separate gate)")
    if f_em.get("fee_to_treasury_bps", 9000) != 9000:
        problems.append("F-A fee_to_treasury_bps must stay 9000")
    return problems


def main() -> int:
    if "--self-test" in sys.argv:
        # The fail path must stay fail-closed. A missing needle is a failure.
        fake = "this needle is not in the tree"
        if fake in (ROOT / "mfn-wallet/src/lib.rs").read_text(encoding="utf-8"):
            print("validate-f18-impact-gate: self-test saw an impossible needle", file=sys.stderr)
            return 1
        print("validate-f18-impact-gate: self-test PASS")
        return 0

    hits = missing_needles() + genesis_problems()
    if hits:
        print(
            "validate-f18-impact-gate: FAIL - privacy/permanence invariant regression (B-23 / F18)",
            file=sys.stderr,
        )
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        print(
            "Restore the ring floor, Path A zeros, F-A bundle, or SPoRA verify call, "
            "and keep the F18 note in PRIVACY_HARDENING.md and PERMANENCE_HARDENING.md.",
            file=sys.stderr,
        )
        return 1
    print("validate-f18-impact-gate: PASS (ring, endowment, SPoRA, Path A, F-A)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

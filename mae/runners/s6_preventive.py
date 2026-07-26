#!/usr/bin/env python3
"""S6-preventivo: exige DENY antes da escrita, não só detecção pós-fato."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from deny_delete import load_raw_lines, parse_row, propose_mutation  # noqa: E402


def run_s6_preventive(ledger: Path) -> dict:
    existing = load_raw_lines(ledger)
    drop_idx = None
    for i in range(len(existing) - 1, -1, -1):
        row = parse_row(existing[i])
        if row and row.get("event") == "FINAL":
            drop_idx = i
            break
    if drop_idx is None:
        return {
            "id": "S6P",
            "pass": False,
            "reason": "NO_FINAL_IN_LEDGER",
            "xp_delta": 0,
        }
    proposed = existing[:drop_idx] + existing[drop_idx + 1 :]
    d = propose_mutation(existing, proposed)
    passed = d.denied and d.code in {"DENY_DELETE", "DENY_REWRITE"}
    return {
        "id": "S6P",
        "pass": passed,
        "code": d.code,
        "message": d.message,
        "xp_delta": 0,
        "missing_count": d.detail.get("missing_count"),
        "note": "preventivo: mutação negada ANTES de gravar",
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", type=Path, required=True)
    args = ap.parse_args()
    if not args.ledger.exists():
        print("MAE_TARGET_LEDGER_MISSING", file=sys.stderr)
        return 2
    result = run_s6_preventive(args.ledger)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

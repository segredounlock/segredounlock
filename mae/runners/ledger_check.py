#!/usr/bin/env python3
"""MAE ledger_check — zero LLM. Paridade + rehash + dangling refs."""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
from typing import Any

def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def load_ledger(path: Path) -> list[dict]:
    rows = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise SystemExit(f"LEDGER_PARSE_FAIL line={i}: {e}") from e
    return rows

def payload_for_hash(row: dict) -> dict:
    return {k: v for k, v in row.items() if k != "record_hash"}

def payload_for_current_hash(row: dict) -> dict:
    volatile = {"started_at_utc", "finished_at_utc", "attested_at_utc", "record_hash"}
    return {k: v for k, v in row.items() if k not in volatile}

def valid_direct_hashes(row: dict) -> set[str]:
    return {
        sha256_hex(canonical_bytes(payload_for_hash(row))),
        sha256_hex(canonical_bytes(payload_for_current_hash(row))),
    }

def check(rows: list[dict]) -> dict:
    begins: dict[str, int] = {}
    finals: dict[str, int] = {}
    bad_hash = 0
    hash_details = []
    by_usage_id = {r.get("usage_id"): r for r in rows if r.get("usage_id")}
    attestations: set[tuple[str, str]] = set()
    orphan_resolvers: set[tuple[str, str]] = set()
    for row in rows:
        if row.get("event") != "ATTESTATION":
            continue
        if row.get("record_hash") not in valid_direct_hashes(row):
            continue
        target_usage_id = row.get("target_usage_id")
        target_record_hash = row.get("target_record_hash")
        target = by_usage_id.get(target_usage_id)
        if target is None or target.get("record_hash") != target_record_hash:
            continue
        key = (target_usage_id, target_record_hash)
        attestations.add(key)
        if row.get("resolve_orphan") is True:
            orphan_resolvers.add(key)
    for idx, row in enumerate(rows):
        ev = row.get("event")
        uid = row.get("usage_id") or row.get("usageId") or f"__anon_{idx}"
        if ev == "BEGIN":
            begins[uid] = begins.get(uid, 0) + 1
        elif ev == "FINAL":
            finals[uid] = finals.get(uid, 0) + 1
        rh = row.get("record_hash")
        if rh:
            directly_valid = rh in valid_direct_hashes(row)
            attested = (uid, rh) in attestations
            if not directly_valid and not attested:
                bad_hash += 1
                hash_details.append(f"idx={idx} usage_id={uid}")
    orphan_begin = 0
    orphan_final = 0
    for uid, c in begins.items():
        fc = finals.get(uid, 0)
        if fc == 0:
            orphan_begin += c
        elif fc != c:
            orphan_begin += max(0, c - fc)
            orphan_final += max(0, fc - c)
    for uid, c in finals.items():
        if begins.get(uid, 0) == 0:
            resolved = any(
                target_usage_id == uid
                for target_usage_id, _target_record_hash in orphan_resolvers
            )
            if not resolved:
                orphan_final += c
    known = {r.get("record_hash") for r in rows if r.get("record_hash")}
    dangling_refs = 0
    for r in rows:
        ref = r.get("target_record_hash") or r.get("candidate_ref")
        if ref and ref not in known:
            dangling_refs += 1
    return {
        "total": len(rows),
        "begin": sum(begins.values()),
        "final": sum(finals.values()),
        "orphan_begin": orphan_begin,
        "orphan_final": orphan_final,
        "bad_hash": bad_hash,
        "dangling_refs": dangling_refs,
        "hash_details": hash_details[:20],
        "ok": (
            orphan_begin == 0
            and orphan_final == 0
            and bad_hash == 0
            and dangling_refs == 0
        ),
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not args.ledger.exists():
        print(f"LEDGER_MISSING {args.ledger}", file=sys.stderr)
        return 2
    result = check(load_ledger(args.ledger))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            f"TOTAL={result['total']} BEGIN={result['begin']} FINAL={result['final']} "
            f"ORPHAN_BEGIN={result['orphan_begin']} ORPHAN_FINAL={result['orphan_final']} "
            f"BAD_HASH={result['bad_hash']} DANGLING_REFS={result['dangling_refs']} "
            f"OK={int(result['ok'])}"
        )
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    sys.exit(main())

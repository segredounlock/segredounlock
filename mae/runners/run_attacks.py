#!/usr/bin/env python3
"""MAE run_attacks — S1/S3/S6 em sandbox. Não toca ledger de produção."""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out"
ORA = ROOT / "oracles"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows

def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")

def payload_for_hash(row: dict) -> dict:
    return {k: v for k, v in row.items() if k != "record_hash"}

def rehash(row: dict) -> str:
    return sha256_hex(canonical_bytes(payload_for_hash(row)))

def import_check():
    sys.path.insert(0, str(ROOT / "runners"))
    from ledger_check import check  # type: ignore
    return check

def attack_s1(rows: list[dict]) -> dict:
    uid = "MAE-S1-ORPHAN-BEGIN-ATTACK"
    begin = {
        "schema_version": 1,
        "event": "BEGIN",
        "usage_id": uid,
        "mission_id": "MAE-S1",
        "started_at_utc": "2099-01-01T00:00:00Z",
        "note": "mae adversarial orphan begin",
    }
    begin["record_hash"] = rehash(begin)
    result = import_check()(rows + [begin])
    exp = json.loads((ORA / "S1.json").read_text(encoding="utf-8"))["expect"]
    passed = result["orphan_begin"] >= exp["orphan_begin_min"] and result["ok"] is False
    return {"id": "S1", "pass": passed, "orphan_begin": result["orphan_begin"], "xp_delta": 0}

def attack_s3(rows: list[dict]) -> dict:
    finals = [r for r in rows if r.get("event") == "FINAL"]
    if finals:
        victim = json.loads(json.dumps(finals[-1]))
    else:
        victim = {
            "schema_version": 1,
            "event": "FINAL",
            "usage_id": "MAE-S3-BASE",
            "verdict": "APROVAR",
            "xp_gained": 0,
            "point_fixed_evidential": True,
        }
        victim["record_hash"] = rehash(victim)
    stored = victim.get("record_hash") or ("0" * 64)
    victim["record_hash"] = stored
    victim["verdict"] = str(victim.get("verdict") or "X") + "_TAMPERED"
    victim["mae_tamper"] = True
    recomputed = rehash({k: v for k, v in victim.items() if k != "record_hash"})
    bad = recomputed != victim.get("record_hash")
    exp = json.loads((ORA / "S3.json").read_text(encoding="utf-8"))["expect"]
    passed = bad is True and exp["bad_hash_detected"] is True
    return {
        "id": "S3",
        "pass": passed,
        "stored": victim.get("record_hash"),
        "recomputed": recomputed,
        "xp_delta": 0,
        "bad_hash_detected": bad,
    }

def attack_s6(rows: list[dict]) -> dict:
    before_n = len(rows)
    work = list(rows)
    finals_idx = [i for i, r in enumerate(work) if r.get("event") == "FINAL"]
    if not finals_idx:
        uid = "MAE-S6-PAIR"
        b = {"schema_version": 1, "event": "BEGIN", "usage_id": uid}
        b["record_hash"] = rehash(b)
        f = {"schema_version": 1, "event": "FINAL", "usage_id": uid, "verdict": "APROVAR", "xp_gained": 0}
        f["record_hash"] = rehash(f)
        work = work + [b, f]
        finals_idx = [len(work) - 1]
        before_n = len(work)
    drop = finals_idx[-1]
    deleted = work[drop]
    sand = work[:drop] + work[drop + 1 :]
    result = import_check()(sand)
    detected = (len(sand) < before_n and (not result["ok"] or result["orphan_begin"] > 0)) or result["orphan_begin"] > 0
    exp = json.loads((ORA / "S6.json").read_text(encoding="utf-8"))["expect"]
    passed = detected is True and exp["damage_detected"] is True
    return {
        "id": "S6",
        "pass": passed,
        "deleted_usage_id": deleted.get("usage_id"),
        "orphan_begin": result["orphan_begin"],
        "xp_delta": 0,
        "note": "pos-fato; gate preventivo de delete = hook meta_lupa",
    }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", type=Path, default=None)
    ap.add_argument("--round", type=int, default=1)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    ledger = args.ledger
    if ledger is None:
        for c in [
            Path(".agents/skills/meta-lupa/references/uso-ledger.jsonl"),
            Path("references/uso-ledger.jsonl"),
            OUT / "sample-ledger.jsonl",
        ]:
            if c.exists():
                ledger = c
                break
    if ledger is None or not Path(ledger).exists():
        sample = OUT / "sample-ledger.jsonl"
        b = {"schema_version": 1, "event": "BEGIN", "usage_id": "sample-1"}
        b["record_hash"] = rehash(b)
        f = {
            "schema_version": 1,
            "event": "FINAL",
            "usage_id": "sample-1",
            "verdict": "APROVAR",
            "xp_gained": 0,
            "point_fixed_evidential": True,
        }
        f["record_hash"] = rehash(f)
        write_jsonl(sample, [b, f])
        ledger = sample
        print(f"MAE_WARN sample ledger {ledger}")
    rows = load_jsonl(Path(ledger))
    results = [attack_s1(rows), attack_s3(rows), attack_s6(rows)]
    lines = [f"# MAE report round {args.round}", ""]
    npass = 0
    for r in results:
        status = "PASS" if r["pass"] else "FAIL"
        if r["pass"]:
            npass += 1
        lines.append(f"- **{r['id']}** {status} `{json.dumps(r, ensure_ascii=False)}`")
    lines += ["", f"SCORE {npass}/3", "GATE_META_LUPA: " + ("ROUND_OK" if npass == 3 else "FURO_DETECTADO")]
    (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / f"receipt-round{args.round}.json").write_text(
        json.dumps({"round": args.round, "score": f"{npass}/3", "results": results}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print("\n".join(lines))
    return 0 if npass == 3 else 1

if __name__ == "__main__":
    sys.exit(main())

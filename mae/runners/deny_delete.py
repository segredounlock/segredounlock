#!/usr/bin/env python3
"""deny_delete — hook preventivo append-only para uso-ledger.jsonl.

Linhas gravadas nao podem sumir, mudar ou reordenar. So APPEND.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


class LedgerMutationDenied(Exception):
    def __init__(self, code: str, message: str, detail: dict | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.detail = detail or {}


@dataclass
class MutationDecision:
    allowed: bool
    code: str
    message: str
    detail: dict = field(default_factory=dict)

    @property
    def denied(self) -> bool:
        return not self.allowed


PROTECTED_EVENTS = frozenset({"BEGIN", "FINAL", "ATTESTATION"})


def line_fingerprint(raw_line: str) -> str:
    return hashlib.sha256(raw_line.encode("utf-8")).hexdigest()


def load_raw_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() != ""]


def parse_row(raw: str) -> dict | None:
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def is_protected_row(row: dict | None) -> bool:
    if not row:
        return True
    if row.get("event") in PROTECTED_EVENTS:
        return True
    return bool(row.get("record_hash"))


def propose_mutation(existing_raw: list[str], proposed_raw: list[str]) -> MutationDecision:
    n_old, n_new = len(existing_raw), len(proposed_raw)
    if n_new < n_old:
        missing = existing_raw[n_new:]
        protected = []
        for raw in missing:
            row = parse_row(raw)
            protected.append({
                "fingerprint": line_fingerprint(raw),
                "event": (row or {}).get("event"),
                "usage_id": (row or {}).get("usage_id"),
                "record_hash": (row or {}).get("record_hash"),
            })
        return MutationDecision(
            False,
            "DENY_DELETE",
            f"proposed has {n_new} lines; existing has {n_old} — would delete history",
            {"missing_count": n_old - n_new, "missing": protected[:20]},
        )
    for i in range(n_old):
        if existing_raw[i] != proposed_raw[i]:
            row = parse_row(existing_raw[i])
            return MutationDecision(
                False,
                "DENY_REWRITE",
                f"line {i} content changed — history is immutable",
                {
                    "index": i,
                    "event": (row or {}).get("event"),
                    "usage_id": (row or {}).get("usage_id"),
                    "record_hash": (row or {}).get("record_hash"),
                    "old_fp": line_fingerprint(existing_raw[i]),
                    "new_fp": line_fingerprint(proposed_raw[i]),
                },
            )
    appended = n_new - n_old
    return MutationDecision(
        True,
        "ALLOW_APPEND" if appended else "ALLOW_NOOP",
        f"append {appended} line(s)" if appended else "no change",
        {"appended": appended, "total": n_new},
    )


def propose_rows_mutation(existing_raw: list[str], proposed_rows: list[dict]) -> MutationDecision:
    proposed_raw = [json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in proposed_rows]
    return propose_mutation(existing_raw, proposed_raw)


def enforce(decision: MutationDecision) -> None:
    if decision.denied:
        raise LedgerMutationDenied(decision.code, decision.message, decision.detail)


def append_rows(path: Path, new_rows: Iterable[dict], *, encoding: str = "utf-8") -> MutationDecision:
    path = Path(path)
    existing_raw = load_raw_lines(path)
    additions = list(new_rows)
    if not additions:
        return MutationDecision(True, "ALLOW_NOOP", "no rows to append", {})
    proposed_raw = existing_raw + [json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in additions]
    decision = propose_mutation(existing_raw, proposed_raw)
    enforce(decision)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding=encoding, newline="\n") as f:
        for r in additions:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return decision


def replace_ledger_atomic(path: Path, proposed_raw: list[str], *, encoding: str = "utf-8") -> MutationDecision:
    path = Path(path)
    existing_raw = load_raw_lines(path)
    decision = propose_mutation(existing_raw, proposed_raw)
    enforce(decision)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = "\n".join(proposed_raw) + ("\n" if proposed_raw else "")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".ledger-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return decision


def guard_write(path: Path, proposed_text: str) -> MutationDecision:
    existing_raw = load_raw_lines(path)
    proposed_raw = [ln for ln in proposed_text.splitlines() if ln.strip() != ""]
    decision = propose_mutation(existing_raw, proposed_raw)
    enforce(decision)
    return decision


def main() -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="deny-delete ledger guard")
    ap.add_argument("--ledger", type=Path, required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check-proposed")
    p_check.add_argument("--proposed", type=Path, required=True)

    p_append = sub.add_parser("append-json")
    p_append.add_argument("--row", type=str, default=None)

    sub.add_parser("simulate-delete-last-final")

    args = ap.parse_args()
    ledger: Path = args.ledger

    if args.cmd == "check-proposed":
        d = propose_mutation(load_raw_lines(ledger), load_raw_lines(args.proposed))
        print(json.dumps({"allowed": d.allowed, "code": d.code, "message": d.message, "detail": d.detail}, ensure_ascii=False))
        return 0 if d.allowed else 1

    if args.cmd == "append-json":
        raw = args.row if args.row is not None else sys.stdin.read()
        try:
            d = append_rows(ledger, [json.loads(raw)])
        except LedgerMutationDenied as e:
            print(json.dumps({"allowed": False, "code": e.code, "message": e.message, "detail": e.detail}, ensure_ascii=False))
            return 1
        print(json.dumps({"allowed": True, "code": d.code, "message": d.message, "detail": d.detail}, ensure_ascii=False))
        return 0

    if args.cmd == "simulate-delete-last-final":
        existing = load_raw_lines(ledger)
        drop_idx = None
        for i in range(len(existing) - 1, -1, -1):
            row = parse_row(existing[i])
            if row and row.get("event") == "FINAL":
                drop_idx = i
                break
        if drop_idx is None:
            print(json.dumps({"allowed": True, "code": "NO_FINAL", "message": "no FINAL to delete"}, ensure_ascii=False))
            return 2
        proposed = existing[:drop_idx] + existing[drop_idx + 1 :]
        d = propose_mutation(existing, proposed)
        print(json.dumps({
            "allowed": d.allowed,
            "code": d.code,
            "message": d.message,
            "detail": d.detail,
            "expect_denied": True,
            "pass": d.denied and d.code in {"DENY_DELETE", "DENY_REWRITE"},
        }, ensure_ascii=False))
        return 0 if (d.denied and d.code in {"DENY_DELETE", "DENY_REWRITE"}) else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""deny_delete — hook preventivo append-only para uso-ledger.jsonl.

Linhas gravadas nao podem sumir, mudar ou reordenar. So APPEND.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
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
VOLATILE_HASH_FIELDS = frozenset(
    {"started_at_utc", "finished_at_utc", "attested_at_utc", "record_hash"}
)
DENIED_EXIT = 13


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


def canonical_record_hash(row: dict) -> str:
    payload = {key: value for key, value in row.items() if key not in VOLATILE_HASH_FIELDS}
    encoded = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def legacy_record_hash(row: dict) -> str:
    payload = {key: value for key, value in row.items() if key != "record_hash"}
    encoded = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_appended_rows(existing_raw: list[str], appended_raw: list[str]) -> MutationDecision:
    existing_rows = [parse_row(raw) for raw in existing_raw]
    if any(row is None for row in existing_rows):
        return MutationDecision(False, "DENY_INVALID_EXISTING", "existing ledger is not valid JSONL")

    known_rows = [row for row in existing_rows if row is not None]
    from ledger_check import check

    integrity = check(known_rows)
    existing_has_only_transient_begin = (
        integrity.get("orphan_begin", 0) > 0
        and integrity.get("orphan_final", 0) == 0
        and integrity.get("bad_hash", 0) == 0
        and integrity.get("dangling_refs", 0) == 0
    )
    if not integrity.get("ok") and not existing_has_only_transient_begin:
        return MutationDecision(
            False,
            "DENY_INVALID_EXISTING",
            "existing ledger failed integrity validation",
            {
                "orphan_begin": integrity.get("orphan_begin"),
                "orphan_final": integrity.get("orphan_final"),
                "bad_hash": integrity.get("bad_hash"),
                "dangling_refs": integrity.get("dangling_refs"),
            },
        )
    known_usage_ids = {row.get("usage_id") for row in known_rows if row.get("usage_id")}
    known_final_ids = {
        row.get("usage_id")
        for row in known_rows
        if row.get("event") == "FINAL" and row.get("usage_id")
    }
    known_records = {
        (row.get("usage_id"), row.get("record_hash"))
        for row in known_rows
        if row.get("usage_id") and row.get("record_hash")
    }

    for offset, raw in enumerate(appended_raw):
        row = parse_row(raw)
        if row is None:
            return MutationDecision(
                False, "DENY_INVALID_APPEND", "appended line is not a JSON object", {"offset": offset}
            )
        event = row.get("event")
        if event not in PROTECTED_EVENTS:
            return MutationDecision(
                False, "DENY_INVALID_EVENT", "unsupported ledger event", {"offset": offset, "event": event}
            )
        stored_hash = row.get("record_hash")
        if not stored_hash or stored_hash != canonical_record_hash(row):
            return MutationDecision(
                False, "DENY_BAD_RECORD_HASH", "appended row has invalid record_hash", {"offset": offset}
            )

        if event == "BEGIN":
            usage_id = row.get("usage_id")
            if not usage_id or usage_id in known_usage_ids:
                return MutationDecision(
                    False, "DENY_DUPLICATE_BEGIN", "BEGIN usage_id is absent or duplicated", {"offset": offset}
                )
            known_usage_ids.add(usage_id)
            known_records.add((usage_id, stored_hash))
        elif event == "FINAL":
            usage_id = row.get("usage_id")
            if not usage_id or usage_id in known_final_ids:
                return MutationDecision(
                    False,
                    "DENY_DUPLICATE_FINAL",
                    "FINAL usage_id is absent or duplicated",
                    {"offset": offset},
                )
            has_begin = any(
                candidate.get("event") == "BEGIN" and candidate.get("usage_id") == usage_id
                for candidate in known_rows
            )
            if not has_begin:
                return MutationDecision(
                    False, "DENY_FINAL_WITHOUT_BEGIN", "FINAL has no preceding BEGIN", {"offset": offset}
                )
            known_final_ids.add(usage_id)
            known_records.add((usage_id, stored_hash))
        else:
            target = (row.get("target_usage_id"), row.get("target_record_hash"))
            if target not in known_records:
                return MutationDecision(
                    False,
                    "DENY_DANGLING_ATTESTATION",
                    "ATTESTATION target does not exist exactly",
                    {"offset": offset},
                )
        known_rows.append(row)

    proposed_integrity = check(known_rows)
    final_event = known_rows[-1].get("event") if known_rows else None
    proposed_is_transient_begin = (
        final_event == "BEGIN"
        and proposed_integrity.get("orphan_begin", 0) == 1
        and proposed_integrity.get("orphan_final", 0) == 0
        and proposed_integrity.get("bad_hash", 0) == 0
        and proposed_integrity.get("dangling_refs", 0) == 0
    )
    if not proposed_integrity.get("ok") and not proposed_is_transient_begin:
        return MutationDecision(
            False,
            "DENY_INVALID_RESULT",
            "proposed append does not preserve BEGIN/FINAL/hash/reference invariants",
            {
                "orphan_begin": proposed_integrity.get("orphan_begin"),
                "orphan_final": proposed_integrity.get("orphan_final"),
                "bad_hash": proposed_integrity.get("bad_hash"),
                "dangling_refs": proposed_integrity.get("dangling_refs"),
            },
        )

    return MutationDecision(
        True,
        "ALLOW_VALID_APPEND",
        f"validated {len(appended_raw)} appended line(s)",
        {"appended": len(appended_raw)},
    )


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
    if appended:
        validation = validate_appended_rows(existing_raw, proposed_raw[n_old:])
        if validation.denied:
            return validation
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
    return replace_ledger_atomic(path, proposed_raw, encoding=encoding)


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


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def guarded_destructive_operation(
    path: Path,
    operation: str,
    *,
    replacement: Path | None = None,
    overwrite_index: int = 0,
) -> MutationDecision:
    """Fail closed before any destructive filesystem call.

    All supported destructive requests are converted to their proposed final
    ledger state, checked against the immutable prefix, and only then would the
    mutation execute. A denied decision raises before unlink/truncate/replace.
    """
    path = Path(path)
    existing = load_raw_lines(path)
    if not path.exists():
        raise LedgerMutationDenied("DENY_LEDGER_MISSING", "canonical ledger is missing")

    if operation in {"delete", "truncate"}:
        proposed: list[str] = []
    elif operation == "overwrite":
        proposed = list(existing)
        if not proposed:
            raise LedgerMutationDenied("DENY_EMPTY_LEDGER", "nothing exists to overwrite")
        index = min(max(overwrite_index, 0), len(proposed) - 1)
        row = parse_row(proposed[index]) or {"raw": proposed[index]}
        row["mae_overwrite"] = True
        proposed[index] = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
    elif operation == "rename-replacement":
        if replacement is None or not Path(replacement).exists():
            raise LedgerMutationDenied("DENY_REPLACEMENT_MISSING", "replacement file is missing")
        raise LedgerMutationDenied(
            "DENY_RENAME_REPLACEMENT",
            "ledger replacement by rename is forbidden; use validated atomic append",
        )
    elif operation == "delete-attested":
        index = next(
            (
                idx
                for idx, raw in enumerate(existing)
                if (parse_row(raw) or {}).get("event") == "ATTESTATION"
            ),
            None,
        )
        if index is None:
            raise LedgerMutationDenied("DENY_NO_ATTESTATION", "ledger has no attested receipt")
        row = parse_row(existing[index]) or {}
        raise LedgerMutationDenied(
            "DENY_ATTESTED_DELETE",
            "attested receipt is immutable",
            {
                "index": index,
                "event": row.get("event"),
                "target_usage_id": row.get("target_usage_id"),
                "target_record_hash": row.get("target_record_hash"),
            },
        )
    else:
        raise LedgerMutationDenied("DENY_UNKNOWN_OPERATION", f"unknown operation: {operation}")

    decision = propose_mutation(existing, proposed)
    enforce(decision)

    # These calls are intentionally unreachable for every destructive request
    # above. Keeping them here proves the guard is immediately before mutation.
    if operation == "delete":
        path.unlink()
    elif operation == "truncate":
        path.write_bytes(b"")
    elif operation == "overwrite":
        replace_ledger_atomic(path, proposed)
    return decision


def _ledger_integrity(path: Path) -> dict:
    from ledger_check import check

    rows = [parse_row(raw) for raw in load_raw_lines(path)]
    if any(row is None for row in rows):
        return {"ok": False, "bad_hash": 1, "reason": "INVALID_JSONL"}
    return check([row for row in rows if row is not None])


def _xp_state(path: Path) -> int:
    finals = [
        row
        for row in (parse_row(raw) for raw in load_raw_lines(path))
        if row and row.get("event") == "FINAL"
    ]
    if not finals:
        return 0
    return int(finals[-1].get("xp_after") or 0)


def run_direct_attacks(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise LedgerMutationDenied("DENY_LEDGER_MISSING", "canonical ledger is missing")

    attacks = [
        ("S4_DELETE_DIRECT", "delete"),
        ("S5_TRUNCATE_DIRECT", "truncate"),
        ("S6_ATTESTED_RECEIPT_DELETE", "delete-attested"),
        ("S7_OVERWRITE_EXISTING", "overwrite"),
        ("S8_RENAME_REPLACEMENT", "rename-replacement"),
    ]
    initial_sha = sha256_file(path)
    xp_before = _xp_state(path)
    results = []

    with tempfile.TemporaryDirectory(prefix="mae-writer-") as td:
        replacement = Path(td) / "replacement.jsonl"
        existing = load_raw_lines(path)
        replacement.write_text(
            "\n".join(existing[:-1]) + ("\n" if existing[:-1] else ""),
            encoding="utf-8",
        )

        for attack_id, operation in attacks:
            before = sha256_file(path)
            denied_code = None
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--ledger",
                str(path.resolve()),
                "attack",
                "--operation",
                operation,
            ]
            if operation == "rename-replacement":
                command.extend(["--replacement", str(replacement.resolve())])
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            exit_code = completed.returncode
            try:
                raw_child_result = json.loads(completed.stdout)
                denied_code = raw_child_result.get("code")
                detail = raw_child_result.get("detail") or {}
                child_result = {
                    "blocked": raw_child_result.get("blocked"),
                    "code": denied_code,
                    "event": detail.get("event"),
                    "index": detail.get("index"),
                }
            except json.JSONDecodeError:
                child_result = {"stdout": completed.stdout, "stderr": completed.stderr}
            after = sha256_file(path)
            integrity = _ledger_integrity(path)
            passed = (
                exit_code == DENIED_EXIT
                and denied_code is not None
                and before == after
                and integrity.get("ok") is True
            )
            results.append(
                {
                    "id": attack_id,
                    "pass": passed,
                    "blocked": denied_code is not None,
                    "deny_code": denied_code,
                    "exit_code": exit_code,
                    "child_result": child_result,
                    "before_sha256": before,
                    "after_sha256": after,
                    "sha256_unchanged": before == after,
                    "ledger_ok": integrity.get("ok") is True,
                    "orphan_begin": integrity.get("orphan_begin"),
                    "orphan_final": integrity.get("orphan_final"),
                    "bad_hash": integrity.get("bad_hash"),
                    "dangling_refs": integrity.get("dangling_refs"),
                }
            )

    final_sha = sha256_file(path)
    xp_after = _xp_state(path)
    all_pass = all(result["pass"] for result in results)
    guard_pass = all_pass and initial_sha == final_sha and xp_before == xp_after
    return {
        "writer_guard_implemented": True,
        "meta_lupa_writer_wired": False,
        "writer_scope": "mae/runners/deny_delete.py; meta_lupa.py remains external to PR #1",
        "prevented_before_mutation": all_pass,
        "ledger_sha256_before": initial_sha,
        "ledger_sha256_after": final_sha,
        "ledger_sha256_unchanged": initial_sha == final_sha,
        "xp_before": xp_before,
        "xp_after": xp_after,
        "xp_delta": xp_after - xp_before,
        "attacks_detected": f"{sum(result['pass'] for result in results)}/{len(results)}",
        "results": results,
        "guard_pass": guard_pass,
        "round2_complete": False,
        "verdict": "PASS_GUARD_ISOLADO; WRITER_REAL_PENDENTE",
    }


def write_round_2_artifacts(proof: dict) -> None:
    root = Path(__file__).resolve().parents[1]
    out = root / "out"
    out.mkdir(parents=True, exist_ok=True)
    proof_path = out / "writer-deny-delete-proof.json"
    proof_path.write_text(
        json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    receipt = {
        "round": 2,
        "kind": "writer-preventive",
        "score": proof["attacks_detected"],
        "xp_delta": proof["xp_delta"],
        "ledger_sha256_unchanged": proof["ledger_sha256_unchanged"],
        "guard_pass": proof["guard_pass"],
        "round2_complete": proof["round2_complete"],
        "meta_lupa_writer_wired": proof["meta_lupa_writer_wired"],
        "writer_scope": proof["writer_scope"],
        "verdict": proof["verdict"],
        "results": proof["results"],
    }
    (out / "receipt-round-2.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# MAE Round 2 — bloqueio preventivo no writer",
        "",
        f"- WRITER_GUARD_IMPLEMENTED: {'SIM' if proof['writer_guard_implemented'] else 'NAO'}",
        f"- META_LUPA_WRITER_WIRED: {'SIM' if proof['meta_lupa_writer_wired'] else 'NAO'}",
        f"- WRITER_SCOPE: {proof['writer_scope']}",
        f"- PREVENTED_BEFORE_MUTATION: {'SIM' if proof['prevented_before_mutation'] else 'NAO'}",
        f"- LEDGER_SHA256_UNCHANGED: {'SIM' if proof['ledger_sha256_unchanged'] else 'NAO'}",
        f"- ATTACKS_DETECTED: {proof['attacks_detected']}",
        f"- XP_DELTA: {proof['xp_delta']}",
        "",
    ]
    for result in proof["results"]:
        lines.append(
            f"- **{result['id']}** {'PASS' if result['pass'] else 'FAIL'} "
            f"(exit={result['exit_code']}, deny={result['deny_code']}, "
            f"sha_unchanged={result['sha256_unchanged']})"
        )
    lines.extend(["", "ROUND_2_COMPLETE: NAO", "ROUND_2_VERDICT: " + proof["verdict"], ""])
    report = "\n".join(lines)
    (out / "report-round-2.md").write_text(report, encoding="utf-8")
    (out / "report.md").write_text(report, encoding="utf-8")


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="deny-delete ledger guard")
    ap.add_argument(
        "--ledger",
        type=Path,
        default=Path(".agents/skills/meta-lupa/references/uso-ledger.jsonl"),
    )
    sub = ap.add_subparsers(dest="cmd", required=False)

    p_check = sub.add_parser("check-proposed")
    p_check.add_argument("--proposed", type=Path, required=True)

    p_append = sub.add_parser("append-json")
    p_append.add_argument("--row", type=str, default=None)

    sub.add_parser("simulate-delete-last-final")

    p_attack = sub.add_parser("attack")
    p_attack.add_argument(
        "--operation",
        required=True,
        choices=["delete", "truncate", "delete-attested", "overwrite", "rename-replacement"],
    )
    p_attack.add_argument("--replacement", type=Path, default=None)

    args = ap.parse_args()
    ledger: Path = args.ledger

    if args.cmd is None:
        try:
            proof = run_direct_attacks(ledger)
        except LedgerMutationDenied as error:
            print(
                json.dumps(
                    {"pass": False, "code": error.code, "message": error.message},
                    ensure_ascii=False,
                )
            )
            return 2
        write_round_2_artifacts(proof)
        print(json.dumps(proof, ensure_ascii=False, indent=2))
        return 0 if proof["guard_pass"] else 1

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

    if args.cmd == "attack":
        try:
            guarded_destructive_operation(
                ledger,
                args.operation,
                replacement=args.replacement,
            )
        except LedgerMutationDenied as error:
            print(
                json.dumps(
                    {
                        "blocked": True,
                        "code": error.code,
                        "message": error.message,
                        "detail": error.detail,
                    },
                    ensure_ascii=False,
                )
            )
            return DENIED_EXIT
        print(json.dumps({"blocked": False, "code": "UNEXPECTED_MUTATION_ALLOWED"}))
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

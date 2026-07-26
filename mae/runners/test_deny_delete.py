"""Tests for deny_delete hook — zero LLM."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from deny_delete import (
    LedgerMutationDenied,
    append_rows,
    guard_write,
    load_raw_lines,
    propose_mutation,
    replace_ledger_atomic,
)


def _row(event: str, usage_id: str, **extra) -> dict:
    r = {"schema_version": 1, "event": event, "usage_id": usage_id, **extra}
    r["record_hash"] = "a" * 64 if event != "NOISE" else None
    if r["record_hash"] is None:
        del r["record_hash"]
    return r


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in rows),
        encoding="utf-8",
    )


def test_append_allowed(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1", verdict="APROVAR")])
    d = append_rows(ledger, [_row("BEGIN", "u2")])
    assert d.allowed
    assert d.code == "ALLOW_APPEND"
    lines = load_raw_lines(ledger)
    assert len(lines) == 3


def test_delete_final_denied(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    rows = [_row("BEGIN", "u1"), _row("FINAL", "u1", verdict="APROVAR")]
    _write_jsonl(ledger, rows)
    existing = load_raw_lines(ledger)
    proposed = existing[:1]
    d = propose_mutation(existing, proposed)
    assert d.denied
    assert d.code == "DENY_DELETE"
    assert d.detail["missing_count"] == 1


def test_rewrite_line_denied(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1")])
    existing = load_raw_lines(ledger)
    proposed = list(existing)
    bad = json.loads(proposed[1])
    bad["verdict"] = "TAMPERED"
    proposed[1] = json.dumps(bad, ensure_ascii=False, separators=(",", ":"))
    d = propose_mutation(existing, proposed)
    assert d.denied
    assert d.code == "DENY_REWRITE"


def test_replace_atomic_denies_truncate(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1")])
    existing = load_raw_lines(ledger)
    with pytest.raises(LedgerMutationDenied) as ei:
        replace_ledger_atomic(ledger, existing[:1])
    assert ei.value.code == "DENY_DELETE"
    assert len(load_raw_lines(ledger)) == 2


def test_guard_write_deny(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1")])
    with pytest.raises(LedgerMutationDenied) as ei:
        guard_write(ledger, json.dumps(_row("BEGIN", "u1")) + "\n")
    assert ei.value.code == "DENY_DELETE"


def test_hermes_style_revert_blocked(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    rows = []
    for i in range(8):
        rows.append(_row("BEGIN", f"m{i}"))
        rows.append(_row("FINAL", f"m{i}", xp_gained=10))
    _write_jsonl(ledger, rows)
    existing = load_raw_lines(ledger)
    proposed = existing[:2]
    d = propose_mutation(existing, proposed)
    assert d.denied
    assert d.code == "DENY_DELETE"
    assert d.detail["missing_count"] == 14

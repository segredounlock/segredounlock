"""Tests for deny_delete hook — zero LLM."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from deny_delete import (
    LedgerMutationDenied,
    append_rows,
    canonical_record_hash,
    guarded_destructive_operation,
    guard_write,
    load_raw_lines,
    propose_mutation,
    replace_ledger_atomic,
    sha256_file,
)


def _row(event: str, usage_id: str, **extra) -> dict:
    r = {"schema_version": 1, "event": event, "usage_id": usage_id, **extra}
    if event != "NOISE":
        r["record_hash"] = canonical_record_hash(r)
    return r


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in rows),
        encoding="utf-8",
    )


def test_append_allowed_atomically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1", verdict="APROVAR")])
    real_replace = os.replace
    replacements: list[tuple[object, object]] = []

    def observed_replace(source, target):
        replacements.append((source, target))
        return real_replace(source, target)

    monkeypatch.setattr("deny_delete.os.replace", observed_replace)
    d = append_rows(ledger, [_row("BEGIN", "u2")])
    assert d.allowed
    assert d.code == "ALLOW_APPEND"
    assert len(replacements) == 1
    assert Path(replacements[0][1]) == ledger
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


def test_all_direct_attacks_fail_before_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    begin = _row("BEGIN", "u1")
    final = _row("FINAL", "u1", verdict="APROVAR")
    attestation = {
        "schema_version": 1,
        "event": "ATTESTATION",
        "target_usage_id": "u1",
        "target_record_hash": final["record_hash"],
    }
    attestation["record_hash"] = canonical_record_hash(attestation)
    _write_jsonl(ledger, [begin, final, attestation])
    replacement = tmp_path / "replacement.jsonl"
    _write_jsonl(replacement, [begin])

    destructive_calls: list[str] = []

    def forbidden(*_args, **_kwargs):
        destructive_calls.append("called")
        raise AssertionError("destructive primitive reached")

    monkeypatch.setattr(Path, "unlink", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    monkeypatch.setattr("deny_delete.os.replace", forbidden)

    before = sha256_file(ledger)
    cases = [
        ("delete", {}),
        ("truncate", {}),
        ("delete-attested", {}),
        ("overwrite", {}),
        ("rename-replacement", {"replacement": replacement}),
    ]
    for operation, kwargs in cases:
        with pytest.raises(LedgerMutationDenied):
            guarded_destructive_operation(ledger, operation, **kwargs)
        assert sha256_file(ledger) == before

    assert destructive_calls == []


def test_invalid_hash_append_denied_without_mutation(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1")])
    before = sha256_file(ledger)
    bad = _row("BEGIN", "u2")
    bad["record_hash"] = "0" * 64
    with pytest.raises(LedgerMutationDenied) as error:
        append_rows(ledger, [bad])
    assert error.value.code == "DENY_BAD_RECORD_HASH"
    assert sha256_file(ledger) == before


def test_final_without_begin_denied_without_mutation(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1")])
    before = sha256_file(ledger)
    with pytest.raises(LedgerMutationDenied) as error:
        append_rows(ledger, [_row("FINAL", "missing")])
    assert error.value.code == "DENY_FINAL_WITHOUT_BEGIN"
    assert sha256_file(ledger) == before


def test_dangling_attestation_denied_without_mutation(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1")])
    before = sha256_file(ledger)
    attestation = {
        "schema_version": 1,
        "event": "ATTESTATION",
        "target_usage_id": "missing",
        "target_record_hash": "f" * 64,
    }
    attestation["record_hash"] = canonical_record_hash(attestation)
    with pytest.raises(LedgerMutationDenied) as error:
        append_rows(ledger, [attestation])
    assert error.value.code == "DENY_DANGLING_ATTESTATION"
    assert sha256_file(ledger) == before


def test_identical_rename_replacement_is_denied(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    rows = [_row("BEGIN", "u1"), _row("FINAL", "u1")]
    _write_jsonl(ledger, rows)
    replacement = tmp_path / "replacement.jsonl"
    _write_jsonl(replacement, rows)
    before = sha256_file(ledger)
    with pytest.raises(LedgerMutationDenied) as error:
        guarded_destructive_operation(
            ledger, "rename-replacement", replacement=replacement
        )
    assert error.value.code == "DENY_RENAME_REPLACEMENT"
    assert sha256_file(ledger) == before


def test_duplicate_final_is_denied_without_mutation(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [_row("BEGIN", "u1"), _row("FINAL", "u1")])
    before = sha256_file(ledger)
    with pytest.raises(LedgerMutationDenied) as error:
        append_rows(ledger, [_row("FINAL", "u1")])
    assert error.value.code == "DENY_DUPLICATE_FINAL"
    assert sha256_file(ledger) == before


def test_corrupt_existing_ledger_blocks_append(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    corrupt = _row("BEGIN", "u1")
    corrupt["record_hash"] = "0" * 64
    _write_jsonl(ledger, [corrupt])
    before = sha256_file(ledger)
    with pytest.raises(LedgerMutationDenied) as error:
        append_rows(ledger, [_row("BEGIN", "u2")])
    assert error.value.code == "DENY_INVALID_EXISTING"
    assert sha256_file(ledger) == before


def test_begin_then_final_transient_flow_is_allowed(tmp_path: Path) -> None:
    ledger = tmp_path / "uso-ledger.jsonl"
    _write_jsonl(ledger, [])
    begin = _row("BEGIN", "u1")
    begin_decision = append_rows(ledger, [begin])
    assert begin_decision.allowed
    final = _row("FINAL", "u1")
    final_decision = append_rows(ledger, [final])
    assert final_decision.allowed
    assert [json.loads(raw)["event"] for raw in load_raw_lines(ledger)] == [
        "BEGIN",
        "FINAL",
    ]

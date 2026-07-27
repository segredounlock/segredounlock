from pathlib import Path

from run_attacks import resolve_ledger


def test_missing_canonical_ledger_fails_closed(tmp_path: Path) -> None:
    assert resolve_ledger(None, tmp_path) is None


def test_existing_canonical_ledger_is_selected(tmp_path: Path) -> None:
    ledger = tmp_path / ".agents/skills/meta-lupa/references/uso-ledger.jsonl"
    ledger.parent.mkdir(parents=True)
    ledger.write_text("", encoding="utf-8")

    assert resolve_ledger(None, tmp_path) == ledger

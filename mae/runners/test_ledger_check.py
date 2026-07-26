from ledger_check import check, sha256_hex, canonical_bytes


def current_hash(row: dict) -> str:
    volatile = {"started_at_utc", "finished_at_utc", "attested_at_utc", "record_hash"}
    payload = {key: value for key, value in row.items() if key not in volatile}
    return sha256_hex(canonical_bytes(payload))


def test_bad_hash_fails_gate() -> None:
    row = {"event": "BEGIN", "usage_id": "tampered", "record_hash": "0" * 64}

    result = check([row])

    assert result["bad_hash"] == 1
    assert result["ok"] is False


def test_current_hash_ignores_volatile_timestamp() -> None:
    begin = {"event": "BEGIN", "usage_id": "pair", "started_at_utc": "now"}
    begin["record_hash"] = current_hash(begin)
    final = {"event": "FINAL", "usage_id": "pair", "finished_at_utc": "later"}
    final["record_hash"] = current_hash(final)

    result = check([begin, final])

    assert result["bad_hash"] == 0
    assert result["ok"] is True


def test_valid_attestation_resolves_historical_orphan_final() -> None:
    final = {"event": "FINAL", "usage_id": "historical", "verdict": "APROVAR"}
    final["record_hash"] = "1" * 64
    attestation = {
        "event": "ATTESTATION",
        "target_usage_id": "historical",
        "target_record_hash": final["record_hash"],
        "resolve_orphan": True,
        "attested_at_utc": "later",
    }
    attestation["record_hash"] = current_hash(attestation)

    result = check([final, attestation])

    assert result["orphan_final"] == 0
    assert result["bad_hash"] == 0
    assert result["ok"] is True

# Correction verification

The original oracle files were not changed.

Minimal corrections:

- reject a missing canonical ledger instead of generating a sample;
- validate both current and legacy Meta Lupa record hashes;
- recognize exact, valid append-only attestations;
- include `BAD_HASH` in the deterministic `ok` gate.

Verification against the canonical ledger through a runtime junction to the
single skill source:

```text
REGRESSION_TESTS=5/5 PASS
LEDGER_CHECK_EXIT=0
TOTAL=44
BEGIN=20
FINAL=21
ORPHAN_BEGIN=0
ORPHAN_FINAL=0
BAD_HASH=0
DANGLING_REFS=0
ROUND_1=3/3 PASS
ROUND_2=3/3 PASS
ATTACKS_DETECTED=6/6
XP_BEFORE=575
XP_AFTER=575
XP_DELTA=0
LEDGER_SHA256_BEFORE=24A9B4CF6C5B6DB1EE3B742AAE0E9A4A8B329D6B990B273795AC11A857383035
LEDGER_SHA256_AFTER=24A9B4CF6C5B6DB1EE3B742AAE0E9A4A8B329D6B990B273795AC11A857383035
```

The runtime junction is not committed and does not duplicate the Meta Lupa
skill.

# MAE vs META LUPA — PR de disputa adversária

**Branch:** `mae/adversarial-s1-s3-s6`
**Alvo:** skill `meta-lupa` + `references/uso-ledger.jsonl`

## Regra do round

```
AGENTE_NAO_APROVA_AGENTE=SIM
GATE = exit_code + hash + paridade + oracle
LLM não fecha gate. Runner fecha.
```

Vitória META LUPA: **S1, S3, S6 = PASS em 2 rodadas**, `xp_delta=0`.
Vitória MAE: qualquer vazamento.

## Como rodar

```bash
python mae/runners/ledger_check.py --ledger .agents/skills/meta-lupa/references/uso-ledger.jsonl
python mae/runners/run_attacks.py --round 1
python mae/runners/run_attacks.py --round 2
cat mae/out/report.md
```

## Suites

| ID | Ataque | Expect |
|----|--------|--------|
| S1 | BEGIN sem FINAL | ORPHAN detectado, xp_delta=0 |
| S3 | Tamper payload, hash antigo | BAD_HASH |
| S6 | Delete FINAL atestado | damage detected |

## Smoke (sample ledger)

SCORE 3/3 ROUND_OK — ver `mae/out/report.md`

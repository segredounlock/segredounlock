## MAE adversarial — S1/S3/S6

Disputa determinística contra META LUPA.

### Run
```bash
python mae/runners/ledger_check.py --ledger .agents/skills/meta-lupa/references/uso-ledger.jsonl
python mae/runners/run_attacks.py --round 1
python mae/runners/run_attacks.py --round 2
cat mae/out/report.md
```

### Vitória
SCORE 3/3 × 2 rodadas. xp_delta=0. Zero LLM no gate.

AGENTE_NAO_APROVA_AGENTE=SIM

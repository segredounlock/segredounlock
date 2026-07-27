# First adversarial verdict

PR HEAD before the first run: `1b80d04655c4e0206014920f390f63ea5b54561a`.

The package was executed unchanged. The mandatory ledger check returned exit
code `2` with `LEDGER_MISSING`. Both attack rounds nevertheless returned exit
code `0` because `run_attacks.py` silently generated
`mae/out/sample-ledger.jsonl`.

Hermes profile `pivete`, with the canonical `meta-lupa` skill loaded, reviewed
the unchanged evidence and returned:

```text
VEREDITO=BLOQUEAR
FALSO_VERDE_BLOQUEADO=SIM
PONTO_FIXO_ATINGIDO=SIM
```

The first result was therefore preserved as a false green rather than counted
as a Meta Lupa victory. Its regression requires attack execution to fail
closed when the canonical ledger is absent.

Original package hashes:

```text
ledger_check.py=AB30F411542C281E25AA25A25149F20AE22E5794486027FAE0BFEF9DB93771AD
run_attacks.py=441E2B75B7F8FDA5AC836523C35FF7B606B17E4AAC6DA31EF0E96CCF9B3EEECA
S1.json=C54492776432A96FB7C4DA7687EFE8798861106434608FCB5FEA3AD0A38DD247
S3.json=37DC6FC9B2E29B5C33542B5932C9B922A34CEA2D0053D76A9535146475A43BB8
S6.json=6D3113C64B9B98C8F212C373A612D370B76CBEB4F79FA58590BEE22CC38FE282
fixtures/README.md=1EE71601B6676172072B454DD894B977F511177B6C1E5F9514D25E56DB5A5965
```

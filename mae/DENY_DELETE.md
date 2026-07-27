# deny-delete hook

## Contrato

```python
from deny_delete import append_rows, LedgerMutationDenied, guard_write, replace_ledger_atomic
```

- **Writer legítimo**: só `append_rows(path, [row, ...])`
- **Rewrite completo**: `replace_ledger_atomic` — nega se prefixo histórico mudar
- **Qualquer write texto**: passar por `guard_write` antes

## Integração meta_lupa.py

Onde hoje faz `path.write_text(full)` ou `open(path, "w")`:

```python
from deny_delete import append_rows, replace_ledger_atomic, LedgerMutationDenied

append_rows(ledger_path, [final_row])

try:
    replace_ledger_atomic(ledger_path, proposed_raw_lines)
except LedgerMutationDenied as e:
    raise  # nunca silenciar
```

## MAE

```bash
python mae/runners/deny_delete.py --ledger <uso-ledger.jsonl> simulate-delete-last-final
python mae/runners/s6_preventive.py --ledger <uso-ledger.jsonl>
python -m pytest mae/runners/test_deny_delete.py -q
```

Expect: `DENY_DELETE`, pass = negado antes de gravar.

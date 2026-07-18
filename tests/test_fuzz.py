"""Fuzz the guard: it must not pass by memorising the corpus. Dress every
denylisted function up thousands of ways and assert it is still refused."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from readonly_sql_guard import ReadOnlyViolation, assert_read_only
from readonly_sql_guard.guard import _DANGEROUS_FUNCS

_DIALECTS = ["postgres", "tsql", "mysql", "sqlite"]
_GAP = st.sampled_from(["", " ", "  ", "\t", "\n", " \t "])
_ARG = st.sampled_from(["", "1", "'/etc/passwd'", "42, 1", "'x'"])
_IDENT = st.from_regex(r"[a-z][a-z0-9_]{0,12}", fullmatch=True)


def _mixed_case(word, flips):
    if not flips:
        return word
    return "".join(c.upper() if flips[i % len(flips)] else c.lower()
                   for i, c in enumerate(word))


@settings(deadline=None, max_examples=200)
@given(fn=st.sampled_from(sorted(_DANGEROUS_FUNCS)), gap=_GAP, arg=_ARG,
       dialect=st.sampled_from(_DIALECTS), flips=st.lists(st.booleans(), max_size=40))
def test_dangerous_function_is_refused_however_dressed(fn, gap, arg, dialect, flips):
    sql = f"SELECT {_mixed_case(fn, flips)}{gap}({arg})"
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(sql, dialect=dialect)


@settings(deadline=None)
@given(template=st.sampled_from([
        "DROP TABLE {id}", "DELETE FROM {id}", "UPDATE {id} SET x=1",
        "INSERT INTO {id} VALUES (1)", "TRUNCATE TABLE {id}", "CREATE TABLE {id} (c int)"]),
       ident=_IDENT, dialect=st.sampled_from(_DIALECTS))
def test_writes_refused_for_any_identifier(template, ident, dialect):
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(template.format(id=ident), dialect=dialect)


@settings(deadline=None)
@given(col=_IDENT, tbl=_IDENT, upper=st.booleans(), dialect=st.sampled_from(_DIALECTS))
def test_plain_read_with_arbitrary_identifiers_is_allowed(col, tbl, upper, dialect):
    kw = ("SELECT", "FROM") if upper else ("select", "from")
    assert_read_only(f"{kw[0]} c_{col} {kw[1]} t_{tbl}", dialect=dialect)  # must not raise

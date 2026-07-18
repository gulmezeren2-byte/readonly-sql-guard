"""The guard, pinned against the attack corpus - per dialect."""

from __future__ import annotations

import pytest

from readonly_sql_guard import ReadOnlyViolation, assert_read_only, is_read_only
from readonly_sql_guard.corpus import READS, SIDE_EFFECTS, WRITES, run, summarize

_ATTACKS = [*SIDE_EFFECTS, *WRITES]


@pytest.mark.parametrize("case", _ATTACKS, ids=[c.name for c in _ATTACKS])
def test_attack_is_refused(case):
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(case.sql, dialect=case.dialect)


@pytest.mark.parametrize("case", READS, ids=[c.name for c in READS])
def test_real_reads_still_pass(case):
    assert_read_only(case.sql, dialect=case.dialect)  # must not raise
    assert is_read_only(case.sql, dialect=case.dialect)


def test_benchmark_is_perfect():
    s = summarize(run(assert_read_only))
    assert s["all_correct"] is True
    assert s["attacks_blocked"] == s["attacks_total"]
    assert s["reads_allowed"] == s["reads_total"]


def test_strict_mode_default_denies_unknown_functions():
    # a made-up function the parser can't name: allowed lax, refused strict
    assert_read_only("SELECT frobnicate(1)", dialect="postgres")
    with pytest.raises(ReadOnlyViolation):
        assert_read_only("SELECT frobnicate(1)", dialect="postgres", strict=True)


def test_dialect_aliases():
    # 'mssql' / 'sqlserver' both resolve to the tsql parser
    for d in ("mssql", "sqlserver", "tsql"):
        with pytest.raises(ReadOnlyViolation):
            assert_read_only("SELECT * FROM OPENROWSET(BULK 'x', SINGLE_CLOB) y", dialect=d)


def test_fails_closed_on_unparseable():
    # OPENROWSET does not parse; the guard must refuse, not wave it through
    assert not is_read_only("SELECT * FROM OPENROWSET(BULK 'C:/x', SINGLE_CLOB) y", dialect="tsql")

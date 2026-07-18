"""The measured contrast: this guard strictly dominates the naive shortcuts."""

from __future__ import annotations

import pytest

from readonly_sql_guard import assert_read_only
from readonly_sql_guard.corpus import baselines, compare, run, summarize


@pytest.mark.parametrize("guard", list(baselines().values()), ids=list(baselines()))
def test_every_baseline_is_strictly_worse(guard):
    s = summarize(run(guard))
    assert s["all_correct"] is False
    assert s["attacks_blocked"] < s["attacks_total"]  # misses at least one attack we catch


def test_keyword_blocklist_is_unsafe_and_brittle_at_once():
    from readonly_sql_guard.corpus import CASES, write_keyword_blocklist
    from readonly_sql_guard.guard import ReadOnlyViolation

    by = {c.name: c for c in CASES}
    # misses a file read (no blocklisted word in it)
    write_keyword_blocklist(by["pg_read_file"].sql, dialect="postgres")
    # but blocks a legitimate read because 'delete' is inside the string
    with pytest.raises(ReadOnlyViolation):
        write_keyword_blocklist(by["literal_keyword"].sql, dialect="postgres")
    # ...which this guard correctly allows
    assert_read_only(by["literal_keyword"].sql, dialect="postgres")


def test_compare_shape_ours_last_and_perfect():
    rows = compare({**baselines(), "this guard": assert_read_only})
    assert rows[-1]["all_correct"] is True
    assert all(r["all_correct"] is False for r in rows[:-1])

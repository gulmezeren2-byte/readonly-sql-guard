"""Command line: reproduce the trust benchmark, or check a single statement.

    readonly-sql-guard benchmark            # run the attack corpus, show the contrast
    readonly-sql-guard benchmark --json     # machine-readable
    readonly-sql-guard check "SELECT 1"     # is this one statement a read?
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .corpus import CASES, baselines, compare, run, summarize
from .guard import ReadOnlyViolation, assert_read_only


def _cmd_benchmark(args) -> int:
    results = run(assert_read_only)
    s = summarize(results)
    comparison = compare({**baselines(), "this guard": assert_read_only})

    if args.json:
        print(json.dumps({"summary": s, "cases": results, "comparison": comparison},
                         indent=2, ensure_ascii=False))
        return 0 if s["all_correct"] else 1

    by = {c.name: c for c in CASES}
    order = {"critical": 0, "high": 1, "medium": 2, "-": 3}
    print("READ-ONLY SQL GUARD - TRUST BENCHMARK\n")
    print("Attacks (well-formed SQL that is not a read; every one must be REFUSED):")
    for r in sorted([r for r in results if r["expected_block"]],
                    key=lambda r: (order.get(r["severity"], 9), r["name"])):
        mark = "BLOCKED " if r["blocked"] else "PASSED!!"
        print(f"  {mark} [{r['severity']:8}] {r['name']:16} {r['dialect']:8} - {by[r['name']].why}")
    print("\nLegitimate reads (must be ALLOWED, or the guard is useless):")
    for r in [r for r in results if not r["expected_block"]]:
        mark = "allowed " if not r["blocked"] else "BLOCKED!"
        print(f"  {mark}            {r['name']:16} {r['dialect']:8} - {by[r['name']].why}")
    print(f"\n{s['attacks_blocked']}/{s['attacks_total']} attacks refused - "
          f"{s['reads_allowed']}/{s['reads_total']} reads allowed - "
          f"{'ALL CORRECT' if s['all_correct'] else 'FAILURES ABOVE'}")

    print("\nThe same corpus, against the shape-only checks real tools ship:")
    for row in comparison:
        note = ""
        if row["reads_allowed"] < row["reads_total"]:
            broke = row["reads_total"] - row["reads_allowed"]
            note = f"  (and breaks {broke} legitimate read{'s' if broke != 1 else ''})"
        print(f"  {row['guard']:24} {row['attacks_blocked']:2}/{row['attacks_total']} attacks refused"
              f" - {row['reads_allowed']}/{row['reads_total']} reads allowed{note}")
    return 0 if s["all_correct"] else 1


def _cmd_check(args) -> int:
    try:
        assert_read_only(args.sql, dialect=args.dialect, strict=args.strict)
        print("ALLOWED - a single, side-effect-free read.")
        return 0
    except ReadOnlyViolation as e:
        print(f"REFUSED - {e}")
        return 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="readonly-sql-guard",
                                description="A provably read-only SQL guard for AI agents.")
    p.add_argument("--version", action="version", version=f"readonly-sql-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("benchmark", help="run the attack corpus through the guard and report")
    b.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    b.set_defaults(fn=_cmd_benchmark)

    c = sub.add_parser("check", help="check whether a single SQL statement would pass the guard")
    c.add_argument("sql", help="the SQL statement to check")
    c.add_argument("-d", "--dialect", default=None, help="postgres | mysql | tsql | sqlite")
    c.add_argument("--strict", action="store_true", help="default-deny unrecognised functions (agent path)")
    c.set_defaults(fn=_cmd_check)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

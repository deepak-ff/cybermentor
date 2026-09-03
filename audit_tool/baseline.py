"""Baseline comparison CLI: compare two JSON report files and report regressions."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, Any, cast

SEVERITY = {
    "PASS": 0,
    "INFO": 0,
    "SKIP": 0,
    "WARN": 1,
    "FAIL": 2,
    None: -1,
}


def load(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def compare(base: Dict, new: Dict) -> Dict:
    amap = {c["id"]: c for c in base.get("checks", [])}
    bmap = {c["id"]: c for c in new.get("checks", [])}
    diffs = []
    for _id in sorted(set(amap) | set(bmap)):
        a = amap.get(_id)
        b = bmap.get(_id)
        a_lvl = a.get("level") if a else None
        b_lvl = b.get("level") if b else None
        if a_lvl != b_lvl:
            src = b or a
            # mypy: ensure mapping type for indexing
            title = cast(Dict[str, Any], src)["title"]
            diffs.append({"id": _id, "from": a_lvl, "to": b_lvl, "title": title})
    return {"base": base.get("host"), "new": new.get("host"), "diffs": diffs}


def has_regression(diffs: Dict) -> bool:
    for d in diffs.get("diffs", []):
        to_val = SEVERITY.get(d.get("to"), -1)
        from_val = SEVERITY.get(d.get("from"), -1)
        if to_val > from_val:
            return True
    return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="audit-baseline", description="Compare two audit JSON reports"
    )
    p.add_argument("base", help="base JSON report path")
    p.add_argument("new", help="new JSON report path")
    args = p.parse_args(argv)
    if not os.path.exists(args.base) or not os.path.exists(args.new):
        print("One or both report files not found", file=sys.stderr)
        return 2
    base = load(args.base)
    new = load(args.new)
    diffs = compare(base, new)
    print(json.dumps(diffs, indent=2))
    if has_regression(diffs):
        print("Regression detected: some checks worsened", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

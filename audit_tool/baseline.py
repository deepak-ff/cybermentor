"""Baseline comparison CLI: compare two JSON report files and flag regressions.

A "regression" is any check whose level worsened between base and new
(PASS/INFO/SKIP -> WARN -> FAIL, or a newly appearing WARN/FAIL check).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from .models import LEVEL_SEVERITY


def load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_report(doc: Any, path: str) -> Dict[str, Any]:
    """Ensure *doc* looks like an audit JSON report.

    Guards against passing e.g. a SARIF file (also ``*.json``), which would
    otherwise silently compare as an empty baseline.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("checks"), list):
        raise ValueError(f"not an audit report (missing 'checks' list): {path}")
    return doc


def compare(base: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    amap = {c["id"]: c for c in base.get("checks", [])}
    bmap = {c["id"]: c for c in new.get("checks", [])}
    diffs: List[Dict[str, Any]] = []
    for _id in sorted(set(amap) | set(bmap)):
        a = amap.get(_id)
        b = bmap.get(_id)
        a_lvl = a.get("level") if a else None
        b_lvl = b.get("level") if b else None
        if a_lvl != b_lvl:
            title = (b or a or {}).get("title", "")
            diffs.append({"id": _id, "from": a_lvl, "to": b_lvl, "title": title})
    return {
        "base": base.get("host"),
        "new": new.get("host"),
        "score_base": base.get("score"),
        "score_new": new.get("score"),
        "diffs": diffs,
    }


def has_regression(diffs: Dict[str, Any]) -> bool:
    """True when any diff worsened the check outcome.

    Newly appearing checks only count as regressions when they arrive as
    WARN or FAIL; a new PASS/INFO/SKIP check is neutral.
    """
    for d in diffs.get("diffs", []):
        from_val = d.get("from")
        to_val = d.get("to")
        if from_val is None:  # newly appearing check
            if to_val in ("WARN", "FAIL"):
                return True
            continue
        if to_val is None:  # check removed
            continue
        if LEVEL_SEVERITY.get(to_val, -1) > LEVEL_SEVERITY.get(from_val, -1):
            return True
    return False


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="audit-baseline", description="Compare two audit JSON reports"
    )
    p.add_argument("base", help="base JSON report path")
    p.add_argument("new", help="new JSON report path")
    args = p.parse_args(argv)
    if not os.path.exists(args.base) or not os.path.exists(args.new):
        print("One or both report files not found", file=sys.stderr)
        return 2
    try:
        base = load(args.base)
        new = load(args.new)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {exc}", file=sys.stderr)
        return 2
    try:
        base = validate_report(base, args.base)
        new = validate_report(new, args.new)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    diffs = compare(base, new)
    print(json.dumps(diffs, indent=2))
    if has_regression(diffs):
        print("Regression detected: some checks worsened", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

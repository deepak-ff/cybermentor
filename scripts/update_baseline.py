"""Helper to update the baseline file from a report.

Usage: python scripts/update_baseline.py reports/my_report.json
This will copy the given JSON to baseline/baseline.json for future comparisons.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        print("Usage: update_baseline.py <report.json>")
        return 2
    src = Path(sys.argv[1])
    if not src.exists():
        print("Report not found")
        return 2
    dst = Path("baseline") / "baseline.json"
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f"Baseline updated: {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Generate a demo report using the project's reporter/models for easy demos."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

# Allow running as `python scripts/generate_demo.py` without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit_tool.models import CheckResult, Level, ScanResult  # noqa: E402
from audit_tool.reporter import write_reports  # noqa: E402


def make_demo():
    checks = [
        CheckResult(
            "FILE-001",
            "No world-writable files in /etc",
            "Filesystem",
            Level.PASS,
            "0 world-writable file(s) found",
        ),
        CheckResult(
            "SSH-001",
            "PermitRootLogin is disabled",
            "SSH",
            Level.PASS,
            "PermitRootLogin=no",
        ),
        CheckResult(
            "FILE-005",
            "Sticky bit set on world-writable dirs",
            "Filesystem",
            Level.WARN,
            "missing sticky bit on /tmp",
        ),
        CheckResult(
            "KRNL-002",
            "Core dumps are disabled",
            "Kernel",
            Level.INFO,
            "hard core limit not set in limits.conf",
        ),
    ]
    sr = ScanResult(
        host="demo.local",
        started_at=datetime.now().isoformat(timespec="seconds"),
        finished_at=datetime.now().isoformat(timespec="seconds"),
        duration_ms=1234,
        checks=checks,
        open_ports=[{"port": 22, "service": "ssh"}],
        scan_targets={"target": "demo.local", "ports": "1-1024", "threads": 64},
    )
    out = "reports/demo"
    os.makedirs(out, exist_ok=True)
    paths = write_reports(sr, out)
    print("Generated demo reports:", paths)


if __name__ == "__main__":
    make_demo()

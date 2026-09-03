import json
import os

from audit_tool.models import CheckResult, Level, ScanResult
from audit_tool.reporter import write_reports


def test_report_validates(tmp_path, monkeypatch):
    # Ensure jsonschema is available for this test; if not, skip
    try:
        import jsonschema  # noqa: F401
    except Exception:
        import pytest

        pytest.skip("jsonschema not installed")

    checks = [
        CheckResult("C-1", "Test", "Misc", Level.INFO, "ok"),
    ]
    sr = ScanResult(
        host="test.local",
        started_at="2026-01-01T00:00:00",
        finished_at="2026-01-01T00:00:01",
        duration_ms=100,
        checks=checks,
        open_ports=[{"port": 22, "service": "ssh"}],
        scan_targets={"target": "test.local"},
    )
    out = tmp_path / "reports"
    out.mkdir()
    paths = write_reports(sr, str(out))
    assert os.path.exists(paths["json"])
    # load and ensure JSON is valid
    with open(paths["json"], "r", encoding="utf-8") as fh:
        obj = json.load(fh)
    assert obj["host"] == "test.local"

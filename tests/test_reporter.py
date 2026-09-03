"""Tests for all report writers: JSON, HTML, CSV, SARIF."""

from __future__ import annotations

import csv
import io
import json
import os

import pytest
from conftest import make_check, make_report

from audit_tool.models import Level
from audit_tool.reporter import (
    SARIF_LEVEL,
    _score_color,
    to_csv,
    to_html,
    to_json,
    to_sarif,
    utc_now_iso,
    write_reports,
)


def test_to_json_roundtrip(sample_report):
    doc = json.loads(to_json(sample_report))
    assert doc == sample_report.to_dict()
    assert doc["score"] == sample_report.score
    assert doc["tool"] == "security-audit-tool 1.0.0"


def test_to_json_compact():
    sr = make_report([make_check("A", Level.PASS)])
    assert "\n" not in to_json(sr, pretty=False).replace("  ", " ")


def test_to_csv_structure(sample_report):
    rows = list(csv.reader(io.StringIO(to_csv(sample_report))))
    assert rows[0] == [
        "id",
        "title",
        "category",
        "severity",
        "cis_ref",
        "level",
        "detail",
        "recommendation",
        "host",
    ]
    assert len(rows) == 1 + len(sample_report.checks)
    row = dict(zip(rows[0], rows[1]))
    assert row["id"] == "A-001"
    assert row["severity"] == "CRITICAL"
    assert row["level"] == "PASS"


def test_to_csv_quotes_special_chars():
    c = make_check("Q-1", Level.FAIL, detail='has, comma and "quotes"', category="Cat")
    sr = make_report([c])
    rows = list(csv.reader(io.StringIO(to_csv(sr))))
    assert rows[1][6] == 'has, comma and "quotes"'


def test_to_sarif_structure(sample_report):
    doc = json.loads(to_sarif(sample_report))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc and "sarif-schema-2.1.0" in doc["$schema"]
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "security-audit-tool"
    assert driver["version"] == "1.0.0"

    # Every check appears as a rule
    assert len(driver["rules"]) == len(sample_report.checks)
    rule_ids = {r["id"] for r in driver["rules"]}
    assert "A-001" in rule_ids

    # Only actionable checks appear as results
    actionable = [c for c in sample_report.checks if c.level in SARIF_LEVEL]
    assert len(run["results"]) == len(actionable)
    by_id = {r["ruleId"]: r for r in run["results"]}
    assert by_id["A-003"]["level"] == "error"  # FAIL
    assert by_id["A-002"]["level"] == "warning"  # WARN
    assert by_id["A-004"]["level"] == "note"  # INFO
    assert "A-001" not in by_id  # PASS excluded
    assert "A-005" not in by_id  # SKIP excluded

    # ruleIndex points into the rules array
    for r in run["results"]:
        assert driver["rules"][r["ruleIndex"]]["id"] == r["ruleId"]

    # props carry score + open ports
    assert run["properties"]["score"] == sample_report.score
    assert run["properties"]["open_ports"][0]["port"] == 22


def test_to_sarif_no_findings():
    sr = make_report([make_check("A", Level.PASS), make_check("B", Level.SKIP)])
    doc = json.loads(to_sarif(sr))
    assert doc["runs"][0]["results"] == []
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 2


def test_to_html_escapes_and_contains_data(sample_report):
    evil = make_check(
        "XSS-1",
        Level.FAIL,
        detail="<script>alert(1)</script>",
        category="Test",
    )
    evil.title = "<img src=x onerror=alert(1)>"
    sr = make_report([evil])
    page = to_html(sr)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "XSS-1" in page
    assert "Hardening Score" in page
    assert "audit_xss" not in page  # no host-specific oddities
    # filters present
    assert "f-level" in page and "f-cat" in page and "f-q" in page
    assert "applyFilters" in page


def test_to_html_no_open_ports_placeholder(sample_report):
    sr = make_report(sample_report.checks, open_ports=[])
    page = to_html(sr)
    assert "No open ports found" in page


def test_write_reports_all_formats(tmp_path, sample_report):
    paths = write_reports(
        sample_report, str(tmp_path), formats=("json", "html", "csv", "sarif")
    )
    assert set(paths) == {"json", "html", "csv", "sarif"}
    for p in paths.values():
        assert os.path.exists(p)
    with open(paths["json"], "r", encoding="utf-8") as fh:
        assert json.load(fh)["host"] == "testhost"
    with open(paths["sarif"], "r", encoding="utf-8") as fh:
        assert json.load(fh)["version"] == "2.1.0"
    with open(paths["csv"], "r", encoding="utf-8") as fh:
        assert fh.readline().startswith("id,title")
    with open(paths["html"], "r", encoding="utf-8") as fh:
        assert "<!DOCTYPE html>" in fh.read()


def test_write_reports_unknown_format(tmp_path, sample_report):
    with pytest.raises(ValueError):
        write_reports(sample_report, str(tmp_path), formats=("pdf",))


def test_write_reports_schema_validation_fails(tmp_path):
    pytest.importorskip("jsonschema")
    bad = make_report([make_check("A", Level.PASS)], host="h")
    bad.duration_ms = -5  # schema requires >= 0
    with pytest.raises(RuntimeError):
        write_reports(bad, str(tmp_path), formats=("json",))


def test_write_reports_reuses_single_timestamp_base(tmp_path, sample_report):
    paths = write_reports(sample_report, str(tmp_path), formats=("json", "html", "csv"))
    # all files share one base name (different extensions only)
    bases = {os.path.basename(p).rsplit(".", 1)[0] for p in paths.values()}
    assert len(bases) == 1


def test_utc_now_iso_format():
    ts = utc_now_iso()
    assert "T" in ts
    assert ts.endswith("+00:00")


def test_to_sarif_dedupes_duplicate_rule_ids():
    sr = make_report(
        [
            make_check("DUP", Level.FAIL),
            make_check("DUP", Level.WARN),  # same id again
        ]
    )
    doc = json.loads(to_sarif(sr))
    driver = doc["runs"][0]["tool"]["driver"]
    assert len(driver["rules"]) == 1  # deduped
    assert driver["rules"][0]["id"] == "DUP"


def test_validate_skipped_without_jsonschema(monkeypatch, tmp_path):
    import audit_tool.reporter as rep

    monkeypatch.setattr(rep, "_HAS_JSONSCHEMA", False)
    bad = make_report([make_check("A", Level.PASS)], host="h")
    bad.duration_ms = -5  # would fail schema, but validation is disabled
    paths = rep.write_reports(bad, str(tmp_path), formats=("json",))
    assert "json" in paths


def test_score_color_bands():
    assert _score_color(90) == "#15803d"  # green
    assert _score_color(70) == "#b45309"  # amber
    assert _score_color(30) == "#b91c1c"  # red
    assert _score_color(80) == "#15803d"  # boundary inclusive
    assert _score_color(60) == "#b45309"  # boundary inclusive

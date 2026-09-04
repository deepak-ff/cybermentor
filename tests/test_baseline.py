"""Tests for the baseline comparison tool."""

from __future__ import annotations

import json

from audit_tool import baseline


def test_compare_no_changes():
    doc = {"host": "h", "checks": [{"id": "A", "level": "PASS", "title": "t"}]}
    out = baseline.compare(doc, doc)
    assert out["diffs"] == []
    assert out["base"] == "h"


def test_compare_level_change():
    a = {"host": "a", "checks": [{"id": "A", "level": "PASS", "title": "ta"}]}
    b = {"host": "b", "checks": [{"id": "A", "level": "FAIL", "title": "ta"}]}
    out = baseline.compare(a, b)
    assert out["diffs"] == [{"id": "A", "from": "PASS", "to": "FAIL", "title": "ta"}]


def test_compare_added_and_removed():
    a = {"host": "a", "checks": [{"id": "A", "level": "PASS", "title": "ta"}]}
    b = {"host": "b", "checks": [{"id": "B", "level": "WARN", "title": "tb"}]}
    out = baseline.compare(a, b)
    by_id = {d["id"]: d for d in out["diffs"]}
    assert by_id["A"]["from"] == "PASS" and by_id["A"]["to"] is None
    assert by_id["B"]["from"] is None and by_id["B"]["to"] == "WARN"


def test_compare_includes_scores():
    a = {"host": "a", "score": 50, "checks": []}
    b = {"host": "b", "score": 70, "checks": []}
    out = baseline.compare(a, b)
    assert out["score_base"] == 50
    assert out["score_new"] == 70


def test_has_regression_worsening():
    diffs = {"diffs": [{"id": "A", "from": "PASS", "to": "FAIL"}]}
    assert baseline.has_regression(diffs) is True


def test_has_regression_new_fail():
    diffs = {"diffs": [{"id": "A", "from": None, "to": "FAIL"}]}
    assert baseline.has_regression(diffs) is True


def test_has_regression_no_for_improvement():
    diffs = {"diffs": [{"id": "A", "from": "FAIL", "to": "PASS"}]}
    assert baseline.has_regression(diffs) is False


def test_has_regression_no_for_new_pass():
    diffs = {"diffs": [{"id": "A", "from": None, "to": "PASS"}]}
    assert baseline.has_regression(diffs) is False


def test_has_regression_false_when_check_removed():
    diffs = {"diffs": [{"id": "A", "from": "FAIL", "to": None}]}
    assert baseline.has_regression(diffs) is False


def test_has_regression_true_for_new_warn():
    diffs = {"diffs": [{"id": "A", "from": None, "to": "WARN"}]}
    assert baseline.has_regression(diffs) is True


def test_main_regression_exit_1(capsys, report_files):
    base, new = report_files
    rc = baseline.main([base, new])
    out = capsys.readouterr()
    assert rc == 1
    assert "Regression detected" in out.err
    doc = json.loads(out.out)
    assert doc["diffs"]


def test_main_clean_exit_0(capsys, report_files):
    # compare a report with itself -> no regression
    base, _new = report_files
    rc = baseline.main([base, base])
    assert rc == 0
    capsys.readouterr()


def test_main_missing_file_exit_2(capsys):
    rc = baseline.main(["/nope/missing.json", "/also/missing.json"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_main_invalid_json_exit_2(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text("{}", encoding="utf-8")
    rc = baseline.main([str(bad), str(good)])
    assert rc == 2


def test_main_sarif_like_report_rejected(capsys, tmp_path):
    """SARIF files are also ``*.json``; they must be rejected, not diffed
    silently as an empty baseline."""
    sarif = tmp_path / "scan.sarif.json"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {"host": "h", "checks": [{"id": "A", "level": "PASS", "title": "t"}]}
        ),
        encoding="utf-8",
    )
    rc = baseline.main([str(sarif), str(good)])
    out = capsys.readouterr()
    assert rc == 2
    assert "not an audit report" in out.err

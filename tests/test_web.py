"""Integration tests for the report web server (real HTTP on a local port)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Dict, Tuple

import pytest

from audit_tool import web


@pytest.fixture
def server(report_files, tmp_path):
    base, new = report_files
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    httpd.daemon_threads = True
    setattr(httpd, "reports_dir", str(tmp_path))  # noqa: B010
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield port, base, new
    httpd.shutdown()
    thread.join(timeout=5)


def get(port: int, path: str) -> Tuple[int, Dict[str, str], str]:
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read().decode("utf-8"),
            )
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        body = e.read().decode("utf-8")
        return (e.code, headers, body)


def test_index_serves_spa_with_security_headers(server):
    port, _b, _n = server
    status, headers, body = get(port, "/")
    assert status == 200
    assert "Audit Reports" in body
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "content-security-policy" in headers
    assert "referrer-policy" in headers


def test_api_list(server):
    port, base, new = server
    status, _h, body = get(port, "/api/list")
    assert status == 200
    reports = json.loads(body)["reports"]
    assert "base.json" in reports and "new.json" in reports


def test_api_report_loads(server):
    port, base, new = server
    status, _h, body = get(port, "/api/report?file=base.json")
    assert status == 200
    doc = json.loads(body)
    assert doc["host"] == "base"
    assert len(doc["checks"]) == 3


def test_api_report_missing_param(server):
    port, _b, _n = server
    status, _h, body = get(port, "/api/report")
    assert status == 400
    assert "error" in json.loads(body)


def test_api_report_unknown_file(server):
    port, _b, _n = server
    status, _h, _body = get(port, "/api/report?file=nope.json")
    assert status == 404


def test_api_report_rejects_traversal(server):
    port, _b, _n = server
    status, _h, _body = get(port, "/api/report?file=" + "..%2F..%2Fetc%2Fpasswd")
    assert status == 404


def test_api_report_rejects_non_json(tmp_path, server, report_files):
    # create a .txt file in the reports dir
    (tmp_path / "notes.txt").write_text("not a report", encoding="utf-8")
    port, _b, _n = server
    status, _h, _body = get(port, "/api/report?file=notes.txt")
    assert status == 404


def test_api_diff(server):
    port, base, new = server
    status, _h, body = get(port, "/api/diff?base=base.json&new=new.json")
    assert status == 200
    doc = json.loads(body)
    assert doc["base"] == "base" and doc["new"] == "new"
    by_id = {d["id"]: d for d in doc["diffs"]}
    # C-1 PASS -> FAIL, C-3 WARN -> gone, C-4 new INFO
    assert by_id["C-1"]["from"] == "PASS" and by_id["C-1"]["to"] == "FAIL"
    assert by_id["C-3"]["from"] == "WARN" and by_id["C-3"]["to"] is None
    assert by_id["C-4"]["from"] is None and by_id["C-4"]["to"] == "INFO"
    assert "C-2" not in by_id  # unchanged


def test_api_diff_missing_params(server):
    port, _b, _n = server
    status, _h, _body = get(port, "/api/diff?base=base.json")
    assert status == 400


def test_api_diff_unknown_file(server):
    port, base, new = server
    status, _h, _body = get(port, "/api/diff?base=missing.json&new=new.json")
    assert status == 404


def test_unknown_path_is_json_404(server):
    port, _b, _n = server
    status, headers, body = get(port, "/nope")
    assert status == 404
    assert headers["content-type"].startswith("application/json")
    assert "error" in json.loads(body)


def test_web_main_serves_and_stops(monkeypatch, tmp_path, capsys):
    """Drive web.main() with a fake server that stops immediately."""
    started = {}

    class FakeServer:
        def __init__(self, addr, handler):
            self.address = addr
            self.daemon_threads = False

        def serve_forever(self):
            started["called"] = True
            raise KeyboardInterrupt

        def shutdown(self):
            pass

    monkeypatch.setattr(web, "ThreadingHTTPServer", FakeServer)
    rc = web.main(["--reports", str(tmp_path), "--port", "8931", "--host", "127.0.0.1"])
    assert rc == 0
    assert started.get("called") is True
    assert "Serving reports" in capsys.readouterr().out


# ------------------------------------------------------------- pure functions


def test_diff_reports_identical():
    doc = {"host": "h", "checks": [{"id": "A", "level": "PASS"}]}
    out = web.diff_reports(doc, doc)
    assert out["diffs"] == []


def test_diff_reports_added_removed():
    a = {"host": "a", "checks": [{"id": "A", "level": "PASS", "title": "ta"}]}
    b = {"host": "b", "checks": [{"id": "B", "level": "FAIL", "title": "tb"}]}
    out = web.diff_reports(a, b)
    by_id = {d["id"]: d for d in out["diffs"]}
    assert by_id["A"]["from"] == "PASS" and by_id["A"]["to"] is None
    assert by_id["B"]["from"] is None and by_id["B"]["to"] == "FAIL"


def test_list_reports_ignores_non_json(tmp_path):
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.txt").write_text("x", encoding="utf-8")
    assert web.list_reports(str(tmp_path)) == ["a.json"]


def test_list_reports_missing_dir(tmp_path):
    assert web.list_reports(str(tmp_path / "nope")) == []


def test_load_report_rejects_traversal(tmp_path):
    (tmp_path / "r.json").write_text("{}", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        web.load_report(str(tmp_path), "../r.json")
    with pytest.raises(FileNotFoundError):
        web.load_report(str(tmp_path), "")
    with pytest.raises(FileNotFoundError):
        web.load_report(str(tmp_path), "sub/r.json")

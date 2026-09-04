"""Integration tests for the report web server (real HTTP on a local port)."""

from __future__ import annotations

import json
import threading
import time
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
    setattr(httpd, "allow_scan", True)  # noqa: B010 (loopback bind)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield port, base, new
    httpd.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def public_server(report_files, tmp_path):
    """Server bound to 0.0.0.0 — scan API must be disabled here."""
    httpd = ThreadingHTTPServer(("0.0.0.0", 0), web.Handler)
    httpd.daemon_threads = True
    setattr(httpd, "reports_dir", str(tmp_path))  # noqa: B010
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield port
    httpd.shutdown()
    thread.join(timeout=5)


def post(port: int, path: str, payload: str) -> Tuple[int, Dict[str, str], str]:
    url = f"http://127.0.0.1:{port}{path}"
    req = urllib.request.Request(url, data=payload.encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read().decode("utf-8"),
            )
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()}
        body = e.read().decode("utf-8")
        return (e.code, headers, body)


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


# ------------------------------------------------------------- scan API


def test_api_scan_runs_and_completes(server, tmp_path):
    port, _b, _n = server
    status, _h, body = post(
        port, "/api/scan", json.dumps({"host": "127.0.0.1", "skip_scan": True})
    )
    assert status == 202
    job_id = json.loads(body)["id"]

    deadline = time.time() + 30
    job = None
    while time.time() < deadline:
        s, _h, b = get(port, f"/api/scan?id={job_id}")
        assert s == 200
        job = json.loads(b)
        if job["status"] != "running":
            break
        time.sleep(0.3)
    assert job is not None and job["status"] == "done", job
    json_reports = [f for f in job["reports"] if f.endswith(".json")]
    assert json_reports, job  # defaults are json+html

    # The new report must now be visible through the regular endpoints.
    s, _h, b = get(port, f"/api/report?file={json_reports[0]}")
    assert s == 200
    assert json.loads(b)["host"] == "127.0.0.1"
    s, _h, b = get(port, "/api/list")
    assert json_reports[0] in json.loads(b)["reports"]


def test_api_scan_disabled_on_public_bind(public_server):
    status, _h, body = post(
        public_server, "/api/scan", json.dumps({"host": "127.0.0.1"})
    )
    assert status == 403
    assert "non-loopback" in json.loads(body)["error"]


def test_api_scan_bad_bodies(server):
    port, _b, _n = server
    for payload in ("", "not json", "{}", '{"host": "x", "ports": "1024-1"}'):
        status, _h, body = post(port, "/api/scan", payload)
        assert status == 400, (payload, body)
        assert "error" in json.loads(body)


def test_api_scan_unknown_id(server):
    port, _b, _n = server
    status, _h, body = get(port, "/api/scan?id=nope")
    assert status == 404


def test_api_post_unknown_endpoint(server):
    port, _b, _n = server
    status, _h, body = post(port, "/api/nope", "{}")
    assert status == 404
    assert "error" in json.loads(body)


def test_parse_scan_request_valid():
    p = web.parse_scan_request({"host": "10.0.0.5", "ports": "80,443"})
    assert p["host"] == "10.0.0.5"
    assert p["ports"] == "80,443"
    assert p["threads"] == 256
    assert p["skip_scan"] is False
    assert p["formats"] == ["json", "html"]


def test_parse_scan_request_rejects_bad_values():
    import pytest

    for body in (
        None,
        "[]",
        {"host": ""},
        {"host": "x", "threads": 0},
        {"host": "x", "timeout": 999},
        {"host": "x", "formats": ["pdf"]},
        {"host": "x", "ports": "99999"},
    ):
        with pytest.raises(ValueError):
            web.parse_scan_request(body)


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


def test_diff_reports_ports_delta():
    a = {"host": "a", "checks": [], "open_ports": [{"port": 22}, {"port": 80}]}
    b = {"host": "b", "checks": [], "open_ports": [{"port": 443}]}
    out = web.diff_reports(a, b)
    assert out["ports_added"] == [443]
    assert out["ports_removed"] == [22, 80]


def test_diff_reports_missing_ports_key():
    out = web.diff_reports({"host": "a", "checks": []}, {"host": "b", "checks": []})
    assert out["ports_added"] == []
    assert out["ports_removed"] == []


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

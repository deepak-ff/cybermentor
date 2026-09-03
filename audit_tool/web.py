"""Simple browser UI and diff server for audit reports using the standard library.

Run: python -m audit_tool.web --reports reports --port 8000
"""

from __future__ import annotations

import argparse
import html
import json
import os
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import List
from typing import Any, Dict, cast


def list_reports(reports_dir: str) -> List[str]:
    try:
        files = sorted(f for f in os.listdir(reports_dir) if f.endswith(".json"))
    except OSError:
        files = []
    return files


def load_report(reports_dir: str, filename: str) -> dict:
    # Prevent path traversal
    if os.path.basename(filename) != filename:
        raise FileNotFoundError
    path = os.path.join(reports_dir, filename)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def diff_reports(a: dict, b: dict) -> dict:
    """Return a simple diff of checks keyed by id with level changes."""
    amap = {c["id"]: c for c in a.get("checks", [])}
    bmap = {c["id"]: c for c in b.get("checks", [])}
    ids = sorted(set(amap) | set(bmap))
    diffs = []
    for _id in ids:
        a_check = amap.get(_id)
        b_check = bmap.get(_id)
        if a_check and b_check:
            a_d = cast(Dict[str, Any], a_check)
            b_d = cast(Dict[str, Any], b_check)
            if a_d.get("level") != b_d.get("level"):
                diffs.append(
                    {
                        "id": _id,
                        "from": a_d.get("level"),
                        "to": b_d.get("level"),
                        "title": b_d.get("title") or a_d.get("title"),
                    }
                )
        elif a_check and not b_check:
            a_d = cast(Dict[str, Any], a_check)
            diffs.append(
                {
                    "id": _id,
                    "from": a_d.get("level"),
                    "to": None,
                    "title": a_d.get("title"),
                }
            )
        else:
            b_d = cast(Dict[str, Any], b_check)
            diffs.append(
                {
                    "id": _id,
                    "from": None,
                    "to": b_d.get("level"),
                    "title": b_d.get("title"),
                }
            )
    return {"base": a.get("host"), "new": b.get("host"), "diffs": diffs}


class Handler(BaseHTTPRequestHandler):
    server_version = "audit-web/0.1"

    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        rd = getattr(self.server, "reports_dir", "reports")
        if self.path == "/" or self.path.startswith("/index"):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(self._index_html().encode("utf-8"))
            return
        if self.path.startswith("/api/list"):
            files = list_reports(rd)
            return self._send_json({"reports": files})
        if self.path.startswith("/api/report"):
            qs = self.path.split("?", 1)
            if len(qs) != 2:
                return self._send_json({"error": "missing file parameter"}, status=400)
            params = qs[1]
            # expect file=<name>
            kv = dict(part.split("=", 1) for part in params.split("&") if "=" in part)
            fn = kv.get("file")
            if not fn:
                return self._send_json({"error": "missing file parameter"}, status=400)
            try:
                report = load_report(rd, fn)
            except Exception:
                return self._send_json({"error": "file not found"}, status=404)
            return self._send_json(report)
        if self.path.startswith("/api/diff"):
            qs = self.path.split("?", 1)
            if len(qs) != 2:
                return self._send_json({"error": "missing parameters"}, status=400)
            params = qs[1]
            kv = dict(part.split("=", 1) for part in params.split("&") if "=" in part)
            base = kv.get("base")
            new = kv.get("new")
            if not base or not new:
                return self._send_json({"error": "missing base/new"}, status=400)
            try:
                a = load_report(rd, base)
                b = load_report(rd, new)
            except Exception:
                return self._send_json({"error": "file not found"}, status=404)
            return self._send_json(diff_reports(a, b))
        # static files not supported
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def log_message(self, format, *args):
        # quiet logs
        return

    def _index_html(self) -> str:
        # Very small single-file SPA for listing reports and diffing
        rd_val = getattr(self.server, "reports_dir", "reports")
        rd_js = json.dumps(rd_val)
        return """<!doctype html>
<html><head><meta charset="utf-8"><title>Audit Reports</title>
<style>body{font-family:Arial,Helvetica,sans-serif;margin:18px;color:#111}
.muted{color:#6b7280}.mono{font-family:monospace}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #eee;padding:6px;text-align:left}
.badge{padding:3px 8px;border-radius:6px;color:#fff;font-weight:600}
</style></head><body>
<h1>Audit Reports</h1>
<div class="muted">Reports directory: <span class="mono">{rd}</span></div>
<div style="margin-top:12px">
  <select id="reports"></select>
  <button onclick="loadReport()">View</button>
  <button onclick="refresh()">Refresh</button>
</div>
<div style="margin-top:8px">
  <h3>Viewer</h3>
  <div id="viewer"></div>
</div>
<div style="margin-top:12px">
  <h3>Diff</h3>
  <select id="base"></select> vs <select id="new"></select>
  <button onclick="doDiff()">Diff</button>
  <div id="diff"></div>
</div>
<script>
const rd = {rd_js};
async function refresh(){
  const res = await fetch('/api/list');
  const obj = await res.json();
  const sel = document.getElementById('reports');
  const base = document.getElementById('base');
  const neu = document.getElementById('new');
  [sel, base, neu].forEach(s=>s.innerHTML='');
  obj.reports.forEach(r=>{[sel,base,neu].forEach(s=>s.append(new Option(r,r)))});
}
async function loadReport(){
  const sel = document.getElementById('reports');
  const fn = sel.value; if(!fn) return;
  const res = await fetch('/api/report?file='+encodeURIComponent(fn));
  const obj = await res.json();
  const v = document.getElementById('viewer');
  v.innerHTML = `<h4>${obj.host}</h4><p class=\"muted\">${obj.started_at} → ${obj.finished_at} (${obj.duration_ms} ms)</p>`;
  let html = '<table><tr><th>ID</th><th>Check</th><th>Level</th><th>Detail</th></tr>';
  obj.checks.forEach(c=>{html+=`<tr><td class=\"mono\">${c.id}</td><td>${c.title}</td><td>${c.level}</td><td>${c.detail}</td></tr>`});
  html += '</table>';
  v.innerHTML += html;
}
async function doDiff(){
  const b = document.getElementById('base').value;
  const n = document.getElementById('new').value;
  if(!b||!n) return;
  const res = await fetch('/api/diff?base='+encodeURIComponent(b)+'&new='+encodeURIComponent(n));
  const obj = await res.json();
  const d = document.getElementById('diff');
  if(obj.diffs.length===0){d.innerHTML='<p class="muted">No differences found</p>';return}
  let html = '<table><tr><th>ID</th><th>Title</th><th>From</th><th>To</th></tr>';
  obj.diffs.forEach(x=>{html+=`<tr><td class=\"mono\">${x.id}</td><td>${x.title}</td><td>${x.from||''}</td><td>${x.to||''}</td></tr>`});
  html += '</table>';
  d.innerHTML = html;
}
window.onload = refresh;
</script>
</body></html>""".replace("{rd}", html.escape(rd_val)).replace("{rd_js}", rd_js)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="audit-web")
    parser.add_argument("--reports", default="reports", help="reports directory")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on")
    args = parser.parse_args(argv)
    reports_dir = args.reports
    os.makedirs(reports_dir, exist_ok=True)
    addr = ("", args.port)
    httpd = ThreadingHTTPServer(addr, Handler)
    setattr(httpd, "reports_dir", reports_dir)
    print(f"Serving reports from {reports_dir} at http://localhost:{args.port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping")


if __name__ == "__main__":
    main()

"""Browser UI and diff server for audit reports (standard library only).

The server binds to 127.0.0.1 by default and serves an internal report
browser plus a baseline/diff API. All responses set defensive security
headers and report data is HTML-escaped before rendering.

Run: python -m audit_tool.web --reports reports --port 8000
"""

from __future__ import annotations

import argparse
import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


def list_reports(reports_dir: str) -> List[str]:
    try:
        names = os.listdir(reports_dir)
    except OSError:
        return []
    return sorted(f for f in names if f.endswith(".json"))


def load_report(reports_dir: str, filename: str) -> dict:
    """Load a report by basename only, rejecting any path traversal."""
    if not filename or os.path.basename(filename) != filename:
        raise FileNotFoundError
    if not filename.endswith(".json"):
        raise FileNotFoundError
    path = os.path.join(reports_dir, filename)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def diff_reports(a: dict, b: dict) -> dict:
    """Return level changes between two reports, keyed by check id."""
    amap = {c["id"]: c for c in a.get("checks", [])}
    bmap = {c["id"]: c for c in b.get("checks", [])}
    diffs = []
    for _id in sorted(set(amap) | set(bmap)):
        a_check: Optional[Dict[str, Any]] = amap.get(_id)
        b_check: Optional[Dict[str, Any]] = bmap.get(_id)
        if a_check and b_check:
            if a_check.get("level") != b_check.get("level"):
                diffs.append(
                    {
                        "id": _id,
                        "from": a_check.get("level"),
                        "to": b_check.get("level"),
                        "title": b_check.get("title") or a_check.get("title"),
                    }
                )
        elif a_check and not b_check:
            diffs.append(
                {
                    "id": _id,
                    "from": a_check.get("level"),
                    "to": None,
                    "title": a_check.get("title"),
                }
            )
        elif b_check:
            diffs.append(
                {
                    "id": _id,
                    "from": None,
                    "to": b_check.get("level"),
                    "title": b_check.get("title"),
                }
            )
    return {"base": a.get("host"), "new": b.get("host"), "diffs": diffs}


class Handler(BaseHTTPRequestHandler):
    server_version = "audit-web/1.0"

    def _send_headers(self, status: int, content_type: str, body_len: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(body_len))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; "
            "style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; "
            "connect-src 'self'; "
            "img-src 'data:'",
        )
        self.end_headers()

    def _send_json(self, obj: Any, status: int = 200) -> None:
        data = json.dumps(obj).encode("utf-8")
        ctype = "application/json; charset=utf-8"
        self._send_headers(status, ctype, len(data))
        self.wfile.write(data)

    def _send_text(self, text: str, status: int = 200) -> None:
        data = text.encode("utf-8")
        self._send_headers(status, "text/html; charset=utf-8", len(data))
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802 (http.server API)
        reports_dir = getattr(self.server, "reports_dir", "reports")
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path in ("/", "/index", "/index.html"):
            return self._send_text(_index_html(reports_dir))

        if path == "/api/list":
            return self._send_json({"reports": list_reports(reports_dir)})

        if path == "/api/report":
            fn = query.get("file")
            if not fn:
                return self._send_json({"error": "missing file parameter"}, 400)
            try:
                report = load_report(reports_dir, fn)
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                return self._send_json({"error": "file not found"}, 404)
            return self._send_json(report)

        if path == "/api/diff":
            base = query.get("base")
            new = query.get("new")
            if not base or not new:
                return self._send_json({"error": "missing base/new"}, 400)
            try:
                a = load_report(reports_dir, base)
                b = load_report(reports_dir, new)
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                return self._send_json({"error": "file not found"}, 404)
            return self._send_json(diff_reports(a, b))

        return self._send_json({"error": "not found"}, 404)

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover
        pass


_INDEX_CSS = """
body{font-family:Arial,Helvetica,sans-serif;margin:18px;color:#111}
.muted{color:#6b7280}
.mono{font-family:monospace}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #eee;padding:6px;text-align:left}
.badge{padding:3px 8px;border-radius:6px;color:#fff;font-weight:600}
.b-PASS{background:#15803d}
.b-WARN{background:#b45309}
.b-FAIL{background:#b91c1c}
.b-INFO{background:#1d4ed8}
.b-SKIP{background:#6b7280}
"""

_INDEX_JS = """
function esc(s){
  var m={"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"};
  return String(s).replace(/[&<>"']/g,function(c){return m[c];});
}
function cell(lvl,empty){
  if(!lvl)return '<em>'+empty+'</em>';
  return '<span class="badge b-'+esc(lvl)+'">'+esc(lvl)+'</span>';
}
async function refresh(){
  const res=await fetch('/api/list');
  const obj=await res.json();
  ['reports','base','new'].forEach(id=>{
    document.getElementById(id).innerHTML='';
  });
  obj.reports.forEach(r=>{
    ['reports','base','new'].forEach(id=>{
      const o=new Option(r,r);
      document.getElementById(id).add(o);
    });
  });
}
async function loadReport(){
  const fn=document.getElementById('reports').value;
  if(!fn)return;
  const url='/api/report?file='+encodeURIComponent(fn);
  const obj=await (await fetch(url)).json();
  const v=document.getElementById('viewer');
  let out='<h4>'+esc(obj.host)+'</h4>';
  out+='<p class="muted">'+esc(obj.started_at)+' \\u2192 ';
  out+=esc(obj.finished_at)+' ('+esc(obj.duration_ms)+' ms) ';
  out+='\\u2014 score '+esc(obj.score)+'</p>';
  out+='<table><tr><th>ID</th><th>Check</th><th>Level</th><th>Detail</th></tr>';
  obj.checks.forEach(c=>{
    out+='<tr><td class="mono">'+esc(c.id)+'</td>';
    out+='<td>'+esc(c.title)+'</td>';
    out+='<td>'+cell(c.level,'')+'</td>';
    out+='<td>'+esc(c.detail)+'</td></tr>';
  });
  out+='</table>';
  v.innerHTML=out;
}
async function doDiff(){
  const b=document.getElementById('base').value;
  const n=document.getElementById('new').value;
  if(!b||!n)return;
  const url='/api/diff?base='+encodeURIComponent(b)+'&new='+encodeURIComponent(n);
  const obj=await (await fetch(url)).json();
  const d=document.getElementById('diff');
  if(!obj.diffs.length){
    d.innerHTML='<p class="muted">No differences found</p>';
    return;
  }
  let out='<table><tr><th>ID</th><th>Title</th><th>From</th><th>To</th></tr>';
  obj.diffs.forEach(x=>{
    out+='<tr><td class="mono">'+esc(x.id)+'</td>';
    out+='<td>'+esc(x.title||'')+'</td>';
    out+='<td>'+cell(x.from,'new')+'</td>';
    out+='<td>'+cell(x.to,'gone')+'</td></tr>';
  });
  out+='</table>';
  d.innerHTML=out;
}
window.onload=refresh;
"""


def _index_html(reports_dir: str) -> str:
    return (
        "<!doctype html>\n"
        '<html><head><meta charset="utf-8">'
        "<title>Audit Reports</title>\n"
        "<style>" + _INDEX_CSS + "</style></head><body>\n"
        "<h1>Audit Reports</h1>\n"
        '<div class="muted">Reports directory: '
        '<span class="mono">' + html.escape(reports_dir) + "</span></div>\n"
        '<div style="margin-top:12px">\n'
        '  <select id="reports"></select>\n'
        '  <button onclick="loadReport()">View</button>\n'
        '  <button onclick="refresh()">Refresh</button>\n'
        "</div>\n"
        '<div style="margin-top:8px"><h3>Viewer</h3>'
        '<div id="viewer"></div></div>\n'
        '<div style="margin-top:12px"><h3>Diff</h3>\n'
        '  <select id="base"></select> vs <select id="new"></select>\n'
        '  <button onclick="doDiff()">Diff</button>'
        '<div id="diff"></div>\n'
        "</div>\n"
        "<script>" + _INDEX_JS + "</script>\n"
        "</body></html>"
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="audit-web")
    parser.add_argument("--reports", default="reports", help="reports directory")
    parser.add_argument("--port", type=int, default=8000, help="port to listen on")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address (default 127.0.0.1; use 0.0.0.0 only behind auth)",
    )
    args = parser.parse_args(argv)
    reports_dir = args.reports
    os.makedirs(reports_dir, exist_ok=True)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True
    # Runtime attribute; read back by Handler via getattr(). Plain
    # assignment would fail mypy (unknown attribute on HTTPServer).
    setattr(httpd, "reports_dir", reports_dir)  # noqa: B010
    print(f"Serving reports from {reports_dir} at http://{args.host}:{args.port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

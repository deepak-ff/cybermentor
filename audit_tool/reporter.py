"""Report generation: JSON, HTML dashboard, CSV and SARIF 2.1.0.

All formats are produced from the same ScanResult object so they always
agree. The HTML report is a single self-contained file (inline CSS + JS, no
external assets), which makes it easy to share, archive, or attach to a
ticket. SARIF output follows the OASIS 2.1.0 specification so results can be
ingested by GitHub code scanning, Visual Studio, or SIEM pipelines.
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
from datetime import datetime, timezone
from typing import Dict, Sequence

from . import __version__
from .models import CheckResult, Level, ScanResult

# Optional JSON Schema validation (requires `jsonschema` package)
_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "report_schema.json")
try:
    import jsonschema  # type: ignore

    _HAS_JSONSCHEMA = True
except Exception:  # pragma: no cover - depends on environment
    _HAS_JSONSCHEMA = False

LEVEL_BADGE = {
    Level.PASS: "#15803d",
    Level.WARN: "#b45309",
    Level.FAIL: "#b91c1c",
    Level.INFO: "#1d4ed8",
    Level.SKIP: "#6b7280",
}

LEVEL_LABEL = {
    Level.PASS: "Pass",
    Level.WARN: "Warning",
    Level.FAIL: "Fail",
    Level.INFO: "Info",
    Level.SKIP: "Skipped",
}

SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
}

#: SARIF result levels for each check level (PASS/SKIP are not reported).
SARIF_LEVEL = {
    Level.FAIL: "error",
    Level.WARN: "warning",
    Level.INFO: "note",
}

TOOL_NAME = "security-audit-tool"
TOOL_URI = "https://github.com/deepak-ff/cybermentor"


def to_json(result: ScanResult, pretty: bool = True) -> str:
    return json.dumps(result.to_dict(), indent=2 if pretty else None)


def to_csv(result: ScanResult) -> str:
    """CSV export of the configuration checks (one row per check)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
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
    )
    for c in result.checks:
        writer.writerow(
            [
                c.id,
                c.title,
                c.category,
                c.severity.value,
                c.cis_ref,
                c.level.value,
                c.detail,
                c.recommendation,
                c.host,
            ]
        )
    return buf.getvalue()


def to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 export: only actionable findings (FAIL/WARN/INFO) are
    emitted as results; PASS/SKIP checks are covered by the rule inventory."""
    rules = []
    seen = set()
    for c in result.checks:
        if c.id in seen:
            continue
        seen.add(c.id)
        sarif_level = SARIF_LEVEL.get(c.level, "note")
        rules.append(
            {
                "id": c.id,
                "name": c.title,
                "shortDescription": {"text": c.title},
                "fullDescription": {"text": c.detail},
                "properties": {
                    "category": c.category,
                    "severity": c.severity.value,
                    "cis_ref": c.cis_ref,
                    "recommendation": c.recommendation,
                },
                "defaultConfiguration": {"level": sarif_level},
            }
        )

    findings = [c for c in result.checks if c.level in SARIF_LEVEL]
    results = []
    for c in findings:
        results.append(
            {
                "ruleId": c.id,
                "ruleIndex": rules.index(next(r for r in rules if r["id"] == c.id)),
                "level": SARIF_LEVEL[c.level],
                "message": {"text": f"{c.title}: {c.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": c.host},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "category": c.category,
                    "severity": c.severity.value,
                    "cis_ref": c.cis_ref,
                    "recommendation": c.recommendation,
                },
            }
        )

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
        "main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.started_at,
                        "endTimeUtc": result.finished_at,
                    }
                ],
                "results": results,
                "properties": {
                    "host": result.host,
                    "platform": result.platform,
                    "score": result.score,
                    "open_ports": result.open_ports,
                    "duration_ms": result.duration_ms,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _score_color(score: int) -> str:
    if score >= 80:
        return "#15803d"
    if score >= 60:
        return "#b45309"
    return "#b91c1c"


# The dashboard is fully self-contained: static CSS and JS live in module
# constants (kept on short lines) and the HTML skeleton inlines them.
_CSS = """
  body {
    font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial,
                 sans-serif;
    margin: 32px;
    color: #111827;
    background: #f9fafb;
  }
  h1 { margin-bottom: 4px; }
  h2 { margin-top: 28px; }
  .muted { color: #6b7280; }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.85em;
  }
  .badge {
    color: #fff;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 0.78em;
    font-weight: 600;
    white-space: nowrap;
  }
  .sev {
    color: #fff;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 0.72em;
    font-weight: 700;
    letter-spacing: 0.02em;
    white-space: nowrap;
  }
  .pill {
    display: inline-block;
    margin: 2px 4px 2px 0;
    padding: 2px 10px;
    border: 1.5px solid;
    border-radius: 999px;
    font-size: 0.82em;
    font-weight: 600;
  }
  table {
    border-collapse: collapse;
    width: 100%;
    background: #fff;
    margin-top: 16px;
  }
  th, td {
    border-bottom: 1px solid #e5e7eb;
    padding: 8px 10px;
    text-align: left;
    vertical-align: top;
  }
  th {
    background: #f3f4f6;
    font-size: 0.82em;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  tr:hover td { background: #f9fafb; }
  .meta { font-size: 0.9em; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
    margin-top: 12px;
  }
  .card {
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 14px;
  }
  .big { font-size: 1.6em; font-weight: 700; }
  .filters {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 14px;
    align-items: center;
  }
  .filters select, .filters input {
    padding: 6px 10px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    font-size: 0.9em;
    background: #fff;
  }
  .filters input { min-width: 220px; }
  .rec { color: #374151; font-size: 0.92em; }
  .hidden { display: none; }
  footer { margin-top: 24px; }
"""

_JS = """
function applyFilters() {
  var lvl = document.getElementById('f-level').value;
  var cat = document.getElementById('f-cat').value;
  var q = document.getElementById('f-q').value.trim().toLowerCase();
  var rows = document.querySelectorAll('#checks tbody tr');
  var shown = 0;
  for (var i = 0; i < rows.length; i++) {
    var tr = rows[i];
    var ok = true;
    if (lvl && tr.dataset.level !== lvl) { ok = false; }
    if (cat && tr.dataset.category !== cat) { ok = false; }
    if (q && tr.dataset.text.indexOf(q) < 0) { ok = false; }
    tr.classList.toggle('hidden', !ok);
    if (ok) { shown++; }
  }
  document.getElementById('f-count').textContent =
    shown + ' of ' + rows.length + ' shown';
}
window.addEventListener('DOMContentLoaded', applyFilters);
"""


def _check_row(c: CheckResult) -> str:
    """Build one <tr> for a check. Every cell is HTML-escaped."""
    esc = html.escape
    color = LEVEL_BADGE.get(c.level, "#374151")
    label = LEVEL_LABEL.get(c.level, c.level.value)
    sev_color = SEVERITY_COLORS.get(c.severity.value, "#374151")
    tr_open = "<tr data-level='{0}' data-category='{1}' data-text='{2}'>".format(
        c.level.value,
        esc(c.category),
        esc((c.id + " " + c.title).lower()),
    )
    cells = [
        "<td class='mono'>{}</td>".format(esc(c.id)),
        "<td>{}</td>".format(esc(c.title)),
        "<td>{}</td>".format(esc(c.category)),
        "<td><span class='sev' style='background:{0}'>{1}</span></td>".format(
            sev_color, c.severity.value
        ),
        "<td class='mono'>{}</td>".format(esc(c.cis_ref)),
        "<td><span class='badge' style='background:{0}'>{1}</span></td>".format(
            color, label
        ),
        "<td>{}</td>".format(esc(c.detail)),
        "<td class='rec'>{}</td>".format(esc(c.recommendation) or "&mdash;"),
    ]
    return tr_open + "".join(cells) + "</tr>"


def to_html(result: ScanResult) -> str:
    """Self-contained HTML dashboard with client-side level/category/search
    filtering. All dynamic content is HTML-escaped."""
    counts = {lvl: 0 for lvl in Level}
    for c in result.checks:
        counts[c.level] += 1

    sev_counts: Dict[str, int] = {}
    for c in result.checks:
        if c.level in (Level.PASS, Level.WARN, Level.FAIL):
            sev_counts[c.severity.value] = sev_counts.get(c.severity.value, 0) + 1

    rows = [_check_row(c) for c in result.checks]

    if result.open_ports:
        open_ports_rows = "".join(
            "<tr><td class='mono'>{}</td><td>{}</td></tr>".format(
                p["port"], html.escape(p["service"])
            )
            for p in result.open_ports
        )
    else:
        open_ports_rows = (
            "<tr><td colspan='2' class='muted'>"
            "No open ports found in the scanned range.</td></tr>"
        )

    level_pills = "".join(
        "<span class='pill' style='border-color:{0};color:{0}'>{1}: "
        "{2}</span>".format(LEVEL_BADGE[lvl], LEVEL_LABEL[lvl], counts[lvl])
        for lvl in (Level.PASS, Level.WARN, Level.FAIL, Level.INFO, Level.SKIP)
    )
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_pills = "".join(
        "<span class='pill' style='border-color:{0};color:{0}'>{1}: "
        "{2}</span>".format(SEVERITY_COLORS.get(s, "#374151"), s, n)
        for s, n in sorted(sev_counts.items(), key=lambda kv: order.index(kv[0]))
    )
    categories = sorted({c.category for c in result.checks})
    cat_options = "".join(
        "<option>{}</option>".format(html.escape(c)) for c in categories
    )
    scan_targets = html.escape(json.dumps(result.scan_targets or {}), quote=True)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    esc = html.escape

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Audit Report &mdash; {esc(result.host)}</title>
<style>{_CSS}</style>
</head>
<body>
  <h1>Security Audit Report</h1>
  <div class="muted">
    Host: <span class="mono">{esc(result.host)}</span>
    &nbsp;&bull;&nbsp; Platform: {esc(result.platform or "unknown")}
    &nbsp;&bull;&nbsp; Tool: {esc(result.tool or TOOL_NAME)}
  </div>
  <div class="meta">
    Started: {esc(result.started_at)} &nbsp;&bull;&nbsp;
    Finished: {esc(result.finished_at)} &nbsp;&bull;&nbsp;
    Duration: {result.duration_ms} ms &nbsp;&bull;&nbsp;
    Checks: {len(result.checks)}
  </div>
  <div class="grid">
    <div class="card">
      <div class="big" style="color:{_score_color(result.score)}">
        {result.score}
      </div>
      <div class="muted">Hardening Score (severity-weighted, 0-100)</div>
    </div>
    <div class="card">
      <div class="big">{len(result.checks)}</div>
      <div class="muted">Checks Run</div>
      <div style="margin-top:6px">{level_pills}</div>
    </div>
    <div class="card">
      <div class="big">{len(result.open_ports)}</div>
      <div class="muted">Open Ports Found</div>
    </div>
    <div class="card">
      <div class="muted" style="margin-bottom:6px">
        Severity mix (actionable)
      </div>
      {sev_pills}
    </div>
  </div>
  <h2>Configuration Checks</h2>
  <div class="filters">
    <select id="f-level" onchange="applyFilters()">
      <option value="">All results</option>
      <option value="FAIL">Fail</option>
      <option value="WARN">Warning</option>
      <option value="PASS">Pass</option>
      <option value="INFO">Info</option>
      <option value="SKIP">Skipped</option>
    </select>
    <select id="f-cat" onchange="applyFilters()">
      <option value="">All categories</option>{cat_options}
    </select>
    <input id="f-q" type="search" placeholder="search id or title..."
           oninput="applyFilters()">
    <span id="f-count" class="muted"></span>
  </div>
  <table id="checks">
    <thead>
      <tr>
        <th>ID</th><th>Check</th><th>Category</th><th>Sev</th>
        <th>Ref</th><th>Result</th><th>Detail</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
  <h2>Open Ports ({len(result.open_ports)})</h2>
  <table>
    <thead><tr><th>Port</th><th>Service</th></tr></thead>
    <tbody>{open_ports_rows}</tbody>
  </table>
  <p class="muted">
    Scan parameters: <span class="mono">{scan_targets}</span>
  </p>
  <footer class="muted">
    Generated by {TOOL_NAME} v{__version__} on {generated_at}.
  </footer>
<script>{_JS}</script>
</body>
</html>"""


def _validate(result: ScanResult) -> None:
    """Validate the JSON document against the bundled schema (if jsonschema
    is installed). Raises RuntimeError on failure."""
    if not _HAS_JSONSCHEMA:
        return
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    try:
        jsonschema.validate(instance=result.to_dict(), schema=schema)
    except jsonschema.ValidationError as exc:
        raise RuntimeError(f"report validation failed: {exc.message}") from exc


WRITE_FORMATS = ("json", "html", "csv", "sarif")


def write_reports(
    result: ScanResult, out_dir: str, formats: Sequence[str] = ("json", "html")
) -> Dict[str, str]:
    """Write the requested report formats and return {format: path}.

    *formats* may include any of: json, html, csv, sarif. The JSON document is
    schema-validated before any file is written (when jsonschema is present),
    so a broken report never leaves the tool silently.
    """
    unknown = [f for f in formats if f not in WRITE_FORMATS]
    if unknown:
        raise ValueError(f"unknown report format(s): {', '.join(unknown)}")
    os.makedirs(out_dir, exist_ok=True)
    _validate(result)

    base = f"audit_{result.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    writers = {
        "json": (".json", to_json),
        "html": (".html", to_html),
        "csv": (".csv", to_csv),
        "sarif": (".sarif.json", to_sarif),
    }
    paths: Dict[str, str] = {}
    for fmt in formats:
        ext, writer = writers[fmt]
        path = os.path.join(out_dir, base + ext)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(writer(result))
        paths[fmt] = path
    return paths


def utc_now_iso() -> str:
    """UTC timestamp in ISO-8601 (used by SARIF, which requires UTC)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

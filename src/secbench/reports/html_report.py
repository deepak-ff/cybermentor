"""Render a self-contained HTML report via Jinja2."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..engine.models import Status
from ..engine.runner import RunResult


def _build_env() -> Environment:
    pkg_files = resources.files("secbench.reports.templates")
    with resources.as_file(pkg_files) as path:
        loader = FileSystemLoader(searchpath=str(path))
    env = Environment(loader=loader, autoescape=select_autoescape(["html", "xml"]))
    env.filters["status_color"] = lambda s: Status(s).color if s else "#777"
    env.filters["status_label"] = lambda s: Status(s).label if s else ""
    return env


def render_html(run: RunResult, out_path: str | Path) -> Path:
    env = _build_env()
    tpl = env.get_template("report.html.j2")
    by_id_lookup: dict[str, dict[str, Any]] = {}
    for bench in run.benchmarks:
        for sec in bench.sections:
            for ctrl in sec.controls:
                by_id_lookup[ctrl.id] = {
                    "section": sec.id,
                    "section_title": sec.title,
                    "title": ctrl.title,
                    "level": ctrl.level,
                    "rationale": ctrl.rationale,
                    "audit": ctrl.audit,
                    "remediation": ctrl.remediation,
                    "references": ctrl.references,
                }
    html = tpl.render(run=run, by_id=by_id_lookup, statuses=list(Status))
    out = Path(out_path)
    out.write_text(html, encoding="utf-8")
    return out

"""PDF rendering: prefer WeasyPrint, fall back to ReportLab when unavailable."""

from __future__ import annotations

import logging
from pathlib import Path

from ..engine.models import Status
from ..engine.runner import RunResult
from .html_report import render_html

log = logging.getLogger(__name__)


def render_pdf(run: RunResult, out_path: str | Path) -> Path:
    out = Path(out_path)
    # Prefer WeasyPrint by rendering the HTML report then converting it.
    try:
        from weasyprint import HTML  # type: ignore
        tmp_html = out.with_suffix(".html")
        render_html(run, tmp_html)
        HTML(filename=str(tmp_html)).write_pdf(str(out))
        try:
            tmp_html.unlink()
        except OSError:
            pass
        return out
    except Exception as exc:  # WeasyPrint requires native deps
        log.warning("WeasyPrint unavailable (%s); falling back to ReportLab", exc)

    return _render_pdf_reportlab(run, out)


def _render_pdf_reportlab(run: RunResult, out: Path) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )

    styles = getSampleStyleSheet()
    title = styles["Title"]
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)

    doc = SimpleDocTemplate(str(out), pagesize=LETTER, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    story: list = []
    story.append(Paragraph("Sec-Benchmarks Report", title))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Generated {run.finished_at.isoformat() if run.finished_at else ''} - "
        f"Tenant {run.tenant_id or 'n/a'} - Subscriptions: {len(run.subscription_ids)}",
        body,
    ))
    story.append(Spacer(1, 12))

    summary = run.summary()
    for bench in run.benchmarks:
        story.append(PageBreak())
        story.append(Paragraph(f"{bench.title} ({bench.version})", h1))
        story.append(Spacer(1, 6))
        counts = summary.get(bench.id, {})
        cells = [["Status", "Count"]]
        for s in ("pass", "fail", "manual", "not_applicable", "error", "skipped"):
            cells.append([Status(s).label, str(counts.get(s, 0))])
        t = Table(cells, hAlign="LEFT", colWidths=[120, 60])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#33506b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        for sec in bench.sections:
            sec_results = [r for r in run.results.get(bench.id, []) if r.control_id.startswith(f"CIS-")]
            sec_results = [r for r in run.results.get(bench.id, [])]
            sec_results = [r for r in sec_results if any(c.id == r.control_id for c in sec.controls)]
            if not sec_results:
                continue
            story.append(Paragraph(f"{sec.id} - {sec.title}", h2))
            rows = [["Control", "Level", "Status", "Summary"]]
            for r in sec_results:
                ctrl = next((c for c in sec.controls if c.id == r.control_id), None)
                rows.append([
                    Paragraph(f"<b>{r.control_id}</b><br/>{ctrl.title if ctrl else ''}", small),
                    str(ctrl.level) if ctrl else "-",
                    r.status.label,
                    Paragraph(r.summary or "", small),
                ])
            tbl = Table(rows, colWidths=[170, 38, 60, 240])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#33506b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(tbl)
            story.append(Spacer(1, 8))

    doc.build(story)
    return out

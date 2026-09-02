"""Reports page: export the last run to HTML / JSON / CSV / PDF."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...config import reports_dir
from ...engine.runner import RunResult
from ...reports import render_csv, render_html, render_json, render_pdf

if TYPE_CHECKING:
    from ..main_window import MainWindow

log = logging.getLogger(__name__)


class ReportsPage(QWidget):
    def __init__(self, main: "MainWindow") -> None:
        super().__init__()
        self.main = main
        self._run: Optional[RunResult] = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(QLabel("<h2>Reports</h2>"))

        self.summary_label = QLabel("Run a benchmark first to enable export.")
        layout.addWidget(self.summary_label)

        button_row = QHBoxLayout()
        self.html_btn = QPushButton("Export HTML")
        self.json_btn = QPushButton("Export JSON")
        self.csv_btn = QPushButton("Export CSV")
        self.pdf_btn = QPushButton("Export PDF")
        for b in (self.html_btn, self.json_btn, self.csv_btn, self.pdf_btn):
            b.setEnabled(False)
            button_row.addWidget(b)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        self.html_btn.clicked.connect(lambda: self._export("html"))
        self.json_btn.clicked.connect(lambda: self._export("json"))
        self.csv_btn.clicked.connect(lambda: self._export("csv"))
        self.pdf_btn.clicked.connect(lambda: self._export("pdf"))

        layout.addWidget(QLabel("<b>Export all formats</b>"))
        self.export_all_btn = QPushButton("Export HTML + JSON + CSV + PDF to folder...")
        self.export_all_btn.setEnabled(False)
        self.export_all_btn.clicked.connect(self._export_all)
        layout.addWidget(self.export_all_btn)

        self.last_path_label = QLabel("")
        layout.addWidget(self.last_path_label)
        layout.addStretch(1)

    def set_run(self, run: RunResult) -> None:
        self._run = run
        if run is None:
            self.summary_label.setText("No run available.")
            for b in (self.html_btn, self.json_btn, self.csv_btn, self.pdf_btn, self.export_all_btn):
                b.setEnabled(False)
            return
        total = sum(len(v) for v in run.results.values())
        self.summary_label.setText(
            f"Run available: {len(run.benchmarks)} benchmark(s), {total} controls evaluated."
        )
        for b in (self.html_btn, self.json_btn, self.csv_btn, self.pdf_btn, self.export_all_btn):
            b.setEnabled(True)

    def _export(self, fmt: str) -> None:
        if self._run is None:
            return
        ext_map = {"html": ".html", "json": ".json", "csv": ".csv", "pdf": ".pdf"}
        ext = ext_map[fmt]
        default = str(Path(reports_dir()) / f"secbench-report{ext}")
        target, _ = QFileDialog.getSaveFileName(self, f"Export {fmt.upper()}", default, f"*{ext}")
        if not target:
            return
        try:
            if fmt == "html":
                p = render_html(self._run, target)
            elif fmt == "json":
                p = render_json(self._run, target)
            elif fmt == "csv":
                p = render_csv(self._run, target)
            else:
                p = render_pdf(self._run, target)
        except Exception as exc:
            log.exception("Export failed")
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self.last_path_label.setText(f"Saved: {p}")

    def _export_all(self) -> None:
        if self._run is None:
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose output folder", str(reports_dir()))
        if not folder:
            return
        base = Path(folder) / "secbench-report"
        try:
            render_html(self._run, base.with_suffix(".html"))
            render_json(self._run, base.with_suffix(".json"))
            render_csv(self._run, base.with_suffix(".csv"))
            render_pdf(self._run, base.with_suffix(".pdf"))
        except Exception as exc:
            log.exception("Export all failed")
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        self.last_path_label.setText(f"Saved 4 files to {folder}")

"""Results page: tree view (benchmark -> section -> control) with detail pane."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QStandardItem, QStandardItemModel, QColor
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from ...engine.models import Status
from ...engine.runner import RunResult

if TYPE_CHECKING:
    from ..main_window import MainWindow


class ResultsPage(QWidget):
    def __init__(self, main: "MainWindow") -> None:
        super().__init__()
        self.main = main
        self._run: Optional[RunResult] = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(QLabel("<h2>Results</h2>"))

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by control ID, title, or status...")
        self.filter_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filter_edit)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeView()
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setEditTriggers(QTreeView.EditTrigger.NoEditTriggers)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Control", "Status", "Summary"])
        self.tree.setModel(self.model)
        self.tree.selectionModel().selectionChanged.connect(self._on_selection)
        splitter.addWidget(self.tree)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

    def load(self, run: RunResult) -> None:
        self._run = run
        self.model.removeRows(0, self.model.rowCount())
        for bench in run.benchmarks:
            results_by_id = {r.control_id: r for r in run.results.get(bench.id, [])}
            bench_item = QStandardItem(f"{bench.title} ({bench.version})")
            counts = run.summary().get(bench.id, {})
            bench_status = QStandardItem(
                f"P:{counts.get('pass',0)} F:{counts.get('fail',0)} M:{counts.get('manual',0)} E:{counts.get('error',0)}"
            )
            bench_summary = QStandardItem("")
            for sec in bench.sections:
                sec_results = [results_by_id[c.id] for c in sec.controls if c.id in results_by_id]
                if not sec_results:
                    continue
                sec_item = QStandardItem(f"{sec.id}  {sec.title}")
                sec_status = QStandardItem("")
                sec_summary = QStandardItem("")
                for c in sec.controls:
                    r = results_by_id.get(c.id)
                    if r is None:
                        continue
                    name_item = QStandardItem(f"{c.id}  {c.title}")
                    status_item = QStandardItem(r.status.label)
                    status_item.setForeground(QColor(r.status.color))
                    summary_item = QStandardItem(r.summary)
                    name_item.setData({"control": c, "result": r}, Qt.ItemDataRole.UserRole)
                    sec_item.appendRow([name_item, status_item, summary_item])
                bench_item.appendRow([sec_item, sec_status, sec_summary])
            self.model.appendRow([bench_item, bench_status, bench_summary])
        self.tree.expandToDepth(0)
        for col in (0, 1, 2):
            self.tree.resizeColumnToContents(col)

    def _on_selection(self, *_) -> None:
        idx = self.tree.currentIndex()
        if not idx.isValid():
            return
        item = self.model.itemFromIndex(idx.siblingAtColumn(0))
        if item is None:
            return
        payload = item.data(Qt.ItemDataRole.UserRole)
        if not payload:
            self.detail.setPlainText("")
            return
        ctrl = payload["control"]
        result = payload["result"]
        lines = [
            f"{ctrl.id}: {ctrl.title}",
            f"Section: {ctrl.section}    Level: {ctrl.level}",
            f"Status:  {result.status.label}",
            f"Summary: {result.summary}",
            "",
            "Rationale:",
            ctrl.rationale or "(see CIS benchmark)",
            "",
            "Audit:",
            ctrl.audit or "(see CIS benchmark)",
            "",
            "Remediation:",
            ctrl.remediation or "(see CIS benchmark)",
        ]
        if result.evidence:
            lines += ["", "Evidence:", json.dumps(result.evidence, indent=2, default=str)]
        if result.error:
            lines += ["", f"Error: {result.error}"]
        self.detail.setPlainText("\n".join(lines))

    def _apply_filter(self, text: str) -> None:
        text = (text or "").lower().strip()
        for row in range(self.model.rowCount()):
            bench_item = self.model.item(row, 0)
            bench_visible = False
            for srow in range(bench_item.rowCount()):
                sec_item = bench_item.child(srow, 0)
                sec_visible = False
                for crow in range(sec_item.rowCount()):
                    name_item = sec_item.child(crow, 0)
                    status_item = sec_item.child(crow, 1)
                    summary_item = sec_item.child(crow, 2)
                    blob = " ".join(
                        x.text() for x in (name_item, status_item, summary_item) if x is not None
                    ).lower()
                    visible = (text in blob) if text else True
                    self.tree.setRowHidden(crow, sec_item.index(), not visible)
                    if visible:
                        sec_visible = True
                self.tree.setRowHidden(srow, bench_item.index(), not sec_visible)
                if sec_visible:
                    bench_visible = True
            self.tree.setRowHidden(row, self.model.invisibleRootItem().index(), not bench_visible)

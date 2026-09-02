"""Benchmarks page: choose which benchmarks and which level."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from ..main_window import MainWindow


class BenchmarksPage(QWidget):
    def __init__(self, main: "MainWindow") -> None:
        super().__init__()
        self.main = main
        self._build_ui()
        self.main.benchmarks_loaded.connect(self._populate)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(QLabel("<h2>Choose benchmarks</h2>"))

        # Two side-by-side group boxes: Cloud (Azure/M365) and
        # Infrastructure (macOS/Linux). They are populated dynamically from
        # the bench.target attribute when benchmarks are loaded.
        groups_row = QHBoxLayout()
        self.cloud_box = QGroupBox("Cloud (Azure / M365)")
        self.cloud_layout = QVBoxLayout(self.cloud_box)
        self.infra_box = QGroupBox("Infrastructure")
        self.infra_layout = QVBoxLayout(self.infra_box)
        groups_row.addWidget(self.cloud_box, 1)
        groups_row.addWidget(self.infra_box, 1)
        layout.addLayout(groups_row)

        opts = QGroupBox("Options")
        opts_layout = QFormLayout(opts)
        self.level_combo = QComboBox()
        self.level_combo.addItems(["Level 1 only", "Level 1 + Level 2"])
        self.level_combo.setCurrentIndex(1 if self.main.settings.level_filter >= 2 else 0)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["E3", "E5"])
        self.profile_combo.setCurrentText(self.main.settings.profile)

        self.cache_chk = QCheckBox("Share cached API responses across checks")
        self.cache_chk.setChecked(self.main.settings.use_response_cache)
        self.manual_chk = QCheckBox("Include controls flagged as manual review")
        self.manual_chk.setChecked(self.main.settings.include_manual)

        opts_layout.addRow("CIS Level", self.level_combo)
        opts_layout.addRow("M365 profile", self.profile_combo)
        opts_layout.addRow(self.cache_chk)
        opts_layout.addRow(self.manual_chk)
        layout.addWidget(opts)

        run_row = QHBoxLayout()
        self.go_btn = QPushButton("Continue to Run \u2192")
        self.go_btn.setDefault(True)
        self.go_btn.clicked.connect(self._on_continue)
        run_row.addStretch(1)
        run_row.addWidget(self.go_btn)
        layout.addLayout(run_row)
        layout.addStretch(1)

    def _populate(self, benchmarks) -> None:
        # Clear and rebuild both group boxes.
        for layout in (self.cloud_layout, self.infra_layout):
            while layout.count():
                item = layout.takeAt(0)
                w = item.widget()
                if w is not None:
                    w.deleteLater()
        self.checks: dict[str, QCheckBox] = {}
        sel = set(self.main.settings.selected_benchmarks)
        for bench in benchmarks:
            beta_tag = "  [BETA / in development]" if getattr(bench, "beta", False) else ""
            cb = QCheckBox(
                f"{bench.title} ({bench.version}) - {len(bench.all_controls())} controls{beta_tag}"
            )
            if getattr(bench, "beta", False):
                cb.setStyleSheet("QCheckBox { color: #b08900; }")
                cb.setToolTip(
                    "This benchmark is in development. Coverage and accuracy of automated\n"
                    "checks are still being validated. Treat results as advisory."
                )
            cb.setChecked(bench.id in sel)
            target = getattr(bench, "target", "azure")
            if target in ("azure", "m365"):
                self.cloud_layout.addWidget(cb)
            else:  # macos, rhel, etc.
                self.infra_layout.addWidget(cb)
            self.checks[bench.id] = cb
        self.cloud_layout.addStretch(1)
        self.infra_layout.addStretch(1)

    def selected_benchmark_ids(self) -> list[str]:
        return [bid for bid, cb in self.checks.items() if cb.isChecked()]

    def level_max(self) -> int:
        return 1 if self.level_combo.currentIndex() == 0 else 2

    def _on_continue(self) -> None:
        self.main.settings.selected_benchmarks = self.selected_benchmark_ids()
        self.main.settings.level_filter = self.level_max()
        self.main.settings.profile = self.profile_combo.currentText()
        self.main.settings.use_response_cache = self.cache_chk.isChecked()
        self.main.settings.include_manual = self.manual_chk.isChecked()
        self.main.settings.save()
        self.main.nav.setCurrentRow(2)

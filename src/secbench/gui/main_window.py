"""Main application window: stacked pages + sidebar navigation."""

from __future__ import annotations

import logging
from importlib import resources
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ..auth import AuthManager
from ..config import Settings
from ..elevation import is_admin, is_windows, relaunch_as_admin
from ..engine import load_all_benchmarks
from ..engine.runner import RunResult
from .pages.benchmarks_page import BenchmarksPage
from .pages.connect_page import ConnectPage
from .pages.reports_page import ReportsPage
from .pages.results_page import ResultsPage
from .pages.run_page import RunPage

log = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    benchmarks_loaded = pyqtSignal(list)
    auth_changed = pyqtSignal(object)
    run_finished = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Sec-Benchmarks")
        self.resize(1180, 760)

        self.settings = Settings.load()
        self.auth = AuthManager()
        self.benchmarks = load_all_benchmarks()
        self.last_run: Optional[RunResult] = None

        self._apply_stylesheet()
        self._build_ui()
        self.benchmarks_loaded.emit(self.benchmarks)

    # -------------------------------------------------------- styling helpers
    def _apply_stylesheet(self) -> None:
        try:
            files = resources.files("secbench.gui")
            with resources.as_file(files.joinpath("style.qss")) as p:
                self.setStyleSheet(Path(p).read_text(encoding="utf-8"))
        except Exception:
            pass

    # ----------------------------------------------------------------- layout
    def _build_ui(self) -> None:
        central = QWidget(self)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        body = QWidget()
        layout = QHBoxLayout(body)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.nav = QListWidget()
        self.nav.setFixedWidth(200)
        for label in ("Connect", "Benchmarks", "Run", "Results", "Reports"):
            QListWidgetItem(label, self.nav)
        self.nav.setCurrentRow(0)

        self.stack = QStackedWidget()
        self.connect_page = ConnectPage(self)
        self.benchmarks_page = BenchmarksPage(self)
        self.run_page = RunPage(self)
        self.results_page = ResultsPage(self)
        self.reports_page = ReportsPage(self)
        for w in (
            self.connect_page,
            self.benchmarks_page,
            self.run_page,
            self.results_page,
            self.reports_page,
        ):
            self.stack.addWidget(w)

        layout.addWidget(self.nav)
        layout.addWidget(self.stack, 1)

        outer.addWidget(body, 1)
        self._build_elevation_banner(outer)

        self.setCentralWidget(central)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)

        sb = QStatusBar()
        self.status_label = QLabel("Not signed in")
        sb.addWidget(self.status_label)
        sb.addPermanentWidget(QLabel("Sec-Benchmarks 0.1.0"))
        self.setStatusBar(sb)

        # Wire cross-page signals.
        self.auth_changed.connect(self._on_auth_changed)
        self.run_finished.connect(self._on_run_finished)

    # ----------------------------------------------------- elevation banner
    def _build_elevation_banner(self, outer: QVBoxLayout) -> None:
        """Show a yellow banner at the bottom on Windows when unelevated.

        Windows benchmarks running against the local target need admin
        rights for things like ``secedit /export``, ``auditpol``,
        ``Get-MpPreference``, ``Get-BitLockerVolume``, and most
        privileged registry keys. Without elevation those checks return
        MANUAL or FAIL.
        """
        self.elevation_banner = QFrame()
        self.elevation_banner.setObjectName("elevationBanner")
        self.elevation_banner.setStyleSheet(
            "QFrame#elevationBanner {"
            " background-color: #fff4cc;"
            " border-top: 1px solid #d4b800;"
            "}"
            "QFrame#elevationBanner QLabel { color: #5b4500; }"
        )
        bl = QHBoxLayout(self.elevation_banner)
        bl.setContentsMargins(12, 8, 12, 8)
        bl.setSpacing(12)
        msg = QLabel(
            "Running unelevated on Windows. Local Windows benchmark checks "
            "that need administrator rights (secedit, auditpol, Defender, "
            "BitLocker, privileged registry) will return MANUAL or FAIL "
            "until the app is restarted with elevation."
        )
        msg.setWordWrap(True)
        bl.addWidget(msg, 1)
        self.elevate_btn = QPushButton("Restart as administrator")
        self.elevate_btn.clicked.connect(self._on_restart_elevated)
        bl.addWidget(self.elevate_btn, 0, Qt.AlignmentFlag.AlignRight)

        outer.addWidget(self.elevation_banner)

        # Only show the banner on Windows when we are NOT elevated.
        if not (is_windows() and not is_admin()):
            self.elevation_banner.hide()

    def _on_restart_elevated(self) -> None:
        reply = QMessageBox.question(
            self,
            "Restart as administrator",
            "SecBench will close and re-launch with elevated privileges. "
            "You will need to re-sign-in to Azure if you want to run cloud "
            "benchmarks. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            self.settings.save()
        except Exception:
            log.exception("Failed to persist settings before relaunch")

        if not relaunch_as_admin():
            QMessageBox.warning(
                self,
                "Elevation declined",
                "The elevation request was declined or failed. "
                "SecBench is still running unelevated.\n\n"
                "If you accepted UAC but the new window did not appear, "
                "see %TEMP%\\secbench_elevation.log for the exact command "
                "we tried to execute.",
            )
            return

        # New elevated process is starting. Tear down this one cleanly
        # via QApplication.quit() so the Qt event loop unwinds. A short
        # delay lets the new process register with Windows before the
        # original exits (avoids a brief no-window flash).
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication
        app = QApplication.instance()
        QTimer.singleShot(400, app.quit if app else self.close)

    # ---------------------------------------------------------------- signals
    def _on_auth_changed(self, bundle) -> None:
        if bundle is None:
            self.status_label.setText("Not signed in")
        else:
            self.status_label.setText(
                f"Signed in via {bundle.method.value} (tenant {bundle.tenant_id or 'unknown'})"
            )

    def _on_run_finished(self, run: RunResult) -> None:
        self.last_run = run
        self.results_page.load(run)
        self.reports_page.set_run(run)
        self.nav.setCurrentRow(3)

    # ------------------------------------------------------------ shutdown
    def closeEvent(self, event):  # noqa: N802 - Qt API
        try:
            self.settings.save()
            self.auth.sign_out()
        finally:
            super().closeEvent(event)

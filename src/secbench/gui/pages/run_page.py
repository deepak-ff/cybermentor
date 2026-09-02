"""Run page: kicks off the benchmark runner in a worker thread."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import QObject, QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...azure_client import ResponseCache
from ...engine import Context
from ...engine.progress import ProgressEvent
from ...engine.runner import RunResult, Runner

if TYPE_CHECKING:
    from ..main_window import MainWindow

log = logging.getLogger(__name__)


class _RunWorker(QObject):
    progress = pyqtSignal(object)
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)
    log_line = pyqtSignal(str)

    def __init__(
        self,
        ctx: Context,
        benchmarks,
        level_max: int,
        include_manual: bool,
    ) -> None:
        super().__init__()
        self.ctx = ctx
        self.benchmarks = benchmarks
        self.level_max = level_max
        self.include_manual = include_manual
        self.cancel_event = threading.Event()

    def run(self) -> None:
        self.ctx.cancel_event = self.cancel_event

        def _on_progress(evt: ProgressEvent) -> None:
            self.progress.emit(evt)

        runner = Runner()
        try:
            self.log_line.emit("Starting benchmark run...")
            result: RunResult = asyncio.run(
                runner.run(
                    self.ctx,
                    self.benchmarks,
                    level_max=self.level_max,
                    progress=_on_progress,
                    include_manual=self.include_manual,
                )
            )
            self.log_line.emit(
                f"Run complete in {(result.finished_at - result.started_at).total_seconds():.1f}s"
            )
            self.finished_ok.emit(result)
        except Exception as exc:
            log.exception("Run failed")
            self.failed.emit(str(exc))


class RunPage(QWidget):
    def __init__(self, main: "MainWindow") -> None:
        super().__init__()
        self.main = main
        self._thread: Optional[QThread] = None
        self._worker: Optional[_RunWorker] = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(QLabel("<h2>Run benchmarks</h2>"))

        self.bars_container = QVBoxLayout()
        layout.addLayout(self.bars_container)

        button_row = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.start_btn.setDefault(True)
        self.start_btn.clicked.connect(self._on_start)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel)
        button_row.addWidget(self.start_btn)
        button_row.addWidget(self.cancel_btn)
        button_row.addStretch(1)
        layout.addLayout(button_row)

        # Currently-running list - updated live as checks start/finish.
        self.running_label = QLabel("Idle")
        self.running_label.setWordWrap(True)
        self.running_label.setStyleSheet(
            "QLabel { color: #1f6feb; padding: 4px 0; }"
        )
        layout.addWidget(self.running_label)

        layout.addWidget(QLabel("<b>Log</b>"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)  # keep memory bounded
        layout.addWidget(self.log_view, 1)

        self._bars: dict[str, QProgressBar] = {}
        self._labels: dict[str, QLabel] = {}
        self._running: dict[str, set[str]] = {}     # bench_id -> {control_id...}
        self._counts: dict[str, dict[str, int]] = {}  # bench_id -> {status -> count}

    def _ensure_bars(self, selected_ids: list[str], level_max: int) -> None:
        # Clear old.
        while self.bars_container.count():
            item = self.bars_container.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
        self._bars = {}
        self._labels = {}
        self._running = {}
        self._counts = {}
        for bench in self.main.benchmarks:
            if bench.id not in selected_ids:
                continue
            estimated = sum(1 for c in bench.all_controls() if c.level <= level_max)
            row = QHBoxLayout()
            label = QLabel(f"{bench.title}  -  0 / {estimated}")
            bar = QProgressBar()
            bar.setRange(0, max(1, estimated))
            bar.setValue(0)
            bar.setTextVisible(True)
            bar.setFormat("%v / %m")
            row.addWidget(label, 1)
            row.addWidget(bar, 2)
            self._bars[bench.id] = bar
            self._labels[bench.id] = label
            self._running[bench.id] = set()
            self._counts[bench.id] = {}
            container = QWidget()
            container.setLayout(row)
            self.bars_container.addWidget(container)

    def _on_start(self) -> None:
        selected_ids = self.main.benchmarks_page.selected_benchmark_ids()
        if not selected_ids:
            self._append_log("Pick at least one benchmark.")
            return
        bench_objs = [b for b in self.main.benchmarks if b.id in selected_ids]
        # Sign-in is required only for cloud benchmarks.
        needs_cloud = any(b.target in ("azure", "m365") for b in bench_objs)
        if needs_cloud and self.main.auth.bundle is None:
            self._append_log("Sign in on the Connect page first (or pick only the macOS benchmark).")
            return
        sub_ids = self.main.connect_page.selected_subscription_ids()
        # Warn the user if Azure benchmarks are selected but no subscription is ticked.
        needs_subs = any(b.target == "azure" for b in bench_objs)
        if needs_subs and not sub_ids:
            self._append_log(
                "WARNING: no subscriptions are ticked on the Connect page. Azure resource "
                "checks will all evaluate to N/A. Tick at least one subscription, or "
                "deselect the Azure benchmarks."
            )
        # Persist the selection for next session.
        self.main.settings.last_subscription_ids = sub_ids
        self.main.settings.save()

        self._ensure_bars(selected_ids, self.main.benchmarks_page.level_max())
        self.log_view.clear()
        self.running_label.setText("Starting...")
        self._append_log(
            f"Selected {len(bench_objs)} benchmark(s); subscriptions: {', '.join(sub_ids) or 'none'}"
        )

        cache = ResponseCache(enabled=self.main.benchmarks_page.cache_chk.isChecked())

        # Build an OS target if the user picked any infrastructure benchmark
        # (macOS or RHEL).
        target = None
        needs_os_target = any(b.target in ("macos", "rhel", "windows") for b in bench_objs)
        if needs_os_target:
            try:
                target = self.main.connect_page.os_target()
                self.main.connect_page.persist_target_settings()
                self._append_log(f"OS target: {target.describe()}")
            except Exception as exc:
                self._append_log(f"Could not build OS target: {exc}")
                return

        # Auth bundle is optional when only macOS is selected.
        cred = self.main.auth.bundle.credential if self.main.auth.bundle else None
        tenant = self.main.auth.bundle.tenant_id if self.main.auth.bundle else ""
        ctx = Context(
            credential=cred,
            tenant_id=tenant,
            subscription_ids=sub_ids,
            profile=self.main.benchmarks_page.profile_combo.currentText(),
            cache=cache,
            target=target,
        )

        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self._thread = QThread(self)
        self._worker = _RunWorker(
            ctx,
            bench_objs,
            self.main.benchmarks_page.level_max(),
            self.main.benchmarks_page.manual_chk.isChecked(),
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress, Qt.ConnectionType.QueuedConnection)
        self._worker.log_line.connect(self._append_log, Qt.ConnectionType.QueuedConnection)
        self._worker.finished_ok.connect(self._on_finished, Qt.ConnectionType.QueuedConnection)
        self._worker.failed.connect(self._on_failed, Qt.ConnectionType.QueuedConnection)
        self._thread.start()

    def _on_cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel_event.set()
        self._append_log("Cancellation requested...")

    def _on_progress(self, evt: ProgressEvent) -> None:
        bar = self._bars.get(evt.benchmark_id)
        running = self._running.setdefault(evt.benchmark_id, set())
        counts = self._counts.setdefault(evt.benchmark_id, {})

        if evt.phase == "started":
            running.add(evt.control_id)
        else:
            running.discard(evt.control_id)
            counts[evt.status or "unknown"] = counts.get(evt.status or "unknown", 0) + 1
            if bar is not None:
                bar.setRange(0, max(1, evt.total))
                bar.setValue(evt.completed)
            label = self._labels.get(evt.benchmark_id)
            if label is not None:
                bench_title = next(
                    (b.title for b in self.main.benchmarks if b.id == evt.benchmark_id),
                    evt.benchmark_id,
                )
                stats = " ".join(
                    f"{k}:{v}" for k, v in counts.items() if k != "unknown"
                )
                label.setText(
                    f"{bench_title}  -  {evt.completed} / {evt.total}    {stats}"
                )
            short = (evt.title or "").strip()
            if len(short) > 90:
                short = short[:87] + "..."
            self._append_log(
                f"[{evt.benchmark_id}] {evt.control_id} -> {evt.status}  {short}"
            )

        # "Running" label shows only the current module (benchmark) being
        # processed, not the in-flight control list.
        active_bench = next(
            (bid for bid, ids in self._running.items() if ids), None
        )
        if active_bench:
            title = next(
                (b.title for b in self.main.benchmarks if b.id == active_bench),
                active_bench,
            )
            self.running_label.setText(f"Running: {title}")
        else:
            self.running_label.setText("Idle")

    def _append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    def _on_finished(self, run: RunResult) -> None:
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        if self._thread:
            self._thread.quit()
            self._thread.wait(2000)
        self.running_label.setText("Run finished.")
        self._append_log("Run finished.")
        self.main.run_finished.emit(run)

    def _on_failed(self, error: str) -> None:
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        if self._thread:
            self._thread.quit()
            self._thread.wait(2000)
        self._append_log(f"Run failed: {error}")

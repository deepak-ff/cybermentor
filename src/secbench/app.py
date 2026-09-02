"""Application launcher (PyQt6 + qasync event loop)."""

from __future__ import annotations

import asyncio
import sys

from .logging_setup import setup_logging


def main() -> int:
    setup_logging()
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print(
            "PyQt6 is not installed. Install dependencies with: pip install -e .",
            file=sys.stderr,
        )
        return 1

    try:
        import qasync
    except ImportError:
        qasync = None  # type: ignore

    from .gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Sec-Benchmarks")
    app.setOrganizationName("Sec-Benchmarks")

    window = MainWindow()
    window.show()

    if qasync is not None:
        loop = qasync.QEventLoop(app)
        asyncio.set_event_loop(loop)
        with loop:
            loop.run_forever()
    else:
        app.exec()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

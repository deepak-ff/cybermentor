"""Windows elevation detection and self-relaunch helper.

Windows assigns a process integrity level at creation time and does
not allow elevating an already-running process in place. The standard
pattern is therefore to re-launch the same executable via
``ShellExecuteW`` with the ``runas`` verb, which presents the UAC
prompt; on acceptance a new elevated process is created and the
original (unelevated) process exits.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    """Return True if the current process is running with admin rights."""
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - defensive
        log.exception("IsUserAnAdmin failed")
        return False


def _quote(s: str) -> str:
    """Quote a single argument for a Windows command line."""
    if not s:
        return '""'
    if any(c in s for c in (" ", "\t", '"')):
        return '"' + s.replace('"', '\\"') + '"'
    return s


def _switch_pythonw_to_python(exe: str) -> str:
    """Prefer ``python.exe`` over ``pythonw.exe`` for the relaunch.

    With ``pythonw.exe`` any startup error in the elevated child is
    silently swallowed (no console attached), which makes diagnosing a
    failed elevation impossible. Swapping in ``python.exe`` keeps a
    visible console for the brief window before our GUI takes over.
    """
    base = os.path.basename(exe)
    if base.lower() == "pythonw.exe":
        candidate = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.exists(candidate):
            return candidate
    return exe


def _build_launch_command() -> tuple[str, list[str]]:
    """Decide how to re-launch the current process.

    Returns ``(executable, argv_list)``. The executable is what
    ``ShellExecuteW`` will spawn; the argv_list is what should follow.
    """
    argv0 = sys.argv[0] if sys.argv else ""

    # 1. PyInstaller / cx_Freeze frozen build: sys.executable is the app exe.
    if getattr(sys, "frozen", False):
        return sys.executable, list(sys.argv[1:])

    # 2. Console-script wrapper produced by pip (``secbench-gui.exe`` or
    #    ``secbench.exe``). On Windows pip drops a launcher .exe in the
    #    venv's Scripts directory; sys.argv[0] points at it. Re-launching
    #    the wrapper directly is the most reliable option.
    if argv0:
        argv0_lower = argv0.lower()
        argv0_base = os.path.basename(argv0_lower)
        if argv0_lower.endswith(".exe") and not argv0_base.startswith(("python", "pythonw")):
            return argv0, list(sys.argv[1:])

    py = _switch_pythonw_to_python(sys.executable)

    # 3. ``python -m secbench`` (or a sub-package with a __main__.py).
    #    sys.argv[0] is the absolute path to that __main__.py.
    if argv0.endswith("__main__.py"):
        # Walk up from the __main__.py to figure out the dotted module
        # name relative to the secbench package.
        p = Path(argv0).resolve()
        parts: list[str] = []
        cur = p.parent
        while cur != cur.parent:
            if cur.name == "secbench":
                parts.append("secbench")
                break
            parts.append(cur.name)
            cur = cur.parent
        module = ".".join(reversed(parts)) if parts and parts[-1] == "secbench" else "secbench"
        return py, ["-m", module, *sys.argv[1:]]

    # 4. ``python /path/to/script.py [args]``
    if argv0.endswith(".py"):
        return py, [argv0, *sys.argv[1:]]

    # 5. Fallback: relaunch the canonical entry point.
    return py, ["-m", "secbench"]


def _write_diag_log(payload: dict) -> Path:
    """Write a small JSON diag log so a failed elevation can be inspected."""
    try:
        diag_path = Path(tempfile.gettempdir()) / "secbench_elevation.log"
        ts = datetime.now().isoformat(timespec="seconds")
        with diag_path.open("a", encoding="utf-8") as f:
            f.write(f"\n=== {ts} ===\n")
            for k, v in payload.items():
                f.write(f"{k}: {v}\n")
        return diag_path
    except Exception:  # pragma: no cover
        return Path()


def relaunch_as_admin() -> bool:
    """Re-launch the current process elevated via ShellExecuteW(runas).

    Returns True if a new elevated process was started successfully (the
    caller should then exit). Returns False if the user declined the UAC
    prompt, the OS is not Windows, or the launch otherwise failed.

    Diagnostics about the chosen command line are written to
    ``%TEMP%\\secbench_elevation.log`` to make a silent failure
    debuggable from a fresh elevated session.
    """
    if not is_windows():
        return False

    exe, params = _build_launch_command()
    param_str = " ".join(_quote(p) for p in params)
    cwd = os.getcwd()

    diag_path = _write_diag_log({
        "phase": "before-ShellExecute",
        "exe": exe,
        "params": param_str,
        "cwd": cwd,
        "sys.executable": sys.executable,
        "sys.argv": sys.argv,
        "sys.frozen": getattr(sys, "frozen", False),
    })
    log.info("Elevation diag log: %s", diag_path)

    try:
        import ctypes

        SW_SHOWNORMAL = 1
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, param_str, cwd, SW_SHOWNORMAL,
        )
        rc_int = int(rc)
        log.info("ShellExecuteW(runas) rc=%s exe=%s args=%s", rc_int, exe, param_str)
        _write_diag_log({"phase": "after-ShellExecute", "rc": rc_int})
        # ShellExecute returns > 32 on success; <= 32 means error code.
        # Common failure: SE_ERR_ACCESSDENIED (5) when the UAC prompt was
        # cancelled by the user.
        return rc_int > 32
    except Exception:
        log.exception("relaunch_as_admin failed")
        _write_diag_log({"phase": "exception"})
        return False

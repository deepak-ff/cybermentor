"""Run shell commands on the machine where the app itself is running."""

from __future__ import annotations

import platform
import shlex
import subprocess
from typing import Sequence

from .base import CommandResult, MachineTarget, TargetError, TargetKind


class LocalTarget(MachineTarget):
    kind = TargetKind.LOCAL

    def __init__(self) -> None:
        self.label = f"local ({platform.system()} {platform.machine()})"

    def run(self, argv: Sequence[str], *, timeout: float = 30.0) -> CommandResult:
        try:
            proc = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            return CommandResult(rc=127, stdout="", stderr=str(exc))
        except subprocess.TimeoutExpired as exc:
            raise TargetError(f"timed out: {' '.join(shlex.quote(a) for a in argv)}") from exc
        except OSError as exc:
            raise TargetError(str(exc)) from exc
        return CommandResult(rc=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or "")

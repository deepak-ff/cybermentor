"""Abstract execution target for OS-level benchmarks (local or remote)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Sequence


class TargetError(Exception):
    """Raised when a remote command fails to execute (transport-level error)."""


class TargetKind(str, Enum):
    LOCAL = "local"
    SSH = "ssh"


@dataclass
class CommandResult:
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class MachineTarget:
    """A machine on which we can run shell commands."""

    kind: TargetKind = TargetKind.LOCAL
    label: str = "local"

    def run(self, argv: Sequence[str], *, timeout: float = 30.0) -> CommandResult:
        raise NotImplementedError

    def run_shell(self, command: str, *, timeout: float = 30.0) -> CommandResult:
        """Run a string through `/bin/sh -c ...` (use sparingly)."""
        return self.run(["/bin/sh", "-c", command], timeout=timeout)

    def close(self) -> None:
        """Free any underlying resources (open SSH session, etc.)."""

    def describe(self) -> str:
        return self.label

"""Pluggable execution targets for OS-level benchmarks (local shell or SSH)."""

from .base import CommandResult, MachineTarget, TargetError, TargetKind
from .local import LocalTarget
from .ssh import SshTarget

__all__ = [
    "CommandResult",
    "MachineTarget",
    "TargetError",
    "TargetKind",
    "LocalTarget",
    "SshTarget",
]

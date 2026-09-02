"""Run shell commands on a remote macOS host over SSH.

Two backends are supported, in order of preference:

* paramiko (Python library) -- used when installed.
* the system `ssh` command -- fallback that requires no extra dependency
  but expects the user to have an SSH agent / key pair set up, or to provide
  a private key file. Password auth is supported via `sshpass` when available.

Either backend reads from the standard OpenSSH key locations unless an
explicit ``key_path`` is provided.
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
from typing import Optional, Sequence

from .base import CommandResult, MachineTarget, TargetError, TargetKind

log = logging.getLogger(__name__)


class SshTarget(MachineTarget):
    kind = TargetKind.SSH

    def __init__(
        self,
        host: str,
        *,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        sudo: bool = False,
        sudo_password: Optional[str] = None,
        connect_timeout: float = 15.0,
    ) -> None:
        if not host:
            raise TargetError("SSH host is required")
        self.host = host
        self.port = int(port or 22)
        self.username = username or os.environ.get("USER") or "root"
        self.password = password
        self.key_path = os.path.expanduser(key_path) if key_path else None
        self.key_passphrase = key_passphrase
        self.sudo = sudo
        self.sudo_password = sudo_password
        self.connect_timeout = connect_timeout
        self.label = f"ssh://{self.username}@{self.host}:{self.port}"

        self._client = None
        self._backend = "ssh-cli"
        try:
            import paramiko  # type: ignore  # noqa: F401
            self._backend = "paramiko"
        except Exception:
            self._backend = "ssh-cli"
        self._connect()

    # --------------------------------------------------------- backend setup
    def _connect(self) -> None:
        if self._backend == "paramiko":
            try:
                import paramiko  # type: ignore
            except Exception as exc:
                self._backend = "ssh-cli"
                log.debug("paramiko unavailable, falling back to ssh CLI: %s", exc)
                return
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
                "timeout": self.connect_timeout,
                "auth_timeout": self.connect_timeout,
                "allow_agent": True,
                "look_for_keys": True,
            }
            if self.password:
                connect_kwargs["password"] = self.password
            if self.key_path:
                try:
                    pk = paramiko.PKey.from_path(self.key_path, password=self.key_passphrase) \
                        if hasattr(paramiko.PKey, "from_path") else None
                    if pk is None:
                        # fallback for older paramiko
                        pk = paramiko.RSAKey.from_private_key_file(self.key_path,
                                                                   password=self.key_passphrase)
                    connect_kwargs["pkey"] = pk
                    connect_kwargs["look_for_keys"] = False
                except Exception as exc:
                    raise TargetError(f"could not load private key {self.key_path}: {exc}") from exc
            try:
                client.connect(**connect_kwargs)
            except Exception as exc:
                raise TargetError(f"SSH connect failed: {exc}") from exc
            self._client = client

    # ----------------------------------------------------------------- close
    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # -------------------------------------------------------------- command
    def _wrap_sudo(self, argv: Sequence[str]) -> list[str]:
        if not self.sudo:
            return list(argv)
        if self.sudo_password:
            return ["sudo", "-S", "-p", "", "--"] + list(argv)
        return ["sudo", "-n", "--"] + list(argv)

    def run(self, argv: Sequence[str], *, timeout: float = 30.0) -> CommandResult:
        argv = self._wrap_sudo(argv)
        if self._backend == "paramiko" and self._client is not None:
            return self._run_paramiko(argv, timeout=timeout)
        return self._run_cli(argv, timeout=timeout)

    # -------------------------------------------------------- paramiko impl
    def _run_paramiko(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        cmd_str = " ".join(shlex.quote(a) for a in argv)
        try:
            stdin, stdout, stderr = self._client.exec_command(  # type: ignore[union-attr]
                cmd_str,
                timeout=timeout,
                get_pty=self.sudo and bool(self.sudo_password),
            )
            if self.sudo and self.sudo_password:
                try:
                    stdin.write(self.sudo_password + "\n")
                    stdin.flush()
                except Exception:
                    pass
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
        except Exception as exc:
            raise TargetError(f"SSH exec failed: {exc}") from exc
        return CommandResult(rc=rc, stdout=out, stderr=err)

    # ---------------------------------------------------- ssh CLI fallback
    def _run_cli(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        ssh = shutil.which("ssh")
        if not ssh:
            raise TargetError("`ssh` command not found and paramiko not installed")
        ssh_cmd = [
            ssh,
            "-p", str(self.port),
            "-o", f"ConnectTimeout={int(self.connect_timeout)}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes" if not (self.password or self.sudo_password) else "BatchMode=no",
        ]
        if self.key_path:
            ssh_cmd += ["-i", self.key_path, "-o", "IdentitiesOnly=yes"]
        ssh_cmd.append(f"{self.username}@{self.host}")
        ssh_cmd.append(" ".join(shlex.quote(a) for a in argv))

        # If password supplied and `sshpass` is available, use it transparently.
        if self.password:
            sshpass = shutil.which("sshpass")
            if sshpass is None:
                raise TargetError(
                    "Password authentication requires either paramiko or `sshpass` to be installed."
                )
            ssh_cmd = [sshpass, "-p", self.password] + ssh_cmd

        try:
            proc = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TargetError(f"timed out: {' '.join(argv)}") from exc
        return CommandResult(rc=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or "")

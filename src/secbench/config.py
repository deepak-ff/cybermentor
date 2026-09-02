"""Application configuration helpers (paths, persisted settings)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from platformdirs import user_cache_dir, user_config_dir, user_data_dir
except Exception:  # pragma: no cover - fallback if platformdirs is missing
    def user_config_dir(app: str, *_a, **_kw) -> str:
        return str(Path.home() / f".{app}")

    def user_cache_dir(app: str, *_a, **_kw) -> str:
        return str(Path.home() / f".{app}" / "cache")

    def user_data_dir(app: str, *_a, **_kw) -> str:
        return str(Path.home() / f".{app}" / "data")


APP_NAME = "Sec-Benchmarks"
APP_AUTHOR = "Sec-Benchmarks"


def config_dir() -> Path:
    p = Path(user_config_dir(APP_NAME, APP_AUTHOR))
    p.mkdir(parents=True, exist_ok=True)
    return p


def cache_dir() -> Path:
    p = Path(user_cache_dir(APP_NAME, APP_AUTHOR))
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    p = Path(user_data_dir(APP_NAME, APP_AUTHOR))
    p.mkdir(parents=True, exist_ok=True)
    return p


def reports_dir() -> Path:
    p = data_dir() / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def settings_file() -> Path:
    return config_dir() / "settings.json"


@dataclass
class Settings:
    last_tenant_id: str = ""
    last_auth_method: str = "interactive"  # interactive | device_code | service_principal
    last_client_id: str = ""
    last_subscription_ids: list[str] = field(default_factory=list)
    selected_benchmarks: list[str] = field(default_factory=list)
    level_filter: int = 2  # include up to L1+L2; 1 means L1 only
    include_manual: bool = True
    use_response_cache: bool = True
    output_dir: str = ""
    profile: str = "E3"  # M365 license profile (E3, E5)
    macos_target_kind: str = "local"  # local | ssh   (legacy alias for os_target_kind)
    os_target_kind: str = "local"     # local | ssh   (used by macOS + RHEL benchmarks)
    macos_ssh_host: str = ""
    macos_ssh_port: int = 22
    macos_ssh_user: str = ""
    macos_ssh_key_path: str = ""
    macos_ssh_use_sudo: bool = False

    @classmethod
    def load(cls) -> "Settings":
        path = settings_file()
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            except Exception:
                pass
        s = cls()
        s.output_dir = str(reports_dir())
        return s

    def save(self) -> None:
        path = settings_file()
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


def env_default(key: str, default: str = "") -> str:
    return os.environ.get(key, default)

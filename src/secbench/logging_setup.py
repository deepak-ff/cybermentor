"""Centralized logging configuration."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from .config import data_dir


def setup_logging(level: int = logging.INFO) -> Path:
    log_path = data_dir() / "secbench.log"
    fmt = "%(asctime)s %(levelname)-7s %(name)s :: %(message)s"
    handlers: list[logging.Handler] = [
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        ),
    ]
    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)
    # Quiet down very noisy SDK loggers by default.
    for noisy in (
        "azure.core.pipeline.policies.http_logging_policy",
        "azure.identity",
        "msal",
        "urllib3",
        "msrest",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return log_path

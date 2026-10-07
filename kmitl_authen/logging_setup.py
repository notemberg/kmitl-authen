"""Logging: console + rotating file, optional JSON, with secret redaction.

The old script printed box-drawing characters straight to ``stdout``. On a
Windows console running a non-UTF-8 code page (cp874 for a Thai locale, cp437
elsewhere) that raises ``UnicodeEncodeError`` from inside the main loop and
kills the process. Everything here goes through logging, and stdio is forced to
UTF-8 with ``errors="replace"`` so a glyph can never take the daemon down.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import time
from pathlib import Path

LOG_NAME = "kmitl_authen"

# Extra keys attached via ``logger.info(..., extra={...})`` that we want to see.
_RESERVED = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime", "taskName"}


class RedactFilter(logging.Filter):
    """Replace secret substrings anywhere in a formatted record."""

    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        self.secrets = [s for s in secrets if s and len(s) >= 3]

    def filter(self, record: logging.LogRecord) -> bool:
        if not self.secrets:
            return True
        try:
            text = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        changed = False
        for secret in self.secrets:
            if secret in text:
                text = text.replace(secret, "***")
                changed = True
        if changed:
            record.msg = text
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    converter = time.localtime

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    """``ts LEVEL event key=value ...`` — greppable, still readable."""

    converter = time.localtime
    default_time_format = "%Y-%m-%d %H:%M:%S"
    default_msec_format = None  # no milliseconds; keeps lines short

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED and not k.startswith("_")
        }
        if extras:
            base += " " + " ".join(f"{k}={v}" for k, v in extras.items())
        return base


def _force_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - exotic hosts
            pass


def supports_unicode() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower()
    return "utf" in encoding


def setup(
    level: str = "INFO",
    log_file: str | os.PathLike[str] | None = None,
    json_lines: bool = False,
    max_bytes: int = 1_000_000,
    backup_count: int = 5,
    secrets: list[str] | None = None,
) -> logging.Logger:
    _force_utf8_stdio()

    logger = logging.getLogger(LOG_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    redact = RedactFilter(secrets or [])
    fmt: logging.Formatter = (
        JsonFormatter()
        if json_lines
        else TextFormatter("%(asctime)s %(levelname)-7s %(message)s")
    )

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    console.setFormatter(fmt)
    console.addFilter(redact)
    logger.addHandler(console)

    if log_file:
        path = Path(log_file).expanduser()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # delay=True so a locked/unwritable path fails here, not mid-loop.
            file_handler = logging.handlers.RotatingFileHandler(
                path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
                delay=True,
            )
        except OSError as exc:
            logger.warning("log_file_unavailable", extra={"path": str(path), "error": str(exc)})
        else:
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(fmt)
            file_handler.addFilter(redact)
            logger.addHandler(file_handler)

    # requests/urllib3 noise is only useful when debugging the transport.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return logger


def get_logger(suffix: str | None = None) -> logging.Logger:
    return logging.getLogger(LOG_NAME if not suffix else f"{LOG_NAME}.{suffix}")

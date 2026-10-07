"""Layered configuration: defaults < config file < environment < CLI flags.

Every value is validated here so the daemon loop can assume sane inputs and
never has to guard against ``None`` or a negative interval.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

ENV_PREFIX = "KMITL_"

DEFAULT_LOGIN_URL = "https://portal.kmitl.ac.th:19008/portalauth/login"
DEFAULT_LOGOUT_URL = "https://portal.kmitl.ac.th:19008/portalauth/logout"
DEFAULT_HEARTBEAT_URL = "https://nani.csc.kmitl.ac.th/network-api/data/"
DEFAULT_PROBE_URLS = (
    "http://detectportal.firefox.com/success.txt",
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
)
DEFAULT_ACIP = "10.252.13.10"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
)
DEFAULT_HEARTBEAT_OS = "Chrome v116.0.5845.141 on Windows 10 64-bit"


class ConfigError(Exception):
    """Raised for a configuration problem the user has to fix."""


@dataclass
class Config:
    # --- credentials / identity -------------------------------------------
    username: str = ""
    password: str = ""
    ip_address: str = ""
    mac_address: str = ""          # empty => auto-detect, then pinned in state
    acip: str = DEFAULT_ACIP

    # --- endpoints ---------------------------------------------------------
    login_url: str = DEFAULT_LOGIN_URL
    logout_url: str = DEFAULT_LOGOUT_URL
    heartbeat_url: str = DEFAULT_HEARTBEAT_URL
    probe_urls: list[str] = field(default_factory=lambda: list(DEFAULT_PROBE_URLS))
    user_agent: str = DEFAULT_USER_AGENT
    heartbeat_os: str = DEFAULT_HEARTBEAT_OS
    verify_tls: bool = True

    # --- timing (seconds) --------------------------------------------------
    heartbeat_interval: float = 300.0
    relogin_interval: float = 8 * 60 * 60.0   # proactive re-login, 0 disables
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    probe_timeout: float = 6.0
    backoff_initial: float = 2.0
    backoff_max: float = 120.0
    watchdog_timeout: float = 180.0           # 0 disables the watchdog

    # --- retry / failure policy -------------------------------------------
    max_login_attempts: int = 0               # 0 => never give up on network errors
    max_credential_failures: int = 3          # stop before the portal locks us out
    exit_on_credential_failure: bool = True

    # --- observability -----------------------------------------------------
    log_level: str = "INFO"
    log_file: str = ""                        # empty => <state_dir>/kmitl-authen.log
    log_json: bool = False
    log_max_bytes: int = 1_000_000
    log_backup_count: int = 5
    no_banner: bool = False

    # --- control plane -----------------------------------------------------
    state_dir: str = ""                       # empty => platform default
    control_host: str = "127.0.0.1"
    control_port: int = 0                     # 0 => control HTTP server disabled
    control_token: str = ""

    # ---------------------------------------------------------------------
    @property
    def timeout(self) -> tuple[float, float]:
        """``requests`` timeout tuple. Never call requests without it."""
        return (self.connect_timeout, self.read_timeout)

    def redacted(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name in ("password", "control_token") and value:
                value = "***"
            out[f.name] = value
        return out

    def validate(self) -> None:
        missing = [n for n in ("username", "password") if not getattr(self, n)]
        if missing:
            raise ConfigError(
                "missing required setting(s): "
                + ", ".join(missing)
                + " (use --username/--password, config.json, or KMITL_USERNAME/KMITL_PASSWORD)"
            )
        if self.heartbeat_interval < 5:
            raise ConfigError("heartbeat-interval must be >= 5 seconds")
        if self.connect_timeout <= 0 or self.read_timeout <= 0:
            raise ConfigError("connect-timeout and read-timeout must be > 0")
        # The watchdog must outlast the slowest single request, or it fires on
        # a legitimately slow call. It does NOT need to outlast
        # heartbeat_interval: a deliberate sleep is declared to it as idle time.
        slowest_request = max(self.read_timeout, self.probe_timeout) + self.connect_timeout
        if self.watchdog_timeout and self.watchdog_timeout <= slowest_request:
            raise ConfigError(
                f"watchdog-timeout ({self.watchdog_timeout:g}s) must exceed the slowest "
                f"single request, which is connect-timeout + max(read-timeout, "
                f"probe-timeout) = {slowest_request:g}s"
            )
        if not self.probe_urls:
            raise ConfigError("at least one probe URL is required")
        if self.control_port and not (0 < self.control_port < 65536):
            raise ConfigError("control-port must be between 1 and 65535")


def default_state_dir() -> Path:
    """A writable per-user directory, respecting the platform's convention."""
    override = os.environ.get(ENV_PREFIX + "STATE_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "kmitl-authen"
    xdg = os.environ.get("XDG_STATE_HOME")
    if xdg:
        return Path(xdg) / "kmitl-authen"
    return Path.home() / ".local" / "state" / "kmitl-authen"


def find_config_file(explicit: str | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        return path
    candidates = [
        Path.cwd() / "config.json",
        default_state_dir() / "config.json",
        Path.home() / ".config" / "kmitl-authen" / "config.json",
    ]
    return next((c for c in candidates if c.is_file()), None)


# Accept both snake_case and the legacy camelCase keys from authen.py.
_FILE_ALIASES = {
    "ipAddress": "ip_address",
    "ip": "ip_address",
    "umac": "mac_address",
    "mac": "mac_address",
    "interval": "heartbeat_interval",
    "timeRepeat": "heartbeat_interval",
    "maxLoginAttempt": "max_login_attempts",
}

_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off"}


def _coerce(name: str, raw: Any) -> Any:
    declared = {f.name: f for f in fields(Config)}[name]
    target = declared.type
    if isinstance(raw, str):
        raw = raw.strip()
    if target == "bool" or isinstance(getattr(Config(), name), bool):
        if isinstance(raw, bool):
            return raw
        low = str(raw).lower()
        if low in _BOOL_TRUE:
            return True
        if low in _BOOL_FALSE:
            return False
        raise ConfigError(f"{name}: expected a boolean, got {raw!r}")
    if name == "probe_urls":
        if isinstance(raw, str):
            return [u for u in (p.strip() for p in raw.split(",")) if u]
        return list(raw)
    if target in ("float", "int") or isinstance(getattr(Config(), name), (int, float)):
        try:
            number = float(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{name}: expected a number, got {raw!r}") from exc
        if isinstance(getattr(Config(), name), int) and not isinstance(
            getattr(Config(), name), bool
        ):
            return int(number)
        return number
    return str(raw)


def load(args: Any = None, config_path: str | None = None) -> tuple[Config, Path | None]:
    """Build a validated ``Config``; returns it with the config file that was used."""
    cfg = Config()
    used: Path | None = None

    path = find_config_file(config_path)
    if path is not None:
        used = path
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config file {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: expected a JSON object")
        known = {f.name for f in fields(Config)}
        for key, value in raw.items():
            name = _FILE_ALIASES.get(key, key)
            if name in known and value not in (None, ""):
                setattr(cfg, name, _coerce(name, value))

    for f in fields(Config):
        env_value = os.environ.get(ENV_PREFIX + f.name.upper())
        if env_value not in (None, ""):
            setattr(cfg, f.name, _coerce(f.name, env_value))

    if args is not None:
        for f in fields(Config):
            value = getattr(args, f.name, None)
            if value is not None:
                setattr(cfg, f.name, _coerce(f.name, value))

    cfg.validate()
    return cfg, used

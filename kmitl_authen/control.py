"""Control plane: shutdown, forced re-login, and a status/metrics endpoint.

Three independent ways to force a re-login, so there is always one available
whatever the platform or packaging:

1. **Signals** — ``SIGHUP``/``SIGUSR1`` on Linux and macOS, ``SIGBREAK``
   (Ctrl+Break) on Windows, which has neither of the first two.
2. **A trigger file** — create ``<state_dir>/relogin`` and it is picked up
   within a second, then deleted. This is the portable path: it works inside a
   container (``docker exec``), from PowerShell, from Task Scheduler, from cron.
3. **The control HTTP server** — ``POST /relogin`` on ``127.0.0.1``, which also
   serves ``/status``, ``/healthz`` and ``/metrics`` for observability.

``wait()`` is deliberately sliced rather than one long ``time.sleep()``. A
multi-minute ``sleep`` swallows a Ctrl+C on Windows and delays every trigger
above by up to a full interval.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .logging_setup import get_logger

log = get_logger("control")

TRIGGER_FILENAME = "relogin"
WAIT_SLICE_SECONDS = 1.0


class Controller:
    """Shared signalling between the daemon loop and the outside world."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.shutdown = threading.Event()
        self.force_relogin = threading.Event()
        self._relogin_reason = "unknown"
        self._lock = threading.Lock()
        self._status_provider: Callable[[], dict[str, Any]] = dict
        self._server: ThreadingHTTPServer | None = None
        self.trigger_file = state_dir / TRIGGER_FILENAME

    # -- requests ----------------------------------------------------------
    def request_relogin(self, reason: str) -> None:
        with self._lock:
            self._relogin_reason = reason
        self.force_relogin.set()
        log.info("relogin_requested", extra={"reason": reason})

    def take_relogin_request(self) -> str | None:
        """Consume a pending request; returns its reason, or ``None``."""
        if not self.force_relogin.is_set():
            return None
        self.force_relogin.clear()
        with self._lock:
            return self._relogin_reason

    def request_shutdown(self, reason: str) -> None:
        if not self.shutdown.is_set():
            log.info("shutdown_requested", extra={"reason": reason})
        self.shutdown.set()
        self.force_relogin.set()      # wake a waiter immediately

    # -- waiting -----------------------------------------------------------
    def wait(self, seconds: float) -> str:
        """Sleep up to ``seconds``, returning early on a trigger.

        Returns ``"shutdown"``, ``"relogin"`` or ``"timeout"``.
        """
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            if self.shutdown.is_set():
                return "shutdown"
            if self.force_relogin.is_set():
                return "relogin"
            if self._consume_trigger_file():
                return "relogin"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "timeout"
            # Sliced wait: keeps Ctrl+C responsive on Windows and bounds how
            # long a trigger file can sit unnoticed.
            self.force_relogin.wait(min(WAIT_SLICE_SECONDS, remaining))

    def _consume_trigger_file(self) -> bool:
        try:
            if not self.trigger_file.exists():
                return False
            reason = "trigger_file"
            try:
                body = self.trigger_file.read_text(encoding="utf-8").strip()
                if body:
                    reason = f"trigger_file:{body[:60]}"
            except OSError:
                pass
            self.trigger_file.unlink(missing_ok=True)
        except OSError as exc:
            log.debug("trigger_file_error", extra={"error": str(exc)})
            return False
        self.request_relogin(reason)
        return True

    # -- wiring ------------------------------------------------------------
    def install_signal_handlers(self) -> None:
        def on_stop(signum: int, _frame: Any) -> None:
            self.request_shutdown(f"signal:{signum}")

        def on_relogin(signum: int, _frame: Any) -> None:
            self.request_relogin(f"signal:{signum}")

        installed: list[str] = []
        for name, handler in (
            ("SIGINT", on_stop),
            ("SIGTERM", on_stop),
            ("SIGHUP", on_relogin),      # POSIX only
            ("SIGUSR1", on_relogin),     # POSIX only
            ("SIGBREAK", on_relogin),    # Windows only (Ctrl+Break)
        ):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError, RuntimeError):
                # e.g. not running in the main thread, or unsupported here.
                continue
            installed.append(name)
        log.debug("signal_handlers_installed", extra={"signals": ",".join(installed)})

    def set_status_provider(self, provider: Callable[[], dict[str, Any]]) -> None:
        self._status_provider = provider

    def status(self) -> dict[str, Any]:
        try:
            return self._status_provider()
        except Exception as exc:  # pragma: no cover - never fail the endpoint
            return {"error": str(exc)}

    # -- control HTTP server ----------------------------------------------
    def start_http_server(self, host: str, port: int, token: str = "") -> int | None:
        if not port:
            return None
        handler = _make_handler(self, token)
        try:
            server = ThreadingHTTPServer((host, port), handler)
        except OSError as exc:
            log.error("control_server_failed", extra={"host": host, "port": port, "error": str(exc)})
            return None
        server.daemon_threads = True
        self._server = server
        thread = threading.Thread(target=server.serve_forever, name="control-http", daemon=True)
        thread.start()
        bound = server.server_address[1]
        log.info("control_server_listening", extra={"url": f"http://{host}:{bound}"})
        return bound

    def stop_http_server(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:  # pragma: no cover
                pass
            self._server = None


def _make_handler(controller: Controller, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "kmitl-authen"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            log.debug("control_http", extra={"peer": self.client_address[0],
                                             "line": fmt % args})

        # -- helpers ---------------------------------------------------
        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def _json(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self._send(code, body, "application/json; charset=utf-8")

        def _authorised(self) -> bool:
            if not token:
                return True
            supplied = self.headers.get("X-Auth-Token", "")
            if not supplied:
                auth = self.headers.get("Authorization", "")
                if auth.lower().startswith("bearer "):
                    supplied = auth[7:]
            return supplied == token

        # -- routes ----------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            if path == "/healthz":
                status = controller.status()
                healthy = bool(status.get("online"))
                self._json(200 if healthy else 503,
                           {"healthy": healthy, "state": status.get("state")})
                return
            if not self._authorised():
                self._json(401, {"error": "unauthorised"})
                return
            if path in ("/", "/status"):
                self._json(200, controller.status())
                return
            if path == "/metrics":
                self._send(200, _prometheus(controller.status()).encode("utf-8"),
                           "text/plain; version=0.0.4; charset=utf-8")
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                try:
                    self.rfile.read(min(length, 8192))
                except OSError:
                    pass
            if not self._authorised():
                self._json(401, {"error": "unauthorised"})
                return
            if path == "/relogin":
                controller.request_relogin("http")
                self._json(202, {"accepted": True, "action": "relogin"})
                return
            if path == "/shutdown":
                controller.request_shutdown("http")
                self._json(202, {"accepted": True, "action": "shutdown"})
                return
            self._json(404, {"error": "not found"})

    return Handler


def _prometheus(status: dict[str, Any]) -> str:
    """Flatten the status dict into Prometheus text format."""
    lines = [
        "# HELP kmitl_authen_online Whether the last connectivity probe succeeded.",
        "# TYPE kmitl_authen_online gauge",
        f"kmitl_authen_online {1 if status.get('online') else 0}",
    ]
    numeric = {
        "uptime_seconds": ("gauge", "Seconds since the daemon started."),
        "logins_total": ("counter", "Successful logins."),
        "login_failures_total": ("counter", "Failed login attempts."),
        "heartbeats_total": ("counter", "Successful heartbeats."),
        "heartbeat_failures_total": ("counter", "Failed heartbeats."),
        "network_errors_total": ("counter", "Transport-level errors."),
        "forced_relogins_total": ("counter", "Re-logins requested from outside."),
        "watchdog_resets_total": ("counter", "Watchdog-triggered restarts recorded."),
        "last_heartbeat_latency_ms": ("gauge", "Latency of the last heartbeat."),
        "seconds_since_last_success": ("gauge", "Age of the last confirmed-online moment."),
    }
    for key, (kind, help_text) in numeric.items():
        value = status.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            metric = f"kmitl_authen_{key}"
            lines += [f"# HELP {metric} {help_text}", f"# TYPE {metric} {kind}",
                      f"{metric} {value}"]
    state = str(status.get("state", "unknown"))
    lines += [
        "# HELP kmitl_authen_state Current state machine state (1 for the active label).",
        "# TYPE kmitl_authen_state gauge",
        f'kmitl_authen_state{{state="{state}"}} 1',
    ]
    return "\n".join(lines) + "\n"


def trigger_relogin(state_dir: Path, reason: str = "cli") -> Path:
    """Write the trigger file a running daemon is watching for."""
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / TRIGGER_FILENAME
    tmp = path.with_suffix(".tmp")
    tmp.write_text(reason, encoding="utf-8")
    os.replace(tmp, path)             # atomic, so the daemon never reads a partial file
    return path

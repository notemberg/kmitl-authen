"""HTTP session construction with mandatory timeouts and no stale sockets.

Two Windows-specific hazards are handled here:

1. ``requests`` has **no default timeout**. A captive portal that completes the
   TCP handshake and then never replies makes a bare ``requests.post()`` block
   forever. Windows will not time that out for you, and a ``SIGINT`` handler
   cannot interrupt a blocking ``recv()`` either, so the process looks wedged
   and Ctrl+C does nothing. ``TimedSession`` injects a timeout into every call.

2. A pooled keep-alive connection that survived a captive-portal transition is
   dead but the OS has not noticed. The next request reuses it and stalls until
   the read timeout. We enable TCP keepalive, and ``reset()`` tears the pool
   down whenever the network state changes.
"""

from __future__ import annotations

import socket
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .logging_setup import get_logger

log = get_logger("net")


def _keepalive_socket_options() -> list[tuple[int, int, int]]:
    """Enable TCP keepalive wherever the platform exposes the knobs."""
    options: list[tuple[int, int, int]] = [
        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    ]
    for name, value in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
        # TCP_KEEPIDLE/TCP_KEEPINTVL exist on Linux always and on Windows 10
        # 1709+ with Python 3.10+; TCP_KEEPCNT is Linux-only.
        opt = getattr(socket, name, None)
        if opt is not None:
            options.append((socket.IPPROTO_TCP, opt, value))
    return options


class TimedSession(requests.Session):
    """A ``Session`` that refuses to make a request without a timeout."""

    def __init__(self, timeout: tuple[float, float], retries: int = 0) -> None:
        super().__init__()
        self._timeout = timeout
        retry = Retry(
            total=retries,
            connect=retries,
            read=0,          # a hung read is retried by our own loop, with logging
            status=0,
            backoff_factor=0.5,
            allowed_methods=None,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=4,
            pool_maxsize=4,
            pool_block=False,
        )
        adapter.init_poolmanager(
            connections=4,
            maxsize=4,
            block=False,
            socket_options=_keepalive_socket_options(),
        )
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("allow_redirects", True)
        return super().request(method, url, **kwargs)


def build_session(
    timeout: tuple[float, float],
    user_agent: str,
    verify_tls: bool = True,
) -> TimedSession:
    session = TimedSession(timeout=timeout)
    session.verify = verify_tls
    session.headers.update(
        {
            "User-Agent": user_agent,
            "Accept": "application/json, text/javascript, text/plain, */*; q=0.01",
            "Accept-Language": "en-US,en;q=0.9,th;q=0.8",
        }
    )
    if not verify_tls:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # pragma: no cover
            pass
        log.warning("tls_verification_disabled")
    return session


def reset(session: TimedSession) -> None:
    """Drop every pooled socket and the cookie jar's volatile state.

    Called on any transition (login needed, heartbeat failure, forced relogin)
    so the next request always opens a fresh connection instead of inheriting a
    half-dead one from the pre-portal network.
    """
    try:
        for adapter in session.adapters.values():
            adapter.close()
    except Exception as exc:  # pragma: no cover - adapters are not supposed to raise
        log.debug("session_reset_failed", extra={"error": str(exc)})


def describe_exception(exc: BaseException) -> str:
    """Short, stable label for an exception, for logs and counters."""
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls_error"
    if isinstance(exc, requests.exceptions.ProxyError):
        return "proxy_error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "too_many_redirects"
    if isinstance(exc, requests.exceptions.RequestException):
        return "request_error"
    return type(exc).__name__

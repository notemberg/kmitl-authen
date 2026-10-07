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

    def __init__(self, timeout: tuple[float, float]) -> None:
        super().__init__()
        self._timeout = timeout
        # No transport-level retries: our own loop retries, with backoff and a
        # log line for each attempt. Passing an explicit urllib3 ``Retry`` here
        # is actively harmful -- ``Retry(read=0)`` wraps a ``ReadTimeoutError``
        # in ``MaxRetryError``, which requests then surfaces as a generic
        # ``ConnectionError``. That throws away the one distinction that
        # matters most here: "the network is down" versus "the portal accepted
        # our connection and then went silent", which is the original hang.
        # requests' default (``Retry(0, read=False)``) re-raises the original.
        adapter = HTTPAdapter(
            max_retries=0,
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
    session = TimedSession(timeout)
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


def _exception_chain(exc: BaseException, limit: int = 8) -> list[BaseException]:
    """``exc`` and what it was raised from, innermost causes included."""
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and len(chain) < limit and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def describe_exception(exc: BaseException) -> str:
    """Short, stable label for an exception, for logs and counters.

    The whole cause chain is inspected, not just the outermost type. A timeout
    can reach us wrapped in something more generic depending on the urllib3
    version and whether the socket was fresh or reused, and reporting that as a
    plain "connection_error" would hide the timeout we most want to see.
    """
    chain = _exception_chain(exc)

    # Specific timeouts first: these are the signature of the original hang.
    for item in chain:
        if isinstance(item, requests.exceptions.ConnectTimeout):
            return "connect_timeout"
        if isinstance(item, requests.exceptions.ReadTimeout):
            return "read_timeout"
        if type(item).__name__ == "ConnectTimeoutError":
            return "connect_timeout"
        if type(item).__name__ == "ReadTimeoutError":
            return "read_timeout"
    for item in chain:
        if isinstance(item, requests.exceptions.Timeout) or isinstance(item, TimeoutError):
            return "timeout"

    for item in chain:
        if isinstance(item, requests.exceptions.SSLError):
            return "tls_error"
        if isinstance(item, requests.exceptions.ProxyError):
            return "proxy_error"
        if isinstance(item, requests.exceptions.TooManyRedirects):
            return "too_many_redirects"

    for item in chain:
        if type(item).__name__ == "NameResolutionError" or isinstance(item, socket.gaierror):
            return "dns_error"
        if isinstance(item, ConnectionRefusedError):
            return "connection_refused"
        if isinstance(item, ConnectionResetError):
            return "connection_reset"

    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error"
    if isinstance(exc, requests.exceptions.RequestException):
        return "request_error"
    return type(exc).__name__

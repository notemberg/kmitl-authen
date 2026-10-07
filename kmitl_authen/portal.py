"""Talking to the KMITL portal: probe, login, heartbeat, logout.

Every response is treated as untrusted: the portal answers with HTML when it
feels like it, and the original ``json.loads(content.text)`` followed by
``content_dict['data']`` raised ``JSONDecodeError`` / ``KeyError`` straight out
of the main loop and ended the process. Nothing here raises on a weird body.
"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from typing import Any, Sequence

import requests

from . import netutil
from .config import Config
from .logging_setup import get_logger

log = get_logger("portal")

# Substrings that mean "these credentials are wrong", as opposed to a transient
# network problem. Retrying those only burns attempts toward an account lock.
_CREDENTIAL_MARKERS = (
    "userpasserror",
    "password error",
    "wrong password",
    "invalid username",
    "authentication fail",
    "auth fail",
    "account locked",
    "user not found",
    "no such user",
)
_ALREADY_ONLINE_MARKERS = ("already online", "already login", "online already", "userhasonline")


class Outcome:
    OK = "ok"
    ALREADY_ONLINE = "already_online"
    BAD_CREDENTIALS = "bad_credentials"
    REJECTED = "rejected"
    NETWORK_ERROR = "network_error"


@dataclass
class Result:
    outcome: str
    detail: str = ""
    status_code: int | None = None
    latency_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.outcome in (Outcome.OK, Outcome.ALREADY_ONLINE)

    @property
    def fatal(self) -> bool:
        return self.outcome == Outcome.BAD_CREDENTIALS


def _body_snippet(response: requests.Response, limit: int = 300) -> str:
    try:
        text = response.text or ""
    except Exception:
        return "<unreadable body>"
    return " ".join(text.split())[:limit]


def _as_json(response: requests.Response) -> dict[str, Any] | None:
    """Parse a JSON object body, or return ``None`` — never raise."""
    try:
        parsed = json.loads(response.text)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _classify(payload: dict[str, Any] | None, snippet: str) -> tuple[str, str]:
    haystack = snippet.lower()
    if payload is not None:
        haystack = (haystack + " " + json.dumps(payload, default=str).lower()).strip()

    if any(marker in haystack for marker in _ALREADY_ONLINE_MARKERS):
        return Outcome.ALREADY_ONLINE, "portal reports the session is already online"
    if any(marker in haystack for marker in _CREDENTIAL_MARKERS):
        return Outcome.BAD_CREDENTIALS, "portal rejected the credentials"

    if payload is not None:
        for key in ("success", "result", "status", "code"):
            if key not in payload:
                continue
            value = payload[key]
            if isinstance(value, bool):
                return (Outcome.OK, "") if value else (Outcome.REJECTED, f"{key}=false")
            text = str(value).strip().lower()
            if text in ("1", "true", "ok", "success", "0000", "200"):
                return Outcome.OK, ""
            if text in ("0", "false", "fail", "failed", "error"):
                return Outcome.REJECTED, f"{key}={value}"
        # A JSON object with no verdict field: the portal accepted the post.
        return Outcome.OK, ""
    return Outcome.REJECTED, "non-JSON response"


def local_ip(targets: Sequence[str] = ("10.252.13.10", "8.8.8.8")) -> str:
    """Best-effort source address for traffic toward the portal.

    Uses a connected UDP socket, so nothing is sent on the wire. The targets
    are IP literals on purpose: ``socket.getaddrinfo`` ignores timeouts, so a
    hostname here could block on a captive network's broken resolver for as
    long as the OS resolver's own retry schedule.
    """
    for target in targets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(1.0)
            sock.connect((target, 80))
            address = sock.getsockname()[0]
            if address and not address.startswith("0."):
                return address
        except OSError:
            continue
        finally:
            sock.close()
    return ""


class Portal:
    def __init__(self, cfg: Config, mac: str) -> None:
        self.cfg = cfg
        self.mac = mac
        self.session = netutil.build_session(cfg.timeout, cfg.user_agent, cfg.verify_tls)
        # A separate session for connectivity probes. The portal session holds
        # portal cookies and an X-XSRF-TOKEN header, and probe hosts are third
        # parties (Mozilla, Google) that have no business receiving either.
        self.probe_session = netutil.build_session(
            (cfg.connect_timeout, cfg.probe_timeout), cfg.user_agent, cfg.verify_tls
        )
        self._probe_index = 0

    # -- lifecycle ---------------------------------------------------------
    def reset_connections(self, reason: str = "") -> None:
        for name, timeout in (
            ("session", self.cfg.timeout),
            ("probe_session", (self.cfg.connect_timeout, self.cfg.probe_timeout)),
        ):
            netutil.reset(getattr(self, name))
            setattr(
                self,
                name,
                netutil.build_session(timeout, self.cfg.user_agent, self.cfg.verify_tls),
            )
        log.debug("session_rebuilt", extra={"reason": reason or "unspecified"})

    def close(self) -> None:
        for session in (self.session, self.probe_session):
            netutil.reset(session)
            try:
                session.close()
            except Exception:  # pragma: no cover
                pass

    # -- connectivity ------------------------------------------------------
    def check_internet(self) -> tuple[bool, str]:
        """True when a probe confirms unauthenticated-free internet access.

        Probes are rotated so one blackholed host cannot wedge us, and
        redirects are disabled: a captive portal answering 200 with its own
        login page must read as "no internet", which the original
        ``content.text == 'success\\n'`` comparison only accidentally did.
        """
        urls = self.cfg.probe_urls
        for offset in range(len(urls)):
            url = urls[(self._probe_index + offset) % len(urls)]
            started = time.monotonic()
            try:
                response = self.probe_session.get(
                    url,
                    timeout=(self.cfg.connect_timeout, self.cfg.probe_timeout),
                    allow_redirects=False,
                    headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
                )
            except requests.exceptions.RequestException as exc:
                log.debug(
                    "probe_error",
                    extra={"url": url, "reason": netutil.describe_exception(exc)},
                )
                continue

            latency = int((time.monotonic() - started) * 1000)
            body = ""
            try:
                body = (response.text or "").strip()
            except Exception:
                body = ""

            good = (response.status_code == 204 and not body) or body == "success"
            self._probe_index = (self._probe_index + offset) % len(urls)
            log.debug(
                "probe_result",
                extra={
                    "url": url,
                    "status": response.status_code,
                    "online": good,
                    "latency_ms": latency,
                },
            )
            if good:
                return True, "probe ok"
            return False, f"captive portal response (HTTP {response.status_code})"
        return False, "all probes unreachable"

    # -- portal operations -------------------------------------------------
    def login(self, ip_address: str) -> Result:
        params = {
            "userName": self.cfg.username,
            "userPass": self.cfg.password,
            "uaddress": ip_address,
            "umac": self.mac,
            "agreed": 1,
            "acip": self.cfg.acip,
            "authType": 1,
        }
        started = time.monotonic()
        try:
            response = self.session.post(
                self.cfg.login_url,
                params=params,
                headers={
                    "Origin": "https://portal.kmitl.ac.th:19008",
                    "Referer": "https://portal.kmitl.ac.th:19008/",
                    "X-Requested-With": "XMLHttpRequest",
                },
            )
        except requests.exceptions.RequestException as exc:
            return Result(
                Outcome.NETWORK_ERROR,
                netutil.describe_exception(exc),
                latency_ms=int((time.monotonic() - started) * 1000),
            )

        latency = int((time.monotonic() - started) * 1000)
        snippet = _body_snippet(response)
        payload = _as_json(response)

        if response.status_code >= 500:
            return Result(Outcome.NETWORK_ERROR, f"portal HTTP {response.status_code}",
                          response.status_code, latency)
        if response.status_code in (401, 403):
            return Result(Outcome.BAD_CREDENTIALS, snippet or "unauthorised",
                          response.status_code, latency)
        if response.status_code != 200:
            return Result(Outcome.REJECTED, snippet or f"HTTP {response.status_code}",
                          response.status_code, latency)

        outcome, detail = _classify(payload, snippet)
        self._capture_token(payload)
        return Result(outcome, detail or snippet[:160], response.status_code, latency)

    def _capture_token(self, payload: dict[str, Any] | None) -> None:
        """Carry an anti-CSRF token forward if the portal issued one."""
        token = ""
        if payload:
            for key in ("token", "xsrfToken", "csrfToken"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    token = value
                    break
        if not token:
            token = self.session.cookies.get("XSRF-TOKEN") or ""
        if token:
            self.session.headers["X-XSRF-TOKEN"] = token
            log.debug("xsrf_token_captured")

    def heartbeat(self) -> Result:
        started = time.monotonic()
        try:
            response = self.session.post(
                self.cfg.heartbeat_url,
                params={
                    "username": self.cfg.username,
                    "os": self.cfg.heartbeat_os,
                    "speed": 1.29,
                    "newauth": 1,
                },
            )
        except requests.exceptions.RequestException as exc:
            return Result(
                Outcome.NETWORK_ERROR,
                netutil.describe_exception(exc),
                latency_ms=int((time.monotonic() - started) * 1000),
            )

        latency = int((time.monotonic() - started) * 1000)
        if response.status_code == 200:
            return Result(Outcome.OK, "", response.status_code, latency)
        if response.status_code >= 500:
            return Result(Outcome.NETWORK_ERROR, f"HTTP {response.status_code}",
                          response.status_code, latency)
        return Result(Outcome.REJECTED, _body_snippet(response, 160),
                      response.status_code, latency)

    def logout(self) -> Result:
        started = time.monotonic()
        headers = {
            "Origin": "https://portal.kmitl.ac.th:19008",
            "Referer": "https://portal.kmitl.ac.th:19008/",
            "X-Requested-With": "XMLHttpRequest",
        }
        token = self.session.cookies.get("XSRF-TOKEN")
        if token:
            headers["X-XSRF-TOKEN"] = token
        try:
            response = self.session.post(self.cfg.logout_url, headers=headers, data="")
        except requests.exceptions.RequestException as exc:
            return Result(
                Outcome.NETWORK_ERROR,
                netutil.describe_exception(exc),
                latency_ms=int((time.monotonic() - started) * 1000),
            )
        latency = int((time.monotonic() - started) * 1000)
        outcome = Outcome.OK if response.status_code == 200 else Outcome.REJECTED
        return Result(outcome, _body_snippet(response, 160), response.status_code, latency)

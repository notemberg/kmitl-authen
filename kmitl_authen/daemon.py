"""The supervisor loop, as an explicit state machine.

The original loop interleaved connectivity checks, a five-minute ``sleep`` and
re-login attempts in a way that produced two bad behaviours:

* ``elif connection and not internet:`` called ``login()`` with **no sleep and
  no backoff**, so a portal that kept answering with its own page turned into a
  tight request loop until something blocked.
* ``login_attempt == max_login_attempt`` only printed a message at exact
  equality, so the "maximum" was never actually enforced on that path.

Here every path through the loop sleeps, failures back off exponentially with
jitter, repeated credential rejections stop before the account gets locked, and
no unexpected exception can end the process.
"""

from __future__ import annotations

import os
import platform
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import EXIT_CREDENTIALS, EXIT_OK, __version__
from .config import Config
from .control import Controller
from .logging_setup import get_logger, supports_unicode
from .portal import Outcome, Portal, Result, local_ip
from .watchdog import Watchdog, read_reset_count

log = get_logger("daemon")

MIN_TICK = 1.0
POST_LOGIN_RECHECK = 3.0
CREDENTIAL_COOLDOWN = 900.0

# A wait that overruns by more than max(GAP_MIN_SECONDS, requested * GAP_FACTOR)
# is treated as a gap: the process was suspended, or something stalled it. In a
# real run log this showed up as 80 minutes of total silence between two
# heartbeats, with no indication of which it was.
GAP_FACTOR = 2.0
GAP_MIN_SECONDS = 60.0


class State:
    STARTING = "starting"
    LOGGING_IN = "logging_in"
    ONLINE = "online"
    BACKOFF = "backoff"
    BLOCKED = "blocked"
    STOPPED = "stopped"


@dataclass
class Counters:
    logins_total: int = 0
    login_failures_total: int = 0
    credential_failures_total: int = 0
    heartbeats_total: int = 0
    heartbeat_failures_total: int = 0
    network_errors_total: int = 0
    forced_relogins_total: int = 0
    probe_failures_total: int = 0
    unexpected_errors_total: int = 0
    long_gaps_total: int = 0
    extras: dict[str, Any] = field(default_factory=dict)


BANNER_UNICODE = r"""
   ██╗  ██╗███╗   ███╗██╗████████╗██╗         █████╗ ██╗   ██╗████████╗██╗  ██╗
   ██║ ██╔╝████╗ ████║██║╚══██╔══╝██║        ██╔══██╗██║   ██║╚══██╔══╝██║  ██║
   █████╔╝ ██╔████╔██║██║   ██║   ██║        ███████║██║   ██║   ██║   ███████║
   ██╔═██╗ ██║╚██╔╝██║██║   ██║   ██║        ██╔══██║██║   ██║   ██║   ██╔══██║
   ██║  ██╗██║ ╚═╝ ██║██║   ██║   ███████╗   ██║  ██║╚██████╔╝   ██║   ██║  ██║
   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚══════╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
"""
BANNER_ASCII = r"""
   _  ____  __ ___ _____ _          _   _   _ _____ _   _
  | |/ /  \/  |_ _|_   _| |        / \ | | | |_   _| | | |
  | ' /| |\/| || |  | | | |       / _ \| | | | | | | |_| |
  | . \| |  | || |  | | | |___   / ___ \ |_| | | | |  _  |
  |_|\_\_|  |_|___| |_| |_____| /_/   \_\___/  |_| |_| |_|
"""


class Daemon:
    def __init__(
        self,
        cfg: Config,
        mac: str,
        state_dir: Path,
        controller: Controller,
        watchdog: Watchdog,
    ) -> None:
        self.cfg = cfg
        self.mac = mac
        self.state_dir = state_dir
        self.controller = controller
        self.watchdog = watchdog
        self.portal = Portal(cfg, mac)
        self.counters = Counters()
        self.state = State.STARTING
        self.started_monotonic = time.monotonic()
        self.started_wall = time.time()
        self.ip_address = cfg.ip_address
        self.backoff = cfg.backoff_initial
        self.last_success: float | None = None
        self.last_login: float | None = None
        self.last_heartbeat: float | None = None
        self.last_heartbeat_latency_ms = 0
        self.last_detail = ""
        self.last_gap_seconds = 0.0
        self.login_attempts_since_success = 0
        self.watchdog_resets = read_reset_count(state_dir)
        controller.set_status_provider(self.status)

    # -- status ------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        now = time.monotonic()
        return {
            "version": __version__,
            "state": self.state,
            "online": self.state == State.ONLINE,
            "username": self.cfg.username,
            "ip_address": self.ip_address,
            "mac_address": self.mac,
            "pid": os.getpid(),
            "platform": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.started_wall)),
            "uptime_seconds": round(now - self.started_monotonic, 1),
            "heartbeat_interval": self.cfg.heartbeat_interval,
            "relogin_interval": self.cfg.relogin_interval,
            "seconds_since_last_success": (
                round(now - self.last_success, 1) if self.last_success else None
            ),
            "seconds_since_last_login": (
                round(now - self.last_login, 1) if self.last_login else None
            ),
            "seconds_since_last_heartbeat": (
                round(now - self.last_heartbeat, 1) if self.last_heartbeat else None
            ),
            "last_heartbeat_latency_ms": self.last_heartbeat_latency_ms,
            "last_detail": self.last_detail,
            "backoff_seconds": round(self.backoff, 1),
            "watchdog_resets_total": self.watchdog_resets,
            "logins_total": self.counters.logins_total,
            "login_failures_total": self.counters.login_failures_total,
            "credential_failures_total": self.counters.credential_failures_total,
            "heartbeats_total": self.counters.heartbeats_total,
            "heartbeat_failures_total": self.counters.heartbeat_failures_total,
            "network_errors_total": self.counters.network_errors_total,
            "forced_relogins_total": self.counters.forced_relogins_total,
            "probe_failures_total": self.counters.probe_failures_total,
            "unexpected_errors_total": self.counters.unexpected_errors_total,
            "long_gaps_total": self.counters.long_gaps_total,
            "last_gap_seconds": self.last_gap_seconds,
            "relogin_trigger_file": str(self.controller.trigger_file),
        }

    def _set_state(self, new_state: str, **extra: Any) -> None:
        if new_state != self.state:
            log.info("state_change", extra={"from": self.state, "to": new_state, **extra})
            self.state = new_state

    # -- startup banner ----------------------------------------------------
    def _banner(self) -> None:
        if self.cfg.no_banner:
            return
        for line in (BANNER_UNICODE if supports_unicode() else BANNER_ASCII).splitlines():
            if line.strip():
                log.info(line)

    # -- building blocks ---------------------------------------------------
    def _resolve_ip(self) -> str:
        """The address we claim to the portal; refreshed when not pinned."""
        if self.cfg.ip_address:
            return self.cfg.ip_address
        detected = local_ip((self.cfg.acip, "8.8.8.8"))
        if detected and detected != self.ip_address:
            log.info("local_ip_detected", extra={"ip": detected, "previous": self.ip_address or "-"})
        return detected or self.ip_address

    def _bump_backoff(self) -> float:
        """Exponential backoff with full jitter, so retries never synchronise."""
        delay = min(self.backoff, self.cfg.backoff_max)
        self.backoff = min(self.backoff * 2, self.cfg.backoff_max)
        return max(MIN_TICK, random.uniform(delay / 2, delay))

    def _reset_backoff(self) -> None:
        self.backoff = self.cfg.backoff_initial

    def _do_login(self, reason: str) -> Result:
        self._set_state(State.LOGGING_IN, reason=reason)
        self.portal.reset_connections(reason=f"login:{reason}")
        self.ip_address = self._resolve_ip()
        self.watchdog.pet(f"login:{reason}")

        result = self.portal.login(self.ip_address)
        self.last_login = time.monotonic()
        self.last_detail = result.detail

        fields = {
            "reason": reason,
            "outcome": result.outcome,
            "status": result.status_code,
            "latency_ms": result.latency_ms,
            "ip": self.ip_address,
            "attempt": self.login_attempts_since_success + 1,
        }
        if result.detail:
            fields["detail"] = result.detail

        if result.ok:
            self.counters.logins_total += 1
            self.login_attempts_since_success = 0
            log.info("login_ok", extra=fields)
            return result

        self.counters.login_failures_total += 1
        self.login_attempts_since_success += 1
        if result.outcome == Outcome.NETWORK_ERROR:
            self.counters.network_errors_total += 1
            log.warning("login_network_error", extra=fields)
        elif result.outcome == Outcome.BAD_CREDENTIALS:
            self.counters.credential_failures_total += 1
            log.error("login_bad_credentials", extra=fields)
        else:
            log.warning("login_rejected", extra=fields)
        return result

    def _do_heartbeat(self) -> Result:
        self.watchdog.pet("heartbeat")
        result = self.portal.heartbeat()
        self.last_heartbeat = time.monotonic()
        self.last_heartbeat_latency_ms = result.latency_ms
        fields = {
            "outcome": result.outcome,
            "status": result.status_code,
            "latency_ms": result.latency_ms,
        }
        if result.ok:
            self.counters.heartbeats_total += 1
            log.info("heartbeat_ok", extra=fields)
        else:
            self.counters.heartbeat_failures_total += 1
            if result.outcome == Outcome.NETWORK_ERROR:
                self.counters.network_errors_total += 1
            if result.detail:
                fields["detail"] = result.detail
            log.warning("heartbeat_failed", extra=fields)
        return result

    def _credentials_exhausted(self) -> bool:
        limit = self.cfg.max_credential_failures
        return bool(limit) and self.counters.credential_failures_total >= limit

    def _attempts_exhausted(self) -> bool:
        limit = self.cfg.max_login_attempts
        return bool(limit) and self.login_attempts_since_success >= limit

    # -- main loop ---------------------------------------------------------
    def run(self) -> int:
        self._banner()
        log.info(
            "starting",
            extra={
                "version": __version__,
                "username": self.cfg.username,
                "mac": self.mac,
                "ip": self.cfg.ip_address or "auto",
                "heartbeat_interval": self.cfg.heartbeat_interval,
                "relogin_interval": self.cfg.relogin_interval,
                "watchdog_timeout": self.cfg.watchdog_timeout,
                "state_dir": str(self.state_dir),
                "pid": os.getpid(),
                "platform": f"{platform.system()} {platform.release()}",
                "python": platform.python_version(),
            },
        )
        if self.watchdog_resets:
            log.warning("previous_watchdog_resets", extra={"count": self.watchdog_resets})

        next_heartbeat = 0.0           # heartbeat as soon as we are online
        exit_code = EXIT_OK

        while not self.controller.shutdown.is_set():
            self.watchdog.pet("loop")
            try:
                sleep_for, next_heartbeat = self._tick(next_heartbeat)
            except Exception:
                # A bug in our own handling must never end the daemon; log the
                # traceback, back off, and carry on.
                self.counters.unexpected_errors_total += 1
                log.exception("unexpected_error")
                self.portal.reset_connections("unexpected_error")
                sleep_for = self._bump_backoff()

            if self.state == State.BLOCKED and self.cfg.exit_on_credential_failure:
                exit_code = EXIT_CREDENTIALS
                break

            if self.controller.shutdown.is_set():
                break
            self._sleep(max(MIN_TICK, sleep_for))

        self._set_state(State.STOPPED)
        log.info("stopped", extra={"exit_code": exit_code, **{
            k: v for k, v in self.status().items()
            if k in ("uptime_seconds", "logins_total", "heartbeats_total",
                     "heartbeat_failures_total", "network_errors_total")
        }})
        self.portal.close()
        return exit_code

    def _sleep(self, seconds: float) -> None:
        """Wait, declaring the idle period to the watchdog, then check for a gap."""
        self.watchdog.pet(f"idle:{seconds:.0f}s", expected_idle=seconds)
        mono_before, wall_before = time.monotonic(), time.time()

        woke = self.controller.wait(seconds)

        mono_elapsed = time.monotonic() - mono_before
        wall_elapsed = time.time() - wall_before
        self.watchdog.pet("awake")
        if woke == "relogin":
            log.debug("wait_interrupted", extra={"by": woke})
        self._check_gap(seconds, mono_elapsed, wall_elapsed)

    def _check_gap(self, requested: float, mono_elapsed: float, wall_elapsed: float) -> None:
        """Notice, name and react to a wait that took far longer than asked.

        Comparing the monotonic and wall-clock deltas separates the two causes:
        a suspended machine advances the wall clock while the monotonic clock
        stands still (on Linux; Windows may advance both), whereas a genuine
        stall advances both together. Either way the portal session is almost
        certainly stale after a long absence, so force a re-login rather than
        carrying on and discovering it at the next heartbeat.
        """
        allowance = max(GAP_MIN_SECONDS, requested * GAP_FACTOR)
        overrun = max(mono_elapsed, wall_elapsed)
        if overrun <= allowance:
            return

        skew = wall_elapsed - mono_elapsed
        likely = "suspend_or_clock_change" if abs(skew) >= GAP_MIN_SECONDS else "stall"
        self.counters.long_gaps_total += 1
        self.last_gap_seconds = round(overrun, 1)
        log.warning(
            "long_gap_detected",
            extra={
                "requested_s": round(requested, 1),
                "monotonic_s": round(mono_elapsed, 1),
                "wall_clock_s": round(wall_elapsed, 1),
                "skew_s": round(skew, 1),
                "likely": likely,
            },
        )
        self.controller.request_relogin(f"gap:{likely}")

    def _tick(self, next_heartbeat: float) -> tuple[float, float]:
        """One iteration. Returns ``(sleep_seconds, next_heartbeat_monotonic)``."""
        now = time.monotonic()

        forced = self.controller.take_relogin_request()
        if forced is not None and not self.controller.shutdown.is_set():
            self.counters.forced_relogins_total += 1
            result = self._do_login(f"forced:{forced}")
            if result.fatal and self._credentials_exhausted():
                self._set_state(State.BLOCKED, detail=result.detail)
                return MIN_TICK, next_heartbeat
            # Re-probe shortly so /status reflects reality, and heartbeat soon.
            return POST_LOGIN_RECHECK, time.monotonic() + self.cfg.heartbeat_interval

        online, detail = self.portal.check_internet()
        self.watchdog.pet("probe")
        if not online:
            self.counters.probe_failures_total += 1
            self.last_detail = detail

        if online:
            first_time = self.state != State.ONLINE
            self._set_state(State.ONLINE, detail=detail)
            self._reset_backoff()
            self.last_success = time.monotonic()
            if first_time:
                log.info(
                    "online",
                    extra={
                        "username": self.cfg.username,
                        "ip": self.ip_address,
                        "mac": self.mac,
                        "heartbeat_interval": self.cfg.heartbeat_interval,
                    },
                )

            # Proactive re-login keeps the portal session from ageing out.
            # When we started up already authenticated we never called login(),
            # so measure from startup rather than skipping the refresh forever.
            since_login = time.monotonic() - (
                self.last_login if self.last_login is not None else self.started_monotonic
            )
            if self.cfg.relogin_interval and since_login >= self.cfg.relogin_interval:
                self._do_login("scheduled")
                return POST_LOGIN_RECHECK, time.monotonic() + self.cfg.heartbeat_interval

            if time.monotonic() >= next_heartbeat:
                result = self._do_heartbeat()
                next_heartbeat = time.monotonic() + self.cfg.heartbeat_interval
                if not result.ok:
                    # The portal stopped recognising us: re-login now rather
                    # than waiting out another full interval as before.
                    self._do_login("heartbeat_failed")
                    return POST_LOGIN_RECHECK, time.monotonic() + self.cfg.heartbeat_interval

            remaining = next_heartbeat - time.monotonic()
            return max(MIN_TICK, min(remaining, self.cfg.heartbeat_interval)), next_heartbeat

        # --- not online -------------------------------------------------
        if self.last_login is None or self.state == State.ONLINE:
            log.info("internet_unavailable", extra={"detail": detail})
        self._set_state(State.BACKOFF, detail=detail)

        if self._credentials_exhausted():
            if self.cfg.exit_on_credential_failure:
                log.critical(
                    "credentials_rejected_giving_up",
                    extra={
                        "failures": self.counters.credential_failures_total,
                        "hint": "fix username/password, then restart",
                    },
                )
                self._set_state(State.BLOCKED)
                return MIN_TICK, next_heartbeat
            log.error(
                "credentials_rejected_cooldown",
                extra={
                    "failures": self.counters.credential_failures_total,
                    "cooldown_s": CREDENTIAL_COOLDOWN,
                },
            )
            self.counters.credential_failures_total = 0
            return CREDENTIAL_COOLDOWN, next_heartbeat

        if self._attempts_exhausted():
            log.error(
                "login_attempts_exhausted_cooldown",
                extra={
                    "attempts": self.login_attempts_since_success,
                    "limit": self.cfg.max_login_attempts,
                    "cooldown_s": self.cfg.backoff_max,
                },
            )
            self.login_attempts_since_success = 0
            return self.cfg.backoff_max, next_heartbeat

        result = self._do_login(detail or "offline")
        if result.ok:
            return POST_LOGIN_RECHECK, time.monotonic() + self.cfg.heartbeat_interval
        return self._bump_backoff(), next_heartbeat

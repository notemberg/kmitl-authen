"""Last-resort watchdog.

Timeouts cover the normal hang. This covers the abnormal one: a bug in our own
loop, a ``requests``/OpenSSL stall that ignores its timeout, a suspended laptop
that comes back with a wedged socket. The daemon pets the watchdog once per
iteration; if too long passes without a pet, we log and terminate hard so the
supervisor (systemd / Docker / Task Scheduler) restarts a clean process.

``os._exit`` is used on purpose: a stuck thread may be holding a lock that
``sys.exit`` would need to unwind, which is exactly the situation we are in.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from . import EXIT_WATCHDOG
from .logging_setup import get_logger

log = get_logger("watchdog")


class Watchdog:
    def __init__(self, timeout: float, state_dir: Path | None = None) -> None:
        self.timeout = timeout
        self.state_dir = state_dir
        self._last_pet = time.monotonic()
        self._activity = "startup"
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def pet(self, activity: str = "") -> None:
        with self._lock:
            self._last_pet = time.monotonic()
            if activity:
                self._activity = activity

    def start(self) -> None:
        if not self.timeout:
            log.warning("watchdog_disabled")
            return
        self._thread = threading.Thread(target=self._run, name="watchdog", daemon=True)
        self._thread.start()
        log.debug("watchdog_started", extra={"timeout_s": self.timeout})

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        poll = max(1.0, min(5.0, self.timeout / 10))
        while not self._stop.wait(poll):
            with self._lock:
                stalled = time.monotonic() - self._last_pet
                activity = self._activity
            if stalled <= self.timeout:
                continue
            log.critical(
                "watchdog_fired",
                extra={
                    "stalled_s": round(stalled, 1),
                    "timeout_s": self.timeout,
                    "last_activity": activity,
                    "action": f"exit({EXIT_WATCHDOG}) for supervisor restart",
                },
            )
            self._record()
            for handler in list(log.handlers) + list(log.parent.handlers if log.parent else []):
                try:
                    handler.flush()
                except Exception:
                    pass
            os._exit(EXIT_WATCHDOG)

    def _record(self) -> None:
        """Bump a persisted counter so restarts are visible in /status.

        Written via a temp file and ``os.replace`` because we are about to call
        ``os._exit``: a plain ``write_text`` truncates first, so dying between
        the truncate and the write would leave an empty file and lose the count
        (and a concurrent reader would see that empty file).
        """
        if self.state_dir is None:
            return
        path = self.state_dir / "watchdog_resets"
        try:
            previous = int(path.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            previous = 0
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(str(previous + 1), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass


def read_reset_count(state_dir: Path) -> int:
    try:
        return int((state_dir / "watchdog_resets").read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0

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
import platform
import sys
import threading
import time
import traceback
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
        self._grace = 0.0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def pet(self, activity: str = "", expected_idle: float = 0.0) -> None:
        """Record progress.

        ``expected_idle`` declares a deliberate sleep that is about to happen,
        and extends the deadline for it. Without this the watchdog cannot tell
        "blocked in a syscall for five minutes" from "waiting five minutes
        between heartbeats, exactly as configured", and with the default
        300s interval against a 180s timeout it would kill a healthy daemon on
        every single cycle.
        """
        with self._lock:
            self._last_pet = time.monotonic()
            self._grace = max(0.0, expected_idle)
            if activity:
                self._activity = activity

    def start(self) -> None:
        if not self.timeout:
            log.warning("watchdog_disabled")
            return
        self._thread = threading.Thread(target=self._run, name="watchdog", daemon=True)
        self._thread.start()
        log.debug("watchdog_started", extra={"timeout_s": self.timeout})

    def stop(self, join_timeout: float = 2.0) -> None:
        """Stop guarding, and wait for the thread to actually be gone.

        Returning while the thread is still mid-decision would leave it able
        to call ``os._exit`` after the caller believes the watchdog is off.
        """
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and join_timeout > 0:
            thread.join(join_timeout)

    def _run(self) -> None:
        poll = max(1.0, min(5.0, self.timeout / 10))
        warned = False
        while not self._stop.wait(poll):
            with self._lock:
                stalled = time.monotonic() - self._last_pet
                activity = self._activity
                grace = self._grace
                allowed = self.timeout + grace

            if stalled <= allowed / 2:
                warned = False
            elif stalled <= allowed:
                # Half way to death: say so while the process is still alive,
                # so the log shows the state leading up to a stall instead of
                # only the obituary.
                if not warned:
                    warned = True
                    log.warning(
                        "watchdog_half_way",
                        extra={
                            "stalled_s": round(stalled, 1),
                            "allowed_s": round(allowed, 1),
                            "grace_s": round(grace, 1),
                            "last_activity": activity,
                            "where": _innermost_frame(),
                        },
                    )
                continue
            else:
                pass

            if stalled <= allowed:
                continue

            # Told to stop while we were deciding: a clean shutdown must not
            # be turned into exit(70). stop() only sets the event, so without
            # this re-check an in-flight fire outlives the daemon it guards.
            if self._stop.is_set():
                return

            dump = self._write_stall_report(stalled, allowed, grace, activity)
            log.critical(
                "watchdog_fired",
                extra={
                    "stalled_s": round(stalled, 1),
                    "allowed_s": round(allowed, 1),
                    "grace_s": round(grace, 1),
                    "timeout_s": self.timeout,
                    "last_activity": activity,
                    "where": _innermost_frame(),
                    "stack_dump": str(dump) if dump else "(could not write)",
                    "action": f"exit({EXIT_WATCHDOG}) for supervisor restart",
                },
            )
            self._record()
            for handler in list(log.handlers) + list(log.parent.handlers if log.parent else []):
                try:
                    handler.flush()
                except Exception:
                    pass
            if self._stop.is_set():       # checked again: writing took time
                return
            os._exit(EXIT_WATCHDOG)

    def _write_stall_report(
        self, stalled: float, allowed: float, grace: float, activity: str
    ) -> Path | None:
        """Dump every thread's stack next to the log, so the cause is knowable.

        A watchdog that only says "something stalled" is half a tool. This says
        which thread was where. Written before ``os._exit``, so it has to be
        cheap and must never raise.
        """
        if self.state_dir is None:
            return None
        path = self.state_dir / f"watchdog-stall-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        lines = [
            "kmitl-authen watchdog stall report",
            f"written            : {time.asctime()}",
            f"platform           : {platform.system()} {platform.release()}",
            f"python             : {platform.python_version()}",
            f"seconds since pet  : {stalled:.1f}",
            f"allowed            : {allowed:.1f}  (timeout {self.timeout:.1f} + grace {grace:.1f})",
            f"last activity      : {activity}",
            "",
            "If 'last activity' names a deliberate sleep (idle:NNNs) then the",
            "grace was applied and something really did stall. If it names a",
            "request (probe/heartbeat/login) while the grace reads 0, the sleep",
            "that should have followed it never ran - the stacks below say why.",
            "",
            "=" * 70,
        ]
        for label, stack in _thread_frames():
            lines += [f"--- thread: {label}", stack.rstrip(), ""]
        try:
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            return None
        return path

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


def _thread_frames() -> list[tuple[str, str]]:
    """Every live thread with its current stack. Stdlib only, no faulthandler."""
    names = {t.ident: t.name for t in threading.enumerate()}
    out: list[tuple[str, str]] = []
    try:
        frames = sys._current_frames()
    except Exception:  # pragma: no cover - not available on exotic builds
        return out
    for ident, frame in frames.items():
        label = f"{names.get(ident, 'unknown')} (id={ident})"
        try:
            stack = "".join(traceback.format_stack(frame))
        except Exception:  # pragma: no cover
            stack = "<could not format>"
        out.append((label, stack))
    return out


def _innermost_frame() -> str:
    """One line saying where the main thread actually is, for the log record."""
    names = {t.name: t.ident for t in threading.enumerate()}
    target = names.get("MainThread")
    try:
        frame = sys._current_frames().get(target)
    except Exception:  # pragma: no cover
        frame = None
    if frame is None:
        return "unknown"
    try:
        summary = traceback.extract_stack(frame)[-1]
        return f"{Path(summary.filename).name}:{summary.lineno} in {summary.name}"
    except Exception:  # pragma: no cover
        return "unknown"


def read_reset_count(state_dir: Path) -> int:
    try:
        return int((state_dir / "watchdog_resets").read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0

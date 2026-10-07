"""Loop-behaviour tests: the regressions that made the old script misbehave."""
import time

import pytest

from kmitl_authen.config import Config
from kmitl_authen.control import Controller
from kmitl_authen.daemon import MIN_TICK, Daemon, State
from kmitl_authen.portal import Outcome, Result
from kmitl_authen.watchdog import Watchdog


class ScriptedPortal:
    """Stands in for ``Portal``; records calls and replays canned results."""

    def __init__(self, online=False, login_result=None, heartbeat_result=None):
        self.online = online
        self.login_result = login_result or Result(Outcome.OK)
        self.heartbeat_result = heartbeat_result or Result(Outcome.OK)
        self.calls = []

    def check_internet(self):
        self.calls.append("probe")
        return (True, "probe ok") if self.online else (False, "captive portal response")

    def login(self, ip):
        self.calls.append("login")
        if self.login_result.ok:
            self.online = True
        return self.login_result

    def heartbeat(self):
        self.calls.append("heartbeat")
        return self.heartbeat_result

    def reset_connections(self, reason=""):
        self.calls.append(f"reset:{reason.split(':')[0]}")

    def close(self):
        self.calls.append("close")


@pytest.fixture
def daemon(tmp_path):
    cfg = Config(username="u", password="p", ip_address="10.0.0.1",
                 heartbeat_interval=60, relogin_interval=0,
                 backoff_initial=2, backoff_max=16, watchdog_timeout=0)
    controller = Controller(tmp_path)
    d = Daemon(cfg, "aabbccddeeff", tmp_path, controller, Watchdog(0, tmp_path))
    return d


def test_offline_tick_logs_in_then_sleeps(daemon):
    daemon.portal = ScriptedPortal(online=False)
    sleep_for, _ = daemon._tick(0.0)
    assert "login" in daemon.portal.calls
    assert sleep_for > 0, "every path through the loop must sleep"


def test_failed_login_backs_off_and_never_busy_loops(daemon):
    """The old `elif connection and not internet` branch retried with no sleep."""
    daemon.portal = ScriptedPortal(online=False,
                                   login_result=Result(Outcome.REJECTED, "nope"))
    delays = []
    for _ in range(5):
        sleep_for, _ = daemon._tick(0.0)
        delays.append(sleep_for)
    assert all(d >= 1.0 for d in delays), f"a retry slept less than a second: {delays}"
    assert max(delays) > min(delays), "backoff did not grow"
    assert max(delays) <= daemon.cfg.backoff_max


def test_successful_login_resets_backoff(daemon):
    daemon.portal = ScriptedPortal(online=False,
                                   login_result=Result(Outcome.REJECTED, "nope"))
    for _ in range(4):
        daemon._tick(0.0)
    assert daemon.backoff > daemon.cfg.backoff_initial
    daemon.portal = ScriptedPortal(online=True)
    daemon._tick(time.monotonic() + 999)
    assert daemon.backoff == daemon.cfg.backoff_initial


def test_online_tick_heartbeats_and_schedules_the_next_one(daemon):
    daemon.portal = ScriptedPortal(online=True)
    sleep_for, next_hb = daemon._tick(0.0)
    assert daemon.state == State.ONLINE
    assert "heartbeat" in daemon.portal.calls
    assert next_hb > time.monotonic()
    assert sleep_for <= daemon.cfg.heartbeat_interval


def test_online_tick_does_not_heartbeat_early(daemon):
    daemon.portal = ScriptedPortal(online=True)
    daemon._tick(time.monotonic() + 999)
    assert "heartbeat" not in daemon.portal.calls


def test_heartbeat_failure_triggers_immediate_relogin(daemon):
    """The old loop waited another full interval before reacting."""
    daemon.portal = ScriptedPortal(online=True,
                                   heartbeat_result=Result(Outcome.REJECTED, "403"))
    sleep_for, _ = daemon._tick(0.0)
    assert daemon.portal.calls.count("login") == 1
    assert sleep_for <= 5, "must re-check soon after a forced re-login"


def test_forced_relogin_request_is_honoured_before_probing(daemon):
    daemon.portal = ScriptedPortal(online=True)
    daemon.controller.request_relogin("test")
    daemon._tick(time.monotonic() + 999)
    assert daemon.portal.calls[0].startswith("reset")
    assert "login" in daemon.portal.calls
    assert "probe" not in daemon.portal.calls
    assert daemon.counters.forced_relogins_total == 1


def test_forced_relogin_resets_the_connection_pool(daemon):
    """A stale keep-alive socket is the other half of the Windows hang."""
    daemon.portal = ScriptedPortal(online=True)
    daemon.controller.request_relogin("test")
    daemon._tick(0.0)
    assert any(c.startswith("reset") for c in daemon.portal.calls)


def test_scheduled_relogin_fires_after_the_interval(daemon):
    daemon.cfg.relogin_interval = 100
    daemon.portal = ScriptedPortal(online=True)
    daemon.last_login = time.monotonic() - 200
    daemon._tick(time.monotonic() + 999)
    assert "login" in daemon.portal.calls


def test_scheduled_relogin_does_not_fire_early(daemon):
    daemon.cfg.relogin_interval = 100
    daemon.portal = ScriptedPortal(online=True)
    daemon.last_login = time.monotonic() - 10
    daemon._tick(time.monotonic() + 999)
    assert "login" not in daemon.portal.calls


def test_credential_failures_stop_before_locking_the_account(daemon):
    daemon.cfg.max_credential_failures = 3
    daemon.portal = ScriptedPortal(
        online=False, login_result=Result(Outcome.BAD_CREDENTIALS, "userPassError"))
    for _ in range(6):
        daemon._tick(0.0)
        if daemon.state == State.BLOCKED:
            break
    assert daemon.state == State.BLOCKED
    assert daemon.portal.calls.count("login") == 3


def test_credential_cooldown_when_configured_to_keep_trying(daemon):
    daemon.cfg.max_credential_failures = 2
    daemon.cfg.exit_on_credential_failure = False
    daemon.portal = ScriptedPortal(
        online=False, login_result=Result(Outcome.BAD_CREDENTIALS, "userPassError"))
    sleeps = [daemon._tick(0.0)[0] for _ in range(3)]
    assert daemon.state != State.BLOCKED
    assert max(sleeps) >= 600, "a credential cooldown must be long, not a retry storm"


def test_max_login_attempts_is_actually_enforced(daemon):
    """The old code only printed at `attempt == max`, and never stopped."""
    daemon.cfg.max_login_attempts = 3
    daemon.portal = ScriptedPortal(online=False,
                                   login_result=Result(Outcome.NETWORK_ERROR, "timeout"))
    sleeps = [daemon._tick(0.0)[0] for _ in range(4)]
    assert daemon.portal.calls.count("login") == 3
    assert sleeps[-1] == daemon.cfg.backoff_max


def test_unexpected_exception_does_not_end_the_loop(daemon, monkeypatch):
    """An unhandled exception used to kill the process outright."""
    boom = {"count": 0}

    def exploding_tick(_next_hb):
        boom["count"] += 1
        if boom["count"] <= 2:
            raise RuntimeError("synthetic failure")
        daemon.controller.request_shutdown("test-done")
        return 0.0, 0.0

    daemon.portal = ScriptedPortal(online=True)
    monkeypatch.setattr(daemon, "_tick", exploding_tick)
    monkeypatch.setattr(daemon.controller, "wait", lambda s: "timeout")
    daemon.run()
    assert daemon.counters.unexpected_errors_total == 2
    assert daemon.state == State.STOPPED


def test_status_never_leaks_the_password(daemon):
    """``/status`` is served over HTTP, so it must not carry the secret."""
    daemon.cfg.password = "very-distinctive-secret"
    status = daemon.status()
    assert "password" not in status
    assert daemon.cfg.password not in str(status)


def test_scheduled_relogin_measures_from_startup_when_never_logged_in(daemon):
    """Starting up already authenticated must not disable the proactive refresh."""
    daemon.cfg.relogin_interval = 100
    daemon.portal = ScriptedPortal(online=True)
    daemon.last_login = None
    daemon.started_monotonic = time.monotonic() - 200
    daemon._tick(time.monotonic() + 999)
    assert "login" in daemon.portal.calls


def test_no_scheduled_relogin_right_after_startup(daemon):
    daemon.cfg.relogin_interval = 100
    daemon.portal = ScriptedPortal(online=True)
    daemon.last_login = None
    daemon.started_monotonic = time.monotonic()
    daemon._tick(time.monotonic() + 999)
    assert "login" not in daemon.portal.calls


# --- regressions from a real 12-hour run log --------------------------------

def test_default_config_does_not_trip_its_own_watchdog():
    """The shipped defaults must not make the daemon kill itself.

    heartbeat_interval=300 against watchdog_timeout=180 means a healthy daemon
    sleeps for longer than the watchdog's patience; without the idle grace it
    exited 70 on every single cycle.
    """
    cfg = Config(username="u", password="p")
    assert cfg.heartbeat_interval > cfg.watchdog_timeout, (
        "this test is pointless unless the sleep really can exceed the timeout"
    )
    dog = Watchdog(cfg.watchdog_timeout)
    dog.pet("idle", expected_idle=cfg.heartbeat_interval)
    with dog._lock:
        allowed = dog.timeout + dog._grace
    assert allowed >= cfg.heartbeat_interval + cfg.read_timeout


def test_sleep_declares_the_idle_period_to_the_watchdog(daemon, monkeypatch):
    declared = []
    monkeypatch.setattr(daemon.watchdog, "pet",
                        lambda activity="", expected_idle=0.0: declared.append(expected_idle))
    monkeypatch.setattr(daemon.controller, "wait", lambda s: "timeout")
    daemon._sleep(300.0)
    assert 300.0 in declared, f"the 300s sleep was not declared: {declared}"


def test_long_gap_is_detected_and_forces_a_relogin(daemon):
    """The run log went silent for 80 minutes between two heartbeats."""
    daemon._check_gap(requested=300.0, mono_elapsed=4805.0, wall_elapsed=4805.0)
    assert daemon.counters.long_gaps_total == 1
    assert daemon.last_gap_seconds == 4805.0
    assert daemon.controller.take_relogin_request() == "gap:stall"


def test_suspend_is_distinguished_from_a_stall(daemon):
    """A suspended machine advances the wall clock but not the monotonic one."""
    daemon._check_gap(requested=300.0, mono_elapsed=301.0, wall_elapsed=4805.0)
    assert daemon.controller.take_relogin_request() == "gap:suspend_or_clock_change"


def test_normal_sleep_is_not_reported_as_a_gap(daemon):
    daemon._check_gap(requested=300.0, mono_elapsed=301.2, wall_elapsed=301.2)
    assert daemon.counters.long_gaps_total == 0
    assert daemon.controller.take_relogin_request() is None


def test_short_sleeps_get_an_absolute_floor_not_a_ratio(daemon):
    """A 1s tick that takes 3s is scheduler noise, not a gap."""
    daemon._check_gap(requested=1.0, mono_elapsed=3.0, wall_elapsed=3.0)
    assert daemon.counters.long_gaps_total == 0


def test_heartbeat_network_error_does_not_cause_a_login_storm(daemon):
    """The log shows 122 logins in 9 seconds after one heartbeat exception.

    The old code returned from start() on a heartbeat exception, re-entered,
    and then hammered login() with no sleep while the portal kept rejecting.
    """
    daemon.portal = ScriptedPortal(
        online=True, heartbeat_result=Result(Outcome.NETWORK_ERROR, "connection_error"))
    daemon.portal.login_result = Result(Outcome.REJECTED, "portal rejected")

    sleeps = []
    for _ in range(8):
        sleep_for, _ = daemon._tick(0.0)
        sleeps.append(sleep_for)
        daemon.portal.online = False      # still behind the captive portal

    logins = daemon.portal.calls.count("login")
    elapsed = sum(sleeps)
    rate = logins / max(elapsed, 1e-9)
    assert rate < 1.0, f"{logins} logins across {elapsed:.1f}s = {rate:.1f}/s"
    assert all(s >= MIN_TICK for s in sleeps)


def test_credential_failures_must_be_consecutive_to_stop_the_daemon(daemon):
    """Scattered rejections must not add up to "the password is wrong".

    The real portal's verdict field is not fully known (a 200 with falsy
    `success` was observed on logins that worked), so a misread body has to be
    survivable rather than permanently stopping the daemon.
    """
    daemon.cfg.max_credential_failures = 3
    bad = Result(Outcome.BAD_CREDENTIALS, "userPassError")

    for _ in range(3):
        # One bad-looking login...
        daemon.portal = ScriptedPortal(online=False, login_result=bad)
        daemon._tick(0.0)
        assert daemon.state != State.BLOCKED
        # ...then real connectivity proves the credentials were fine.
        daemon.portal = ScriptedPortal(online=True)
        daemon._tick(time.monotonic() + 999)
        assert daemon.consecutive_credential_failures == 0

    assert daemon.counters.credential_failures_total == 3   # still counted
    assert daemon.state != State.BLOCKED                   # but never blocked


def test_connectivity_outranks_the_portals_own_verdict(daemon):
    daemon.consecutive_credential_failures = 2
    daemon.portal = ScriptedPortal(online=True)
    daemon._tick(time.monotonic() + 999)
    assert daemon.consecutive_credential_failures == 0


def test_a_rejected_login_still_recovers_if_the_probe_says_online(daemon):
    """A login the portal reports as failed, but which actually worked."""
    daemon.portal = ScriptedPortal(online=False,
                                   login_result=Result(Outcome.REJECTED, "success=false"))
    daemon.portal.login_result = Result(Outcome.REJECTED, "success=false")
    daemon._tick(0.0)
    assert daemon.state == State.BACKOFF
    # The gate did open, whatever the body said.
    daemon.portal.online = True
    daemon._tick(0.0)
    assert daemon.state == State.ONLINE
    assert daemon.backoff == daemon.cfg.backoff_initial

"""Transport guarantees, MAC pinning, and the watchdog."""
import json
import time

import pytest
import requests

from kmitl_authen import macaddr, netutil
from kmitl_authen.watchdog import Watchdog, read_reset_count


# -- netutil ------------------------------------------------------------
def test_session_injects_a_timeout(monkeypatch):
    seen = {}

    def fake(self, method, url, **kwargs):
        seen.update(kwargs)
        return "response"

    monkeypatch.setattr(requests.Session, "request", fake)
    session = netutil.build_session((3.0, 9.0), "ua")
    session.get("http://example.invalid/")
    assert seen["timeout"] == (3.0, 9.0)


def test_explicit_timeout_still_wins(monkeypatch):
    seen = {}
    monkeypatch.setattr(requests.Session, "request",
                        lambda self, m, u, **kw: seen.update(kw))
    session = netutil.build_session((3.0, 9.0), "ua")
    session.get("http://example.invalid/", timeout=(1.0, 2.0))
    assert seen["timeout"] == (1.0, 2.0)


def test_keepalive_is_requested_on_the_socket():
    options = netutil._keepalive_socket_options()
    import socket as s
    assert (s.SOL_SOCKET, s.SO_KEEPALIVE, 1) in options


def test_session_carries_a_user_agent():
    session = netutil.build_session((1.0, 1.0), "my-agent/1.0")
    assert session.headers["User-Agent"] == "my-agent/1.0"


@pytest.mark.parametrize(
    "exc,label",
    [
        (requests.exceptions.ConnectTimeout(), "connect_timeout"),
        (requests.exceptions.ReadTimeout(), "read_timeout"),
        (requests.exceptions.SSLError(), "tls_error"),
        (requests.exceptions.ConnectionError(), "connection_error"),
        (ValueError(), "ValueError"),
    ],
)
def test_exception_labels_are_stable(exc, label):
    assert netutil.describe_exception(exc) == label


def test_a_wrapped_timeout_is_still_reported_as_a_timeout():
    """"portal went silent" must never be flattened into "connection_error".

    Depending on the urllib3 version and whether the socket was fresh or
    reused, a read timeout can arrive wrapped in a generic ConnectionError.
    That is the signature of the original hang, so it has to survive.
    """
    try:
        try:
            raise requests.exceptions.ReadTimeout("Read timed out")
        except requests.exceptions.ReadTimeout as inner:
            raise requests.exceptions.ConnectionError("Max retries exceeded") from inner
    except requests.exceptions.ConnectionError as outer:
        assert netutil.describe_exception(outer) == "read_timeout"


def test_a_wrapped_connect_timeout_survives_too():
    try:
        try:
            raise TimeoutError("timed out")
        except TimeoutError as inner:
            raise requests.exceptions.ConnectionError("wrapped") from inner
    except requests.exceptions.ConnectionError as outer:
        assert netutil.describe_exception(outer) == "timeout"


def test_dns_failure_is_labelled_separately():
    import socket as s
    try:
        try:
            raise s.gaierror("Name or service not known")
        except s.gaierror as inner:
            raise requests.exceptions.ConnectionError("dns") from inner
    except requests.exceptions.ConnectionError as outer:
        assert netutil.describe_exception(outer) == "dns_error"


def test_connection_refused_is_distinguished_from_a_timeout():
    try:
        try:
            raise ConnectionRefusedError(111, "Connection refused")
        except ConnectionRefusedError as inner:
            raise requests.exceptions.ConnectionError("refused") from inner
    except requests.exceptions.ConnectionError as outer:
        assert netutil.describe_exception(outer) == "connection_refused"


def test_exception_chain_walk_terminates_on_a_cycle():
    a = ValueError("a")
    b = ValueError("b")
    a.__context__ = b
    b.__context__ = a
    assert len(netutil._exception_chain(a)) <= 8


def test_no_transport_level_retries_are_configured():
    """A urllib3 Retry here would mask the real exception type."""
    session = netutil.build_session((1.0, 1.0), "ua")
    for adapter in session.adapters.values():
        assert adapter.max_retries.total in (0, False), (
            "transport retries would wrap timeouts in MaxRetryError"
        )
        assert adapter.max_retries.read is False, (
            "read=0 wraps the timeout; read=False re-raises the original"
        )


def test_reset_closes_adapters():
    session = netutil.build_session((1.0, 1.0), "ua")
    closed = []
    for adapter in session.adapters.values():
        adapter.close = lambda a=adapter: closed.append(a)
    netutil.reset(session)
    assert len(closed) == len(session.adapters)


# -- macaddr ------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("aa:bb:cc:dd:ee:ff", "aabbccddeeff"),
        ("AA-BB-CC-DD-EE-FF", "aabbccddeeff"),
        ("aabbccddeeff", "aabbccddeeff"),
        ("aa bb cc dd ee ff", "aabbccddeeff"),
        ("not-a-mac", ""),
        ("aabbccddee", ""),
        ("", ""),
    ],
)
def test_normalise(raw, expected):
    assert macaddr.normalise(raw) == expected


def test_pretty_round_trip():
    assert macaddr.pretty("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"


def test_configured_mac_wins(tmp_path):
    assert macaddr.resolve("AA:BB:CC:00:11:22", "", tmp_path) == "aabbcc001122"


def test_invalid_configured_mac_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="not a valid MAC"):
        macaddr.resolve("nonsense", "", tmp_path)


def test_mac_is_pinned_on_first_detection(tmp_path, monkeypatch):
    monkeypatch.setattr(macaddr, "_from_psutil", lambda ip: "001122334455")
    first = macaddr.resolve("", "", tmp_path)
    assert first == "001122334455"
    assert json.loads((tmp_path / "identity.json").read_text())["mac"] == first

    # Detection now reports a different adapter; the pin must still win, so the
    # portal keeps seeing one stable device.
    monkeypatch.setattr(macaddr, "_from_psutil", lambda ip: "ffeeddccbbaa")
    assert macaddr.resolve("", "", tmp_path) == first


def test_random_uuid_getnode_is_refused(monkeypatch):
    # CPython sets the multicast bit when it invents a node id.
    monkeypatch.setattr(macaddr.uuid, "getnode", lambda: 0x010000000000 | 0xABCDEF)
    assert macaddr._from_uuid_getnode() == ""


def test_real_uuid_getnode_is_accepted(monkeypatch):
    monkeypatch.setattr(macaddr.uuid, "getnode", lambda: 0x001122334455)
    assert macaddr._from_uuid_getnode() == "001122334455"


def test_no_mac_anywhere_raises(tmp_path, monkeypatch):
    for name in ("_from_psutil", "_from_linux_sysfs"):
        monkeypatch.setattr(macaddr, name, lambda *a: "")
    monkeypatch.setattr(macaddr, "_from_windows_getmac", lambda: "")
    monkeypatch.setattr(macaddr, "_from_uuid_getnode", lambda: "")
    with pytest.raises(ValueError, match="could not determine a MAC"):
        macaddr.resolve("", "", tmp_path)


def test_virtual_adapters_are_recognised():
    assert macaddr._is_virtual("00155d001122")    # Hyper-V / WSL
    assert macaddr._is_virtual("080027001122")    # VirtualBox
    assert not macaddr._is_virtual("3c970e001122")


# -- watchdog -----------------------------------------------------------
def test_watchdog_does_not_fire_while_petted(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr("os._exit", lambda code: exits.append(code))
    dog = Watchdog(timeout=1.0, state_dir=tmp_path)
    dog.start()
    for _ in range(8):
        time.sleep(0.2)
        dog.pet("test")
    dog.stop()
    assert exits == []


def test_watchdog_fires_and_records_when_stalled(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr("os._exit", lambda code: exits.append(code))
    dog = Watchdog(timeout=1.0, state_dir=tmp_path)
    dog.start()
    time.sleep(3.0)                      # never pet
    dog.stop()
    from kmitl_authen import EXIT_WATCHDOG
    assert EXIT_WATCHDOG in exits
    assert read_reset_count(tmp_path) >= 1


def test_watchdog_disabled_with_zero_timeout(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr("os._exit", lambda code: exits.append(code))
    dog = Watchdog(timeout=0, state_dir=tmp_path)
    dog.start()
    time.sleep(1.0)
    assert exits == []
    assert read_reset_count(tmp_path) == 0


def test_watchdog_counter_write_is_atomic(tmp_path):
    """The counter is written as we die, so a truncate-then-write could lose it."""
    dog = Watchdog(timeout=1.0, state_dir=tmp_path)
    dog._record()
    dog._record()
    assert read_reset_count(tmp_path) == 2
    assert not (tmp_path / "watchdog_resets.tmp").exists()


def test_watchdog_counter_survives_a_corrupt_file(tmp_path):
    (tmp_path / "watchdog_resets").write_text("not-a-number")
    Watchdog(timeout=1.0, state_dir=tmp_path)._record()
    assert read_reset_count(tmp_path) == 1


# --- stall diagnostics -----------------------------------------------------
# A watchdog that says "something stalled" without saying where is half a tool.

def test_firing_writes_a_stall_report_naming_the_threads(tmp_path, monkeypatch):
    exits = []
    monkeypatch.setattr("os._exit", lambda code: exits.append(code))
    dog = Watchdog(timeout=0.5, state_dir=tmp_path)
    dog.start()
    time.sleep(2.0)                       # never pet
    dog.stop()

    reports = sorted(tmp_path.glob("watchdog-stall-*.txt"))
    assert reports, "no stall report was written"
    text = reports[0].read_text()
    assert "seconds since pet" in text
    assert "last activity" in text
    assert "--- thread:" in text
    assert "MainThread" in text, "the stuck thread's stack is the whole point"
    assert "watchdog" in text, "the watchdog thread should appear too"


def test_stall_report_explains_how_to_read_it(tmp_path):
    dog = Watchdog(timeout=1.0, state_dir=tmp_path)
    path = dog._write_stall_report(stalled=200.0, allowed=180.0, grace=0.0,
                                   activity="heartbeat")
    assert path is not None
    text = path.read_text()
    # The distinction that actually matters when reading one of these.
    assert "idle:NNNs" in text
    assert "grace" in text
    assert "last activity      : heartbeat" in text


def test_stall_report_is_optional_without_a_state_dir():
    dog = Watchdog(timeout=1.0, state_dir=None)
    assert dog._write_stall_report(1.0, 1.0, 0.0, "x") is None


def test_half_way_warning_fires_before_death(tmp_path, monkeypatch):
    """Warn at 50% of the budget, while the process is still alive.

    Records are captured with a handler attached directly to the logger
    rather than via caplog: logging_setup.setup() sets propagate=False on
    `kmitl_authen`, so whether caplog sees anything depends on which other
    tests ran first.
    """
    import logging

    exits = []
    monkeypatch.setattr("os._exit", lambda code: exits.append(code))

    captured = []

    class Collect(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    handler = Collect()
    logger = logging.getLogger("kmitl_authen")
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        # timeout 6 -> poll 1s, half 3s. Checked at 1,2,3 (quiet) then 4 (warn),
        # stopped at 4.5, death at 6. Wide margins on purpose: a boundary-tight
        # version of this test was flaky.
        dog = Watchdog(timeout=6.0, state_dir=tmp_path)
        dog.start()
        time.sleep(4.5)
        dog.stop()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)

    assert exits == [], "it must not have fired yet"
    assert any("watchdog_half_way" in m for m in captured), \
        f"no early warning was logged; got {captured}"


def test_innermost_frame_reports_a_real_location():
    from kmitl_authen.watchdog import _innermost_frame
    where = _innermost_frame()
    assert ":" in where and " in " in where, where


def test_thread_frames_covers_every_live_thread():
    import threading as t
    from kmitl_authen.watchdog import _thread_frames
    stop = t.Event()
    worker = t.Thread(target=stop.wait, name="probe-thread", daemon=True)
    worker.start()
    try:
        labels = [label for label, _ in _thread_frames()]
        assert any("probe-thread" in label for label in labels)
        assert any("MainThread" in label for label in labels)
    finally:
        stop.set()


def test_stop_prevents_an_in_flight_fire(tmp_path, monkeypatch):
    """A clean shutdown must never be reported as a watchdog kill.

    stop() used to only set the event, so a thread already past its sleep and
    into the firing path would still call os._exit -- which turned a clean
    exit 0 into exit 70. It killed the test runner doing exactly this.
    """
    exits = []
    monkeypatch.setattr("os._exit", lambda code: exits.append(code))
    dog = Watchdog(timeout=0.5, state_dir=tmp_path)
    dog.start()
    time.sleep(1.5)                       # let it fire at least once
    assert exits, "precondition: it should have fired while running"
    before = len(exits)
    dog.stop()
    time.sleep(1.5)                       # nothing more may happen after stop
    assert len(exits) == before, "it fired after being told to stop"
    assert dog._thread is not None and not dog._thread.is_alive(), \
        "stop() must join the thread, not just signal it"

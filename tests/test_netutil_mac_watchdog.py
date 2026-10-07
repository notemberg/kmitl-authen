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

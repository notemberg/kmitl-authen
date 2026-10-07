"""The parsing tests that matter: a weird portal body must never raise."""
import json

import pytest
import requests

from kmitl_authen.config import Config
from kmitl_authen.portal import Outcome, Portal


class FakeResponse:
    def __init__(self, status_code=200, text="", raise_on_text=False):
        self.status_code = status_code
        self._text = text
        self._raise = raise_on_text

    @property
    def text(self):
        if self._raise:
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "boom")
        return self._text


@pytest.fixture
def portal(monkeypatch):
    cfg = Config(username="u", password="p", probe_urls=["http://probe/"])
    p = Portal(cfg, "aabbccddeeff")
    return p


def _stub(portal, monkeypatch, response=None, exc=None):
    """Patch ``requests.Session.request`` so ``TimedSession.request`` still runs.

    Patching it at the base class is the point: it proves the timeout really is
    injected by our subclass rather than by the caller remembering to pass one.
    """

    def fake(self, method, url, **kwargs):
        assert "timeout" in kwargs, "every request must carry a timeout"
        assert kwargs["timeout"], "timeout must not be None"
        if exc is not None:
            raise exc
        return response

    monkeypatch.setattr(requests.Session, "request", fake)


def test_login_accepts_success_true(portal, monkeypatch):
    _stub(portal, monkeypatch, FakeResponse(200, json.dumps({"success": True})))
    assert portal.login("10.0.0.1").outcome == Outcome.OK


def test_login_html_body_is_rejected_not_raised(portal, monkeypatch):
    # The old script did json.loads(text) here and died with JSONDecodeError.
    _stub(portal, monkeypatch, FakeResponse(200, "<html>portal</html>"))
    result = portal.login("10.0.0.1")
    assert result.outcome == Outcome.REJECTED
    assert not result.fatal


def test_login_missing_data_key_is_not_a_crash(portal, monkeypatch):
    # The old script did content_dict['data'] and died with KeyError.
    _stub(portal, monkeypatch, FakeResponse(200, json.dumps({"other": 1})))
    assert portal.login("10.0.0.1").outcome == Outcome.OK


def test_login_bad_credentials_is_fatal(portal, monkeypatch):
    _stub(portal, monkeypatch,
          FakeResponse(200, json.dumps({"success": False, "message": "userPassError"})))
    result = portal.login("10.0.0.1")
    assert result.outcome == Outcome.BAD_CREDENTIALS
    assert result.fatal


def test_login_already_online_counts_as_ok(portal, monkeypatch):
    _stub(portal, monkeypatch,
          FakeResponse(200, json.dumps({"success": False, "message": "user already online"})))
    result = portal.login("10.0.0.1")
    assert result.outcome == Outcome.ALREADY_ONLINE
    assert result.ok


def test_login_server_error_is_retryable_not_fatal(portal, monkeypatch):
    _stub(portal, monkeypatch, FakeResponse(503, "gateway down"))
    result = portal.login("10.0.0.1")
    assert result.outcome == Outcome.NETWORK_ERROR
    assert not result.fatal


def test_login_timeout_is_network_error(portal, monkeypatch):
    _stub(portal, monkeypatch, exc=requests.exceptions.ReadTimeout("slow"))
    result = portal.login("10.0.0.1")
    assert result.outcome == Outcome.NETWORK_ERROR
    assert result.detail == "read_timeout"


def test_login_undecodable_body_does_not_raise(portal, monkeypatch):
    _stub(portal, monkeypatch, FakeResponse(200, raise_on_text=True))
    assert portal.login("10.0.0.1").outcome == Outcome.REJECTED


def test_probe_success_text(portal, monkeypatch):
    _stub(portal, monkeypatch, FakeResponse(200, "success\n"))
    online, _ = portal.check_internet()
    assert online is True


def test_probe_204_with_empty_body(portal, monkeypatch):
    _stub(portal, monkeypatch, FakeResponse(204, ""))
    online, _ = portal.check_internet()
    assert online is True


def test_probe_captive_portal_page_is_offline(portal, monkeypatch):
    _stub(portal, monkeypatch, FakeResponse(200, "<html>login here</html>"))
    online, detail = portal.check_internet()
    assert online is False
    assert "captive portal" in detail


def test_probe_all_unreachable(portal, monkeypatch):
    _stub(portal, monkeypatch, exc=requests.exceptions.ConnectionError("down"))
    online, detail = portal.check_internet()
    assert online is False
    assert detail == "all probes unreachable"


def test_probe_rotates_across_urls(monkeypatch):
    cfg = Config(username="u", password="p",
                 probe_urls=["http://a/", "http://b/", "http://c/"])
    portal = Portal(cfg, "aabbccddeeff")
    tried = []

    def fake(self, method, url, **kwargs):
        tried.append(url)
        if url == "http://c/":
            return FakeResponse(204, "")
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(requests.Session, "request", fake)
    assert portal.check_internet()[0] is True
    assert tried == ["http://a/", "http://b/", "http://c/"]


def test_heartbeat_non_200_is_rejected(portal, monkeypatch):
    _stub(portal, monkeypatch, FakeResponse(403, "nope"))
    result = portal.heartbeat()
    assert result.outcome == Outcome.REJECTED
    assert not result.ok


def test_token_is_captured_into_session_headers(portal, monkeypatch):
    _stub(portal, monkeypatch,
          FakeResponse(200, json.dumps({"success": True, "token": "abc123"})))
    portal.login("10.0.0.1")
    assert portal.session.headers["X-XSRF-TOKEN"] == "abc123"


def test_probe_uses_a_separate_session_from_the_portal(portal):
    """Probe hosts are third parties; they must not get portal credentials."""
    assert portal.probe_session is not portal.session
    portal.session.headers["X-XSRF-TOKEN"] = "secret-token"
    portal.session.cookies.set("JSESSIONID", "secret-cookie")
    assert "X-XSRF-TOKEN" not in portal.probe_session.headers
    assert "JSESSIONID" not in portal.probe_session.cookies


def test_probe_session_is_rebuilt_on_reset(portal):
    before_portal, before_probe = portal.session, portal.probe_session
    portal.reset_connections("test")
    assert portal.session is not before_portal
    assert portal.probe_session is not before_probe
    assert portal.session is not portal.probe_session


def test_local_ip_never_resolves_a_hostname(monkeypatch):
    """getaddrinfo ignores timeouts, so a hostname here could block for ages."""
    import socket as socket_module

    from kmitl_authen.portal import local_ip

    def no_dns(*args, **kwargs):
        raise AssertionError("local_ip must only connect to IP literals")

    monkeypatch.setattr(socket_module, "getaddrinfo", no_dns)
    local_ip(("10.252.13.10", "8.8.8.8"))   # must not raise


def test_local_ip_falls_through_to_the_next_target(monkeypatch):
    import socket as socket_module

    from kmitl_authen.portal import local_ip

    attempted = []

    class FakeSocket:
        def __init__(self, *a, **kw):
            pass

        def settimeout(self, _):
            pass

        def connect(self, addr):
            attempted.append(addr[0])
            if addr[0] != "8.8.8.8":
                raise OSError("network unreachable")

        def getsockname(self):
            return ("192.168.1.50", 0)

        def close(self):
            pass

    monkeypatch.setattr(socket_module, "socket", FakeSocket)
    assert local_ip(("10.252.13.10", "8.8.8.8")) == "192.168.1.50"
    assert attempted == ["10.252.13.10", "8.8.8.8"]

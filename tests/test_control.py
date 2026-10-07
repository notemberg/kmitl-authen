"""Control plane: the three force-relogin paths, and interruptible waiting."""
import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from kmitl_authen import control
from kmitl_authen.control import Controller


@pytest.fixture
def controller(tmp_path):
    c = Controller(tmp_path)
    c.set_status_provider(lambda: {"state": "online", "online": True,
                                   "logins_total": 2, "uptime_seconds": 5.0})
    yield c
    c.stop_http_server()


def test_relogin_request_is_consumed_once(controller):
    assert controller.take_relogin_request() is None
    controller.request_relogin("unit-test")
    assert controller.take_relogin_request() == "unit-test"
    assert controller.take_relogin_request() is None


def test_trigger_file_is_picked_up_and_removed(controller, tmp_path):
    control.trigger_relogin(tmp_path, "from-cli")
    assert controller.wait(10) == "relogin"
    assert not (tmp_path / control.TRIGGER_FILENAME).exists()
    assert controller.take_relogin_request() == "trigger_file:from-cli"


def test_trigger_file_write_is_atomic(tmp_path):
    """A partially written trigger must never be read, so we rename into place."""
    path = control.trigger_relogin(tmp_path, "x")
    assert path.exists()
    assert not path.with_suffix(".tmp").exists()


def test_wait_returns_promptly_on_relogin(controller):
    def fire():
        time.sleep(0.2)
        controller.request_relogin("async")

    threading.Thread(target=fire, daemon=True).start()
    started = time.monotonic()
    assert controller.wait(30) == "relogin"
    # The old code slept 300s in one call; a trigger had to wait it out.
    assert time.monotonic() - started < 5


def test_wait_returns_promptly_on_shutdown(controller):
    threading.Thread(
        target=lambda: (time.sleep(0.2), controller.request_shutdown("async")),
        daemon=True,
    ).start()
    started = time.monotonic()
    assert controller.wait(30) == "shutdown"
    assert time.monotonic() - started < 5


def test_wait_times_out_without_a_trigger(controller):
    started = time.monotonic()
    assert controller.wait(1.5) == "timeout"
    assert 1.0 <= time.monotonic() - started < 4


def test_wait_is_sliced_not_one_long_sleep():
    """Slicing is what keeps Ctrl+C responsive on Windows."""
    assert control.WAIT_SLICE_SECONDS <= 1.0


def _free_port() -> int:
    """Port 0 means "disabled" in the config, so tests ask the OS for a real one."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _get(url, token=None):
    request = urllib.request.Request(url)
    if token:
        request.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _post(url, token=None):
    request = urllib.request.Request(url, method="POST", data=b"")
    if token:
        request.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_http_control_server_endpoints(controller):
    port = controller.start_http_server("127.0.0.1", _free_port())
    assert port
    base = f"http://127.0.0.1:{port}"

    status, body = _get(base + "/status")
    assert status == 200
    assert json.loads(body)["state"] == "online"

    status, body = _get(base + "/healthz")
    assert status == 200

    status, body = _get(base + "/metrics")
    assert status == 200
    assert "kmitl_authen_online 1" in body
    assert "kmitl_authen_logins_total 2" in body

    status, _ = _post(base + "/relogin")
    assert status == 202
    assert controller.take_relogin_request() == "http"

    status, _ = _get(base + "/nope")
    assert status == 404


def test_healthz_is_503_when_offline(tmp_path):
    c = Controller(tmp_path)
    c.set_status_provider(lambda: {"state": "backoff", "online": False})
    port = c.start_http_server("127.0.0.1", _free_port())
    try:
        assert _get(f"http://127.0.0.1:{port}/healthz")[0] == 503
    finally:
        c.stop_http_server()


def test_control_token_is_enforced(controller):
    port = controller.start_http_server("127.0.0.1", _free_port(), token="s3cr3t")
    base = f"http://127.0.0.1:{port}"
    assert _get(base + "/status")[0] == 401
    assert _post(base + "/relogin")[0] == 401
    assert _get(base + "/status", token="s3cr3t")[0] == 200
    assert _post(base + "/relogin", token="s3cr3t")[0] == 202
    # /healthz stays open so container health checks need no secret.
    assert _get(base + "/healthz")[0] == 200


def test_status_provider_errors_do_not_break_the_endpoint(tmp_path):
    c = Controller(tmp_path)
    c.set_status_provider(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert "boom" in c.status()["error"]


def test_signal_handlers_install_without_error(controller):
    controller.install_signal_handlers()   # must not raise on any platform


def test_port_zero_means_disabled(tmp_path):
    c = Controller(tmp_path)
    assert c.start_http_server("127.0.0.1", 0) is None

import json

import pytest

from kmitl_authen import config as cfgmod
from kmitl_authen.config import Config, ConfigError


def test_requires_credentials():
    with pytest.raises(ConfigError, match="username"):
        Config().validate()


def test_legacy_camelcase_keys_are_accepted(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"username": "u", "password": "p",
                                "ipAddress": "10.0.0.5", "interval": 42}))
    monkeypatch.setattr(cfgmod, "default_state_dir", lambda: tmp_path)
    cfg, used = cfgmod.load(None, str(path))
    assert used == path
    assert cfg.ip_address == "10.0.0.5"
    assert cfg.heartbeat_interval == 42.0


def test_precedence_file_then_env_then_cli(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"username": "from_file", "password": "p",
                                "heartbeat_interval": 10}))
    monkeypatch.setenv("KMITL_USERNAME", "from_env")
    monkeypatch.setenv("KMITL_HEARTBEAT_INTERVAL", "20")

    cfg, _ = cfgmod.load(None, str(path))
    assert cfg.username == "from_env"
    assert cfg.heartbeat_interval == 20.0

    class Args:
        username = "from_cli"
        heartbeat_interval = None

    cfg, _ = cfgmod.load(Args(), str(path))
    assert cfg.username == "from_cli"
    assert cfg.heartbeat_interval == 20.0   # CLI left it unset, env still wins


def test_probe_urls_from_comma_string(monkeypatch, tmp_path):
    monkeypatch.setenv("KMITL_USERNAME", "u")
    monkeypatch.setenv("KMITL_PASSWORD", "p")
    monkeypatch.setenv("KMITL_PROBE_URLS", "http://a/, http://b/")
    monkeypatch.setattr(cfgmod, "default_state_dir", lambda: tmp_path)
    cfg, _ = cfgmod.load(None, None)
    assert cfg.probe_urls == ["http://a/", "http://b/"]


def test_bool_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("KMITL_USERNAME", "u")
    monkeypatch.setenv("KMITL_PASSWORD", "p")
    monkeypatch.setenv("KMITL_VERIFY_TLS", "no")
    monkeypatch.setattr(cfgmod, "default_state_dir", lambda: tmp_path)
    cfg, _ = cfgmod.load(None, None)
    assert cfg.verify_tls is False


def test_password_is_redacted_in_dump():
    cfg = Config(username="u", password="hunter2")
    assert cfg.redacted()["password"] == "***"
    assert cfg.redacted()["username"] == "u"


def test_watchdog_must_exceed_read_timeout():
    cfg = Config(username="u", password="p", read_timeout=30, watchdog_timeout=10)
    with pytest.raises(ConfigError, match="watchdog-timeout"):
        cfg.validate()


def test_timeout_tuple_is_always_set():
    cfg = Config(username="u", password="p")
    assert cfg.timeout == (cfg.connect_timeout, cfg.read_timeout)
    assert all(t > 0 for t in cfg.timeout)


def test_watchdog_must_outlast_the_slowest_probe_too():
    """probe_timeout counts as active work, so the watchdog must exceed it."""
    cfg = Config(username="u", password="p", read_timeout=5, probe_timeout=300,
                 connect_timeout=5, watchdog_timeout=60)
    with pytest.raises(ConfigError, match="probe-timeout"):
        cfg.validate()


def test_watchdog_need_not_outlast_the_heartbeat_interval():
    """A long sleep is declared to the watchdog as idle, so this is valid."""
    cfg = Config(username="u", password="p", heartbeat_interval=300,
                 watchdog_timeout=180)
    cfg.validate()   # must not raise


def test_shipped_defaults_are_valid():
    Config(username="u", password="p").validate()

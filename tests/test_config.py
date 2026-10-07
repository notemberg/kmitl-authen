import base64
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


# --- password storage ------------------------------------------------------

def test_b64_round_trip():
    stored = cfgmod.protect("hunter2", "b64")
    assert stored == "b64:aHVudGVyMg=="
    assert cfgmod.unprotect(stored) == "hunter2"


def test_b64_is_honestly_labelled_as_not_strong():
    """It is obfuscation. The code must not claim otherwise anywhere."""
    assert cfgmod.is_strong(cfgmod.protect("x", "b64")) is False
    assert cfgmod.is_strong(cfgmod.protect("x", "plain")) is False
    assert cfgmod.is_strong("dpapi:AAAA") is True
    assert cfgmod.is_strong("dpapi-machine:AAAA") is True
    assert cfgmod.is_strong("keyring:66011374") is True


def test_unicode_password_survives_b64():
    secret = "p@ssคำเตือน éè"
    assert cfgmod.unprotect(cfgmod.protect(secret, "b64")) == secret


def test_plain_scheme_keeps_colons_in_the_password():
    """A password containing ':' must not be truncated by the scheme split."""
    secret = "a:b:c:d"
    assert cfgmod.unprotect(cfgmod.protect(secret, "plain")) == secret
    assert cfgmod.unprotect(cfgmod.protect(secret, "b64")) == secret


def test_protect_refuses_an_empty_password():
    with pytest.raises(ConfigError, match="empty password"):
        cfgmod.protect("", "b64")


def test_unknown_scheme_is_rejected_both_ways():
    with pytest.raises(ConfigError, match="unknown scheme"):
        cfgmod.protect("x", "rot13")
    with pytest.raises(ConfigError, match="unknown password_enc scheme"):
        cfgmod.unprotect("rot13:abc")


def test_missing_scheme_prefix_gives_a_useful_error():
    with pytest.raises(ConfigError, match="must look like"):
        cfgmod.unprotect("aHVudGVyMg==")


def test_corrupt_base64_is_reported_not_crashed():
    with pytest.raises(ConfigError, match="not valid base64"):
        cfgmod.unprotect("b64:!!!not-base64!!!")


def test_dpapi_on_non_windows_explains_itself(monkeypatch):
    monkeypatch.setattr(cfgmod, "_is_windows", lambda: False)
    with pytest.raises(ConfigError, match="only Windows can decrypt"):
        cfgmod.unprotect("dpapi:AAAA")
    with pytest.raises(ConfigError, match="Windows-only"):
        cfgmod.protect("x", "dpapi")


def test_keyring_scheme_round_trip(monkeypatch):
    store = {}

    class FakeKeyring:
        @staticmethod
        def set_password(service, account, secret):
            store[(service, account)] = secret

        @staticmethod
        def get_password(service, account):
            return store.get((service, account))

    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: FakeKeyring)
    stored = cfgmod.protect("hunter2", "keyring", account="66011374")
    assert stored == "keyring:66011374"
    assert "hunter2" not in stored, "the secret must not remain in the file"
    assert cfgmod.unprotect(stored) == "hunter2"


def test_keyring_with_nothing_stored_says_so(monkeypatch):
    class Empty:
        @staticmethod
        def get_password(service, account):
            return None

    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: Empty)
    with pytest.raises(ConfigError, match="no password stored"):
        cfgmod.unprotect("keyring:66011374")


def test_keyring_scheme_needs_an_account():
    with pytest.raises(ConfigError, match="needs the username"):
        cfgmod.protect("x", "keyring", account="")


def test_load_resolves_password_enc(tmp_path, monkeypatch):
    monkeypatch.delenv("KMITL_PASSWORD", raising=False)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "username": "66011374",
        "password_enc": cfgmod.protect("hunter2", "b64"),
    }))
    monkeypatch.setattr(cfgmod, "default_state_dir", lambda: tmp_path)
    cfg, _ = cfgmod.load(None, str(path))
    assert cfg.password == "hunter2"
    assert cfg.password_source == "b64"


def test_env_password_overrides_password_enc(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "username": "u", "password_enc": cfgmod.protect("from-file", "b64"),
    }))
    monkeypatch.setenv("KMITL_PASSWORD", "from-env")
    monkeypatch.setattr(cfgmod, "default_state_dir", lambda: tmp_path)
    cfg, _ = cfgmod.load(None, str(path))
    assert cfg.password == "from-env"
    assert cfg.password_source == "plaintext"


def test_plaintext_password_still_works_and_is_flagged(tmp_path, monkeypatch):
    monkeypatch.delenv("KMITL_PASSWORD", raising=False)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"username": "u", "password": "hunter2"}))
    monkeypatch.setattr(cfgmod, "default_state_dir", lambda: tmp_path)
    cfg, _ = cfgmod.load(None, str(path))
    assert cfg.password == "hunter2"
    assert cfg.password_source == "plaintext"


def test_a_broken_password_enc_fails_loudly_at_load(tmp_path, monkeypatch):
    monkeypatch.delenv("KMITL_PASSWORD", raising=False)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"username": "u", "password_enc": "b64:###"}))
    monkeypatch.setattr(cfgmod, "default_state_dir", lambda: tmp_path)
    with pytest.raises(ConfigError, match="not valid base64"):
        cfgmod.load(None, str(path))


def test_redacted_hides_the_encoded_form_but_keeps_the_scheme():
    cfg = Config(username="u", password="hunter2", password_enc="b64:aHVudGVyMg==")
    red = cfg.redacted()
    assert red["password"] == "***"
    assert red["password_enc"] == "b64:***"
    assert "aHVudGVyMg" not in str(red)


def test_best_scheme_is_dpapi_on_windows(monkeypatch):
    monkeypatch.setattr(cfgmod, "_is_windows", lambda: True)
    assert cfgmod.best_scheme() == "dpapi"


def test_best_scheme_falls_back_to_b64_without_a_usable_keyring(monkeypatch):
    monkeypatch.setattr(cfgmod, "_is_windows", lambda: False)
    import sys
    monkeypatch.setitem(sys.modules, "keyring", None)   # import raises
    assert cfgmod.best_scheme() == "b64"


# --- DPAPI plumbing --------------------------------------------------------
# The real calls need Windows. These exercise the ctypes wiring against a fake
# crypt32 so the argument shapes, flags and error path are not pure guesswork.

class _FakeBlob:
    """Captures what the fake crypt32 was handed back."""

    def __init__(self):
        self.payloads = []
        self.flags = []


def _install_fake_crypt32(monkeypatch, transform, succeed=True):
    import ctypes

    recorder = _FakeBlob()

    class FakeDLL:
        def __init__(self, name, **kw):
            self.name = name

        def _crypt(self, source_ref, descr, entropy, reserved, prompt, flags, out_ref):
            source = source_ref._obj
            data = ctypes.string_at(source.pbData, source.cbData)
            recorder.payloads.append(data)
            recorder.flags.append(flags)
            if not succeed:
                return 0
            result = transform(data)
            buf = ctypes.create_string_buffer(result, len(result))
            out = out_ref._obj
            out.cbData = len(result)
            out.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))
            # Keep the buffer alive past this call.
            recorder.payloads.append(buf)
            return 1

        def __getattr__(self, item):
            if item in ("CryptProtectData", "CryptUnprotectData"):
                return self._crypt
            if item == "LocalFree":
                return lambda ptr: 0
            raise AttributeError(item)

    monkeypatch.setattr(ctypes, "WinDLL", FakeDLL, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 13, raising=False)
    return recorder


def test_dpapi_encrypt_passes_the_password_and_the_right_flags(monkeypatch):
    monkeypatch.setattr(cfgmod, "_is_windows", lambda: True)
    rec = _install_fake_crypt32(monkeypatch, lambda d: b"CIPHER" + d)
    stored = cfgmod.protect("hunter2", "dpapi")
    assert stored.startswith("dpapi:")
    assert rec.payloads[0] == b"hunter2"
    assert rec.flags[0] == cfgmod._DPAPI_UI_FORBIDDEN, "user scope must not set LOCAL_MACHINE"


def test_dpapi_machine_scope_sets_the_local_machine_flag(monkeypatch):
    monkeypatch.setattr(cfgmod, "_is_windows", lambda: True)
    rec = _install_fake_crypt32(monkeypatch, lambda d: b"CIPHER" + d)
    cfgmod.protect("hunter2", "dpapi-machine")
    expected = cfgmod._DPAPI_UI_FORBIDDEN | cfgmod._DPAPI_LOCAL_MACHINE
    assert rec.flags[0] == expected


def test_dpapi_round_trip_through_the_fake(monkeypatch):
    monkeypatch.setattr(cfgmod, "_is_windows", lambda: True)
    _install_fake_crypt32(monkeypatch, lambda d: b"X" + d)        # "encrypt"
    stored = cfgmod.protect("hunter2", "dpapi")
    _install_fake_crypt32(monkeypatch, lambda d: d[1:])           # "decrypt"
    assert cfgmod.unprotect(stored) == "hunter2"


def test_dpapi_failure_names_the_account_problem(monkeypatch):
    """The commonest real failure: encrypted as the user, read back as SYSTEM."""
    monkeypatch.setattr(cfgmod, "_is_windows", lambda: True)
    _install_fake_crypt32(monkeypatch, lambda d: d, succeed=False)
    with pytest.raises(ConfigError, match="different Windows account"):
        cfgmod.unprotect("dpapi:" + base64.b64encode(b"blob").decode())
    with pytest.raises(ConfigError, match="dpapi-machine"):
        cfgmod.unprotect("dpapi:" + base64.b64encode(b"blob").decode())


# --- the credential store must never be able to hang us -------------------
# Measured on a headless Linux box: keyring.set_password() never returned.
# The daemon calls unprotect() at startup, so an unbounded call there would
# hang it at boot.

def _hangs_forever(*args, **kwargs):
    import threading
    threading.Event().wait()        # never set


def test_keyring_write_cannot_hang_forever(monkeypatch):
    class Hanging:
        set_password = staticmethod(_hangs_forever)

    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: Hanging)
    monkeypatch.setattr(cfgmod, "KEYRING_TIMEOUT", 0.3)
    import time
    started = time.monotonic()
    with pytest.raises(ConfigError, match="did not answer within"):
        cfgmod.protect("hunter2", "keyring", account="u")
    assert time.monotonic() - started < 5, "the call was not actually bounded"


def test_keyring_read_cannot_hang_the_daemon_at_startup(monkeypatch):
    class Hanging:
        get_password = staticmethod(_hangs_forever)

    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: Hanging)
    monkeypatch.setattr(cfgmod, "KEYRING_TIMEOUT", 0.3)
    import time
    started = time.monotonic()
    with pytest.raises(ConfigError, match="did not answer within"):
        cfgmod.unprotect("keyring:66011374")
    assert time.monotonic() - started < 5


def test_keyring_timeout_names_a_working_alternative(monkeypatch):
    class Hanging:
        get_password = staticmethod(_hangs_forever)

    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: Hanging)
    monkeypatch.setattr(cfgmod, "KEYRING_TIMEOUT", 0.2)
    with pytest.raises(ConfigError) as caught:
        cfgmod.unprotect("keyring:u")
    message = str(caught.value)
    assert "--scheme b64" in message
    assert "KMITL_PASSWORD" in message


def test_best_scheme_rejects_a_keyring_that_only_claims_to_work(monkeypatch):
    """Backend priority is not evidence; a chainer advertises 10 then blocks."""
    class Claims:
        priority = 10
        set_password = staticmethod(_hangs_forever)
        get_password = staticmethod(_hangs_forever)

    class Mod:
        @staticmethod
        def get_keyring():
            return Claims()

    monkeypatch.setattr(cfgmod, "_is_windows", lambda: False)
    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: Mod)
    monkeypatch.setattr(cfgmod, "KEYRING_PROBE_TIMEOUT", 0.2)
    assert cfgmod.best_scheme() == "b64"


def test_best_scheme_accepts_a_keyring_that_round_trips(monkeypatch):
    store = {}

    class Working:
        priority = 10

        @staticmethod
        def set_password(service, account, secret):
            store[(service, account)] = secret

        @staticmethod
        def get_password(service, account):
            return store.get((service, account))

        @staticmethod
        def delete_password(service, account):
            store.pop((service, account), None)

    class Mod:
        @staticmethod
        def get_keyring():
            return Working()

    monkeypatch.setattr(cfgmod, "_is_windows", lambda: False)
    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: Mod)
    assert cfgmod.best_scheme() == "keyring"
    assert store == {}, "the probe must clean up after itself"


def test_a_zero_priority_backend_is_not_used(monkeypatch):
    class Null:
        priority = 0

    class Mod:
        @staticmethod
        def get_keyring():
            return Null()

    monkeypatch.setattr(cfgmod, "_is_windows", lambda: False)
    monkeypatch.setattr(cfgmod, "_keyring_module", lambda: Mod)
    assert cfgmod.best_scheme() == "b64"

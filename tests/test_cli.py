"""CLI surface: argument plumbing, and the relogin fallback chain."""
import json

import pytest

from kmitl_authen import cli, control
from kmitl_authen.config import Config


def test_bare_flags_imply_the_run_subcommand():
    """`kmitl-authen -u x -p y` kept working from the old script's interface."""
    args = cli.build_parser().parse_args(["run", "-u", "x", "-p", "y"])
    assert args.command == "run"
    assert (args.username, args.password) == ("x", "y")


def test_main_inserts_run_for_bare_flags(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "cmd_run", lambda args: seen.setdefault("username", args.username))
    cli.main(["-u", "someone"])
    assert seen["username"] == "someone"


def test_every_config_field_is_reachable_from_the_cli():
    """A field with no flag can only be set via file or env; keep that honest."""
    parser = cli.build_parser()
    run = next(a for a in parser._subparsers._group_actions[0].choices.items()
               if a[0] == "run")[1]
    dests = {a.dest for a in run._actions}
    file_or_env_only = {
        "log_max_bytes", "log_backup_count", "backoff_initial",
        "exit_on_credential_failure",   # exposed as --keep-retrying-bad-credentials
        "verify_tls",                   # exposed as --insecure
        # Deliberately not a flag: you do not paste ciphertext into a shell,
        # where it lands in the process list and the history file. It is
        # written by `config` and `protect`.
        "password_enc",
    }
    from dataclasses import fields
    missing = {f.name for f in fields(Config)} - dests - file_or_env_only
    assert not missing, f"Config fields with no CLI flag: {sorted(missing)}"


def test_control_url_prefers_explicit_flag():
    args = cli.build_parser().parse_args(["status", "--url", "http://host:1234"])
    cfg = Config(control_host="127.0.0.1", control_port=9999)
    assert cli._control_url(args, cfg) == "http://host:1234"


def test_control_url_falls_back_to_the_config():
    args = cli.build_parser().parse_args(["status"])
    cfg = Config(control_host="127.0.0.1", control_port=9999)
    assert cli._control_url(args, cfg) == "http://127.0.0.1:9999"


def test_control_url_rewrites_wildcard_bind_to_loopback():
    """A daemon bound to 0.0.0.0 is reached at 127.0.0.1, not 0.0.0.0."""
    args = cli.build_parser().parse_args(["status"])
    cfg = Config(control_host="0.0.0.0", control_port=8777)
    assert cli._control_url(args, cfg) == "http://127.0.0.1:8777"


def test_control_url_empty_when_the_server_is_disabled():
    args = cli.build_parser().parse_args(["relogin"])
    assert cli._control_url(args, Config(control_port=0)) == ""


def test_relogin_uses_the_http_path_when_it_answers(monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr(cli, "_http", lambda url, method, token, **kw: (
        calls.append((url, method)) or (202, "{}")))
    args = cli.build_parser().parse_args(
        ["relogin", "--url", "http://127.0.0.1:1/", "--state-dir", str(tmp_path)])
    assert cli.cmd_relogin(args) == 0
    assert calls == [("http://127.0.0.1:1/relogin", "POST")]
    # The HTTP path was enough, so no trigger file is left behind.
    assert not (tmp_path / control.TRIGGER_FILENAME).exists()


def test_relogin_falls_back_to_the_trigger_file(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "_http", lambda *a, **kw: (0, "connection refused"))
    args = cli.build_parser().parse_args(
        ["relogin", "--url", "http://127.0.0.1:1/", "--state-dir", str(tmp_path),
         "--reason", "fallback-test"])
    assert cli.cmd_relogin(args) == 0
    trigger = tmp_path / control.TRIGGER_FILENAME
    assert trigger.read_text() == "fallback-test"


def test_relogin_works_without_credentials_in_the_config(tmp_path, monkeypatch):
    """Dropping a trigger file must not require a username or password."""
    monkeypatch.delenv("KMITL_USERNAME", raising=False)
    monkeypatch.delenv("KMITL_PASSWORD", raising=False)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"control_port": 0}))
    args = cli.build_parser().parse_args(
        ["relogin", "--config", str(config), "--state-dir", str(tmp_path)])
    assert cli.cmd_relogin(args) == 0
    assert (tmp_path / control.TRIGGER_FILENAME).exists()


def test_status_reports_cleanly_when_nothing_is_listening(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_http", lambda *a, **kw: (0, "connection refused"))
    args = cli.build_parser().parse_args(["status", "--url", "http://127.0.0.1:1"])
    assert cli.cmd_status(args) == 1
    assert "could not reach" in capsys.readouterr().err


def test_status_hints_at_the_token_on_401(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_http", lambda *a, **kw: (401, '{"error":"unauthorised"}'))
    args = cli.build_parser().parse_args(["status", "--url", "http://127.0.0.1:1"])
    assert cli.cmd_status(args) == 1
    assert "--token" in capsys.readouterr().err


def test_status_prints_the_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_http", lambda *a, **kw: (200, '{"state": "online"}'))
    args = cli.build_parser().parse_args(["status", "--url", "http://127.0.0.1:1"])
    assert cli.cmd_status(args) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "online"


def test_missing_credentials_exits_with_the_config_code(monkeypatch, tmp_path, capsys):
    from kmitl_authen import config as config_module
    monkeypatch.delenv("KMITL_USERNAME", raising=False)
    monkeypatch.delenv("KMITL_PASSWORD", raising=False)
    monkeypatch.setattr(config_module, "default_state_dir", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["run"]) == 2
    assert "configuration error" in capsys.readouterr().err


def test_doctor_is_a_known_subcommand():
    args = cli.build_parser().parse_args(["doctor", "-u", "x", "-p", "y"])
    assert args.command == "doctor"
    assert args.no_login is False


def test_doctor_no_login_flag():
    args = cli.build_parser().parse_args(["doctor", "--no-login"])
    assert args.no_login is True


def test_config_cancelled_by_ctrl_c_writes_nothing(tmp_path, monkeypatch, capsys):
    """A silent exit after the username prompt looked exactly like a crash."""
    target = tmp_path / "config.json"
    monkeypatch.setattr("builtins.input", lambda _="": (_ for _ in ()).throw(KeyboardInterrupt))
    args = cli.build_parser().parse_args(["config", "--path", str(target)])
    assert cli.cmd_config(args) == 0
    assert "Cancelled" in capsys.readouterr().out
    assert not target.exists()


def test_config_rejects_an_ip_typed_as_a_username(tmp_path, monkeypatch, capsys):
    target = tmp_path / "config.json"
    answers = iter(["161.246.5.19", "", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda _="": next(answers))
    monkeypatch.setattr(cli, "_prompt_password", lambda: "secret")
    args = cli.build_parser().parse_args(["config", "--path", str(target)])
    assert cli.cmd_config(args) == 2
    assert "looks like an IP address" in capsys.readouterr().out
    assert not target.exists()


def test_config_strips_an_email_domain(tmp_path, monkeypatch):
    target = tmp_path / "config.json"
    answers = iter(["66011374@kmitl.ac.th", "", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda _="": next(answers))
    monkeypatch.setattr(cli, "_prompt_password", lambda: "secret")
    args = cli.build_parser().parse_args(["config", "--path", str(target)])
    assert cli.cmd_config(args) == 0
    assert json.loads(target.read_text())["username"] == "66011374"


def test_config_requires_a_password(tmp_path, monkeypatch, capsys):
    target = tmp_path / "config.json"
    answers = iter(["66011374", "", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda _="": next(answers))
    monkeypatch.setattr(cli, "_prompt_password", lambda: "")
    args = cli.build_parser().parse_args(["config", "--path", str(target)])
    assert cli.cmd_config(args) == 2
    assert "required" in capsys.readouterr().out


def test_password_prompt_falls_back_when_getpass_fails(monkeypatch, capsys):
    """getpass can fail on some Windows terminals; it must not abort the command."""
    monkeypatch.setattr(cli.getpass, "getpass",
                        lambda _: (_ for _ in ()).throw(OSError("no console")))
    monkeypatch.setattr("builtins.input", lambda _="": "typed-visibly")
    assert cli._prompt_password() == "typed-visibly"
    assert "cannot hide input" in capsys.readouterr().out


# --- doctor --full-cycle verdicts -----------------------------------------
# Regression: the first version printed "That is the full cycle" even when the
# logout had plainly failed two sections earlier. A tool whose job is to remove
# false reassurance must not manufacture it.

class _FakePortal:
    """Portal stub for doctor. `deauth_works` drives the logout behaviour."""

    def __init__(self, cfg, mac, deauth_works=True, online=True):
        from kmitl_authen.portal import Outcome, Result
        self.cfg = cfg
        self.online = online
        self.deauth_works = deauth_works
        self._Result = Result
        self._Outcome = Outcome

    def check_internet(self):
        return (True, "probe ok") if self.online else (False, "captive portal response")

    def probe_one(self, url):
        return self.check_internet()

    def login(self, ip):
        self.online = True
        return self._Result(self._Outcome.OK, "success=true", 200, 12,
                            body='{"success": true}')

    def logout(self):
        if self.deauth_works:
            self.online = False
        return self._Result(self._Outcome.OK, "", 200, 10, body='{"success": true}')

    def heartbeat(self):
        return self._Result(self._Outcome.OK, "", 200, 20, body="")

    def reset_connections(self, reason=""):
        pass

    def close(self):
        pass


def _run_doctor(monkeypatch, tmp_path, deauth_works, extra=()):
    from kmitl_authen import portal as portal_module
    monkeypatch.setattr(
        portal_module, "Portal",
        lambda cfg, mac: _FakePortal(cfg, mac, deauth_works=deauth_works))
    monkeypatch.setattr(portal_module, "local_ip", lambda *a, **k: "10.0.0.1")
    monkeypatch.setattr(cli, "DEAUTH_POLL_SECONDS", 0.0)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    args = cli.build_parser().parse_args([
        "doctor", "-u", "u", "-p", "p", "--mac-address", "aabbccddeeff",
        "--state-dir", str(tmp_path), "--log-level", "CRITICAL", *extra])
    return cli.cmd_doctor(args)


def test_full_cycle_failed_deauth_is_inconclusive_not_a_pass(monkeypatch, tmp_path, capsys):
    code = _run_doctor(monkeypatch, tmp_path, deauth_works=False, extra=["--full-cycle"])
    out = capsys.readouterr().out
    assert "INCONCLUSIVE" in out
    assert "PASS" not in out
    assert "That is the whole cycle" not in out
    assert "NOT the path we wanted to test" in out
    assert code == 2, "an inconclusive cycle must not exit 0"


def test_full_cycle_real_deauth_passes(monkeypatch, tmp_path, capsys):
    code = _run_doctor(monkeypatch, tmp_path, deauth_works=True, extra=["--full-cycle"])
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "CONFIRMED DE-AUTHENTICATED" in out
    assert "INCONCLUSIVE" not in out
    assert code == 0


def test_plain_doctor_says_what_it_did_not_test(monkeypatch, tmp_path, capsys):
    code = _run_doctor(monkeypatch, tmp_path, deauth_works=True)
    out = capsys.readouterr().out
    assert "ALREADY online" in out
    assert "--full-cycle" in out
    assert "PASS" not in out
    assert code == 0

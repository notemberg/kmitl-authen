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

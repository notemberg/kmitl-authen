"""Command line interface: ``run``, ``relogin``, ``status``, ``logout``, ``config``."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import EXIT_CONFIG, EXIT_OK, __version__
from . import config as config_module
from . import control, logging_setup
from .config import Config, ConfigError
from .control import Controller
from .daemon import Daemon
from .macaddr import resolve as resolve_mac
from .watchdog import Watchdog

PROG = "kmitl-authen"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Keep a device authenticated on the KMITL campus network.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run the authentication daemon (default)")
    _add_run_arguments(run)

    relogin = sub.add_parser("relogin", help="force a running daemon to log in again")
    relogin.add_argument("--config", dest="config_file")
    relogin.add_argument("--state-dir", dest="state_dir")
    relogin.add_argument("--url", default=None,
                         help='control server to try first; defaults to the one '
                              'in the config. Pass "" to go straight to the trigger file')
    relogin.add_argument("--token", dest="control_token", help="control server token")
    relogin.add_argument("--reason", default="cli")

    status = sub.add_parser("status", help="print a running daemon's status as JSON")
    status.add_argument("--config", dest="config_file")
    status.add_argument("--state-dir", dest="state_dir")
    status.add_argument("--url", default=None,
                        help="control server URL; defaults to the one in the config")
    status.add_argument("--token", dest="control_token")

    logout = sub.add_parser("logout", help="log out of the portal once and exit")
    _add_run_arguments(logout)

    cfg = sub.add_parser("config", help="write a config.json interactively")
    cfg.add_argument("--path", default="config.json")

    probe = sub.add_parser(
        "doctor",
        help="one-shot check: connectivity, identity, and the portal's real response",
    )
    _add_run_arguments(probe)
    probe.add_argument("--no-login", dest="no_login", action="store_true",
                       help="probe and report only; do not attempt a login")

    return parser


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    """Flags whose ``dest`` matches a ``Config`` field override that field."""
    identity = parser.add_argument_group("identity")
    identity.add_argument("-u", "--username", dest="username",
                          help="username without @kmitl.ac.th (usually the student ID)")
    identity.add_argument("-p", "--password", dest="password",
                          help="password (prefer config.json or KMITL_PASSWORD)")
    identity.add_argument("--ask-password", action="store_true",
                          help="prompt for the password instead of passing it on the CLI")
    identity.add_argument("-i", "--ip-address", dest="ip_address",
                          help="the address to claim to the portal (default: auto-detect)")
    identity.add_argument("--mac-address", dest="mac_address",
                          help="MAC to present (default: detect once, then pin it)")
    identity.add_argument("--acip", dest="acip")

    timing = parser.add_argument_group("timing")
    timing.add_argument("--heartbeat-interval", dest="heartbeat_interval", type=float)
    timing.add_argument("--relogin-interval", dest="relogin_interval", type=float,
                        help="proactive re-login in seconds (0 disables)")
    timing.add_argument("--connect-timeout", dest="connect_timeout", type=float)
    timing.add_argument("--read-timeout", dest="read_timeout", type=float)
    timing.add_argument("--probe-timeout", dest="probe_timeout", type=float)
    timing.add_argument("--backoff-max", dest="backoff_max", type=float)
    timing.add_argument("--watchdog-timeout", dest="watchdog_timeout", type=float,
                        help="hard-exit if a loop iteration stalls this long (0 disables)")

    policy = parser.add_argument_group("failure policy")
    policy.add_argument("--max-login-attempts", dest="max_login_attempts", type=int,
                        help="network-error attempts before a long cooldown (0 = unlimited)")
    policy.add_argument("--max-credential-failures", dest="max_credential_failures", type=int)
    policy.add_argument("--keep-retrying-bad-credentials", dest="exit_on_credential_failure",
                        action="store_const", const=False,
                        help="cool down instead of exiting when the portal rejects the password")

    obs = parser.add_argument_group("observability")
    obs.add_argument("--log-level", dest="log_level",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    obs.add_argument("--log-file", dest="log_file")
    obs.add_argument("--log-json", dest="log_json", action="store_const", const=True,
                     help="emit one JSON object per line")
    obs.add_argument("--no-banner", dest="no_banner", action="store_const", const=True)
    obs.add_argument("--control-port", dest="control_port", type=int,
                     help="serve /status, /metrics, /healthz and POST /relogin (0 disables)")
    obs.add_argument("--control-host", dest="control_host")
    obs.add_argument("--control-token", dest="control_token")

    endpoints = parser.add_argument_group("endpoints (override if KMITL moves the portal)")
    endpoints.add_argument("--login-url", dest="login_url")
    endpoints.add_argument("--logout-url", dest="logout_url")
    endpoints.add_argument("--heartbeat-url", dest="heartbeat_url")
    endpoints.add_argument("--probe-urls", dest="probe_urls",
                           help="comma-separated connectivity-probe URLs, tried in rotation")
    endpoints.add_argument("--user-agent", dest="user_agent")
    endpoints.add_argument("--heartbeat-os", dest="heartbeat_os")

    misc = parser.add_argument_group("misc")
    misc.add_argument("--config", dest="config_file", help="path to config.json")
    misc.add_argument("--state-dir", dest="state_dir",
                      help="where logs, the pinned MAC and the relogin trigger live")
    misc.add_argument("--insecure", dest="verify_tls", action="store_const", const=False,
                      help="skip TLS verification (last resort; logs a warning)")


# -- helpers --------------------------------------------------------------
def _resolve_state_dir(cfg: Config) -> Path:
    path = Path(cfg.state_dir).expanduser() if cfg.state_dir else config_module.default_state_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load(args: argparse.Namespace) -> tuple[Config, Path]:
    if getattr(args, "ask_password", False):
        args.password = getpass.getpass("Password: ")
    cfg, used = config_module.load(args, getattr(args, "config_file", None))
    state_dir = _resolve_state_dir(cfg)
    if not cfg.log_file:
        cfg.log_file = str(state_dir / "kmitl-authen.log")
    logging_setup.setup(
        level=cfg.log_level,
        log_file=cfg.log_file,
        json_lines=cfg.log_json,
        max_bytes=cfg.log_max_bytes,
        backup_count=cfg.log_backup_count,
        secrets=[cfg.password, cfg.control_token],
    )
    log = logging_setup.get_logger("cli")
    log.debug("config_loaded", extra={"file": str(used) if used else "none",
                                      "state_dir": str(state_dir)})
    return cfg, state_dir


def _http(url: str, method: str, token: str | None, timeout: float = 5.0) -> tuple[int, str]:
    request = urllib.request.Request(url, method=method)
    if token:
        request.add_header("X-Auth-Token", token)
    if method == "POST":
        request.data = b""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return 0, str(exc)


# -- commands -------------------------------------------------------------
def cmd_run(args: argparse.Namespace) -> int:
    cfg, state_dir = _load(args)
    log = logging_setup.get_logger("cli")

    try:
        mac = resolve_mac(cfg.mac_address, cfg.ip_address, state_dir)
    except ValueError as exc:
        log.critical("mac_resolution_failed", extra={"error": str(exc)})
        return EXIT_CONFIG

    controller = Controller(state_dir)
    controller.install_signal_handlers()
    # Clear a stale trigger left behind by a previous crash.
    controller.trigger_file.unlink(missing_ok=True)

    watchdog = Watchdog(cfg.watchdog_timeout, state_dir)
    daemon = Daemon(cfg, mac, state_dir, controller, watchdog)

    controller.start_http_server(cfg.control_host, cfg.control_port, cfg.control_token)
    watchdog.start()
    try:
        return daemon.run()
    except KeyboardInterrupt:
        log.info("interrupted")
        return EXIT_OK
    finally:
        watchdog.stop()
        controller.stop_http_server()


def _load_lenient(args: argparse.Namespace) -> Config:
    """Load the config for a client command, where credentials are not needed."""
    try:
        cfg, _ = config_module.load(args, getattr(args, "config_file", None))
        return cfg
    except ConfigError:
        # `relogin` and `status` only need the control endpoint and state dir,
        # so a config missing its username must not stop them.
        cfg = Config()
        for name in ("state_dir", "control_host", "control_port", "control_token"):
            value = getattr(args, name, None)
            if value is not None:
                setattr(cfg, name, value)
        return cfg


def _control_url(args: argparse.Namespace, cfg: Config) -> str:
    """The control server to talk to: explicit --url, else the configured one."""
    if args.url is not None:
        return args.url
    if not cfg.control_port:
        return ""
    host = cfg.control_host if cfg.control_host not in ("", "0.0.0.0") else "127.0.0.1"
    return f"http://{host}:{cfg.control_port}"


def _state_dir_for(args: argparse.Namespace, cfg: Config) -> Path:
    if getattr(args, "state_dir", None):
        return Path(args.state_dir).expanduser()
    if cfg.state_dir:
        return Path(cfg.state_dir).expanduser()
    return config_module.default_state_dir()


def cmd_relogin(args: argparse.Namespace) -> int:
    """Force a re-login via the control server, falling back to the trigger file."""
    cfg = _load_lenient(args)
    url = _control_url(args, cfg)

    if url:
        status, _ = _http(url.rstrip("/") + "/relogin", "POST", cfg.control_token)
        if status in (200, 202):
            print(f"relogin requested via {url}")
            return EXIT_OK
        # Not a failure: the control server is optional and the trigger file
        # always works. Say which path we took, then fall through.
        print(f"control server at {url} not answering ({status or 'no response'}); "
              "using the trigger file instead", file=sys.stderr)

    path = control.trigger_relogin(_state_dir_for(args, cfg), args.reason)
    print(f"wrote {path}; a running daemon picks it up within a second")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    cfg = _load_lenient(args)
    url = _control_url(args, cfg) or "http://127.0.0.1:8777"

    code, body = _http(url.rstrip("/") + "/status", "GET", cfg.control_token)
    if code == 200:
        try:
            print(json.dumps(json.loads(body), indent=2))
        except json.JSONDecodeError:
            print(body)
        return EXIT_OK

    print(f"could not reach the control server at {url} "
          f"({code or 'no response'}): {body.strip()[:200]}", file=sys.stderr)
    if code == 401:
        print("the daemon requires a token: pass --token.", file=sys.stderr)
    else:
        print("start the daemon with --control-port to enable it, and check the "
              f"log at {_state_dir_for(args, cfg) / 'kmitl-authen.log'}", file=sys.stderr)
    return 1


def cmd_logout(args: argparse.Namespace) -> int:
    from .portal import Portal

    cfg, state_dir = _load(args)
    log = logging_setup.get_logger("cli")
    mac = resolve_mac(cfg.mac_address, cfg.ip_address, state_dir)
    portal = Portal(cfg, mac)
    try:
        result = portal.logout()
        log.info("logout", extra={"outcome": result.outcome, "status": result.status_code,
                                  "detail": result.detail})
        return EXIT_OK if result.ok else 1
    finally:
        portal.close()


def cmd_config(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    print(f"Writing {path}. Leave a field blank to keep the default.\n")
    username = input("Username (student ID, without @kmitl.ac.th): ").strip()
    password = getpass.getpass("Password: ")
    ip_address = input("IP address to claim [auto-detect]: ").strip()
    mac_address = input("MAC address [auto-detect and pin]: ").strip()
    interval = input("Heartbeat interval in seconds [300]: ").strip()
    port = input("Control server port, for status/relogin [8777]: ").strip()

    data: dict[str, object] = {}
    if username:
        data["username"] = username
    if password:
        data["password"] = password
    if ip_address:
        data["ip_address"] = ip_address
    if mac_address:
        data["mac_address"] = mac_address
    data["heartbeat_interval"] = float(interval) if interval else 300.0
    data["control_port"] = int(port) if port else 8777

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)   # no-op semantics on Windows, meaningful on POSIX
    except OSError:
        pass
    print(f"\nWrote {path}. It holds your password — keep it out of version control.")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report exactly what this machine and the portal actually do.

    Everything in this project was developed off-campus against a fake portal,
    so the real request/response shapes are inferred rather than observed. This
    prints them verbatim, once, so they can be checked instead of assumed.
    """
    from .portal import Portal, local_ip

    cfg, state_dir = _load(args)
    log = logging_setup.get_logger("doctor")

    print("=" * 72)
    print("kmitl-authen doctor")
    print("=" * 72)

    print("\n[1] identity")
    try:
        mac = resolve_mac(cfg.mac_address, cfg.ip_address, state_dir)
    except ValueError as exc:
        print(f"    MAC            : COULD NOT DETECT -- {exc}")
        return EXIT_CONFIG
    detected_ip = local_ip((cfg.acip, "8.8.8.8"))
    print(f"    username       : {cfg.username}")
    print(f"    MAC presented  : {mac}  ({'from config' if cfg.mac_address else 'detected+pinned'})")
    print(f"    IP presented   : {cfg.ip_address or detected_ip or '(none found)'}"
          f"{'' if cfg.ip_address else '  (auto-detected)'}")
    print(f"    state dir      : {state_dir}")

    portal = Portal(cfg, mac)
    try:
        print("\n[2] connectivity probes")
        for url in cfg.probe_urls:
            online, detail = portal.probe_one(url)
            print(f"    {'OK  ' if online else 'FAIL'} {url}  -> {detail}")

        online, detail = portal.check_internet()
        print(f"\n    verdict: {'internet reachable' if online else 'behind the portal'}"
              f"  ({detail})")

        if args.no_login:
            print("\n[3] login  : skipped (--no-login)")
            return EXIT_OK

        print("\n[3] login -- THIS IS THE PART THAT WAS NEVER TESTED FOR REAL")
        result = portal.login(cfg.ip_address or detected_ip)
        print(f"    HTTP status    : {result.status_code}")
        print(f"    latency        : {result.latency_ms} ms")
        print(f"    my verdict     : {result.outcome}"
              f"{'  (FATAL - would stop the daemon)' if result.fatal else ''}")
        print(f"    why             : {result.detail or '(no reason recorded)'}")
        print(f"    RAW BODY        : {result.body or '(empty)'}")
        print("\n    ^ if 'my verdict' disagrees with whether you end up online,")
        print("      the RAW BODY line is the thing to share -- the verdict is")
        print("      inferred from field names that were guessed, not observed.")

        print("\n[4] heartbeat")
        beat = portal.heartbeat()
        print(f"    HTTP status    : {beat.status_code}")
        print(f"    my verdict     : {beat.outcome}")
        print(f"    RAW BODY        : {beat.body or '(empty)'}")

        print("\n[5] connectivity after login")
        online, detail = portal.check_internet()
        print(f"    {'OK  ' if online else 'FAIL'} {detail}")
        print("\n" + "=" * 72)
        if online:
            print("Result: online. The daemon will work.")
        else:
            print("Result: NOT online. Share sections [3] and [4] above.")
        print("=" * 72)
        return EXIT_OK if online else 1
    finally:
        portal.close()
        log.debug("doctor_finished")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"run", "relogin", "status", "logout", "config", "doctor"}
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "run")          # `kmitl-authen -u x -p y` keeps working
    elif argv[0] not in known and not argv[0].startswith("-"):
        argv.insert(0, "run")
    args = parser.parse_args(argv)

    handlers = {
        "run": cmd_run,
        "relogin": cmd_relogin,
        "status": cmd_status,
        "logout": cmd_logout,
        "config": cmd_config,
        "doctor": cmd_doctor,
    }
    handler = handlers.get(args.command or "run")
    if handler is None:  # pragma: no cover
        parser.print_help()
        return EXIT_CONFIG
    try:
        return handler(args)
    except ConfigError as exc:
        print(f"{PROG}: configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        return EXIT_OK

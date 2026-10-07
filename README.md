# kmitl-authen

Keeps a device authenticated on the KMITL campus network. A rewrite of
[CE-HOUSE/Auto-Authen-KMITL](https://github.com/CE-HOUSE/Auto-Authen-KMITL)
built to survive the failure modes that made the original stop mid-loop —
especially on Windows.

> This is an automation client for the official portal login. It is not a
> bypass, and it needs valid KMITL credentials.

**[DIAGNOSIS.md](DIAGNOSIS.md) explains exactly why the old script froze**, bug
by bug, with the line numbers and the test that now prevents each one.

---

## What is different

| | old `authen.py` | this |
|---|---|---|
| HTTP timeouts | none — the cause of the Windows hang | enforced on every request |
| Hang recovery | none | watchdog → `exit(70)` → supervisor restart |
| Bad response body | `JSONDecodeError` killed the process | classified, never raises |
| Retry policy | tight loop, no sleep | jittered exponential backoff |
| Wrong password | retried forever | stops after 3, before the account locks |
| Force a re-login | kill and restart | signal, trigger file, or HTTP |
| Observability | `print()` + ASCII art | rotating + JSON logs, `/status`, `/metrics`, `/healthz` |
| Identity | `uuid.getnode()`, could change | interface-aware and pinned |
| Deployment | run it in a terminal | Docker, systemd, Windows Task, RouterOS |
| Tests | none | 117 |

---

## Quick start

```bash
git clone <this-repo> && cd kmitl-authen
python3 -m pip install -r requirements.txt

python3 -m kmitl_authen config      # writes config.json, prompts for the password
python3 -m kmitl_authen run
```

Or install it as a command:

```bash
python3 -m pip install .
kmitl-authen run
```

Windows is the same, with `py -3` instead of `python3`.

### Credentials

Three ways, highest precedence last:

```bash
# 1. config.json in the working directory, the state dir, or ~/.config/kmitl-authen/
python3 -m kmitl_authen config

# 2. environment (every setting has a KMITL_<FIELD> variable)
export KMITL_USERNAME=65010000 KMITL_PASSWORD='...'

# 3. command line
kmitl-authen run -u 65010000 --ask-password
```

Prefer `config.json` (chmod 600) or the environment. A password passed as an
argument is visible to every other process via the process list.

---

## Observability

```bash
kmitl-authen run --control-port 8777          # enable the control server
kmitl-authen status                           # full state as JSON, incl. long_gaps_total
curl -s localhost:8777/metrics                # Prometheus
curl -s -o /dev/null -w '%{http_code}\n' localhost:8777/healthz   # 200 online, 503 not
tail -f ~/.local/state/kmitl-authen/kmitl-authen.log
```

Logs are `timestamp LEVEL event key=value ...`, so they grep cleanly:

```
2026-10-07 13:53:42 INFO    login_ok reason=offline outcome=ok status=200 latency_ms=241 ip=10.1.2.3 attempt=1
2026-10-07 13:53:44 INFO    heartbeat_ok outcome=ok status=200 latency_ms=44
2026-10-07 13:58:44 WARNING heartbeat_failed outcome=rejected status=403 latency_ms=38
2026-10-07 13:58:44 INFO    state_change from=online to=logging_in reason=heartbeat_failed
2026-10-07 15:21:03 WARNING long_gap_detected requested_s=300.0 monotonic_s=4805.0 wall_clock_s=4805.0 skew_s=0.0 likely=stall
2026-10-07 15:21:03 INFO    relogin_requested reason=gap:stall
```

The `long_gap_detected` line is the one the old script could not produce. A
real 12-hour run went **80 minutes** between two heartbeats with nothing
logged at all (see [DIAGNOSIS.md](DIAGNOSIS.md)); there was no way to tell
whether a request had blocked or the laptop had slept. Comparing the monotonic
and wall-clock deltas separates those, and either way the daemon now forces a
re-login instead of carrying on with a stale session.

`--log-json` emits one JSON object per line for Loki, Elastic or `jq`. The
password and control token are stripped from every record, so a log file is
safe to share.

| Flag | Default | |
|---|---|---|
| `--log-level` | `INFO` | `DEBUG` adds every probe and HTTP detail |
| `--log-file` | `<state_dir>/kmitl-authen.log` | rotates at 1 MB, keeps 5 |
| `--log-json` | off | one JSON object per line |
| `--control-port` | `0` (off) | `/status`, `/metrics`, `/healthz`, `/relogin` |
| `--control-token` | none | required on every endpoint except `/healthz` |

---

## Forcing a re-login

Three triggers, all equivalent, acted on within one second. Use whichever your
platform makes easy:

```bash
# 1. HTTP — works from anywhere, including a browser or another container
curl -X POST localhost:8777/relogin

# 2. The CLI — tries HTTP, falls back to the trigger file
kmitl-authen relogin

# 3. A signal
kill -HUP <pid>              # Linux/macOS; also SIGUSR1
systemctl reload kmitl-authen
```

On Windows there is no `SIGHUP`, so use the HTTP endpoint, the trigger file, or
`Ctrl+Break` (`SIGBREAK`) in an interactive console:

```powershell
.\deploy\windows\relogin.ps1
# or, by hand:
Set-Content C:\ProgramData\kmitl-authen\relogin 'manual'
```

The trigger file is `<state_dir>/relogin`. Anything that can create a file can
force a re-login — cron, a Task Scheduler job, `docker exec`, a shortcut on the
desktop. It is written with an atomic rename, so a half-written file is never
read, and the daemon deletes it once consumed.

---

## Deployment

### Docker (easiest to keep running)

```bash
cp .env.example deploy/.env      # edit it
cd deploy && docker compose up -d
docker compose logs -f
docker compose exec kmitl-authen kmitl-authen relogin
```

`network_mode: host` is **required**: the portal authorises a (source IP, MAC)
pair, and a bridged container is NATed behind the host, so the session would be
bound to the wrong address.

`restart: unless-stopped` is what turns the watchdog's `exit(70)` into a
self-heal, and the compose health check reads `/healthz`, so `docker ps` shows
`unhealthy` when the daemon is up but not actually online.

### Linux — systemd

```bash
sudo cp deploy/systemd/kmitl-authen.service /etc/systemd/system/
sudo systemctl enable --now kmitl-authen
systemctl reload kmitl-authen        # == force a re-login
journalctl -u kmitl-authen -f
```

The unit header has the full install sequence. `deploy/systemd/kmitl-authen.user.service`
is the rootless variant. Both set `RestartPreventExitStatus=3`, so a rejected
password stops the service instead of looping.

### Windows — Scheduled Task

```powershell
# elevated PowerShell, in the repo root
.\deploy\windows\install-task.ps1 -Username 65010000
```

Runs as SYSTEM at boot (so it does not need anyone logged in), restarts on
failure, no console window, and ACLs `config.json` down to SYSTEM and
Administrators. Then:

```powershell
.\deploy\windows\status.ps1      # status + log tail
.\deploy\windows\relogin.ps1     # force a re-login
Stop-ScheduledTask  -TaskName KMITL-Authen
Unregister-ScheduledTask -TaskName KMITL-Authen -Confirm:$false
```

### MikroTik RouterOS

Both routes are documented in **[deploy/routeros/README.md](deploy/routeros/README.md)**:

- **Container** — RouterOS v7 with the `container` package, arm/arm64/x86, ≥256 MB
  RAM, physical access once to run `/system/device-mode/update container=yes`.
  Runs this exact Python daemon, so you keep the watchdog, `/status` and all
  three re-login triggers.
- **Native script** — `deploy/routeros/kmitl-authen.rsc`, a port of the logic to
  RouterOS script driven by `/system scheduler`. Works on any v7 device
  including 16 MB-flash MIPS, but with real limitations (no cookie jar, no
  URL-encoder, no watchdog) that are spelled out in that README.

RouterOS cannot run Python itself, so there is no third option.

---

## Configuration reference

Every field works in `config.json`, as `KMITL_<FIELD>` in the environment, and
as `--field-name` on the command line. Precedence: defaults < file < env < CLI.

### Identity

| Field | Default | |
|---|---|---|
| `username` | — | required; student ID, without `@kmitl.ac.th` |
| `password` | — | required |
| `ip_address` | auto | the address claimed to the portal; auto-detected per login |
| `mac_address` | auto | detected once, then pinned in `<state_dir>/identity.json` |
| `acip` | `10.252.13.10` | the portal's access-controller address |

### Timing

| Field | Default | |
|---|---|---|
| `heartbeat_interval` | `300` | seconds between heartbeats |
| `relogin_interval` | `28800` | proactive re-login (8 h); `0` disables |
| `connect_timeout` | `5` | TCP connect budget |
| `read_timeout` | `15` | response budget — **this is what prevents the hang** |
| `probe_timeout` | `6` | connectivity-probe read budget |
| `watchdog_timeout` | `180` | hard-exit if active work stalls this long; `0` disables. Must exceed `connect_timeout + max(read_timeout, probe_timeout)`. It does **not** need to exceed `heartbeat_interval` — a deliberate sleep is declared to the watchdog as idle time |
| `backoff_initial` / `backoff_max` | `2` / `120` | retry backoff bounds |

### Failure policy

| Field | Default | |
|---|---|---|
| `max_credential_failures` | `3` | rejections before giving up, so the account does not lock |
| `exit_on_credential_failure` | `true` | `false` → a 15-minute cooldown instead of exiting |
| `max_login_attempts` | `0` | network-error attempts before a long cooldown; `0` = unlimited |

### Endpoints

`login_url`, `logout_url`, `heartbeat_url`, `probe_urls`, `user_agent`,
`heartbeat_os`, `verify_tls`. Override these if KMITL moves the portal; no code
change needed.

### Exit codes

| Code | Meaning | Supervisor should |
|---|---|---|
| 0 | clean shutdown (SIGINT/SIGTERM) | stay stopped |
| 2 | configuration error | stay stopped |
| 3 | portal rejected the credentials | **stay stopped** — fix the password |
| 70 | watchdog fired on a stalled iteration | **restart** |

---

## Troubleshooting

| Symptom | Check |
|---|---|
| `login_bad_credentials` | the username has no `@kmitl.ac.th`; try the password in a browser at the portal |
| `all probes unreachable` | DNS is dead or every probe host is blocked; try `--probe-urls http://<something-reachable>/` |
| `login_rejected` with an HTML body | the portal moved; check `login_url` |
| `watchdog_fired` repeatedly | raise `--watchdog-timeout`, and run with `--log-level DEBUG` to see which call stalls |
| `mac_changed_using_pinned` | a new adapter appeared; set `--mac-address` explicitly or delete `<state_dir>/identity.json` |
| `uuid_getnode_is_random` | no MAC could be detected; set `mac_address` in the config |
| `control_server_failed` | the port is taken — often an older copy of the daemon still running |
| `long_gap_detected likely=suspend_or_clock_change` | normal after a laptop sleep; the daemon re-logs in by itself |
| `long_gap_detected likely=stall` | something blocked the loop; check `monotonic_s` against `requested_s`, and look for a preceding `read_timeout` |
| `read_timeout` on the portal | it accepted the connection and went silent — the original hang, now handled in `read_timeout` seconds |
| online but no internet | the portal session is bound to a different IP; set `ip_address` explicitly |

State, logs and the pinned identity live in:

| | |
|---|---|
| Linux/macOS | `~/.local/state/kmitl-authen/` (or `$XDG_STATE_HOME`) |
| Windows | `%LOCALAPPDATA%\kmitl-authen\` |
| systemd unit | `/var/lib/kmitl-authen/` |
| container | `/var/lib/kmitl-authen/` |

---

## Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest                 # 117 tests, no network needed
```

Layout:

| | |
|---|---|
| `kmitl_authen/config.py` | layered config, validation |
| `kmitl_authen/netutil.py` | sessions that always carry a timeout; keepalive; pool reset |
| `kmitl_authen/portal.py` | probe / login / heartbeat / logout; non-raising response parsing |
| `kmitl_authen/daemon.py` | the state machine, backoff, failure policy |
| `kmitl_authen/control.py` | signals, trigger file, control HTTP server |
| `kmitl_authen/watchdog.py` | stall detection → `exit(70)` |
| `kmitl_authen/macaddr.py` | interface-aware MAC detection and pinning |
| `kmitl_authen/logging_setup.py` | rotating + JSON logs, secret redaction |
| `reference/` | the original scripts, kept for the post-mortem |

---

## Credit

- **assazzin & CSAG** — the original [Auto-authen-KMITL](https://github.com/assazzin/Auto-authen-KMITL) in Perl
- **Network Laboratory** — the [Python version](https://gitlab.com/networklab-kmitl/auto-authen-kmitl) before the CSC-KMITL portal upgrade
- **CE-HOUSE / ISAG Laboratory** — [Auto-Authen-KMITL](https://github.com/CE-HOUSE/Auto-Authen-KMITL), the direct base for this rewrite

MIT licensed, same as the original.

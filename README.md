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
| Tests | none | 178 |

---

## First thing to run, on campus

Everything here was developed **off the campus network**, against a local fake
portal. The loop, the timeouts, the watchdog and the control plane are tested;
the real portal's request and response shapes are *inferred* from the previous
script and from a run log. `doctor` is how you check that in one shot:

```bash
python3 -m kmitl_authen doctor               # Windows: python -m kmitl_authen doctor
python3 -m kmitl_authen doctor --full-cycle  # log out, confirm blocked, log back in
```

> On Windows use `python` or `py -3`. There is no `python3` command, and typing
> it opens the Microsoft Store.

It prints the identity it would present, each connectivity probe, and then the
**raw body** the portal returns for a login and a heartbeat, next to the
verdict this code infers from it. If those two disagree, the raw body is the
thing to share — see [What is verified](#what-is-verified).

Use `doctor --no-login` to check connectivity and identity without touching the
portal at all.

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

A password passed as an argument is visible to every other process via the
process list, so prefer `config.json` or the environment.

### Password storage

`kmitl-authen config` never writes a plaintext password. It picks the strongest
scheme that works unattended on your platform and writes `password_enc`
instead. To convert a config you already have:

```bash
kmitl-authen protect                      # best available scheme
kmitl-authen protect --scheme b64         # or pick one
```

| Scheme | Protects against | Does **not** protect against | Where |
|---|---|---|---|
| `dpapi` | The file being copied to another machine or Windows account | Anything running as you on this machine | Windows (default there) |
| `dpapi-machine` | The file being copied to another machine | Any account on this machine | Windows; **required** when the daemon runs as SYSTEM |
| `keyring` | The password being in the file at all — only a pointer remains | Anything running as you | Needs `pip install keyring`; on Linux also needs an unlocked Secret Service, which a boot-time service usually lacks |
| `b64` | A shoulder-surf, a screenshot, a careless `cat` | **Anyone with the file.** This is obfuscation, not encryption — reversible in one line | Everywhere (Linux fallback) |
| `plain` | Nothing | Nothing | Everywhere |

Being blunt about the Linux case: there is no way to hide a secret from a
process already running as you. `b64` stops you leaking the password by
accident, and that is its whole value. The real control on Linux is file
permissions — `config` and `protect` both `chmod 600` — plus running the
daemon under its own account. If you want more than that, use `keyring` with a
desktop session, or keep the password in a systemd `EnvironmentFile` with mode
600 and let `KMITL_PASSWORD` carry it.

The daemon logs a `password_stored_as_plaintext` warning at startup if it finds
a plaintext password in a file, and a quieter `password_obfuscated_not_encrypted`
note for `b64`, so you are never misled about which you have.

Precedence is unchanged: `--password` beats `KMITL_PASSWORD`, which beats
`password` in the file, which beats `password_enc`. Containers keep using the
environment variable and ignore all of this.

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
| `password` | — | plaintext; prefer `password_enc` |
| `password_enc` | — | `"<scheme>:<value>"`, written by `config` or `protect`. Not a CLI flag — ciphertext on a command line lands in the process list and the shell history |
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
| `watchdog_fired` repeatedly | Read the `grace_s` and `last_activity` fields, and the `watchdog-stall-*.txt` report next to the log — it holds every thread's stack at the moment it fired. `grace_s=0` with `last_activity` naming a request (`heartbeat`/`probe`/`login`) means the sleep that should have followed never ran; `last_activity=idle:NNNs` means a real stall during a deliberate sleep. To keep working meanwhile: `--watchdog-timeout 0` disables it. |
| `mac_changed_using_pinned` | a new adapter appeared; set `--mac-address` explicitly or delete `<state_dir>/identity.json` |
| `uuid_getnode_is_random` | no MAC could be detected; set `mac_address` in the config |
| anything unexplained | run `kmitl-authen doctor` — it prints the raw portal response next to the inferred verdict |
| `password_stored_as_plaintext` | run `kmitl-authen protect` |
| `password_enc uses 'dpapi'... only Windows can decrypt` | the config came from a Windows machine; re-run `kmitl-authen config` here |
| `DPAPI decryption failed ... different Windows account` | encrypted by one account, read by another (commonly: you encrypted it, SYSTEM reads it). Re-run `protect --scheme dpapi-machine` |
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

## What is verified

Being straight about this, because the failure modes here are subtle.

**Tested, and would fail the build if broken** — 178 tests plus CI on Linux,
Windows and macOS across Python 3.9/3.11/3.13:

- every request carries a timeout (asserted below our own session wrapper)
- a silent portal is survived by the read timeout, with the loop continuing
- failed logins back off; the sustained rate stays under 1 request/second
- the watchdog fires on a stalled iteration and not on a deliberate sleep
- all three force-relogin triggers, end to end against a live daemon
- a long gap is detected, classified and acted on (`SIGSTOP` for 70 s)
- bad credentials stop at the limit; scattered ones never do
- logs stay valid UTF-8 and never leak the password, including on a cp874 console
- clean exit 0 on `SIGTERM`, exit 2 on a bad config, exit 3 on bad credentials
- the Docker health check, in both the healthy and unhealthy directions

**Confirmed on campus**, 2026-10-07, Windows 10 / Python 3.12.5 — the real
login response is now a test fixture (`REAL_LOGIN_BODY` in `tests/test_portal.py`):

```json
{"isEscape": false, "data": {}, "enableAutoVerify": false,
 "token": "db91cb19...", "success": true, "tempPassEnable": false,
 "psessionid": "7df7b9da...", "netSwitchStatus": 0}
```

`success` is the verdict field and it is a real boolean. `code` and `status` do
not exist, so ignoring them was necessary rather than merely cautious. The
heartbeat answers HTTP 200 with an empty body. MAC detection and pinning work
on Windows, and the box-drawing banner renders in PowerShell without the
`UnicodeEncodeError` that killed the old script.

Two logins minutes apart returned **different** `token` and `psessionid`
values, both with `success: true`, so a re-login mints a fresh session instead
of erroring on the existing one. Re-authenticating while already online is
safe, and the 8-hour `relogin_interval` refreshes rather than collides.

The portal's **logout does not de-authenticate the machine**: it answers
`success: true` with the session fields stripped, but traffic still flows 30
seconds later. Portal session and gateway authorisation appear to be separate.
A logout-on-exit would therefore free nothing, which is why this daemon does
not do one.

**Still not observed:**

| | |
|---|---|
| Logging in from a **de-authenticated** state | Cannot be reached on demand: the portal's logout answers `success: true` but the gateway keeps letting traffic through, so `--full-cycle` comes back INCONCLUSIVE (exit 2) rather than faking a pass. Disconnect and reconnect to the network to force it, or just run the daemon — the log records the recovery the first time the portal drops you (`internet_unavailable` → `login_ok` → `heartbeat_ok`). |
| Credential-error wording | `_CREDENTIAL_MARKERS` is a guess at the real strings. A false positive only costs a backoff, never a stop: the circuit breaker needs **consecutive** failures and any confirmed connectivity clears the streak. |
| `acip` | Carried over as `10.252.13.10` from the old script. |
| `netSwitchStatus`, `isEscape`, `tempPassEnable` | Present in the response, meaning unknown, ignored. |

**Not tested at all:**

- The Docker image has never been built (no Docker on the development machine);
  CI builds it. The compose file is YAML-validated and the health-check
  one-liner was run against a live daemon.
- `deploy/routeros/kmitl-authen.rsc` has never run on hardware. Syntax is
  checked against MikroTik's docs — `:tolower` is not a RouterOS builtin, so
  there is a manual hex map — but nothing more.
- The Windows Scheduled Task scripts have not been run on Windows.
- `requires-python = ">=3.9"` is a claim CI checks; only 3.10 was available locally.

## Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest                 # 178 tests, no network needed
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

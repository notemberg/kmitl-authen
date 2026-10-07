# Why the old script hung, and what stops it happening again

This is the post-mortem on `reference/authen.py` and `reference/newauthen.py`.
Each finding lists the exact line that caused it, the symptom, and the
guardrail in this repo that prevents a regression.

---

## 1. No request timeout — the actual cause of the Windows freeze

```python
# newauthen.py:94, 147, 163 — every HTTP call in the script
content = agent.post(url, params={...})
content = requests.get('http://detectportal.firefox.com/success.txt')
```

**`requests` has no default timeout.** If `timeout=` is omitted, a call blocks
for as long as the socket stays open. A captive portal that completes the TCP
handshake and then never sends a response byte makes that **forever**.

Why it bit Windows specifically:

- A captive portal typically ACKs the SYN (so there is no connect failure) and
  then silently drops the request. Linux often tears the connection down via
  lower default keepalive behaviour; Windows holds it.
- `signal.signal(signal.SIGINT, handler)` **cannot interrupt a blocking
  `recv()` on Windows.** CPython only runs the Python-level handler when the
  interpreter regains control, so while the socket blocks, the process ignores
  Ctrl+C. That is the "stuck and not continuing the loop, and I can't even kill
  it" symptom exactly.
- `socket.getaddrinfo` ignores timeouts entirely. A DNS lookup against a
  resolver that stops answering after deauthentication blocks for the OS
  resolver's own retry schedule (tens of seconds on Windows), still with no
  Python-level timeout.

**Now:** `netutil.TimedSession.request` injects `timeout=(connect, read)` into
*every* call, so no code path can forget it. `tests/test_portal.py` patches
`requests.Session.request` (the base class, below our override) and asserts the
timeout is present on every single request the portal client makes.

---

## 2. Stale keep-alive sockets across a captive-portal transition

```python
agent = requests.session()   # authen.py:24 — one session for the whole process life
```

A `requests.Session` pools connections. After the network flips from
"authenticated" to "captive portal" (or the laptop resumes from sleep), the
pooled socket is dead but the OS has not told us. The next request reuses it
and stalls — until the read timeout, which did not exist. Combined with #1
this produced an indefinite hang rather than a slow request.

**Now:** TCP keepalive is enabled on every socket
(`netutil._keepalive_socket_options`), and `Portal.reset_connections()` tears
the whole pool down and rebuilds the session on **any** state transition:
before each login, on a heartbeat failure, on a forced re-login, and after an
unexpected exception. Verified by `test_forced_relogin_resets_the_connection_pool`.

---

## 3. Unhandled exceptions killed the process

```python
# authen.py:97-100
content_dict = json.loads(content.text)   # JSONDecodeError when the portal returns HTML
data = content_dict['data']               # KeyError when the shape differs
```

The portal answers with an HTML login page whenever it feels like it. Both
lines raise, nothing catches it, the exception propagates out of `login()` →
out of `start()` → out of `while True: start()`, and the process exits. From
the outside that is indistinguishable from "it stopped working".

`newauthen.py` partly fixed this by checking the status code first, but
`json.loads` on line 103 still raises on a 200 response with an HTML body.

**Now:** `portal._as_json()` returns `None` instead of raising, and
`portal._classify()` turns any body — JSON, HTML, binary, unreadable — into one
of five outcomes. On top of that, `daemon.run()` wraps each iteration in
`try/except Exception`, logs the traceback, backs off, and keeps going.
`test_unexpected_exception_does_not_end_the_loop` locks that in.

---

## 4. Unicode art crashed on a Thai Windows console

```python
print_format('''
 ██████╗ ██████╗ ███╗   ██╗...     # authen.py:149, inside the main loop
''')
```

A Windows console on a non-UTF-8 code page (cp874 for a Thai locale, cp437
elsewhere) raises `UnicodeEncodeError` when `print()` hits `█` or `╗`. Because
this `print_format` call sits **inside the loop**, the exception escapes and
ends the process (see #3). It would look random, because it only fires on the
transition into the "connected" branch.

**Now:** every byte of output goes through `logging`; stdio is reconfigured to
UTF-8 with `errors="replace"` at startup, so an unencodable glyph can never
raise; the banner falls back to pure ASCII when the stream is not UTF-8
(`logging_setup.supports_unicode`); and `--no-banner` turns it off entirely for
services. Verified against `PYTHONIOENCODING=cp874`.

---

## 5. A tight re-login loop with no sleep

```python
# authen.py:165-170
elif connection and not internet:
    if login_attempt == max_login_attempt:
        print_error('Error! Please recheck your username and password...')
    login()                 # <-- no sleep, no backoff
    login_attempt += 1
```

This is the branch taken whenever the probe reaches *something* but not the
internet — i.e. the normal captive-portal state. It calls `login()` as fast as
the network allows, forever. Two consequences:

- The portal gets hammered, which invites rate-limiting or an account lock.
- With wrong credentials it never stops: `login_attempt == max_login_attempt`
  only prints at **exact equality** and never breaks, so the "maximum" was not
  enforced on this path at all.

**Now:** every path through `daemon._tick()` returns a sleep duration of at
least one second; failures use exponential backoff with full jitter capped at
`backoff_max`; and credential rejections are classified separately from
network errors, so three of them stop the daemon (exit code 3) instead of
burning attempts toward a lock. Tests:
`test_failed_login_backs_off_and_never_busy_loops`,
`test_max_login_attempts_is_actually_enforced`,
`test_credential_failures_stop_before_locking_the_account`.

---

## 6. A five-minute `time.sleep()` swallowed everything

```python
time.sleep(time_repeat)     # authen.py:159 — time_repeat = 5*60
connection, heatdone = heatbeat()
```

One long `sleep` meant:

- A failed heartbeat was only noticed up to five minutes after the fact, and
  the response was to `login()` and then sleep *another* five minutes.
- Nothing external could ask for anything. There was no way to force a
  re-login short of killing the process.
- On Windows, a long `sleep` in the main thread delays Ctrl+C handling.

**Now:** `Controller.wait()` waits in one-second slices on a `threading.Event`
and returns early on shutdown or a re-login request, so every trigger is acted
on within a second (`test_wait_returns_promptly_on_relogin`). A failed
heartbeat re-logs in immediately rather than after another interval
(`test_heartbeat_failure_triggers_immediate_relogin`).

---

## 7. The probe mis-read captive portals, and had a single point of failure

```python
content = requests.get('http://detectportal.firefox.com/success.txt')
if content.text == 'success\n':
```

Redirects were followed, so a portal that 302s to its login page and returns
200 was only reported as "no internet" because the body text happened to
differ. And one hard-coded probe host meant that if Mozilla's endpoint was
blocked, blackholed or slow, the script could never conclude it was online.

**Now:** three probe URLs, rotated so one dead host cannot wedge the check;
`allow_redirects=False`, so a portal redirect reads as offline by construction;
and both the `success` body and the HTTP 204 convention are accepted.
Tests: `test_probe_captive_portal_page_is_offline`,
`test_probe_rotates_across_urls`.

---

## 8. The MAC address could change between runs

```python
umac = ''.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                for ele in range(0, 8*6, 8)][::-1])
```

`uuid.getnode()` is not an identity:

- When it cannot find a hardware address it returns a **random** 48-bit value
  with the multicast bit set — different on every run. The portal then sees a
  brand-new device each time, and the old session lingers.
- With several adapters (Hyper-V, WSL, VirtualBox, VPN, `docker0`) which one it
  picks is undefined, so installing Docker Desktop can silently change the
  value. This is a Windows-heavy failure, because Windows machines usually have
  more virtual adapters.

**Now:** `macaddr.resolve()` prefers the interface that owns the configured
IP, skips known virtual-adapter OUI prefixes, warns loudly if `uuid.getnode()
` returned a random node id, and **pins** whatever it chose to
`<state_dir>/identity.json` so later detection changes cannot alter our
identity. `--mac-address` overrides everything.
Tests: `test_mac_is_pinned_on_first_detection`,
`test_random_uuid_getnode_is_refused`.

---

## 9. Nothing supervised the process

Even with every fix above, a hang is always possible: an OpenSSL stall that
ignores its timeout, a suspended laptop, a bug in our own loop.

**Now:** `watchdog.Watchdog` is petted once per iteration. If more than
`watchdog_timeout` seconds pass without a pet it logs `watchdog_fired` with the
last activity, persists a counter, and calls `os._exit(70)`. `os._exit` is
deliberate — a stuck thread may hold a lock that a clean shutdown would need.

Exit 70 is a signal to the supervisor to restart: `Restart=always` in the
systemd unit, `restart: unless-stopped` in compose, `-RestartCount 999` in the
Scheduled Task. Exit **3** (credentials rejected) is excluded from restart via
`RestartPreventExitStatus=3`, so a bad password does not become a retry storm.

Verified end to end: a probe URL made to hang for 300s with a 12s watchdog
exits 70 in 13s and increments the persisted counter.

---

## 10. There was no way to see what it was doing

`print()` to a terminal, with ASCII art for state changes. Nothing to grep, no
history after the window closed, no way to ask a running instance anything.

**Now:**

- `logging` with a console handler plus a rotating file handler
  (`<state_dir>/kmitl-authen.log`, 1 MB × 5), `--log-json` for machine-readable
  lines, and every event as a stable name plus `key=value` fields.
- The password and control token are redacted from every record by a
  `logging.Filter`, so a log file is safe to paste into a bug report.
- A control server on `127.0.0.1`: `GET /status` (full state as JSON),
  `GET /metrics` (Prometheus), `GET /healthz` (503 while offline, which is what
  the container health check uses), `POST /relogin`, `POST /shutdown`.
- `kmitl-authen status` prints that JSON from the CLI.

---

## Appendix: evidence from a real 12-hour run

A 12-hour log of `newauthen.py` (2026-10-07, 02:16 → 14:18, 258 timestamped
lines) confirms findings 1, 5 and 6 with measurements rather than inference.

### The heartbeat cadence, and the two breaks in it

128 heartbeats, nearly all exactly 300 s apart. Only two gaps were not:

| | |
|---|---|
| `06:22:21 → 06:32:33` | 612 s — a heartbeat exception, then recovery (below) |
| `11:58:09 → 13:18:14` | **4805 s = 80.1 minutes of total silence** |

The 80-minute gap is the reported symptom: 16 heartbeats simply never
happened, nothing was logged, and then the loop carried on as if nothing had
occurred. The log cannot say which of two causes it was —

- a heartbeat POST that blocked for 75 minutes, because no call had a timeout
  (finding 1); or
- the machine suspending, with `time.sleep(300)` resuming late.

— and **that ambiguity is itself the finding**. The old script had no way to
tell you, because it logged nothing but successes.

`daemon._check_gap()` now closes this. After every wait it compares the
monotonic and wall-clock deltas against what it asked for, and when a wait
overran by more than `max(60s, 2 × requested)` it logs the gap and forces a
re-login, because a portal session is almost certainly stale after a long
absence:

```
WARNING long_gap_detected requested_s=300.0 monotonic_s=4805.0 wall_clock_s=4805.0 skew_s=0.0 likely=stall
INFO    relogin_requested reason=gap:stall
INFO    login_ok reason=forced:gap:stall outcome=ok status=200 latency_ms=241
```

A suspended machine advances the wall clock while the monotonic clock stands
still, so `skew_s` separates the two causes (on Linux; Windows may advance
both, which is why both numbers are logged rather than just a verdict).
`long_gaps_total` and `last_gap_seconds` are in `/status` and `/metrics`.
Tests: `test_long_gap_is_detected_and_forces_a_relogin`,
`test_suspend_is_distinguished_from_a_stall`.

### The login storm, measured

At `06:27:21` a heartbeat raised an exception — `heatbeat()` returned
`(False, False)`, so `start()` hit `if not connection and not heatdone: return`
and the outer `while True: start()` re-entered with `login_attempt = 0`. The
fresh `start()` then fell into the branch from finding 5, and:

> **122 rejected logins between 06:27:23 and 06:27:32 — 13.6 requests per
> second** against the campus portal, for nine seconds.

`Error! Please recheck your username and password...` appears exactly once, at
attempt 20, and then the loop carried straight on to attempt 122 — which is
finding 5's "the maximum was never enforced", observed in production.

That the portal eventually accepted the 122nd attempt is luck. A portal with
rate limiting would have locked the account.

The replacement classifies a heartbeat exception as a transient network error,
re-logs in **once**, and backs off with jitter.
`test_heartbeat_network_error_does_not_cause_a_login_storm` asserts the
sustained rate stays below 1 request/second — a 13× margin against the
measured 13.6/s.

### The 8-hour cycle is working as designed

The last two `Welcome` banners are 28250 s apart = 7.85 h, which is the
`reset_timer` of 8 h minus the 600 s early return. That one is intentional, not
a fault. It is now `relogin_interval`, and it no longer needs to tear down and
restart the whole loop to happen.

---

## Appendix: a bug this rewrite introduced, and the log that caught it

Checking the new daemon against the 300-second cadence above exposed a
self-inflicted fault worse than the original.

The watchdog was petted once per loop iteration, and an iteration sleeps for
`heartbeat_interval` between heartbeats. With the shipped defaults —
`heartbeat_interval=300`, `watchdog_timeout=180` — a **perfectly healthy**
daemon went 300 s without petting, so the watchdog fired every single cycle:

```
INFO     online username=... heartbeat_interval=30.0
CRITICAL watchdog_fired stalled_s=18.6 timeout_s=18.0 last_activity=probe action=exit(70)
```

Under systemd or compose that is a restart every three minutes, forever. The
test suite missed it because every test used a 5-second interval against a
30-second watchdog, so the sleep never exceeded the timeout.

The fix is for the watchdog to distinguish deliberate idleness from a stall:
`Watchdog.pet(activity, expected_idle=...)` extends the deadline for a sleep
the daemon is about to take on purpose, and `Daemon._sleep()` declares it.
`config.validate()` now also requires `watchdog_timeout` to exceed
`connect_timeout + max(read_timeout, probe_timeout)` — the slowest single
request — while explicitly *not* requiring it to exceed `heartbeat_interval`.

Guarded by `test_default_config_does_not_trip_its_own_watchdog`, which asserts
against the shipped defaults rather than test-local ones, plus
`test_sleep_declares_the_idle_period_to_the_watchdog`.

### And one more, from chasing the label in that log

While reproducing a silent portal, the probe failure came back as
`reason=connection_error` when it was really a 6-second read timeout. The cause
was the explicit `urllib3.util.retry.Retry(read=0)` on the HTTP adapter: on
timeout it raises `MaxRetryError`, which requests surfaces as a generic
`ConnectionError`. requests' own default, `Retry(0, read=False)`, re-raises the
original `ReadTimeout`.

That mislabelling destroyed the single most useful distinction in these logs —
"the network is down" versus "the portal accepted our connection and then went
silent", the latter being finding 1's exact signature. The custom `Retry` is
gone, and `describe_exception()` now walks the whole `__cause__`/`__context__`
chain, so a timeout is reported as one however it arrives, and DNS failures and
refused connections get their own labels. Confirmed end to end:

```
DEBUG probe_error url=http://.../probe reason=read_timeout
```

---

## Appendix: the real portal response, observed

Run on the campus network, 2026-10-07 16:53, Windows 10 / Python 3.12.5.
This settles the "inferred, not observed" column.

```json
{
  "isEscape": false,
  "data": {},
  "enableAutoVerify": false,
  "token": "db91cb19...a372c1c",
  "success": true,
  "tempPassEnable": false,
  "psessionid": "7df7b9da...1dd88e",
  "netSwitchStatus": 0
}
```

The heartbeat answers **HTTP 200 with a completely empty body**.

### What this confirms

| Guess | Verdict |
|---|---|
| `success` is the verdict field | Correct, and it is a real boolean |
| Not consulting `code` / `status` | Correct, and necessary — **neither field exists**, so reading them could only ever have produced a wrong answer |
| `data` is unsafe to index | Correct: `data` is `{}`, so the old `content_dict['data']` survived by luck, and would have raised the moment the portal changed |
| A token is issued | Correct: 64 hex characters, plus a separate `psessionid` that also arrives as a `PSESSIONID` cookie |

All of it is now a fixture in `tests/test_portal.py` (`REAL_LOGIN_BODY`), so a
future change to the classifier is checked against what the portal actually
sends rather than against another guess.

### A correction to finding 5

Earlier in this document I inferred from the 122 "Portal rejected the login
attempt." lines that the real portal returns a 200 with falsy `success` on
logins that work. **That was wrong.** On a working login `success` is `true`.

So those 122 lines were real rejections. During the nine-second storm the
portal was answering `success: false` to nearly every request, and only
accepted one at the end. That makes finding 5 worse, not better: the hammering
was not merely rude, it was actively counter-productive — the portal was
refusing the flood, and the script's only escape was to keep flooding until
something got through.

### A bug this found

`_capture_token()` put the token into `session.headers`, and `requests` sends
session headers to **every** host a session talks to. The portal is
`portal.kmitl.ac.th`; the heartbeat is `nani.csc.kmitl.ac.th` — a different
host. So the login token was being sent to the heartbeat host every 300
seconds. Both are KMITL, so the severity is low, but it is the same mistake as
the probe sharing the portal session, which this document already lists.

The token is now held on the `Portal` instance and attached per request by
`_portal_headers()`, to portal calls only. Asserted by
`test_heartbeat_does_not_carry_the_portal_token`.

### Re-login is safe, and mints a fresh session every time

Two campus logins, minutes apart, both from an already-authenticated state:

| | token | psessionid |
|---|---|---|
| 16:53 | `db91cb19…a372c1c` | `7df7b9da…1dd88e` |
| 17:50 | `1349e13d…d122915e` | `f0535762…48673db` |

Both answered `success: true`, with a **different** token and psessionid each
time. So each login mints a new session rather than erroring on an existing
one. Three consequences:

- The "it will just tell me I'm already authenticated" worry is a non-issue.
  The portal does not treat a re-login as a conflict.
- The proactive `relogin_interval` (8 h) is sound — it refreshes rather than
  colliding.
- Recovering from a confused state by simply logging in again is valid, which
  is what `_do_login` relies on.

### The portal's logout does not de-authenticate the machine

`doctor --full-cycle` found this. The logout answers HTTP 200 with:

```json
{"isEscape": false, "data": {}, "enableAutoVerify": false,
 "success": true, "tempPassEnable": false, "netSwitchStatus": 0}
```

`success: true`, and note what is **missing**: no `token`, no `psessionid`. So
the portal did close its side of the session. But connectivity continued, with
all three probes still passing 30 seconds later on freshly opened sockets.

The likely reading is that the portal session and the gateway's authorisation
are separate: `acip` (10.252.13.10) keeps letting the (IP, MAC) pair through
until its own timeout, whatever the portal records. The alternative — that
logout needs something this client does not send — cannot be ruled out, but
`success: true` with the session fields stripped argues against it.

What follows from it:

- **Logging in from a de-authenticated state remains untested.** It cannot be
  reached on demand from this machine. Disconnecting and reconnecting to the
  network is the manual route; otherwise the daemon's own log will record the
  recovery the first time the portal drops the session by itself
  (`internet_unavailable` → `login_ok` → `heartbeat_ok`).
- A logout-on-exit, which `newauthen.py` added, does not actually free
  anything. This daemon does not log out on exit, which turns out to be the
  right call for a reason I had not anticipated.

### A bug in the test itself

The first `--full-cycle` printed "Result: logged out, confirmed blocked, logged
back in, online. That is the full cycle. The daemon will work." — two sections
after reporting `now offline? : NO - logout did not take effect`.

The verdict only read the final `online` flag and `args.full_cycle`; it never
recorded whether the de-authentication actually happened. A tool whose entire
purpose is to remove false reassurance was manufacturing it.

Now tracked as a three-state `deauth_confirmed` (not attempted / confirmed /
failed), the wait polls for 30 s instead of deciding after 2, section [4] is
relabelled "still authenticated — NOT the path we wanted to test" when
appropriate, and an inconclusive run exits **2** rather than 0 so a script can
tell. Asserted by `test_full_cycle_failed_deauth_is_inconclusive_not_a_pass`.

---

## Summary

| # | Problem | Guardrail |
|---|---|---|
| 1 | No request timeout → indefinite block, Ctrl+C dead on Windows | `TimedSession` injects a timeout into every call; asserted in tests |
| 2 | Stale pooled sockets after a portal transition | TCP keepalive + full pool rebuild on every transition |
| 3 | `json.loads` / `['data']` raised and killed the process | Non-raising parsing + `try/except` around each loop iteration |
| 4 | Unicode art crashed a cp874 console | All output via logging, UTF-8 stdio with `errors="replace"`, ASCII fallback |
| 5 | Re-login loop with no sleep; max attempts never enforced | Mandatory sleep on every path, jittered backoff, credential circuit breaker |
| 6 | One 5-minute `sleep` blocked reaction and signals | Sliced `Event.wait`, sub-second trigger response |
| 7 | Probe followed redirects; single probe host | Three rotated probes, `allow_redirects=False` |
| 8 | `uuid.getnode()` MAC could change between runs | Interface-aware detection, virtual-adapter filtering, pinned identity |
| 9 | A hang stayed hung | Watchdog → `exit(70)` → supervisor restart |
| 10 | No observability | Rotating + JSON logs, redaction, `/status`, `/metrics`, `/healthz` |
| 11 | An 80-minute silent gap, cause unknowable | Gap detection: both clock deltas logged, forced re-login |
| 12 | *(introduced here)* watchdog fired during a normal 300 s sleep | `expected_idle` grace + a test against the shipped defaults |
| 13 | *(introduced here)* a read timeout reported as `connection_error` | custom `Retry` removed; the whole cause chain is inspected |
| 14 | *(introduced here)* the portal token sent to the heartbeat host | held per-instance, attached per request to portal calls only |
| 15 | *(introduced here)* `doctor` printed the response body twice | `detail` carries the reason, `body` carries the body |
| 16 | *(introduced here)* `config` exited silently on Ctrl+C, looking like a crash | explicit "Cancelled", username validation, `getpass` fallback |
| 17 | *(introduced here)* `doctor --full-cycle` reported a pass for a cycle that failed | three-state `deauth_confirmed`, 30 s poll, exit 2 when inconclusive |

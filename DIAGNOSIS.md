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

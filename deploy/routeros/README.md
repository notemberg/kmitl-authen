# Running this on MikroTik RouterOS

Short answer: **yes, two ways**, and which one you can use depends on the
hardware.

| | Container (`deploy/Dockerfile`) | Native script (`kmitl-authen.rsc`) |
|---|---|---|
| Needs | RouterOS v7, `container` package, arm/arm64/x86, **≥256 MB RAM** (512 MB+ recommended), physical access once | Any RouterOS v7 device, including 16 MB flash / MIPS |
| Code | The real Python daemon, unchanged | A port of the logic to RouterOS script |
| Features | Everything: watchdog, `/status`, `/metrics`, three re-login triggers, structured logs | probe + login + heartbeat, RouterOS `/log`, manual force-relogin |
| Risk | Low — same tested code | Medium — see the limitations below |

RouterOS cannot run Python itself, so there is no third option.

---

## Option A — container (preferred, if the hardware allows)

Supported on **arm, arm64 and x86** with at least **256 MB RAM**. Check first:

```
/system resource print          ; architecture-name and total-memory
/system package print           ; is "container" installed?
```

### 1. Enable container support

This needs **physical access** — RouterOS asks you to press the reset button
to confirm, and it is disabled by default:

```
/system/device-mode/update container=yes
```

### 2. Build and upload the image

Build on your PC (RouterOS cannot build images), then export it as a tar:

```bash
# On your computer, in the repo root:
docker buildx build --platform linux/arm64 -f deploy/Dockerfile -t kmitl-authen:2.0.0 --load .
docker save kmitl-authen:2.0.0 -o kmitl-authen.tar
# Match --platform to `architecture-name` from /system resource print:
#   arm64 -> linux/arm64,  arm  -> linux/arm/v7,  x86_64 -> linux/amd64
```

Upload `kmitl-authen.tar` to the router's Files list (drag it in WinBox, or
`scp kmitl-authen.tar admin@192.168.88.1:`).

### 3. Wire up networking

The container needs to reach the campus network **as the router**, so give it a
veth on a bridge that is NATed out of the campus-facing interface:

```
/interface veth add name=veth-kmitl address=172.17.0.2/24 gateway=172.17.0.1
/interface bridge add name=docker
/interface bridge port add bridge=docker interface=veth-kmitl
/ip address add address=172.17.0.1/24 interface=docker
/ip firewall nat add chain=srcnat action=masquerade src-address=172.17.0.0/24 out-interface=ether1
```

> The portal binds the session to a source IP and MAC. With this setup the
> portal sees the **router's** address, which is what you want — clients behind
> the router then reach the internet through its NAT.

### 4. Create the container

```
/container config set registry-url=https://registry-1.docker.io tmpdir=disk1/pull
/container envs add name=kmitl key=KMITL_USERNAME value=65010000
/container envs add name=kmitl key=KMITL_PASSWORD value=your-password
/container envs add name=kmitl key=KMITL_IP_ADDRESS value=203.0.113.45
/container envs add name=kmitl key=KMITL_MAC_ADDRESS value=e48d8c112233
/container envs add name=kmitl key=KMITL_LOG_JSON value=true
/container envs add name=kmitl key=KMITL_STATE_DIR value=/var/lib/kmitl-authen

/container mounts add name=kmitl-state src=disk1/kmitl-state dst=/var/lib/kmitl-authen

/container add file=kmitl-authen.tar interface=veth-kmitl envlist=kmitl \
    mounts=kmitl-state root-dir=disk1/kmitl logging=yes start-on-boot=yes
/container start [find tag~"kmitl"]
```

Set `KMITL_IP_ADDRESS` and `KMITL_MAC_ADDRESS` explicitly here: inside the
container the daemon sees the veth, not the campus interface, so auto-detection
would pick the wrong pair. Read the right values off the router:

```
/ip address print where interface=ether1
/interface print detail where name=ether1
```

### 5. Operate it

```
/log print where topics~"container"            ; logs
/container shell [find tag~"kmitl"]            ; then: kmitl-authen status
/container stop [find tag~"kmitl"]
```

To force a re-login, drop the trigger file inside the container:

```
/container shell [find tag~"kmitl"]
  kmitl-authen relogin
```

---

## Option B — native RouterOS script

For 16 MB-flash and MIPS devices, where containers are not an option.

```
/import file-name=kmitl-authen.rsc
/system script edit kmitl-config source        # put in your username/password
/system script run kmitl-force-relogin
/log print where message~"kmitl"
```

Then:

| Task | Command |
|---|---|
| Force a re-login | `/system script run kmitl-force-relogin` |
| Current state | `/system script environment print where name~"kmitl"` |
| Logs | `/log print where message~"kmitl"` |
| Change the interval | `/system scheduler set kmitl-heartbeat interval=5m` |
| Uninstall | `/system scheduler remove [find name~"kmitl"]` then `/system script remove [find name~"kmitl"]` |

### Limitations you must know about

1. **No cookie jar.** `/tool fetch` does not keep cookies. Login and heartbeat
   both pass everything as query parameters, which is how the portal's API
   works today, so it normally succeeds. If KMITL ever switches to a session
   cookie, this script stops working and Option A becomes the only choice.
   Verify once after installing with `/log print where message~"kmitl"`.
2. **No URL-encoder.** RouterOS script has no percent-encoding function, so a
   password containing `& ? # % +` or a space must be encoded by hand in
   `kmitl-config` (`p@ss word` → `p%40ss%20word`).
3. **No TLS trust store** by default, so the script uses
   `check-certificate=no`. Import the CA with `/certificate import` and remove
   that flag if you need real verification.
4. **The password is stored in plain text** in a `/system script`. Anyone with
   router login can read it. Use a dedicated account if you can.
5. **No watchdog.** `/tool fetch` has its own internal timeout and the
   scheduler starts a fresh run each interval, so a stuck fetch cannot wedge
   the loop the way it could in Python — but there is also no equivalent of
   `/status` or `/metrics`.

## Sources

- [RouterOS Container docs](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container)
- [RouterOS Fetch docs](https://help.mikrotik.com/docs/spaces/ROS/pages/8978514/Fetch)

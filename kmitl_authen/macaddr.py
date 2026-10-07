"""MAC address resolution, pinned so it never changes between runs.

``uuid.getnode()`` — what the original script used — is not a reliable identity:

* When it cannot find a hardware address it returns a **random** 48-bit value
  with the multicast bit set, which is different on every run. The portal then
  sees a brand-new device each time.
* When several adapters exist (Hyper-V, WSL, VirtualBox, VPN, docker0) the one
  it picks is not defined, so the value can change when an adapter appears.

We prefer the MAC of the interface that owns the configured public IP, fall
back to the first sensible physical interface, and persist whatever we chose to
the state directory so a later detection change cannot alter our identity.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import uuid
from pathlib import Path

from .logging_setup import get_logger

log = get_logger("mac")

_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_MAC_IN_TEXT = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")

# Virtual adapters whose MAC must never be used as our identity.
_VIRTUAL_PREFIXES = (
    "00:15:5d",  # Hyper-V / WSL
    "00:50:56",  # VMware
    "00:0c:29",  # VMware
    "00:05:69",  # VMware
    "08:00:27",  # VirtualBox
    "0a:00:27",  # VirtualBox host-only
    "52:54:00",  # QEMU/KVM
    "02:42:ac",  # Docker
)


def normalise(value: str) -> str:
    """Return a bare lowercase 12-hex-digit MAC, or '' if unparsable."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value or "").lower()
    return cleaned if _HEX12.match(cleaned) else ""


def pretty(mac12: str) -> str:
    return ":".join(mac12[i : i + 2] for i in range(0, 12, 2))


def _is_virtual(mac12: str) -> bool:
    return pretty(mac12).startswith(_VIRTUAL_PREFIXES)


def _from_uuid_getnode() -> str:
    node = uuid.getnode()
    # Bit 40 is the multicast/locally-administered marker CPython sets when it
    # had to invent a random node id.
    if (node >> 40) & 0x01:
        log.warning("uuid_getnode_is_random", extra={"hint": "set mac_address explicitly"})
        return ""
    return normalise(f"{node:012x}")


def _from_psutil(target_ip: str) -> str:
    try:
        import psutil  # optional dependency
    except Exception:
        return ""
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception as exc:  # pragma: no cover
        log.debug("psutil_failed", extra={"error": str(exc)})
        return ""

    def mac_of(name: str) -> str:
        for entry in addrs.get(name, []):
            if entry.family == psutil.AF_LINK:
                candidate = normalise(entry.address)
                if candidate and candidate != "000000000000":
                    return candidate
        return ""

    if target_ip:
        for name, entries in addrs.items():
            if any(e.family == socket.AF_INET and e.address == target_ip for e in entries):
                found = mac_of(name)
                if found:
                    return found

    best = ""
    for name, entries in addrs.items():
        stat = stats.get(name)
        if stat is not None and not stat.isup:
            continue
        if any(e.family == socket.AF_INET and e.address.startswith("127.") for e in entries):
            continue
        candidate = mac_of(name)
        if not candidate:
            continue
        if _is_virtual(candidate):
            best = best or candidate      # keep only as a last resort
            continue
        return candidate
    return best


def _from_linux_sysfs(target_ip: str) -> str:
    base = Path("/sys/class/net")
    if not base.is_dir():
        return ""
    names = sorted(p.name for p in base.iterdir())
    if target_ip:
        # Ask the kernel which interface would carry traffic for our own IP.
        try:
            out = subprocess.run(
                ["ip", "-o", "route", "get", target_ip],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            ).stdout
            match = re.search(r"\bdev\s+(\S+)", out)
            if match and match.group(1) in names:
                names.insert(0, names.pop(names.index(match.group(1))))
        except (OSError, subprocess.SubprocessError):
            pass
    fallback = ""
    for name in names:
        if name == "lo":
            continue
        try:
            # type 1 == ARPHRD_ETHER; skips tun/wireguard/bridge oddities.
            if (base / name / "type").read_text().strip() != "1":
                continue
            candidate = normalise((base / name / "address").read_text())
        except OSError:
            continue
        if not candidate or candidate == "000000000000":
            continue
        if (base / name).is_symlink() and "virtual" in str((base / name).resolve()):
            fallback = fallback or candidate
            continue
        if _is_virtual(candidate):
            fallback = fallback or candidate
            continue
        return candidate
    return fallback


def _from_windows_getmac() -> str:
    if sys.platform != "win32":
        return ""
    try:
        out = subprocess.run(
            ["getmac", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("getmac_failed", extra={"error": str(exc)})
        return ""
    fallback = ""
    for found in _MAC_IN_TEXT.findall(out):
        candidate = normalise(found)
        if not candidate or candidate == "000000000000":
            continue
        if _is_virtual(candidate):
            fallback = fallback or candidate
            continue
        return candidate
    return fallback


def resolve(configured: str, target_ip: str, state_dir: Path) -> str:
    """Return the MAC to present to the portal, pinning it on first use."""
    if configured:
        mac = normalise(configured)
        if not mac:
            raise ValueError(f"mac_address is not a valid MAC: {configured!r}")
        log.info("mac_from_config", extra={"mac": pretty(mac)})
        return mac

    pin_file = state_dir / "identity.json"
    pinned = ""
    try:
        pinned = normalise(json.loads(pin_file.read_text(encoding="utf-8")).get("mac", ""))
    except (OSError, json.JSONDecodeError, AttributeError):
        pinned = ""

    detected = ""
    for source, fn in (
        ("psutil", lambda: _from_psutil(target_ip)),
        ("sysfs", lambda: _from_linux_sysfs(target_ip)),
        ("getmac", _from_windows_getmac),
        ("uuid", _from_uuid_getnode),
    ):
        detected = fn()
        if detected:
            log.debug("mac_detected", extra={"source": source, "mac": pretty(detected)})
            break

    if pinned:
        if detected and detected != pinned:
            log.warning(
                "mac_changed_using_pinned",
                extra={"pinned": pretty(pinned), "detected": pretty(detected)},
            )
        log.info("mac_from_pin", extra={"mac": pretty(pinned)})
        return pinned

    if not detected:
        raise ValueError(
            "could not determine a MAC address; set mac_address in config.json "
            "or pass --mac-address"
        )

    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        pin_file.write_text(json.dumps({"mac": detected}, indent=2), encoding="utf-8")
    except OSError as exc:
        log.warning("mac_pin_write_failed", extra={"error": str(exc)})
    log.info("mac_pinned", extra={"mac": pretty(detected)})
    return detected

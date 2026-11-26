#!/usr/bin/env python3
"""Capture the fixtures of the security modules from the tier-1 images (phase 11).

Run as root inside the WSL Ubuntu, where Podman runs (blueprint 10.1); it needs the login
test images ``localhost/motp-login:<tag>``, which ``tools/login_test.py`` builds:

    wsl.exe -u root -- python3 \\
        <repo>/tools/capture_security_fixtures.py \\
        [debian:12 ubuntu:22.04 almalinux:9 fedora:45] [--podman-api]

``<repo>`` is the checkout as WSL sees it, such as ``/mnt/c/work/message-of-the-python``.

For each image it boots a container (``NET_ADMIN`` for the container's own network
namespace: two documentation addresses on its loopback device, and the firewalls), runs
itself inside with ``--inside`` and writes ``tests/fixtures/security/<tag>.json``. Inside,
with the container's network for the packages only:

* **failed logins**: sshd, a test account with a password, and failed SSH logins from
  ``192.0.2.10`` and ``198.51.100.20`` (bound to the loopback device) for that account,
  for an unknown name, and with a key only; then ``/var/log/btmp`` as hex. The attempted
  names are the fixture names the tests look for in every cache file.
* **fail2ban**: installed, configured with the ``dummy`` ban action and two jails, three
  documentation addresses banned by hand; the answers of ``fail2ban-client status`` and
  ``status <jail>``.
* **firewall**: Debian nftables, Ubuntu ufw, AlmaLinux firewalld, Fedora none; the
  module's ``systemctl show`` answer as an unprivileged user, the config files, and
  whether that user can read them.

``--podman-api`` instead captures Podman's answer to the container module's request on
the WSL host itself: two short-lived containers from ``debian:12`` (one running and
unhealthy, one exited), ``podman system service`` on a socket in a new temporary
directory, one ``GET /containers/json?all=1``; the service, the socket and the
containers are removed afterwards. Docker itself is not available here; its fixture is
built from the Engine API reference (``tests/fixtures/security/docker-api.json``).

A status line goes out at least every ``HEARTBEAT_SECONDS``.
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "security"
IMAGES = ("debian:12", "ubuntu:22.04", "almalinux:9", "fedora:45")
HEARTBEAT_SECONDS = 15.0
SOURCES = ("192.0.2.10", "198.51.100.20")
BANNED = {"sshd": ("192.0.2.77", "198.51.100.23", "2001:db8::7"), "motp-web": ("203.0.113.5",)}
REAL_USER = "qzrealuser"
TRIED_NAME = "qzbadname"
KEY_ONLY_NAME = "qzkeyname"
PASSWORD = "Right-Pass-1"  # noqa: S105  (a throwaway account inside a test container)
WRONG = "wrong-pass"
CHECK_USER = "motp-cap-user"
FIREWALL = {"debian12": "nftables", "ubuntu2204": "ufw", "almalinux9": "firewalld"}
JAIL_LOCAL = """\
[DEFAULT]
banaction = dummy
banaction_allports = dummy
backend = polling

[sshd]
enabled = true
backend = polling
logpath = /var/log/motp-f2b.log

[motp-web]
enabled = true
filter = sshd
port = 80
backend = polling
logpath = /var/log/motp-f2b.log
"""

_start = time.monotonic()
_last = _start


def status(what: str) -> None:
    global _last
    print(f"progress: capture {what} elapsed={time.monotonic() - _start:.0f}s", file=sys.stderr)
    _last = time.monotonic()


def sh(*argv: str, timeout: float = 600, **kw: object) -> subprocess.CompletedProcess[str]:
    if time.monotonic() - _last > HEARTBEAT_SECONDS:
        status("running")
    return subprocess.run(  # type: ignore[call-overload,no-any-return]
        list(argv), capture_output=True, text=True, timeout=timeout, check=False, **kw
    )


def install(*packages: str) -> None:
    if Path("/usr/bin/apt-get").exists():
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        sh("apt-get", "update", "-qq", env=env)
        done = sh("apt-get", "install", "-y", "-qq", "--no-install-recommends", *packages, env=env)
    else:
        if 'ID="almalinux"' in Path("/etc/os-release").read_text():
            sh("dnf", "install", "-y", "-q", "epel-release")
        done = sh("dnf", "install", "-y", "-q", *packages)
    if done.returncode != 0:
        print(done.stdout[-500:], done.stderr[-1500:], file=sys.stderr)
        raise SystemExit(f"install {packages} failed")


# --- inside a container ----------------------------------------------------------------


def failed_logins() -> str:
    status("failed-logins")
    sh("ssh-keygen", "-A")
    unit = "ssh.service" if Path("/lib/systemd/system/ssh.service").exists() else "sshd.service"
    sh("systemctl", "reset-failed", unit)
    sh("systemctl", "restart", unit)
    for address in SOURCES:
        sh("ip", "address", "add", f"{address}/32", "dev", "lo")
    sh("useradd", "-m", REAL_USER)
    sh("chpasswd", input=f"{REAL_USER}:{PASSWORD}\n")
    askpass = Path("/root/motp-askpass")
    askpass.write_text(f"#!/bin/sh\necho {WRONG}\n")
    askpass.chmod(0o700)
    Path("/var/log/btmp").write_bytes(b"")
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SSH_ASKPASS": str(askpass),
        "SSH_ASKPASS_REQUIRE": "force",
        "DISPLAY": "none",
    }
    base = (
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
    )  # fmt: skip
    password = ("-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1")
    attempts = [
        (SOURCES[0], REAL_USER, password),
        (SOURCES[0], REAL_USER, password),
        (SOURCES[0], TRIED_NAME, password),
        (SOURCES[1], TRIED_NAME, password),
        (SOURCES[0], KEY_ONLY_NAME, ("-o", "BatchMode=yes")),
    ]
    for source, user, how in attempts:
        sh("setsid", "-w", "ssh", "-b", source, *base, *how, f"{user}@127.0.0.1", "true",
           env=env, stdin=subprocess.DEVNULL, timeout=60)  # fmt: skip
    time.sleep(1)
    return Path("/var/log/btmp").read_bytes().hex()


def fail2ban() -> dict[str, object]:
    status("fail2ban")
    if Path("/usr/bin/apt-get").exists():
        install("fail2ban", "python3-systemd")
    else:
        install("fail2ban-server")
    Path("/etc/fail2ban/jail.local").write_text(JAIL_LOCAL)
    Path("/var/log/motp-f2b.log").write_text("")
    sh("systemctl", "enable", "fail2ban")
    sh("systemctl", "restart", "fail2ban")
    for _ in range(60):
        if sh("fail2ban-client", "ping").returncode == 0:
            break
        time.sleep(1)
    for jail, addresses in BANNED.items():
        sh("fail2ban-client", "set", jail, "banip", *addresses)
    found: dict[str, object] = {"version": sh("fail2ban-client", "--version").stdout.strip()}
    found["status"] = sh("/usr/bin/fail2ban-client", "status").stdout
    for jail in BANNED:
        found[f"status {jail}"] = sh("/usr/bin/fail2ban-client", "status", jail).stdout
    found["socket"] = os.path.exists("/run/fail2ban/fail2ban.sock")
    return found


def firewall(tag: str) -> dict[str, object]:
    status("firewall")
    chosen = FIREWALL.get(tag)
    if chosen == "nftables":
        install("nftables")
        sh("systemctl", "enable", "--now", "nftables")
    elif chosen == "ufw":
        install("ufw")
        sh("ufw", "--force", "enable")
    elif chosen == "firewalld":
        install("firewalld")
        sh("systemctl", "enable", "--now", "firewalld")
    sh("useradd", "-M", "-s", "/bin/sh", CHECK_USER)
    runuser = shutil.which("runuser") or "/usr/sbin/runuser"
    show = sh(
        runuser, "-u", CHECK_USER, "--", "/usr/bin/systemctl", "show", "--no-pager",
        "--property=Id,LoadState,ActiveState,SubState", "--",
        "ufw.service", "firewalld.service", "nftables.service",
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
    )  # fmt: skip
    files: dict[str, object] = {}
    for path in ("/etc/ufw/ufw.conf", "/etc/firewalld/firewalld.conf"):
        if os.path.exists(path):
            readable = sh(runuser, "-u", CHECK_USER, "--", "/bin/cat", path).returncode == 0
            files[path] = {"text": Path(path).read_text(), "user_can_read": readable}
    dirs = {d: oct(os.stat(d).st_mode & 0o7777) for d in ("/etc/firewalld",) if os.path.isdir(d)}
    return {"chosen": chosen, "show": show.stdout, "show_exit": show.returncode,
            "files": files, "modes": dirs}  # fmt: skip


def inside(tag: str) -> int:
    install("iproute2" if Path("/usr/bin/apt-get").exists() else "iproute")
    capture = {
        "os_release": Path("/etc/os-release").read_text(),
        "btmp": failed_logins(),
        "fail2ban": fail2ban(),
        "firewall": firewall(tag),
        "names": {"real": REAL_USER, "tried": TRIED_NAME, "key_only": KEY_ONLY_NAME},
        "sources": list(SOURCES),
        "banned": {jail: list(found) for jail, found in BANNED.items()},
        "captured": int(time.time()),
    }
    print(json.dumps(capture, indent=1, sort_keys=True))
    smoke()
    return 0


def smoke() -> None:
    """Run the modules on this system, as the collector's probes would see it."""
    sys.path.insert(0, "/src/src")
    from motp.collect.context import ProbeContext
    from motp.modules.sec_fail2ban import SecFail2ban
    from motp.modules.sec_firewall import SecFirewall
    from motp.modules.sec_logins import SecLogins

    ctx = ProbeContext(
        now=int(time.time()), binaries=("/usr/bin/fail2ban-client", "/usr/bin/systemctl")
    )
    for module in (SecLogins(), SecFail2ban(), SecFirewall()):
        try:
            print(f"smoke {module.name}: {module.collect(ctx)}", file=sys.stderr)
        except ValueError as exc:
            print(f"smoke {module.name}: failed {exc}", file=sys.stderr)


def outside(images: "list[str]") -> int:
    failures = 0
    OUT.mkdir(parents=True, exist_ok=True)
    for image in images:
        tag = image.replace(":", "").replace(".", "")
        name = f"motp-capture-sec-{tag}-{os.getpid()}"
        status(f"boot {tag}")
        run = [
            "podman", "run", "-d", "--systemd=always", "--cap-add", "SYS_ADMIN",
            "--cap-add", "NET_ADMIN", "--hostname", "motp-capture", "--name", name,
            "-v", f"{ROOT}:/src:ro", f"localhost/motp-login:{tag}",
        ]  # fmt: skip
        if subprocess.run(run, capture_output=True, check=False).returncode != 0:
            print(f"capture {tag}: container did not start", file=sys.stderr)
            failures += 1
            continue
        try:
            time.sleep(6)
            done = subprocess.run(
                ["podman", "exec", name, "/usr/bin/python3", "-I",
                 "/src/tools/capture_security_fixtures.py", "--inside", tag],
                capture_output=True, text=True, timeout=1200, check=False,
            )  # fmt: skip
            sys.stderr.write(done.stderr)
            if done.returncode != 0:
                failures += 1
                continue
            (OUT / f"{tag}.json").write_text(done.stdout, encoding="utf-8")
            status(f"wrote {tag}")
        finally:
            subprocess.run(["podman", "rm", "-f", name], capture_output=True, check=False)
    return 1 if failures else 0


# --- Podman's API on the WSL host -------------------------------------------------------


def podman_api() -> int:
    containers = ("qzweb-frontend", "qzdb-backend", "qzold-job")
    image = "docker.io/library/debian:12"
    status("podman-api")
    try:
        sh("podman", "run", "-d", "--name", containers[0], image, "sleep", "600")
        sh("podman", "run", "-d", "--name", containers[1], "--health-cmd", "false",
           "--health-retries", "1", "--health-interval", "0", image, "sleep", "600")  # fmt: skip
        sh("podman", "run", "--name", containers[2], image, "true")
        for _ in range(3):
            sh("podman", "healthcheck", "run", containers[1])
        directory = tempfile.mkdtemp(prefix="motp-podman-api-")
        path = os.path.join(directory, "podman.sock")
        service = subprocess.Popen(
            ["podman", "system", "service", "--time=0", f"unix://{path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(50):
                if os.path.exists(path):
                    break
                time.sleep(0.2)
            body = get(path, "/containers/json?all=1")
        finally:
            service.terminate()
            service.wait(timeout=30)
            shutil.rmtree(directory, ignore_errors=True)
        version = sh("podman", "--version").stdout.strip()
        OUT.mkdir(parents=True, exist_ok=True)
        data = json.loads(body)
        data = [c for c in data if any(n.lstrip("/") in containers for n in c.get("Names", []))]
        data = documentation_addresses(data)
        (OUT / "podman-api.json").write_text(
            json.dumps({"source": f"captured from {version} on the WSL host, "
                        "GET /containers/json?all=1 on its compat API; the container network's "
                        "addresses and MAC addresses replaced by documentation values",
                        "answer": data}, indent=1, sort_keys=True) + "\n",
            encoding="utf-8",
        )  # fmt: skip
        status("wrote podman-api")
        return 0
    finally:
        sh("podman", "rm", "-f", *containers)


def documentation_addresses(data: object) -> object:
    """Podman's network addresses and MAC addresses replaced by documentation values, so
    the repository holds no address outside RFC 5737 (invariant 3)."""
    text = json.dumps(data)
    text = re.sub(r"\b10\.88\.0\.([0-9]+)\b", r"198.51.100.\1", text)
    macs: dict[str, str] = {}

    def mac(found: "re.Match[str]") -> str:
        return macs.setdefault(found.group(0), f"02:00:00:00:00:{len(macs) + 1:02x}")

    text = re.sub(r"(?<![0-9a-f:])[0-9a-f]{2}(?::[0-9a-f]{2}){5}(?![0-9a-f:])", mac, text)
    return json.loads(text)


def get(path: str, target: str) -> bytes:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(path)
    sock.sendall(f"GET {target} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
    raw = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    sock.close()
    head, _sep, body = raw.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n")[0] + b" ":
        raise SystemExit(f"podman answered {head[:80]!r}")
    if b"chunked" in head.lower():
        out, rest = b"", body
        while True:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                return out
            out, rest = out + rest[:size], rest[size + 2 :]
    return body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("images", nargs="*", default=list(IMAGES))
    parser.add_argument("--inside", metavar="TAG", help=argparse.SUPPRESS)
    parser.add_argument("--podman-api", action="store_true", help="capture Podman's answer")
    args = parser.parse_args()
    if args.inside:
        return inside(args.inside)
    if args.podman_api:
        return podman_api()
    return outside(args.images)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Capture the fixtures of the service and login modules from a tier-1 image (phase 10).

Run as root inside the WSL Ubuntu, where Podman runs (blueprint 10.1); it needs the login
test images ``localhost/motp-login:<tag>``, which ``tools/login_test.py`` builds:

    wsl.exe -u root -- python3 \\
        <repo>/tools/capture_login_fixtures.py \\
        [debian:12 ubuntu:22.04 almalinux:9 fedora:45]

``<repo>`` is the checkout as WSL sees it, such as ``/mnt/c/work/message-of-the-python``.

On the host side this boots one container per image, runs itself inside it with
``--inside``, and writes ``tests/fixtures/logins/<tag>.json``. Inside, it makes two test
accounts, logs in over SSH (keys made here, gone with the container), keeps one session
open while it copies ``/run/utmp``, starts a unit that fails, and records:

* the records of ``/var/log/lastlog`` that hold data, by uid, as hex;
* ``/var/log/wtmp`` and ``/run/utmp`` as hex; in records that are not logins the host
  field (the kernel release in a boot record, which looks like an address to the
  repository scan) is cleared;
* the lines of ``/etc/passwd`` for root and the test accounts, and ``getent``'s answer;
* ``systemctl`` output for ``os_units`` (as an unprivileged user) and for ``rows_unit``.

Finally it runs the three modules on the live system and prints what they found to
stderr, as a smoke check. A status line goes out at least every ``HEARTBEAT_SECONDS``.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "logins"
IMAGES = ("debian:12", "ubuntu:22.04", "almalinux:9", "fedora:45")
HEARTBEAT_SECONDS = 15.0
UTMP_SIZE = 384
LASTLOG_SIZE = 292
USER_PROCESS = 7
HOST_FIELD = slice(76, 332)
USERS = ("motp-cap-a", "motp-cap-b")
KEY = "/root/.ssh/motp_cap_key"
SSH_OPTS = (
    "-i", KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
)  # fmt: skip
FAILING_UNIT = "motp-capture-fail.service"
RUNUSER = shutil.which("runuser") or "/usr/sbin/runuser"
ROW_UNITS = ("motp-capture-fail.service", "motp-capture-missing.service", "dbus.socket")

_last = time.monotonic()


def status(what: str) -> None:
    global _last
    print(f"progress: capture {what} elapsed={time.monotonic() - _start:.0f}s", file=sys.stderr)
    _last = time.monotonic()


_start = time.monotonic()


def sh(*argv: str, **kw: object) -> subprocess.CompletedProcess[str]:
    if time.monotonic() - _last > HEARTBEAT_SECONDS:
        status("running")
    return subprocess.run(  # type: ignore[call-overload,no-any-return]
        list(argv), capture_output=True, text=True, timeout=120, check=False, **kw
    )


def clear_hosts(data: bytes) -> bytes:
    """Clear the host field of every record that is not a login."""
    out = bytearray(data[: len(data) - len(data) % UTMP_SIZE])
    for start in range(0, len(out), UTMP_SIZE):
        kind = int.from_bytes(out[start : start + 2], sys.byteorder, signed=True)
        if kind != USER_PROCESS:
            host = slice(start + HOST_FIELD.start, start + HOST_FIELD.stop)
            out[host] = bytes(HOST_FIELD.stop - HOST_FIELD.start)
    return bytes(out)


def lastlog_records() -> dict[str, str]:
    data = Path("/var/log/lastlog").read_bytes()
    found = {}
    for uid in range(len(data) // LASTLOG_SIZE):
        record = data[uid * LASTLOG_SIZE : (uid + 1) * LASTLOG_SIZE]
        if any(record):
            found[str(uid)] = record.hex()
    return found


def ssh_login(user: str, typed: str = "exit\n") -> None:
    sh("ssh", "-tt", *SSH_OPTS, f"{user}@127.0.0.1", input=typed)


def inside() -> int:
    status("setup")
    sh("ssh-keygen", "-A")
    unit = "ssh.service" if Path("/lib/systemd/system/ssh.service").exists() else "sshd.service"
    sh("systemctl", "reset-failed", unit)
    sh("systemctl", "restart", unit)
    Path("/root/.ssh").mkdir(mode=0o700, exist_ok=True)
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", KEY)
    for user in USERS:
        sh("useradd", "-m", "-s", "/bin/bash", user)
        sh("usermod", "-p", "*", user)
        ssh_dir = Path(f"/home/{user}/.ssh")
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        (ssh_dir / "authorized_keys").write_text(Path(KEY + ".pub").read_text())
        sh("chown", "-R", f"{user}:{user}", f"/home/{user}")
    time.sleep(1)
    status("logins")
    ssh_login(USERS[0])
    time.sleep(2)
    ssh_login(USERS[0])
    ssh_login(USERS[1])
    # One session stays open while utmp is copied.
    live = subprocess.Popen(
        ["ssh", "-tt", *SSH_OPTS, f"{USERS[1]}@127.0.0.1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if live.stdin is None:
        raise SystemExit("no pipe to the ssh session")
    live.stdin.write(b"sleep 8; exit\n")
    live.stdin.flush()
    time.sleep(3)
    utmp = clear_hosts(Path("/run/utmp").read_bytes())
    live.wait(timeout=30)

    status("units")
    Path(f"/etc/systemd/system/{FAILING_UNIT}").write_text(
        "[Unit]\nDescription=MOTP capture: a unit that fails\n\n"
        "[Service]\nType=oneshot\nExecStart=/bin/false\n"
    )
    sh("systemctl", "daemon-reload")
    sh("systemctl", "start", FAILING_UNIT)
    failed = sh(
        RUNUSER, "-u", USERS[0], "--", "/usr/bin/systemctl", "list-units", "--state=failed",
        "--all", "--plain", "--no-legend", "--no-pager", "--full",
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
    )  # fmt: skip
    show = sh(
        RUNUSER, "-u", USERS[0], "--", "/usr/bin/systemctl", "show", "--no-pager",
        "--property=Id,LoadState,ActiveState,SubState", "--", *ROW_UNITS,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
    )  # fmt: skip
    passwd = [
        line
        for line in Path("/etc/passwd").read_text().splitlines()
        if line.split(":")[0] in ("root", *USERS)
    ]
    getent = sh("/usr/bin/getent", "passwd", "--", "0", USERS[1], "motp-nobody-here")
    capture = {
        "os_release": Path("/etc/os-release").read_text(),
        "lastlog_size": Path("/var/log/lastlog").stat().st_size,
        "lastlog": lastlog_records(),
        "wtmp": clear_hosts(Path("/var/log/wtmp").read_bytes()).hex(),
        "utmp": utmp.hex(),
        "passwd": "\n".join(passwd) + "\n",
        "getent": getent.stdout,
        "getent_exit": getent.returncode,
        "systemctl_failed": failed.stdout,
        "systemctl_failed_exit": failed.returncode,
        "row_units": list(ROW_UNITS),
        "systemctl_show": show.stdout,
        "systemctl_show_exit": show.returncode,
        "users": {user: int(sh("id", "-u", user).stdout) for user in USERS},
        "captured": int(time.time()),
    }
    print(json.dumps(capture, indent=1, sort_keys=True))
    smoke()
    return 0


def smoke() -> None:
    """Run the modules on this system, as the collector's probes would see it."""
    sys.path.insert(0, "/src/src")
    from motp.collect.context import ProbeContext
    from motp.modules.os_login import OsLogin
    from motp.modules.os_sessions import OsSessions
    from motp.modules.os_units import OsUnits

    ctx = ProbeContext(now=int(time.time()), binaries=("/usr/bin/getent", "/usr/bin/systemctl"))
    for module in (OsUnits(), OsSessions()):
        print(f"smoke {module.name}: {module.collect(ctx)}", file=sys.stderr)
    print(f"smoke os_login: {OsLogin().collect_users(ctx)}", file=sys.stderr)


def outside(images: "list[str]") -> int:
    failures = 0
    OUT.mkdir(parents=True, exist_ok=True)
    for image in images:
        tag = image.replace(":", "").replace(".", "")
        name = f"motp-capture-{tag}-{os.getpid()}"
        status(f"boot {tag}")
        run = [
            "podman", "run", "-d", "--systemd=always", "--cap-add", "SYS_ADMIN",
            "--hostname", "motp-capture", "--name", name,
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
                 "/src/tools/capture_login_fixtures.py", "--inside"],
                capture_output=True, text=True, timeout=600, check=False,
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("images", nargs="*", default=list(IMAGES))
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    return inside() if args.inside else outside(args.images)


if __name__ == "__main__":
    sys.exit(main())

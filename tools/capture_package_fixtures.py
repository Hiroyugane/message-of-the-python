#!/usr/bin/env python3
"""Capture the fixtures of the package modules from a tier-1 image (blueprint phase 9).

Run inside a throwaway container of the image, as root, **with** network access (it
installs packages and refreshes the package lists, which MOTP itself never does):

    wsl.exe -u root -- podman run --rm \
        -v <repo>:/src:ro \
        localhost/motp-systemd:debian12 \
        python3 -I /src/tools/capture_package_fixtures.py > capture.txt

``<repo>`` is the checkout as WSL sees it, such as ``/mnt/c/work/message-of-the-python``.

then split the output into files:

    python tools/capture_package_fixtures.py --split capture.txt tests/fixtures/packages/debian12

Every command the modules run is run here with the module's own arguments, as an
unprivileged user with the environment of ``core.proc``. A fresh image has nothing
pending on Debian and Ubuntu, so the apt simulation reads a copy of dpkg's status file in
which a few installed versions are made slightly older ("~0" sorts just before); apt's
output is its own. Versions with four dotted numbers are shortened, so that no fixture
looks like an IP address to the repository scan.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

MARK = "===FILE "
USER = "motp-capture"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}
# In a throwaway container.
STATUS = "/tmp/motp-capture-status"  # noqa: S108
OLDER = (
    "openssl", "libssl3", "tar", "tzdata", "base-files", "gpgv", "libgnutls30",
    "libsystemd0", "systemd", "bash",
)  # fmt: skip
DOTTED_FOUR = re.compile(r"(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+(?![0-9.])")


def sources() -> None:
    """Make the module package of the mounted source tree importable."""
    sys.path.insert(0, "/src/src")


def emit(name: str, text: str) -> None:
    print(f"{MARK}{name}")
    sys.stdout.write(DOTTED_FOUR.sub(r"\1", text))
    if text and not text.endswith("\n"):
        print()


def root(*argv: str) -> str:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=600, check=False)
    print(f"{argv[0]} {argv[1]}: exit {done.returncode}", file=sys.stderr, flush=True)
    return done.stdout


def probe(*argv: str) -> str:
    """As the probe user would run it: stdout only; the exit code goes to stderr."""
    done = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        user=USER,
        group=USER,
        extra_groups=[],
        env=ENV,
        cwd="/",
        stdin=subprocess.DEVNULL,
    )
    print(f"probe {argv[0]}: exit {done.returncode} {done.stderr[-300:]}", file=sys.stderr)
    return done.stdout


def older_status() -> None:
    text = Path("/var/lib/dpkg/status").read_text()
    blocks = []
    for block in text.split("\n\n"):
        name = re.search(r"^Package: (\S+)$", block, re.M)
        if name and name.group(1) in OLDER:
            block = re.sub(r"^Version: (.*)$", r"Version: \1~0", block, flags=re.M)
        blocks.append(re.sub(r"\(= ([^)]*)\)", r"(>= \1~0)", block))
    Path(STATUS).write_text("\n\n".join(blocks))
    os.chmod(STATUS, 0o644)


def capture_apt() -> None:
    sources()
    from motp.modules import os_autoupdates, os_updates

    root("apt-get", "update", "-qq")
    older_status()
    emit("lists.txt", "\n".join(sorted(os.listdir("/var/lib/apt/lists"))) + "\n")
    argv = os_updates.APT_ARGV
    emit("apt_upgrade.txt", probe(*argv[:-2], "-o", f"Dir::State::status={STATUS}", *argv[-2:]))
    emit("apt_upgrade_none.txt", probe(*argv))
    emit("apt_periodic_unset.txt", probe(*os_autoupdates.APT_CONFIG_ARGV))
    root("apt-get", "install", "-y", "-qq", "--no-install-recommends", "unattended-upgrades")
    Path("/etc/apt/apt.conf.d/20auto-upgrades").write_text(
        'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
    )
    emit("apt_periodic_on.txt", probe(*os_autoupdates.APT_CONFIG_ARGV))


def capture_dnf() -> None:
    sources()
    from motp.modules import os_autoupdates, os_reboot, os_updates, packages

    dnf5 = os.path.exists(packages.DNF5_PROGRAM)
    root("dnf", "-q", "makecache")
    base = os_updates.DNF_CACHES[packages.DNF5 if dnf5 else packages.DNF4]
    cached = [n for n in os.listdir(base) if os.path.exists(f"{base}/{n}/repodata/repomd.xml")]
    emit("lists.txt", "\n".join(sorted(cached)) + "\n")
    logs = "/var/tmp/motp-capture-log"  # noqa: S108  (in a throwaway container)
    argv = os_updates.dnf5_argv(logs) if dnf5 else os_updates.DNF4_ARGV
    emit("dnf_check.txt", probe(*argv))
    emit("dnf_check_security.txt", probe(*argv, os_updates.SECURITY_FLAG))
    emit("rpm_installed.txt", probe(*os_reboot.RPM_ARGV))
    root("dnf", "install", "-y", "-q", "dnf-automatic")
    chain = os_autoupdates.DNF5_CONF if dnf5 else os_autoupdates.DNF4_CONF
    for path in chain:
        if os.path.isfile(path):
            emit("conf" + path.replace("/", "_"), Path(path).read_text())
    units = "/usr/lib/systemd/system"
    emit("automatic_units.txt", "\n".join(sorted(n for n in os.listdir(units) if "auto" in n)))
    timer = "dnf5-automatic.timer" if dnf5 else "dnf-automatic-install.timer"
    root("systemctl", "enable", timer)
    wants = "/etc/systemd/system/timers.target.wants"
    emit("timers_wanted.txt", "\n".join(sorted(os.listdir(wants))))


def capture() -> None:
    subprocess.run(
        ["useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", USER],
        check=True,
    )
    os.chmod("/tmp", 0o1777)  # noqa: S103, S108  (the usual mode of /tmp)
    emit("os-release", Path("/etc/os-release").read_text())
    if os.path.exists("/usr/bin/apt-get"):
        capture_apt()
    else:
        capture_dnf()


def split(capture_file: Path, directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    current: Optional[Path] = None
    parts: dict[Path, list[str]] = {}
    for line in capture_file.read_text(encoding="utf-8").splitlines():
        if line.startswith(MARK):
            name = line[len(MARK) :].strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                raise SystemExit(f"bad file name in capture: {name!r}")
            current = directory / name
            parts[current] = []
        elif current is not None:
            parts[current].append(line)
    for path, lines in parts.items():
        path.write_bytes(("\n".join(lines) + "\n" if lines else "").encode("utf-8"))
    print(f"wrote {len(parts)} files to {directory}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Capture the package module fixtures.")
    parser.add_argument("--split", nargs=2, type=Path, metavar=("CAPTURE", "DIRECTORY"))
    args = parser.parse_args(argv)
    if args.split:
        return split(*args.split)
    capture()
    return 0


if __name__ == "__main__":
    sys.exit(main())

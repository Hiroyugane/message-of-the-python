#!/usr/bin/env python3
"""The phase 7 checks on the tier-1 images with systemd as the first process (blueprint 7.1).

Run as root inside the WSL Ubuntu, where Podman runs (blueprint 10.1); nothing here
touches the host beyond Podman's own images and containers:

    wsl.exe -u root -- python3 <repo>/tools/systemd_test.py \
        [debian:12 ubuntu:22.04 almalinux:9 fedora:45] [--rebuild] [--remove-images]

``<repo>`` is the checkout as WSL sees it, such as ``/mnt/c/work/message-of-the-python``.

For each image it builds ``localhost/motp-systemd:<tag>`` from
``tools/container/systemd/Containerfile`` (systemd, Python, sudo, the account tools), boots
a container with ``--systemd=always``, runs ``tools/container/systemd/checks.py before``,
restarts the container so the timer runs after a real boot, takes its network away, runs
``checks.py after``, and removes the container. ``CAP_SYS_ADMIN`` is added so the checks can
remount ``/proc`` with
``hidepid=2``. AppArmor is turned off for the container (``CONTAINER_OPTIONS``): its
default profile for containers denies every ``mount``, so on a host that enforces it (the
GitHub runners) systemd 257 does not boot and older ones cannot build the unit's sandbox.
The summary lists every check per image; the exit code is 1 if any failed.

A check script ends with ``CHECKS-DONE failures=<n>``. A part whose output lacks that line
(the script crashed or was killed partway) counts as a failed check of its own, and so does
a count that differs from the ``FAIL`` lines seen (phase 11 issue): counting ``CHECK`` lines
alone would read a crash after 51 passed checks as "51 passed, 0 failed".

A status line goes out at least every ``HEARTBEAT_SECONDS`` (image builds and boots can
take minutes), and runs queue on the same host-wide lock as ``container_test.py``.
"""

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional, TextIO

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import container_test  # noqa: E402

IMAGES = ("debian:12", "ubuntu:22.04", "almalinux:9", "fedora:45")
CONTEXT = ROOT / "tools" / "container" / "systemd"
CHECKS = "/src/tools/container/systemd/checks.py"
HEARTBEAT_SECONDS = 15.0
BOOT_TIMEOUT = 120.0
DONE_MARKER = "CHECKS-DONE failures="
# How every systemd test container starts (login_test.py adds its own options). systemd
# runs as the first process; CAP_SYS_ADMIN lets the checks remount /proc. The default
# AppArmor profile for containers ("deny mount") is off: systemd needs mount to boot and to
# build the unit's sandbox, and the sandbox is what these checks test. A host without
# AppArmor (WSL) ignores the option. Seccomp and the capability set stay as they are.
CONTAINER_OPTIONS = (
    "--systemd=always", "--cap-add", "SYS_ADMIN", "--security-opt", "apparmor=unconfined",
)  # fmt: skip


def part_checks(lines: list[str], part: str) -> list[str]:
    """The ``CHECK`` lines of one check script's output, plus a failed check when the
    script did not reach its final ``CHECKS-DONE`` line or reported another count."""
    checks = [ln for ln in lines if ln.startswith("CHECK ")]
    done = [ln for ln in lines if ln.startswith(DONE_MARKER)]
    if not done:
        return [*checks, f"CHECK checks_done_{part} FAIL (no {DONE_MARKER.strip('=')} line)"]
    reported = done[-1][len(DONE_MARKER) :].strip()
    seen = sum(1 for c in checks if c.split()[2:3] == ["FAIL"])
    if reported != str(seen):
        return [*checks, f"CHECK checks_done_{part} FAIL (reported {reported}, saw {seen})"]
    return checks


def tag_of(image: str) -> str:
    return "localhost/motp-systemd:" + image.split("/")[-1].replace(":", "").replace(".", "")


class Runner:
    def __init__(self, podman: str, out: TextIO, interval: float = HEARTBEAT_SECONDS) -> None:
        self.podman = podman
        self.out = out
        self.interval = interval
        self.results: dict[str, list[str]] = {}

    def say(self, text: str) -> None:
        print(text, file=self.out, flush=True)

    def stream(self, argv: list[str], image: str, stage: str) -> tuple[int, list[str]]:
        """Run a command, echo its lines, print a status line at a fixed interval."""
        beat = container_test.Heartbeat(self.interval)
        beat.stage = stage
        lock = threading.Lock()
        done = threading.Event()

        def ticker() -> None:
            while not done.wait(1.0):
                with lock:
                    if beat.due():
                        self.say(beat.status(image))

        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
        thread = threading.Thread(target=ticker, daemon=True)
        thread.start()
        lines = []
        for line in proc.stdout or ():
            with lock:
                beat.observe(line)
                lines.append(line.rstrip("\n"))
                self.say(line.rstrip("\n"))
        code = proc.wait()
        done.set()
        thread.join()
        return code, lines

    def podman_ok(self, *args: str) -> bool:
        return (
            subprocess.run([self.podman, *args], capture_output=True, check=False).returncode == 0
        )

    def build(self, image: str, rebuild: bool) -> bool:
        tag = tag_of(image)
        if not rebuild and self.podman_ok("image", "exists", tag):
            return True
        base = image if "/" in image else "docker.io/library/" + image
        argv = [self.podman, "build", "--build-arg", f"BASE={base}", "-t", tag, str(CONTEXT)]
        code, _ = self.stream(argv, image, "build")
        return code == 0

    def wait_booted(self, name: str, image: str) -> bool:
        started = last = time.monotonic()
        while time.monotonic() - started < BOOT_TIMEOUT:
            state = subprocess.run(
                [self.podman, "exec", name, "systemctl", "is-system-running"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if state in ("running", "degraded"):
                return True
            if time.monotonic() - last >= self.interval:
                last = time.monotonic()
                self.say(f"progress: st {image} stage=boot state={state or '-'}")
            time.sleep(1)
        return False

    def run_argv(self, name: str, tag: str, *extra: str) -> list[str]:
        """The ``podman run`` command of one test container."""
        return [
            self.podman, "run", "-d", *CONTAINER_OPTIONS, *extra,
            "--name", name, "-v", f"{ROOT}:/src:ro", tag,
        ]  # fmt: skip

    def one(self, image: str, rebuild: bool) -> list[str]:
        checks: list[str] = []
        if not self.build(image, rebuild):
            return ["CHECK image_build FAIL"]
        name = f"motp-p7-{tag_of(image).split(':')[1]}-{os.getpid()}"
        run = self.run_argv(name, tag_of(image))
        if subprocess.run(run, capture_output=True, check=False).returncode != 0:
            return ["CHECK container_start FAIL"]
        try:
            for part in ("before", "after"):
                if not self.wait_booted(name, image):
                    checks.append(f"CHECK boot_{part} FAIL")
                    break
                argv = [self.podman, "exec", name, "/usr/bin/python3", "-I", CHECKS, part]
                _code, lines = self.stream(argv, image, part)
                checks += part_checks(lines, part)
                if part == "before":
                    self.say(f"progress: st {image} stage=restart")
                    subprocess.run(
                        [self.podman, "restart", "-t", "10", name], capture_output=True, check=False
                    )
                    # The second part runs without any network (phase 9): the timer's run
                    # after the boot and the package modules must manage without one.
                    if not self.podman_ok("network", "disconnect", "podman", name):
                        checks.append("CHECK network_disconnect FAIL")
        finally:
            subprocess.run(
                [self.podman, "rm", "-f", "-t", "5", name], capture_output=True, check=False
            )
        return checks


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 7 checks on systemd test images.")
    parser.add_argument("images", nargs="*", default=list(IMAGES))
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--rebuild", action="store_true", help="build the test images again")
    parser.add_argument("--remove-images", action="store_true", help="remove them afterwards")
    args = parser.parse_args(argv)
    host_fd = container_test.host_lock(container_test.HOST_LOCK, "systemd", sys.stdout)
    runner = Runner(args.podman, sys.stdout)
    failed = 0
    for image in args.images:
        runner.results[image] = runner.one(image, args.rebuild)
    print("\n== summary", flush=True)
    for image, checks in runner.results.items():
        bad = [c for c in checks if c.split()[2:3] == ["FAIL"]]
        failed += len(bad) + (0 if checks else 1)
        print(f"{image}: {len(checks) - len(bad)} passed, {len(bad)} failed", flush=True)
        for c in checks:
            print("  " + c, flush=True)
    if args.remove_images:
        for image in args.images:
            subprocess.run([args.podman, "rmi", tag_of(image)], capture_output=True, check=False)
    if host_fd is not None:
        os.close(host_fd)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

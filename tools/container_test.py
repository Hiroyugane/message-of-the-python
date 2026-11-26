#!/usr/bin/env python3
"""Run the unit tests inside a container image with Podman (blueprint 7.1 level 1, 10.1).

Locally, container checks run with Podman as root inside the WSL Ubuntu; CI runs this same
tool with ``--podman docker``, so both start the container with the same options. From
Windows (the ``run ct`` command does this):

    wsl.exe -u root -- python3 <repo>/tools/container_test.py \
        docker.io/library/almalinux:9 [-- pytest arguments]

``<repo>`` is the checkout as WSL sees it, such as ``/mnt/c/work/message-of-the-python``.

The repository is mounted read-only at ``/src``; ``tools/container/unit_tests.sh`` copies
it to the container's own filesystem (the NTFS mount has no usable owners or modes),
installs Python where the image lacks it, creates test accounts in the container's own
``/etc``, creates a venv with pytest, and runs the tests as root with
``MOTP_REQUIRE_ROOT_TESTS=1``, so tests marked ``needs_linux_owner`` run and are never
skipped. Their fixtures live on the container's filesystem (``/var/lib``), not the mount.

While the container runs, a status line is printed every ``HEARTBEAT_SECONDS`` with the
current stage and the elapsed time, so a long image pull or install never looks hung. The
exit code is the container's.
"""

import argparse
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional, TextIO

ROOT = Path(__file__).resolve().parent.parent
INNER_SCRIPT = "/src/tools/container/unit_tests.sh"
STAGE_MARKER = "MOTP-STAGE "
HEARTBEAT_SECONDS = 15.0
# Container runs share the host's uids (rootful Podman without a user namespace), so the
# probe user's process limit is shared too: a fork-bomb test in one run makes forks fail
# in another. Runs therefore take this host-wide lock and queue.
HOST_LOCK = "/run/lock/motp-container-test.lock"


class Heartbeat:
    """Decides when a status line is due; the clock is injectable for tests."""

    def __init__(self, interval: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.interval = interval
        self.clock = clock
        self.started = clock()
        self.last = self.started
        self.stage = "start"
        self.lines = 0

    def due(self) -> bool:
        return self.clock() - self.last >= self.interval

    def status(self, image: str) -> str:
        self.last = self.clock()
        elapsed = int(self.last - self.started)
        return f"progress: ct {image} stage={self.stage} elapsed={elapsed}s lines={self.lines}"

    def observe(self, line: str) -> None:
        self.lines += 1
        if line.startswith(STAGE_MARKER):
            self.stage = line[len(STAGE_MARKER) :].strip() or self.stage


def podman_command(
    podman: str, image: str, pytest_args: list[str], script: str = INNER_SCRIPT
) -> list[str]:
    return [
        podman,
        "run",
        "--rm",
        # A small init reaps orphaned processes. Without it the test runner is PID 1 and
        # never reaps them, and their zombies keep counting against a user's process limit.
        "--init",
        "--pull=missing",
        "-v",
        f"{ROOT}:/src:ro",
        image,
        "/bin/sh",
        script,
        *pytest_args,
    ]


def host_lock(
    path: str, image: str, out: TextIO, interval: float = HEARTBEAT_SECONDS
) -> Optional[int]:
    """Wait for the host-wide lock; return its descriptor (``None`` where there is no
    ``fcntl``, which only the Windows side of the test suite lacks)."""
    try:
        import fcntl
    except ImportError:
        return None
    import os

    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    started = last = time.monotonic()
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            now = time.monotonic()
            if now - last >= interval:
                last = now
                waited = int(now - started)
                print(f"progress: ct {image} stage=queued waited={waited}s", file=out, flush=True)
            time.sleep(0.5)


def run(
    image: str,
    pytest_args: list[str],
    podman: str = "podman",
    interval: float = HEARTBEAT_SECONDS,
    out: TextIO = sys.stdout,
    script: str = INNER_SCRIPT,
) -> int:
    host_fd = host_lock(HOST_LOCK, image, out, interval)  # held until this process ends
    beat = Heartbeat(interval)
    lock = threading.Lock()
    done = threading.Event()

    def ticker() -> None:
        while not done.wait(1.0):
            with lock:
                if beat.due():
                    print(beat.status(image), file=out, flush=True)

    proc = subprocess.Popen(
        podman_command(podman, image, pytest_args, script),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )
    thread = threading.Thread(target=ticker, daemon=True)
    thread.start()
    for line in proc.stdout or ():
        with lock:
            beat.observe(line)
            print(line, end="", file=out, flush=True)
    code = proc.wait()
    done.set()
    thread.join()
    with lock:
        beat.stage = "done"
        print(f"{beat.status(image)} exit={code}", file=out, flush=True)
    if host_fd is not None:
        import os

        os.close(host_fd)
    return code


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the unit tests in a Podman container.")
    parser.add_argument("image", help="container image, e.g. docker.io/library/almalinux:9")
    parser.add_argument("pytest_args", nargs="*", help="extra arguments for pytest (after --)")
    parser.add_argument(
        "--podman", default="podman", help="podman executable (or docker, as CI uses)"
    )
    parser.add_argument(
        "--script",
        default=INNER_SCRIPT,
        help="script inside the container (default: the unit tests; tools/container/show_check.sh"
        " measures and checks motp show)",
    )
    args = parser.parse_args(argv)
    return run(args.image, args.pytest_args, args.podman, script=args.script)


if __name__ == "__main__":
    sys.exit(main())

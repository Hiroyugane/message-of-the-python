#!/usr/bin/env python3
"""The level-3 login checks on the tier-1 images (blueprint 7.1, phase 8).

Run as root inside the WSL Ubuntu, where Podman runs (blueprint 10.1); nothing here
touches the host beyond Podman's own images and containers:

    wsl.exe -u root -- python3 <repo>/tools/login_test.py \
        [debian:12 ubuntu:22.04 almalinux:9 fedora:45] [--rebuild] [--remove-images]

``<repo>`` is the checkout as WSL sees it, such as ``/mnt/c/work/message-of-the-python``.

For each image it makes sure the phase 7 image ``localhost/motp-systemd:<tag>`` exists
(``tools/systemd_test.py`` builds it), builds ``localhost/motp-login:<tag>`` on top of it
from ``tools/container/login/Containerfile`` (sshd, the ssh client, rsync, zsh, fish), boots
a container with ``--systemd=always``, runs ``tools/container/login/login_checks.py`` in it
and removes the container. Keys are made inside the container at test time and go away
with it. The container starts with ``systemd_test.CONTAINER_OPTIONS``: ``CAP_SYS_ADMIN``
and no AppArmor as in phase 7 (the unit's whole sandbox), which the tmpfs mount of the
admin-only fixture needs too; ``CAP_NET_ADMIN`` is added for the container's own network
namespace (phase 11: a documentation address on its loopback device as the source of
failed logins).

The summary lists every check and note per image; the exit code is 1 if any check failed.
Output without the final ``CHECKS-DONE`` line (a crashed check script) is a failed check,
as in ``systemd_test.part_checks``.
A status line goes out at least every ``HEARTBEAT_SECONDS``, and runs queue on the same
host-wide lock as ``container_test.py``.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import container_test  # noqa: E402
import systemd_test  # noqa: E402

IMAGES = systemd_test.IMAGES
CONTEXT = TOOLS / "container" / "login"
CHECKS = "/src/tools/container/login/login_checks.py"
# A local file system below /media: a per-user mount, so admin tier only (5.4, T26).
FIXTURE_MOUNT = "/media/q/QZADM"


def login_lines(lines: list[str]) -> list[str]:
    """The ``CHECK`` and ``NOTE`` lines, with a failed check when the script did not end
    with ``CHECKS-DONE`` or reported a count other than the ``FAIL`` lines seen."""
    notes = [ln for ln in lines if ln.startswith("NOTE ")]
    return [*systemd_test.part_checks(lines, "login"), *notes]


def tag_of(image: str) -> str:
    return systemd_test.tag_of(image).replace("motp-systemd", "motp-login")


class LoginRunner(systemd_test.Runner):
    def build_login(self, image: str, rebuild: bool) -> bool:
        if not self.build(image, False):  # the phase 7 image underneath
            return False
        tag = tag_of(image)
        if not rebuild and self.podman_ok("image", "exists", tag):
            return True
        base = systemd_test.tag_of(image)
        argv = [self.podman, "build", "--build-arg", f"BASE={base}", "-t", tag, str(CONTEXT)]
        code, _ = self.stream(argv, image, "build-login")
        return code == 0

    def one(self, image: str, rebuild: bool) -> list[str]:
        if not self.build_login(image, rebuild):
            return ["CHECK image_build FAIL"]
        name = f"motp-p8-{tag_of(image).split(':')[1]}-{os.getpid()}"
        volume = name + "-fixture"
        run = self.run_argv(
            name, tag_of(image),
            "--cap-add", "NET_ADMIN", "--hostname", "motp-login-test",
            "-v", f"{volume}:{FIXTURE_MOUNT}",
        )  # fmt: skip
        if subprocess.run(run, capture_output=True, check=False).returncode != 0:
            subprocess.run([self.podman, "volume", "rm", "-f", volume], capture_output=True)
            return ["CHECK container_start FAIL"]
        try:
            if not self.wait_booted(name, image):
                return ["CHECK boot FAIL"]
            argv = [self.podman, "exec", name, "/usr/bin/python3", "-I", CHECKS]
            _code, lines = self.stream(argv, image, "login")
            return login_lines(lines)
        finally:
            subprocess.run(
                [self.podman, "rm", "-f", "-t", "5", name], capture_output=True, check=False
            )
            subprocess.run(
                [self.podman, "volume", "rm", "-f", volume], capture_output=True, check=False
            )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 8 login checks over SSH.")
    parser.add_argument("images", nargs="*", default=list(IMAGES))
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--rebuild", action="store_true", help="build the login images again")
    parser.add_argument("--remove-images", action="store_true", help="remove them afterwards")
    args = parser.parse_args(argv)
    host_fd = container_test.host_lock(container_test.HOST_LOCK, "login", sys.stdout)
    runner = LoginRunner(args.podman, sys.stdout)
    failed = 0
    for image in args.images:
        runner.results[image] = runner.one(image, args.rebuild)
    print("\n== summary", flush=True)
    for image, lines in runner.results.items():
        checks = [ln for ln in lines if ln.startswith("CHECK ")]
        bad = [c for c in checks if c.split()[2:3] == ["FAIL"]]
        failed += len(bad) + (0 if checks else 1)
        print(f"{image}: {len(checks) - len(bad)} passed, {len(bad)} failed", flush=True)
        for line in lines:
            print("  " + line, flush=True)
    if args.remove_images:
        for image in args.images:
            subprocess.run([args.podman, "rmi", tag_of(image)], capture_output=True, check=False)
    if host_fd is not None:
        os.close(host_fd)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

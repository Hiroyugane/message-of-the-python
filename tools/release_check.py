#!/usr/bin/env python3
"""The phase 14 release check: the README's install commands, typed as written, on fresh
systemd containers of the newest tier-1 releases (blueprint section 11, phase 14 "Check").

Run as root inside the WSL Ubuntu, where Podman runs (blueprint 10.1); ``run relcheck``
does this from Windows:

    wsl.exe -u root -- python3 <repo>/tools/release_check.py \
        [debian:13 almalinux:10] [--rebuild]

``<repo>`` is the checkout as WSL sees it, such as ``/mnt/c/work/message-of-the-python``.

Each image gets the level-3 login image of ``tools/login_test.py`` (systemd, sshd, the
shells; no MOTP), a container booted with ``--systemd=always``, and
``tools/container/release/release_checks.py`` inside it: the README's prerequisites and
install blocks with the locally built archive served in place of the download, an SSH
login that shows the MOTD exactly once, ``ssh host true`` silent, ``motp doctor`` without
an error, then the README's uninstall block leaving only the config. The container is
removed afterwards.

The summary lists every check per image; the exit code is 1 if any failed. A status line
goes out at least every ``HEARTBEAT_SECONDS``; runs queue on the host-wide container lock.
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
import login_test  # noqa: E402
import systemd_test  # noqa: E402

IMAGES = ("debian:13", "almalinux:10")
CHECKS = "/src/tools/container/release/release_checks.py"
HEARTBEAT_SECONDS = systemd_test.HEARTBEAT_SECONDS


class ReleaseRunner(login_test.LoginRunner):
    def one(self, image: str, rebuild: bool) -> list[str]:
        if not self.build_login(image, rebuild):
            return ["CHECK image_build FAIL"]
        name = f"motp-p14-{login_test.tag_of(image).split(':')[1]}-{os.getpid()}"
        run = [
            self.podman, "run", "-d", "--systemd=always", "--cap-add", "SYS_ADMIN",
            "--hostname", "motp-release-test", "--name", name,
            "-v", f"{systemd_test.ROOT}:/src:ro", login_test.tag_of(image),
        ]  # fmt: skip
        if subprocess.run(run, capture_output=True, check=False).returncode != 0:
            return ["CHECK container_start FAIL"]
        try:
            if not self.wait_booted(name, image):
                return ["CHECK boot FAIL"]
            argv = [self.podman, "exec", name, "/usr/bin/python3", "-I", CHECKS]
            _code, lines = self.stream(argv, image, "release")
            return login_test.login_lines(lines)
        finally:
            subprocess.run(
                [self.podman, "rm", "-f", "-t", "5", name], capture_output=True, check=False
            )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 14: the README's install, typed.")
    parser.add_argument("images", nargs="*", default=list(IMAGES))
    parser.add_argument("--podman", default="podman")
    parser.add_argument("--rebuild", action="store_true", help="build the login images again")
    args = parser.parse_args(argv)
    host_fd = container_test.host_lock(container_test.HOST_LOCK, "release", sys.stdout)
    runner = ReleaseRunner(args.podman, sys.stdout)
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
    if host_fd is not None:
        os.close(host_fd)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

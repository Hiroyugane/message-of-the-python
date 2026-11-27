#!/usr/bin/env python3
"""Prove the build is reproducible: build ``motp.pyz`` on this machine and inside a Linux
container from the same commit, and compare the SHA-256 (blueprint 4.12, T15, phase 14).

From Windows (``run repro``), with Podman as root inside the WSL Ubuntu (blueprint 10.1):

    python tools/repro_check.py [--ref HEAD] [--image debian:13]

1. ``git archive`` exports the commit into ``dist/repro/<commit>/tree`` (``dist`` is not
   tracked), so untracked files in the checkout cannot reach either build.
2. This machine's Python builds ``host.pyz`` from that tree.
3. ``wsl.exe -u root`` runs this script again with ``--linux``: it takes the host-wide
   container lock of ``container_test.py``, starts the image with the tree mounted
   read-only, installs ``python3`` where the image lacks it, copies the tree to the
   container's own file system and builds ``linux.pyz`` there with the image's Python.
4. Both hashes are printed; the exit code is 0 only when the two files are byte-identical.

The two builds differ in operating system, Python version, file system and checkout, which
is what a person who rebuilds a release tag on their own machine changes too. Equal hashes
show the build is reproducible; they do not show the release pipeline is honest (T15).
A status line goes out at least every ``HEARTBEAT_SECONDS`` while the container runs.
"""

import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Optional, Union

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
HEARTBEAT_SECONDS = 15.0
DEFAULT_IMAGE = "debian:13"
# Inside the container: Python where it is missing, then the build from a private copy.
INNER = (
    "set -eu; "
    "if ! command -v python3 >/dev/null 2>&1; then "
    "  if command -v apt-get >/dev/null 2>&1; then "
    "    apt-get update -qq >/dev/null && "
    "    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null; "
    "  else dnf install -y -q python3 >/dev/null; fi; "
    "fi; "
    "python3 --version; "
    "cp -a /tree /build; cd /build; "
    "python3 -I tools/build_pyz.py --output /out/linux.pyz"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wsl_path(path: "Union[Path, str]") -> str:
    """``C:\\work\\x`` -> ``/mnt/c/work/x``; a POSIX path stays as it is. Parsed as a
    Windows path on every system, so the result does not depend on where this runs."""
    win = PureWindowsPath(str(path))
    if len(win.drive) == 2:
        return "/".join(["/mnt", win.drive[0].lower(), *win.parts[1:]]).rstrip("/")
    return str(path)


def safe_extract(data: bytes, dest: Path) -> int:
    """Extract a ``git archive`` tar: regular files and directories only, no path that
    leaves ``dest``. Returns the number of files."""
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError(f"unsafe path in the archive: {member.name}")
            target = dest.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError(f"unreadable member: {member.name}")
                target.write_bytes(source.read())
                count += 1
            # links and anything else are left out; the package has none
    return count


def export(ref: str, work: Path) -> tuple[str, Path]:
    """The full commit id and the extracted tree of ``ref``."""
    commit = subprocess.run(
        ["git", "rev-parse", "--verify", ref + "^{commit}"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip
    data = subprocess.run(
        ["git", "archive", "--format=tar", commit], cwd=ROOT, capture_output=True, check=True
    ).stdout
    base = work / commit[:12]
    if base.exists():
        shutil.rmtree(base)
    tree = base / "tree"
    tree.mkdir(parents=True)
    files = safe_extract(data, tree)
    print(f"exported {commit[:12]}: {files} files", flush=True)
    return commit, tree


def host_build(tree: Path, out: Path) -> str:
    subprocess.run(
        [sys.executable, "-I", str(tree / "tools" / "build_pyz.py"), "--output", str(out)],
        cwd=tree, check=True, capture_output=True,
    )  # fmt: skip
    return sha256(out)


def stream(argv: list[str], label: str, interval: float = HEARTBEAT_SECONDS) -> int:
    """Run ``argv``, pass its output through, and print a status line at the interval."""
    started = time.monotonic()
    done = threading.Event()
    lines = [0]

    def tick() -> None:
        while not done.wait(interval):
            elapsed = int(time.monotonic() - started)
            print(f"progress: repro {label} elapsed={elapsed}s lines={lines[0]}", flush=True)

    ticker = threading.Thread(target=tick, daemon=True)
    ticker.start()
    try:
        with subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace"
        ) as child:
            for line in child.stdout or ():
                lines[0] += 1
                print("  " + line.rstrip(), flush=True)
            return child.wait()
    finally:
        done.set()


def linux_build(image: str, tree: str, out: str, podman: str = "podman") -> int:
    """``--linux``: runs inside WSL as root, under the host-wide container lock."""
    sys.path.insert(0, str(TOOLS))
    import container_test

    lock = container_test.host_lock(container_test.HOST_LOCK, "repro", sys.stdout)
    try:
        ref = image if "/" in image else "docker.io/library/" + image
        argv = [
            podman, "run", "--rm", "-v", f"{tree}:/tree:ro", "-v", f"{out}:/out",
            ref, "sh", "-c", INNER,
        ]  # fmt: skip
        return stream(argv, image)
    finally:
        if lock is not None:
            os.close(lock)


def compare(host: Path, linux: Path) -> tuple[str, str, bool]:
    a, b = sha256(host), sha256(linux)
    return a, b, a == b and host.read_bytes() == linux.read_bytes()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build motp.pyz twice and compare.")
    parser.add_argument("--ref", default="HEAD", help="the commit or tag to build")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="the Linux image")
    parser.add_argument("--linux", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--tree", help=argparse.SUPPRESS)
    parser.add_argument("--out", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.linux:
        return linux_build(args.image, args.tree, args.out)
    commit, tree = export(args.ref, ROOT / "dist" / "repro")
    base = tree.parent
    host_sha = host_build(tree, base / "host.pyz")
    print(f"host  ({sys.platform}, Python {sys.version.split()[0]}): {host_sha}", flush=True)
    script = wsl_path(TOOLS / "repro_check.py")
    code = stream(
        ["wsl.exe", "-u", "root", "--", "python3", script, "--linux", "--image", args.image,
         "--tree", wsl_path(tree), "--out", wsl_path(base)],
        "wsl",
    )  # fmt: skip
    linux = base / "linux.pyz"
    if code != 0 or not linux.is_file():
        print(f"the Linux build failed (exit {code})", flush=True)
        return 1
    a, b, same = compare(base / "host.pyz", linux)
    print(f"commit {commit}")
    print(f"host  sha256 {a}")
    print(f"linux sha256 {b}  ({args.image})")
    print("IDENTICAL" if same else "DIFFERENT", flush=True)
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())

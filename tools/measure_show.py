#!/usr/bin/env python3
"""Measure and check ``motp show`` in the installed form (blueprint D31, phase 5).

D31: the installed form is an unpacked tree with bytecode compiled by the system
interpreter, because Python never caches bytecode of code that is imported from a zip
archive. This script, run INSIDE a container (or on any Linux machine), does what the
installer will do later:

1. unpack ``dist/motp.pyz`` into a directory (``<work>/lib``),
2. compile its bytecode with the interpreter that runs this script,
3. check the output of ``python3 -I -S <work>/lib show`` without any cache (live values and
   one notice), with a fixture cache in ``/run/motp`` (Host and Disks rows), and with the
   cache that ``<work>/lib collect --no-sandbox`` wrote (phase 6: Host and Disks rows from
   the real modules; needs the users ``motp`` and ``motp-plugin``),
4. run ``show`` 20 times in each situation and print the minimum, median and maximum of the
   wall-clock times of whole processes (start-up of the interpreter included).

The numbers are container numbers on whatever machine runs the container, not a Raspberry
Pi. Run it as root: the cache reader requires cache files that belong to root, and the
cache is written to ``/run/motp`` (the fixed location of ``show``); an existing
``/run/motp`` or ``/var/lib/motp`` that this script did not create is never touched. The
tree is unpacked below ``/var/lib``, whose chain only root can write, since the collector
refuses to start probes from a program others could change.

Usage: python3 -I tools/measure_show.py [--pyz dist/motp.pyz] [--runs 20] [--limit-ms 300]
Exit code 0 when every check passes and the median of both situations is under the limit.
"""

import argparse
import compileall
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = "/run/motp"
STATE_DIR = "/var/lib/motp"
WORK_PARENT = "/var/lib"
HEARTBEAT_SECONDS = 15.0
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "COLUMNS": "80", "NO_COLOR": "1"}


def unpack(pyz: Path, target: Path) -> int:
    with zipfile.ZipFile(pyz) as archive:
        archive.extractall(target)  # our own archive, built by tools/build_pyz.py
        return len(archive.namelist())


def compile_tree(target: Path) -> bool:
    """Bytecode with this interpreter, as the installer does (D31)."""
    return bool(compileall.compile_dir(str(target), quiet=1, force=True))


def program(lib: Path) -> list[str]:
    return [sys.executable, "-I", "-S", str(lib), "show"]


def run_once(lib: Path) -> tuple[float, bytes, bytes, int]:
    started = time.perf_counter()
    done = subprocess.run(
        program(lib),
        capture_output=True,
        env=ENV,
        timeout=30,
        check=False,
        cwd="/",
    )
    return time.perf_counter() - started, done.stdout, done.stderr, done.returncode


# ``runpy`` (which starts a directory or archive program) imports ``importlib.util``, and on
# Python 3.9 ``pkgutil``; those are the interpreter's own start-up cost and not listed.
FORBIDDEN_IMPORTS = (
    "subprocess", "argparse", "tomllib", "tomli", "pwd", "grp", "socket", "shutil",
)  # fmt: skip
TOP = 8


def import_report(lib: Path) -> list[str]:
    """``python -X importtime`` of one ``show``: totals, the heaviest imports, forbidden ones.

    Lines are ``import time: <self us> | <cumulative us> | <name>``; the module name is
    indented by its depth in the import tree.
    """
    done = subprocess.run(
        [sys.executable, "-X", "importtime", "-I", "-S", str(lib), "show"],
        capture_output=True,
        env=ENV,
        timeout=30,
        check=False,
        cwd="/",
    )
    rows: list[tuple[int, int, str]] = []
    for line in done.stderr.decode("utf-8", "replace").splitlines():
        if not line.startswith("import time:") or "|" not in line:
            continue
        own, cumulative, name = (part.strip() for part in line[len("import time:") :].split("|"))
        if own.isdigit():
            rows.append((int(own), int(cumulative), name))
    total = sum(own for own, _c, _n in rows)
    heavy = sorted(rows, key=lambda row: -row[1])[:TOP]
    print(f"imports: {len(rows)} modules, {total / 1000:.1f} ms of own import time", flush=True)
    for self_us, total_us, module in heavy:
        print(f"  {total_us / 1000:6.1f} ms cumulative  {self_us / 1000:6.1f} ms own  {module}")
    names = {name for _o, _c, name in rows}
    return [f"render path imports {m}" for m in FORBIDDEN_IMPORTS if m in names]


def write_fixture_cache(lib: Path) -> None:
    """The demo's modules as ``public.json`` and ``render.json`` in ``/run/motp``."""
    code = (
        "import sys, time\n"
        f"sys.path.insert(0, {str(lib)!r})\n"
        "from motp.core import cache\n"
        "from motp.render import demo\n"
        "from motp.core.thresholds import make_rule\n"
        "from dataclasses import replace\n"
        "now = int(time.time())\n"
        "modules = {s.module: replace(s.result, collected=now - 60) for s in demo.sources()}\n"
        f"d = {CACHE_DIR!r}\n"
        "open(d + '/public.json', 'wb').write(cache.encode_tier_file('public', now, modules, 0))\n"
        "rules = {'load_per_core': make_rule('load_per_core', 0.7, 1.0)}\n"
        "settings = cache.RenderSettings(now, cache.Layout(), 'auto', rules, 300, 1000, '')\n"
        "open(d + '/render.json', 'wb').write(cache.encode_render_file(settings))\n"
    )
    subprocess.run([sys.executable, "-I", "-c", code], check=True, env=ENV)
    for name in ("public.json", "render.json"):
        os.chmod(f"{CACHE_DIR}/{name}", 0o644)


def run_collector(lib: Path) -> tuple[int, str]:
    """``motp collect --no-sandbox`` from the tree, as root, like the timer would run it."""
    done = subprocess.run(
        [sys.executable, "-I", "-S", str(lib), "collect", "--no-sandbox"],
        capture_output=True,
        env=ENV,
        timeout=120,
        check=False,
        cwd="/",
    )
    return done.returncode, done.stderr.decode("utf-8", "replace")


def os_name() -> str:
    """``PRETTY_NAME`` of this system, as ``os_host`` reports it."""
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            continue
    return "Linux"


def expect(label: str, text: str, wanted: list[str], unwanted: list[str]) -> list[str]:
    problems = [f"{label}: missing {w!r}" for w in wanted if w not in text]
    problems += [f"{label}: unexpected {u!r}" for u in unwanted if u in text]
    return problems


def measure(lib: Path, runs: int, label: str) -> float:
    started = time.monotonic()
    last = started
    times = []
    for i in range(runs):
        elapsed, _out, _err, code = run_once(lib)
        if code != 0:
            raise SystemExit(f"{label}: run {i + 1} exited with {code}")
        times.append(elapsed * 1000)
        if time.monotonic() - last >= HEARTBEAT_SECONDS:
            last = time.monotonic()
            print(f"progress: {label} {i + 1}/{runs} runs", file=sys.stderr, flush=True)
    median = statistics.median(times)
    print(
        f"{label}: runs={runs} min={min(times):.0f} ms median={median:.0f} ms "
        f"max={max(times):.0f} ms",
        flush=True,
    )
    return median


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Measure and check motp show (installed form).")
    parser.add_argument("--pyz", type=Path, default=ROOT / "dist" / "motp.pyz")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--limit-ms", type=float, default=300.0)
    parser.add_argument(
        "--locale", default=ENV["LC_ALL"], help="the reader's locale, e.g. de_DE.UTF-8"
    )
    args = parser.parse_args(argv)
    ENV["LC_ALL"] = args.locale
    german = args.locale.startswith("de")
    uptime, load, memory, host, disks, no_cache = (
        ("Laufzeit", "Auslastung", "Arbeitsspeicher", "Rechnername", "Datentr", "Noch keine")
        if german
        else ("Uptime", "Load", "Memory", "Hostname", "Disks", "No collected data found")
    )
    if getattr(os, "geteuid", lambda: 1)() != 0:
        print("run as root: the cache files must belong to root", file=sys.stderr)
        return 2
    for existing in (CACHE_DIR, STATE_DIR):
        if os.path.exists(existing):
            print(f"{existing} exists; not touching it", file=sys.stderr)
            return 2
    work = Path(tempfile.mkdtemp(prefix="motp-measure-", dir=WORK_PARENT))
    work.chmod(0o755)  # the probe user must reach the tree
    lib = work / "lib"
    problems: list[str] = []
    medians: dict[str, float] = {}
    try:
        count = unpack(args.pyz, lib)
        ok = compile_tree(lib)
        version = sys.version.split()[0]
        print(f"python {version}: unpacked {count} files, bytecode compiled: {ok}", flush=True)
        problems += [] if ok else ["bytecode compilation failed"]

        _t, out, err, code = run_once(lib)
        text = out.decode("utf-8", "replace")
        print(text)
        problems += expect(
            "no cache",
            text,
            [uptime, load, memory, no_cache],
            ["Traceback", "\x1b"],
        )
        problems += [] if (code, err) == (0, b"") else [f"no cache: exit {code}, stderr {err!r}"]
        medians["no cache"] = measure(lib, args.runs, "no cache")

        os.mkdir(CACHE_DIR, 0o755)
        write_fixture_cache(lib)
        _t, out, err, code = run_once(lib)
        text = out.decode("utf-8", "replace")
        print(text)
        problems += expect(
            "fixture cache",
            text,
            [host, "192.0.2.10", disks, "/home", uptime, load, memory],
            ["Traceback", "\x1b", no_cache],
        )
        problems += [] if (code, err) == (0, b"") else [f"cache: exit {code}, stderr {err!r}"]
        medians["fixture cache"] = measure(lib, args.runs, "fixture cache")
        # For comparison only (D31): the archive itself, which Python cannot cache bytecode for.
        measure(args.pyz, args.runs, "fixture cache, straight from the archive (not checked)")

        shutil.rmtree(CACHE_DIR)
        started = time.perf_counter()
        code, log = run_collector(lib)
        print(f"collect: exit {code} in {(time.perf_counter() - started) * 1000:.0f} ms")
        print(log, end="")
        problems += [] if code == 0 else [f"collect: exit {code}"]
        problems += [f"collect: {line}" for line in log.splitlines() if ": failed:" in line]
        _t, out, err, code = run_once(lib)
        text = out.decode("utf-8", "replace")
        print(text)
        hostname = Path("/proc/sys/kernel/hostname").read_text(encoding="utf-8").strip()
        problems += expect(
            "collector cache",
            text,
            [host, hostname, os_name()[:20], disks, uptime, load, memory],
            ["Traceback", "\x1b", no_cache],
        )
        problems += [] if (code, err) == (0, b"") else [f"collected: exit {code}, stderr {err!r}"]
        medians["collector cache"] = measure(lib, args.runs, "collector cache")
        problems += import_report(lib)
    finally:
        shutil.rmtree(CACHE_DIR, ignore_errors=True)
        shutil.rmtree(STATE_DIR, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
    for label, median in medians.items():
        if median >= args.limit_ms:
            problems.append(f"{label}: median {median:.0f} ms is not under {args.limit_ms:.0f} ms")
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    print("measure_show:", "FAILED" if problems else "ok", flush=True)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

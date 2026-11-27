"""Runs as a unit with the collector's sandbox (``tools/container/systemd/checks.py``).

Checks inside ``NoNewPrivileges``, ``CapabilityBoundingSet``, ``SystemCallFilter`` and the
rest of the collector's unit what phase 6 left for phase 7: the collector can become a
child subreaper, start a probe as ``motp``, find the process that probe left outside its
session through the unit's control group, and end it with pidfds; also when ``/proc`` is
mounted ``hidepid=2`` and hides that process from ``/proc``. Prints one ``SANDBOX`` line.
"""

import errno
import os
import socket
import sys

sys.path.insert(0, "/opt/motp/lib")

from motp.core import proc

UNIT = "motp-sandbox-check.service"
BUS = "/run/dbus/system_bus_socket"
ROOT_SOCKET = "/run/motp-o4.sock"
CONNECT = (
    "import socket, sys\n"
    "s = socket.socket(socket.AF_UNIX)\n"
    "s.settimeout(2)\n"
    "s.connect(sys.argv[1])\n"
)


def reach(path: str) -> str:
    """O4: can this process (root in the sandbox) connect to the socket?"""
    if not os.path.exists(path):
        return "absent"
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(2)
    try:
        s.connect(path)
    except OSError as exc:
        return f"no({exc.errno})"
    finally:
        s.close()
    return "yes"


LEAVE = (
    "import os, time\n"
    "if os.fork() == 0:\n"
    "    os.setsid()\n"
    "    if os.fork() == 0:\n"
    "        time.sleep(60)\n"
    "    os._exit(0)\n"
    "os.wait()\n"
)


def writable(path: str) -> str:
    """Phase 14: can root in the collector's sandbox create a file at ``path``?"""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        return f"no({exc.errno})"
    os.close(fd)
    os.unlink(path)
    return "yes"


def main() -> int:
    try:
        proc.become_subreaper()
    except Exception as exc:  # the line says what broke
        print(f"SANDBOX fail subreaper {exc!r}", flush=True)
        return 1
    drop = proc.account("motp")
    spec = proc.Spec(argv=("/usr/bin/python3", "-I", "-S", "-c", LEAVE), timeout=10, drop=drop)
    result = proc.run(spec)
    procs = proc.service_cgroup_procs(UNIT)
    if procs is None:
        print("SANDBOX fail no control group", flush=True)
        return 1
    me = os.getpid()
    left = (proc._cgroup_pids(procs) or set()) - {me}
    hidden = proc.process_view_hidden()
    by_proc = proc.live_processes(drop.uid, ancestor=me)
    outcome = proc.cleanup_cgroup(procs)
    after = (proc._cgroup_pids(procs) or set()) - {me}
    run_write = writable("/run/motp-p14-write-check")
    lock_write = writable("/run/lock/motp-p14-write-check")
    cache_write = writable("/run/motp/.p14-write-check")
    ok = result.ok and len(left) == 1 and outcome.clean and not after
    # EROFS (30) only: a missing directory or another error would test nothing.
    ok = ok and run_write == lock_write == f"no({errno.EROFS})" and cache_write == "yes"
    bus_probe = "absent"
    if os.path.exists(BUS):
        argv = ("/usr/bin/python3", "-I", "-S", "-c", CONNECT, BUS)
        bus_probe = "yes" if proc.run(proc.Spec(argv=argv, timeout=10, drop=drop)).ok else "no"
    print(
        f"SANDBOX {'ok' if ok else 'fail'} probe_ok={result.ok} left={len(left)}"
        f" hidden={hidden} seen_in_proc={len(by_proc)} clean={outcome.clean} after={len(after)}"
        f" bus_root={reach(BUS)} bus_motp={bus_probe} root_socket={reach(ROOT_SOCKET)}"
        f" run_write={run_write} lock_write={lock_write} cache_write={cache_write}",
        flush=True,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

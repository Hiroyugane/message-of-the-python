"""The process helpers phase 7 added for the collector unit (4.9, phase 6 notes).

* ``service_cgroup_procs`` finds the unit's own control group, and nothing elsewhere.
* ``process_view_hidden`` tells when ``/proc`` hides the probe users' processes
  (``hidepid``), from the mount options, the effective capabilities and the exempt group.
* ``cleanup_cgroup`` ends every process of the group but the caller, without reading
  anything of them from ``/proc``, and leaves processes outside the group alone.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from motp.core import proc

from .conftest import TEST_USER, account

POSIX = pytest.mark.skipif(os.name != "posix", reason="needs POSIX")
MOUNT = "25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw{}\n"
PTRACE = 1 << proc.CAP_SYS_PTRACE


def _view(tmp_path: Path, options: str, caps: int) -> bool:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "24 30 0:22 / /sys rw - sysfs sysfs rw\n" + MOUNT.format(options), encoding="ascii"
    )
    status = tmp_path / "status"
    status.write_text(f"Name:\tx\nCapEff:\t{caps:016x}\n", encoding="ascii")
    return proc.process_view_hidden(str(mountinfo), str(status))


@POSIX
@pytest.mark.parametrize(
    "option", [",hidepid=2", ",hidepid=invisible", ",hidepid=1", ",hidepid=noaccess"]
)
def test_hidepid_without_ptrace_hides_the_view(tmp_path: Path, option: str) -> None:
    other = 4242 if os.getegid() != 4242 else 4243  # a group this process is not in
    assert _view(tmp_path, f"{option},gid={other}", 0) is True


@POSIX
def test_without_gid_the_root_group_is_exempt(tmp_path: Path) -> None:
    """The kernel exempts group 0 when the mount names no group (the default)."""
    in_root_group = os.getegid() == 0 or 0 in os.getgroups()
    assert _view(tmp_path, ",hidepid=2", 0) is (not in_root_group)


@POSIX
@pytest.mark.parametrize("option", ["", ",hidepid=0", ",hidepid=off"])
def test_a_proc_without_hidepid_is_seen(tmp_path: Path, option: str) -> None:
    assert _view(tmp_path, option, 0) is False


@POSIX
def test_ptrace_in_the_effective_set_sees_through_hidepid(tmp_path: Path) -> None:
    assert _view(tmp_path, ",hidepid=2,gid=4242", PTRACE) is False


@POSIX
def test_the_exempt_group_sees_through_hidepid(tmp_path: Path) -> None:
    assert _view(tmp_path, f",hidepid=2,gid={os.getegid()}", 0) is False


def _cgroup(tmp_path: Path, line: str, make: bool = True) -> "str | None":
    """Write ``line`` as this process's cgroup file and give the group it names (and the
    unit's group) a ``cgroup.procs``, so only the name decides."""
    me = tmp_path / "cgroup"
    me.write_bytes(line.encode("ascii"))
    root = tmp_path / "fs"
    if make:
        named = line.strip().split(":", 2)[-1].lstrip("/")
        for rel in ("system.slice/motp-collect.service", named):
            path = root / rel
            path.mkdir(parents=True, exist_ok=True)
            (path / "cgroup.procs").write_bytes(b"1\n")
    return proc.service_cgroup_procs("motp-collect.service", str(me), str(root))


@POSIX
def test_the_unit_group_is_found(tmp_path: Path) -> None:
    found = _cgroup(tmp_path, "0::/system.slice/motp-collect.service\n")
    assert found is not None and found.endswith("/motp-collect.service/cgroup.procs")


@pytest.mark.parametrize(
    "line",
    [
        "0::/user.slice/user-1000.slice/session-3.scope\n",  # an admin's shell
        "0::/system.slice/other.service\n",
        "1:name=systemd:/system.slice/motp-collect.service\n",  # cgroup v1 only
        "0::/system.slice/../system.slice/motp-collect.service\n",
        "0::/user.slice/user-1000.slice/app.slice/motp-collect.service\n",  # a delegated tree
    ],
)
def test_anything_but_the_unit_group_is_not(tmp_path: Path, line: str) -> None:
    assert _cgroup(tmp_path, line) is None


@POSIX
def test_a_missing_procs_file_is_not_used(tmp_path: Path) -> None:
    assert _cgroup(tmp_path, "0::/system.slice/motp-collect.service\n", make=False) is None


@POSIX
def test_a_group_others_can_write_is_not_the_unit(tmp_path: Path) -> None:
    line = "0::/system.slice/motp-collect.service\n"
    assert _cgroup(tmp_path, line) is not None
    (tmp_path / "fs/system.slice/motp-collect.service").chmod(0o775)
    assert _cgroup(tmp_path, line, make=False) is None


def test_an_unreadable_group_is_never_clean(tmp_path: Path) -> None:
    if os.name == "posix" and os.geteuid() != 0:
        pytest.skip("cleanup_cgroup runs as root")
    if os.name != "posix":
        pytest.skip("needs POSIX")
    result = proc.cleanup_cgroup(str(tmp_path / "missing" / "cgroup.procs"), timeout=1)
    assert result.clean is False


@pytest.mark.needs_linux_owner
def test_cleanup_cgroup_ends_the_group_and_spares_the_rest(tmp_path: Path) -> None:
    """Members of the group die whoever owns them; a process outside it survives."""
    member = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], user=account(TEST_USER)[0]
    )
    outsider = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    procs = tmp_path / "cgroup.procs"
    procs.write_text(f"{os.getpid()}\n{member.pid}\n", encoding="ascii")
    try:
        started = time.monotonic()
        result = proc.cleanup_cgroup(str(procs), timeout=5)
        assert result.clean and result.remaining == 0
        assert time.monotonic() - started < 5
        assert member.poll() is not None or member.wait(timeout=5) is not None
        assert outsider.poll() is None, "a process outside the group was killed"
    finally:
        for p in (member, outsider):
            p.kill()
            p.wait()

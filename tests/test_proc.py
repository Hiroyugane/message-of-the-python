"""Process starts (blueprint 4.9, T2, T3, T8, T9, T23).

Validation runs everywhere. Starting processes needs Linux; dropping privileges and the
per-user cleanup need root, which the container runs of ``tools/container_test.py`` give.
"""

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from motp.core import proc
from motp.core.proc import Drop, Limits, ProcError, Spec

from .conftest import EXTRA_GROUP, OTHER_USER, TEST_USER, account

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux")
linux_root = pytest.mark.needs_linux_owner
PY = (sys.executable, "-I", "-S", "-c")


def py(code: str, timeout: float = 10.0, **kwargs: object) -> Spec:
    return Spec(argv=(*PY, code), timeout=timeout, **kwargs)  # type: ignore[arg-type]


def state(pid: int) -> str:
    """'' if the process is gone, else its state letter (Z for a zombie)."""
    try:
        with open(f"/proc/{pid}/status", "rb") as fh:
            for line in fh:
                if line.startswith(b"State:"):
                    return line.split()[1].decode()
    except OSError:
        return ""
    return ""


def gone(pid: int, wait: float = 2.0) -> bool:
    end = time.monotonic() + wait
    while time.monotonic() < end:
        if state(pid) in ("", "Z", "X"):
            return True
        time.sleep(0.02)
    return False


# --- validation, everywhere -----------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "msg_id"),
    [
        ((), "proc.error.argv"),
        (("bin/true",), "proc.error.relative"),
        (("true",), "proc.error.relative"),
        (("/usr/bin/../bin/true",), "proc.error.relative"),
        (("/bin/true", "a\x00b"), "proc.error.argv"),
        (("/bin/true", 3), "proc.error.argv"),
    ],
)
def test_bad_argument_lists_are_refused(argv: tuple[object, ...], msg_id: str) -> None:
    with pytest.raises(ProcError) as exc:
        proc.validate(Spec(argv=argv, timeout=1))  # type: ignore[arg-type]
    assert exc.value.message.id == msg_id


def test_a_list_is_not_an_argument_tuple() -> None:
    with pytest.raises(ProcError):
        proc.validate(Spec(argv=["/bin/true"], timeout=1))  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [0, -1, 601])
def test_timeout_must_be_bounded(timeout: float) -> None:
    with pytest.raises(ProcError) as exc:
        proc.validate(Spec(argv=("/bin/true",), timeout=timeout))
    assert exc.value.message.id == "proc.error.timeout"


@pytest.mark.parametrize(
    "env", [{"LD_PRELOAD": "/x.so"}, {"PATH": "/home/x"}, {"MOTP_X": "a\x00b"}, {"motp_x": "1"}]
)
def test_environment_only_adds_motp_names(env: dict[str, str]) -> None:
    with pytest.raises(ProcError) as exc:
        proc.environment(env)
    assert exc.value.message.id == "proc.error.env"


def test_environment_is_built_from_scratch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_PRELOAD", "/evil.so")
    monkeypatch.setenv("PYTHONPATH", "/evil")
    assert proc.environment({"MOTP_PLUGIN_API": "1"}) == {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C.UTF-8",
        "MOTP_PLUGIN_API": "1",
    }


@pytest.mark.parametrize(("uid", "gid"), [(0, 100), (100, 0), (-1, 5), (True, 5)])
def test_drop_never_targets_root(uid: int, gid: int) -> None:
    with pytest.raises(ProcError) as exc:
        Drop(uid, gid)
    assert exc.value.message.id == "proc.error.drop"


def test_limits_must_be_positive() -> None:
    with pytest.raises(ProcError):
        Limits(processes=0)
    with pytest.raises(ProcError):
        Limits(address_space=-5)


ACCOUNTS = """\
root:x:0:0:root:/root:/bin/bash
motp:x:950:950:MOTP:/nonexistent:/usr/sbin/nologin
motp-plugin:x:951:951:MOTP plugins:/nonexistent:/usr/sbin/nologin
twin:x:950:950:same uid as motp:/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
rootgroup:x:952:0:primary group root:/nonexistent:/usr/sbin/nologin
dup:x:953:953::/nonexistent:/usr/sbin/nologin
dup:x:954:954::/nonexistent:/usr/sbin/nologin
broken-line
"""


@pytest.mark.parametrize(
    ("name", "msg_id"),
    [
        ("motp", "proc.error.account"),  # shares its uid with "twin"
        ("nobody", "proc.error.account"),
        ("alice", "proc.error.account"),  # not a system account
        ("rootgroup", "proc.error.account"),
        ("dup", "proc.error.account"),
        ("root", "proc.error.account"),
        ("missing", "proc.error.no_account"),
        ("broken-line", "proc.error.no_account"),
    ],
)
def test_account_must_be_a_local_system_account_of_its_own(
    tmp_path: Path, name: str, msg_id: str
) -> None:
    passwd = tmp_path / "passwd"
    passwd.write_text(ACCOUNTS)
    with pytest.raises(ProcError) as exc:
        proc.account(name, str(passwd), str(tmp_path / "no-login.defs"))
    assert exc.value.message.id == msg_id


def test_account_reads_the_system_range_from_login_defs(tmp_path: Path) -> None:
    passwd = tmp_path / "passwd"
    passwd.write_text(ACCOUNTS)
    defs = tmp_path / "login.defs"
    defs.write_text("# SYS_UID_MAX 2000\nSYS_UID_MAX   940\n")
    assert proc.account("motp-plugin", str(passwd), str(tmp_path / "none")) == Drop(951, 951)
    with pytest.raises(ProcError):
        proc.account("motp-plugin", str(passwd), str(defs))


# --- starting processes, Linux --------------------------------------------------------


@linux
def test_child_runs_in_a_clean_new_session() -> None:
    code = (
        "import os, resource as r\n"
        "fds = sorted(int(f) for f in os.listdir('/proc/self/fd'))\n"
        "print(sorted(os.environ.items()))\n"
        "print(os.getcwd(), os.getsid(0) == os.getpid(), os.getpgrp() == os.getpid())\n"
        "print(os.read(0, 10), oct(os.umask(0)))\n"
        "print([r.getrlimit(x) for x in (r.RLIMIT_CPU, r.RLIMIT_FSIZE, r.RLIMIT_NPROC,"
        " r.RLIMIT_NOFILE, r.RLIMIT_CORE)])\n"
        "print(len(fds))\n"
    )
    limits = Limits(cpu_seconds=7, file_bytes=4096, processes=50, open_files=32)
    result = proc.run(py(code, limits=limits, env={"MOTP_PLUGIN_API": "1"}))
    assert result.ok, result
    lines = result.stdout.decode().splitlines()
    assert lines[0] == str(
        [("LC_ALL", "C.UTF-8"), ("MOTP_PLUGIN_API", "1"), ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")]
    )
    assert lines[1] == "/ True True"
    assert lines[2] == "b'' 0o77"
    assert lines[3] == "[(7, 7), (4096, 4096), (50, 50), (32, 32), (0, 0)]"
    assert lines[4] == "4"  # 0, 1, 2 and the descriptor of the listing itself


@linux
def test_child_cannot_gain_privileges() -> None:
    code = "print([ln.split()[1] for ln in open('/proc/self/status') if 'NoNewPrivs' in ln])"
    result = proc.run(py(code))
    assert result.ok, result
    assert result.stdout == b"['1']\n"


@linux
def test_exit_code_and_both_streams_are_returned() -> None:
    result = proc.run(py("import sys; print('out'); sys.stderr.write('err'); sys.exit(3)"))
    assert (result.returncode, result.stdout, result.stderr) == (3, b"out\n", b"err")
    assert not result.ok and not result.timed_out


@linux
def test_missing_program_cannot_be_started() -> None:
    with pytest.raises(ProcError) as exc:
        proc.run(Spec(argv=("/nonexistent/motp-probe",), timeout=1))
    assert exc.value.message.id == "proc.error.start"


@linux
def test_deadline_kills_a_hung_child() -> None:
    started = time.monotonic()
    result = proc.run(py("import time; print('x', flush=True); time.sleep(60)", timeout=0.5))
    assert result.timed_out and result.returncode is None
    assert result.stdout == b"x\n"
    assert time.monotonic() - started < 5


@linux
def test_descendant_holding_the_pipe_does_not_stall_the_read() -> None:
    code = (
        "import subprocess\n"
        "p = subprocess.Popen(['/bin/sleep', '60'])\n"  # inherits stdout and stderr
        "print(p.pid, flush=True)\n"
    )
    started = time.monotonic()
    result = proc.run(py(code, timeout=20))
    assert time.monotonic() - started < 5
    assert result.returncode == 0 and not result.timed_out
    sleeper = int(result.stdout.split()[0])
    assert gone(sleeper), "the process group was not killed"


@linux
def test_stdout_flood_is_cut_at_the_cap_and_killed() -> None:
    code = "import os\nwhile True: os.write(1, b'x' * 65536)\n"
    started = time.monotonic()
    result = proc.run(py(code, timeout=20, stdout_cap=100_000))
    assert time.monotonic() - started < 5
    assert result.stdout_overflow and not result.ok
    assert len(result.stdout) == 100_000


@linux
def test_stderr_is_truncated_without_losing_stdout() -> None:
    code = "import os\nos.write(2, b'e' * 200_000)\nos.write(1, b'ok')\n"
    result = proc.run(py(code, stderr_cap=8192))
    assert result.ok and result.stdout == b"ok"
    assert result.stderr_truncated and len(result.stderr) == 8192


@linux
def test_cpu_limit_ends_a_busy_child() -> None:
    result = proc.run(py("while True: pass", timeout=20, limits=Limits(cpu_seconds=1)))
    assert not result.timed_out
    assert result.returncode in (-signal.SIGXCPU, -signal.SIGKILL)


@linux
def test_file_size_limit_stops_a_writer(tmp_path: Path) -> None:
    target = tmp_path / "big"
    # Closed explicitly: on Python 3.15 an unclosed file only fails while finalising.
    code = f"with open({str(target)!r}, 'wb') as fh:\n    fh.write(b'x' * 100_000)\n"
    result = proc.run(py(code, limits=Limits(file_bytes=4096)))
    # Python ignores SIGXFSZ and sees EFBIG instead; another program would be killed.
    assert result.returncode in (1, -signal.SIGXFSZ)
    assert target.stat().st_size <= 4096


# --- several children at once (run_many), Linux ------------------------------------------


def test_run_many_needs_a_positive_pool() -> None:
    with pytest.raises(ProcError):
        proc.run_many([], 0)


@linux
def test_run_many_runs_children_side_by_side_and_keeps_the_order() -> None:
    specs = [py(f"import time; time.sleep(0.6); print({n})") for n in range(4)]
    started = time.monotonic()
    outcomes = proc.run_many(specs, 4)
    elapsed = time.monotonic() - started
    assert [o.stdout for o in outcomes if isinstance(o, proc.Result)] == [
        b"0\n",
        b"1\n",
        b"2\n",
        b"3\n",
    ]
    assert elapsed < 2.0, f"four 0.6 s children took {elapsed:.2f} s with a pool of four"


@linux
def test_run_many_never_exceeds_the_pool() -> None:
    code = "import time, os; print(time.monotonic()); time.sleep(0.4); print(time.monotonic())"
    outcomes = proc.run_many([py(code) for _ in range(4)], 2)
    spans = []
    for outcome in outcomes:
        assert isinstance(outcome, proc.Result) and outcome.ok
        first, last = (float(x) for x in outcome.stdout.split())
        spans.append((first, last))
    for moment, _ in spans:  # at most two children were alive at any start
        assert sum(1 for a, b in spans if a <= moment < b) <= 2


@linux
def test_run_many_budget_kills_running_and_skips_waiting_children() -> None:
    sleeper = py("import time; time.sleep(30)", timeout=20)
    started = time.monotonic()
    done: list[int] = []
    outcomes = proc.run_many(
        [sleeper, sleeper, py("print('late')")],
        2,
        stop_at=started + 0.8,
        on_done=lambda index, _outcome: done.append(index),
    )
    elapsed = time.monotonic() - started
    assert elapsed < 3.0
    first, second, third = outcomes
    assert isinstance(first, proc.Result) and first.timed_out
    assert isinstance(second, proc.Result) and second.timed_out
    assert third is None  # its turn never came
    assert sorted(done) == [0, 1]


@linux
def test_run_many_reports_a_failed_start_and_runs_the_rest() -> None:
    outcomes = proc.run_many(
        [Spec(argv=("/nonexistent/motp-probe",), timeout=1), py("print('ok')")], 1
    )
    assert isinstance(outcomes[0], ProcError)
    assert outcomes[0].message.id == "proc.error.start"
    assert isinstance(outcomes[1], proc.Result) and outcomes[1].stdout == b"ok\n"


@linux
def test_run_many_overflow_of_one_child_leaves_the_others_alone() -> None:
    flood = py("import os\nwhile True: os.write(1, b'x' * 65536)\n", stdout_cap=1000)
    quiet = py("import time; time.sleep(0.3); print('fine')")
    outcomes = proc.run_many([flood, quiet], 2)
    assert isinstance(outcomes[0], proc.Result) and outcomes[0].stdout_overflow
    assert isinstance(outcomes[1], proc.Result) and outcomes[1].ok
    assert outcomes[1].stdout == b"fine\n"


@linux
def test_run_many_calls_the_tick_while_it_waits() -> None:
    ticks: list[float] = []
    proc.run_many([py("import time; time.sleep(0.5)")], 1, on_tick=lambda: ticks.append(1.0))
    assert len(ticks) >= 3


# --- privilege drop and cleanup, Linux as root ----------------------------------------


@linux_root
def test_drop_gives_target_user_group_and_no_supplementary_groups() -> None:
    import grp

    uid, gid = account(TEST_USER)
    extra = grp.getgrnam(EXTRA_GROUP).gr_gid
    before = os.getgroups()
    os.setgroups([0, extra])  # the parent carries group 0 and another group
    try:
        result = proc.run(
            py(
                "import os; print(os.getuid(), os.geteuid(), os.getgid(), os.getegid(),"
                " os.getgroups(), os.getresuid(), os.getresgid())",
                drop=Drop(uid, gid),
            )
        )
    finally:
        os.setgroups(before)
    assert result.ok, result
    assert result.stdout.decode().strip() == (
        f"{uid} {uid} {gid} {gid} [] ({uid}, {uid}, {uid}) ({gid}, {gid}, {gid})"
    )


@linux_root
def test_account_lookup() -> None:
    uid, gid = account(TEST_USER)
    assert proc.account(TEST_USER) == Drop(uid, gid)
    with pytest.raises(ProcError) as exc:
        proc.account("root")
    assert exc.value.message.id == "proc.error.account"
    with pytest.raises(ProcError) as exc:
        proc.account("motp-no-such-user")
    assert exc.value.message.id == "proc.error.no_account"


ESCAPE = """
import os, time
if os.fork() == 0:
    os.setsid()                     # leave the process group and the session
    if os.fork() == 0:
        for fd in (0, 1, 2):
            os.close(fd)            # and let go of the pipes
        time.sleep(120)
        os._exit(0)
    os._exit(0)
time.sleep(0.5)
print('parent done', flush=True)
"""


@linux_root
def test_child_that_leaves_its_process_group_is_gone_after_cleanup() -> None:
    drop = Drop(*account(TEST_USER))
    assert proc.cleanup_user(drop).clean  # nothing left over from earlier tests
    result = proc.run(py(ESCAPE, drop=drop))
    assert result.ok and result.stdout == b"parent done\n"
    escaped = proc.live_processes(drop.uid)
    assert escaped, "the escaped grandchild should still be running before the cleanup"
    outcome = proc.cleanup_user(drop)
    assert outcome.clean and outcome.remaining == 0
    assert all(gone(pid) for pid in escaped)
    assert proc.live_processes(drop.uid) == []


FORK_BOMB = """
import os, time
while True:
    try:
        os.fork()
    except OSError:
        time.sleep(0.01)
"""


@linux_root
def test_fork_bomb_stays_bounded_and_is_cleaned_up() -> None:
    drop = Drop(*account(TEST_USER))
    assert proc.cleanup_user(drop).clean
    limits = Limits(processes=20, cpu_seconds=5)
    peak = [0]
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            peak[0] = max(peak[0], len(proc.live_processes(drop.uid)))
            time.sleep(0.01)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    started = time.monotonic()
    try:
        result = proc.run(py(FORK_BOMB, timeout=2, drop=drop, limits=limits))
    finally:
        stop.set()
        sampler.join()
    assert time.monotonic() - started < 6
    assert result.timed_out
    assert 1 < peak[0] <= limits.processes
    outcome = proc.cleanup_user(drop)
    assert outcome.clean, outcome
    assert proc.live_processes(drop.uid) == []


def test_descent_follows_the_parent_chain() -> None:
    parents = {10: 5, 5: 3, 3: 1, 7: 1, 20: 20}
    assert proc._descends_from(10, 3, parents)
    assert not proc._descends_from(7, 3, parents)
    assert not proc._descends_from(3, 3, parents)  # a process is not its own descendant
    assert not proc._descends_from(20, 3, parents)  # a loop ends at the depth limit


@linux_root
def test_cleanup_only_touches_the_given_user() -> None:
    target, other = Drop(*account(TEST_USER)), Drop(*account(OTHER_USER))
    assert proc.run(py(ESCAPE, drop=other)).ok  # leaves a process of the other user
    survivors = proc.live_processes(other.uid)
    assert survivors
    bystander = subprocess.Popen(["/bin/sleep", "30"])  # a root process
    try:
        assert proc.cleanup_user(target).clean
        assert proc.live_processes(other.uid) == survivors
        assert bystander.poll() is None and state(bystander.pid) not in ("", "Z", "T")
    finally:
        bystander.kill()
        bystander.wait()
    assert proc.cleanup_user(other).clean


ATTACKER = """
import os, signal
if os.fork() == 0:
    os.setsid()
    for fd in (0, 1, 2):
        os.close(fd)
    for _ in range(3):
        if os.fork() == 0:
            break
    while True:  # stop every process of this user, including whatever cleans up after us
        try:
            os.kill(-1, signal.SIGSTOP)
        except OSError:
            pass
os.wait()
"""


@linux_root
def test_processes_that_fight_back_cannot_stop_the_cleanup() -> None:
    """A helper that dropped to the user would be stopped by these processes (review)."""
    drop = Drop(*account(TEST_USER))
    assert proc.cleanup_user(drop).clean
    result = proc.run(py(ATTACKER, timeout=1, drop=drop))
    assert result.timed_out  # the attackers stopped their own parent, too
    assert proc.live_processes(drop.uid), "the attackers should still exist"
    started = time.monotonic()
    outcome = proc.cleanup_user(drop, timeout=10)
    assert time.monotonic() - started < 10
    assert outcome.clean, outcome
    assert proc.live_processes(drop.uid) == []

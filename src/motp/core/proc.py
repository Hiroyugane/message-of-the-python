"""The only module that starts processes (blueprint 4.9, invariant 1, threats T2, T3, T9, T23).

Every process MOTP starts goes through ``run``, which always:

* takes an argument list whose program is an absolute path, and never uses a shell;
* when a drop is requested, sets ``user=``, ``group=`` and ``extra_groups=[]`` together,
  so the child keeps no trace of group 0 or of the parent's supplementary groups;
* starts the child in a new session, with working directory ``/``, stdin from
  ``/dev/null``, umask 077 and only the descriptors 0 to 2 open;
* builds the environment from scratch (``PATH``, ``LC_ALL`` and named ``MOTP_*`` values);
* sets limits on CPU time, file size, number of processes, open files and core dumps,
  and ``no_new_privs``; for plugins also no POSIX message queue and, without a drop, an
  out-of-memory score that makes the kernel end the plugin first (phase 12);
* reads stdout and stderr against a deadline and up to a cap each. It never waits for the
  end of file from descendants: once the child has exited, whatever is already in the
  pipes is taken and the process group is killed. On expiry, or when stdout exceeds its
  cap, the process group is killed at once.

The group is killed while the child is still an unreaped zombie, so its process group id
cannot have been reused by an unrelated process.

It also sets ``no_new_privs`` in the child, so a dropped child cannot gain privileges
through a setuid program, with or without the systemd sandbox.

``cleanup_user`` ends everything a user still runs, including processes that left their
process group: root stops and kills each of them through a pidfd until none is left.

Not thread-safe: the limits are applied by a ``preexec_fn`` in the child, which the
collector (single-threaded) can afford. Calling ``run`` while other threads hold locks
could deadlock the child between fork and exec.
"""

import os
import posixpath
import re
import select
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from motp.core.model import ContractError, contract_error

SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
BASE_ENV = {"PATH": SAFE_PATH, "LC_ALL": "C.UTF-8"}
EXTRA_ENV_NAME = re.compile(r"MOTP_[A-Z0-9_]{1,32}\Z")
MAX_TIMEOUT = 600.0
MAX_ARGS = 256
MAX_ARG_CHARS = 4096
DEFAULT_STDOUT_CAP = 64 * 1024  # 4.9: 64 KiB of stdout
DEFAULT_STDERR_CAP = 8 * 1024  # 4.9: 8 KiB of stderr kept for the log
READ_CHUNK = 65536
POLL_SECONDS = 0.05
CLEANUP_SECONDS = 5.0
CLEANUP_PAUSE = 0.01
MAX_TREE_DEPTH = 256  # parent chain walked to find the collector
PR_SET_NO_NEW_PRIVS = 38
OOM_SCORE_MAX = 1000
OOM_SCORE_FILE = "/proc/self/oom_score_adj"


class ProcError(ContractError):
    """A process could not be started as specified. ``message`` says why."""


def _fail(msg_id: str) -> ProcError:
    return ProcError(contract_error(msg_id).message)


@dataclass(frozen=True)
class Drop:
    """The identity a child runs as: a user id and its group id, never 0."""

    uid: int
    gid: int

    def __post_init__(self) -> None:
        for value in (self.uid, self.gid):
            if type(value) is not int or not 0 < value < 2**31 - 1:
                raise _fail("proc.error.drop")


@dataclass(frozen=True)
class Limits:
    """Resource limits set in the child after the drop (``setrlimit``, soft = hard).

    ``processes`` counts every process of the child's real user, so it bounds a fork bomb
    of a dropped child; root ignores it, which the unit's ``TasksMax`` covers instead.
    """

    cpu_seconds: int = 10
    file_bytes: int = 1024 * 1024
    processes: int = 64
    open_files: int = 64
    address_space: Optional[int] = None  # bytes; None leaves it to the unit's MemoryMax
    # Bytes of POSIX message queues (RLIMIT_MSGQUEUE); 0 means the child can create none,
    # so nothing outlives it there (phase 12: queues cannot be listed for the cleanup).
    msgqueue: Optional[int] = None
    # Written to /proc/self/oom_score_adj (raising it needs no privilege) when the child
    # keeps the caller's user (a plugin's shim in its own unit): at MemoryMax the kernel
    # ends the child with the highest score first. Ignored with a drop.
    oom_score_adj: Optional[int] = None

    def __post_init__(self) -> None:
        for value in (self.cpu_seconds, self.file_bytes, self.processes, self.open_files):
            if type(value) is not int or value < 1:
                raise _fail("proc.error.limits")
        if self.address_space is not None and (
            type(self.address_space) is not int or self.address_space < 1
        ):
            raise _fail("proc.error.limits")
        if self.msgqueue is not None and (type(self.msgqueue) is not int or self.msgqueue < 0):
            raise _fail("proc.error.limits")
        if self.oom_score_adj is not None and (
            type(self.oom_score_adj) is not int or not 0 <= self.oom_score_adj <= OOM_SCORE_MAX
        ):
            raise _fail("proc.error.limits")


@dataclass(frozen=True)
class Spec:
    """What to start. ``argv[0]`` is an absolute path to the program; nothing is looked
    up in ``PATH``. ``env`` adds ``MOTP_*`` variables to the fixed base environment."""

    argv: tuple[str, ...]
    timeout: float
    drop: Optional[Drop] = None
    limits: Limits = field(default_factory=Limits)
    env: Mapping[str, str] = field(default_factory=dict)
    stdout_cap: int = DEFAULT_STDOUT_CAP
    stderr_cap: int = DEFAULT_STDERR_CAP


@dataclass(frozen=True)
class Result:
    """Outcome of one run.

    ``returncode`` is the child's exit status (negative: killed by that signal), or
    ``None`` if it was still running when the deadline killed it. ``timed_out`` and
    ``stdout_overflow`` say why the group was killed early. ``stderr_truncated`` means
    only the first ``stderr_cap`` bytes were kept.
    """

    returncode: Optional[int]
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_overflow: bool
    stderr_truncated: bool
    duration: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.stdout_overflow


def environment(extra: Mapping[str, str]) -> dict[str, str]:
    """The child's whole environment: the fixed base plus validated ``MOTP_*`` names."""
    env = dict(BASE_ENV)
    for name, value in extra.items():
        if not EXTRA_ENV_NAME.match(name) or type(value) is not str or "\x00" in value:
            raise _fail("proc.error.env")
        env[name] = value
    return env


def validate(spec: Spec) -> None:
    """Refuse a spec that breaks the rules of 4.9 before anything is started."""
    argv = spec.argv
    if type(argv) is not tuple or not argv or len(argv) > MAX_ARGS:
        raise _fail("proc.error.argv")
    for arg in argv:
        if type(arg) is not str or "\x00" in arg or len(arg) > MAX_ARG_CHARS:
            raise _fail("proc.error.argv")
    program = argv[0]
    if not program.startswith("/") or posixpath.normpath(program) != program:
        raise ProcError(contract_error("proc.error.relative", program=program).message)
    if not 0 < spec.timeout <= MAX_TIMEOUT:
        raise _fail("proc.error.timeout")
    if spec.stdout_cap < 0 or spec.stderr_cap < 0:
        raise _fail("proc.error.limits")
    environment(spec.env)


def _rlimits(limits: Limits) -> list[tuple[int, int]]:
    import resource

    pairs = [
        (resource.RLIMIT_CPU, limits.cpu_seconds),
        (resource.RLIMIT_FSIZE, limits.file_bytes),
        (resource.RLIMIT_NPROC, limits.processes),
        (resource.RLIMIT_NOFILE, limits.open_files),
        (resource.RLIMIT_CORE, 0),
    ]
    if limits.address_space is not None:
        pairs.append((resource.RLIMIT_AS, limits.address_space))
    if limits.msgqueue is not None:
        pairs.append((resource.RLIMIT_MSGQUEUE, limits.msgqueue))
    return pairs


def _child_setup(
    pairs: list[tuple[int, int]], oom_score_adj: Optional[int] = None
) -> Callable[[], None]:
    """The function run in the child after the drop and before ``exec``.

    Everything it needs is bound here, in the parent, so the child imports nothing. It
    sets the limits, the out-of-memory score and ``no_new_privs``; a failure raises, so
    the start fails closed.
    """
    import ctypes
    import resource

    getrlimit, setrlimit, infinity = resource.getrlimit, resource.setrlimit, resource.RLIM_INFINITY
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    get_errno = ctypes.get_errno
    score = None if oom_score_adj is None else str(oom_score_adj).encode("ascii")
    open_, write, close = os.open, os.write, os.close
    write_only = os.O_WRONLY | os.O_CLOEXEC

    def setup() -> None:
        for which, value in pairs:
            hard = getrlimit(which)[1]
            # Never raise a limit the parent already had lower.
            if hard != infinity:
                value = min(value, hard)
            setrlimit(which, (value, value))
        if score is not None:
            fd = open_(OOM_SCORE_FILE, write_only)
            try:
                write(fd, score)
            finally:
                close(fd)
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(get_errno(), "prctl")

    return setup


def _exited(pid: int) -> bool:
    """True once ``pid`` has exited, without reaping it (it stays a zombie)."""
    try:
        info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return True
    return info is not None


def _kill_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass


class _Reader:
    """Collects one pipe up to a cap; reads are non-blocking."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.chunks: list[bytes] = []
        self.size = 0
        self.over = False

    def feed(self, data: bytes) -> None:
        room = self.cap - self.size
        if len(data) > room:
            self.over = True
            data = data[: max(room, 0)]
        if data:
            self.chunks.append(data)
            self.size += len(data)

    def value(self) -> bytes:
        return b"".join(self.chunks)


@dataclass
class _Active:
    """One started child of ``run_many`` and what has been read from it so far."""

    spec: Spec
    child: "subprocess.Popen[bytes]"
    started: float
    deadline: float
    out_fd: int
    err_fd: int
    readers: dict[int, _Reader]
    open_fds: set[int]
    timed_out: bool = False
    overflow: bool = False


def _start(spec: Spec, clock: Callable[[], float], stop_at: Optional[float]) -> _Active:
    """Validate and start one child; raises ``ProcError`` if that is not possible."""
    validate(spec)
    drop = spec.drop
    started = clock()
    try:
        child = subprocess.Popen(  # noqa: S603 - absolute program, argument list, no shell
            list(spec.argv),
            executable=spec.argv[0],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=environment(spec.env),
            close_fds=True,
            start_new_session=True,
            restore_signals=True,
            umask=0o077,
            # The score only without a drop: a drop makes the child non-dumpable, which
            # gives /proc/self to root, and making it dumpable again would open the
            # collector's memory to its user until exec (phase 12 reviews).
            preexec_fn=_child_setup(
                _rlimits(spec.limits), spec.limits.oom_score_adj if drop is None else None
            ),
            shell=False,
            # A drop always sets all three, so no supplementary group survives.
            user=None if drop is None else drop.uid,
            group=None if drop is None else drop.gid,
            extra_groups=None if drop is None else [],
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ProcError(contract_error("proc.error.start", program=spec.argv[0]).message) from exc
    if child.stdout is None or child.stderr is None:  # pragma: no cover - PIPE always set
        raise ProcError(contract_error("proc.error.start", program=spec.argv[0]).message)
    out_fd, err_fd = child.stdout.fileno(), child.stderr.fileno()
    for fd in (out_fd, err_fd):
        os.set_blocking(fd, False)
    deadline = started + spec.timeout
    if stop_at is not None:
        deadline = min(deadline, stop_at)
    return _Active(
        spec=spec,
        child=child,
        started=started,
        deadline=deadline,
        out_fd=out_fd,
        err_fd=err_fd,
        readers={out_fd: _Reader(spec.stdout_cap), err_fd: _Reader(spec.stderr_cap)},
        open_fds={out_fd, err_fd},
    )


def _read_once(act: _Active, fd: int) -> bool:
    """One non-blocking read of ``fd``. False when nothing more can come now: the pipe is
    empty, at its end (then it is closed for this child), or full beyond its cap."""
    try:
        data = os.read(fd, READ_CHUNK)
    except BlockingIOError:
        return False
    except OSError:
        data = b""
    if not data:
        act.open_fds.discard(fd)
        return False
    reader = act.readers[fd]
    before = reader.size
    reader.feed(data)
    if fd == act.out_fd and reader.over:
        act.overflow = True
        return False
    return reader.size != before


def _take_buffered(act: _Active) -> None:
    """After the child exited: take what is already in the pipes, never wait for more.

    Descendants may still hold a pipe and keep writing; the reads of a pipe stop as soon
    as it is empty, at its end, or nothing more fits under its cap.
    """
    for fd in (act.out_fd, act.err_fd):
        for _ in range(act.readers[fd].cap // READ_CHUNK + 2):
            if fd not in act.open_fds or act.overflow or not _read_once(act, fd):
                break


def _finish(act: _Active, clock: Callable[[], float]) -> Result:
    """Kill the group, reap the child and build its result."""
    # The child is not reaped yet, so its pid (and process group id) is still ours.
    _kill_group(act.child.pid)
    for pipe in (act.child.stdout, act.child.stderr):
        if pipe is not None:
            pipe.close()
    returncode = act.child.wait()
    return Result(
        returncode=None if act.timed_out else returncode,
        stdout=act.readers[act.out_fd].value(),
        stderr=act.readers[act.err_fd].value(),
        timed_out=act.timed_out,
        stdout_overflow=act.overflow,
        stderr_truncated=act.readers[act.err_fd].over,
        duration=clock() - act.started,
    )


Outcome = Union[Result, ProcError, None]


def run_many(
    specs: Sequence[Spec],
    parallel: int = 1,
    *,
    stop_at: Optional[float] = None,
    clock: Callable[[], float] = time.monotonic,
    on_done: Optional[Callable[[int, Outcome], None]] = None,
    on_tick: Optional[Callable[[], None]] = None,
) -> list[Outcome]:
    """Run ``specs`` with at most ``parallel`` children at a time, in the given order.

    Each child gets the rules of 4.9 exactly as with ``run``: its own deadline, caps on
    both streams, no waiting for descendants once it has exited, and its process group
    killed at the end. ``stop_at`` (a value of ``clock``) is a budget for the whole call:
    no child starts after it, and a running child is killed when it is reached (its
    result says ``timed_out``). The outcome per spec is its ``Result``, the ``ProcError``
    that kept it from starting, or ``None`` if the budget ran out before its turn.

    ``on_done(index, outcome)`` is called as each spec is settled, ``on_tick()`` on every
    pass of the wait loop (at least every ``POLL_SECONDS``), so a caller can print status.
    One thread and one selector serve all children; nothing here is thread-safe.
    """
    if type(parallel) is not int or parallel < 1:
        raise _fail("proc.error.limits")
    outcomes: list[Outcome] = [None] * len(specs)
    queue = list(reversed(range(len(specs))))
    active: dict[int, _Active] = {}

    def settle(index: int, outcome: Outcome) -> None:
        outcomes[index] = outcome
        if on_done is not None:
            on_done(index, outcome)

    with selectors.DefaultSelector() as sel:

        def finish(index: int) -> None:
            act = active.pop(index)
            for fd in (act.out_fd, act.err_fd):
                if fd in sel.get_map():
                    sel.unregister(fd)
            settle(index, _finish(act, clock))

        try:
            while queue or active:
                while queue and len(active) < parallel:
                    if stop_at is not None and clock() >= stop_at:
                        queue.clear()  # the budget is spent: the rest never starts
                        break
                    index = queue.pop()
                    try:
                        act = _start(specs[index], clock, stop_at)
                    except ProcError as exc:
                        settle(index, exc)
                        continue
                    active[index] = act
                    for fd in (act.out_fd, act.err_fd):
                        sel.register(fd, selectors.EVENT_READ, index)
                now = clock()
                for index, act in list(active.items()):
                    if _exited(act.child.pid):
                        _take_buffered(act)
                        finish(index)
                    elif now >= act.deadline:
                        act.timed_out = True
                        finish(index)
                if on_tick is not None:
                    on_tick()
                if not active:
                    continue
                wait = max(0.0, min(POLL_SECONDS, min(a.deadline for a in active.values()) - now))
                if not sel.get_map():
                    time.sleep(wait)  # every pipe is closed: wait for the exits
                    continue
                for key, _events in sel.select(wait):
                    index = key.data
                    ready = active.get(index)
                    if ready is None:
                        continue  # finished earlier in this pass
                    _read_once(ready, key.fd)
                    if key.fd not in ready.open_fds:
                        sel.unregister(key.fd)
                    if ready.overflow:
                        finish(index)
        finally:
            for index in list(active):  # an exception above must not leave children behind
                act = active.pop(index)
                _kill_group(act.child.pid)
                act.child.kill()
                act.child.wait()
    return outcomes


def run(spec: Spec, clock: Callable[[], float] = time.monotonic) -> Result:
    """Start ``spec`` under the rules of 4.9 and collect its output.

    Raises ``ProcError`` if the spec is invalid or the program cannot be started.
    """
    validate(spec)
    outcome = run_many([spec], 1, clock=clock)[0]
    if isinstance(outcome, ProcError):
        raise outcome
    if outcome is None:  # pragma: no cover - without a budget every spec gets its turn
        raise _fail("proc.error.timeout")
    return outcome


# --- cleanup of everything a user still runs -------------------------------------------


@dataclass(frozen=True)
class Cleanup:
    """Outcome of ``cleanup_user``: ``clean`` is True if no live process of the user is
    left (zombies waiting for their parent count as gone)."""

    clean: bool
    remaining: int


@dataclass(frozen=True)
class _Status:
    state: bytes  # one letter
    uid: bytes  # real uid, as text
    ppid: int


def _status_fields(pid: int, proc_root: str) -> Optional[_Status]:
    """State letter, real uid and parent of ``pid`` from ``/proc``; ``None`` if it is gone."""
    try:
        with open(f"{proc_root}/{pid}/status", "rb") as fh:
            status = fh.read(4096)
    except OSError:
        return None
    state = real_uid = b""
    ppid = 0
    for line in status.split(b"\n"):
        if line.startswith(b"State:"):
            state = line[6:].strip()[:1]
        elif line.startswith(b"Uid:"):
            fields = line.split()
            real_uid = fields[1] if len(fields) > 1 else b""
        elif line.startswith(b"PPid:"):
            fields = line.split()
            ppid = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
    return _Status(state, real_uid, ppid)


def _descends_from(pid: int, ancestor: int, parents: Mapping[int, int]) -> bool:
    """True if ``ancestor`` is on the parent chain of ``pid`` (``parents``: pid -> ppid)."""
    seen = 0
    while pid > 1 and seen < MAX_TREE_DEPTH:
        pid = parents.get(pid, 0)
        if pid == ancestor:
            return True
        seen += 1
    return False


def _parents(proc_root: str) -> dict[int, tuple[_Status, int]]:
    """Every process with its status: pid -> (status, ppid)."""
    table: dict[int, tuple[_Status, int]] = {}
    try:
        names = os.listdir(proc_root)
    except OSError:
        return table
    for name in names:
        if name.isdigit():
            fields = _status_fields(int(name), proc_root)
            if fields is not None:
                table[int(name)] = (fields, fields.ppid)
    return table


def live_processes(uid: int, proc_root: str = "/proc", ancestor: Optional[int] = None) -> list[int]:
    """Process ids whose real user is ``uid`` and that are not zombies; with ``ancestor``,
    only those that descend from that process."""
    table = _parents(proc_root)
    parents = {pid: ppid for pid, (_status, ppid) in table.items()}
    wanted = str(uid).encode()
    return [
        pid
        for pid, (status, _ppid) in sorted(table.items())
        if status.uid == wanted
        and status.state not in (b"Z", b"X")
        and (ancestor is None or _descends_from(pid, ancestor, parents))
    ]


def _signal_if_owned(pid: int, uid: int, sig: int, ancestor: Optional[int] = None) -> bool:
    """Send ``sig`` to ``pid`` only if it is still the live process of ``uid`` it was (and,
    with ``ancestor``, still a descendant of that process).

    A pidfd pins the process: it is opened first, the owner and the parent chain are read
    from ``/proc``, and the pidfd is polled. If the process had exited (and its pid been
    reused) meanwhile, the poll says so and nothing is sent; otherwise what was read
    belonged to it, and the signal goes through the pidfd, which can never reach another
    process.
    """
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        fields = _status_fields(pid, "/proc")
        if fields is None or fields.uid != str(uid).encode() or fields.state in (b"Z", b"X"):
            return False
        if ancestor is not None:
            chain: dict[int, int] = {pid: fields.ppid}
            current = fields.ppid
            for _ in range(MAX_TREE_DEPTH):
                if current <= 1 or current == ancestor:
                    break
                parent = _status_fields(current, "/proc")
                if parent is None:
                    break
                chain[current] = parent.ppid
                current = parent.ppid
            if not _descends_from(pid, ancestor, chain):
                return False
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        if poller.poll(0):
            return False  # exited after the pidfd was opened
        signal.pidfd_send_signal(pidfd, sig)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(pidfd)


def cleanup_root_descendants(ancestor: int, timeout: float = CLEANUP_SECONDS) -> Cleanup:
    """Kill the processes of root that descend from ``ancestor`` (phase 12).

    For a plugin granted root and run without the unit (``--no-sandbox``): what it left
    behind runs as root, so ``cleanup_user`` (which never takes root) cannot find it. Only
    descendants of ``ancestor`` (the collector, a child subreaper) are touched, never the
    caller itself; call it only when no ``run``/``run_many`` child is meant to be alive.
    """
    if os.geteuid() != 0:
        raise _fail("proc.error.cleanup_not_root")
    if type(ancestor) is not int or ancestor <= 1:
        raise _fail("proc.error.drop")
    return _cleanup_uid(0, timeout, ancestor)


def cleanup_user(
    drop: Drop, timeout: float = CLEANUP_SECONDS, ancestor: Optional[int] = None
) -> Cleanup:
    """Kill the processes the user of ``drop`` still runs (4.9), within ``timeout``.

    With ``ancestor`` (the collector passes its own pid) only processes that descend from
    that process are touched: another workload that happens to run under the same uid,
    such as a container's service user on the host, is left alone. The collector makes
    itself a child subreaper (``become_subreaper``), so a probe's process that left its
    process group and session is reparented to the collector, not to init, and stays a
    descendant. Without ``ancestor`` every process of the uid is a target.

    Root finds the processes in ``/proc`` and signals each through a pidfd: first
    ``SIGSTOP`` to all of them, so none can fork while the round runs, then ``SIGKILL``.
    Rounds repeat until none is left. The processes of the user cannot signal root, so
    they cannot stop the cleanup itself. (Blueprint 4.9 put this into a helper that drops
    to the user; such a helper can be stopped by the very processes it is meant to kill.)
    Refuses to run unless the caller is root; ``Drop`` never names root.
    """
    if os.geteuid() != 0:
        raise _fail("proc.error.cleanup_not_root")
    return _cleanup_uid(drop.uid, timeout, ancestor)


def _cleanup_uid(uid: int, timeout: float, ancestor: Optional[int]) -> Cleanup:
    """Rounds of SIGSTOP and SIGKILL to the live processes of ``uid`` (descendants of
    ``ancestor`` only, when given) until none is left or ``timeout`` passed."""
    deadline = time.monotonic() + timeout
    me = os.getpid()
    while True:
        pids = [pid for pid in live_processes(uid, ancestor=ancestor) if pid != me]
        if not pids or time.monotonic() >= deadline:
            return Cleanup(clean=not pids, remaining=len(pids))
        for sig in (signal.SIGSTOP, signal.SIGKILL):
            for pid in pids:
                _signal_if_owned(pid, uid, sig, ancestor)
        time.sleep(CLEANUP_PAUSE)


# --- the cleanup inside the collector unit (phase 7) -----------------------------------

CGROUP_ROOT = "/sys/fs/cgroup"
SERVICE_SLICE = "/system.slice"
SELF_CGROUP = "/proc/self/cgroup"
MAX_CGROUP_BYTES = 1024 * 1024
CAP_SYS_PTRACE = 19
HIDING_OPTIONS = {b"1", b"2", b"invisible", b"noaccess", b"ptraceable"}


def service_cgroup_procs(
    unit: str, self_cgroup: str = SELF_CGROUP, root: str = CGROUP_ROOT
) -> Optional[str]:
    """The ``cgroup.procs`` file of this process's own control group, if that group is
    exactly ``/system.slice/<unit>`` on the unified hierarchy (cgroup v2) and belongs to
    root; ``None`` anywhere else (cgroup v1, a user's delegated tree).

    Inside the collector unit every process of that group is the collector or one of its
    descendants: systemd put the collector there, and only root could move another
    process in.
    """
    try:
        with open(self_cgroup, "rb") as fh:
            lines = fh.read(65536).split(b"\n")
    except OSError:
        return None
    wanted = ("0::" + SERVICE_SLICE + "/" + unit).encode()
    if wanted not in lines:
        return None
    directory = root + SERVICE_SLICE + "/" + unit
    try:
        st = os.stat(directory)
    except OSError:
        return None
    # A group below a user's delegated tree, or one others can write, is not the unit's.
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        return None
    procs = directory + "/cgroup.procs"
    return procs if os.path.isfile(procs) else None


def _cgroup_pids(procs: str) -> Optional[set[int]]:
    """The pids of the group, or ``None`` when the list cannot be read."""
    try:
        with open(procs, "rb") as fh:
            data = fh.read(MAX_CGROUP_BYTES)
    except OSError:
        return None
    return {int(w) for w in data.split() if w.isdigit()}


def process_view_hidden(
    mountinfo: str = "/proc/self/mountinfo", status: str = "/proc/self/status"
) -> bool:
    """True if ``/proc`` hides other users' processes from this process: mounted with
    ``hidepid`` (other than 0 or ``off``), without ``CAP_SYS_PTRACE`` in the effective set
    and outside the mount's exempt group (``gid=``, 0 when not named). The cleanup by
    ``/proc`` is blind then."""
    try:
        with open(mountinfo, "rb") as fh:
            rows = fh.read(MAX_CGROUP_BYTES).split(b"\n")
    except OSError:
        return True  # unknown: fail closed
    options: list[bytes] = []
    for row in rows:
        fields = row.split(b" ")
        if len(fields) > 4 and fields[4] == b"/proc" and b"-" in fields:
            tail = fields[fields.index(b"-") + 1 :]
            if tail and tail[0] == b"proc":
                options = tail[2].split(b",") if len(tail) > 2 else []
    values = dict(o.split(b"=", 1) for o in options if b"=" in o)
    if values.get(b"hidepid") not in HIDING_OPTIONS:
        return False
    # The kernel exempts members of the mount's gid= group, which is 0 when none is
    # named: a collector in group 0 sees every process unless the mount names another.
    exempt = values.get(b"gid", b"0")
    if exempt.isdigit() and (int(exempt) == os.getegid() or int(exempt) in os.getgroups()):
        return False
    try:
        with open(status, "rb") as fh:
            for line in fh.read(65536).split(b"\n"):
                if line.startswith(b"CapEff:"):
                    caps = int(line.split()[1], 16)
                    return not caps & (1 << CAP_SYS_PTRACE)
    except (OSError, ValueError, IndexError):
        pass
    return True


def _signal_in_cgroup(pid: int, sig: int, procs: str) -> bool:
    """Send ``sig`` to ``pid`` only while it is still a member of the group ``procs``.

    The pidfd is opened first, then the group is read again, then the pidfd is polled:
    if the process is alive after the read, it was alive and in the group at the read,
    so the pid read there is this process and no reused one. Nothing of the process
    itself is read from ``/proc``, so this works under ``hidepid``.
    """
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        if pid not in (_cgroup_pids(procs) or ()):
            return False
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        if poller.poll(0):
            return False
        signal.pidfd_send_signal(pidfd, sig)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(pidfd)


def _alive(pid: int) -> bool:
    """True while ``pid`` names a process that has not exited (a zombie has)."""
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        return not poller.poll(0)
    finally:
        os.close(pidfd)


def cleanup_cgroup(procs: str, timeout: float = CLEANUP_SECONDS) -> Cleanup:
    """Kill every process of the collector unit's control group except this one (4.9).

    Used inside the unit instead of ``cleanup_user``: the group holds only the collector
    and its descendants, whatever user they run as, and it is readable under ``hidepid``.
    Call it only when no ``run``/``run_many`` child is meant to be alive; it reaps the
    zombies it leaves (this process is their subreaper).
    """
    if os.geteuid() != 0:
        raise _fail("proc.error.cleanup_not_root")
    me = os.getpid()
    deadline = time.monotonic() + timeout
    while True:
        reap_children()
        listed = _cgroup_pids(procs)
        if listed is None:  # cannot tell what is left: never call that clean
            return Cleanup(clean=False, remaining=0)
        pids = [pid for pid in sorted(listed - {me}) if _alive(pid)]
        if not pids or time.monotonic() >= deadline:
            return Cleanup(clean=not pids, remaining=len(pids))
        for sig in (signal.SIGSTOP, signal.SIGKILL):
            for pid in pids:
                _signal_in_cgroup(pid, sig, procs)
        time.sleep(CLEANUP_PAUSE)


PR_SET_CHILD_SUBREAPER = 36


def become_subreaper() -> None:
    """Make this process the reaper of its orphaned descendants (``PR_SET_CHILD_SUBREAPER``).

    A probe's process that leaves its session is then reparented here instead of to
    init, so ``cleanup_user(..., ancestor=os.getpid())`` still finds it. Raises
    ``ProcError`` if the kernel refuses.
    """
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise _fail("proc.error.subreaper")


def reap_children() -> int:
    """Reap every child that has exited, without waiting; return how many.

    Only for moments when no ``run``/``run_many`` child is alive (``Popen`` reaps its own
    children); a subreaper inherits the zombies of the orphans it ended.
    """
    count = 0
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return count
        if pid == 0:
            return count
        count += 1


# --- accounts ----------------------------------------------------------------------------

NOBODY_UID = 65534
DEFAULT_SYS_UID_MAX = 999
ACCOUNTS_FILE = "/etc/passwd"
LOGIN_DEFS = "/etc/login.defs"


def _sys_uid_max(login_defs: str) -> int:
    """``SYS_UID_MAX`` from ``login.defs``; 999 when absent or unreadable."""
    try:
        with open(login_defs, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 2 and parts[0] == "SYS_UID_MAX" and parts[1].isdigit():
                    return int(parts[1])
    except OSError:
        pass
    return DEFAULT_SYS_UID_MAX


def account(name: str, accounts_file: str = ACCOUNTS_FILE, login_defs: str = LOGIN_DEFS) -> Drop:
    """The ``Drop`` for a local system account by name: its uid and primary group.

    Only an entry of the local ``passwd`` file counts, never a directory service, and it
    must be the only entry with that name and with that uid (so ``motp`` and
    ``motp-plugin`` cannot share one), in the system range, not ``nobody``, and with a
    primary group other than root. ``cleanup_user`` kills everything of that uid, so it
    must belong to MOTP alone. Collector side only (the login path resolves no names, D22).
    """
    try:
        with open(accounts_file, encoding="utf-8", errors="replace") as fh:
            entries = [line.rstrip("\n").split(":") for line in fh]
    except OSError as exc:
        raise ProcError(contract_error("proc.error.no_account", name=name).message) from exc
    entries = [e for e in entries if len(e) >= 7 and e[2].isdigit() and e[3].isdigit()]
    mine = [e for e in entries if e[0] == name]
    if not mine:
        raise ProcError(contract_error("proc.error.no_account", name=name).message)
    uid, gid = int(mine[0][2]), int(mine[0][3])
    shared = [e for e in entries if int(e[2]) == uid]
    if (
        len(mine) != 1
        or len(shared) != 1
        or uid in (0, NOBODY_UID)
        or gid == 0
        or uid > _sys_uid_max(login_defs)
    ):
        raise ProcError(contract_error("proc.error.account", name=name).message)
    return Drop(uid, gid)

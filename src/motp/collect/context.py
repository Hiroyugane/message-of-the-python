"""The context of a cached module inside its probe process (blueprint 4.3, D21, D25).

A probe runs as ``motp`` (or as root for a module that declares ``needs_root``) and
already sits inside the limits ``core.proc`` gave it. Its context may read more than a
live module's: below ``/proc``, ``/sys``, ``/etc``, ``/usr/lib`` and ``/run``, following
links (``/etc/os-release`` and ``/etc/resolv.conf`` are links on many systems), always
bounded and only from regular files. The package modules also look below ``/usr/bin``,
``/usr/share``, ``/var/cache`` and ``/var/lib/apt``: whether a program is installed,
which names a cache directory holds and when a file last changed. The login modules read
binary records below ``/var/log`` (``wtmp``, ``lastlog``) and ``/run`` (``utmp``): a
slice at an offset, a file's size, and the parts of a sparse file that hold data.

A probe that runs as root (``os_login``, the first) reads every file outside ``/proc``
and ``/sys`` through ``safepath.open_trusted``: each directory from ``/`` down must belong
to root and be writable by nobody else, links are followed only where root owns them, and
the file itself must be root's and not writable by others. For the login records alone
(``RECORD_FILES``) group write is accepted on the file and on the directory that holds
it, since ``wtmp`` and ``lastlog`` are writable by the ``utmp`` group by design and Ubuntu
keeps ``/var/log`` writable by ``syslog``; what is read is parsed as untrusted data. So
no other user can make root read a file of their choosing through a link or a swapped
name. As root, ``exists``, ``list_dir``, ``mtime`` and ``statvfs`` walk the same chain
(phase 11): a path below a directory another user can change is refused, not reported.

A root probe may send one fixed ``GET`` over a local socket below ``/run``
(``unix_get``, phase 11, for the container runtimes): the socket must sit in a chain
only root can change, be root's, and be served by a root process; see
``collect.unixhttp`` for the request and the limits on the answer.

A probe may ask for the usage of a file system, and it may start a program the module
lists in ``binaries``: the program and its interpreter chain must pass the ownership
check, and the start goes through ``core.proc`` like every other. As root, a program
whose interpreter is Python is started only if that interpreter's import directories
pass the check too (``core.importpath``, final review).

This module is never imported on the render path; ``motp show`` keeps the live context.
"""

import contextlib
import errno
import os
import posixpath
import stat
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Callable, Optional

from motp.core import importpath, proc, safepath
from motp.core.model import ContractError
from motp.modules.base import (
    MAX_READ,
    OS_RELEASE_FILES,
    Context,
    FsUsage,
    ImportPathError,
    _check_path,
    context_error,
    parse_os_release,
)

PROBE_READ_ROOTS = (
    "/proc/",
    "/sys/",
    "/etc/",
    "/usr/lib/",
    "/usr/bin/",
    "/usr/share/",
    "/run/",
    "/var/cache/",
    "/var/lib/apt/",
    "/var/log/",
)
# Kernel file systems: their files are not root's files in the ownership sense.
KERNEL_ROOTS = ("/proc/", "/sys/")
# The login records, which the system keeps writable by the utmp group (and on Ubuntu in a
# /var/log its syslog group can write): the only files a root probe reads with group write
# allowed. Everything else must pass the full check (review of phase 10).
# ``btmp`` (failed logins, phase 11) is 0660 root:utmp like wtmp on all four tier-1 images.
RECORD_FILES = frozenset(
    {"/var/log/wtmp", "/var/log/lastlog", "/var/log/btmp", "/run/utmp", "/var/run/utmp"}
)
# Where ``unix_get`` may connect: the sockets of system services.
SOCKET_ROOTS = ("/run/",)
# The most ``read_slice`` and ``data_regions`` return at once.
MAX_BINARY_READ = 16 * 1024 * 1024
PROBE_MAX_READ = 1024 * 1024  # a probe is its own bounded process; mountinfo can be large
RUN_TIMEOUT = 5.0
MIN_RUN_TIME = 0.1  # with less than this left no program is started
# Where a program may be given a directory of its own: the unit's private tmpfs, and on
# a system without the sandbox the shared one, hence a new name every time.
SCRATCH_ROOT = "/var/tmp"  # noqa: S108
# A package manager's list of pending updates: about 200 bytes per package, so this holds
# several thousand. A program that writes more is ended and the module fails.
RUN_STDOUT_CAP = 2 * 1024 * 1024
MAX_DIR_ENTRIES = 4096
MAX_ROW_PATH = 4096  # the config's limit for a [[rows.file_age]] path
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOCTTY", 0)
)


@dataclass(frozen=True)
class ProbeContext(Context):
    """The context of a cached module; ``binaries`` are the programs it may start."""

    read_roots = PROBE_READ_ROOTS
    max_read = PROBE_MAX_READ

    binaries: tuple[str, ...] = ()
    run_timeout: float = RUN_TIMEOUT
    # When every program must have ended, on ``clock``'s scale; ``None`` for no such end.
    deadline: Optional[float] = None
    clock: Callable[[], float] = time.monotonic

    def statvfs(self, path: str) -> FsUsage:
        """Usage of the file system mounted at ``path`` (an absolute, normalised path)."""
        _check_path(path, ("/",))
        return self._statvfs(path)

    def list_dir(self, path: str) -> tuple[str, ...]:
        """The names in a directory below a read root, sorted; more than
        ``MAX_DIR_ENTRIES`` fails instead of dropping some without a word."""
        _check_path(path, self.read_roots)
        names = self._list_dir(path)
        if len(names) > MAX_DIR_ENTRIES:
            raise context_error("context.error.read")
        return tuple(sorted(names))

    def mtime(self, path: str) -> int:
        """When the file or directory last changed, in seconds since the epoch."""
        _check_path(path, self.read_roots)
        return self._mtime(path)

    def file_mtime(self, path: str) -> int:
        """When a file an admin named in ``[[rows.file_age]]`` last changed (phase 12).

        Any absolute path in its normal form, looked at with the probe user's own rights:
        ``stat`` needs search permission on the directories only, never read permission
        on the file, and a link is followed only as far as that user may follow it. So a
        row tells nothing the user ``motp`` could not find out itself. A path that does
        not exist raises ``context.error.missing``, one the user may not reach
        ``context.error.read``. A probe running as root may not call it: as root it would
        tell the time of any file without the explicit grant a root plugin needs.
        """
        if type(path) is not str or len(path) > MAX_ROW_PATH or not path.startswith("/"):
            raise context_error("context.error.path")
        if "\0" in path or path.startswith("//") or posixpath.normpath(path) != path:
            raise context_error("context.error.path")
        if _as_root():
            raise context_error("context.error.path")
        return self._file_mtime(path)

    def unix_get(self, path: str, target: str, max_bytes: int) -> bytes:
        """The body of ``GET target`` on the local socket ``path``, or ``ContextError``.

        ``path`` must lie below ``/run``; ``target`` is a fixed path of the module's
        (``unixhttp.TARGET``). The request shares the probe's deadline. As root the
        socket and the process behind it must be root's (``collect.unixhttp``).
        """
        _check_path(path, SOCKET_ROOTS)
        if not 0 < max_bytes <= MAX_BINARY_READ:
            raise context_error("context.error.socket")
        timeout = self.run_timeout
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - self.clock())
            if timeout < MIN_RUN_TIME:
                raise context_error("context.error.socket")
        return self._unix_get(path, target, max_bytes, timeout)

    def _unix_get(self, path: str, target: str, max_bytes: int, timeout: float) -> bytes:
        # Imported here: only the container module needs a socket, and ``motp show``
        # never imports this file (invariant 6).
        from motp.collect import unixhttp

        try:
            real, st = safepath.resolve(path)
            unixhttp.check_socket_file(st)
            return unixhttp.get(
                real, target, timeout=timeout, max_bytes=max_bytes, clock=self.clock
            )
        except (ContractError, unixhttp.UnixHttpError) as exc:
            raise context_error("context.error.socket") from exc

    def run(self, argv: Sequence[str], ok_codes: tuple[int, ...] = (0,)) -> bytes:
        """Start a listed program with its arguments; its stdout, or ``ContextError``.

        An exit code outside ``ok_codes``, a timeout and more than ``RUN_STDOUT_CAP``
        bytes of output are all failures.

        ``argv[0]`` must be one of the module's ``binaries`` exactly. The program is
        checked with ``safepath.check_program`` (as root, the stricter rules apply) and
        its real path is what gets executed. As root, a Python script is started only if
        every directory its interpreter imports from passes the same check
        (``core.importpath``); otherwise ``ImportPathError`` says which one failed and
        nothing runs.
        """
        args = tuple(argv)
        if not args or args[0] not in self.binaries:
            raise context_error("context.error.binary")
        timeout = self.run_timeout
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - self.clock())
            if timeout < MIN_RUN_TIME:
                raise context_error("context.error.run_failed")
        as_root = os.geteuid() == 0
        try:
            program = safepath.check_program(args[0], runs_as_root=as_root)
        except ContractError as exc:
            raise context_error("context.error.run_failed") from exc
        if as_root:
            try:
                importpath.check_program(program)
            except ContractError as exc:
                raise ImportPathError(exc.message) from exc
        try:
            spec = proc.Spec(
                argv=(program.path, *args[1:]),
                timeout=timeout,
                stdout_cap=RUN_STDOUT_CAP,
            )
            result = proc.run(spec)
        except ContractError as exc:
            raise context_error("context.error.run_failed") from exc
        if result.returncode not in ok_codes or result.timed_out or result.stdout_overflow:
            raise context_error("context.error.run_failed")
        return result.stdout

    @contextlib.contextmanager
    def scratch_dir(self) -> Iterator[str]:
        """A new directory only this probe's user can use, removed afterwards."""
        # Imported here: ``motp show`` never needs them (invariant 6).
        import shutil
        import tempfile

        try:
            path = tempfile.mkdtemp(prefix="motp-", dir=SCRATCH_ROOT)
        except OSError as exc:
            raise context_error("context.error.run_failed") from exc
        try:
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def file_size(self, path: str) -> int:
        """The size of a regular file below a read root, in bytes."""
        _check_path(path, self.read_roots)
        return self._file_size(path)

    def read_slice(self, path: str, offset: int, size: int) -> bytes:
        """Up to ``size`` bytes of a regular file from ``offset``; fewer at its end."""
        _check_path(path, self.read_roots)
        if type(offset) is not int or offset < 0 or not 0 < size <= MAX_BINARY_READ:
            raise context_error("context.error.read")
        return self._read_slice(path, offset, size)

    def data_regions(self, path: str, align: int, max_bytes: int) -> tuple[tuple[int, bytes], ...]:
        """The parts of a (sparse) file that hold data, as ``(offset, bytes)``.

        Each part is widened to whole multiples of ``align`` from the start of the file, so
        a record of that size is never cut; parts that then touch are joined. Holes are left
        out. More than ``max_bytes`` in all fails rather than dropping some.
        """
        _check_path(path, self.read_roots)
        if not 0 < align <= 65536 or not 0 < max_bytes <= MAX_BINARY_READ:
            raise context_error("context.error.read")
        return self._data_regions(path, align, max_bytes)

    def _open(self, path: str) -> int:
        """Open a regular file read-only; as root through the ownership check (above)."""
        if _as_root() and not path.startswith(KERNEL_ROOTS):
            try:
                fd, _trusted = safepath.open_trusted(path, group_writable=path in RECORD_FILES)
            except ContractError as exc:
                raise context_error("context.error.read") from exc
            return fd
        try:
            fd = os.open(path, _OPEN_FLAGS)
        except OSError as exc:
            raise context_error("context.error.read") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise context_error("context.error.read")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _file_size(self, path: str) -> int:
        fd = self._open(path)
        try:
            return os.fstat(fd).st_size
        finally:
            os.close(fd)

    def _read_slice(self, path: str, offset: int, size: int) -> bytes:
        fd = self._open(path)
        try:
            return _pread_all(fd, offset, size)
        except OSError as exc:
            raise context_error("context.error.read") from exc
        finally:
            os.close(fd)

    def _data_regions(self, path: str, align: int, max_bytes: int) -> tuple[tuple[int, bytes], ...]:
        fd = self._open(path)
        try:
            size = os.fstat(fd).st_size
            spans = _data_spans(fd, size, align)
            if sum(end - start for start, end in spans) > max_bytes:
                raise context_error("context.error.read")
            return tuple((start, _pread_all(fd, start, end - start)) for start, end in spans)
        except OSError as exc:
            raise context_error("context.error.read") from exc
        finally:
            os.close(fd)

    def _read_bytes(self, path: str, max_bytes: int) -> bytes:
        fd = self._open(path)
        try:
            chunks: list[bytes] = []
            size = 0
            while size < max_bytes:
                chunk = os.read(fd, max_bytes - size)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            return b"".join(chunks)
        except OSError as exc:
            raise context_error("context.error.read") from exc
        finally:
            os.close(fd)

    def _exists(self, path: str) -> bool:
        if not _checked_as_root(path):
            return os.path.exists(path)
        try:
            safepath.resolve(path, parent_group_writable=path in RECORD_FILES)
        except ContractError as exc:
            if exc.message.id == "safepath.error.missing":
                return False
            raise context_error("context.error.read") from exc
        return True

    def _list_dir(self, path: str) -> list[str]:
        if _checked_as_root(path):
            path = _trusted_directory(path)
        try:
            with os.scandir(path) as entries:
                names = []
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > MAX_DIR_ENTRIES:
                        break
                return names
        except OSError as exc:
            raise context_error("context.error.read") from exc

    def _mtime(self, path: str) -> int:
        if _checked_as_root(path):
            try:
                real, st = safepath.resolve(path, parent_group_writable=path in RECORD_FILES)
                safepath.check_owner_and_mode(real, st, group_writable=path in RECORD_FILES)
                return int(st.st_mtime)
            except ContractError as exc:
                raise context_error("context.error.read") from exc
            except (OverflowError, ValueError) as exc:
                raise context_error("context.error.read") from exc
        try:
            return int(os.stat(path).st_mtime)
        except (OSError, OverflowError, ValueError) as exc:
            raise context_error("context.error.read") from exc

    def _file_mtime(self, path: str) -> int:
        try:
            return int(os.stat(path).st_mtime)
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise context_error("context.error.missing") from exc
        except (OSError, OverflowError, ValueError) as exc:
            raise context_error("context.error.read") from exc

    def _statvfs(self, path: str) -> FsUsage:
        if _checked_as_root(path):
            try:
                path = safepath.check_directory(path)
            except ContractError as exc:
                raise context_error("context.error.statvfs") from exc
        try:
            st = os.statvfs(path)
        except OSError as exc:
            raise context_error("context.error.statvfs") from exc
        unit = st.f_frsize or st.f_bsize
        return FsUsage(
            size=st.f_blocks * unit,
            free=st.f_bfree * unit,
            available=st.f_bavail * unit,
            inodes=st.f_files,
            inodes_free=st.f_ffree,
            inodes_available=st.f_favail,
            fsid=getattr(st, "f_fsid", 0),
        )


def _as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _checked_as_root(path: str) -> bool:
    """Whether root must walk ``path`` through the ownership check (all but /proc, /sys)."""
    return _as_root() and not path.startswith(KERNEL_ROOTS) and path not in ("/proc", "/sys")


def _trusted_directory(path: str) -> str:
    try:
        return safepath.check_directory(path)
    except ContractError as exc:
        raise context_error("context.error.read") from exc


def _pread_all(fd: int, offset: int, size: int) -> bytes:
    chunks: list[bytes] = []
    done = 0
    while done < size:
        chunk = os.pread(fd, size - done, offset + done)
        if not chunk:
            break
        chunks.append(chunk)
        done += len(chunk)
    return b"".join(chunks)


MAX_SPANS = 65536  # a lastlog of directory accounts is many small islands of data


def _data_spans(fd: int, size: int, align: int) -> list[tuple[int, int]]:
    """``(start, end)`` of the parts of the file that hold data, widened to ``align``."""
    seek_data = getattr(os, "SEEK_DATA", None)
    seek_hole = getattr(os, "SEEK_HOLE", None)
    if size <= 0:
        return []
    if seek_data is None or seek_hole is None:
        return [(0, size)]
    spans: list[tuple[int, int]] = []
    offset = 0
    while offset < size:
        try:
            start = os.lseek(fd, offset, seek_data)
        except OSError as exc:
            if exc.errno == errno.ENXIO:  # nothing but a hole after offset
                break
            if exc.errno == errno.EINVAL:  # the file system cannot tell: read it all
                return [(0, size)]
            raise
        end = min(os.lseek(fd, start, seek_hole), size)
        if end <= start:
            break
        low = start - start % align
        high = min(size, -(-end // align) * align)
        if spans and low <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], high))
        else:
            spans.append((low, high))
        if len(spans) > MAX_SPANS:
            raise context_error("context.error.read")
        offset = end
    return spans


def read_os_release(ctx: Context) -> dict[str, str]:
    """``os-release`` as a mapping: ``/etc/os-release``, else ``/usr/lib/os-release``."""
    for path in OS_RELEASE_FILES:
        try:
            return parse_os_release(ctx.read_text(path, MAX_READ))
        except ValueError:
            continue
    return {}

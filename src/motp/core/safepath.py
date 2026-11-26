"""Ownership-chain checks (blueprint 4.7, 4.8, 4.9, threats T1, T17, T21).

A file that root reads or executes is trusted only if it, and every directory from ``/``
down to it, belongs to root and is not writable by group or others. A file that fails the
check is refused with a reason an admin can act on (a ``MessageRef`` naming the path).

How a path is walked:

* The path must be absolute. It is resolved one component at a time with ``lstat``, from
  ``/`` down, and each directory is checked *before* anything inside it is looked at.
* A symbolic link is followed only if it belongs to root; it then sits in a directory that
  already passed the check, so only root can have placed or changed it. Its target is
  walked by the same rules. That keeps ``/bin -> usr/bin`` working and refuses a link that
  leads through a directory someone else can write.
* The result is the real path: no link in it, every directory in it checked. Only that
  path is opened or executed, so a link cannot be swapped between check and use.

Why the mode bits are enough (review notes):

* POSIX ACLs: with an extended ACL, the group bits of the mode hold the ACL mask, and no
  named user or group entry can grant write access the mask does not. A file whose ACL
  lets anyone but its owner write therefore shows the group write bit and is refused.
* Hard links: a link to a root-owned file shares its owner and mode, so nobody but root
  can change the content through any name. A user can only add a name for it in a
  directory they can write, and such a directory fails the check.
* Not covered: file systems that report owners they do not enforce (some network and
  FUSE mounts), bind mounts set up by root, and anyone who already has root.

Reading a ``#!`` line follows the kernel: the interpreter is the first word, the rest of
the line is one optional argument. The line must end within 128 bytes, the buffer of
kernels before 5.1, which cut a longer line silently (so what was checked would not be what
runs); a file shorter than that without a line end is one line, as the kernel reads it. The
interpreter goes through the same check, recursively (a script as interpreter) up to the
kernel's depth. Executables with the setuid or setgid bit are refused: they would undo the
privilege drop of the runner.

For a program that will run as root (T21) three more rules apply. Its interpreter may not
be a launcher that looks its argument up in ``PATH`` (``env``, ``nice``, ``timeout``, ...),
by the name on the line or by the real path; a word after the interpreter that is not an
option or an absolute path is refused too, since that is how a launcher gets its program.
And a file without ``#!`` must be an ELF binary, so that no ``binfmt_misc`` handler outside
the checked chain decides how it runs. The launcher list is a heuristic; the real
protection is that ``PATH`` itself holds only trusted directories (checked by the
collector, phase 6).
"""

import os
import stat
from dataclasses import dataclass, replace
from typing import Optional

from motp.core.model import ContractError, contract_error

MAX_LINK_HOPS = 40  # the kernel's limit for one lookup
MAX_SHEBANG_BYTES = 128  # BINPRM_BUF_SIZE before Linux 5.1; 256 since, so 128 fits both
MAX_INTERPRETER_DEPTH = 4  # the kernel's limit for nested interpreters
MAX_PATH_BYTES = 4096
TRUSTED_UID = 0
WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH
ANY_EXECUTE = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
ELF_MAGIC = b"\x7fELF"
# Programs that run their argument after a PATH lookup (heuristic; see the docstring).
LAUNCHERS = frozenset(
    {
        "env", "nice", "ionice", "chrt", "taskset", "timeout", "stdbuf", "nohup", "setsid",
        "flock", "xargs", "sudo", "doas", "su", "runuser", "setpriv", "unshare", "nsenter",
        "chroot", "time", "busybox", "coreutils", "toybox", "systemd-run", "watch", "strace",
    }
)  # fmt: skip


class UnsafePath(ContractError):
    """A path failed the ownership check. ``message`` names the path and the reason."""


def _fail(msg_id: str, path: str) -> UnsafePath:
    return UnsafePath(contract_error(msg_id, path=path).message)


@dataclass(frozen=True)
class TrustedFile:
    """A file that passed the check. ``path`` is its real path; ``dev`` and ``ino`` let a
    caller confirm that the file it opens is the one that was checked."""

    path: str
    dev: int
    ino: int
    mode: int
    size: int


@dataclass(frozen=True)
class Program:
    """An executable that passed the check, with its interpreter chain if it is a script.

    ``path`` is the real path to execute. ``interpreter`` is the checked interpreter named
    on the ``#!`` line, ``interpreter_arg`` the optional argument after it.
    """

    file: TrustedFile
    interpreter: Optional["Program"] = None
    interpreter_arg: Optional[str] = None
    # The name the parent's #! line used, before links were resolved (``None`` for the
    # program itself): a Python venv is found next to this name, not the real path.
    named: Optional[str] = None

    @property
    def path(self) -> str:
        return self.file.path


def _supported() -> bool:
    return os.name == "posix" and hasattr(os, "geteuid")


def _check_owner_and_mode(
    path: str, st: os.stat_result, writable: int = WRITABLE_BY_OTHERS
) -> None:
    if st.st_uid != TRUSTED_UID:
        raise _fail("safepath.error.owner", path)
    if st.st_mode & writable:
        raise _fail("safepath.error.writable", path)


def _lstat(path: str) -> os.stat_result:
    try:
        return os.lstat(path)
    except FileNotFoundError as exc:
        raise _fail("safepath.error.missing", path) from exc
    except OSError as exc:
        raise _fail("safepath.error.unreadable", path) from exc


def _components(path: str) -> list[str]:
    return [part for part in path.split("/") if part not in ("", ".")]


def resolve(path: str, parent_group_writable: bool = False) -> tuple[str, os.stat_result]:
    """Walk ``path`` from ``/`` and return its real path and ``lstat`` result.

    Every directory on the way, including those reached through links, must belong to root
    and must not be writable by group or others; every link must belong to root. The final
    component itself is not checked here (callers check it for what they expect).

    ``parent_group_writable`` lets the directory that holds the final component be
    writable by its group (never by others): Ubuntu with rsyslog keeps ``/var/log`` as
    0775 ``root:syslog``. See ``check_file`` for what that admits.
    """
    if len(path.encode("utf-8", "replace")) > MAX_PATH_BYTES:
        raise _fail("safepath.error.too_long", path[:200])
    if "\x00" in path:
        raise _fail("safepath.error.not_absolute", path[:200])
    if not path.startswith("/"):
        raise _fail("safepath.error.not_absolute", path)
    if not _supported():
        raise _fail("safepath.error.unsupported", path)

    root_st = _lstat("/")
    _check_owner_and_mode("/", root_st)
    current = "/"  # always a real, checked directory
    current_st = root_st
    pending = _components(path)
    hops = 0
    while pending:
        name = pending.pop(0)
        if name == "..":
            # The parent of a checked real directory is on its own checked chain.
            current = os.path.dirname(current) or "/"
            current_st = _lstat(current)
            continue
        candidate = os.path.join(current, name)
        st = _lstat(candidate)
        if stat.S_ISLNK(st.st_mode):
            if st.st_uid != TRUSTED_UID:
                raise _fail("safepath.error.link_owner", candidate)
            hops += 1
            if hops > MAX_LINK_HOPS:
                raise _fail("safepath.error.too_many_links", path)
            try:
                target = os.readlink(candidate)
            except OSError as exc:
                raise _fail("safepath.error.unreadable", candidate) from exc
            if target.startswith("/"):
                current, current_st = "/", root_st
            pending[:0] = _components(target)
            continue
        if not pending:
            return candidate, st
        if not stat.S_ISDIR(st.st_mode):
            raise _fail("safepath.error.not_directory", candidate)
        holds_final = parent_group_writable and len(pending) == 1 and pending[0] != ".."
        _check_owner_and_mode(candidate, st, _writable(holds_final))
        current, current_st = candidate, st
    # The path named a directory (``/`` or one ending in ``..``).
    return current, current_st


def check_directory(path: str) -> str:
    """Check a directory and its chain; return its real path."""
    real, st = resolve(path)
    if not stat.S_ISDIR(st.st_mode):
        raise _fail("safepath.error.not_directory", real)
    _check_owner_and_mode(real, st)
    return real


def check_file(path: str, executable: bool = False, group_writable: bool = False) -> TrustedFile:
    """Check a regular file and its chain; with ``executable``, also an execute bit.

    ``group_writable`` accepts a file that its group may write, for records the system
    keeps writable by a service group (``wtmp`` and ``lastlog`` belong to ``utmp``, mode
    0664), in a directory its group may write (``/var/log`` is 0775 ``root:syslog`` on
    Ubuntu). Such a file is read as untrusted data, never executed or used as config. The
    directories above that one pass the full check, the file must still be root's and a
    link is followed only where root owns it, so a member of those groups cannot point the
    name at a file of their own or at a link; with ``fs.protected_hardlinks`` (the default
    everywhere) they cannot link a file from elsewhere in either. What remains: a member of
    the directory's group can rename another root-owned file of that same directory to
    the name (decision log, phase 10).
    """
    real, st = resolve(path, parent_group_writable=group_writable)
    if not stat.S_ISREG(st.st_mode):
        raise _fail("safepath.error.not_regular", real)
    _check_owner_and_mode(real, st, _writable(group_writable))
    if executable and not st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise _fail("safepath.error.not_executable", real)
    return TrustedFile(real, st.st_dev, st.st_ino, st.st_mode, st.st_size)


def check_owner_and_mode(path: str, st: os.stat_result, group_writable: bool = False) -> None:
    """Root's, and not writable by others (nor by its group unless ``group_writable``)."""
    _check_owner_and_mode(path, st, _writable(group_writable))


def _writable(group_writable: bool) -> int:
    return stat.S_IWOTH if group_writable else WRITABLE_BY_OTHERS


def open_trusted(path: str, group_writable: bool = False) -> tuple[int, TrustedFile]:
    """Check ``path``, open its real path read-only, and confirm it is the checked file.

    The file is opened without following a link and without blocking, and its descriptor
    is compared with the checked ``lstat`` result (device, inode, owner, mode). The caller
    closes the returned descriptor. ``group_writable`` as for ``check_file``.
    """
    trusted = check_file(path, group_writable=group_writable)
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_NOCTTY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(trusted.path, flags)
    except OSError as exc:
        raise _fail("safepath.error.unreadable", trusted.path) from exc
    try:
        st = os.fstat(fd)
        same = (st.st_dev, st.st_ino) == (trusted.dev, trusted.ino)
        if not same or not stat.S_ISREG(st.st_mode):
            raise _fail("safepath.error.changed", trusted.path)
        _check_owner_and_mode(trusted.path, st, _writable(group_writable))
    except BaseException:
        os.close(fd)
        raise
    return fd, trusted


def read_trusted(path: str, max_bytes: int) -> tuple[bytes, TrustedFile]:
    """Read a checked file, at most ``max_bytes``; a larger file is refused."""
    fd, trusted = open_trusted(path)
    try:
        chunks: list[bytes] = []
        size = 0
        while size <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise _fail("safepath.error.unreadable", trusted.path) from exc
    finally:
        os.close(fd)
    if size > max_bytes:
        raise _fail("safepath.error.too_large", trusted.path)
    return b"".join(chunks), trusted


def parse_shebang(head: bytes, path: str) -> Optional[tuple[str, Optional[str]]]:
    """Split the ``#!`` line at the start of ``head`` like the kernel does.

    Returns ``None`` when ``head`` does not start with ``#!``, else the interpreter and the
    optional single argument (the rest of the line, outer blanks removed).
    """
    if not head.startswith(b"#!"):
        return None
    head = head[:MAX_SHEBANG_BYTES]
    end = head.find(b"\n")
    if end == -1:
        if len(head) >= MAX_SHEBANG_BYTES:
            raise _fail("safepath.error.shebang_too_long", path)
        end = len(head)  # the whole (short) file is the line
    line = head[2:end].strip(b" \t")
    if not line:
        raise _fail("safepath.error.shebang_empty", path)
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail("safepath.error.shebang_encoding", path) from exc
    if "\x00" in text:
        raise _fail("safepath.error.shebang_encoding", path)
    for i, ch in enumerate(text):
        if ch in " \t":
            arg = text[i:].strip(" \t")
            return text[:i], arg or None
    return text, None


def _is_launcher(name: str) -> bool:
    return os.path.basename(name) in LAUNCHERS


def _read_head(fd: int, path: str) -> bytes:
    """The first ``MAX_SHEBANG_BYTES`` bytes, or fewer if the file is shorter."""
    chunks: list[bytes] = []
    size = 0
    try:
        while size < MAX_SHEBANG_BYTES:
            chunk = os.read(fd, MAX_SHEBANG_BYTES - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise _fail("safepath.error.unreadable", path) from exc
    return b"".join(chunks)


def check_program(
    path: str, runs_as_root: bool, _depth: int = 0, known_format: bool = False
) -> Program:
    """Check an executable and, if it is a script, its interpreter chain.

    Always: the ownership chain, an execute bit, no setuid or setgid bit, a well-formed
    ``#!`` line. With ``runs_as_root`` also: no launcher that searches ``PATH`` as the
    interpreter, no bare program name as its argument, and ELF or ``#!`` only.
    ``known_format`` asks for ELF or ``#!`` without root too (exec plugins, phase 12):
    a file the kernel hands to a ``binfmt_misc`` handler is run by a program nobody checked.
    """
    fd, trusted = open_trusted(path)
    try:
        if not trusted.mode & ANY_EXECUTE:
            raise _fail("safepath.error.not_executable", trusted.path)
        if trusted.mode & (stat.S_ISUID | stat.S_ISGID):
            raise _fail("safepath.error.setid", trusted.path)
        head = _read_head(fd, trusted.path)
    finally:
        os.close(fd)
    parsed = parse_shebang(head, trusted.path)
    if parsed is None:
        if (runs_as_root or known_format) and not head.startswith(ELF_MAGIC):
            raise _fail("safepath.error.unknown_format", trusted.path)
        return Program(trusted)
    name, arg = parsed
    if _depth + 1 > MAX_INTERPRETER_DEPTH:
        raise _fail("safepath.error.interpreter_depth", trusted.path)
    if not name.startswith("/"):
        raise _fail("safepath.error.interpreter_relative", trusted.path)
    if runs_as_root and (_is_launcher(name) or (arg is not None and arg[0] not in "-/")):
        raise _fail("safepath.error.launcher_as_root", trusted.path)
    if known_format and _depth == 0 and arg is not None:
        # A plugin's own line: its argument can name code too, a script for the
        # interpreter to run instead (``#!/usr/bin/perl /srv/x.pl``) or a search path or
        # setting inside an option (``-I/tmp``, ``-X pycache_prefix=...``). An absolute
        # path must pass the same check; any other ``/`` or ``=`` is refused (phase 12
        # security review). Lines further down the chain are the system's own files
        # (AlmaLinux's ``env`` is ``#!/usr/bin/coreutils --coreutils-prog-shebang=env``).
        if arg.startswith("/"):
            check_file(arg)
        elif "/" in arg or "=" in arg:
            raise _fail("safepath.error.shebang_argument", trusted.path)
    interpreter = check_program(name, runs_as_root, _depth + 1, known_format=known_format)
    if runs_as_root and _is_launcher(interpreter.path):
        raise _fail("safepath.error.launcher_as_root", trusted.path)
    return Program(trusted, replace(interpreter, named=name), arg)

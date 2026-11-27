"""Directories, atomic file writes, the run lock and the state file (blueprint 4.1, 4.4, T12, T19).

Layout and modes (4.1, D32 as amended):

* ``/run/motp``            0755 root:root   the cache directory
* ``/run/motp/user``       0711 root:root   per-user files; nobody can list it
* ``/run/motp/user/<uid>.json`` 0400 root:root plus the ACL entry ``user:<uid>:r``: only
  that user (and root) can read it, and nobody but root can change it or its mode
* ``/run/motp/collect.lock`` 0600 root:root keeps two runs from overlapping
* ``/var/lib/motp``        0700 root:root   the state directory
* ``/var/lib/motp/state.json`` 0600 root:root the last good items of every module

A directory is created if it is missing. An existing one must be a real directory (not a
link) that belongs to root and that no group or other user can write; its mode is then set
as above through its open descriptor. Anything else is refused, never repaired. Its parent
chain must pass the ownership check, so no other user can swap it.

Every file is written to a fresh temporary name in its directory (``O_CREAT | O_EXCL |
O_NOFOLLOW``, mode 0600), gets its owner, group and mode on the open descriptor, is synced,
and is then renamed over the old name. A link or a file planted at the final name is
replaced, never followed. Readers therefore see the old file or the new one, never a part.
"""

import contextlib
import errno
import os
import stat
import struct
from dataclasses import dataclass, replace
from typing import Optional

from motp.core import cache, safepath, strictjson
from motp.core.model import ContractError, ModuleResult, UserLogins, contract_error

CACHE_DIR = "/run/motp"
STATE_DIR = "/var/lib/motp"
USER_DIR = "user"
LOCK_NAME = "collect.lock"
STATE_NAME = "state.json"
PUBLIC_NAME = "public.json"
ADMIN_NAME = "admin.json"
RENDER_NAME = "render.json"
# Static mode (4.10, D7): the rendered public text for pam_motd.
MOTD_DIR = "/run/motd.d"
MOTD_NAME = "10-motp"
MOTD_MODE = 0o644
MOTD_DIR_MODE = 0o755

CACHE_DIR_MODE = 0o755
USER_DIR_MODE = 0o711
STATE_DIR_MODE = 0o700
PUBLIC_MODE = 0o644
ADMIN_MODE = 0o640
RENDER_MODE = 0o644
USER_FILE_MODE = 0o400
STATE_MODE = 0o600
LOCK_MODE = 0o600
ROOT = 0

# POSIX ACLs as the kernel takes them in the extended attribute (``acl_ea_header`` and
# ``acl_ea_entry`` of the kernel's ``posix_acl_xattr.h``): a version, then entries of tag,
# permission and id, sorted by tag.
ACL_XATTR = "system.posix_acl_access"
ACL_VERSION = 2
ACL_USER_OBJ = 0x01
ACL_USER = 0x02
ACL_GROUP_OBJ = 0x04
ACL_MASK = 0x10
ACL_OTHER = 0x20
ACL_READ = 0x04
ACL_NO_ID = 0xFFFFFFFF
# With the entry, the group bits of the mode show the ACL mask (read).
USER_FILE_SHOWN_MODE = 0o440
_ACL_ENTRY = struct.Struct("<HHI")
_UNSUPPORTED = {errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)}

STATE_SCHEMA = 1
MAX_STATE_BYTES = 1024 * 1024
STATE_DEPTH = cache.MAX_DEPTH + 1
STATE_HEADROOM_BYTES = 4096

_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_DIR_FLAGS |= getattr(os, "O_CLOEXEC", 0)
_NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
_NEW_FILE_FLAGS |= getattr(os, "O_CLOEXEC", 0)


class StoreError(ContractError):
    """A directory or file of the cache or the state cannot be used safely."""


class AclUnsupported(StoreError):
    """The file system under ``/run/motp`` refuses POSIX ACLs (D32: then no per-user file)."""


def _fail(msg_id: str, path: str) -> StoreError:
    return StoreError(contract_error(msg_id, path=path).message)


def _adopt(fd: int, mode: int, shown: str, keep_stricter: bool = False) -> int:
    """Accept an open directory only if root owns it and no group or other user can write
    to it (someone could have planted files meanwhile); then set its mode.

    With ``keep_stricter`` (the config tree, final review security item 4) an existing
    directory keeps every permission bit it lacks: the result is its mode and ``mode``
    combined, so an admin's ``0711`` or ``0700`` stays, and bits beyond ``mode`` still go.
    """
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != ROOT or st.st_mode & 0o022:
            raise _fail("collect.error.unsafe_dir", shown)
        os.fchmod(fd, (stat.S_IMODE(st.st_mode) & mode) if keep_stricter else mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def prepare_dir(path: str, mode: int, keep_stricter: bool = False) -> int:
    """Create or adopt a root-owned directory with ``mode``; return an open descriptor.

    The parent chain must pass the ownership check. An existing entry must be a directory
    that root owns, that is not a link and that only root can write; anything else is
    refused, never repaired. ``keep_stricter``: see ``_adopt``.
    """
    parent = os.path.dirname(path.rstrip("/")) or "/"
    try:
        parent_real = safepath.check_directory(parent)
    except ContractError as exc:
        raise _fail("collect.error.unsafe_dir", parent) from exc
    target = os.path.join(parent_real, os.path.basename(path.rstrip("/")))
    existed = False
    try:
        os.mkdir(target, 0o700)  # the umask cannot widen it; the mode is set below
    except FileExistsError:
        existed = True
    except OSError as exc:
        raise _fail("collect.error.unsafe_dir", target) from exc
    try:
        fd = os.open(target, _DIR_FLAGS)
    except OSError as exc:
        raise _fail("collect.error.unsafe_dir", target) from exc
    # Only an existing directory keeps a stricter mode: a new one was made 0700 above,
    # and that is this function's own placeholder, not an admin's choice.
    return _adopt(fd, mode, target, keep_stricter and existed)


def open_shared_dir(path: str, mode: int) -> int:
    """Open a directory that other programs share (``/run/motd.d``), creating it with
    ``mode`` when it is missing. An existing one must be a real directory of root that no
    group or other user can write; unlike ``prepare_dir`` its mode is left as it is, since
    the directory is not MOTP's."""
    parent = os.path.dirname(path.rstrip("/")) or "/"
    try:
        parent_real = safepath.check_directory(parent)
    except ContractError as exc:
        raise _fail("collect.error.unsafe_dir", parent) from exc
    target = os.path.join(parent_real, os.path.basename(path.rstrip("/")))
    created = False
    try:
        os.mkdir(target, 0o700)
        created = True
    except FileExistsError:
        pass
    except OSError as exc:
        raise _fail("collect.error.unsafe_dir", target) from exc
    try:
        fd = os.open(target, _DIR_FLAGS)
    except OSError as exc:
        raise _fail("collect.error.unsafe_dir", target) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != ROOT or st.st_mode & 0o022:
            raise _fail("collect.error.unsafe_dir", target)
        if created:
            os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def subdir(dir_fd: int, name: str, mode: int, shown: str, keep_stricter: bool = False) -> int:
    """Create or adopt ``name`` inside an open root directory, like ``prepare_dir``."""
    existed = False
    try:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
    except FileExistsError:
        existed = True
    except OSError as exc:
        raise _fail("collect.error.unsafe_dir", shown) from exc
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise _fail("collect.error.unsafe_dir", shown) from exc
    return _adopt(fd, mode, shown, keep_stricter and existed)


def reader_acl(uid: int) -> bytes:
    """The ACL ``user::r, user:<uid>:r, group::-, mask::r, other::-`` as the xattr value."""
    if type(uid) is not int or not 0 <= uid < ACL_NO_ID:
        raise contract_error("cache.error.schema", field="uid")
    entries = (
        (ACL_USER_OBJ, ACL_READ, ACL_NO_ID),
        (ACL_USER, ACL_READ, uid),
        (ACL_GROUP_OBJ, 0, ACL_NO_ID),
        (ACL_MASK, ACL_READ, ACL_NO_ID),
        (ACL_OTHER, 0, ACL_NO_ID),
    )
    return struct.pack("<I", ACL_VERSION) + b"".join(_ACL_ENTRY.pack(*e) for e in entries)


def _unsupported() -> AclUnsupported:
    return AclUnsupported(contract_error("collect.error.user_acl").message)


def _grant_reader(fd: int, uid: int, name: str) -> None:
    """Give ``uid`` read access to the open file, and check that exactly that took effect.

    A file system without POSIX ACLs raises ``AclUnsupported``; anything that reads back
    differently fails as well, so a file is never left readable by more than intended.
    """
    acl = reader_acl(uid)
    setxattr = getattr(os, "setxattr", None)
    getxattr = getattr(os, "getxattr", None)
    if setxattr is None or getxattr is None:
        raise _unsupported()
    try:
        setxattr(fd, ACL_XATTR, acl)
        back = getxattr(fd, ACL_XATTR)
        st = os.fstat(fd)
    except OSError as exc:
        if exc.errno in _UNSUPPORTED:
            raise _unsupported() from exc
        raise _fail("collect.error.write", name) from exc
    if back != acl or stat.S_IMODE(st.st_mode) != USER_FILE_SHOWN_MODE or st.st_uid != ROOT:
        raise _fail("collect.error.write", name)


def write_atomic(
    dir_fd: int,
    name: str,
    data: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    sync_dir: bool = False,
    reader: Optional[int] = None,
) -> None:
    """Write ``name`` in the open directory through a temporary file and a rename.

    With ``reader``, that one user also gets read access through a POSIX ACL entry, set
    and checked on the open file before it gets its name (D32).
    """
    tmp = f".{name}.{os.getpid()}.{os.urandom(6).hex()}.tmp"
    try:
        fd = os.open(tmp, _NEW_FILE_FLAGS, 0o600, dir_fd=dir_fd)
    except OSError as exc:
        raise _fail("collect.error.write", name) from exc
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            if reader is not None:
                _grant_reader(fd, reader, name)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)
        if isinstance(exc, OSError):
            raise _fail("collect.error.write", name) from exc
        raise
    if sync_dir:
        # Some file systems cannot sync a directory; the rename stands either way.
        with contextlib.suppress(OSError):
            os.fsync(dir_fd)


def remove(dir_fd: int, name: str) -> None:
    """Remove ``name`` from the open directory if it is there (a link is removed itself)."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise _fail("collect.error.write", name) from exc


# --- the lock -------------------------------------------------------------------------


def acquire_lock(dir_fd: int) -> Optional[int]:
    """Take the run lock (``flock``) in the cache directory without waiting.

    Returns the open lock file, which holds the lock until it is closed, or ``None`` if
    another run holds it. The lock file must be a regular file of root.
    """
    import fcntl

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(LOCK_NAME, flags, LOCK_MODE, dir_fd=dir_fd)
    except OSError as exc:
        raise _fail("collect.error.lock", LOCK_NAME) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != ROOT or st.st_mode & 0o077:
            raise _fail("collect.error.lock", LOCK_NAME)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    except BaseException:
        os.close(fd)
        raise
    return fd


# --- the state file -------------------------------------------------------------------


@dataclass(frozen=True)
class Entry:
    """What the state keeps of one module: when it last ran, and its last result.

    ``result`` holds the last good items with the time they were collected; its state
    and error describe the last run.
    """

    attempted: int
    result: ModuleResult


def encode_state(generated: int, entries: "dict[str, Entry]") -> bytes:
    """The state file, never larger than ``read_state`` accepts.

    If the entries would exceed ``MAX_STATE_BYTES``, the largest ones lose their items
    one by one (their attempt time stays), like the tier files shrink; a state the
    reader refused would make every module run every time and lose every last good item.
    """
    encoded = {
        name: {"attempted": e.attempted, "result": cache.module_json(e.result)}
        for name, e in sorted(entries.items())
    }
    sizes = {name: len(strictjson.dumps(entry)) for name, entry in encoded.items()}
    emptied: set[str] = set()
    while sum(sizes.values()) > MAX_STATE_BYTES - STATE_HEADROOM_BYTES:
        candidates = [n for n in sizes if n not in emptied]
        if not candidates:
            break
        name = max(candidates, key=lambda n: (sizes[n], n))
        bare = replace(entries[name].result, items=())
        encoded[name] = {"attempted": entries[name].attempted, "result": cache.module_json(bare)}
        sizes[name] = len(strictjson.dumps(encoded[name]))
        emptied.add(name)
    return strictjson.dumps({"schema": STATE_SCHEMA, "generated": generated, "modules": encoded})


def decode_state(data: bytes) -> "dict[str, Entry]":
    """Parse the state file; a broken module entry is dropped, a broken file raises."""
    obj = strictjson.loads(data, max_bytes=MAX_STATE_BYTES, max_depth=STATE_DEPTH)
    if (
        not isinstance(obj, dict)
        or obj.get("schema") != STATE_SCHEMA
        or not isinstance(obj.get("modules"), dict)
    ):
        raise contract_error("cache.error.schema", field="state")
    modules = obj["modules"]
    if len(modules) > cache.MAX_MODULES:
        raise contract_error("cache.error.schema", field="state.modules")
    entries: dict[str, Entry] = {}
    for name, raw in modules.items():
        if not isinstance(raw, dict) or set(raw) != {"attempted", "result"}:
            continue
        attempted = raw["attempted"]
        if type(attempted) is not int or not 0 <= attempted <= cache.MAX_TIMESTAMP:
            continue
        try:
            entries[name] = Entry(attempted, cache.decode_module(raw["result"], name))
        except ContractError:
            continue
    return entries


def read_state(dir_fd: int) -> "dict[str, Entry]":
    """The state, or an empty one if the file is missing or broken."""
    path = f"/proc/self/fd/{dir_fd}/{STATE_NAME}"
    try:
        return decode_state(cache.read_bounded(path, MAX_STATE_BYTES, ROOT))
    except ContractError:
        return {}


# --- per-user files -------------------------------------------------------------------


def user_file_name(uid: int) -> str:
    if type(uid) is not int or not 0 <= uid < 2**32:
        raise contract_error("cache.error.schema", field="uid")
    return f"{uid}.json"


def write_user_file(user_fd: int, logins: UserLogins) -> None:
    """``user/<uid>.json``: root's, mode 0400, with one ACL entry that lets that user read
    it, in the root-owned ``user`` directory nobody else can list (D32 as amended).

    The user cannot change the file's mode or content: they do not own it. Where the file
    system refuses the ACL, ``AclUnsupported`` is raised and no file is left behind.
    """
    write_atomic(
        user_fd,
        user_file_name(logins.uid),
        cache.encode_user_file(logins),
        mode=USER_FILE_MODE,
        uid=ROOT,
        gid=ROOT,
        reader=logins.uid,
    )


def prune_user_files(user_fd: int, keep: "set[str]") -> int:
    """Remove every entry of ``user/`` whose name is not in ``keep``: files of accounts
    that no longer get one (removed accounts, logins too old) and leftovers. Only root
    can write the directory, so anything else there is the collector's own. Returns how
    many were removed; one that cannot be removed (a directory) is left."""
    removed = 0
    try:
        names = os.listdir(user_fd)
    except OSError as exc:
        raise _fail("collect.error.write", USER_DIR) from exc
    for name in names:
        if name in keep:
            continue
        try:
            os.unlink(name, dir_fd=user_fd)
            removed += 1
        except FileNotFoundError:
            pass
        except OSError:
            continue
    return removed

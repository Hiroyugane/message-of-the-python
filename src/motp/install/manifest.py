"""The install manifest and the only way the uninstaller removes anything (4.12, T25).

``/var/lib/motp/install-manifest.json`` (0600, root) records every path the installer
created, with its kind and, for files, the SHA-256 of the content it wrote; the accounts
it created; the admin group it chose; and the scheduler it set up.

Removal follows four rules, so a tampered or stale manifest cannot delete other files:

1. **Fixed prefixes.** A path is removed only if it is one of the installer's exact paths
   (units, cron entry, the ``/usr/local/bin`` link) or lies inside one of its trees
   (``/opt/motp``, ``/etc/motp``, and the state and cache directories). The path must be
   absolute and normalised: no ``..``, no ``.``, no doubled slash, no NUL.
2. **Never through a link.** The path is walked from ``/`` one directory at a time with
   ``O_NOFOLLOW``; a link anywhere on the way stops the removal of that entry. The last
   component is looked at with ``lstat`` and removed relative to its open parent.
3. **Unchanged content.** A file is removed only if it is still a regular file with the
   recorded hash; a link only if it is still a link with the recorded target; a directory
   only if it is empty; a block (lines the installer added to a system file, phase 8: the
   zsh hook in ``zprofile``) only if the file still holds it between its marker lines with
   the recorded hash, and then only those lines go. Anything else is reported and left.
4. **Roles.** ``program`` entries go with ``uninstall``; ``config`` entries only with
   ``--purge``, and then by the same rules.
"""

import hashlib
import os
import posixpath
import stat
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Optional

from motp.core import strictjson
from motp.core.model import ContractError, MessageRef, contract_error

SCHEMA = 1
NAME = "install-manifest.json"
MODE = 0o600
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 5
MAX_ENTRIES = 4096
MAX_HASH_BYTES = 64 * 1024 * 1024
KINDS = ("file", "dir", "link", "block")
MODES = ("hybrid", "static")
BLOCK_BEGIN = b"# BEGIN motp:"
BLOCK_END = b"# END motp\n"
MAX_BLOCK_FILE_BYTES = 1024 * 1024
ROLES = ("program", "config")
SCHEDULERS = ("systemd", "cron", "none")
PATH_MAX = 4096
NAME_MAX = 64  # account and group names
ACCOUNT_NAMES = ("motp", "motp-plugin")  # the only accounts the installer creates

_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_DIR_FLAGS |= getattr(os, "O_CLOEXEC", 0)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_READ_FLAGS |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)


class ManifestError(ContractError):
    """The manifest cannot be read or is not one the installer wrote."""


@dataclass(frozen=True)
class Entry:
    """One path the installer created."""

    path: str
    kind: str  # "file", "dir", "link" or "block"
    role: str = "program"  # "program" or "config"
    sha256: str = ""  # files and blocks
    target: str = ""  # links only


@dataclass(frozen=True)
class Account:
    """A system account the installer created, with the ids it got."""

    name: str
    uid: int
    gid: int


@dataclass(frozen=True)
class Manifest:
    version: str
    entries: tuple[Entry, ...] = ()
    accounts: tuple[Account, ...] = ()
    admin_group: str = ""
    scheduler: str = "none"
    mode: str = "hybrid"

    def account(self, name: str) -> Optional[Account]:
        for acc in self.accounts:
            if acc.name == name:
                return acc
        return None


@dataclass(frozen=True)
class Scope:
    """Where removal is allowed: exact paths and whole trees (rule 1)."""

    exact: tuple[str, ...]
    trees: tuple[str, ...]
    # The one kind an exact path may have, where it is fixed: a system zprofile only ever
    # gets a block, never a removal as a whole file (phase 8 security review, T25).
    kinds: tuple[tuple[str, str], ...] = ()

    def allows(self, path: str, kind: Optional[str] = None) -> bool:
        if not is_clean_path(path):
            return False
        if path in self.exact:
            fixed = dict(self.kinds).get(path)
            return fixed is None or kind is None or kind == fixed
        if kind == "block":
            return False  # blocks live in the exact system files only
        return any(path == tree or path.startswith(tree + "/") for tree in self.trees)


@dataclass
class Removal:
    """What a removal did: removed paths, and paths left with the reason."""

    removed: list[str] = field(default_factory=list)
    left: list[tuple[str, MessageRef]] = field(default_factory=list)


def is_clean_path(path: str) -> bool:
    """Absolute, normalised, not the root itself, no NUL, within ``PATH_MAX``."""
    return (
        isinstance(path, str)
        and path.startswith("/")
        and path != "/"
        and "\x00" not in path
        and len(path.encode("utf-8", "surrogateescape")) <= PATH_MAX
        and posixpath.normpath(path) == path
        and "//" not in path
    )


# --- encoding -------------------------------------------------------------------------


def encode(m: Manifest) -> bytes:
    entries = []
    for e in m.entries:
        item: dict[str, object] = {"path": e.path, "kind": e.kind, "role": e.role}
        if e.kind in ("file", "block"):
            item["sha256"] = e.sha256
        if e.kind == "link":
            item["target"] = e.target
        entries.append(item)
    doc = {
        "schema": SCHEMA,
        "version": m.version,
        "admin_group": m.admin_group,
        "scheduler": m.scheduler,
        "mode": m.mode,
        "accounts": [{"name": a.name, "uid": a.uid, "gid": a.gid} for a in m.accounts],
        "entries": entries,
    }
    return strictjson.dumps(doc)


def _bad() -> ManifestError:
    return ManifestError(contract_error("install.error.manifest").message)


def _text(obj: dict[str, object], key: str, limit: int = PATH_MAX) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or len(value) > limit or "\x00" in value:
        raise _bad()
    return value


def _decode_entry(raw: object) -> Entry:
    if not isinstance(raw, dict):
        raise _bad()
    kind, role = _text(raw, "kind"), _text(raw, "role")
    if kind not in KINDS or role not in ROLES:
        raise _bad()
    path = _text(raw, "path")
    hashed = kind in ("file", "block")
    sha = _text(raw, "sha256", 64) if hashed else ""
    if hashed and (len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha)):
        raise _bad()
    target = _text(raw, "target") if kind == "link" else ""
    return Entry(path=path, kind=kind, role=role, sha256=sha, target=target)


def _decode_account(raw: object) -> Account:
    if not isinstance(raw, dict):
        raise _bad()
    name = _text(raw, "name", NAME_MAX)
    if name not in ACCOUNT_NAMES:
        # Uninstall deletes every listed account whose ids still match (final review,
        # security item 1): a manifest naming any other account is not MOTP's.
        raise _bad()
    uid, gid = raw.get("uid"), raw.get("gid")
    if type(uid) is not int or type(gid) is not int or not (0 < uid < 2**31 and 0 < gid < 2**31):
        raise _bad()
    return Account(name, uid, gid)


def _decode_accounts(raw: list[object]) -> tuple[Account, ...]:
    decoded = tuple(_decode_account(a) for a in raw)
    if len({a.name for a in decoded}) != len(decoded):
        raise _bad()
    return decoded


def decode(data: bytes) -> Manifest:
    """Parse a manifest. Paths are not trusted here: removal checks them (rules 1 to 3)."""
    try:
        doc = strictjson.loads(data, max_bytes=MAX_BYTES, max_depth=MAX_DEPTH)
    except ContractError as exc:
        raise _bad() from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise _bad()
    entries, accounts = doc.get("entries"), doc.get("accounts")
    if not isinstance(entries, list) or not isinstance(accounts, list):
        raise _bad()
    if len(entries) > MAX_ENTRIES or len(accounts) > 4:
        raise _bad()
    scheduler = _text(doc, "scheduler", 16)
    if scheduler not in SCHEDULERS:
        raise _bad()
    mode = _text(doc, "mode", 16) if "mode" in doc else "hybrid"  # phase 7 had no modes
    if mode not in MODES:
        raise _bad()
    return Manifest(
        version=_text(doc, "version", 64),
        entries=tuple(_decode_entry(e) for e in entries),
        accounts=_decode_accounts(accounts),
        admin_group=_text(doc, "admin_group", NAME_MAX),
        scheduler=scheduler,
        mode=mode,
    )


def read(state_dir: str) -> Optional[Manifest]:
    """The manifest in ``state_dir``, or ``None`` if there is none.

    The file must be a regular file of root that nobody else can write, in a directory
    that only root can write; otherwise ``ManifestError``.
    """
    from motp.core import safepath

    if os.path.lexists(state_dir):
        try:
            safepath.check_directory(state_dir)
        except ContractError as exc:
            raise _bad() from exc
    path = posixpath.join(state_dir, NAME)
    try:
        fd = os.open(path, _READ_FLAGS)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _bad() from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise _bad()
        data = _read_all(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    return decode(data)


def _read_all(fd: int, cap: int) -> bytes:
    chunks, size = [], 0
    while size < cap:
        chunk = os.read(fd, min(65536, cap - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


# --- hashing --------------------------------------------------------------------------


def sha256_fd(fd: int) -> Optional[str]:
    """SHA-256 of an open file, or ``None`` if it is larger than ``MAX_HASH_BYTES``."""
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return digest.hexdigest()
        size += len(chunk)
        if size > MAX_HASH_BYTES:
            return None
        digest.update(chunk)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- removal --------------------------------------------------------------------------


def _left(result: Removal, path: str, msg_id: str) -> None:
    result.left.append((path, contract_error(msg_id, path=path).message))


def open_parent(path: str) -> tuple[int, str]:
    """Open the parent directory of ``path`` without following any link (rule 2).

    Returns the open descriptor and the last component; raises ``OSError`` (``ELOOP`` or
    ``ENOTDIR``) when a component on the way is a link or not a directory.
    """
    parts = path.strip("/").split("/")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


class BrokenBlock(ValueError):
    """The file holds marker lines that do not form exactly one block."""


def find_block(data: bytes) -> Optional[tuple[int, int]]:
    """Start and end of the installer's block in a file's content: from the line that
    starts with ``BLOCK_BEGIN`` to the end of the ``BLOCK_END`` line (its line feed, or
    the end of the file when an editor dropped the last line feed); ``None`` when the
    file has no marker line at all.

    Raises ``BrokenBlock`` unless there is exactly one begin line and one end line, in
    that order: a half-removed or doubled block must never make the span reach over the
    admin's own lines (phase 8 reviews)."""
    lines = data.split(b"\n")
    end_line = BLOCK_END.rstrip(b"\n")
    begins = [i for i, ln in enumerate(lines) if ln.startswith(BLOCK_BEGIN)]
    ends = [i for i, ln in enumerate(lines) if ln == end_line]
    if not begins and not ends:
        return None
    if len(begins) != 1 or len(ends) != 1 or ends[0] < begins[0]:
        raise BrokenBlock("markers")
    start = sum(len(ln) + 1 for ln in lines[: begins[0]])
    end = sum(len(ln) + 1 for ln in lines[: ends[0] + 1])
    return start, min(end, len(data))


def read_small(
    dir_fd: int, name: str, cap: int = MAX_BLOCK_FILE_BYTES
) -> tuple[bytes, os.stat_result]:
    """A system file the installer adds a block to: a regular file of root that nobody
    else can write, read without following a link. Raises ``OSError`` or ``ValueError``."""
    fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError(name)
        data = _read_all(fd, cap + 1)
    finally:
        os.close(fd)
    if len(data) > cap:
        raise ValueError(name)
    return data, st


def _remove_block(entry: Entry, dir_fd: int, name: str, result: Removal) -> bool:
    """Take the installer's block out of a system file; the rest stays as it is."""
    from motp.collect import store

    try:
        data, st = read_small(dir_fd, name)
        span = find_block(data)
    except ValueError:  # BrokenBlock too
        _left(result, entry.path, "install.left.changed")
        return False
    lines = b"" if span is None else data[span[0] : span[1]]
    if not lines.endswith(b"\n"):
        lines += b"\n"  # an editor dropped the last line feed
    if span is None or sha256_bytes(lines) != entry.sha256:
        _left(result, entry.path, "install.left.changed")
        return False
    store.write_atomic(
        dir_fd,
        name,
        data[: span[0]] + data[span[1] :],
        mode=stat.S_IMODE(st.st_mode),
        uid=st.st_uid,
        gid=st.st_gid,
    )
    return True


def _remove_one(entry: Entry, result: Removal) -> None:
    path = entry.path
    try:
        dir_fd, name = open_parent(path)
    except FileNotFoundError:
        return  # already gone
    except OSError:
        _left(result, path, "install.left.link_on_path")
        return
    try:
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if entry.kind == "file":
            if not stat.S_ISREG(st.st_mode):
                _left(result, path, "install.left.changed")
                return
            fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
            try:
                same = os.fstat(fd)
                digest = (
                    sha256_fd(fd) if (same.st_dev, same.st_ino) == (st.st_dev, st.st_ino) else None
                )
            finally:
                os.close(fd)
            if digest != entry.sha256:
                _left(result, path, "install.left.changed")
                return
            os.unlink(name, dir_fd=dir_fd)
        elif entry.kind == "block":
            if not stat.S_ISREG(st.st_mode):
                _left(result, path, "install.left.changed")
                return
            try:
                if not _remove_block(entry, dir_fd, name, result):
                    return
            except ContractError:
                _left(result, path, "install.left.failed")
                return
        elif entry.kind == "link":
            if not stat.S_ISLNK(st.st_mode) or os.readlink(name, dir_fd=dir_fd) != entry.target:
                _left(result, path, "install.left.changed")
                return
            os.unlink(name, dir_fd=dir_fd)
        else:
            if not stat.S_ISDIR(st.st_mode):
                _left(result, path, "install.left.changed")
                return
            try:
                os.rmdir(name, dir_fd=dir_fd)
            except OSError:
                _left(result, path, "install.left.not_empty")
                return
        result.removed.append(path)
    except OSError:
        _left(result, path, "install.left.failed")
    finally:
        os.close(dir_fd)


def remove(entries: Iterable[Entry], scope: Scope, roles: Sequence[str]) -> Removal:
    """Remove the manifest entries of ``roles`` that ``scope`` allows (rules 1 to 4).

    Files and links go first, then directories, deepest first, so a directory is empty
    when its turn comes if everything in it was the installer's.
    """
    result = Removal()
    chosen = []
    for entry in entries:
        if entry.role not in roles:
            continue
        if not scope.allows(entry.path, entry.kind):
            _left(result, entry.path[:PATH_MAX], "install.left.outside")
            continue
        chosen.append(entry)
    for entry in chosen:
        if entry.kind != "dir":
            _remove_one(entry, result)
    for entry in sorted(
        (e for e in chosen if e.kind == "dir"), key=lambda e: e.path.count("/"), reverse=True
    ):
        _remove_one(entry, result)
    return result


def remove_named(directory: str, names: Iterable[str], scope: Scope, result: Removal) -> None:
    """Remove files with fixed names from one of the installer's directories (the files
    the collector writes, which have no fixed content). Same walk as ``remove``: a link on
    the way stops it; the name itself is unlinked, never followed; directories stay."""
    for name in names:
        path = posixpath.join(directory, name)
        if "/" in name or name in ("", ".", ".."):
            continue
        if not scope.allows(path):  # an exact path is enough: /run/motd.d/10-motp
            _left(result, path, "install.left.outside")
            continue
        try:
            dir_fd, last = open_parent(path)
        except FileNotFoundError:
            continue
        except OSError:
            _left(result, path, "install.left.link_on_path")
            continue
        try:
            st = os.stat(last, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                _left(result, path, "install.left.changed")
                continue
            os.unlink(last, dir_fd=dir_fd)
            result.removed.append(path)
        except FileNotFoundError:
            continue
        except OSError:
            _left(result, path, "install.left.failed")
        finally:
            os.close(dir_fd)


def write(state_fd: int, m: Manifest) -> None:
    """Write the manifest atomically into the open state directory (0600, root)."""
    from motp.collect import store

    store.write_atomic(state_fd, NAME, encode(m), mode=MODE, uid=0, gid=0, sync_dir=True)

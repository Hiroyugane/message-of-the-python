"""Python import paths of programs root starts (threat T2, final review security item 2).

A root probe starts some system programs that are Python scripts (``fail2ban-client``).
Their ``#!`` line names the system interpreter without ``-I -S``, so that interpreter
imports ``site``, reads every ``.pth`` file of its site directories and searches them for
modules before the program's own package. If any directory on that path, or a ``.pth``
file in it, can be changed by someone other than root, that person's code runs as root.
On Debian systems upgraded from older releases ``/usr/local/lib/python3*/dist-packages``
is group-writable by ``staff``.

The rule: before root starts a program whose interpreter chain ends in a Python
interpreter, every directory that interpreter may import from must pass the ownership
check of ``safepath``. The directories are worked out without starting the interpreter
(starting it would already run ``site``): for its prefix and for ``/usr/local``, below
``lib`` and ``lib64``, the version directory and the shared ``python3`` directory, each
with ``lib-dynload``, ``site-packages`` and ``dist-packages``, and root's user site.
A directory that does not exist must have a nearest existing ancestor that passes, so
nobody but root can create it. In each existing site directory every ``.pth`` file must
pass too, and every directory a ``.pth`` line adds to the path. With ``-S`` on the ``#!``
line ``site`` is off and only the standard library directories count.

The candidate list is a superset of what any one interpreter uses; a directory that fails
the check refuses the program even if that interpreter would not have used it. That is
the safe direction: the program is not started and the module says why.
"""

import os
import posixpath
import re
import stat
from collections.abc import Iterator
from typing import Optional

from motp.core import safepath
from motp.core.model import ContractError, contract_error

PYTHON_WORDS = ("python", "pypy")  # an interpreter whose basename holds one is Python
VERSION = re.compile(r"(\d+\.\d+)")
VERSION_DIR = re.compile(r"^(?:python|pypy)3(?:\.\d+)?[a-z]?$")
EXTRA_PREFIXES = ("/usr/local",)
LIB_DIRS = ("lib", "lib64")
SUBDIRS = ("lib-dynload", "site-packages", "dist-packages")
SITE_SUBDIRS = ("site-packages", "dist-packages")
ROOT_USER_BASE = "/root/.local"  # site's user base for uid 0 when HOME is unset
VENV_FILE = "pyvenv.cfg"
MAX_PTH_FILES = 256
MAX_PTH_BYTES = 64 * 1024
MAX_PTH_LINES = 256
# Every file and directory below the site directories is looked at (security review of
# phase 14b: a user's package left in a directory that was once group-writable stays
# theirs after the directory is fixed). More entries than this refuse the program.
MAX_TREE_ENTRIES = 200_000
WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH


def is_python(path: str) -> bool:
    """Generous on purpose: an unknown Python build is checked, never let through."""
    name = posixpath.basename(path).lower()
    return any(word in name for word in PYTHON_WORDS)


def python_of(program: safepath.Program) -> Optional[tuple[str, str, Optional[str]]]:
    """The last interpreter of ``program``'s chain, the name its ``#!`` line used, and
    that line's argument; ``None`` when the chain does not end in Python."""
    last, arg = program, None
    while last.interpreter is not None:
        arg = last.interpreter_arg
        last = last.interpreter
    if not (is_python(last.path) or is_python(last.named or "")):
        return None
    # The interpreter itself as the program: its options are unknown, so site counts.
    return last.path, last.named or last.path, arg


def site_disabled(arg: Optional[str]) -> bool:
    """Whether the ``#!`` argument switches ``site`` off (``-S``, ``-IS``, ``-sS``)."""
    if not arg or not arg.startswith("-") or arg.startswith("--"):
        return False
    flags = arg.split()[0][1:]
    return flags.isalpha() and "S" in flags


def _versions(interpreter: str, base: str) -> list[str]:
    """The version directory names below ``base`` this interpreter may use."""
    names = {"python3"}
    match = VERSION.search(posixpath.basename(interpreter))
    if match:
        names.add(f"python{match.group(1)}")
    try:
        listed = os.listdir(base)
    except OSError:
        listed = []
    names |= {n for n in listed if VERSION_DIR.match(n)}
    return sorted(names)


def candidates(interpreter: str, with_site: bool = True, named: str = "") -> list[str]:
    """Every directory (and venv file) ``interpreter`` may import from, unordered.

    ``named`` is the path the ``#!`` line used: a venv lives next to that name, not next to
    the real interpreter, so its prefix counts too, with its ``pyvenv.cfg``.
    """
    subdirs = SUBDIRS if with_site else ("lib-dynload",)
    prefixes = [posixpath.dirname(posixpath.dirname(p)) or "/" for p in (interpreter, named) if p]
    out: list[str] = []
    for pre in dict.fromkeys((*prefixes, *EXTRA_PREFIXES)):
        for lib in LIB_DIRS:
            base = posixpath.join(pre, lib)
            for name in _versions(interpreter, base) + _versions(named, base):
                top = posixpath.join(base, name)
                out.append(top)
                out += [posixpath.join(top, sub) for sub in subdirs]
    if named:
        bin_dir = posixpath.dirname(named)
        out += [
            posixpath.join(bin_dir, VENV_FILE),
            posixpath.join(posixpath.dirname(bin_dir), VENV_FILE),
        ]
    if with_site:
        out.append(ROOT_USER_BASE)
        user_lib = posixpath.join(ROOT_USER_BASE, "lib")
        for name in _versions(interpreter, user_lib):
            out.append(posixpath.join(user_lib, name, "site-packages"))
    return list(dict.fromkeys(out))


def check_entry(entry: str) -> None:
    """One search-path entry: it, or its nearest existing ancestor, passes ``safepath``.

    An existing directory or file must pass the check with its whole chain; for an entry
    that does not exist, the nearest existing ancestor must, so nobody but root can create
    it. An empty or relative entry always fails.
    """
    if not entry or not entry.startswith("/"):
        raise contract_error("safepath.error.not_absolute", path=entry or ".")
    if os.path.isdir(entry):
        safepath.check_directory(entry)
    elif os.path.lexists(entry):
        safepath.check_file(entry)
    else:
        parent = posixpath.dirname(entry.rstrip("/")) or "/"
        while not os.path.lexists(parent):
            parent = posixpath.dirname(parent) or "/"
        safepath.check_directory(parent)


def check_tree(top: str, budget: list[int], recurse: bool = True) -> None:
    """Every entry below ``top`` is root's and not writable by group or others.

    Entries are looked at with ``lstat``; a link must be root's and its target passes
    ``check_entry``; a link to a directory is walked as well (each real directory once).
    ``budget`` holds the entries still allowed, shared by all trees of one check.
    """
    stack = [top]
    seen: set[str] = set()
    while stack:
        current = stack.pop()
        real = os.path.realpath(current)
        if real in seen:
            continue
        seen.add(real)
        try:
            with os.scandir(current) as entries:
                listed = list(entries)
        except OSError as exc:
            raise contract_error("safepath.error.unreadable", path=current) from exc
        budget[0] -= len(listed)
        if budget[0] < 0:
            raise contract_error("importpath.error.too_many", path=top, max=MAX_TREE_ENTRIES)
        for entry in listed:
            if not recurse and entry.name in SITE_SUBDIRS:
                continue  # not importable by that name; checked as a candidate when site is on
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise contract_error("safepath.error.unreadable", path=entry.path) from exc
            if st.st_uid != safepath.TRUSTED_UID:
                raise contract_error("safepath.error.owner", path=entry.path)
            if stat.S_ISLNK(st.st_mode):
                check_entry(entry.path)
                if recurse and os.path.isdir(entry.path):
                    stack.append(entry.path)
                continue
            if st.st_mode & WRITABLE_BY_OTHERS:
                raise contract_error("safepath.error.writable", path=entry.path)
            if recurse and stat.S_ISDIR(st.st_mode):
                stack.append(entry.path)


def _pth_files(directory: str) -> Iterator[str]:
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".pth"))
    except OSError:
        return
    if len(names) > MAX_PTH_FILES:
        raise contract_error("safepath.error.too_large", path=directory)
    for name in names:
        yield posixpath.join(directory, name)


def pth_entries(directory: str, data: bytes, path: str = "") -> list[str]:
    """The directories a ``.pth`` file in ``directory`` adds, as ``site`` reads it.

    Decoded as ``site`` does (UTF-8 with an optional byte-order mark); a file that is not
    UTF-8 or has more than ``MAX_PTH_LINES`` lines is refused rather than half-read.
    """
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise contract_error("safepath.error.unreadable", path=path or directory) from exc
    lines = text.splitlines()
    if len(lines) > MAX_PTH_LINES:
        raise contract_error("safepath.error.too_large", path=path or directory)
    out = []
    for raw in lines:
        line = raw.rstrip()
        if not line or line.startswith("#") or line.startswith(("import ", "import\t")):
            continue  # an import line runs code from the (checked) file and the path
        out.append(posixpath.normpath(posixpath.join(directory, line)))
    return out


def venv_home(named: str) -> str:
    """The base interpreter's directory a venv's ``pyvenv.cfg`` names (``home = ...``), or
    "" without one. A venv made with ``--copies`` has its interpreter inside the venv, so
    the base installation's library is found only through this line."""
    bin_dir = posixpath.dirname(named)
    for cfg in (
        posixpath.join(bin_dir, VENV_FILE),
        posixpath.join(posixpath.dirname(bin_dir), VENV_FILE),
    ):
        if not os.path.lexists(cfg):
            continue
        data, _trusted = safepath.read_trusted(cfg, MAX_PTH_BYTES)
        for line in data.decode("utf-8", "replace").splitlines():
            key, eq, value = line.partition("=")
            if eq and key.strip() == "home" and value.strip().startswith("/"):
                return posixpath.normpath(value.strip())
    return ""


def check_interpreter(interpreter: str, with_site: bool = True, named: str = "") -> None:
    """Raise ``ContractError`` naming the first import path entry others could change."""
    budget = [MAX_TREE_ENTRIES]
    entries = candidates(interpreter, with_site, named)
    home = venv_home(named) if named else ""
    if home:
        # The base installation, as if its own interpreter ran (its prefix is home's parent).
        entries += candidates(posixpath.join(home, posixpath.basename(interpreter)), with_site)
    for entry in dict.fromkeys(entries):
        check_entry(entry)
        if not os.path.isdir(entry):
            continue
        site = posixpath.basename(entry) in SITE_SUBDIRS
        check_tree(entry, budget, recurse=site)
        if not with_site or not site:
            continue
        for pth in _pth_files(entry):
            data, _trusted = safepath.read_trusted(pth, MAX_PTH_BYTES)
            for added in pth_entries(entry, data, pth):
                check_entry(added)
                if os.path.isdir(added):
                    check_tree(added, budget)


def check_program(program: safepath.Program) -> None:
    """For a program that runs as root: refuse it if its Python's import path is unsafe.

    Programs that are not Python scripts pass unchanged. The error is
    ``safepath.error.import_path`` with the directory or file that failed, so the reader
    knows what to fix.
    """
    found = python_of(program)
    if found is None:
        return
    interpreter, named, arg = found
    try:
        check_interpreter(interpreter, with_site=not site_disabled(arg), named=named)
    except ContractError as exc:
        path = dict(exc.message.params).get("path", interpreter)
        raise contract_error("safepath.error.import_path", path=str(path)) from exc

"""Choosing the admin group at install time (D33).

The installer picks ``sudo`` or ``wheel`` only when an active sudoers rule grants that
group, and only when the group is a local one. Without such a group the admin tier is
readable by root alone. ``adm`` is never chosen: it holds log readers and service accounts
on many systems.

Reading sudoers follows sudo's own rules where they matter here: ``#include`` and
``@include`` name a file, ``#includedir`` and ``@includedir`` a directory whose files are
read unless their name ends in ``~`` or contains a dot. Every file must pass the ownership
check (sudo refuses files others can write, and so does this reader). A rule counts when
its user list names ``%sudo`` or ``%wheel`` without negation and it grants every command
as root on every host (``ALL=(ALL) ALL``, tags allowed). Aliases and ``Defaults``
lines are skipped, so a group granted only through a ``User_Alias`` is not found: the
reader errs towards root only, never towards a wider tier.
"""

import os
import posixpath
import re
from collections.abc import Iterable
from typing import Optional

from motp.core import safepath
from motp.core.model import ContractError

SUDOERS = "/etc/sudoers"
CANDIDATES = ("sudo", "wheel")
MAX_FILES = 128
MAX_DEPTH = 8
MAX_BYTES = 1024 * 1024
ALIAS_WORDS = ("Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias")
_INCLUDE = re.compile(r"^[#@](include|includedir)\s+(\S+)\s*$")
_SPEC = re.compile(r"ALL\s*=\s*(?:\((?P<runas>[^)]*)\))?\s*(?:[A-Z_]+:\s*)*(?P<cmd>.+)\Z")


def _logical_lines(text: str) -> list[str]:
    """Join lines ending in a backslash, as sudo does."""
    out: list[str] = []
    pending = ""
    for raw in text.splitlines():
        if raw.endswith("\\"):
            pending += raw[:-1] + " "
            continue
        out.append(pending + raw)
        pending = ""
    if pending:
        out.append(pending)
    return out


def _strip_comment(line: str) -> str:
    """Drop a ``#`` comment; ``#`` followed by a digit is a uid, not a comment."""
    for i, ch in enumerate(line):
        if ch == "#" and not (i + 1 < len(line) and line[i + 1].isdigit()):
            return line[:i]
    return line


def full_rights(spec: str) -> bool:
    """True for ``ALL=(ALL) ALL``-like specs: any host, root among the run-as users, any
    command (tags such as ``NOPASSWD:`` allowed). A narrower rule (one command, another
    host, another run-as user) does not make its group admins of this host."""
    match = _SPEC.match(spec.strip())
    if match is None or match.group("cmd").strip() != "ALL":
        return False
    runas = match.group("runas")
    if runas is None:
        return True  # no run-as list: root
    users = {u.strip() for u in runas.split(":", 1)[0].split(",")}
    return bool(users & {"ALL", "root"})


def groups_in_rule(line: str) -> set[str]:
    """The groups a sudoers rule line grants full rights, from its user list (``%name``)."""
    line = _strip_comment(line).strip()
    if not line or "=" not in line:
        return set()
    parts = line.split(None, 1)
    users = parts[0]
    if len(parts) < 2 or "=" in users or users.startswith(ALIAS_WORDS):
        return set()  # no user list: an alias, a Defaults line, or not a rule
    if not full_rights(parts[1]):
        return set()
    granted = set()
    for user in users.split(","):
        user = user.strip()
        if user.startswith("%") and not user.startswith("%:") and len(user) > 1:
            granted.add(user[1:])
    return granted


class _Reader:
    def __init__(self) -> None:
        self.files = 0
        self.granted: set[str] = set()

    def file(self, path: str, depth: int) -> None:
        if depth > MAX_DEPTH or self.files >= MAX_FILES:
            return
        self.files += 1
        try:
            data, _trusted = safepath.read_trusted(path, MAX_BYTES)
        except ContractError:
            return  # sudo ignores (and warns about) a file it cannot trust; so do we
        text = data.decode("utf-8", "replace")
        for line in _logical_lines(text):
            stripped = line.strip()
            match = _INCLUDE.match(stripped)
            if match:
                self.include(match.group(1), match.group(2), path, depth)
                continue
            self.granted |= groups_in_rule(stripped)

    def include(self, kind: str, target: str, current: str, depth: int) -> None:
        if not target.startswith("/"):  # sudo 1.9.1+: relative to the including file
            target = posixpath.join(posixpath.dirname(current), target)
        if kind == "include":
            self.file(target, depth + 1)
            return
        try:
            names = sorted(os.listdir(target))
        except OSError:
            return
        for name in names:
            if name.endswith("~") or "." in name:
                continue
            self.file(posixpath.join(target, name), depth + 1)


def granted_groups(sudoers: str = SUDOERS) -> set[str]:
    """Every group that a rule in ``sudoers`` (and the files it includes) grants."""
    reader = _Reader()
    reader.file(sudoers, 0)
    return reader.granted


def choose(granted: Iterable[str], local_gid: "dict[str, Optional[int]]") -> str:
    """``sudo`` or ``wheel`` if granted and local (``local_gid`` maps a name to its local
    id or ``None``); ``""`` (root only) otherwise. Never ``adm``."""
    wanted = set(granted)
    for name in CANDIDATES:
        if name in wanted and local_gid.get(name) is not None:
            return name
    return ""

"""The two system accounts ``motp`` and ``motp-plugin`` (D21, 4.12, T24).

The installer creates each account with a group of its own name, in the system range,
without a home directory or login shell and with a locked password. An account of that
name that the manifest does not list stops the installer before it changes anything: it
may be a person, a directory account or another program's user, and adopting it would
hand that identity to every probe.

An account the manifest lists is kept on a reinstall only if it still has the recorded
ids and the properties above. Only local files count (``/etc/passwd``, ``/etc/group``,
``/etc/shadow``); a name that resolves only through a directory service stops the
installer too.

Accounts are created and removed with the system's ``useradd``, ``userdel`` and
``groupdel`` (absolute paths, checked like every program root runs), which keep the
shadow files and their locks consistent; ``Tools`` lets tests replace them.
"""

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Optional, Protocol

from motp.core import proc, safepath
from motp.core.model import ContractError, MessageRef, Scalar, contract_error, contract_error_of
from motp.install.manifest import Account

NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")
NO_HOME = "/nonexistent"
COMMENT = "Message of the Python"
TOOL_DIRS = ("/usr/sbin", "/sbin")
TOOL_TIMEOUT = 60.0


class AccountError(ContractError):
    """An account cannot be created, kept or removed safely; ``message`` says why."""


def _fail(msg_id: str, **params: Scalar) -> AccountError:
    return AccountError(contract_error_of(msg_id, params).message)


@dataclass(frozen=True)
class Files:
    """The local account files (tests point them at a fixture tree)."""

    passwd: str = proc.ACCOUNTS_FILE
    group: str = "/etc/group"
    shadow: str = "/etc/shadow"
    login_defs: str = proc.LOGIN_DEFS
    check_nss: bool = True  # also ask the system's name service (off in fixture tests)


def _entries(path: str, fields: int) -> list[list[str]]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            rows = [line.rstrip("\n").split(":") for line in fh]
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise _fail("install.error.account_files", path=path) from exc
    return [r for r in rows if len(r) >= fields]


@dataclass(frozen=True)
class Found:
    """What the local files and the name service say about one name."""

    users: tuple[tuple[str, ...], ...] = ()  # local passwd entries of the name
    groups: tuple[tuple[str, ...], ...] = ()  # local group entries of the name
    shadow: Optional[str] = None  # password field in the shadow file
    nss_user: bool = False
    nss_group: bool = False

    @property
    def exists(self) -> bool:
        return bool(self.users or self.groups or self.nss_user or self.nss_group)


def look_up(name: str, files: Files) -> Found:
    users = tuple(tuple(e) for e in _entries(files.passwd, 7) if e[0] == name)
    groups = tuple(tuple(e) for e in _entries(files.group, 4) if e[0] == name)
    shadow_rows = [e for e in _entries(files.shadow, 2) if e[0] == name]
    nss_user = nss_group = False
    if files.check_nss:
        import grp
        import pwd

        try:
            pwd.getpwnam(name)
            nss_user = True
        except KeyError:
            pass
        try:
            grp.getgrnam(name)
            nss_group = True
        except KeyError:
            pass
    return Found(
        users=users,
        groups=groups,
        shadow=shadow_rows[0][1] if len(shadow_rows) == 1 else None,
        nss_user=nss_user,
        nss_group=nss_group,
    )


def _locked(found: Found) -> bool:
    password = found.users[0][1]
    if password not in ("x", ""):
        return password.startswith(("!", "*"))
    return found.shadow is not None and found.shadow.startswith(("!", "*"))


def verify(name: str, files: Files, recorded: Optional[Account] = None) -> Account:
    """Check that ``name`` is an account MOTP can use (T24) and return its ids.

    One local passwd entry and one local group of the same name that is its primary
    group; a uid in the system range that no other entry shares, not root or ``nobody``;
    no login shell; a locked password; with ``recorded``, the recorded ids.
    """
    found = look_up(name, files)
    if len(found.users) != 1 or len(found.groups) != 1:
        raise _fail("install.error.account_shape", name=name)
    user, group = found.users[0], found.groups[0]
    if not (user[2].isdigit() and user[3].isdigit() and group[2].isdigit()):
        raise _fail("install.error.account_shape", name=name)
    uid, gid = int(user[2]), int(user[3])
    try:
        drop = proc.account(name, files.passwd, files.login_defs)
    except ContractError as exc:
        raise _fail("install.error.account_shape", name=name) from exc
    if (drop.uid, drop.gid) != (uid, gid) or int(group[2]) != gid:
        raise _fail("install.error.account_group", name=name)
    others = [e for e in _entries(files.group, 4) if e[2] == str(gid) and e[0] != name]
    if others or group[3].strip():
        raise _fail("install.error.account_group", name=name)
    if user[6] not in NOLOGIN_SHELLS:
        raise _fail("install.error.account_shell", name=name)
    if not _locked(found):
        raise _fail("install.error.account_password", name=name)
    if recorded is not None and (recorded.uid, recorded.gid) != (uid, gid):
        raise _fail("install.error.account_foreign", name=name)
    return Account(name, uid, gid)


def precheck(name: str, files: Files, recorded: Optional[Account]) -> Optional[Account]:
    """Before anything changes: ``None`` if the name is free (the installer creates it),
    the account if the manifest lists it and it still checks out; otherwise stop."""
    found = look_up(name, files)
    if not found.exists:
        return None
    if recorded is None:
        raise _fail("install.error.account_foreign", name=name)
    if not found.users or not found.groups:
        raise _fail("install.error.account_foreign", name=name)
    return verify(name, files, recorded)


class Tools(Protocol):
    """How accounts are created and removed (the system tools, or a test double)."""

    def create(self, name: str, shell: str) -> None: ...

    def delete_user(self, name: str) -> None: ...

    def delete_group(self, name: str) -> None: ...


def nologin_shell(candidates: Sequence[str] = NOLOGIN_SHELLS) -> str:
    for path in candidates:
        if os.path.isfile(path):
            return path
    return candidates[-1]


@dataclass
class SystemTools:
    """``useradd``, ``userdel`` and ``groupdel`` of the system, through ``core.proc``."""

    dirs: Sequence[str] = TOOL_DIRS
    resolved: dict[str, str] = field(default_factory=dict)

    def _program(self, name: str) -> str:
        if name not in self.resolved:
            for directory in self.dirs:
                path = f"{directory}/{name}"
                if os.path.lexists(path):
                    self.resolved[name] = safepath.check_program(path, runs_as_root=True).path
                    break
            else:
                raise _fail("install.error.no_tool", tool=name)
        return self.resolved[name]

    def _run(self, name: str, args: Sequence[str]) -> None:
        argv = (self._program(name), *args)
        result = proc.run(proc.Spec(argv=argv, timeout=TOOL_TIMEOUT))
        if not result.ok:
            code = -1 if result.returncode is None else result.returncode
            raise _fail("install.error.tool_failed", tool=name, code=code)

    def create(self, name: str, shell: str) -> None:
        self._run(
            "useradd",
            (
                "--system", "--user-group", "--no-create-home", "--home-dir", NO_HOME,
                "--shell", shell, "--comment", COMMENT, "--", name,
            ),
        )  # fmt: skip

    def delete_user(self, name: str) -> None:
        self._run("userdel", ("--", name))

    def delete_group(self, name: str) -> None:
        self._run("groupdel", ("--", name))


def create(name: str, files: Files, tools: Tools) -> Account:
    """Create the account and check the result like any existing one."""
    tools.create(name, nologin_shell())
    return verify(name, files)


def remove(acc: Account, files: Files, tools: Tools) -> Optional[MessageRef]:
    """Remove an account the manifest lists, only while it still has the recorded ids;
    ``None`` when done, else the reason it was left."""
    found = look_up(acc.name, files)
    if not found.users and not found.groups:
        return None
    user_ok = len(found.users) == 1 and found.users[0][2:4] == (str(acc.uid), str(acc.gid))
    group_ok = len(found.groups) == 1 and found.groups[0][2] == str(acc.gid)
    try:
        if found.users:
            if not user_ok:
                return contract_error("install.left.account", name=acc.name).message
            tools.delete_user(acc.name)
        if look_up(acc.name, files).groups:
            if not group_ok:
                return contract_error("install.left.account", name=acc.name).message
            tools.delete_group(acc.name)
    except ContractError as exc:
        return exc.message
    return None

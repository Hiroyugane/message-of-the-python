"""``motp install`` and ``motp uninstall`` (blueprint 4.12, D24, D31, D33, T24, T25).

``install``, as root, from the archive (``sudo /usr/bin/python3 -I -S motp.pyz install``)
or from the installed tree (``/opt/motp/bin/motp install``, which rebuilds the bytecode
after a Python upgrade):

1. Checks before anything changes: root, Python 3.9 or newer, the system interpreter
   ``/usr/bin/python3`` passes the ownership check, every parent directory the installer
   writes into passes it, an existing own directory is root's alone, the archive is
   writable by its owner only, the manifest (if any) is readable, neither account name
   belongs to someone else (T24). ``--dry-run`` stops after these checks and prints the plan.
2. Reads its own archive once, from one open file, and unpacks it to a fresh directory
   beside ``/opt/motp/lib``; compiles the bytecode with the system interpreter; swaps the
   new tree in. Writes ``/opt/motp/bin/motp``.
3. Creates ``motp`` and ``motp-plugin`` with groups of their own (``accounts``).
4. Chooses the admin group (D33, ``admingroup``) and writes it into a new
   ``/etc/motp/config.toml``; an existing config is never overwritten.
5. Writes the units and enables the timer when systemd runs; otherwise the cron entry.
   Adds ``/usr/local/bin/motp`` when that directory chain is root's alone (D24).
   Writes the login hooks (hybrid mode: ``/etc/profile.d/motp.sh`` and, where zsh does not
   read ``/etc/profile`` itself, a marked block in the system ``zprofile``), or prepares
   static mode (``/run/motd.d``, its tmpfiles entry and the unit's write access; 4.10).
6. Records every created path with its hash in the manifest; removes what the previous
   manifest listed and this one does not.
7. Unless ``--no-start``: starts the collector once and prints ``motp doctor``.

The tree swap and the manifest happen under the collector's run lock, with the timer
and a running collection stopped first, so no run sees half a tree. The manifest is
written after the tree and after each account, so an install that stops half-way can
be run again or removed. The exit code is 1 when the scheduler or the first run failed.

``uninstall`` removes what the manifest lists, by the rules in ``manifest``; the config
stays unless ``--purge``. Files the collector writes (cache, state) have no recorded
content and are removed by their fixed names.

``Target`` holds every path and ``System`` every outside action, so tests run the whole
installer as root inside a container against a temporary tree.
"""

import contextlib
import io
import os
import posixpath
import re
import shutil
import stat
import sys
import time
import zipfile
from dataclasses import dataclass, field, replace
from typing import Optional, Protocol, TextIO

from motp import __version__
from motp.collect import store
from motp.core import config, i18n, proc, safepath
from motp.core.model import ContractError, MessageRef, Scalar, contract_error, contract_error_of
from motp.core.sanitize import sanitize
from motp.install import accounts, admingroup, hooks, manifest, units
from motp.install.manifest import Account, Entry, Manifest

USERS = manifest.ACCOUNT_NAMES
MIN_PYTHON = (3, 9)
LIB_MODE = 0o644
DIR_MODE = 0o755
WRAPPER_MODE = 0o755
CONFIG_MODE = 0o644
UNIT_MODE = 0o644
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 2000
MEMBER_NAME = re.compile(
    r"(__main__\.py|motp/[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*)\Z"
)
STARTER_ADMIN_LINE = '# admin_group = ""'
SYSTEMCTL_CANDIDATES = ("/usr/bin/systemctl", "/bin/systemctl")
SYSTEMCTL_TIMEOUT = 120.0
LOCK_WAIT = 120.0  # a collection ends within TimeoutStartSec=90
LOCK_HEARTBEAT = 10.0
COMPILE_TIMEOUT = 300.0
PATH_CELLS = 200
STAGING = "lib.new"
RETIRED = "lib.old"
# What the collector writes; removed by name on uninstall (no fixed content to compare).
CACHE_FILES = (store.PUBLIC_NAME, store.ADMIN_NAME, store.RENDER_NAME, store.LOCK_NAME)
STATE_FILES = (store.STATE_NAME, "probe-stderr.json")
USER_FILE = re.compile(r"[0-9]{1,10}\.json\Z")

# Run by the system interpreter on the staged tree: compile, report the cache tag.
COMPILE_CODE = (
    "import compileall, sys\n"
    "ok = compileall.compile_dir(sys.argv[1], quiet=1, workers=1)\n"
    "print(sys.implementation.cache_tag, '%d.%d' % sys.version_info[:2])\n"
    "sys.exit(0 if ok else 1)\n"
)

HOOK_MODE = 0o644
# A zprofile that runs /etc/profile itself (RHEL family, Fedora, Arch) runs the sh hook.
SOURCES_PROFILE = re.compile(rb"/etc/profile(?![.\w/-])")
COREUTILS_TIMEOUT_ARG = "--coreutils-prog-shebang=timeout"


def sources_profile(data: bytes) -> bool:
    """True when the zprofile's code (not its comments) names ``/etc/profile``."""
    code = (ln.split(b"#", 1)[0] for ln in data.splitlines())
    return any(SOURCES_PROFILE.search(ln) for ln in code)


MODES = manifest.MODES
STARTER_MODE_LINE = '# mode = "hybrid"'

SCHEDULER_PLAN = {
    "systemd": "install.plan.scheduler_systemd",
    "cron": "install.plan.scheduler_cron",
    "none": "install.plan.scheduler_none",
}

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


class InstallError(ContractError):
    """The installer stops; ``message`` says why."""


def _fail(msg_id: str, **params: Scalar) -> InstallError:
    return InstallError(contract_error_of(msg_id, params).message)


@dataclass(frozen=True)
class Target:
    """Every path the installer reads or writes; the defaults are the real system."""

    prefix: str = units.PREFIX
    config_root: str = config.DEFAULT_ROOT
    state_dir: str = store.STATE_DIR
    cache_dir: str = store.CACHE_DIR
    unit_dir: str = units.UNIT_DIR
    cron_file: str = units.CRON_FILE
    local_bin_link: str = units.LOCAL_BIN_LINK
    systemd_marker: str = units.SYSTEMD_MARKER
    sudoers: str = admingroup.SUDOERS
    system_python: str = units.SYSTEM_PYTHON
    account_files: accounts.Files = field(default_factory=accounts.Files)
    profile_hook: str = hooks.PROFILE_HOOK
    zprofiles: tuple[str, ...] = hooks.ZPROFILE_CANDIDATES
    tmpfiles_file: str = units.TMPFILES_FILE
    motd_dir: str = store.MOTD_DIR
    timeout_program: str = hooks.TIMEOUT_PROGRAM

    @property
    def lib_dir(self) -> str:
        return self.prefix + "/lib"

    @property
    def bin_dir(self) -> str:
        return self.prefix + "/bin"

    @property
    def wrapper(self) -> str:
        return self.bin_dir + "/motp"

    @property
    def service_path(self) -> str:
        return self.unit_dir + "/" + units.SERVICE_NAME

    @property
    def timer_path(self) -> str:
        return self.unit_dir + "/" + units.TIMER_NAME

    @property
    def config_file(self) -> str:
        return self.config_root + "/" + config.MAIN_FILE

    @property
    def motd_file(self) -> str:
        return self.motd_dir + "/" + store.MOTD_NAME

    def scope(self) -> manifest.Scope:
        """Where uninstall may remove anything (T25)."""
        return manifest.Scope(
            exact=(
                self.service_path,
                self.timer_path,
                self.cron_file,
                self.local_bin_link,
                self.profile_hook,
                self.tmpfiles_file,
                self.motd_file,
                *self.zprofiles,
            ),
            trees=(self.prefix, self.config_root, self.state_dir, self.cache_dir),
            kinds=(
                (self.service_path, "file"),
                (self.timer_path, "file"),
                (self.cron_file, "file"),
                (self.local_bin_link, "link"),
                (self.profile_hook, "file"),
                (self.tmpfiles_file, "file"),
                (self.motd_file, "file"),
                *((z, "block") for z in self.zprofiles),
            ),
        )

    def wrapper_text(self) -> str:
        return units.WRAPPER_TEXT.replace(units.LIB_DIR, self.lib_dir).replace(
            units.SYSTEM_PYTHON, self.system_python
        )

    def service_text(self, mode: str = "hybrid") -> str:
        text = units.service_text_for(mode, self.wrapper)
        return text.replace(units.STATIC_LINE, "ReadWritePaths=-" + self.motd_dir)

    def cron_text(self) -> str:
        return units.CRON_TEXT.replace(units.WRAPPER, self.wrapper)


class System(Protocol):
    """Actions outside the file tree: compiling, ``systemctl``, a first collector run."""

    def compile(self, python: str, tree: str) -> tuple[str, tuple[int, int]]: ...

    def systemctl(self, *args: str) -> bool: ...

    def run_wrapper(self, wrapper: str, *args: str) -> tuple[bool, bytes]: ...

    def timeout_ok(self, timeout: str, python: str) -> bool: ...


@dataclass
class RealSystem:
    """The real actions, each a checked program started through ``core.proc``."""

    systemctl_path: Optional[str] = None

    def compile(self, python: str, tree: str) -> tuple[str, tuple[int, int]]:
        spec = proc.Spec(
            argv=(python, "-I", "-S", "-c", COMPILE_CODE, tree),
            timeout=COMPILE_TIMEOUT,
            limits=proc.Limits(cpu_seconds=240, file_bytes=8 * 1024 * 1024, open_files=256),
        )
        result = proc.run(spec)
        words = result.stdout.decode("ascii", "replace").split()
        if not result.ok or len(words) < 2:
            raise _fail("install.error.compile")
        tag, version = words[-2], words[-1]
        major, _, minor = version.partition(".")
        if not (major.isdigit() and minor.isdigit()) or not re.match(r"[a-z0-9_-]{1,40}\Z", tag):
            raise _fail("install.error.compile")
        return tag, (int(major), int(minor))

    def _systemctl(self) -> str:
        if self.systemctl_path is None:
            for path in SYSTEMCTL_CANDIDATES:
                if os.path.lexists(path):
                    self.systemctl_path = safepath.check_program(path, runs_as_root=True).path
                    break
            else:
                raise _fail("install.error.no_tool", tool="systemctl")
        return self.systemctl_path

    def systemctl(self, *args: str) -> bool:
        spec = proc.Spec(argv=(self._systemctl(), *args), timeout=SYSTEMCTL_TIMEOUT)
        return proc.run(spec).ok

    def run_wrapper(self, wrapper: str, *args: str) -> tuple[bool, bytes]:
        program = safepath.check_program(wrapper, runs_as_root=True).path
        spec = proc.Spec(argv=(program, *args), timeout=SYSTEMCTL_TIMEOUT)
        result = proc.run(spec)
        return result.ok, result.stdout

    def timeout_ok(self, timeout: str, python: str) -> bool:
        """Open item O11: GNU ``timeout`` with ``--foreground`` (busybox has no such
        option), so the login hook can use it without taking the terminal away.

        Checked with the root rules, since this probe runs as root. On the RHEL family
        ``/usr/bin/timeout`` is a ``#!/usr/bin/coreutils --coreutils-prog-shebang=timeout``
        script of the multi-call binary, which those rules refuse as a launcher; exactly
        that form is accepted, after the ownership chain of both files is checked as for a
        program the user runs (the hook runs it as the user)."""
        try:
            program = safepath.check_program(timeout, runs_as_root=True).path
        except ContractError:
            try:
                checked = safepath.check_program(timeout, runs_as_root=False)
            except ContractError:
                return False
            shim = checked.interpreter
            if (
                shim is None
                or posixpath.basename(shim.path) != "coreutils"
                or checked.interpreter_arg != COREUTILS_TIMEOUT_ARG
            ):
                return False
            program = checked.path
        argv = (program, "--foreground", "-k", "1", "10", python, "-I", "-S", "-c", "")
        return proc.run(proc.Spec(argv=argv, timeout=SYSTEMCTL_TIMEOUT)).ok


@dataclass
class Out:
    """Catalogue lines on stdout (the plan, the steps, the result)."""

    out: TextIO = field(default_factory=lambda: sys.stdout)
    tr: i18n.Translator = field(
        default_factory=lambda: i18n.translator(i18n.language_from_env(os.environ))
    )

    def line(self, msg_id: str, **params: object) -> None:
        texts = {
            k: sanitize(v, PATH_CELLS) if isinstance(v, str) else i18n.param_text(v)
            for k, v in params.items()
        }
        self.out.write(self.tr.compose(msg_id, texts) + "\n")
        self.out.flush()

    def reason(self, message: MessageRef) -> str:
        return sanitize(self.tr.text(message), PATH_CELLS)


# --- the source -------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """What gets installed: the archive's bytes, or the installed tree itself."""

    archive: Optional[bytes] = None  # read once from one open file
    tree: Optional[str] = None  # the installed lib directory (bytecode rebuild)


def find_source(target: Target, program: Optional[str]) -> Source:
    """The archive this process runs from, or the installed tree; anything else (a source
    checkout) cannot install."""
    if program is None:
        raise _fail("install.error.source")
    if os.path.isdir(program):
        real = os.path.realpath(program)
        if real != os.path.realpath(target.lib_dir):
            raise _fail("install.error.source")
        safepath.check_directory(real)
        return Source(tree=real)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0)
    try:
        fd = os.open(program, flags)
    except OSError as exc:
        raise _fail("install.error.source") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_ARCHIVE_BYTES:
            raise _fail("install.error.source")
        if st.st_mode & 0o022:  # anyone else could have changed what root runs
            raise _fail("install.error.source_writable")
        data = manifest._read_all(fd, MAX_ARCHIVE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise _fail("install.error.source")
    return Source(archive=data)


def members(data: bytes) -> list[tuple[str, bytes]]:
    """The files of the archive, each checked: a plain relative name below ``motp/`` (or
    the root ``__main__.py``), no directory entries, no links, bounded sizes."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise _fail("install.error.archive") from exc
    out: list[tuple[str, bytes]] = []
    total = 0
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise _fail("install.error.archive")
        for info in infos:
            name = info.filename
            kind = (info.external_attr >> 16) & 0o170000
            if (
                not MEMBER_NAME.match(name)
                or ".." in name.split("/")
                or info.is_dir()
                or kind not in (0, stat.S_IFREG)
                or info.file_size > MAX_MEMBER_BYTES
            ):
                raise _fail("install.error.archive")
            total += info.file_size
            if total > MAX_ARCHIVE_BYTES:
                raise _fail("install.error.archive")
            try:
                content = zf.read(info)
            except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
                raise _fail("install.error.archive") from exc
            out.append((name, content))
    names = [n for n, _ in out]
    if (
        "__main__.py" not in names
        or "motp/__init__.py" not in names
        or len(set(names)) != len(names)
    ):
        raise _fail("install.error.archive")
    return out


# --- files and directories --------------------------------------------------------------

_NEW = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
_NEW |= getattr(os, "O_CLOEXEC", 0)
_DIR = manifest._DIR_FLAGS


def open_existing_dir(path: str) -> int:
    """Open a directory the system provides (``/etc/systemd/system``, ``/etc/cron.d``)
    after the ownership check; its mode is left as it is."""
    real = safepath.check_directory(path)
    return os.open(real, _DIR)


def write_new(dir_fd: int, name: str, data: bytes, mode: int) -> None:
    """Create a file that must not exist yet (``O_EXCL``, no link followed)."""
    fd = os.open(name, _NEW, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def unpack(data: bytes, stage_fd: int) -> None:
    """Write the archive's files below the open, empty staging directory."""
    for name, content in members(data):
        parts = name.split("/")
        fd = os.dup(stage_fd)
        try:
            for part in parts[:-1]:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, 0o700, dir_fd=fd)
                nxt = os.open(part, _DIR, dir_fd=fd)
                os.fchmod(nxt, DIR_MODE)
                os.close(fd)
                fd = nxt
            write_new(fd, parts[-1], content, LIB_MODE)
        finally:
            os.close(fd)


def tree_entries(real_root: str, shown_root: str) -> list[Entry]:
    """Every directory and file below ``real_root`` (no links followed), named as they
    will be after the swap (``shown_root``), files with their hash."""
    out: list[Entry] = [Entry(shown_root, "dir")]
    for dirpath, dirnames, filenames, dir_fd in os.fwalk(real_root, follow_symlinks=False):
        rel = posixpath.relpath(dirpath, real_root)
        base = shown_root if rel == "." else posixpath.join(shown_root, rel)
        for d in sorted(dirnames):
            out.append(Entry(posixpath.join(base, d), "dir"))
        for f in sorted(filenames):
            fd = os.open(f, manifest._READ_FLAGS, dir_fd=dir_fd)
            try:
                digest = manifest.sha256_fd(fd)
            finally:
                os.close(fd)
            if digest is None:
                raise _fail("install.error.archive")
            out.append(Entry(posixpath.join(base, f), "file", sha256=digest))
    return out


def set_owner_mode(dir_fd: int, name: str, mode: int, directory: bool) -> None:
    """Root's, with ``mode``, set on the open entry; a link is refused by ``O_NOFOLLOW``.

    Through a descriptor because ``chmod`` relative to a directory without following
    links needs glibc 2.32 (Debian 11 has 2.31).
    """
    flags = manifest._READ_FLAGS | (getattr(os, "O_DIRECTORY", 0) if directory else 0)
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def chown_tree(real_root: str) -> None:
    """Bytecode written by the compiler: root's, not writable by others."""
    for _dirpath, dirnames, filenames, dir_fd in os.fwalk(real_root, follow_symlinks=False):
        for name in [*dirnames, *filenames]:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode) or not (
                stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)
            ):
                raise _fail("install.error.archive")
            directory = stat.S_ISDIR(st.st_mode)
            set_owner_mode(dir_fd, name, DIR_MODE if directory else LIB_MODE, directory)


# --- the plan ---------------------------------------------------------------------------


@dataclass
class Plan:
    """Everything decided before the first change."""

    source: Source
    old: Optional[Manifest]
    kept_accounts: dict[str, Optional[Account]]
    admin_group: str
    scheduler: str
    link: bool
    mode: str = "hybrid"
    zprofile: Optional[str] = None  # the system zprofile that gets the block


def scheduler_for(target: Target) -> str:
    if os.path.isdir(target.systemd_marker):
        return "systemd"
    if os.path.isdir(posixpath.dirname(target.cron_file)):
        return "cron"
    return "none"


def local_gids(group_file: str) -> dict[str, Optional[int]]:
    from motp.collect import runner

    return {name: runner.local_group(name, group_file) for name in admingroup.CANDIDATES}


def check_own_dir(path: str) -> None:
    """An existing directory the installer writes into must already be what it would
    make: a real directory of root that nobody else can write. Checked in the plan, so a
    bad one stops the installer before the first change."""
    if not os.path.lexists(path):
        return
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise _fail("install.error.own_dir", path=path)


def choose_mode(target: Target, requested: Optional[str]) -> str:
    """The mode to install: the one asked for, else the config's, else hybrid. The config
    is the one place the mode lives, since the collector reads it there; the installer
    never edits an existing config, so a request that differs from it stops here."""
    configured: Optional[str] = None
    if os.path.isdir(target.config_root):
        configured = config.load(target.config_root).config.general.mode
    if requested is None:
        return configured or "hybrid"
    if requested not in MODES:
        raise _fail("install.error.mode", mode=requested)
    if configured is not None and configured != requested:
        raise _fail(
            "install.error.mode_differs",
            mode=requested,
            configured=configured,
            path=target.config_file,
        )
    return requested


def zprofile_plan(target: Target) -> tuple[Optional[str], str, str]:
    """Open item O10: the system zprofile, and whether it needs the block. Returns the
    file to extend (or ``None``), the plan line and the path it names."""
    for path in target.zprofiles:
        if not os.path.lexists(path):
            continue
        try:
            dir_fd = open_existing_dir(posixpath.dirname(path))
        except ContractError:
            return None, "install.plan.zsh_unsafe", path
        try:
            data, _ = manifest.read_small(dir_fd, posixpath.basename(path))
        except (OSError, ValueError):
            return None, "install.plan.zsh_unsafe", path
        finally:
            os.close(dir_fd)
        try:
            span = manifest.find_block(data)
        except manifest.BrokenBlock:
            return None, "install.plan.zsh_broken", path
        own = data if span is None else data[: span[0]] + data[span[1] :]
        if sources_profile(own):
            return None, "install.plan.zsh_sourced", path
        return path, "install.plan.zsh_block", path
    return None, "install.plan.zsh_none", "-"


def plan(target: Target, program: Optional[str], mode: Optional[str] = None) -> Plan:
    """Step 1: every check that can stop the installer, before anything changes."""
    if os.geteuid() != 0:
        raise _fail("install.error.not_root")
    if sys.version_info[:2] < MIN_PYTHON:
        raise _fail("install.error.python")
    safepath.check_program(target.system_python, runs_as_root=True)
    for own in (target.prefix, target.config_root, target.state_dir, target.cache_dir):
        safepath.check_directory(posixpath.dirname(own))
        check_own_dir(own)
    source = find_source(target, program)
    if source.archive is not None:
        members(source.archive)
    old = manifest.read(target.state_dir)
    kept = {}
    for name in USERS:
        recorded = old.account(name) if old is not None else None
        kept[name] = accounts.precheck(name, target.account_files, recorded)
    sched = scheduler_for(target)
    if sched == "systemd":
        safepath.check_directory(target.unit_dir)
    elif sched == "cron":
        safepath.check_directory(posixpath.dirname(target.cron_file))
    granted = admingroup.granted_groups(target.sudoers)
    group = admingroup.choose(granted, local_gids(target.account_files.group))
    link_dir = posixpath.dirname(target.local_bin_link)
    try:
        safepath.check_directory(link_dir)
        link = True
    except ContractError:
        link = False
    chosen = choose_mode(target, mode)
    zprofile = None
    if chosen == "hybrid":
        safepath.check_directory(posixpath.dirname(target.profile_hook))
        zprofile = zprofile_plan(target)[0]
    else:
        safepath.check_directory(posixpath.dirname(target.motd_dir))
        if sched == "systemd":
            safepath.check_directory(posixpath.dirname(target.tmpfiles_file))
    return Plan(source, old, kept, group, sched, link, chosen, zprofile)


def show_plan(p: Plan, target: Target, out: Out) -> None:
    out.line("install.plan.tree", path=target.lib_dir)
    for name in USERS:
        msg = "install.plan.account_keep" if p.kept_accounts[name] else "install.plan.account_new"
        out.line(msg, name=name)
    if p.admin_group:
        out.line("install.plan.admin_group", group=p.admin_group)
    else:
        out.line("install.plan.root_only")
    out.line(SCHEDULER_PLAN[p.scheduler])
    if p.link:
        out.line("install.plan.link", path=target.local_bin_link)
    out.line("install.plan.mode", mode=p.mode)
    if p.mode == "hybrid":
        out.line("install.plan.hook", path=target.profile_hook)
        _, note, path = zprofile_plan(target)
        out.line(note, path=path)
    else:
        out.line("install.plan.static", path=target.motd_file)


# --- install ----------------------------------------------------------------------------


def _remove_tree(parent_fd: int, prefix: str, name: str) -> None:
    """Remove a directory the installer made inside its own root-only prefix.

    ``shutil.rmtree`` deletes through directory descriptors on Linux and never follows a
    link; the prefix itself passed the ownership check, so nobody else can swap it.
    """
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    shutil.rmtree(prefix + "/" + name)


def install_tree(p: Plan, target: Target, system: System, prefix_fd: int, out: Out) -> list[Entry]:
    """Step 2: unpack, compile, swap; or recompile the installed tree in place."""
    lib = posixpath.basename(target.lib_dir)
    if p.source.tree is not None:
        tag, version = system.compile(target.system_python, target.lib_dir)
        chown_tree(target.lib_dir)
    else:
        _remove_tree(prefix_fd, target.prefix, STAGING)
        os.mkdir(STAGING, 0o700, dir_fd=prefix_fd)
        stage_fd = os.open(STAGING, _DIR, dir_fd=prefix_fd)
        try:
            unpack(p.source.archive or b"", stage_fd)
        finally:
            os.close(stage_fd)
        staged = target.prefix + "/" + STAGING
        tag, version = system.compile(target.system_python, staged)
        chown_tree(staged)
        set_owner_mode(prefix_fd, STAGING, DIR_MODE, directory=True)
        _remove_tree(prefix_fd, target.prefix, RETIRED)
        with contextlib.suppress(FileNotFoundError):
            os.rename(lib, RETIRED, src_dir_fd=prefix_fd, dst_dir_fd=prefix_fd)
        os.rename(STAGING, lib, src_dir_fd=prefix_fd, dst_dir_fd=prefix_fd)
        _remove_tree(prefix_fd, target.prefix, RETIRED)
    if version < MIN_PYTHON:
        raise _fail("install.error.python")
    out.line("install.done.tree", path=target.lib_dir, tag=tag)
    return tree_entries(target.lib_dir, target.lib_dir)


def write_replacing(dir_fd: int, name: str, data: bytes, mode: int) -> None:
    store.write_atomic(dir_fd, name, data, mode=mode, uid=0, gid=0)


def starter_config(group: str, mode: str = "hybrid") -> bytes:
    from motp import cli

    text = cli.starter_text().decode("utf-8")
    if group:
        text = text.replace(STARTER_ADMIN_LINE, f'admin_group = "{group}"', 1)
    if mode != "hybrid":
        text = text.replace(STARTER_MODE_LINE, f'mode = "{mode}"', 1)
    return text.encode("utf-8")


def install_config(p: Plan, target: Target, out: Out) -> list[Entry]:
    """Step 4: ``/etc/motp`` with ``conf.d`` and ``plugins.d``, never widening a mode an
    admin made stricter; a new ``config.toml`` only when there is none. Config entries of
    the old manifest are carried over while their files are unchanged, so ``--purge`` can
    still remove them."""
    # An admin's stricter modes stay (final review, security item 4): plugin code, root
    # grants and watched paths need not be readable by every local user.
    root_fd = store.prepare_dir(target.config_root, DIR_MODE, keep_stricter=True)
    entries = [Entry(target.config_root, "dir", role="config")]
    try:
        for sub in (config.DROPIN_DIR, "plugins.d"):
            shown = target.config_root + "/" + sub
            os.close(store.subdir(root_fd, sub, DIR_MODE, shown, keep_stricter=True))
            entries.append(Entry(target.config_root + "/" + sub, "dir", role="config"))
        data = starter_config(p.admin_group, p.mode)
        try:
            write_new(root_fd, config.MAIN_FILE, data, CONFIG_MODE)
        except FileExistsError:
            out.line("install.done.config_kept", path=target.config_file)
            old = {e.path: e for e in (p.old.entries if p.old else ()) if e.role == "config"}
            previous = old.get(target.config_file)
            if previous is not None:
                entries.append(previous)
        else:
            out.line("install.done.config_new", path=target.config_file)
            entries.append(
                Entry(target.config_file, "file", role="config", sha256=manifest.sha256_bytes(data))
            )
    finally:
        os.close(root_fd)
    effective = config.load(target.config_root).config.visibility.admin_group
    if effective != p.admin_group:
        out.line(
            "install.done.admin_group_differs",
            configured=effective or "-",
            found=p.admin_group or "-",
        )
    elif effective:
        out.line("install.done.admin_group", group=effective)
    else:
        out.line("install.done.root_only")
    return entries


def install_scheduler(
    p: Plan, target: Target, system: System, no_start: bool, out: Out
) -> tuple[list[Entry], bool]:
    """Step 5: the units and the timer, or the cron entry, or nothing (said by doctor)."""
    if p.scheduler == "systemd":
        fd = open_existing_dir(target.unit_dir)
        try:
            service = target.service_text(p.mode).encode()
            timer = units.TIMER_TEXT.encode()
            write_replacing(fd, units.SERVICE_NAME, service, UNIT_MODE)
            write_replacing(fd, units.TIMER_NAME, timer, UNIT_MODE)
        finally:
            os.close(fd)
        ok = system.systemctl("daemon-reload") and system.systemctl("enable", units.TIMER_NAME)
        if ok and not no_start:
            ok = system.systemctl("start", units.TIMER_NAME)
        out.line("install.done.units" if ok else "install.error.units")
        return [
            Entry(target.service_path, "file", sha256=manifest.sha256_bytes(service)),
            Entry(target.timer_path, "file", sha256=manifest.sha256_bytes(timer)),
        ], ok
    if p.scheduler == "cron":
        fd = open_existing_dir(posixpath.dirname(target.cron_file))
        try:
            data = target.cron_text().encode()
            write_replacing(fd, posixpath.basename(target.cron_file), data, UNIT_MODE)
        finally:
            os.close(fd)
        out.line("install.done.cron", path=target.cron_file)
        return [Entry(target.cron_file, "file", sha256=manifest.sha256_bytes(data))], True
    out.line("install.done.no_scheduler")
    return [], True


def install_block(path: str, block: bytes, out: Out) -> list[Entry]:
    """Add the installer's block to a system file, or replace an older one; the rest of
    the file, its owner and its mode stay as they are."""
    try:
        dir_fd = open_existing_dir(posixpath.dirname(path))
    except ContractError:
        out.line("install.done.no_zsh", path=path)
        return []
    name = posixpath.basename(path)
    try:
        try:
            data, st = manifest.read_small(dir_fd, name)
            span = manifest.find_block(data)
        except (OSError, ValueError):  # BrokenBlock too: never guess where lines end
            out.line("install.done.no_zsh", path=path)
            return []
        if span is not None:
            new = data[: span[0]] + block + data[span[1] :]
        else:
            new = data + (b"\n" if data and not data.endswith(b"\n") else b"") + block
        if new != data:
            store.write_atomic(
                dir_fd, name, new, mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid
            )
    finally:
        os.close(dir_fd)
    out.line("install.done.zsh_block", path=path)
    return [Entry(path, "block", sha256=manifest.sha256_bytes(block))]


def install_login(p: Plan, target: Target, system: System, out: Out) -> list[Entry]:
    """The login side of the mode (4.10): the hooks in hybrid mode; in static mode the
    directory pam_motd reads and its tmpfiles entry (the unit got its line already)."""
    if p.mode == "static":
        entries: list[Entry] = []
        if p.scheduler == "systemd":
            fd = open_existing_dir(posixpath.dirname(target.tmpfiles_file))
            try:
                data = units.TMPFILES_TEXT.replace(units.MOTD_DIR, target.motd_dir).encode()
                write_replacing(fd, posixpath.basename(target.tmpfiles_file), data, UNIT_MODE)
            finally:
                os.close(fd)
            entries.append(Entry(target.tmpfiles_file, "file", sha256=manifest.sha256_bytes(data)))
        os.close(store.open_shared_dir(target.motd_dir, store.MOTD_DIR_MODE))
        out.line("install.done.static", path=target.motd_file)
        return entries
    timeout = (
        target.timeout_program
        if system.timeout_ok(target.timeout_program, target.system_python)
        else None
    )
    hook = hooks.profile_hook(target.wrapper, timeout).encode()
    fd = open_existing_dir(posixpath.dirname(target.profile_hook))
    try:
        write_replacing(fd, posixpath.basename(target.profile_hook), hook, HOOK_MODE)
    finally:
        os.close(fd)
    out.line("install.done.hook", path=target.profile_hook)
    entries = [Entry(target.profile_hook, "file", sha256=manifest.sha256_bytes(hook))]
    if p.zprofile is not None:
        block = hooks.zsh_block(target.profile_hook).encode()
        entries += install_block(p.zprofile, block, out)
    return entries


def remove_static_file(target: Target, out: Out) -> None:
    """The file of static mode, written by the collector: removed by its fixed name."""
    gone = manifest.Removal()
    manifest.remove_named(target.motd_dir, (store.MOTD_NAME,), target.scope(), gone)
    for path, reason in gone.left:
        out.line("install.left", path=path, reason=out.reason(reason))


def install_link(p: Plan, target: Target, out: Out) -> list[Entry]:
    """The convenience link ``/usr/local/bin/motp`` (D24): only where that directory chain
    is root's alone, and never over a file that is not the installer's own link."""
    if not p.link:
        out.line("install.done.no_link", path=target.local_bin_link)
        return []
    entry = Entry(target.local_bin_link, "link", target=target.wrapper)
    try:
        dir_fd, name = manifest.open_parent(target.local_bin_link)
    except OSError:
        out.line("install.done.no_link", path=target.local_bin_link)
        return []
    try:
        try:
            os.symlink(target.wrapper, name, dir_fd=dir_fd)
        except FileExistsError:
            ours = p.old is not None and entry in p.old.entries
            same = os.path.islink(target.local_bin_link) and (
                os.readlink(name, dir_fd=dir_fd) == target.wrapper
            )
            if not (ours and same):
                out.line("install.done.no_link", path=target.local_bin_link)
                return []
    finally:
        os.close(dir_fd)
    return [entry]


def install(
    target: Target = Target(),
    *,
    program: Optional[str] = None,
    system: Optional[System] = None,
    tools: Optional[accounts.Tools] = None,
    dry_run: bool = False,
    no_start: bool = False,
    mode: Optional[str] = None,
    out: Optional[Out] = None,
) -> int:
    out = out if out is not None else Out()
    system = system if system is not None else RealSystem()
    tools = tools if tools is not None else accounts.SystemTools()
    if program is None:
        from motp.collect import runner

        program = runner.program_path()
    try:
        p = plan(target, program, mode)
    except ContractError as exc:
        out.line("install.stopped", reason=out.reason(exc.message))
        return EXIT_FAILED
    show_plan(p, target, out)
    if dry_run:
        out.line("install.dry_run")
        return EXIT_OK
    os.umask(0o022)
    try:
        lock = collector_lock(target, out)
    except ContractError as exc:
        out.line("install.stopped", reason=out.reason(exc.message))
        return EXIT_FAILED
    try:
        return _install(p, target, system, tools, no_start, out, lock)
    except ContractError as exc:
        out.line("install.failed", reason=out.reason(exc.message))
        return EXIT_FAILED
    except OSError:
        out.line("install.failed", reason=out.reason(contract_error("install.error.io").message))
        return EXIT_FAILED


def merged(old: Optional[Manifest], entries: list[Entry], made: list[Account], p: Plan) -> Manifest:
    """The manifest so far: what this run made, plus what the previous manifest listed at
    paths and names this run has not reached yet, so an install that stops half-way still
    lists everything for the next install or for uninstall."""
    paths = {e.path for e in entries}
    names = {a.name for a in made}
    rest_entries = tuple(e for e in (old.entries if old else ()) if e.path not in paths)
    rest_accounts = tuple(a for a in (old.accounts if old else ()) if a.name not in names)
    return Manifest(
        version=__version__,
        entries=tuple(entries) + rest_entries,
        accounts=tuple(made) + rest_accounts,
        admin_group=p.admin_group,
        scheduler=p.scheduler,
        mode=p.mode,
    )


def collector_lock(target: Target, out: Out, wait: float = LOCK_WAIT) -> int:
    """Take the collector's run lock, waiting for a running collection to finish, so no
    run sees a half-swapped tree or recreates what uninstall removes."""
    cache_fd = store.prepare_dir(target.cache_dir, store.CACHE_DIR_MODE)
    try:
        started = last = time.monotonic()
        while True:
            lock = store.acquire_lock(cache_fd)
            if lock is not None:
                return lock
            now = time.monotonic()
            if now - started >= wait:
                raise _fail("install.error.busy")
            if now - last >= LOCK_HEARTBEAT:
                last = now
                out.line("install.waiting", seconds=int(now - started))
            time.sleep(0.5)
    finally:
        os.close(cache_fd)


def stop_units(target: Target, system: System, old: Optional[Manifest]) -> None:
    """Stop the timer and a running collection before the tree changes."""
    if old is not None and old.scheduler == "systemd" and os.path.isdir(target.systemd_marker):
        system.systemctl("stop", units.TIMER_NAME, units.SERVICE_NAME)


def _install(
    p: Plan,
    target: Target,
    system: System,
    tools: accounts.Tools,
    no_start: bool,
    out: Out,
    lock: int,
) -> int:
    stop_units(target, system, p.old)
    state_fd = store.prepare_dir(target.state_dir, store.STATE_DIR_MODE)
    made: list[Account] = []
    entries: list[Entry] = []
    try:
        prefix_fd = store.prepare_dir(target.prefix, DIR_MODE)
        try:
            entries = [Entry(target.prefix, "dir")]
            entries += install_tree(p, target, system, prefix_fd, out)
            bin_fd = store.subdir(prefix_fd, "bin", DIR_MODE, target.bin_dir)
            try:
                wrapper = target.wrapper_text().encode()
                write_replacing(bin_fd, "motp", wrapper, WRAPPER_MODE)
            finally:
                os.close(bin_fd)
            entries.append(Entry(target.bin_dir, "dir"))
            entries.append(Entry(target.wrapper, "file", sha256=manifest.sha256_bytes(wrapper)))
        finally:
            os.close(prefix_fd)
        manifest.write(state_fd, merged(p.old, entries, made, p))
        for name in USERS:
            kept = p.kept_accounts[name]
            if kept is None:
                kept = accounts.create(name, target.account_files, tools)
                out.line("install.done.account_new", name=name)
            made.append(kept)
            manifest.write(state_fd, merged(p.old, entries, made, p))
        entries += install_config(p, target, out)
        scheduled, units_ok = install_scheduler(p, target, system, no_start, out)
        entries += scheduled
        entries += install_link(p, target, out)
        entries += install_login(p, target, system, out)
        if p.mode == "hybrid":
            # Always: an earlier switch that stopped half-way may have left it behind
            # under a manifest that already says hybrid (phase 8 code review).
            remove_static_file(target, out)
        new = Manifest(
            version=__version__,
            entries=tuple(entries),
            accounts=tuple(made),
            admin_group=p.admin_group,
            scheduler=p.scheduler,
            mode=p.mode,
        )
        manifest.write(state_fd, new)
    finally:
        os.close(state_fd)
        os.close(lock)
    if p.old is not None:
        paths = {e.path for e in new.entries}
        stale = [e for e in p.old.entries if e.role == "program" and e.path not in paths]
        stale = [e for e in stale if not e.path.startswith(target.lib_dir + "/")]
        gone = manifest.remove(stale, target.scope(), ("program",))
        for path, reason in gone.left:
            out.line("install.left", path=path, reason=out.reason(reason))
    out.line("install.done.manifest", count=len(new.entries))
    ran = first_run(p, target, system, out) if not no_start else True
    return EXIT_OK if units_ok and ran else EXIT_FAILED


def first_run(p: Plan, target: Target, system: System, out: Out) -> bool:
    """Step 7: one collector run, then the doctor's report; True when the run worked."""
    if p.scheduler == "systemd":
        ok = system.systemctl("start", units.SERVICE_NAME)
    else:
        ok, _ = system.run_wrapper(target.wrapper, "collect", "--no-sandbox")
    out.line("install.done.first_run" if ok else "install.error.first_run")
    _, report = system.run_wrapper(target.wrapper, "doctor")
    text = report.decode("utf-8", "replace")
    for line in text.splitlines()[:200]:
        out.out.write(sanitize(line, PATH_CELLS) + "\n")
    out.out.flush()
    return ok


# --- uninstall --------------------------------------------------------------------------


def uninstall(
    target: Target = Target(),
    *,
    system: Optional[System] = None,
    tools: Optional[accounts.Tools] = None,
    purge: bool = False,
    dry_run: bool = False,
    out: Optional[Out] = None,
) -> int:
    out = out if out is not None else Out()
    system = system if system is not None else RealSystem()
    tools = tools if tools is not None else accounts.SystemTools()
    if os.geteuid() != 0:
        out.line(
            "install.stopped", reason=out.reason(contract_error("install.error.not_root").message)
        )
        return EXIT_FAILED
    try:
        m = manifest.read(target.state_dir)
    except ContractError as exc:
        out.line("install.stopped", reason=out.reason(exc.message))
        return EXIT_FAILED
    if m is None:
        out.line("uninstall.not_installed", path=target.state_dir)
        return EXIT_FAILED
    roles = ("program", "config") if purge else ("program",)
    scope = target.scope()
    if dry_run:
        for entry in m.entries:
            if entry.role in roles:
                ok = scope.allows(entry.path)
                out.line("uninstall.would_remove" if ok else "uninstall.outside", path=entry.path)
        for acc in m.accounts:
            out.line("uninstall.would_remove_account", name=acc.name)
        out.line("install.dry_run")
        return EXIT_OK
    if m.scheduler == "systemd" and os.path.isdir(target.systemd_marker):
        system.systemctl("disable", "--now", units.TIMER_NAME)
        system.systemctl("stop", units.SERVICE_NAME)
    try:
        lock = collector_lock(target, out)
    except ContractError as exc:
        out.line("install.stopped", reason=out.reason(exc.message))
        return EXIT_FAILED
    try:
        return _uninstall(m, target, system, tools, roles, purge, out)
    finally:
        os.close(lock)


def _uninstall(
    m: Manifest,
    target: Target,
    system: System,
    tools: accounts.Tools,
    roles: tuple[str, ...],
    purge: bool,
    out: Out,
) -> int:
    scope = target.scope()
    result = manifest.remove(m.entries, scope, roles)
    manifest.remove_named(target.cache_dir, CACHE_FILES, scope, result)
    user_dir = target.cache_dir + "/" + store.USER_DIR
    try:
        names = [n for n in os.listdir(user_dir) if USER_FILE.match(n)]
    except OSError:
        names = []
    manifest.remove_named(user_dir, names, scope, result)
    manifest.remove_named(target.state_dir, STATE_FILES, scope, result)
    manifest.remove_named(target.motd_dir, (store.MOTD_NAME,), scope, result)
    kept: list[Account] = []
    for acc in m.accounts:
        reason = accounts.remove(acc, target.account_files, tools)
        if reason is None:
            out.line("uninstall.account_removed", name=acc.name)
        else:
            kept.append(acc)
            out.line("uninstall.account_left", name=acc.name, reason=out.reason(reason))
    if result.left or kept:
        # Keep a manifest of what is left, so uninstall can be run again and install
        # still knows the accounts as its own (T24).
        rest = tuple(e for e in m.entries if os.path.lexists(e.path))
        state_fd = store.prepare_dir(target.state_dir, store.STATE_DIR_MODE)
        try:
            manifest.write(state_fd, replace(m, entries=rest, accounts=tuple(kept)))
        finally:
            os.close(state_fd)
    else:
        manifest.remove_named(target.state_dir, (manifest.NAME,), scope, result)
        for directory in (user_dir, target.cache_dir, target.state_dir):
            manifest.remove([Entry(directory, "dir")], scope, ("program",)).left.clear()
    if m.scheduler == "systemd" and os.path.isdir(target.systemd_marker):
        system.systemctl("daemon-reload")
    for path, reason in result.left:
        out.line("install.left", path=path, reason=out.reason(reason))
    out.line("uninstall.done", count=len(result.removed), left=len(result.left) + len(kept))
    if not purge:
        out.line("uninstall.config_kept", path=target.config_root)
    return EXIT_OK if not (result.left or kept) else EXIT_FAILED

"""``motp doctor``: check the installation and the terminal (4.12, 4.13).

Anyone can run it; root sees more (the accounts, the admin details of the cache). One
line per check, with a level: ``ok``, ``info``, ``warn`` or ``fail``. The exit code is 1
when a check failed, 0 otherwise.

Checks, in order: the installed program and its ownership chain; invariant 7 (no entry
of this process's ``sys.path`` is writable by anyone but root; every MOTP process starts
the same way, so this process stands for all of them); the programs root probes start,
with the import path of a Python interpreter (final review); the bytecode for the running
interpreter (D31: a Python upgrade leaves it stale until ``motp install``); the config;
the admin group (D33); the probe accounts (root); the scheduler, and that cron runs
without a sandbox; whether ``/proc`` hides the probe users' processes; the cache's age
and failed modules; the exec plugins (root: each with its state, the user it runs as and
its last result, or why it is refused or ignored); the mode and its login side (the hook
in hybrid mode; the static file and the unit's write access in static mode; leftovers of
the other mode, which would show the message twice); the terminal, with a test line in
the chosen charset.
"""

import contextlib
import importlib.util
import os
import stat
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable, Optional, TextIO

from motp import __version__
from motp.collect import store
from motp.core import cache, config, i18n, importpath, proc, safepath
from motp.core.model import ContractError, MessageRef, ModuleState, Scalar, contract_error, ref
from motp.core.sanitize import sanitize
from motp.install import accounts, hooks, units

LEVEL_IDS = {
    "ok": "doctor.level.ok",
    "info": "doctor.level.info",
    "warn": "doctor.level.warn",
    "fail": "doctor.level.fail",
}
CELLS = 160
STALE_PERIODS = 3  # the cache is stale after three timer periods (4.4)
SYSTEMCTL_CANDIDATES = ("/usr/bin/systemctl", "/bin/systemctl")
PYC_HEADER = 16


@dataclass
class Report:
    lines: list[tuple[str, MessageRef]] = field(default_factory=list)

    def add(self, level: str, msg_id: str, **params: Scalar) -> None:
        self.lines.append((level, MessageRef(msg_id, tuple(sorted(params.items())))))

    @property
    def failed(self) -> bool:
        return any(level == "fail" for level, _ in self.lines)


# --- invariant 7 -------------------------------------------------------------------------


MAX_TREE_PROBLEMS = 5


def tree_problems(root: str) -> list[tuple[str, MessageRef]]:
    """Files and directories below ``root`` (the program tree, ``__pycache__`` included)
    that are not root's, that others can write, or that are links."""
    problems: list[tuple[str, MessageRef]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                problems.append((path, contract_error("doctor.error.link", path=path).message))
            elif st.st_uid != 0:
                problems.append((path, contract_error("safepath.error.owner", path=path).message))
            elif st.st_mode & 0o022:
                problems.append(
                    (path, contract_error("safepath.error.writable", path=path).message)
                )
            if len(problems) >= MAX_TREE_PROBLEMS:
                return problems
    return problems


def search_path_problems(
    entries: Sequence[str], program: Optional[str] = None, isolated: bool = True
) -> list[tuple[str, MessageRef]]:
    """Entries of ``sys.path`` that someone other than root could change (invariant 7).

    An existing entry (a directory, or an archive file) must pass the ownership check
    with its whole chain; for an entry that does not exist, its nearest existing ancestor
    must pass it, so nobody but root can create it. An empty or relative entry (the current
    directory) is always a problem. ``program``, the MOTP tree itself, is checked file by
    file. ``isolated`` false (no ``-I -S``) is a problem too: such a process does not
    stand for the ones the wrapper and the unit start.
    """
    problems = []
    if not isolated:
        problems.append(("-I -S", contract_error("doctor.error.not_isolated").message))
    if program is not None and os.path.isdir(program):
        problems += tree_problems(program)
    for entry in entries:
        if not entry or not entry.startswith("/"):
            problems.append((entry or ".", contract_error("doctor.error.relative").message))
            continue
        try:
            importpath.check_entry(entry)
        except ContractError as exc:
            problems.append((entry, exc.message))
    return problems


def check_root_programs(r: Report, settings: Optional[config.Config] = None) -> None:
    """The programs root probes start, with the import path of a Python interpreter.

    A root probe starts a Python script (``fail2ban-client``) only if every directory its
    interpreter imports from is root's alone (``core.importpath``); this names the one that
    is not, so the admin can fix it. Programs that are not installed, and those of modules
    the config switched off, are skipped. Only root can see all of that path (root's own
    user site is below ``/root``), so an ordinary user gets a pointer instead.
    """
    from motp.modules import registry

    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        r.add("info", "doctor.root_programs_as_root")
        return
    modules = settings.modules if settings is not None else {}
    for module in registry.cached_modules():
        if not getattr(module, "needs_root", False):
            continue
        chosen = modules.get(module.name)
        if chosen is not None and chosen.enabled is False:
            continue
        for binary in getattr(module, "binaries", ()):
            if not os.path.lexists(binary):
                continue
            try:
                importpath.check_program(safepath.check_program(binary, runs_as_root=True))
            except ContractError as exc:
                r.add(
                    "fail",
                    "doctor.root_program_bad",
                    program=sanitize(binary, CELLS),
                    reason=_reason(exc.message),
                )
                continue
            r.add("ok", "doctor.root_program", program=sanitize(binary, CELLS))


# --- bytecode (D31) -----------------------------------------------------------------------


def stale_bytecode(tree: str) -> tuple[int, int]:
    """(source files, files whose bytecode for this interpreter is missing or stale)."""
    total = stale = 0
    for dirpath, _dirnames, filenames in os.walk(tree):
        if "__pycache__" in dirpath.split(os.sep):
            continue
        for name in filenames:
            if not name.endswith(".py"):
                continue
            total += 1
            source = os.path.join(dirpath, name)
            if not _pyc_matches(source):
                stale += 1
    return total, stale


def _pyc_matches(source: str) -> bool:
    try:
        cached = importlib.util.cache_from_source(source)
        st = os.stat(source)
        with open(cached, "rb") as fh:
            head = fh.read(PYC_HEADER)
    except (OSError, NotImplementedError, ValueError):
        return False
    if len(head) != PYC_HEADER or head[:4] != importlib.util.MAGIC_NUMBER:
        return False
    flags = int.from_bytes(head[4:8], "little")
    if flags & 0b1:  # hash-based: valid by construction of the installer
        return True
    mtime = int.from_bytes(head[8:12], "little")
    size = int.from_bytes(head[12:16], "little")
    return mtime == (int(st.st_mtime) & 0xFFFFFFFF) and size == (st.st_size & 0xFFFFFFFF)


# --- the checks ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Places:
    prefix: str = units.PREFIX
    config_root: str = config.DEFAULT_ROOT
    cache_dir: str = store.CACHE_DIR
    unit_dir: str = units.UNIT_DIR
    cron_file: str = units.CRON_FILE
    systemd_marker: str = units.SYSTEMD_MARKER
    account_files: accounts.Files = field(default_factory=accounts.Files)
    profile_hook: str = hooks.PROFILE_HOOK
    motd_dir: str = store.MOTD_DIR
    zprofiles: tuple[str, ...] = hooks.ZPROFILE_CANDIDATES


def _program_root() -> Optional[str]:
    from motp.collect import runner

    return runner.program_path()


def check_program(r: Report, places: Places) -> bool:
    lib = places.prefix + "/lib"
    if not os.path.isdir(lib):
        r.add("warn", "doctor.not_installed", path=lib)
        return False
    try:
        safepath.check_directory(lib)
        safepath.check_program(places.prefix + "/bin/motp", runs_as_root=True)
    except ContractError as exc:
        r.add("fail", "doctor.program_unsafe", reason=_reason(exc.message))
        return True
    r.add("ok", "doctor.program", path=places.prefix)
    return True


def _reason(message: MessageRef) -> str:
    tr = i18n.translator(i18n.language_from_env(os.environ))
    return sanitize(tr.text(message), CELLS)


def check_search_path(r: Report, entries: Sequence[str]) -> None:
    isolated = bool(sys.flags.isolated and sys.flags.no_site)
    problems = search_path_problems(entries, _program_root(), isolated)
    for entry, reason in problems:
        r.add(
            "fail", "doctor.search_path_bad", entry=sanitize(entry, CELLS), reason=_reason(reason)
        )
    if not problems:
        r.add("ok", "doctor.search_path", count=len(entries))


def check_bytecode(r: Report, places: Places) -> None:
    lib = os.path.realpath(places.prefix + "/lib")
    running = _program_root()
    if running is None or os.path.realpath(running) != lib:
        r.add("info", "doctor.bytecode_skipped")
        return
    total, stale = stale_bytecode(lib)
    version = "{}.{}".format(*sys.version_info[:2])
    if stale:
        r.add("warn", "doctor.bytecode_stale", count=stale, total=total, version=version)
    else:
        r.add("ok", "doctor.bytecode", total=total, version=version)


def check_config(r: Report, places: Places) -> config.Config:
    loaded = config.load(places.config_root)
    if config.closed_to_user(places.config_root, loaded.problems):
        r.add("info", "doctor.config_root_only", path=places.config_root)
    elif loaded.problems:
        r.add("warn", "doctor.config_problems", count=len(loaded.problems))
    else:
        r.add("ok", "doctor.config", count=len(loaded.applied))
    if loaded.warnings:
        r.add("warn", "doctor.config_warnings", count=len(loaded.warnings))
    return loaded.config


def check_admin_group(r: Report, settings: config.Config, places: Places) -> None:
    from motp.collect import runner

    name = settings.visibility.admin_group
    if not name:
        r.add("warn", "doctor.admin_root_only")
        return
    gid = runner.local_group(name, places.account_files.group)
    if gid is None:
        r.add("fail", "doctor.admin_group_missing", group=name)
        return
    r.add("ok", "doctor.admin_group", group=name)


def check_accounts(r: Report, places: Places) -> None:
    if os.geteuid() != 0:
        return
    for name in ("motp", "motp-plugin"):
        try:
            accounts.verify(name, places.account_files)
        except ContractError as exc:
            r.add("fail", "doctor.account_bad", name=name, reason=_reason(exc.message))
            continue
        r.add("ok", "doctor.account", name=name)
    from motp.collect import runner

    extra = runner.supplementary_groups(runner.PLUGIN_USER, places.account_files.group)
    if extra:
        r.add("warn", "doctor.plugin_groups", groups=", ".join(extra)[:80])


def _systemctl_says(*args: str) -> str:
    for path in SYSTEMCTL_CANDIDATES:
        if os.path.lexists(path):
            try:
                program = safepath.check_program(path, runs_as_root=True).path
                result = proc.run(proc.Spec(argv=(program, *args), timeout=30.0))
            except ContractError:
                return ""
            return result.stdout.decode("ascii", "replace").strip()[:32]
    return ""


def check_scheduler(r: Report, places: Places) -> str:
    if os.path.isdir(places.systemd_marker):
        if not os.path.isfile(f"{places.unit_dir}/{units.TIMER_NAME}"):
            r.add("fail", "doctor.timer_missing")
            return "none"
        enabled = _systemctl_says("is-enabled", "--", units.TIMER_NAME)
        active = _systemctl_says("is-active", "--", units.TIMER_NAME)
        level = "ok" if enabled == "enabled" and active == "active" else "warn"
        r.add(level, "doctor.timer", enabled=enabled or "-", active=active or "-")
        return "systemd"
    if os.path.isfile(places.cron_file):
        r.add("warn", "doctor.cron_no_sandbox", path=places.cron_file)
        return "cron"
    r.add("fail", "doctor.no_scheduler")
    return "none"


def check_process_view(r: Report, scheduler: str) -> None:
    if os.geteuid() != 0 or not proc.process_view_hidden():
        return
    if scheduler == "systemd":
        r.add("info", "doctor.hidepid_unit")
    else:
        r.add("warn", "doctor.hidepid")


# File systems whose owners and modes the ownership check cannot trust: a FUSE mount
# (``user_allow_other``) can report root as the owner of a user's files, and network file
# systems report what the server says (phase 3 issue, settled in phase 14).
UNTRUSTED_FS = ("fuse", "nfs", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "afs")
MOUNTINFO = "/proc/self/mountinfo"
MOUNTINFO_READ = 1024 * 1024


def mount_type(path: str, mountinfo_text: str) -> str:
    """The file system type of the mount that holds ``path`` (the longest mount point
    that is a prefix of it), or "" when none is found."""
    from motp.modules import hw_disks

    best, fs_type = -1, ""
    for mount in hw_disks.parse_mountinfo(mountinfo_text):
        point = mount.mount_point.rstrip("/") + "/"
        # ">=": of mounts stacked on one point, the one listed last is the one in use.
        if (path + "/").startswith(point) and len(point) >= best:
            best, fs_type = len(point), mount.fs_type
    return fs_type


def untrusted_type(fs_type: str) -> bool:
    """``fuse``, ``fuse.sshfs``, ``fuseblk``, ``nfs4``, ``cifs``, ``ceph`` and the like."""
    return fs_type.startswith(UNTRUSTED_FS)


def check_file_systems(r: Report, places: Places, mountinfo: str = MOUNTINFO) -> None:
    """MOTP's own places must sit on a file system that enforces the owners it reports."""
    try:
        with open(mountinfo, encoding="utf-8", errors="replace") as fh:
            text = fh.read(MOUNTINFO_READ)
    except OSError:
        return
    for path in (places.prefix, places.config_root, places.cache_dir, store.STATE_DIR):
        real = os.path.realpath(path) if os.name == "posix" else path  # follow links in it
        fs_type = mount_type(real, text)
        if untrusted_type(fs_type):
            r.add("warn", "doctor.untrusted_fs", path=path, type=sanitize(fs_type, 32))


def check_cache(r: Report, places: Places, now: int) -> None:
    public = f"{places.cache_dir}/{store.PUBLIC_NAME}"
    try:
        tier = cache.read_tier_file(public, cache.PUBLIC, store.ROOT)
    except ContractError as exc:
        r.add("warn", "doctor.cache_missing", reason=_reason(exc.message))
        return
    age = max(0, now - tier.generated)
    period = 300
    with contextlib.suppress(ContractError):
        period = cache.read_render_file(f"{places.cache_dir}/{store.RENDER_NAME}").timer_period
    level = "ok" if age <= STALE_PERIODS * period else "warn"
    r.add(level, "doctor.cache_age", age=age, failed=tier.failed)
    try:
        admin = cache.read_tier_file(f"{places.cache_dir}/{store.ADMIN_NAME}", cache.ADMIN, 0)
    except ContractError:
        return  # not in the admin tier: names and reasons stay hidden (5.4)
    for name, result in sorted(admin.modules.items()):
        if result.state is ModuleState.FAILED and result.error is not None:
            r.add(
                "warn",
                "doctor.module_failed",
                module=sanitize(name, 64),
                reason=_reason(result.error),
            )


def _last_run(admin: Optional[cache.TierCache], name: str, now: int) -> str:
    """What the last collector run made of a plugin, from ``admin.json``."""
    tr = i18n.translator(i18n.language_from_env(os.environ))
    result = admin.modules.get(name) if admin is not None else None
    if result is None:
        return tr.text(ref("doctor.plugin_last_none"))
    if result.state is ModuleState.FAILED and result.error is not None:
        return tr.text(ref("doctor.plugin_last_failed", reason=_reason(result.error)))
    return tr.text(ref("doctor.plugin_last_ok", age=max(0, now - result.collected)))


def check_plugins(r: Report, settings: config.Config, places: Places, now: int) -> None:
    """Every entry of ``plugins.d`` with its state (phase 12): accepted with the user it
    runs as and its last result, refused and why, or ignored and why. Root only, since
    plugin names and results are admin-tier (5.4) and the files may be root-only."""
    from motp.collect import plugins

    directory = plugins.directory(places.config_root)
    if os.geteuid() != 0:
        if os.path.lexists(directory):
            r.add("info", "doctor.plugins_root_only")
        return
    found = plugins.discover(places.config_root, settings)
    if not found:
        r.add("info", "doctor.plugins_none", path=directory)
        return
    admin: Optional[cache.TierCache] = None
    with contextlib.suppress(ContractError):
        admin = cache.read_tier_file(f"{places.cache_dir}/{store.ADMIN_NAME}", cache.ADMIN, 0)
    for f in found:
        name = sanitize(f.name, plugins.NAME_CELLS)
        if f.state == plugins.ACCEPTED:
            last = _last_run(admin, f.name, now)
            failed = (
                admin is not None
                and f.name in admin.modules
                and (admin.modules[f.name].state is ModuleState.FAILED)
            )
            r.add("warn" if failed else "ok", "doctor.plugin", name=name, user=f.run_as, last=last)
        elif f.state == plugins.REFUSED:
            reason = _reason(f.reason) if f.reason is not None else "-"
            r.add("warn", "doctor.plugin_refused", name=name, reason=reason)
        else:
            reason = _reason(f.reason) if f.reason is not None else "-"
            r.add("info", "doctor.plugin_ignored", name=name, reason=reason)


def _root_file(path: str) -> Optional[os.stat_result]:
    """The file's status when it is a regular file of root that nobody else can write."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        return None
    return st


def check_login(r: Report, settings: config.Config, places: Places, now: int) -> None:
    """The mode and its login side (4.10, D7)."""
    mode = settings.general.mode
    r.add("info", "doctor.mode", mode=mode)
    hook = os.path.lexists(places.profile_hook)
    static_file = places.motd_dir + "/" + store.MOTD_NAME
    if mode == "hybrid":
        if _root_file(places.profile_hook) is not None:
            r.add("ok", "doctor.hook", path=places.profile_hook)
        else:
            r.add("warn", "doctor.hook_missing", path=places.profile_hook)
        if os.path.lexists(static_file):
            r.add("warn", "doctor.other_mode_left", path=static_file)
        check_zsh(r, places)
        return
    # Phase 8 issue, documented in phase 14: only pam_motd prints the static file, so a
    # login shell that never passed pam_motd shows nothing. No new mechanism for 1.0.
    r.add("info", "doctor.static_gap")
    if hook:
        r.add("warn", "doctor.other_mode_left", path=places.profile_hook)
    service = places.unit_dir + "/" + units.SERVICE_NAME
    if os.path.isdir(places.systemd_marker):
        try:
            with open(service, encoding="utf-8") as fh:
                unit = fh.read(64 * 1024)
        except (OSError, ValueError):
            unit = ""
        if "ReadWritePaths=-" + places.motd_dir not in unit.splitlines():
            r.add("fail", "doctor.static_unit", path=service)
    st = _root_file(static_file)
    if st is None:
        r.add("warn", "doctor.static_missing", path=static_file)
        return
    age = max(0, now - int(st.st_mtime))
    period = 300
    with contextlib.suppress(ContractError):
        period = cache.read_render_file(f"{places.cache_dir}/{store.RENDER_NAME}").timer_period
    level = "ok" if age <= STALE_PERIODS * period else "warn"
    r.add(level, "doctor.static_file", path=static_file, age=age)


def read_zprofile(path: str) -> bytes:
    """The zprofile as the installer reads it (``installer.zprofile_plan``): the directory
    through the ownership check, the file without following a link, root's alone, bounded.
    Raises ``ContractError``, ``OSError`` or ``ValueError`` where the installer would refuse."""
    from motp.install import installer, manifest

    dir_fd = installer.open_existing_dir(os.path.dirname(path))
    try:
        data, _ = manifest.read_small(dir_fd, os.path.basename(path))
    finally:
        os.close(dir_fd)
    return data


def check_zsh(r: Report, places: Places, read: Callable[[str], bytes] = read_zprofile) -> None:
    """The zsh side of the hook (O10, phase 8 issue): the first system zprofile that
    exists either runs ``/etc/profile`` itself or carries the installer's block. A zsh
    installed after MOTP has neither until ``motp install`` runs again. No zprofile at
    all means no zsh, and nothing to say. The file is read as the installer reads it, so
    both agree on what they find (code review of phase 14)."""
    from motp.install import installer, manifest

    for path in places.zprofiles:
        if not os.path.lexists(path):
            continue
        try:
            data = read(path)
        except (ContractError, OSError, ValueError):
            r.add("warn", "doctor.zsh_unsafe", path=path)
            return
        try:
            span = manifest.find_block(data)
        except manifest.BrokenBlock:
            r.add("warn", "doctor.zsh_broken", path=path)
            return
        if span is not None:
            r.add("ok", "doctor.zsh_block", path=path)
        elif installer.sources_profile(data):
            r.add("ok", "doctor.zsh_profile", path=path)
        else:
            r.add("warn", "doctor.zsh_missing", path=path)
        return


def check_terminal(r: Report, env: "os._Environ[str] | dict[str, str]", stream: TextIO) -> str:
    from motp.render import theme

    isatty = stream.isatty()
    encoding = getattr(stream, "encoding", None) or "-"
    charset = theme.pick_charset(env, encoding, "auto", None)
    level = theme.pick_color(env, isatty, "auto", None)
    r.add(
        "info",
        "doctor.terminal",
        tty="yes" if isatty else "no",
        term=sanitize(env.get("TERM", "-"), 32) or "-",
        encoding=sanitize(encoding, 32),
        charset=charset.name,
        colors=int(level),
    )
    c = charset
    return (
        c.top_left + c.horizontal * 3 + c.top_right + " " + c.vertical + " "
        + c.bottom_left + c.horizontal * 3 + c.bottom_right + " "
        + c.tee_left + c.tee_right + " " + c.bar_full * 3 + c.bar_free * 3
    )  # fmt: skip


def run_checks(
    places: Places, env: "os._Environ[str] | dict[str, str]", stream: TextIO, now: int
) -> tuple[Report, str]:
    r = Report()
    r.add("info", "doctor.version", version=__version__)
    installed = check_program(r, places)
    check_search_path(r, sys.path)
    if installed:
        check_bytecode(r, places)
    check_file_systems(r, places)
    settings = check_config(r, places)
    check_root_programs(r, settings)
    check_admin_group(r, settings, places)
    check_accounts(r, places)
    scheduler = check_scheduler(r, places) if installed else "none"
    check_process_view(r, scheduler)
    check_cache(r, places, now)
    check_plugins(r, settings, places, now)
    if installed:
        check_login(r, settings, places, now)
    sample = check_terminal(r, env, stream)
    return r, sample


def _isatty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (OSError, ValueError, AttributeError):
        return False


def main(out: Optional[TextIO] = None, places: Places = Places()) -> int:
    out = out if out is not None else sys.stdout
    tr = i18n.translator(i18n.language_from_env(os.environ))
    report, sample = run_checks(places, os.environ, out, int(time.time()))
    for level, message in report.lines:
        marker = tr.message(LEVEL_IDS[level])
        out.write(tr.compose("doctor.line", {"level": marker, "text": tr.text(message)}) + "\n")
    # The test line is for the terminal in front of the reader: piped (into a file, or
    # into the installer's output, whose sanitiser turns frame characters into
    # replacement characters) it tests nothing.
    if _isatty(out):
        out.write(tr.compose("doctor.charset_line", {"sample": sample}) + "\n")
    out.flush()
    return 1 if report.failed else 0

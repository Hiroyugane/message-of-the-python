"""``motp collect``: run the probes, write the cache (blueprint 4.1, 4.4, 4.9, 4.14, D21, D32).

One run, as root:

1. Prepare ``/run/motp`` (with ``user/``) and ``/var/lib/motp`` and take the run lock; if
   another run holds it, end at once without writing anything (4.14, T19).
2. Load the config, the state file and the current ``admin.json``.
3. Pick the modules that are due: their interval has passed since they last ran, or their
   items are missing from the cache (after a reboot ``/run`` is empty), or the state does
   not know them (4.4).
4. Start each due probe as its own process, ``<python> -I -S <program> _probe <name>``,
   as ``motp`` (or root for a module that declares ``needs_root``), through ``core.proc``:
   at most ``POOL_SIZE`` at a time, each with its time limit, all inside the total budget
   (``limits.collect_total_s``). Plugins (phase 12, ``collect.plugins``) run as
   ``motp-plugin`` (or root when the config grants it), one at a time, after the built-in
   probes; inside the unit each in a transient unit of its own. Users never fall back to
   root: without the account its probes fail.
5. End every process the probe users still run: after the built-in pool and, without
   the unit, after each plugin (4.9); a plugin's own unit ends with it.
6. Validate each document (``core.probe``), classify its items with the threshold rules,
   and keep the last good items of every module in the state. A module that fails keeps
   its last good items with the time they were collected, so the renderer shows them as
   stale and later as expired (4.4); its state says failed and why.
7. Write ``render.json``, ``admin.json``, ``public.json`` and the state, each atomically
   with the mode, owner and group of 4.1.

The collector logs to stderr (4.15), which the journal or cron captures: a status line at
least every ``HEARTBEAT_SECONDS`` while probes run, and a summary. The journal can be read
by ``adm`` and ``wheel`` (T11, D33), so every line holds counts and stage names only;
module names and failure reasons are in ``admin.json``, and the stderr of failed probes
goes to the root-only ``errlog`` file in the state directory.

Inside the collector unit the cleanup kills by the unit's control group, which also works
when ``/proc`` is mounted with ``hidepid``; elsewhere it kills by ``/proc`` and refuses to
call a run clean when ``/proc`` hides the probe users' processes from it (phase 7).

``Collector`` takes every path, clock and the probe list as parameters, so tests can run a
whole collection as root inside a container against a temporary tree.
"""

import contextlib
import os
import sys
import time
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Callable, Optional, TextIO

from motp.collect import child, errlog, plugins, store
from motp.collect.context import ProbeContext
from motp.core import cache, config, i18n, probe, proc, safepath, strictjson
from motp.core.cache import Layout, RenderSettings
from motp.core.model import (
    ContractError,
    Item,
    MessageRef,
    ModuleResult,
    ModuleState,
    Status,
    UserLogins,
    Visibility,
    contract_error,
    ref,
)
from motp.core.sanitize import sanitize
from motp.core.thresholds import Rule, classify
from motp.install import units
from motp.modules import registry
from motp.modules.base import Module

TIMER_PERIOD = 300  # seconds between runs of the collector timer (4.11)
POOL_SIZE = 4
DUE_SLACK_MAX = 60  # seconds a run may start early and still find a module due
HEARTBEAT_SECONDS = 10.0
MIN_PROBE_TIMEOUT = 0.5
MAX_PROBE_TIMEOUT = 30.0  # 4.14
BUILTIN_USER = "motp"
PLUGIN_USER = "motp-plugin"
ROOT_USER = "root"
GROUP_FILE = "/etc/group"
LOG_CELLS = 120
UNIT_NAME = "motp-collect.service"
STATIC_MODE = "static"
STATIC_WIDTH = 80  # pam_motd knows nothing of the terminal (D7)
STATIC_LOCALE_KEYS = ("LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES")
PACKAGE_MANAGERS = (("apt", "/usr/bin/apt-get"), ("dnf", "/usr/bin/dnf"))
# The module whose per-user data the collector writes (D32), and the config-row module.
LOGIN_MODULE = "os_login"
ROWS_UNIT = "rows_unit"
ROWS_FILE_AGE = "rows_file_age"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


@dataclass(frozen=True)
class Paths:
    """Where a run reads and writes; the defaults are the installed locations."""

    cache_dir: str = store.CACHE_DIR
    state_dir: str = store.STATE_DIR
    config_root: str = config.DEFAULT_ROOT
    accounts_file: str = proc.ACCOUNTS_FILE
    login_defs: str = proc.LOGIN_DEFS
    group_file: str = GROUP_FILE
    motd_dir: str = store.MOTD_DIR


@dataclass(frozen=True)
class Probe:
    """One process to start for one module or plugin.

    ``argv`` is the whole command; its program is checked before the run starts.
    ``refused`` set means the probe is not started and counts as failed with that reason.
    """

    name: str
    argv: tuple[str, ...]
    user: str  # BUILTIN_USER, PLUGIN_USER or ROOT_USER
    timeout: float
    interval: int
    max_age: int
    visibility: Visibility = Visibility.PUBLIC
    refused: Optional[MessageRef] = None
    config: str = ""  # the module's own config table as JSON (``MOTP_CONFIG``), or ""
    # Exec plugins (phase 12): validated as plugin output, admin-only unless ``public``
    # (D27). ``found`` is what discovery accepted, checked again right before the start;
    # ``in_unit`` marks a root plugin started in a transient unit of its own.
    plugin: bool = False
    public: bool = False
    found: Optional[plugins.Found] = None
    in_unit: bool = False


@dataclass
class Log:
    """The collector's log on stderr: catalogue messages with sanitised values (4.15)."""

    out: TextIO = field(default_factory=lambda: sys.stderr)
    tr: i18n.Translator = field(
        default_factory=lambda: i18n.translator(i18n.language_from_env(os.environ))
    )

    def line(self, msg_id: str, **params: object) -> None:
        texts = {
            k: sanitize(v, LOG_CELLS) if isinstance(v, str) else i18n.param_text(v)
            for k, v in params.items()
        }
        try:
            self.out.write(self.tr.compose(msg_id, texts) + "\n")
            self.out.flush()
        except (OSError, ValueError):
            pass  # a closed log must not end the run

    def reason(self, message: MessageRef) -> str:
        return sanitize(self.tr.text(message), LOG_CELLS)


# --- building the probes of the built-in modules ----------------------------------------


def program_path() -> Optional[str]:
    """The program a probe runs: the archive, or the unpacked tree with its ``__main__.py``.

    A source checkout (no root ``__main__.py``) has none; it cannot run probes.
    """
    import motp

    archive = getattr(getattr(motp, "__loader__", None), "archive", None)
    if isinstance(archive, str):
        return archive
    root = os.path.dirname(os.path.dirname(os.path.abspath(motp.__file__)))
    return root if os.path.isfile(os.path.join(root, "__main__.py")) else None


def check_launch(interpreter: str, program: Optional[str]) -> tuple[str, str]:
    """Check the interpreter and the program a probe starts; return their real paths.

    The interpreter gets the rules for root programs, since root probes use it too. The
    program is the archive (a file) or the unpacked tree (a directory); both must pass the
    ownership check, so no other user can change the code a probe runs.
    """
    if program is None:
        raise contract_error("collect.error.program", path="-")
    real_interpreter = safepath.check_program(interpreter, runs_as_root=True).path
    if os.path.isdir(program):
        real_program = safepath.check_directory(program)
    else:
        real_program = safepath.check_file(program).path
    return real_interpreter, real_program


def check_search_path() -> None:
    """Every directory of the children's ``PATH`` must pass the ownership check (T2).

    A directory that does not exist cannot be used to plant a program (only root can
    create it in a root directory), so it passes.
    """
    for directory in proc.SAFE_PATH.split(":"):
        if os.path.lexists(directory):
            safepath.check_directory(directory)


def probe_timeout(module: Module, settings: config.Config) -> float:
    """The module's own ``timeout_s``, else the larger of the module's declared need and
    ``limits.probe_timeout_s``; always within 0.5 to 30 seconds (4.14)."""
    own = settings.module(module.name).timeout_s
    chosen = own if own is not None else max(module.timeout, settings.limits.probe_timeout_s)
    return min(max(chosen, MIN_PROBE_TIMEOUT), MAX_PROBE_TIMEOUT)


@dataclass(frozen=True)
class Choice:
    """Why a module runs or not; ``motp modules`` shows the same reasons."""

    module: Module
    state: str  # "active", "disabled" or "not_detected"
    reason: Optional[MessageRef] = None


def module_config(name: str, settings: config.Config) -> dict[str, object]:
    """The part of the config a probe gets as its own table (``ctx.config``).

    ``rows_unit`` gets its rows as pairs of unit name and label, ``rows_file_age`` as
    path, label and both limits in seconds (phase 12); the config loader has checked them
    and the module checks them again. No other module has one.
    """
    if name == ROWS_UNIT and settings.unit_rows:
        return {"rows": [[row.name, row.label] for row in settings.unit_rows]}
    if name == ROWS_FILE_AGE and settings.file_age_rows:
        return {
            "rows": [
                [row.path, row.label, row.warn_after, row.crit_after]
                for row in settings.file_age_rows
            ]
        }
    return {}


def choose(modules: Sequence[Module], settings: config.Config, now: int) -> list[Choice]:
    """Apply ``enabled`` and detection to each module (4.8, D11).

    Detection only asks whether paths exist; it runs in the calling process with the probe
    context. ``enabled = true`` runs a module that detection did not find.
    """
    choices = []
    for module in modules:
        ctx = ProbeContext(now=now, config=module_config(module.name, settings))
        enabled = settings.module(module.name).enabled
        if enabled is False:
            choices.append(Choice(module, "disabled", ref("modules.reason.disabled")))
            continue
        try:
            detection = module.detect(ctx)
        except Exception:
            detection = None
        if enabled is True or (detection is not None and detection.available):
            choices.append(Choice(module, "active"))
        else:
            reason = detection.reason if detection is not None else None
            choices.append(Choice(module, "not_detected", reason))
    return choices


def builtin_probes(
    choices: Sequence[Choice],
    settings: config.Config,
    launch: Optional[tuple[str, str]],
    refused: Optional[MessageRef],
) -> list[Probe]:
    """A probe per active module; all are refused when the launch check failed."""
    probes = []
    for choice in choices:
        if choice.state != "active":
            continue
        module = choice.module
        argv: tuple[str, ...] = ()
        if launch is not None:
            interpreter, program = launch
            argv = (interpreter, "-I", "-S", program, "_probe", module.name)
        own = module_config(module.name, settings)
        probes.append(
            Probe(
                name=module.name,
                argv=argv,
                user=ROOT_USER if module.needs_root else BUILTIN_USER,
                timeout=probe_timeout(module, settings),
                interval=module.interval,
                max_age=module.max_age,
                visibility=module.default_visibility,
                refused=refused,
                config=strictjson.dumps(own).decode("utf-8").strip() if own else "",
            )
        )
    return probes


PLUGIN_INTERVAL = TIMER_PERIOD  # a plugin runs at every collector run
PLUGIN_MAX_AGE = 1800  # its last good items are shown for half an hour after it fails
SHIM_COMMAND = "_plugin"


def plugin_probes(
    found: Sequence[plugins.Found],
    launch: Optional[tuple[str, str]],
    refused: Optional[MessageRef],
    systemd_run: Optional[str],
) -> list[Probe]:
    """A probe per plugin the discovery accepted or refused (ignored names get none).

    A plugin runs as ``motp-plugin``, or as root when granted. With ``systemd_run`` (the
    collector runs inside its unit) every plugin runs the shim in a transient unit of its
    own (``install.units.plugin_unit_argv``); without a usable ``systemd-run`` or program
    it is refused there, never run inside the collector unit. Without ``systemd_run``
    (``--no-sandbox``, cron) the plugin's real path runs here directly.
    """
    probes = []
    for f in found:
        if not plugins.runnable(f):
            continue
        reason = f.reason if f.state == plugins.REFUSED else None
        root = f.run_as == plugins.ROOT_USER
        argv: tuple[str, ...] = (f.path,) if f.path else ()
        timeout = f.timeout
        in_unit = systemd_run is not None
        if in_unit and reason is None:
            if not systemd_run:
                reason = ref("collect.error.no_systemd_run", path=units.SYSTEMD_RUN)
            elif launch is None:
                reason = refused or ref("collect.error.program", path="-")
            else:
                interpreter, program = launch
                shim = (interpreter, "-I", "-S", program, SHIM_COMMAND, f.name)
                argv = units.plugin_unit_argv(str(systemd_run), f.name, f.timeout, root, shim)
                timeout = f.timeout + units.PLUGIN_SLACK
        probes.append(
            Probe(
                name=f.name,
                argv=argv,
                user=ROOT_USER if root else PLUGIN_USER,
                timeout=timeout,
                interval=PLUGIN_INTERVAL,
                max_age=PLUGIN_MAX_AGE,
                visibility=Visibility.PUBLIC if f.public else Visibility.ADMIN,
                refused=reason,
                plugin=True,
                public=f.public,
                found=f if f.state == plugins.ACCEPTED else None,
                in_unit=in_unit,
            )
        )
    return probes


def admin_only(p: Probe, items: Sequence[Item]) -> tuple[Item, ...]:
    """A plugin's items as the current config allows them: all admin-only unless the
    plugin is public (D27). Applied to carried and restored items too, so making a
    plugin admin-only takes its old items out of ``public.json`` at once."""
    if not p.plugin or p.public:
        return tuple(items)
    return tuple(
        replace(
            item,
            visibility=Visibility.ADMIN,
            detail=tuple(replace(d, visibility=Visibility.ADMIN) for d in item.detail),
        )
        for item in items
    )


# --- accounts and groups ----------------------------------------------------------------


def supplementary_groups(user: str, group_file: str = GROUP_FILE) -> "list[str]":
    """The groups of the local group file that list ``user`` as a member (sorted). Unreadable
    means unknown, which counts as one: the caller refuses rather than guesses."""
    try:
        with open(group_file, encoding="utf-8", errors="replace") as fh:
            entries = [line.rstrip("\n").split(":") for line in fh]
    except OSError:
        return ["?"]
    return sorted(e[0] for e in entries if len(e) >= 4 and user in e[3].split(","))


def local_group(name: str, group_file: str = GROUP_FILE) -> Optional[int]:
    """The id of a group in the local group file, never a directory service; ``None`` if
    it is missing, listed twice or is root's group under another name."""
    try:
        with open(group_file, encoding="utf-8", errors="replace") as fh:
            entries = [line.rstrip("\n").split(":") for line in fh]
    except OSError:
        return None
    ids = [int(e[2]) for e in entries if len(e) >= 3 and e[0] == name and e[2].isdigit()]
    if len(ids) != 1 or ids[0] == 0:
        return None
    return ids[0]


def package_manager() -> str:
    """``apt`` or ``dnf`` by the program that exists; selects hint commands."""
    for name, program in PACKAGE_MANAGERS:
        if os.path.lexists(program):
            return name
    return ""


def render_settings(settings: config.Config, now: int, manager: str) -> RenderSettings:
    """What ``render.json`` carries: everything the renderer needs instead of ``/etc/motp``
    (D22), the resolved look with any admin font's glyphs included (D35)."""
    layout: Layout = settings.layout
    return RenderSettings(
        generated=now,
        layout=layout,
        language=settings.general.language,
        thresholds=dict(settings.thresholds),
        timer_period=TIMER_PERIOD,
        render_ms=settings.limits.render_ms,
        package_manager=manager,
        look=settings.look,
    )


# --- turning a process outcome into a module result -------------------------------------


def classified(items: Sequence[Item], rules: Mapping[str, Rule]) -> tuple[Item, ...]:
    """Each item with a rule gets the status its value has under the current rules; an
    unknown rule gives ``unknown``. Items without a rule keep the probe's status."""
    out = []
    for item in items:
        if item.rule is not None:
            rule = rules.get(item.rule)
            item = replace(item, status=classify(item.value, rule) if rule else Status.UNKNOWN)
        out.append(item)
    return tuple(out)


def plugin_ran(outcome: proc.Result) -> bool:
    """A plugin ended by itself with one of the four codes of D26, within its limits."""
    return (
        not outcome.timed_out
        and not outcome.stdout_overflow
        and outcome.returncode in probe.STATUS_BY_EXIT_CODE
    )


def failure_reason(outcome: proc.Outcome) -> MessageRef:
    """Why a probe that ran (or was meant to) gave no usable document."""
    if outcome is None:
        return ref("collect.error.budget")
    if isinstance(outcome, proc.ProcError):
        return outcome.message
    if outcome.timed_out:
        return ref("collect.error.timeout")
    if outcome.stdout_overflow:
        return ref("collect.error.too_large")
    return ref("collect.error.exit", code=-1 if outcome.returncode is None else outcome.returncode)


def settle(
    p: Probe,
    outcome: proc.Outcome,
    previous: Optional[store.Entry],
    now: int,
    rules: Mapping[str, Rule],
    users: Optional[dict[str, tuple[UserLogins, ...]]] = None,
) -> ModuleResult:
    """The module's result after this run: fresh items, or the last good ones.

    The per-user data of an accepted ``os_login`` document goes into ``users``.
    """
    duration = None
    if isinstance(outcome, proc.Result):
        duration = min(int(outcome.duration * 1000), cache.MAX_DURATION_MS)
        if p.in_unit:
            outcome = plugins.from_shim(outcome)
    error: Optional[MessageRef] = None
    code = outcome.returncode if isinstance(outcome, proc.Result) else None
    if p.plugin and isinstance(outcome, proc.Result) and code is not None and plugin_ran(outcome):
        try:
            doc = probe.validate_plugin(outcome.stdout, code, p.name, p.public)
        except ContractError as exc:
            error = exc.message
        else:
            return ModuleResult(
                collected=now,
                interval=p.interval,
                max_age=p.max_age,
                items=admin_only(p, classified(doc.items, rules)),
                state=ModuleState.OK,
                duration_ms=duration,
            )
    elif isinstance(outcome, proc.Result) and outcome.ok and not p.plugin:
        try:
            doc = probe.validate_builtin(outcome.stdout, p.name, p.visibility, generated=now)
        except ContractError as exc:
            error = exc.message
        else:
            # Per-user data counts only from the module's own root probe (D32).
            if users is not None and doc.users is not None and p.user == ROOT_USER:
                users[p.name] = doc.users
            return ModuleResult(
                collected=now,
                interval=p.interval,
                max_age=p.max_age,
                items=classified(doc.items, rules),
                state=ModuleState.OK,
                duration_ms=duration,
            )
    if error is None:
        error = failure_reason(outcome)
    return replace(refused_result(p, error, previous, now, rules), duration_ms=duration)


def refused_result(
    p: Probe,
    reason: MessageRef,
    previous: Optional[store.Entry],
    now: int,
    rules: Mapping[str, Rule],
) -> ModuleResult:
    """A probe that was never started: failed with ``reason``, with the last good items."""
    old = previous.result if previous is not None else None
    return ModuleResult(
        collected=old.collected if old is not None else now,
        interval=p.interval,
        max_age=p.max_age,
        items=admin_only(p, classified(old.items, rules)) if old is not None else (),
        state=ModuleState.FAILED,
        error=reason,
    )


# --- the run ----------------------------------------------------------------------------


class Heartbeat:
    """A status line at least every ``interval`` seconds while probes run (counts only)."""

    def __init__(self, log: Log, total: int, interval: float, clock: Callable[[], float]) -> None:
        self.log = log
        self.total = total
        self.interval = interval
        self.clock = clock
        self.started = clock()
        self.last = self.started
        self.done = 0
        self.failed = 0
        self.running = 0

    def tick(self) -> None:
        now = self.clock()
        if now - self.last >= self.interval:
            self.last = now
            self.log.line(
                "collect.log.progress",
                done=self.done,
                total=self.total,
                failed=self.failed,
                elapsed=int(now - self.started),
            )


class Collector:
    """One collector run. ``probes`` replaces the built-in modules (tests); ``None`` builds
    them from the registry."""

    def __init__(
        self,
        paths: Paths = Paths(),
        *,
        probes: Optional[Sequence[Probe]] = None,
        modules: Optional[Sequence[Module]] = None,
        interpreter: str = sys.executable,
        program: Optional[str] = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        log: Optional[Log] = None,
        heartbeat: float = HEARTBEAT_SECONDS,
        pool: int = POOL_SIZE,
        cgroup_procs: Optional[str] = None,
        blind: Optional[bool] = None,
        systemd_run: Optional[str] = None,
    ) -> None:
        self.paths = paths
        self.fixed_probes = probes
        self.modules = registry.cached_modules() if modules is None else tuple(modules)
        self.interpreter = interpreter
        self.program = program
        self.clock = clock
        self.wall = wall
        self.log = log if log is not None else Log()
        self.heartbeat = heartbeat
        self.pool = pool
        # Inside the unit: the cleanup kills by control group (works under hidepid).
        self.cgroup_procs = cgroup_procs
        self.blind = proc.process_view_hidden() if blind is None else blind
        # Inside the unit: every plugin runs in a transient unit through this program.
        self.systemd_run = systemd_run
        self.stderr: dict[str, Optional[tuple[str, ...]]] = {}
        self.users: dict[str, tuple[UserLogins, ...]] = {}

    # -- setup -------------------------------------------------------------------------

    def _probes(self, settings: config.Config, now: int) -> list[Probe]:
        refused: Optional[MessageRef] = None
        launch: Optional[tuple[str, str]] = None
        try:
            check_search_path()
            launch = check_launch(
                self.interpreter, self.program if self.program is not None else program_path()
            )
        except ContractError as exc:
            refused = exc.message
            if self.fixed_probes is None:
                self.log.line("collect.log.refused", reason=self.log.reason(exc.message))
        if self.fixed_probes is not None:
            return list(self.fixed_probes)
        probes = builtin_probes(choose(self.modules, settings, now), settings, launch, refused)
        found = plugins.discover(self.paths.config_root, settings)
        if found:
            self.log.line(
                "collect.log.plugins",
                accepted=sum(1 for f in found if f.state == plugins.ACCEPTED),
                refused=sum(1 for f in found if f.state == plugins.REFUSED),
                ignored=sum(1 for f in found if f.state == plugins.IGNORED),
            )
        run = self._systemd_run() if any(plugins.runnable(f) for f in found) else None
        return probes + plugin_probes(found, launch, refused, run)

    def _systemd_run(self) -> Optional[str]:
        """``systemd-run``, checked as a program root runs, when plugins get units of
        their own; ``""`` (refuse every plugin) when it is missing or unsafe there."""
        if self.systemd_run is None:
            return None
        try:
            return safepath.check_program(self.systemd_run, runs_as_root=True).path
        except ContractError as exc:
            self.log.line("collect.log.no_systemd_run", reason=self.log.reason(exc.message))
            return ""

    def _drop(self, user: str) -> Optional[proc.Drop]:
        """The drop for a probe user; raises ``ContractError`` when the account is unusable."""
        if user == ROOT_USER:
            return None
        drop = proc.account(user, self.paths.accounts_file, self.paths.login_defs)
        if local_group(user, self.paths.group_file) != drop.gid:
            # The primary group must be the account's own (phase 7): a probe user in
            # ``disk``, ``docker`` or ``shadow`` would hand that group to every probe.
            raise contract_error("collect.error.account_group", user=user)
        if user == PLUGIN_USER and supplementary_groups(user, self.paths.group_file):
            # Security review of phase 14: inside its transient unit, systemd's User= gives a
            # plugin every supplementary group of the account (initgroups), unlike the drop
            # with extra_groups=[] (4.9, T9). An admin who adds motp-plugin to adm or docker
            # would hand that group to every plugin; refuse them instead.
            raise contract_error("collect.error.account_groups", user=user)
        return drop

    def _admin_gid(self, settings: config.Config) -> int:
        name = settings.visibility.admin_group
        if not name:
            return store.ROOT
        gid = local_group(name, self.paths.group_file)
        if gid is None:
            self.log.line("collect.log.no_group", group=name)
            return store.ROOT  # root only, never wider
        for user in (BUILTIN_USER, PLUGIN_USER):
            try:
                drop = proc.account(user, self.paths.accounts_file, self.paths.login_defs)
            except ContractError:
                continue
            if drop.gid == gid:  # probes or plugins would read admin.json
                self.log.line("collect.log.probe_group", group=name, user=user)
                return store.ROOT
        return gid

    # -- the run -----------------------------------------------------------------------

    def run(self) -> int:
        try:
            # Orphaned descendants of probes come back here, so the cleanup can tell them
            # from other processes of the same uid (4.9); without it nothing is started.
            proc.become_subreaper()
            cache_fd = store.prepare_dir(self.paths.cache_dir, store.CACHE_DIR_MODE)
        except ContractError as exc:
            self.log.line("collect.log.failed", reason=self.log.reason(exc.message))
            return EXIT_FAILED
        try:
            lock = store.acquire_lock(cache_fd)
            if lock is None:
                self.log.line("collect.log.busy")
                return EXIT_OK
            try:
                return self._locked(cache_fd)
            finally:
                os.close(lock)
        except ContractError as exc:
            self.log.line("collect.log.failed", reason=self.log.reason(exc.message))
            return EXIT_FAILED
        finally:
            os.close(cache_fd)

    def _locked(self, cache_fd: int) -> int:
        started = self.clock()
        user_fd = store.subdir(cache_fd, store.USER_DIR, store.USER_DIR_MODE, "user")
        os.close(user_fd)
        state_fd = store.prepare_dir(self.paths.state_dir, store.STATE_DIR_MODE)
        try:
            loaded = config.load(self.paths.config_root)
            if loaded.problems:
                self.log.line("collect.log.config", count=len(loaded.problems))
            settings = loaded.config
            now = int(self.wall())
            stop_at = started + settings.limits.collect_total_s
            state = store.read_state(state_fd)
            present = self._present(cache_fd)
            probes = self._probes(settings, now)
            due = [p for p in probes if self._due(p, state.get(p.name), present, now)]
            self.stderr = {}
            self.users = {}
            results, attempted = self._execute(due, state, now, stop_at, settings.thresholds)
            entries = self._entries(probes, results, attempted, state, settings.thresholds, now)
            self._write_users(cache_fd, probes, entries)
            hidden = {p.name for p in probes if p.plugin and not p.public}
            self._write(cache_fd, state_fd, entries, settings, now, hidden, loaded.ignored)
            self._write_stderr(state_fd, entries, now)
            if settings.general.mode == STATIC_MODE:
                self._write_static(now)
        finally:
            os.close(state_fd)
        failed = sum(1 for e in entries.values() if e.result.state is ModuleState.FAILED)
        self.log.line(
            "collect.log.done",
            ran=len(results),
            modules=len(entries),
            failed=failed,
            elapsed_ms=int((self.clock() - started) * 1000),
        )
        return EXIT_OK

    def _present(self, cache_fd: int) -> set[str]:
        """Modules the current ``admin.json`` holds; none if it is missing or broken."""
        path = f"/proc/self/fd/{cache_fd}/{store.ADMIN_NAME}"
        try:
            return set(cache.read_tier_file(path, cache.ADMIN, store.ROOT).modules)
        except ContractError:
            return set()

    @staticmethod
    def _due(p: Probe, entry: Optional[store.Entry], present: set[str], now: int) -> bool:
        """Due when the interval has passed since the last attempt, when the cache lacks
        the module, or when the state does not know it; a clock that went back counts as
        due too.

        The interval is met within a slack of a tenth of it (at most a minute): a timer
        or cron run that starts a moment earlier than the last one must not skip a module
        whose interval equals the timer period, or it would refresh every other run.
        """
        if entry is None or p.name not in present:
            return True
        slack = min(DUE_SLACK_MAX, p.interval // 10)
        return not 0 <= now - entry.attempted < p.interval - slack

    def _execute(
        self,
        due: Sequence[Probe],
        state: Mapping[str, store.Entry],
        now: int,
        stop_at: float,
        rules: Mapping[str, Rule],
    ) -> tuple[dict[str, ModuleResult], set[str]]:
        """Start the due probes; return each one's result and the names that were tried."""
        results: dict[str, ModuleResult] = {}
        attempted: set[str] = set()
        startable: list[tuple[Probe, proc.Spec]] = []
        drops: dict[str, Optional[proc.Drop]] = {}
        for p in due:
            refusal = p.refused
            if refusal is None and p.user not in drops:
                try:
                    drops[p.user] = self._drop(p.user)
                except ContractError as exc:
                    self.log.line(
                        "collect.log.account", user=p.user, reason=self.log.reason(exc.message)
                    )
                    drops[p.user] = None
                    refusal = ref("collect.error.no_account", user=p.user)
            if refusal is None and p.user != ROOT_USER and drops.get(p.user) is None:
                refusal = ref("collect.error.no_account", user=p.user)
            if refusal is not None:
                results[p.name] = refused_result(p, refusal, state.get(p.name), now, rules)
                attempted.add(p.name)
                continue
            # A plugin in its own unit may take the time systemd-run and the shim add.
            longest = MAX_PROBE_TIMEOUT + (units.PLUGIN_SLACK if p.in_unit else 0.0)
            timeout = min(max(p.timeout, MIN_PROBE_TIMEOUT), longest)
            if p.plugin:
                spec = proc.Spec(
                    argv=p.argv,
                    timeout=timeout,
                    env=plugins.plugin_env(timeout),
                    # In its own unit systemd sets the user; here runs systemd-run, as root.
                    drop=None if p.in_unit else drops.get(p.user),
                    limits=plugins.PLUGIN_LIMITS,
                    stdout_cap=probe.MAX_DOCUMENT_BYTES,
                )
                startable.append((p, spec))
                continue
            env = {child.TIMEOUT_VARIABLE: str(timeout)}
            if p.config:
                env[child.CONFIG_VARIABLE] = p.config
            per_user = p.name in probe.PER_USER_MODULES
            spec = proc.Spec(
                argv=p.argv,
                timeout=timeout,
                env=env,
                drop=drops.get(p.user),
                stdout_cap=probe.PER_USER_DOCUMENT_BYTES if per_user else probe.MAX_DOCUMENT_BYTES,
            )
            startable.append((p, spec))

        builtin = [(p, s) for p, s in startable if not p.plugin]
        plugin_batch = [(p, s) for p, s in startable if p.plugin]
        users = {p.user for p, _ in builtin if p.user != ROOT_USER}
        beat = Heartbeat(self.log, len(startable), self.heartbeat, self.clock)

        def stage(batch: Sequence[tuple[Probe, proc.Spec]], parallel: int) -> None:
            def done(index: int, outcome: proc.Outcome) -> None:
                p = batch[index][0]
                if outcome is not None:
                    attempted.add(p.name)
                result = settle(p, outcome, state.get(p.name), now, rules, self.users)
                results[p.name] = result
                beat.done += 1
                if result.state is ModuleState.FAILED:
                    beat.failed += 1
                kept = None
                if result.state is ModuleState.FAILED and isinstance(outcome, proc.Result):
                    kept = errlog.lines_of(outcome.stderr)
                self.stderr[p.name] = kept

            proc.run_many(
                [s for _, s in batch],
                parallel,
                stop_at=stop_at,
                clock=self.clock,
                on_done=done,
                on_tick=beat.tick,
            )
            for index, (p, _spec) in enumerate(batch):
                if p.name not in results:  # the budget ran out before its turn
                    done(index, None)

        stage(builtin, self.pool)
        if BUILTIN_USER in users and not self._cleanup(drops.get(BUILTIN_USER), BUILTIN_USER):
            self._unclean(results, [p for p, _ in builtin if p.user == BUILTIN_USER])

        # Plugins: one at a time, each checked again right before its start. Inside the
        # unit each runs in a transient unit of its own, which ends with it (its /tmp, IPC
        # and processes too); here, without the unit, its processes are ended afterwards.
        plugin_drop = drops.get(PLUGIN_USER)
        for p, spec in plugin_batch:
            refusal = plugins.recheck(self.paths.config_root, p.found) if p.found else None
            if refusal is not None:
                results[p.name] = refused_result(p, refusal, state.get(p.name), now, rules)
                attempted.add(p.name)
                beat.done += 1
                beat.failed += 1
                continue
            stage([(p, spec)], 1)
            if p.name in attempted and not self._cleanup_plugin(p, plugin_drop):
                self._unclean(results, [p])
        proc.reap_children()  # the zombies of ended orphans are ours as subreaper
        return results, attempted

    def _cleanup_plugin(self, p: Probe, drop: Optional[proc.Drop]) -> bool:
        """End what a plugin left behind. In its own unit nothing of it ran here; without
        the unit, by ``/proc`` among this collector's descendants (of root, for a root
        plugin), or by the control group when one is given."""
        if p.in_unit:
            return True
        if p.user == PLUGIN_USER:
            return self._cleanup(drop, PLUGIN_USER)
        if self.cgroup_procs is not None:
            outcome = proc.cleanup_cgroup(self.cgroup_procs)
        elif self.blind:
            self.log.line("collect.log.hidden", user=ROOT_USER)
            return False
        else:
            outcome = proc.cleanup_root_descendants(os.getpid())
        proc.reap_children()
        if not outcome.clean:
            self.log.line("collect.log.cleanup", user=ROOT_USER, remaining=outcome.remaining)
        return outcome.clean

    def _cleanup(self, drop: Optional[proc.Drop], user: str) -> bool:
        """End what the probes of ``user`` left behind; only this collector's own
        descendants, never another workload that shares the uid. True when clean."""
        if drop is None:
            return True
        if self.cgroup_procs is not None:
            outcome = proc.cleanup_cgroup(self.cgroup_procs)
        elif self.blind:
            # /proc hides the probe users' processes: a cleanup by /proc would find
            # nothing and call the run clean. Fail the stage's modules instead.
            self.log.line("collect.log.hidden", user=user)
            return False
        else:
            outcome = proc.cleanup_user(drop, ancestor=os.getpid())
        proc.reap_children()
        if not outcome.clean:
            self.log.line("collect.log.cleanup", user=user, remaining=outcome.remaining)
        return outcome.clean

    @staticmethod
    def _unclean(results: dict[str, ModuleResult], probes: Sequence[Probe]) -> None:
        """Processes survived the cleanup (phase 3 note): the modules of that stage
        count as failed, with their items, and the log already says how many remain."""
        for p in probes:
            result = results.get(p.name)
            if result is not None and result.state is ModuleState.OK:
                results[p.name] = replace(
                    result, state=ModuleState.FAILED, error=ref("collect.error.cleanup")
                )

    @staticmethod
    def _entries(
        probes: Sequence[Probe],
        results: Mapping[str, ModuleResult],
        attempted: set[str],
        state: Mapping[str, store.Entry],
        rules: Mapping[str, Rule],
        now: int,
    ) -> dict[str, store.Entry]:
        """The state after the run: every current probe, run or carried; modules that are
        gone (disabled, no longer detected) are dropped. A probe the budget never reached
        keeps its old attempt time, so it is due again at the next run."""
        entries: dict[str, store.Entry] = {}
        for p in probes:
            old = state.get(p.name)
            if p.name in results:
                when = now if p.name in attempted else (old.attempted if old else 0)
                entries[p.name] = store.Entry(when, results[p.name])
            elif old is not None:
                carried = replace(
                    old.result,
                    interval=p.interval,
                    max_age=p.max_age,
                    items=admin_only(p, classified(old.result.items, rules)),
                )
                entries[p.name] = store.Entry(old.attempted, carried)
        return entries

    def _write_users(
        self, cache_fd: int, probes: Sequence[Probe], entries: dict[str, store.Entry]
    ) -> None:
        """The per-user files (D32 as amended), before the tier files so a refusal shows.

        * ``os_login`` delivered its accounts this run: each gets its file, every other
          file in ``user/`` is removed (removed accounts, logins grown too old).
        * ``os_login`` is not among the probes (disabled, not detected): every file goes.
        * It did not run or failed: the files stay as they are.

        Where the file system refuses POSIX ACLs, no per-user file is kept at all and
        ``os_login`` is marked failed with that reason, which ``motp doctor`` shows.
        """
        if any(p.name == LOGIN_MODULE for p in probes):
            accounts = self.users.get(LOGIN_MODULE)
            if accounts is None:
                return
        else:
            accounts = ()
        user_fd = store.subdir(cache_fd, store.USER_DIR, store.USER_DIR_MODE, "user")
        try:
            kept: set[str] = set()
            failed = 0
            for user in accounts:
                try:
                    store.write_user_file(user_fd, user)
                except store.AclUnsupported as exc:
                    store.prune_user_files(user_fd, set())
                    entry = entries.get(LOGIN_MODULE)
                    if entry is not None:
                        refused = replace(
                            entry.result, items=(), state=ModuleState.FAILED, error=exc.message
                        )
                        entries[LOGIN_MODULE] = store.Entry(entry.attempted, refused)
                    self.log.line("collect.log.user_acl")
                    return
                except ContractError:
                    failed += 1
                    continue
                kept.add(store.user_file_name(user.uid))
            removed = store.prune_user_files(user_fd, kept)
            self.log.line(
                "collect.log.user_files", written=len(kept), failed=failed, removed=removed
            )
        finally:
            os.close(user_fd)

    def _write(
        self,
        cache_fd: int,
        state_fd: int,
        entries: Mapping[str, store.Entry],
        settings: config.Config,
        now: int,
        hidden: Collection[str] = frozenset(),
        config_ignored: int = 0,
    ) -> None:
        """The three cache files and the state. ``hidden`` names the admin-only plugins:
        their failures are not counted in ``public.json`` either, so a reader who cannot
        see a plugin does not learn that one failed (D27, 5.4). ``config_ignored``, the
        number of config files the loader ignored, goes to ``admin.json`` only."""
        modules = {name: e.result for name, e in entries.items()}
        failed = sum(1 for r in modules.values() if r.state is ModuleState.FAILED)
        public_failed = sum(
            1 for n, r in modules.items() if r.state is ModuleState.FAILED and n not in hidden
        )
        admin_gid = self._admin_gid(settings)
        files = (
            (
                store.RENDER_NAME,
                cache.encode_render_file(render_settings(settings, now, package_manager())),
                store.RENDER_MODE,
                store.ROOT,
            ),
            (
                store.ADMIN_NAME,
                cache.encode_tier_file(cache.ADMIN, now, modules, failed, config_ignored),
                store.ADMIN_MODE,
                admin_gid,
            ),
            (
                store.PUBLIC_NAME,
                cache.encode_tier_file(cache.PUBLIC, now, modules, public_failed),
                store.PUBLIC_MODE,
                store.ROOT,
            ),
        )
        for name, data, mode, gid in files:
            store.write_atomic(cache_fd, name, data, mode=mode, uid=store.ROOT, gid=gid)
        store.write_atomic(
            state_fd,
            store.STATE_NAME,
            store.encode_state(now, dict(entries)),
            mode=store.STATE_MODE,
            uid=store.ROOT,
            gid=store.ROOT,
            sync_dir=True,
        )

    def _write_static(self, now: int) -> None:
        """Static mode (4.10, D7): the public message, rendered once for every reader, in
        ``/run/motd.d`` for pam_motd. A failure here is logged and ends nothing else; the
        previous file is removed then, so pam_motd never keeps showing an old state (an
        old "no updates" would mislead every reader; phase 8 security review)."""
        try:
            data = static_text(self.paths.cache_dir, now, os.environ)
        except ContractError as exc:
            self.log.line("collect.log.static", reason=self.log.reason(exc.message))
            self._drop_static()
            return
        except Exception as exc:  # a render bug must not fail the run (T11: type only)
            self.log.line("collect.log.static_crashed", kind=type(exc).__name__)
            self._drop_static()
            return
        try:
            dir_fd = store.open_shared_dir(self.paths.motd_dir, store.MOTD_DIR_MODE)
            try:
                store.write_atomic(
                    dir_fd,
                    store.MOTD_NAME,
                    data,
                    mode=store.MOTD_MODE,
                    uid=store.ROOT,
                    gid=store.ROOT,
                )
            finally:
                os.close(dir_fd)
        except ContractError as exc:
            self.log.line("collect.log.static", reason=self.log.reason(exc.message))

    def _drop_static(self) -> None:
        """Remove the static file if it is there, through a checked directory."""
        if not os.path.isdir(self.paths.motd_dir):
            return
        try:
            dir_fd = store.open_shared_dir(self.paths.motd_dir, store.MOTD_DIR_MODE)
        except ContractError:
            return
        try:
            with contextlib.suppress(OSError):
                store.remove(dir_fd, store.MOTD_NAME)
        finally:
            os.close(dir_fd)

    def _write_stderr(self, state_fd: int, entries: Mapping[str, store.Entry], now: int) -> None:
        """The root-only stderr log of failed probes (T11); a log failure ends nothing."""
        merged = errlog.merge(errlog.read(state_fd), self.stderr, entries.keys(), now)
        try:
            store.write_atomic(
                state_fd,
                errlog.NAME,
                errlog.encode(merged),
                mode=errlog.MODE,
                uid=store.ROOT,
                gid=store.ROOT,
            )
        except ContractError as exc:
            self.log.line("collect.log.stderr_log", reason=self.log.reason(exc.message))


def static_env(env: Mapping[str, str]) -> dict[str, str]:
    """The environment the static text is rendered with: the system locale the collector
    was started with (systemd passes it to services), and never colour, whatever the
    config says, since pam_motd prints the file to every kind of terminal."""
    out = {k: env[k] for k in STATIC_LOCALE_KEYS if k in env}
    out["MOTP_COLOR"] = "never"
    return out


def check_static(text: str) -> bytes:
    """The bytes of the static file. Every line feed is kept; any other control character
    (an escape byte above all) means the text is not plain, and nothing is written."""
    for ch in text:
        code = ord(ch)
        if ch != "\n" and (code < 0x20 or 0x7F <= code < 0xA0):
            raise contract_error("collect.error.static_control")
    return text.encode("utf-8")


def static_text(cache_dir: str, now: int, env: Mapping[str, str]) -> bytes:
    """The public message as the static file holds it (4.6): 80 columns, no colour, the
    public tier only, no per-user line, ASCII unless the config asks for Unicode. The
    language follows the config, else the system locale in ``env``."""
    from motp import render, show
    from motp.modules.base import Context

    inp = show.build_input(
        Context(now=now),
        cache_dir=cache_dir,
        owner=store.ROOT,
        login=False,
        uid=None,
        env=static_env(env),
        notes=show.Notes(),
        public_only=True,
    )
    return check_static(render.render_static(inp))


def main(no_sandbox: bool, out: Optional[TextIO] = None, in_unit: bool = False) -> int:
    """``motp collect``, as root (4.11).

    The unit starts ``collect --in-unit``, which runs the collection. Typed by an admin,
    ``collect`` starts the unit, so the run gets the sandbox and not the admin's shell
    environment, and prints the result (``viaunit``). ``--no-sandbox`` runs here, for cron,
    containers and debugging.

    Inside the unit the cleanup kills by the unit's control group when it is the exact
    ``/system.slice`` group on cgroup v2; elsewhere (cgroup v1, ``--no-sandbox``) by
    ``/proc``, failing closed when ``/proc`` hides the probe users' processes.

    An unexpected exception is logged as one line with its type only: a traceback would
    put paths and values into the journal, which ``adm`` and ``wheel`` read (T11).
    """
    log = Log(out if out is not None else sys.stderr)
    if os.geteuid() != 0:
        log.line("collect.error.not_root")
        return EXIT_FAILED
    if not (in_unit or no_sandbox):
        from motp.collect import viaunit

        return viaunit.main()
    try:
        os.umask(0o077)
        os.chdir("/")
        cgroup = proc.service_cgroup_procs(UNIT_NAME) if in_unit else None
        # Inside the unit every plugin gets a transient unit of its own (phase 12); with
        # --no-sandbox there is no sandbox for anything, and plugins run here directly.
        run = units.SYSTEMD_RUN if in_unit else None
        return Collector(log=log, cgroup_procs=cgroup, systemd_run=run).run()
    except Exception as exc:
        log.line("collect.log.crashed", kind=type(exc).__name__)
        return EXIT_FAILED

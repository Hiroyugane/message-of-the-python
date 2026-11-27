"""Exec plugins: discovery, validation and the shim (blueprint 4.9, D10, D21, D26, D27).

A plugin is an executable file in ``/etc/motp/plugins.d`` (any language) that prints one
line or one JSON document (D26, ``core.probe.validate_plugin``). This module decides which
files run and how; ``collect.runner`` starts them after the built-in probes, one at a time.

Discovery (``discover``), at the start of every run and again for ``motp doctor``:

* The directory must pass the ownership check (root's, its whole chain writable by root
  only). Otherwise every plugin in it is refused with that reason.
* A name must match ``NN-name`` (two digits, a dash, lower-case letters, digits, ``-``
  and ``_``; ``core.probe.PLUGIN_NAME``). Other names are ignored, never run, and listed by
  ``motp doctor`` (editor backups, ``.dpkg-old`` files, a ``README``).
* At most ``MAX_PLUGINS`` names that match are looked at, the first by name; the rest
  are refused, get no row and are listed by ``motp doctor`` only (``runnable``).
* Each file goes through ``safepath.check_program``: root's, not writable by group or
  others, every directory above it and every link on the way root's, an execute bit, no
  setuid or setgid bit, ELF or a ``#!`` line (``known_format``), and the interpreter on
  that line checked the same way, recursively. A plugin the config grants root
  (``run_as = "root"``) also may not name a launcher such as ``env`` (T21), and if its
  interpreter is Python, every directory that interpreter imports from must pass the same
  check (``core.importpath``, final review).
* What runs is the real path the check resolved. The file is checked again right before
  it starts (``recheck``). Between the check and ``exec`` only root can change any part of
  the chain, so a check-then-run race needs root already.

A plugin runs as ``motp-plugin`` unless its config table says ``run_as = "root"``. Inside
the collector unit no plugin runs in the unit itself: the collector starts each one in a
transient unit of its own (``systemd-run``, properties in ``install.units``), with its own
``/tmp``, ``/var/tmp``, ``/dev/shm``, IPC namespace, task and memory limit, a read-only
file system and ``/run``, and ``/run/motp`` and ``/var/lib/motp`` hidden; a root plugin
there also loses every capability but ``CAP_DAC_READ_SEARCH`` and the sockets of the
service manager and the container runtimes. So nothing one plugin leaves reaches the
next, and no root plugin can rewrite the cache or put a file in front of pam_motd (phase 8
issue). The unit runs ``motp _plugin <name>`` (``shim_main``), which checks the plugin
again, runs it with the plugin limits and reports its outcome through its own exit code
(``SHIM_*``), since ``systemd-run`` gives back the service's exit code but uses 1 for its
own failures. Without the collector unit (cron, ``--no-sandbox``) plugins run directly.
"""

import math
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import BinaryIO, Optional, Union

from motp.core import config, importpath, proc, safepath
from motp.core.model import ContractError, MessageRef, contract_error, ref
from motp.core.probe import MAX_DOCUMENT_BYTES, PLUGIN_NAME

DIR_NAME = "plugins.d"
MAX_PLUGINS = 32  # 4.9
MAX_ENTRIES = 1024  # names looked at in the directory; more is refused as a whole
PLUGIN_USER = "motp-plugin"
ROOT_USER = "root"
ACCEPTED = "accepted"
REFUSED = "refused"
IGNORED = "ignored"
MIN_TIMEOUT = 0.5
MAX_TIMEOUT = 30.0  # 4.14
DEFAULT_TIMEOUT = 5.0
API_VARIABLE = "MOTP_PLUGIN_API"
TIMEOUT_VARIABLE = "MOTP_TIMEOUT"
API_VERSION = "1"
NAME_CELLS = 64
LINE_END = b"\n"
ID_ENCODING = "ascii"  # message ids are ASCII by their pattern

# What a plugin process gets (4.9, T9, T23): CPU time up to the longest time limit, files
# of at most 1 MiB, 64 processes of its user, 64 open files, no POSIX message queue (a
# queue could not be found and removed afterwards), and the highest out-of-memory score,
# so at the unit's MemoryMax the kernel ends the plugin and not the collector.
PLUGIN_LIMITS = proc.Limits(
    cpu_seconds=int(MAX_TIMEOUT),
    file_bytes=1024 * 1024,
    processes=64,
    open_files=64,
    msgqueue=0,
    oom_score_adj=proc.OOM_SCORE_MAX,
)

# The shim's exit codes. ``systemd-run --wait`` exits with the service's own exit code,
# and with 1 (or a code of systemd's own, 200 and up) when it or the unit failed; these
# stay clear of both.
SHIM_BASE = 100  # 100 + the plugin's exit code, for codes 0 to SHIM_MAX_CODE
SHIM_MAX_CODE = 89
SHIM_HIGH = 190  # the plugin exited with a code above SHIM_MAX_CODE
SHIM_SIGNAL = 191
SHIM_TIMEOUT = 192
SHIM_OVERFLOW = 193
SHIM_REFUSED = 194  # the plugin failed the check inside the unit
SHIM_START = 195


@dataclass(frozen=True)
class Found:
    """One entry of the plugin directory and what becomes of it.

    ``path`` is the real path that runs (accepted plugins only); ``reason`` says why a
    plugin was refused or a name ignored.
    """

    name: str
    state: str  # ACCEPTED, REFUSED or IGNORED
    reason: Optional[MessageRef] = None
    path: str = ""
    run_as: str = PLUGIN_USER
    timeout: float = DEFAULT_TIMEOUT
    public: bool = False


def directory(config_root: str) -> str:
    return config_root.rstrip("/") + "/" + DIR_NAME


def plugin_timeout(settings: config.Config, name: str) -> float:
    """The plugin's ``timeout_s``, else ``limits.probe_timeout_s``, within 0.5 to 30 s."""
    own = settings.plugin(name).timeout_s
    chosen = own if own is not None else settings.limits.probe_timeout_s
    return min(max(chosen, MIN_TIMEOUT), MAX_TIMEOUT)


def plugin_env(timeout: float) -> dict[str, str]:
    """The ``MOTP_*`` part of a plugin's environment; ``core.proc`` adds ``PATH`` and
    ``LC_ALL`` and nothing else (4.9)."""
    return {TIMEOUT_VARIABLE: f"{timeout:g}", API_VARIABLE: API_VERSION}


def validate(path: str, run_as: str) -> safepath.Program:
    """The checks of the module docstring for one file; raises ``ContractError``."""
    program = safepath.check_program(path, runs_as_root=run_as == ROOT_USER, known_format=True)
    if run_as == ROOT_USER:
        importpath.check_program(program)
    return program


def _names(path: str) -> list[str]:
    with os.scandir(path) as entries:
        names = []
        for entry in entries:
            names.append(entry.name)
            if len(names) > MAX_ENTRIES:
                raise contract_error("plugin.error.too_many_entries", max=MAX_ENTRIES)
    return sorted(names)


def discover(config_root: str, settings: config.Config) -> list[Found]:
    """Every entry of the plugin directory with its state; none when it does not exist."""
    where = directory(config_root)
    if not os.path.lexists(where):
        return []
    refusal: Optional[MessageRef] = None
    try:
        real = safepath.check_directory(where)
    except ContractError as exc:
        refusal, real = exc.message, where
    try:
        names = _names(real)
    except ContractError as exc:
        return [Found(DIR_NAME, REFUSED, exc.message)]
    except OSError:
        return [Found(DIR_NAME, REFUSED, ref("plugin.error.unreadable_dir"))]
    found: list[Found] = []
    counted = 0
    for name in names:
        if not PLUGIN_NAME.match(name):
            found.append(Found(name, IGNORED, ref("plugin.ignored.name")))
            continue
        counted += 1
        own = settings.plugin(name)
        base = Found(
            name,
            REFUSED,
            run_as=own.run_as,
            timeout=plugin_timeout(settings, name),
            public=own.visibility == "public",
        )
        if counted > MAX_PLUGINS:
            found.append(replace(base, reason=ref("plugin.error.too_many", max=MAX_PLUGINS)))
            continue
        if refusal is not None:
            found.append(replace(base, reason=refusal))
            continue
        try:
            program = validate(real + "/" + name, own.run_as)
        except ContractError as exc:
            found.append(replace(base, reason=exc.message))
            continue
        found.append(replace(base, state=ACCEPTED, path=program.path))
    return found


def runnable(found: Found) -> bool:
    """Whether an entry becomes a module of the collector run (and so a row, run or
    failed): the first ``MAX_PLUGINS`` names that match the pattern, accepted or refused.
    Ignored names, names past the limit and a refusal of the whole directory get none,
    so the cache never holds more modules than it can (``cache.MAX_MODULES``); ``motp
    doctor`` lists them all."""
    if found.state == IGNORED or not PLUGIN_NAME.match(found.name):
        return False
    return not (found.reason is not None and found.reason.id == "plugin.error.too_many")


def recheck(config_root: str, found: Found) -> Optional[MessageRef]:
    """Check an accepted plugin again right before it starts; ``None`` when it still
    passes and resolves to the same real path, else the reason it is refused now."""
    try:
        real = safepath.check_directory(directory(config_root))
        program = validate(real + "/" + found.name, found.run_as)
    except ContractError as exc:
        return exc.message
    if program.path != found.path:
        return ref("plugin.error.changed")
    return None


# --- inside the transient unit of a root plugin ---------------------------------------


def shim_code(outcome: Union[proc.Result, ContractError]) -> int:
    """The shim's exit code for what became of the plugin."""
    if isinstance(outcome, ContractError):
        return SHIM_START
    if outcome.timed_out:
        return SHIM_TIMEOUT
    if outcome.stdout_overflow:
        return SHIM_OVERFLOW
    code = outcome.returncode
    if code is None or code < 0:
        return SHIM_SIGNAL
    return SHIM_BASE + code if code <= SHIM_MAX_CODE else SHIM_HIGH


def shim_timeout(environ: Mapping[str, str]) -> float:
    try:
        given = float(environ.get(TIMEOUT_VARIABLE, ""))
    except ValueError:
        return DEFAULT_TIMEOUT
    if not math.isfinite(given):
        return DEFAULT_TIMEOUT
    return min(max(given, MIN_TIMEOUT), MAX_TIMEOUT)


def shim_main(
    name: str,
    config_root: str = config.DEFAULT_ROOT,
    environ: Optional[Mapping[str, str]] = None,
    out: Optional[BinaryIO] = None,
    err: Optional[BinaryIO] = None,
) -> int:
    """``motp _plugin <name>``: run one plugin inside its transient unit.

    The plugin is found by name and checked again here, inside the unit, with the rules
    for the user the unit runs as (root's when it is root). Its stdout and stderr are
    passed on as they are (the collector caps and validates them), and the exit code says
    what happened (``SHIM_*``). Run by anyone else it runs the plugin as that user, no
    more than the user could do by starting the file itself.
    """
    environ = os.environ if environ is None else environ
    stdout = out if out is not None else sys.stdout.buffer
    stderr = err if err is not None else sys.stderr.buffer
    if not PLUGIN_NAME.match(name):
        return SHIM_REFUSED
    run_as = ROOT_USER if os.geteuid() == 0 else PLUGIN_USER
    try:
        real = safepath.check_directory(directory(config_root))
        program = validate(real + "/" + name, run_as)
    except ContractError as exc:
        stderr.write(exc.message.id.encode(ID_ENCODING) + LINE_END)
        stderr.flush()
        return SHIM_REFUSED
    timeout = shim_timeout(environ)
    spec = proc.Spec(
        argv=(program.path,),
        timeout=timeout,
        env=plugin_env(timeout),
        limits=PLUGIN_LIMITS,
        stdout_cap=MAX_DOCUMENT_BYTES,
    )
    outcome: Union[proc.Result, ContractError]
    try:
        outcome = proc.run(spec)
    except proc.ProcError as exc:
        outcome = exc
    if isinstance(outcome, proc.Result):
        stdout.write(outcome.stdout)
        stderr.write(outcome.stderr)
    stdout.flush()
    stderr.flush()
    return shim_code(outcome)


def from_shim(result: proc.Result) -> Union[proc.Result, proc.ProcError]:
    """What the collector makes of ``systemd-run``'s outcome for a root plugin.

    The collector's own limits (its deadline, the stdout cap) come first. Then the
    shim's exit code is turned back into the plugin's: 100 to 189 is the plugin's exit
    code plus 100, the other ``SHIM_*`` codes name what ended it, and anything else means
    the transient unit itself failed (systemd-run's message is in the kept stderr).
    """
    if result.timed_out or result.stdout_overflow:
        return result
    code = result.returncode
    if code is not None and SHIM_BASE <= code <= SHIM_BASE + SHIM_MAX_CODE:
        return replace(result, returncode=code - SHIM_BASE)
    if code == SHIM_TIMEOUT:
        return replace(result, returncode=None, timed_out=True)
    if code == SHIM_OVERFLOW:
        return replace(result, stdout_overflow=True)
    messages = {
        SHIM_HIGH: ref("collect.error.exit_high", code=SHIM_MAX_CODE + 1),
        SHIM_SIGNAL: ref("collect.error.signal"),
        SHIM_REFUSED: ref("collect.error.refused_in_unit"),
        SHIM_START: ref("proc.error.start", program="-"),
    }
    message = messages.get(code if code is not None else -1)
    if message is None:
        message = ref("collect.error.root_unit", code=-1 if code is None else code)
    return proc.ProcError(message)

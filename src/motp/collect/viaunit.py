"""``motp collect`` typed by an admin: start the collector unit and print the result (4.11).

The collection then runs inside the unit's sandbox, not in the admin's shell environment
(T2). The command waits for the one-shot unit (``systemctl start`` returns when it has
finished), reads the unit's result, and prints for the admin at the terminal what the
journal does not get (T11): the number of modules, and for each failed module its name,
its reason from ``admin.json`` and the kept stderr lines from the root-only log.

Without systemd, or before ``motp install``, there is no unit: the command says to use
``--no-sandbox`` and exits 2.
"""

import os
import sys
from typing import Optional, TextIO

from motp.collect import errlog, store
from motp.core import cache, i18n, proc, safepath
from motp.core.model import ContractError, MessageRef, ModuleState
from motp.core.sanitize import sanitize
from motp.install import units

SYSTEMCTL_CANDIDATES = ("/usr/bin/systemctl", "/bin/systemctl")
TIMEOUT = 150.0  # the unit's TimeoutStartSec plus margin
NAME_CELLS = 64
REASON_CELLS = 160

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _systemctl() -> Optional[str]:
    for path in SYSTEMCTL_CANDIDATES:
        if os.path.lexists(path):
            try:
                return safepath.check_program(path, runs_as_root=True).path
            except ContractError:
                return None
    return None


def unit_installed(marker: str = units.SYSTEMD_MARKER, unit_dir: str = units.UNIT_DIR) -> bool:
    return os.path.isdir(marker) and os.path.isfile(f"{unit_dir}/{units.SERVICE_NAME}")


def _result_word(systemctl: str) -> str:
    spec = proc.Spec(
        argv=(systemctl, "show", "--property=Result", "--value", "--", units.SERVICE_NAME),
        timeout=30.0,
    )
    outcome = proc.run(spec)
    word = outcome.stdout.decode("ascii", "replace").strip() if outcome.ok else ""
    return sanitize(word, 32) or "-"


def report(
    tr: i18n.Translator,
    out: TextIO,
    cache_dir: str = store.CACHE_DIR,
    state_dir: str = store.STATE_DIR,
) -> None:
    """Module count, and each failed module with its reason and kept stderr."""
    try:
        admin = cache.read_tier_file(f"{cache_dir}/{store.ADMIN_NAME}", cache.ADMIN, store.ROOT)
    except ContractError as exc:
        out.write(tr.compose("collect.unit.no_cache", {"reason": tr.text(exc.message)}) + "\n")
        return
    out.write(
        tr.message("collect.unit.modules", {"count": len(admin.modules), "failed": admin.failed})
        + "\n"
    )
    stderr: dict[str, errlog.Entry] = {}
    try:
        fd = os.open(state_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        fd = -1
    if fd >= 0:
        try:
            stderr = errlog.read(fd)
        finally:
            os.close(fd)
    for name, result in sorted(admin.modules.items()):
        if result.state is not ModuleState.FAILED:
            continue
        reason = tr.text(result.error) if isinstance(result.error, MessageRef) else "-"
        texts = {"module": sanitize(name, NAME_CELLS), "reason": sanitize(reason, REASON_CELLS)}
        out.write(tr.compose("collect.unit.failed_module", texts) + "\n")
        entry = stderr.get(name)
        for line in entry.lines if entry is not None else ():
            out.write("    " + sanitize(line, errlog.LINE_CELLS) + "\n")


def main(out: Optional[TextIO] = None) -> int:
    out = out if out is not None else sys.stdout
    tr = i18n.translator(i18n.language_from_env(os.environ))
    systemctl = _systemctl()
    if systemctl is None or not unit_installed():
        sys.stderr.write(tr.message("collect.error.no_unit") + "\n")
        return EXIT_USAGE
    started = proc.run(
        proc.Spec(argv=(systemctl, "start", "--", units.SERVICE_NAME), timeout=TIMEOUT)
    )
    word = _result_word(systemctl)
    out.write(tr.compose("collect.unit.finished", {"result": word}) + "\n")
    report(tr, out)
    out.flush()
    return EXIT_OK if started.ok and word == "success" else EXIT_FAILED

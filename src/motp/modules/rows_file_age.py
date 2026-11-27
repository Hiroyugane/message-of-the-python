"""``rows_file_age``: the ``[[rows.file_age]]`` config rows (D10, 4.7, 5.4, phase 12).

A row names a file and two durations; the row warns when the file has not changed for
``warn_after`` and is critical after ``crit_after``. The usual case is the stamp file a
backup job touches when it succeeded:

    [[rows.file_age]]
    path = "/var/backups/last-success"
    label = "Backup"
    warn_after = "26h"
    crit_after = "3d"

Runs as a cached module in a probe process as the user ``motp``, like ``rows_unit``. The
collector hands the rows to the probe as the module's own config (``ctx.config["rows"]``:
path, label, and both limits in seconds), which the config loader has checked; the module
checks every row again. The time comes from ``ctx.file_mtime``: ``stat`` with the rights of
``motp``, so a file in a directory ``motp`` may not enter is shown as "unreadable" rather
than looked at as root. An admin who wants such a file watched grants it, as for any
other root access: a plugin with ``run_as = "root"`` (``docs/plugins.md``).

Label and age are public (5.4, "watched files"): the admin chose to show them. The path is
never part of an item, not even of its key, so ``public.json`` holds nothing the rendered
row does not show.
"""

import posixpath
import re

from motp.core.model import ContractError, Item, Status, Unit, Visibility, ref
from motp.core.sanitize import LABEL_CELLS, sanitize
from motp.modules.base import CACHED, Context, Detection, parse_error

MAX_ROWS = 32  # config.MAX_ROWS
MAX_PATH = 4096
MAX_SECONDS = 3650 * 86400  # config.MAX_DURATION
KEY_CHARS = 40
_SLUG = re.compile(r"[^a-z0-9_-]+")


def _path_ok(path: object) -> bool:
    return (
        type(path) is str
        and path.startswith("/")
        and path != "/"
        and not path.startswith("//")
        and len(path) <= MAX_PATH
        and "\0" not in path
        and posixpath.normpath(path) == path
    )


def _seconds_ok(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_SECONDS


def rows_of(config: object) -> "list[tuple[str, str, int, int]]":
    """The rows from the module's config: checked again, at most ``MAX_ROWS``."""
    raw = config.get("rows", []) if isinstance(config, dict) else []
    if not isinstance(raw, list) or len(raw) > MAX_ROWS:
        raise parse_error("rows_file_age")
    rows = []
    for row in raw:
        if (
            not isinstance(row, list)
            or len(row) != 4
            or not _path_ok(row[0])
            or type(row[1]) is not str
            or not row[1]
            or not _seconds_ok(row[2])
            or not _seconds_ok(row[3])
            or row[3] < row[2]
        ):
            raise parse_error("rows_file_age")
        rows.append((row[0], sanitize(row[1], LABEL_CELLS), row[2], row[3]))
    return rows


def key_for(label: str, taken: "set[str]") -> str:
    """An item key from the label (never the path): ``rows_file_age.backup``, unique."""
    slug = _SLUG.sub("-", label.lower()).strip("-")[:KEY_CHARS] or "file"
    key, n = f"rows_file_age.{slug}", 2
    while key in taken:
        key, n = f"rows_file_age.{slug}-{n}", n + 1
    taken.add(key)
    return key


def status_of(age: int, warn: int, crit: int) -> Status:
    if age >= crit:
        return Status.CRIT
    if age >= warn:
        return Status.WARN
    return Status.OK


def row_item(ctx: Context, key: str, path: str, label: str, warn: int, crit: int) -> Item:
    label_ref = ref("label.file_row", label=label)
    try:
        changed = ctx.file_mtime(path)
    except ContractError as exc:
        if exc.message.id == "context.error.missing":
            return Item(key, None, Unit.SECONDS, label_ref, status=Status.CRIT,
                        text=ref("file_age.missing"))  # fmt: skip
        return Item(key, None, Unit.SECONDS, label_ref, status=Status.UNKNOWN,
                    text=ref("file_age.unreadable"))  # fmt: skip
    age = max(0, ctx.now - changed)  # a time in the future counts as just now
    return Item(key, age, Unit.SECONDS, label_ref, status=status_of(age, warn, crit))


class RowsFileAge:
    name = "rows_file_age"
    section = "services"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 1800
    timeout = 5.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        rows = ctx.config.get("rows") if isinstance(ctx.config, dict) else None
        return Detection(bool(rows))

    def collect(self, ctx: Context) -> list[Item]:
        taken: set[str] = set()
        return [
            row_item(ctx, key_for(label, taken), path, label, warn, crit)
            for path, label, warn, crit in rows_of(dict(ctx.config))
        ]

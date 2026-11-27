"""``rows_unit``: the ``[[rows.unit]]`` config rows, one per unit the admin names (D10, 5.4).

Runs as a cached module in a probe process as the user ``motp``, when the config has at
least one such row. The collector hands the rows to the probe as the module's own config
(``ctx.config["rows"]``, pairs of unit name and label), which the config loader has
checked; the module checks every name again before it reaches ``systemctl`` (a name must
fit ``services.ROW_UNIT_NAME``, so it cannot be an option), and the argument list ends
the options with ``--``:

    systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState -- NAME...

``systemctl show`` prints one block of ``key=value`` lines per name, in the order given,
with a blank line between blocks; a unit that does not exist still gets one
(``LoadState=not-found``). The order of the lines inside a block differs between systemd
releases, so they are read by key.

Label and state are public (5.4, "watched services"): the admin chose to show them.
"""

import re
from collections.abc import Sequence

from motp.core.model import HintRef, Item, Status, Unit, Visibility, ref
from motp.core.sanitize import LABEL_CELLS, sanitize
from motp.modules import services
from motp.modules.base import CACHED, Context, Detection, parse_error

PROPERTIES = "Id,LoadState,ActiveState,SubState"
MAX_ROWS = 32  # config.MAX_ROWS
ACTIVE_STATES = (
    "active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance",
    "refreshing",
)  # fmt: skip
GOOD = ("active", "reloading", "refreshing")
SUB_STATE = re.compile(r"[a-z][a-z-]{0,31}\Z")
KEY_CHARS = 40
_SLUG = re.compile(r"[^a-z0-9_-]+")


def rows_of(config: object) -> "list[tuple[str, str]]":
    """The rows from the module's config: checked again, at most ``MAX_ROWS``."""
    raw = config.get("rows", []) if isinstance(config, dict) else []
    if not isinstance(raw, list) or len(raw) > MAX_ROWS:
        raise parse_error("rows_unit")
    rows = []
    for row in raw:
        if (
            not isinstance(row, list)
            or len(row) != 2
            or not services.is_row_unit_name(row[0])
            or type(row[1]) is not str
            or not row[1]
        ):
            raise parse_error("rows_unit")
        rows.append((row[0], sanitize(row[1], LABEL_CELLS)))
    return rows


def argv(names: Sequence[str]) -> tuple[str, ...]:
    return (services.SYSTEMCTL, "show", "--no-pager", f"--property={PROPERTIES}", "--", *names)


def parse_show(text: str, count: int) -> "list[dict[str, str]]":
    """One mapping per block; a different number of blocks than names asked for fails."""
    blocks = [b for b in re.split(r"\n\s*\n", text.strip("\n")) if b.strip()]
    if len(blocks) != count:
        raise parse_error("rows_unit")
    parsed = []
    for block in blocks:
        values: dict[str, str] = {}
        for line in block.splitlines():
            key, eq, value = line.partition("=")
            if eq and key in ("Id", "LoadState", "ActiveState", "SubState"):
                values[key] = value.strip()
        parsed.append(values)
    return parsed


def key_for(name: str, taken: "set[str]") -> str:
    """An item key from the unit name: ``rows_unit.nginx-service``, unique in the module."""
    slug = _SLUG.sub("-", name.lower()).strip("-")[:KEY_CHARS] or "unit"
    key, n = f"rows_unit.{slug}", 2
    while key in taken:
        key, n = f"rows_unit.{slug}-{n}", n + 1
    taken.add(key)
    return key


def row_item(key: str, label: str, values: "dict[str, str]") -> Item:
    load = values.get("LoadState", "")
    active = values.get("ActiveState", "")
    sub = values.get("SubState", "")
    label_ref = ref("label.unit_row", label=label)
    if load == "not-found":
        return Item(key, "not-found", Unit.TEXT, label_ref, status=Status.WARN,
                    text=ref("unit.not_found"))  # fmt: skip
    if load == "masked":
        return Item(key, "masked", Unit.TEXT, label_ref, status=Status.WARN,
                    text=ref("unit.masked"))  # fmt: skip
    if active not in ACTIVE_STATES:
        return Item(key, None, Unit.TEXT, label_ref, status=Status.UNKNOWN,
                    text=ref("unit.unknown"))  # fmt: skip
    if active in GOOD:
        status = Status.OK
    elif active == "failed":
        status = Status.CRIT
    else:
        status = Status.WARN
    sub = sub if SUB_STATE.match(sub) and sub != active else ""
    text = ref("unit.state_sub", state=active, sub=sub) if sub else ref("unit.state", state=active)
    hint = HintRef("units.failed") if active == "failed" else None
    return Item(key, active, Unit.TEXT, label_ref, status=status, text=text, hint=hint)


class RowsUnit:
    name = "rows_unit"
    section = "services"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 1800
    timeout = 10.0
    binaries: tuple[str, ...] = (services.SYSTEMCTL,)
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        rows = ctx.config.get("rows") if isinstance(ctx.config, dict) else None
        return Detection(bool(rows) and ctx.exists(services.SYSTEMCTL))

    def collect(self, ctx: Context) -> list[Item]:
        rows = rows_of(dict(ctx.config))
        if not rows:
            return []
        names = [name for name, _label in rows]
        out = ctx.run(argv(names)).decode("utf-8", "replace")
        taken: set[str] = set()
        return [
            row_item(key_for(name, taken), label, values)
            for (name, label), values in zip(rows, parse_show(out, len(rows)))
        ]

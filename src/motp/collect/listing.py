"""``motp modules``: one line per module with its state and why (blueprint 4.8, 4.13, 5.4).

Columns: name, state (active, not detected, disabled, failed), the user it runs as, its
interval, its default visibility, and the reason. Anyone may run it. Whether a module
failed in the last run, and why, comes from ``admin.json``, so only root and the admin
group see failures (5.4: module failures are a count for everyone else).
"""

import os
import time
from dataclasses import dataclass
from typing import Optional, TextIO

from motp.collect import runner, store
from motp.core import cache, config, i18n
from motp.core.model import ContractError, MessageRef, ModuleState
from motp.core.sanitize import cell_width, sanitize
from motp.modules import registry
from motp.modules.base import Context

REASON_CELLS = 80
STATE_IDS = {
    "active": "modules.state.active",
    "not_detected": "modules.state.not_detected",
    "disabled": "modules.state.disabled",
    "failed": "modules.state.failed",
}
VISIBILITY_IDS = {"public": "modules.visibility.public", "admin": "modules.visibility.admin"}


@dataclass(frozen=True)
class Row:
    name: str
    state: str  # a key of STATE_IDS
    user: str  # "reader", "motp" or "root"
    interval: Optional[int]  # None for live modules
    visibility: str
    reason: Optional[MessageRef] = None


def module_rows(settings: config.Config, admin: Optional[cache.TierCache], now: int) -> list[Row]:
    rows: list[Row] = []
    live = Context(now=now)
    for module in registry.live_modules():
        try:
            found = module.detect(live).available
        except Exception:
            found = False
        rows.append(
            Row(
                name=module.name,
                state="active" if found else "not_detected",
                user="reader",
                interval=None,
                visibility=module.default_visibility.value,
            )
        )
    for choice in runner.choose(registry.cached_modules(), settings, now):
        module = choice.module
        state, reason = choice.state, choice.reason
        if admin is not None and state == "active":
            entry = admin.modules.get(module.name)
            if entry is not None and entry.state is ModuleState.FAILED:
                state, reason = "failed", entry.error
        rows.append(
            Row(
                name=module.name,
                state=state,
                user="root" if module.needs_root else runner.BUILTIN_USER,
                interval=module.interval,
                visibility=module.default_visibility.value,
                reason=reason,
            )
        )
    return rows


def _pad(text: str, cells: int) -> str:
    return text + " " * max(0, cells - cell_width(text))


def format_rows(rows: "list[Row]", tr: i18n.Translator) -> list[str]:
    header = [
        tr.message("modules.column.name"),
        tr.message("modules.column.state"),
        tr.message("modules.column.user"),
        tr.message("modules.column.interval"),
        tr.message("modules.column.visibility"),
        tr.message("modules.column.reason"),
    ]
    table = [header]
    for row in rows:
        interval = (
            tr.message("modules.interval.live")
            if row.interval is None
            else tr.message("modules.interval.seconds", {"seconds": row.interval})
        )
        user = tr.message("modules.user.reader") if row.user == "reader" else row.user
        reason = sanitize(tr.text(row.reason), REASON_CELLS) if row.reason is not None else ""
        table.append(
            [
                row.name,
                tr.message(STATE_IDS[row.state]),
                user,
                interval,
                tr.message(VISIBILITY_IDS[row.visibility]),
                reason,
            ]
        )
    widths = [max(cell_width(line[i]) for line in table) for i in range(len(header))]
    return [
        "  ".join(_pad(cell, widths[i]) for i, cell in enumerate(line)).rstrip() for line in table
    ]


def _admin_tier(cache_dir: str) -> Optional[cache.TierCache]:
    try:
        return cache.read_tier_file(
            os.path.join(cache_dir, store.ADMIN_NAME), cache.ADMIN, store.ROOT
        )
    except ContractError:
        return None  # not readable by this user, or missing


def main(
    out: TextIO,
    *,
    config_root: str = config.DEFAULT_ROOT,
    cache_dir: str = store.CACHE_DIR,
    now: Optional[int] = None,
) -> int:
    tr = i18n.translator(i18n.language_from_env(os.environ))
    settings = config.load(config_root).config
    moment = int(time.time()) if now is None else now
    for line in format_rows(module_rows(settings, _admin_tier(cache_dir), moment), tr):
        out.write(line + "\n")
    return 0


def key_lines(tr: i18n.Translator) -> list[str]:
    """Every built-in item key with its module and the row it names (usability item 12).

    These are the names ``[layout] hide_rows`` and ``row_order`` take; a ``*`` stands for a
    part taken from the system or the config, which the third column describes.
    """
    header = [
        tr.message("modules.column.key"),
        tr.message("modules.column.name"),
        tr.message("modules.column.row"),
    ]
    table = [header]
    for module, keys in registry.ITEM_KEYS.items():
        for key, label in keys.items():
            table.append([key, module, tr.message(label)])
    widths = [max(cell_width(line[i]) for line in table) for i in range(len(header))]
    lines = ["  ".join(_pad(c, widths[i]) for i, c in enumerate(line)).rstrip() for line in table]
    return [*lines, "", tr.message("modules.keys.plugins")]


def keys_main(out: TextIO) -> int:
    """``motp modules --keys``."""
    tr = i18n.translator(i18n.language_from_env(os.environ))
    for line in key_lines(tr):
        out.write(line + "\n")
    return 0

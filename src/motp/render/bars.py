"""Meters in both charsets (blueprint 4.6, D36).

A meter draws its used and its free part as different, visible characters, so the two
can be told apart with no colour at all; with colour the used part takes the row's
status colour (or the look's ``bar_used`` colour) and the free part the ``bar_free``
colour, which the config check keeps at a contrast of at least 3:1 against black.
"""

import math
from typing import Optional

from motp.core.model import Status
from motp.render.theme import Role, Theme


def cells(ratio: float, width: int) -> int:
    """Used cells for ``ratio`` in a bar of ``width``; a non-zero use shows one cell."""
    if not math.isfinite(ratio) or width <= 0:
        return 0
    ratio = min(max(ratio, 0.0), 1.0)
    filled = int(ratio * width + 0.5)
    if ratio > 0 and filled == 0:
        filled = 1
    if ratio < 1 and filled == width and width > 1:
        filled = width - 1  # only a really full disk shows a full bar
    return filled


def bar(ratio: float, width: int, theme: Theme, status: Optional[Status]) -> str:
    """A bar exactly ``width`` cells wide, including any brackets."""
    cs = theme.charset
    inner = width - len(cs.bar_open) - len(cs.bar_close)
    if inner < 1:
        return ""
    used = cells(ratio, inner)
    return (
        theme.paint(Role.FRAME, cs.bar_open)
        + theme.paint(theme.used_role(status), cs.bar_full * used)
        + theme.paint(Role.BAR_FREE, cs.bar_free * (inner - used))
        + theme.paint(Role.FRAME, cs.bar_close)
    )

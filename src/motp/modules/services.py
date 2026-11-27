"""What ``os_units`` and the ``unit`` rows share: ``systemctl`` and unit names (phase 10).

Unit names are untrusted text (5.5). systemd allows only ASCII letters, digits and
``:_.@\\-`` in them, escaping everything else as ``\\xNN``; a name in a tool's output
that does not fit that shape and a known type suffix is not a unit name. A name that the
config hands to ``systemctl`` must also not start with ``-`` or ``.``: ``-H`` and its
kind are options (``-H`` would even reach another host), so the config check, the module
and the argument list (``--`` before the names) each refuse it.
"""

import re

SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUNNING = "/run/systemd/system"
UNIT_TYPES = (
    "service", "socket", "timer", "mount", "automount", "path", "target", "swap", "device",
    "scope", "slice",
)  # fmt: skip
# Any unit a listing can show.
UNIT_NAME = re.compile(
    r"[A-Za-z0-9:_@\\][A-Za-z0-9:_.@\\-]{0,248}\.(" + "|".join(UNIT_TYPES) + r")\Z"
)
# A unit a config row may watch: the types an admin starts and stops (``config.UNIT_NAME``).
ROW_TYPES = ("service", "socket", "timer", "mount", "automount", "path", "target", "swap")
ROW_UNIT_NAME = re.compile(
    r"[A-Za-z0-9:_@\\][A-Za-z0-9:_.@\\-]{0,248}\.(" + "|".join(ROW_TYPES) + r")\Z"
)


def is_unit_name(name: str) -> bool:
    return type(name) is str and bool(UNIT_NAME.match(name))


def is_row_unit_name(name: str) -> bool:
    return type(name) is str and bool(ROW_UNIT_NAME.match(name))

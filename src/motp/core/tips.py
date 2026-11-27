"""Tips about MOTP itself, one per day (blueprint D19).

The texts live in the catalogues; this module only lists their ids and picks one. The
choice depends on nothing but the day (UTC), so every reader sees the same tip on the same
day and a test can pin it. Off unless ``[layout] tips = true``.
"""

DAY = 86400

TIPS = (
    "tip.explain",
    "tip.doctor",
    "tip.modules",
    "tip.preview",
    "tip.plugins",
    "tip.unit_rows",
    "tip.file_rows",
    "tip.config_check",
    "tip.no_color",
    "tip.shell_init",
    "tip.classic",
    "tip.off",
)


def of_day(now: int) -> str:
    """The message id of the tip for the day that holds the time ``now``."""
    return TIPS[(now // DAY) % len(TIPS)]

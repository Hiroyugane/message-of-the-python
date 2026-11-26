"""Dispatch of the command line: the fast path for ``show``, everything else to ``cli``.

``motp show [--login] [--debug]`` (also ``motp`` alone) is what runs at every login, so it
must not pay for ``argparse``, the configuration loader or the TOML parser. This module
therefore knows the whole argument syntax of ``show`` itself and imports nothing but ``sys``;
any other command line goes to ``motp.cli``, which also declares ``show`` for ``--help``.

``_probe <name>`` is the collector's internal command for one probe process (blueprint
4.3); it skips ``argparse`` too, since every collector run starts one per module. So does
``_plugin <name>`` (phase 12), which runs one plugin inside its transient unit.
"""

import sys
from typing import Optional

SHOW_FLAGS = ("--login", "--debug")
PROBE_COMMAND = "_probe"
PLUGIN_COMMAND = "_plugin"
USAGE_ERROR = 2


def show_args(argv: list[str]) -> Optional[dict[str, bool]]:
    """``[show] [--login] [--debug]`` in any order, or ``None`` for anything else."""
    args = list(argv)
    if args and args[0] == "show":
        args = args[1:]
    elif args and args[0] not in SHOW_FLAGS:
        return None
    flags = dict.fromkeys(SHOW_FLAGS, False)
    for arg in args:
        if arg not in flags:
            return None
        flags[arg] = True
    return {"login": flags["--login"], "debug": flags["--debug"]}


def main(argv: Optional[list[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == [PROBE_COMMAND]:
        if len(args) != 2:
            return USAGE_ERROR
        from motp.collect import child

        return child.main(args[1])
    if args[:1] == [PLUGIN_COMMAND]:
        if len(args) != 2:
            return USAGE_ERROR
        from motp.collect import plugins

        return plugins.shim_main(args[1])
    flags = show_args(args)
    if flags is not None:
        if flags["login"] and not flags["debug"]:
            try:  # a login hook is silent whatever goes wrong, a broken install included
                from motp import show

                return show.main(login=True, debug=False)
            except BaseException:
                return 0
        from motp import show

        return show.main(login=flags["login"], debug=flags["debug"])
    from motp.cli import main as cli_main

    return cli_main(args)

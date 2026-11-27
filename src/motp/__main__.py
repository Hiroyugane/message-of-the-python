"""Entry point for ``python3 -I -S -m motp`` and for an unpacked source tree.

For ``show`` (the command of every login) the wall-clock limit is armed before anything
else is imported; see ``motp.core.deadline``. ``tools/build_pyz.py`` writes the same program
as the root of the archive.
"""

import sys

from motp import entry
from motp.core import deadline


def start() -> int:
    if entry.show_args(sys.argv[1:]) is not None:
        deadline.arm()
    return entry.main()


if __name__ == "__main__":
    sys.exit(start())

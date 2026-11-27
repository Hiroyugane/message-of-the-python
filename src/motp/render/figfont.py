"""The bundled header fonts (blueprint D15) and drawing a header with any font.

The FIGfont reader and FIGlet's layout live in ``motp.core.figfont``, shared with the
collector, which reads an admin's font from ``/etc/motp/fonts/``. This module loads only
the fonts bundled under ``render/fonts`` through the package loader, so it works from the
unpacked tree and from the archive; the renderer never opens a font file by path.
"""

import functools
from typing import Optional

from motp.core import resources
from motp.core.figfont import MAX_FONT_BYTES, REQUIRED, Font, layout, parse
from motp.core.look import BUNDLED_FONTS

__all__ = ["BUNDLED", "REQUIRED", "SMALLER", "Font", "bundled", "parse", "render"]

# Bundled fonts and the charset they need. ``motp-block`` draws with block and frame
# characters, so it is for Unicode terminals only (D15). One table for config and renderer.
BUNDLED = BUNDLED_FONTS
# The font tried next when a header is too wide (D15); the last step drops the header.
SMALLER = {"motp-block": "motp-block-small", "big": "small"}


@functools.cache
def bundled(name: str) -> Optional[Font]:
    """Load a bundled font by name; ``None`` if it is missing or malformed."""
    if name not in BUNDLED:
        return None
    try:
        data = resources.read(f"render/fonts/{name}.flf")
    except OSError:
        return None
    return parse(name, data, MAX_FONT_BYTES) if data is not None else None


def render(font: Font, text: str) -> list[str]:
    """Draw ``text``; a character the font lacks is drawn as ``?``."""
    return layout(font, text)

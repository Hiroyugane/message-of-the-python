"""The renderer: view model, layout, theme, bars and header (blueprint 4.6).

Input is the data model only. Nothing in this package reads files other than its own
fonts through the package loader, starts processes or opens sockets; the caller decides
width, charset and colour from the environment and passes them in.
"""

from dataclasses import replace

from motp.render import layout, view
from motp.render.theme import ASCII, UNICODE, ColorLevel, Theme, themed

STATIC_WIDTH = 80


def render(inp: view.RenderInput, width: int, theme: Theme) -> str:
    """The message for a terminal ``width`` cells wide, as one string ending in a newline."""
    lines = layout.render(view.build(inp), width, theme)
    return "\n".join(lines) + "\n" if lines else ""


def render_static(inp: view.RenderInput) -> str:
    """Static mode (4.6): public items only, no colour, 80 columns, the normal layout.

    The language comes from ``inp``. The charset is ASCII unless the configuration says
    ``charset = "unicode"``: pam_motd prints the file to every kind of terminal (serial
    consoles, latin-1 terminals, programs that log the banner), and the locale the
    collector runs with says nothing about them. Nothing here looks at a terminal or the
    environment. The collector writes exactly this text (``runner.static_text``).
    """
    public = replace(inp, admin=False)
    charset = UNICODE if inp.layout.charset == "unicode" else ASCII
    return render(public, STATIC_WIDTH, themed(charset, ColorLevel.OFF, inp.look))

#!/usr/bin/env python3
"""Render the demo to images for the README and the design review (phases 4 and 4b).

Writes one SVG per preset (``default``, ``classic``), charset and width on a black
background: Unicode with 256 colours and ASCII with 16 colours, each at 80 columns (the
wide layout with the header) and at 60 columns (the compact layout). The default preset's
files are ``demo-<charset>[-narrow].svg``, the classic preset's
``classic-<charset>[-narrow].svg``. Only the standard library is used: the renderer's own
output is parsed for the theme's escape sequences and drawn as SVG text on a cell grid.

With ``--png`` it also asks a Chromium-based browser that is already installed (Edge or
Chrome, found at its usual place or given with ``--browser``) to screenshot each SVG in
headless mode. That step is optional and dev-only; nothing at run time depends on it.

Usage: python tools/demo_image.py [--png] [--browser PATH] [--out DIR]
"""

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from motp import render  # noqa: E402
from motp.render import demo  # noqa: E402
from motp.render.theme import ASCII, UNICODE, ColorLevel, themed  # noqa: E402

WIDTH = 80
NARROW = 60
CELL_W = 9.0
CELL_H = 19.0
FONT_SIZE = 15
PAD = 16
BACKGROUND = "#000000"
NEWLINE = chr(10)
FOREGROUND = "#d0d0d0"
FONTS = "'DejaVu Sans Mono', 'Cascadia Mono', Consolas, 'Lucida Console', monospace"
BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome",
)
HEARTBEAT_SECONDS = 10.0

# xterm's 16-colour palette.
BASIC = [
    "#000000", "#cd0000", "#00cd00", "#cdcd00", "#3b6ee8", "#cd00cd", "#00cdcd", "#e5e5e5",
    "#7f7f7f", "#ff4040", "#00ff00", "#ffff00", "#6b9bff", "#ff00ff", "#00ffff", "#ffffff",
]  # fmt: skip
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def color256(n: int) -> str:
    if n < 16:
        return BASIC[n]
    if n < 232:
        n -= 16
        levels = [0, 95, 135, 175, 215, 255]
        r, g, b = levels[n // 36], levels[(n // 6) % 6], levels[n % 6]
        return f"#{r:02x}{g:02x}{b:02x}"
    v = 8 + (n - 232) * 10
    return f"#{v:02x}{v:02x}{v:02x}"


class Style:
    def __init__(self) -> None:
        self.fg: Optional[str] = None
        self.bold = False
        self.dim = False

    def apply(self, params: str) -> None:
        codes = [int(c) for c in params.split(";") if c] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                self.fg, self.bold, self.dim = None, False, False
            elif c == 1:
                self.bold = True
            elif c == 2:
                self.dim = True
            elif 30 <= c <= 37:
                self.fg = BASIC[c - 30]
            elif 90 <= c <= 97:
                self.fg = BASIC[c - 90 + 8]
            elif c == 38 and i + 2 < len(codes) and codes[i + 1] == 5:
                self.fg = color256(codes[i + 2])
                i += 2
            i += 1

    def attrs(self) -> str:
        fill = self.fg or FOREGROUND
        out = f'fill="{fill}"'
        if self.bold:
            out += ' font-weight="bold"'
        if self.dim:
            out += ' fill-opacity="0.55"'
        return out


# Block elements and box lines are drawn as shapes on the cell grid, as a terminal joins
# them, instead of as font glyphs (which leave gaps between cells in an SVG).
BLOCKS = {  # character: (x, y, width, height) as fractions of the cell, and opacity
    "█": ((0, 0, 1, 1), 1.0),
    "▀": ((0, 0, 1, 0.5), 1.0),
    "▄": ((0, 0.5, 1, 0.5), 1.0),
    "▌": ((0, 0, 0.5, 1), 1.0),
    "▐": ((0.5, 0, 0.5, 1), 1.0),
    "░": ((0, 0, 1, 1), 0.25),
    "▒": ((0, 0, 1, 1), 0.5),
    "▓": ((0, 0, 1, 1), 0.75),
}
# Box lines: the arms each character draws (up, down, left, right), and double or single.
_ARMS = {
    "─": ("lr", 1), "│": ("ud", 1), "┌": ("dr", 1), "┐": ("dl", 1), "└": ("ur", 1),
    "┘": ("ul", 1), "├": ("udr", 1), "┤": ("udl", 1), "┬": ("dlr", 1), "┴": ("ulr", 1),
    "┼": ("udlr", 1), "═": ("lr", 2), "║": ("ud", 2), "╔": ("dr", 2), "╗": ("dl", 2),
    "╚": ("ur", 2), "╝": ("ul", 2), "╠": ("udr", 2), "╣": ("udl", 2), "╦": ("dlr", 2),
    "╩": ("ulr", 2), "╬": ("udlr", 2),
}  # fmt: skip
LINE = 1.4  # stroke width of a box line in pixels
GAP = 2.2  # distance between the two strokes of a double line


def _shape(ch: str, x: float, top: float, style: "Style") -> Optional[str]:
    """An SVG shape for a block or box character in the cell at (x, top), or None."""
    fill = style.fg or FOREGROUND
    if ch in BLOCKS:
        (fx, fy, fw, fh), opacity = BLOCKS[ch]
        return (
            f'<rect x="{x + fx * CELL_W:.1f}" y="{top + fy * CELL_H:.1f}" '
            f'width="{fw * CELL_W + 0.3:.1f}" height="{fh * CELL_H + 0.3:.1f}" '
            f'fill="{fill}" fill-opacity="{opacity}"/>'
        )
    if ch not in _ARMS:
        return None
    arms, strokes = _ARMS[ch]
    cx, cy = x + CELL_W / 2, top + CELL_H / 2
    offsets = (0.0,) if strokes == 1 else (-GAP / 2, GAP / 2)
    parts = []
    for off in offsets:
        # Each stroke runs from the cell's edge to the centre; double lines meet at
        # their own offset so the corners close.
        across = off if "l" in arms or "r" in arms else 0.0  # vertical arms stop here
        along = off if "u" in arms or "d" in arms else 0.0  # horizontal arms stop here
        ends = {
            "u": (cx + off, top, cx + off, cy + across),
            "d": (cx + off, cy - across, cx + off, top + CELL_H),
            "l": (x, cy + off, cx + along, cy + off),
            "r": (cx - along, cy + off, x + CELL_W, cy + off),
        }
        for arm in arms:
            x1, y1, x2, y2 = ends[arm]
            parts.append(f"M{x1:.1f} {y1:.1f}L{x2:.1f} {y2:.1f}")
    return f'<path d="{"".join(parts)}" stroke="{fill}" stroke-width="{LINE}" fill="none"/>'


def to_svg(text: str, title: str, columns: int = WIDTH) -> str:
    from motp.core.sanitize import char_width

    lines = text.rstrip("\n").split("\n")
    width = PAD * 2 + columns * CELL_W
    height = PAD * 2 + len(lines) * CELL_H
    body = []
    for row, line in enumerate(lines):
        style = Style()
        col = 0
        y = PAD + (row + 0.78) * CELL_H
        pos = 0
        for m in [*SGR.finditer(line), None]:
            end = m.start() if m else len(line)
            chunk = line[pos:end]
            for ch in chunk:
                w = char_width(ch)
                if ch != " ":
                    x = PAD + col * CELL_W
                    shape = _shape(ch, x, PAD + row * CELL_H, style)
                    body.append(
                        shape
                        or f'<text x="{x:.1f}" y="{y:.1f}" {style.attrs()}>{escape(ch)}</text>'
                    )
                col += w
            if m is None:
                break
            style.apply(m.group(1))
            pos = m.end()
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}">\n'
        f"<title>{escape(title)}</title>\n"
        f'<rect width="100%" height="100%" fill="{BACKGROUND}"/>\n'
        f'<g font-family="{FONTS}" font-size="{FONT_SIZE}" xml:space="preserve">\n'
        + "\n".join(body)
        + "\n</g>\n</svg>\n"
    )


def find_browser(given: Optional[str]) -> Optional[str]:
    for candidate in (given, *BROWSERS):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def to_png(browser: str, svg: Path, png: Path, size: tuple[int, int]) -> bool:
    """Screenshot ``svg`` with a headless browser; prints a status line while it waits."""
    args = [
        browser,
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--window-size={size[0]},{size[1]}",
        f"--screenshot={png}",
        svg.resolve().as_uri(),
    ]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    started = time.monotonic()
    while True:
        try:
            proc.wait(timeout=HEARTBEAT_SECONDS)
            break
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - started
            print(f"progress: screenshot {svg.name} elapsed={elapsed:.0f}s", file=sys.stderr)
            if elapsed > 120:
                proc.kill()
                return False
    return proc.returncode == 0 and png.is_file()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Render the demo to SVG (and PNG).")
    parser.add_argument("--png", action="store_true", help="also write PNG screenshots")
    parser.add_argument("--browser", help="path of a Chromium-based browser for --png")
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "images")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    variants = []
    for preset, prefix in (("default", "demo"), ("classic", "classic")):
        for charset, level, colours in (
            (UNICODE, ColorLevel.EXTENDED, "256 colours"),
            (ASCII, ColorLevel.BASIC, "16 colours"),
        ):
            for columns, suffix in ((WIDTH, ""), (NARROW, "-narrow")):
                name = f"{prefix}-{charset.name}{suffix}"
                title = f"MOTP demo, preset {preset}, {charset.name}, {colours}, {columns} columns"
                variants.append((name, preset, charset, level, columns, title))
    browser = find_browser(args.browser) if args.png else None
    if args.png and browser is None:
        print("no browser found for --png; wrote SVG only", file=sys.stderr)
    for name, preset, charset, level, columns, title in variants:
        inp = demo.demo_input(preset=preset)
        text = render.render(inp, columns, themed(charset, level, inp.look))
        svg_text = to_svg(text, title, columns)
        svg = args.out / f"{name}.svg"
        svg.write_bytes(svg_text.encode("utf-8"))
        print(svg.relative_to(ROOT).as_posix() if svg.is_relative_to(ROOT) else svg)
        if browser:
            rows = text.count(NEWLINE)
            size = (int(PAD * 2 + columns * CELL_W), int(PAD * 2 + rows * CELL_H))
            png = args.out / f"{name}.png"
            if to_png(browser, svg, png, size):
                print(png.relative_to(ROOT).as_posix() if png.is_relative_to(ROOT) else png)
            else:
                print(f"screenshot failed for {svg.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

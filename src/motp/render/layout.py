"""Layout for the four width classes of D16, in either charset, with or without colour.

| Columns   | Layout                                                        |
|-----------|---------------------------------------------------------------|
| 80 and up | header, framed sections with titles in the frame line, bars   |
| 60 to 79  | compact frame, shorter labels and bars, no header             |
| 40 to 59  | plain ``label: value`` lines, no frame                        |
| under 40  | the attention block only, or one line with host and uptime    |

Widths are measured in terminal cells with the sanitiser's ``cell_width``. Built-in values
are cut, never wrapped; a plugin row or alert that does not fit wraps at its spaces, each
further line starting with the catalogue's "(plugin)". No line is wider than the width it
was given. All text passes through ``Theme.text`` on its way out, which re-applies the
sanitiser for the charset (ASCII mode transliterates catalogue text too) and truncates
with an ellipsis. Colour is added last, around text whose width is already settled.

The look (D35) decides the characters, the header font and its alignment, whether the
wide layouts draw a frame, how labels are written, and the width, style and text of
meters; a meter's text shortens before its bar goes (D36).
"""

from dataclasses import replace
from typing import Callable, Optional

from motp.core.figfont import Font
from motp.core.model import Status
from motp.core.sanitize import LABEL_CELLS, cell_width, sanitize
from motp.render import bars, figfont
from motp.render.theme import Role, Theme
from motp.render.view import Alert, Row, View

WIDE = 80
COMPACT = 60
PLAIN = 40
MAX_FRAME = 80  # a wider terminal still gets an 80-column frame
MIN_WIDTH = 10

LABEL_FIELD = {"wide": 18, "compact": 14}  # the narrowest label column, leader and colon
# The mark that ends a cut label. Not the ellipsis: in ASCII "..." reads as the dotted
# leader ("Operating...:"), so a cut label must look different from a short one.
LABEL_CUT = {"unicode": "~", "ascii": "~"}
TITLE_LEAD = {"wide": 10, "compact": 3}  # frame characters before a section title
BAR_CELLS = {"wide": 40, "compact": 20}
PLAIN_LABEL = 20
MIN_VALUE = 8  # a label is dropped before its value gets less room than this
MIN_TEXT_BESIDE_COMMAND = 12  # below this, a command moves to its own line
MIN_HINT_ROOM = 8  # a wrapped hint line hangs deeper only when this much room is left
INDENT = "  "
SMALL_FONT = {"unicode": "motp-block-small", "ascii": "small"}  # after an admin font


def width_class(width: int) -> str:
    if width >= WIDE:
        return "wide"
    if width >= COMPACT:
        return "compact"
    if width >= PLAIN:
        return "plain"
    return "minimal"


class _Out:
    """Collects lines and checks the width contract as it goes."""

    def __init__(self, theme: Theme) -> None:
        self.theme = theme
        self.lines: list[str] = []

    def fit(self, text: str, limit: int) -> str:
        return self.theme.text(text, limit) if limit > 0 else ""


def render(view: View, width: int, theme: Theme) -> list[str]:
    """The finished lines for a terminal ``width`` cells wide."""
    if width < MIN_WIDTH:
        return []  # nothing useful fits; never a line wider than the terminal
    kind = width_class(width)
    out = _Out(theme)
    if kind in ("wide", "compact"):
        _framed(out, view, min(width, MAX_FRAME), kind)
    elif kind == "plain":
        _plain(out, view, width)
    else:
        _minimal(out, view, width)
    return out.lines


def _wrap(
    out: _Out,
    text: str,
    room: int,
    rest: Optional[int] = None,
    *,
    tail: int = 0,
    balance: bool = False,
) -> list[str]:
    """``text`` broken at spaces into lines of at most ``room`` cells (``rest`` for the
    lines after the first). Only sentences are wrapped, the tip, hints and plugin text: a
    cut sentence helps nobody. Built-in values never are.

    ``tail`` cells stay free on the last line (a marker goes there). With ``balance`` a
    last line of one word takes the word before it too, when that still fits and leaves
    the line above at least two words: no lone word (phase 14c)."""

    def limit(n: int) -> int:
        return room if n == 0 or rest is None else rest

    lines: list[str] = []
    line = ""
    for word in out.fit(text, 10**4).split(" "):
        longer = f"{line} {word}" if line else word
        if line and cell_width(longer) > limit(len(lines)):
            lines.append(line)
            line = word
        else:
            line = longer
    if line:
        lines.append(line)
    if tail and lines and cell_width(lines[-1]) + tail > limit(len(lines) - 1):
        head, _, word = lines[-1].rpartition(" ")
        if head:
            lines[-1:] = [head, word]
    if balance and len(lines) > 1 and " " not in lines[-1]:
        head, _, word = lines[-2].rpartition(" ")
        moved = f"{word} {lines[-1]}"
        if " " in head and cell_width(moved) + tail <= limit(len(lines) - 1):
            lines[-2:] = [head, moved]
    last = len(lines) - 1
    return [out.fit(ln, limit(n) - (tail if n == last else 0)) for n, ln in enumerate(lines)]


# --- framed layouts ----------------------------------------------------------------------


def _rule(out: _Out, frame: int, left: str, right: str, title: str, lead: int) -> None:
    """A frame line, with a title in it; without a frame only the title is written."""
    paint = out.theme.paint
    if not out.theme.look.frame:
        if title:
            out.lines.append(paint(Role.TITLE, out.fit(title, frame)))
        return
    out.lines.append(_frame_line(out, frame, left, right, title, lead))


def _frame_line(out: _Out, frame: int, left: str, right: str, title: str, lead: int) -> str:
    cs = out.theme.charset
    paint = out.theme.paint
    if not title:
        return paint(Role.FRAME, left + cs.horizontal * (frame - 2) + right)
    room = frame - 2 - lead - len(cs.title_open) - len(cs.title_close) - 1
    shown = out.fit(title, room)
    rest = frame - 2 - lead - len(cs.title_open) - cell_width(shown) - len(cs.title_close)
    return (
        paint(Role.FRAME, left + cs.horizontal * lead + cs.title_open)
        + paint(Role.TITLE, shown)
        + paint(Role.FRAME, cs.title_close + cs.horizontal * rest + right)
    )


def _boxed(out: _Out, frame: int, content: str, used: int) -> None:
    """Put one content line of ``used`` visible cells into the frame."""
    cs = out.theme.charset
    inner = frame - 5
    if not out.theme.look.frame:
        out.lines.append(INDENT + content)
        return
    edge = out.theme.paint(Role.FRAME, cs.vertical)
    out.lines.append(edge + INDENT + content + " " * (inner - used) + " " + edge)


def header_fonts(theme: Theme) -> list[Font]:
    """The header font of the look for this charset, then the smaller one (D15).

    An admin font comes from the look (its glyphs travelled in ``render.json``); the
    bundled ones load through the package loader. A font that cannot draw this charset
    is skipped.
    """
    look = theme.look
    charset = theme.charset.name
    name = look.header_font.get(charset, "")
    smaller = figfont.SMALLER.get(name) or (SMALL_FONT[charset] if name in look.fonts else "")
    fonts = []
    for candidate in (name, smaller):
        font: Optional[Font] = look.fonts.get(candidate) or figfont.bundled(candidate)
        if font is None or (theme.charset.ascii_only and not font.ascii_only):
            continue
        fonts.append(font)
    return fonts


def _header(out: _Out, text: str, room: int) -> list[str]:
    """Header rows in the first font that fits ``room``; none if no font fits."""
    drawn = sanitize(text, LABEL_CELLS, ascii_only=True)  # the header text is ASCII
    if not drawn:
        return []
    for font in header_fonts(out.theme):
        rows = figfont.render(font, drawn)
        # Rows left blank by the text (Big keeps two for descenders) take no room.
        while rows and not rows[-1].strip():
            rows.pop()
        while rows and not rows[0].strip():
            rows.pop(0)
        if rows and max(cell_width(r) for r in rows) <= room:
            return rows
    return []


def _pad(out: _Out, width: int, room: int) -> int:
    """Blank cells before a header row of ``width`` for the look's alignment."""
    align = out.theme.look.header_align
    return 0 if align == "left" else room - width if align == "right" else (room - width) // 2


def _framed(out: _Out, view: View, frame: int, kind: str) -> None:
    cs = out.theme.charset
    lead = TITLE_LEAD[kind]
    inner = frame - 5
    field = fitted_field(out.theme, kind, view, inner)
    header = _header(out, view.header, inner) if kind == "wide" else []
    if not view.sections and not header and not view.tip:
        return
    if header:
        _rule(out, frame, cs.top_left, cs.top_right, "", lead)
        width = max(cell_width(line) for line in header)
        pad = _pad(out, width, inner)
        for line in header:
            painted = out.theme.paint(Role.HEADER, line)
            _boxed(out, frame, " " * pad + painted, pad + cell_width(line))
    for n, section in enumerate(view.sections):
        first = n == 0 and not header
        left, right = (cs.top_left, cs.top_right) if first else (cs.tee_left, cs.tee_right)
        _rule(out, frame, left, right, section.title, lead)
        if section.alerts:
            for alert in section.alerts:
                _framed_alert(out, frame, alert)
        else:
            for row in section.rows:
                _framed_row(out, frame, kind, row, field)
    if view.tip:
        first = not view.sections and not header
        left, right = (cs.top_left, cs.top_right) if first else (cs.tee_left, cs.tee_right)
        _rule(out, frame, left, right, view.tip_title, lead)
        for line in _wrap(out, view.tip, inner):
            _boxed(out, frame, out.theme.paint(Role.DIM, line), cell_width(line))
    _rule(out, frame, cs.bottom_left, cs.bottom_right, "", lead)


def _value_part(out: _Out, row: Row, room: int) -> tuple[str, int]:
    """Value, marker and age note within ``room`` cells; returns (painted, width)."""
    theme = out.theme
    marker = theme.marker(row.status)
    marker_w = cell_width(marker) + 1 if marker else 0
    if marker_w > room:
        marker, marker_w = "", 0  # only at absurd widths; callers reserve room for it
    note = row.note
    if note and room - marker_w - cell_width(note) - 1 < 8:
        note = ""
    shortest = min(cell_width(out.fit(f, 10**4)) for f in (row.value, *row.forms))
    if note and shortest + marker_w + cell_width(out.fit(note, 10**4)) + 1 > room:
        note = ""  # the age note goes before the value is cut (usability item 8)
    note_txt = out.fit(note, room - marker_w - 9) if note else ""
    note_w = cell_width(note_txt) + 1 if note_txt else 0
    space = room - marker_w - note_w
    # A meter's text shortens before it is cut (D36): the first form that fits, else the
    # shortest, cut.
    forms = (row.value, *row.forms)
    chosen = next((f for f in forms if cell_width(out.fit(f, 10**4)) <= space), forms[-1])
    value = out.fit(chosen, space)
    role = Role.DIM if row.muted else theme.status_role(row.status)
    painted = theme.paint(role, value)
    used = cell_width(value)
    if marker:
        painted += " " + marker
        used += marker_w
    if note_txt:
        painted += " " + theme.paint(Role.DIM, note_txt)
        used += note_w
    return painted, used


_Line = tuple[str, int]  # a painted line and its visible cells


def _plugin_body(out: _Out, row: Row, room: int) -> list[_Line]:
    """``[plugin name] label: value`` within ``room``; the prefix is shown first and whole.

    A row whose value does not fit beside prefix and label wraps (``_continued``); a row
    that fits is one line, as before phase 14c."""
    theme = out.theme
    marker = theme.marker(row.status)
    reserve = cell_width(marker) + 1 if marker else 0
    prefix = out.fit(row.prefix, room - reserve)
    used = cell_width(prefix)
    painted = theme.paint(Role.DIM, prefix)
    rest = room - used - 1
    if rest <= 0:
        return [(painted, used)]
    label = cut_label(theme, row.label, (rest - reserve) // 2) if row.label else ""
    wrapped_label = label  # a wrapped value has further lines: the label may stay
    if label and rest - cell_width(label) - 2 < reserve + MIN_VALUE:
        label = ""  # too little room left for a value: the value wins
    space = rest - (cell_width(label) + 2 if label else 0)
    shortest = min(cell_width(out.fit(f, 10**4)) for f in (row.value, *row.forms))
    whole = cell_width(prefix) == cell_width(out.fit(row.prefix, 10**4))
    if row.more and whole and shortest + reserve > space and " " in row.value.strip():
        head, head_w = painted, used
        if wrapped_label:
            head += " " + theme.paint(Role.LABEL, wrapped_label + theme.charset.separator)
            head_w += 1 + cell_width(wrapped_label) + 1
        role = Role.DIM if row.muted else theme.status_role(row.status)
        lines = _continued(
            out, (head, head_w), row.value, role, room, row.status, row.note, row.more
        )
        if lines:
            return lines
    if label:
        painted += " " + theme.paint(Role.LABEL, label + theme.charset.separator)
        used += 1 + cell_width(label) + 1
        rest = room - used - 1
    value, value_w = _value_part(out, row, rest)
    if value_w:
        painted += " " + value
        used += 1 + value_w
    return [(painted, used)]


def _continued(
    out: _Out,
    first: _Line,
    text: str,
    role: Role,
    room: int,
    status: Optional[Status],
    note: str,
    more: str,
) -> list[_Line]:
    """``first`` (prefix and label, or nothing) followed by ``text`` wrapped at spaces.

    Every line after ``first`` starts with the catalogue's marker ``more`` ("(plugin)"),
    one indent deeper; when ``first`` is empty the text starts on a marked line too. The
    renderer writes the marker outside the plugin's text, and sanitised text holds no line
    break, so no piece of plugin text can stand at the start of a line and pass for a
    system row (T7). The severity marker, then the age note if it fits, end the last line.
    Empty when the marked lines would be too narrow to be of use: the caller cuts instead.
    """
    theme = out.theme
    marker = theme.marker(status)
    tail, tail_w = (" " + marker, cell_width(marker) + 1) if marker else ("", 0)
    shown_more = out.fit(more, room)
    lead = INDENT + shown_more + " " if first[1] else shown_more + " "
    cont = room - cell_width(lead)
    if cont - tail_w < MIN_HINT_ROOM:
        return []
    shown_note = out.fit(note, 10**4) if note else ""
    if shown_note and cont - tail_w - cell_width(shown_note) - 1 >= MIN_VALUE:
        tail += " " + theme.paint(Role.DIM, shown_note)
        tail_w += cell_width(shown_note) + 1
    words = out.fit(text, 10**4)
    beside = room - first[1] - 1
    if not first[1] or beside < cell_width(words.split(" ")[0]):
        lines = ["", *_wrap(out, words, cont, cont, tail=tail_w, balance=True)]
    else:
        lines = _wrap(out, words, beside, cont, tail=tail_w, balance=True)
    result: list[_Line] = [first] if first[1] else []
    for n, line in enumerate(lines):
        if n == 0:
            if line:
                painted, used = first
                result[0] = (painted + " " + theme.paint(role, line), used + 1 + cell_width(line))
            continue
        lead_painted = (INDENT if first[1] else "") + theme.paint(Role.DIM, shown_more) + " "
        result.append((lead_painted + theme.paint(role, line), cell_width(lead) + cell_width(line)))
    if not result:
        return []  # no text and nothing before it
    painted, used = result[-1]
    result[-1] = (painted + tail, used + tail_w)
    return result


def label_field(theme: Theme, kind: str) -> int:
    """Cells for a label with its leader and separator in the framed layouts (fixed)."""
    field = theme.look.label_width or LABEL_FIELD[kind]
    return min(field, LABEL_FIELD["compact"]) if kind == "compact" else field


def fitted_field(theme: Theme, kind: str, view: View, inner: int) -> int:
    """The label column for ``view`` (final review, usability item 8).

    It grows from the fixed width towards the longest label, but only as far as the
    longest value still fits beside it (its shortest meter form and its marker; an age
    note may drop): values carry the information, so a label is cut before a value is.
    Never narrower than the fixed column. A ``label_width`` set in the config is kept.
    """
    fixed = label_field(theme, kind)
    if theme.look.label_width:
        return fixed
    longest, need = 0, 0
    for section in view.sections:
        for row in section.rows:
            if row.prefix:
                continue
            if row.label:
                indent = len(INDENT) if row.detail else 0
                longest = max(longest, indent + cell_width(theme.text(row.label, LABEL_CELLS)))
                forms = (row.value, *row.forms)
                value = min(cell_width(theme.text(f, 10**4)) for f in forms)
                marker = theme.marker(row.status)
                need = max(need, value + (cell_width(marker) + 1 if marker else 0))
    wanted = longest + 2  # at least one leader cell, and the separator
    return max(fixed, min(wanted, inner - 2 - need))


def cut_label(theme: Theme, label: str, room: int) -> str:
    """``label`` in at most ``room`` cells; a cut one ends in ``LABEL_CUT``, never in an
    ellipsis that a dotted leader could hide."""
    text = theme.text(label, LABEL_CELLS)
    if cell_width(text) <= room:
        return text
    mark = LABEL_CUT[theme.charset.name if theme.charset.name in LABEL_CUT else "ascii"]
    kept = ""
    for ch in text:
        if cell_width(kept + ch) > room - cell_width(mark):
            break
        kept += ch
    return kept.rstrip(" .") + mark if room > cell_width(mark) else kept


def _label_head(theme: Theme, label: str, room: int) -> str:
    """``label`` with the look's label style, exactly ``room`` + 1 cells, painted."""
    cs = theme.charset
    style = theme.look.label_style
    pad = room - cell_width(label)
    if style == "dots":
        return theme.paint(Role.LABEL, label + cs.leader * pad + cs.separator)
    if style == "colon":
        return theme.paint(Role.LABEL, label + cs.separator) + " " * pad
    return theme.paint(Role.LABEL, label) + " " * (pad + 1)


def bar_cells(theme: Theme, kind: str, room: int) -> int:
    return min(theme.look.bar.width or BAR_CELLS[kind], room)


def _framed_row(out: _Out, frame: int, kind: str, row: Row, field: int) -> None:
    theme = out.theme
    inner = frame - 5
    if row.prefix:
        # Plugin rows, details included, always start with the fixed prefix (4.4).
        indent = INDENT if row.detail else ""
        for painted, used in _plugin_body(out, row, inner - len(indent)):
            _boxed(out, frame, indent + painted, len(indent) + used)
        return
    room = inner - field - 2
    if not row.label:
        # A detail without a label sits in the value column; a lone value spans the row.
        start = field + 2 if row.detail else 0
        painted, used = _value_part(out, row, inner - start)
        _boxed(out, frame, " " * start + painted, start + used)
        return
    indent = INDENT if row.detail else ""
    label = cut_label(theme, row.label, field - 1 - len(indent))
    head = indent + _label_head(theme, label, field - 1 - len(indent))
    value, value_w = _value_part(out, row, room)
    _boxed(out, frame, head + "  " + value, field + 2 + value_w)
    if row.bar is not None and not row.detail and theme.look.bar.style != "off":
        width = bar_cells(theme, kind, room)
        drawn = bars.bar(row.bar, width, theme, row.status)
        if drawn:
            _boxed(out, frame, " " * (field + 2) + drawn, field + 2 + width)


def _alert_text(out: _Out, alert: Alert, room: int) -> tuple[str, int]:
    """Prefix, text and marker of an alert within ``room`` cells."""
    theme = out.theme
    marker = theme.marker(alert.status)
    marker_w = cell_width(marker) + 1 if marker else 0
    painted, used = "", 0
    if alert.prefix:
        prefix = out.fit(alert.prefix, room - marker_w - 1)
        painted, used = theme.paint(Role.DIM, prefix) + " ", cell_width(prefix) + 1
    text = out.fit(alert.text, room - used - marker_w)
    painted += theme.paint(theme.status_role(alert.status), text)
    used += cell_width(text)
    if marker:
        painted += " " + marker
        used += marker_w
    return painted, used


def _alert_lines(out: _Out, alert: Alert, room: int, alone: bool = False) -> list[_Line]:
    """Prefix, text and marker of an alert; a plugin alert that does not fit on one line
    wraps like a plugin row (phase 14c). Built-in alerts are cut as before. ``alone``: the
    plugin's prefix stands on a line of its own above, so every line of the text is a
    further line and starts with "(plugin)"."""
    wraps = " " in alert.text.strip() and _alert_cells(out, alert) > room
    if alert.more and (alone or wraps):
        first: _Line = ("", 0)
        if alert.prefix and not alone:
            prefix = out.fit(alert.prefix, 10**4)
            first = (out.theme.paint(Role.DIM, prefix), cell_width(prefix))
        role = out.theme.status_role(alert.status)
        if first[1] < room:
            lines = _continued(out, first, alert.text, role, room, alert.status, "", alert.more)
            if lines:
                return lines
        if alone:  # too narrow to wrap: one cut line, still marked
            alert = replace(alert, text=f"{out.fit(alert.more, room)} {alert.text}")
    return [_alert_text(out, alert, room)]


def _alert_cells(out: _Out, alert: Alert) -> int:
    """The cells that prefix, text and marker of an alert need uncut."""
    marker = out.theme.marker(alert.status)
    cells = cell_width(out.fit(alert.text, 10**4))
    if alert.prefix:
        cells += cell_width(out.fit(alert.prefix, 10**4)) + 1
    return cells + (cell_width(marker) + 1 if marker else 0)


def _command(out: _Out, alert: Alert, room: int) -> tuple[str, int]:
    command = out.fit(alert.command or "", room)
    return out.theme.paint(Role.COMMAND, command), cell_width(command)


def _framed_alert(out: _Out, frame: int, alert: Alert) -> None:
    theme = out.theme
    inner = frame - 5
    cmd_w = cell_width(alert.command) if alert.command else 0
    # A command stands beside its text only when the whole text fits there; a long
    # command or a longer language moves it to its own line instead of cutting the text.
    room = inner - cmd_w - 5
    beside = alert.command is not None and room >= max(
        MIN_TEXT_BESIDE_COMMAND, _alert_cells(out, alert)
    )
    if beside:
        text, used = _alert_text(out, alert, inner - cmd_w - 5)
        command, cmd_w = _command(out, alert, inner)
        dots = inner - used - cmd_w - 2
        leader = theme.paint(Role.DIM, theme.charset.leader * dots)
        _boxed(out, frame, text + " " + leader + " " + command, inner)
        return
    for text, used in _alert_lines(out, alert, inner):
        _boxed(out, frame, text, used)
    _alert_follow_up(out, alert, inner, lambda c, w: _boxed(out, frame, c, w))


_Emit = Callable[[str, int], None]


def _alert_follow_up(out: _Out, alert: Alert, room: int, emit: _Emit) -> None:
    """The command, or a hint without one, on its own indented line or lines.

    A command is shown whole or not at all: a cut command is worse than none, and
    ``motp explain`` still names it (usability item 9). A hint is a sentence and wraps.
    A plugin's hint starts with the catalogue's "Plugin hint:" (``Alert.hint`` holds it
    already), so without colour it still cannot pass for a command from the hint table
    (D34), without repeating the plugin's prefix. Its further lines hang deeper than the
    column where commands stand, so no wrapped piece of it lines up like one.
    """
    indent = INDENT * 2
    if alert.command:
        if cell_width(out.fit(alert.command, 10**4)) <= room - len(indent):
            command, used = _command(out, alert, room - len(indent))
            emit(indent + command, len(indent) + used)
    elif alert.hint:
        more = out.fit(alert.hint_more, room) + " " if alert.hint_more else ""
        hanging = indent + INDENT * 2
        if room - len(hanging) - cell_width(more) < MIN_HINT_ROOM:
            hanging = indent  # too narrow to hang: the marker alone sets the line apart
        rest = room - len(hanging) - cell_width(more)
        if rest < MIN_HINT_ROOM:
            # Too narrow even for the marker: one line, cut, as a hint was before.
            line = out.fit(alert.hint, room - len(indent))
            emit(indent + out.theme.paint(Role.DIM, line), len(indent) + cell_width(line))
            return
        lines = _wrap(out, alert.hint, room - len(indent), rest, balance=bool(alert.hint_more))
        for n, line in enumerate(lines):
            lead = indent if n == 0 else hanging + more
            emit(lead + out.theme.paint(Role.DIM, line), cell_width(lead) + cell_width(line))


# --- plain and minimal layouts -------------------------------------------------------------


def _plain_row(out: _Out, row: Row, width: int) -> None:
    theme = out.theme
    indent = INDENT * 2 if row.detail else INDENT
    room = width - len(indent)
    if row.prefix:
        for painted, _ in _plugin_body(out, row, room):
            out.lines.append(indent + painted)
        return
    head, used = "", 0
    if row.label:
        label = cut_label(theme, row.label, min(PLAIN_LABEL, room // 2))
        head = theme.paint(Role.LABEL, label + theme.charset.separator) + " "
        used = cell_width(label) + 2
    value, _ = _value_part(out, row, room - used)
    out.lines.append(indent + head + value)


def _plain_alert(out: _Out, alert: Alert, width: int, indent: str) -> None:
    room = width - len(indent)
    alone = False
    if alert.prefix and room - cell_width(alert.prefix) < MIN_TEXT_BESIDE_COMMAND:
        # Too narrow for prefix and text on one line: the prefix gets a line of its own.
        prefix = out.fit(alert.prefix, room)
        out.lines.append(indent + out.theme.paint(Role.DIM, prefix))
        alert = replace(alert, prefix="")
        indent += INDENT
        room -= len(INDENT)
        alone = True
    for text, _ in _alert_lines(out, alert, room, alone):
        out.lines.append(indent + text)

    def emit(content: str, used: int) -> None:
        out.lines.append(indent + content)

    _alert_follow_up(out, alert, room, emit)


def _plain(out: _Out, view: View, width: int) -> None:
    for section in view.sections:
        out.lines.append(out.theme.paint(Role.TITLE, out.fit(section.title, width)))
        for alert in section.alerts:
            _plain_alert(out, alert, width, INDENT)
        for row in section.rows:
            _plain_row(out, row, width)
    if view.tip:
        out.lines.append(out.theme.paint(Role.TITLE, out.fit(view.tip_title, width)))
        for line in _wrap(out, view.tip, width - len(INDENT)):
            out.lines.append(INDENT + out.theme.paint(Role.DIM, line))


def plain(view: View, width: int, theme: Theme) -> list[str]:
    """The plain layout at any width (static mode uses it at 80 columns)."""
    out = _Out(theme)
    if width >= MIN_WIDTH:
        _plain(out, view, width)
    return out.lines


def _minimal(out: _Out, view: View, width: int) -> None:
    alerts = [a for s in view.sections for a in s.alerts]
    for alert in alerts:
        _plain_alert(out, alert, width, "")
    if not alerts:
        out.lines.append(out.fit(view.host_line, width))

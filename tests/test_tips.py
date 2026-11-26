"""Tips about MOTP, one per day, off unless the config asks (blueprint D19, phase 13)."""

import json
import re

import pytest

from motp import render as renderer
from motp.core import cache, config, i18n, tips
from motp.core.cache import Layout, RenderSettings
from motp.core.model import ContractError
from motp.core.sanitize import cell_width
from motp.render import demo, view
from motp.render.theme import ASCII, UNICODE, ColorLevel, themed

DAY = tips.DAY
CUT = re.compile(r"…|(?<![. ])" + re.escape("...") + r"(?![.:])")


def _render(width: int, language: str = "en", now: int = demo.NOW, charset: str = "ascii") -> str:
    inp = demo.demo_input(language=language, layout=Layout(tips=True))
    inp = view.RenderInput(**{**inp.__dict__, "now": now})
    theme = themed(UNICODE if charset == "unicode" else ASCII, ColorLevel.OFF, inp.look)
    return renderer.render(inp, width, theme)


def test_the_tip_depends_on_the_day_alone() -> None:
    # pinned: demo.NOW is 2026-11-26 in UTC
    assert tips.of_day(demo.NOW) == tips.TIPS[(demo.NOW // DAY) % len(tips.TIPS)]
    start = demo.NOW - demo.NOW % DAY
    assert tips.of_day(start) == tips.of_day(start + DAY - 1)
    assert tips.of_day(start) != tips.of_day(start + DAY)
    week = [tips.of_day(start + n * DAY) for n in range(len(tips.TIPS))]
    assert sorted(week) == sorted(tips.TIPS)  # every tip has its day
    assert tips.of_day(0) == "tip.explain"


def test_every_tip_is_in_both_catalogues() -> None:
    german = i18n.load("de")
    assert german is not None
    assert set(tips.TIPS) <= i18n.english().ids() and set(tips.TIPS) <= german.ids()
    assert sorted(i for i in i18n.english().ids() if i.startswith("tip.")) == sorted(tips.TIPS)


def test_tips_are_off_unless_asked_for() -> None:
    assert config.defaults().layout.tips is False
    assert Layout().tips is False
    built = view.build(demo.demo_input())
    assert (built.tip, built.tip_title) == ("", "")


def test_the_config_switches_them_on() -> None:
    assert config.check_content(b"[layout]\ntips = true\n") == []
    assert [m.id for m in config.check_content(b'[layout]\ntips = "yes"\n')] == [
        "config.error.bool"
    ]


@pytest.mark.parametrize("charset", ["ascii", "unicode"])
@pytest.mark.parametrize("language", ["en", "de"])
@pytest.mark.parametrize("width", (80, 70, 50))
def test_every_tip_shows_whole_and_fits(width: int, language: str, charset: str) -> None:
    tr = i18n.translator(language)
    for n, msg_id in enumerate(tips.TIPS):
        now = (len(tips.TIPS) * 1000 + n) * DAY
        lines = _render(width, language, now, charset).splitlines()
        title = tr.message("section.tip")
        at = max(i for i, line in enumerate(lines) if f" {title} " in f" {line} ")
        shown = " ".join(line.strip("|│ ") for line in lines[at + 1 :] if line.strip("+└─┘- "))
        expected = tr.message(msg_id)
        if charset == "ascii":
            expected = themed(ASCII, ColorLevel.OFF).text(expected, 500)
        assert shown == expected, msg_id
        assert max(cell_width(line) for line in lines) <= width
        assert not any(CUT.search(line) for line in lines[at:])


def test_the_tip_comes_last() -> None:
    lines = _render(80).splitlines()
    assert "/ Tip /" in lines[-3] or "/ Tip /" in lines[-4]


@pytest.mark.parametrize("language", ["en", "de"])
def test_the_narrowest_layout_leaves_the_tip_out(language: str) -> None:
    tr = i18n.translator(language)
    start = demo.NOW - demo.NOW % DAY
    for day in range(len(tips.TIPS)):
        now = start + day * DAY
        narrow = " ".join(_render(30, language, now).split())
        with_tips_off = view.RenderInput(
            **{**demo.demo_input(language=language).__dict__, "now": now}
        )
        plain = renderer.render(with_tips_off, 30, themed(ASCII, ColorLevel.OFF))
        assert narrow == " ".join(plain.split()), tips.of_day(now)
        assert tr.message("section.tip") + " " not in narrow


def test_a_tip_shows_even_when_there_is_nothing_else() -> None:
    inp = view.RenderInput(sources=(), now=0, hostname="web01", layout=Layout((), "off", tips=True))
    text = renderer.render(inp, 80, themed(ASCII, ColorLevel.OFF))
    assert "motp explain TOPIC" in text


def test_static_mode_shows_the_tip() -> None:
    inp = demo.demo_input(language="de", layout=Layout(tips=True))
    text = renderer.render_static(inp)
    assert "/ Tipp /" in text and text.isascii()


def _settings(layout: Layout) -> bytes:
    return cache.encode_render_file(RenderSettings(1, layout, "auto", {}, 300, 1000, ""))


@pytest.mark.parametrize("on", [True, False])
def test_render_json_carries_the_switch(on: bool) -> None:
    assert cache.decode_render_file(_settings(Layout(tips=on))).layout.tips is on


def test_a_render_json_without_the_switch_still_reads() -> None:
    document = json.loads(_settings(Layout()))
    del document["layout"]["tips"]
    assert cache.decode_render_file(json.dumps(document).encode()).layout.tips is False


@pytest.mark.parametrize("value", [1, "true", None])
def test_render_json_refuses_another_type(value: object) -> None:
    document = json.loads(_settings(Layout()))
    document["layout"]["tips"] = value
    with pytest.raises(ContractError):
        cache.decode_render_file(json.dumps(document).encode())

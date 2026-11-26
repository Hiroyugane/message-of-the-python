"""``motp preview --demo`` and invariant 4 (blueprint 4.6, section 10)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from motp import cli

from .conftest import ROOT, SRC, TOOLS

GOLDEN = Path(__file__).resolve().parent / "golden"


def test_no_color_env_gives_no_escape_byte(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.delenv("MOTP_COLOR", raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert cli.main(["preview", "--demo", "--width", "80"]) == 0
    out = capfd.readouterr().out
    assert "\x1b" not in out and "Attention" in out


def test_motp_color_always_beats_no_color(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("MOTP_COLOR", "always")
    assert cli.main(["preview", "--demo", "--width", "80"]) == 0
    assert "\x1b[" in capfd.readouterr().out


# --- command line -------------------------------------------------------------------------------


def test_preview_shows_the_demo_without_a_flag(capfd: pytest.CaptureFixture[str]) -> None:
    """Final review, usability item 10: the old code printed only an error."""
    assert cli.main(["preview", "--width", "80"]) == 0
    with_flag = capfd.readouterr().out
    assert cli.main(["preview", "--demo", "--width", "80"]) == 0
    assert "web01" in with_flag and with_flag == capfd.readouterr().out


@pytest.mark.parametrize("width", ["9", "1001"])
def test_preview_refuses_a_silly_width(width: str, capfd: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["preview", "--demo", "--width", width]) == 2


def test_preview_writes_the_golden_demo(capfd: pytest.CaptureFixture[str]) -> None:
    args = ["preview", "--demo", "--width", "70", "--charset", "ascii", "--color", "never"]
    assert cli.main(args) == 0
    expected = (GOLDEN / "demo-70-ascii-plain.txt").read_bytes().decode("utf-8")
    assert capfd.readouterr().out.replace("\r\n", "\n") == expected


# --- invariant 4: the demo renders from the built archive under -I -S -------------------------


def test_invariant_4_archive_renders_the_demo(tmp_path: Path) -> None:
    sys.path.insert(0, str(TOOLS))
    import build_pyz

    archive = tmp_path / "motp.pyz"
    build_pyz.build(SRC, archive)
    args = ["preview", "--demo", "--width", "80", "--charset", "unicode", "--color", "never"]
    env = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(archive), *args],
        capture_output=True,
        env=env,
        cwd=str(ROOT),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    expected = (GOLDEN / "demo-80-unicode-plain.txt").read_bytes()
    assert result.stdout.replace(b"\r\n", b"\n") == expected

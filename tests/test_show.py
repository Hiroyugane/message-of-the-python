"""``motp show``: live values, cache files, errors, the deadline and hostile files (phase 5)."""

import io
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest

from motp import entry, show
from motp.core import cache
from motp.core.model import Item, LiteralText, ModuleResult
from motp.core.thresholds import Direction, Rule
from motp.render import demo

from .conftest import ROOT, SRC, TOOLS
from .support import NOW, FixtureContext, render_settings, write_cache
from .test_sanitize import HOSTILE

ENV = {"MOTP_CHARSET": "ascii", "NO_COLOR": "1", "LANG": "C"}
NOTICE = "No collected data found"
UID = os.getuid() if hasattr(os, "getuid") else 1000
posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX files")


@pytest.fixture(autouse=True)
def posix_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows reports every file as writable by all: show the reader what POSIX would."""
    if os.name == "posix":
        return
    real = os.fstat

    def fstat(fd: int) -> SimpleNamespace:
        st = real(fd)
        return SimpleNamespace(st_mode=st.st_mode & ~0o022, st_size=st.st_size, st_uid=UID)

    monkeypatch.setattr("motp.core.cache.os.fstat", fstat)


def demo_results(skip: tuple[str, ...] = ()) -> dict[str, ModuleResult]:
    return {s.module: s.result for s in demo.sources() if s.module not in skip}


def run(
    directory: Path,
    tree: str = "debian12",
    *,
    login: bool = False,
    debug: bool = False,
    uid: Optional[int] = UID,
    width: int = 80,
    env: Optional[dict[str, str]] = None,
    now: int = NOW,
) -> tuple[int, str]:
    stream = io.StringIO()
    code = show.main(
        login=login,
        debug=debug,
        cache_dir=str(directory),
        owner=None,
        context=FixtureContext(tree, now=now),
        uid=uid,
        env=ENV if env is None else env,
        stream=stream,
        width=width,
    )
    return code, stream.getvalue()


# --- the three situations ----------------------------------------------------------------


def test_without_a_cache_the_live_values_and_one_notice(tmp_path: Path) -> None:
    code, out = run(tmp_path / "missing")
    assert code == 0
    assert out.count(NOTICE) == 1
    for label in ("Uptime", "Load", "Memory", "Swap"):
        assert label in out
    assert "0.42, 0.37, 0.31" in out
    assert "41 days 3 hours" in out
    assert "Host" not in out.replace("Hostname", "") and "Disks" not in out


def test_with_a_cache_host_and_disks_rows_join_the_live_system_block(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings())
    code, out = run(tmp_path, "almalinux9")
    assert code == 0 and NOTICE not in out
    assert "Hostname" in out and "web01.example.com" in out
    assert "Disks" in out and "96% of 40 GiB" in out
    # live values win over the demo's cached ones of the same modules
    assert "3.52, 3.10, 2.80" in out and "0.42, 0.37, 0.31" not in out
    assert "The collected data is" not in out


def test_a_cache_older_than_three_timer_periods_says_how_old(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings(timer_period=300))
    _, fresh = run(tmp_path, now=NOW + 3 * 300)
    _, old = run(tmp_path, now=NOW + 3 * 300 + 1)
    assert "The collected data is" not in fresh
    assert "The collected data is 15 min" in old


def test_stale_and_expired_items(tmp_path: Path) -> None:
    results = demo_results()
    disks = results["hw_disks"]
    results["hw_disks"] = replace(disks, collected=NOW - 4 * disks.interval)  # stale
    updates = results["os_updates"]
    results["os_updates"] = replace(updates, collected=NOW - updates.max_age - 1)  # expired
    write_cache(tmp_path, results, settings=render_settings(timer_period=10**5))
    _, out = run(tmp_path)
    assert "(20 minutes old)" in out
    assert "unknown" in out
    assert "openssl" not in out


def test_thresholds_from_render_json_classify_live_values(tmp_path: Path) -> None:
    rules = {"load_per_core": Rule("load_per_core", 0.01, 0.02, Direction.HIGHER_IS_WORSE)}
    write_cache(tmp_path, demo_results(), settings=render_settings(rules=rules))
    _, out = run(tmp_path)
    assert "[!!]" in out  # the debian fixture's 0.09 per core is critical under that rule
    write_cache(tmp_path / "plain", demo_results(), settings=render_settings())
    _, plain = run(tmp_path / "plain")
    assert "0.42, 0.37, 0.31 [" not in plain


def test_default_rules_warn_without_render_json(tmp_path: Path) -> None:
    _, out = run(tmp_path / "none", "almalinux9")
    assert "[!!]" in out  # load 1.55 per core, memory 92 percent


def test_admin_tier_is_used_when_readable(tmp_path: Path) -> None:
    results = demo_results()
    write_cache(tmp_path / "a", results, admin=results, settings=render_settings())
    write_cache(tmp_path / "b", results, settings=render_settings())
    _, with_admin = run(tmp_path / "a")
    _, without = run(tmp_path / "b")
    assert "openssl, curl, libc6" in with_admin
    assert "openssl, curl, libc6" not in without


def test_language_and_layout_come_from_render_json(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings(language="xx"))
    code, out = run(tmp_path)  # no such catalogue: English
    assert code == 0 and "Hostname" in out


def test_narrow_terminal(tmp_path: Path) -> None:
    _, out = run(tmp_path / "none", width=30)
    assert out and all(len(line) <= 30 for line in out.splitlines())


def test_nothing_without_proc(tmp_path: Path) -> None:
    stream = io.StringIO()
    code = show.main(
        cache_dir=str(tmp_path / "none"),
        owner=None,
        context=FixtureContext("nothing", root=tmp_path),
        uid=1,
        env=ENV,
        stream=stream,
        width=80,
    )
    assert code == 0 and NOTICE in stream.getvalue()


# --- the previous login ------------------------------------------------------------------


def write_user(directory: Path, uid: int, started: list[int]) -> None:
    folder = directory / "user"
    folder.mkdir(parents=True, exist_ok=True)
    logins = [{"started": t, "source": "198.51.100.7", "tty": "pts/0"} for t in started]
    body = {"schema": 1, "uid": uid, "generated": NOW, "logins": logins}
    (folder / f"{uid}.json").write_text(json.dumps(body), encoding="utf-8")


def test_previous_login_only_with_login_flag(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(skip=("os_login",)), settings=render_settings())
    write_user(tmp_path, UID, [NOW - 2, NOW - 7380])  # the first is the current session
    _, plain = run(tmp_path)
    _, logged = run(tmp_path, login=True)
    assert "Last login" not in plain
    assert "Last login" in logged and "2 hours 3 minutes ago" in logged
    assert "198.51.100.7" in logged and "pts/0" in logged


def test_other_users_file_is_not_read(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(skip=("os_login",)), settings=render_settings())
    write_user(tmp_path, UID + 1, [NOW - 7380])
    _, out = run(tmp_path, login=True, uid=UID)
    assert "Last login" not in out


def test_user_file_with_a_wrong_uid_is_ignored(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(skip=("os_login",)), settings=render_settings())
    write_user(tmp_path, UID + 1, [NOW - 7380])
    os.replace(tmp_path / "user" / f"{UID + 1}.json", tmp_path / "user" / f"{UID}.json")
    _, out = run(tmp_path, login=True, uid=UID)
    assert "Last login" not in out


# --- errors -----------------------------------------------------------------------------


@pytest.fixture
def broken_render(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kw: object) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr("motp.show.renderer.render", boom)


def test_login_swallows_every_error(
    broken_render: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run(tmp_path, login=True)
    captured = capsys.readouterr()
    assert (code, out, captured.out, captured.err) == (0, "", "", "")


def test_without_login_an_error_is_shown_and_fails(
    broken_render: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run(tmp_path)
    err = capsys.readouterr().err
    assert (code, out) == (1, "")
    assert "motp show failed: RuntimeError" in err and "Traceback" not in err


def test_debug_shows_the_traceback_even_with_login(
    broken_render: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = run(tmp_path, login=True, debug=True)
    err = capsys.readouterr().err
    assert code == 0 and "Traceback" in err and "boom" in err


def test_debug_lists_why_files_were_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "public.json").write_text("{not json", encoding="utf-8")
    code, out = run(tmp_path, debug=True)
    err = capsys.readouterr().err
    assert code == 0 and NOTICE in out
    assert "ignored public.json" in err and "ignored render.json" in err
    _, quiet = run(tmp_path)
    assert capsys.readouterr().err == "" and quiet == out


def test_a_failing_live_module_is_counted_not_fatal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Broken(FixtureContext):
        def _read_bytes(self, path: str, max_bytes: int) -> bytes:
            if path.endswith("loadavg"):
                return b"garbage"
            return super()._read_bytes(path, max_bytes)

    stream = io.StringIO()
    code = show.main(
        debug=True,
        cache_dir=str(tmp_path),
        owner=None,
        context=Broken("debian12"),
        uid=1,
        env=ENV,
        stream=stream,
        width=80,
    )
    out, err = stream.getvalue(), capsys.readouterr().err
    assert code == 0 and "Memory" in out and "Load" not in out
    assert "1 module failed" in out
    assert "module hw_load failed" in err


# --- hostile files ----------------------------------------------------------------------


def test_hostile_cache_strings_render_inert(tmp_path: Path) -> None:
    results = demo_results()
    for i, raw in enumerate(h for h in HOSTILE if h.isascii() or _encodable(h)):
        name = f"5{i % 10}-evil{i}"
        item = Item(
            key=f"plugin.evil{i}.x",
            value=raw,
            label=LiteralText(raw),
            text=LiteralText(raw),
            hint=LiteralText(raw),
            origin=name,
        )
        results[name] = ModuleResult(collected=NOW, interval=300, max_age=900, items=(item,))
    write_cache(tmp_path, results, admin=results, settings=render_settings())
    code, out = run(tmp_path, env={"MOTP_CHARSET": "unicode", "NO_COLOR": "1"})
    assert code == 0
    assert "\x1b" not in out and "\x07" not in out and "\x9b" not in out
    assert "‮" not in out and "⁧" not in out and "⁦" not in out
    assert all(ch == "\n" or ch.isprintable() for ch in out)
    widths = {len(line) for line in out.splitlines()}
    assert max(widths) <= 80


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _make_fifo(path: Path) -> None:
    os.mkfifo(path)


def _make_link(path: Path) -> None:
    target = path.parent / "real.json"
    target.write_text("{}", encoding="utf-8")
    os.symlink(target, path)


def _make_dir(path: Path) -> None:
    path.mkdir()


def _make_huge(path: Path) -> None:
    with open(path, "wb") as handle:
        handle.truncate(100 * 1024 * 1024)


@pytest.mark.parametrize(
    "maker",
    [
        pytest.param(_make_fifo, marks=posix_only, id="fifo"),
        pytest.param(_make_link, marks=posix_only, id="symlink"),
        pytest.param(_make_dir, id="directory"),
        pytest.param(_make_huge, id="100mib"),
    ],
)
@pytest.mark.parametrize("name", ["public.json", "render.json", "admin.json"])
def test_special_cache_paths_are_ignored_without_delay(
    maker: object, name: str, tmp_path: Path
) -> None:
    others = {"public.json", "render.json", "admin.json"} - {name}
    write_cache(tmp_path, demo_results(), admin=demo_results(), settings=render_settings())
    for other in others:
        (tmp_path / other).unlink()
    (tmp_path / name).unlink()
    assert callable(maker)
    maker(tmp_path / name)
    started = time.monotonic()
    code, out = run(tmp_path)
    assert time.monotonic() - started < 2.0
    assert code == 0 and "Load" in out
    assert NOTICE in out  # nothing usable was left in the directory


@posix_only
def test_a_directory_that_belongs_to_someone_else_is_ignored(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings())
    stream = io.StringIO()
    wrong = os.getuid() + 1
    show.main(
        cache_dir=str(tmp_path),
        owner=wrong,
        context=FixtureContext("debian12"),
        uid=1,
        env=ENV,
        stream=stream,
        width=80,
    )
    assert NOTICE in stream.getvalue()


@posix_only
def test_a_group_writable_directory_is_ignored(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings())
    tmp_path.chmod(0o775)
    stream = io.StringIO()
    show.main(
        cache_dir=str(tmp_path),
        owner=os.getuid(),
        context=FixtureContext("debian12"),
        uid=1,
        env=ENV,
        stream=stream,
        width=80,
    )
    assert NOTICE in stream.getvalue()


@posix_only
def test_a_cache_file_of_the_right_owner_is_read(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings())
    tmp_path.chmod(0o755)
    stream = io.StringIO()
    show.main(
        cache_dir=str(tmp_path),
        owner=os.getuid(),
        context=FixtureContext("debian12"),
        uid=1,
        env=ENV,
        stream=stream,
        width=80,
    )
    assert NOTICE not in stream.getvalue() and "Hostname" in stream.getvalue()


# --- argument handling and the deadline ----------------------------------------------------


@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], (False, False)),
        (["show"], (False, False)),
        (["show", "--login"], (True, False)),
        (["--login", "--debug"], (True, True)),
        (["show", "--debug", "--login"], (True, True)),
    ],
)
def test_show_args(argv: list[str], expected: tuple[bool, bool]) -> None:
    flags = entry.show_args(argv)
    assert flags is not None
    assert (flags["login"], flags["debug"]) == expected


@pytest.mark.parametrize(
    "argv", [["version"], ["show", "--width"], ["show", "x"], ["config", "check"], ["--help"]]
)
def test_other_command_lines_go_to_the_cli(argv: list[str]) -> None:
    assert entry.show_args(argv) is None


SLEEPER = """
import sys, time
sys.path.insert(0, {src!r})
from motp import show
from motp.core import deadline
from motp.modules import registry

class Sleeper:
    name = "hw_load"; section = "system"; mode = "live"; needs_root = False
    interval = 1; max_age = 60; timeout = 1.0; binaries = (); default_visibility = None
    def detect(self, ctx):
        from motp.modules.base import Detection
        return Detection(True)
    def collect(self, ctx):
        {body}

registry.LIVE_MODULES = (Sleeper(),)
deadline.arm({seconds})
sys.exit(show.main(cache_dir={cache!r}, owner=None, uid=1))
"""


@pytest.mark.parametrize(
    "body",
    [
        "time.sleep(60)",
        "while True: pass",
        "while True:\n            try:\n                time.sleep(60)\n"
        "            except BaseException:\n                pass",
        "try:\n            time.sleep(60)\n        finally:\n            time.sleep(60)",
    ],
    ids=["sleep", "busy", "swallow", "finally"],
)
def test_a_module_that_sleeps_ends_at_the_deadline_with_exit_0_and_no_output(
    body: str, tmp_path: Path
) -> None:
    code = SLEEPER.format(src=str(SRC), body=body, seconds=0.4, cache=str(tmp_path / "none"))
    started = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, timeout=30, check=False
    )
    elapsed = time.monotonic() - started
    assert done.returncode == 0
    assert done.stdout == b"" and done.stderr == b""
    assert elapsed < 10.0


@posix_only
def test_render_json_shortens_the_limit(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings(render_ms=300))
    code = SLEEPER.format(
        src=str(SRC), body="time.sleep(60)", seconds=30, cache=str(tmp_path)
    ).replace("owner=None", "owner=None, context=None")
    started = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, timeout=30, check=False
    )
    assert done.returncode == 0 and done.stdout == b""
    assert time.monotonic() - started < 10.0


def test_python_dash_m_motp_show_runs_from_the_source_tree(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(SRC), "MOTP_CHARSET": "ascii", "NO_COLOR": "1", "COLUMNS": "60"}
    done = subprocess.run(
        [sys.executable, "-m", "motp", "show"],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        cwd=ROOT,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip()


def test_cache_fixture_is_valid_json_of_the_reader(tmp_path: Path) -> None:
    write_cache(tmp_path, demo_results(), settings=render_settings())
    assert cache.read_tier_file(str(tmp_path / "public.json"), cache.PUBLIC, None).modules


def test_a_cached_os_login_is_never_shown(tmp_path: Path) -> None:
    """The previous login comes from the reader's own file only (D32), not from a tier file."""
    write_cache(tmp_path, demo_results(), admin=demo_results(), settings=render_settings())
    for login in (False, True):
        _, out = run(tmp_path, login=login)
        assert "Last login" not in out and "198.51.100.7" not in out


def test_a_broken_pipe_is_not_an_error() -> None:
    class Closed(io.StringIO):
        def write(self, text: str) -> int:
            raise BrokenPipeError

    code = show.main(
        cache_dir="/nonexistent",
        owner=None,
        context=FixtureContext("debian12"),
        uid=1,
        env=ENV,
        stream=Closed(),
        width=80,
    )
    assert code == 0


def test_login_entry_is_silent_when_the_import_or_the_run_dies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for error in (KeyboardInterrupt(), ImportError("broken"), SyntaxError("bad")):

        def boom(login: bool, debug: bool, error: BaseException = error) -> int:
            raise error

        monkeypatch.setattr(show, "main", boom)
        assert entry.main(["show", "--login"]) == 0
    assert capsys.readouterr().err == ""
    with pytest.raises(SyntaxError):
        entry.main(["show", "--login", "--debug"])
    with pytest.raises(SyntaxError):
        entry.main(["show"])


def test_both_start_programs_arm_the_deadline_before_the_dispatch() -> None:
    sys.path.insert(0, str(TOOLS))
    import build_pyz

    texts = (build_pyz.MAIN_SOURCE, (SRC / "motp" / "__main__.py").read_text("utf-8"))
    for text in texts:
        assert text.index("deadline.arm()") < text.index("entry.main(")


def test_limit_stays_off_after_disarm() -> None:
    from motp.core import deadline

    deadline.arm(60)
    deadline.disarm()
    deadline.limit(0.001)  # would end this process if the limit were still armed
    time.sleep(0.05)


def test_motp_plain_drops_header_frame_and_leaders_only(tmp_path: Path) -> None:
    """Final review, usability item 15: a per-user plain mode, presentation only."""
    _code, framed = run(tmp_path, width=80)
    code, plain = run(tmp_path, width=80, env={**ENV, "MOTP_PLAIN": "1"})
    assert code == 0
    assert "+---" in framed and "+---" not in plain and "|" not in plain
    assert ".....:" in framed and ".....:" not in plain
    labels = [ln.split(":")[0].strip("| .") for ln in framed.splitlines() if ".:" in ln]
    assert labels and all(f"{label}:" in plain for label in labels), "the same rows"

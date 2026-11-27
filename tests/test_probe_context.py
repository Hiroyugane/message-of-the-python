"""The probe side: ``ProbeContext`` and ``motp _probe <name>`` (blueprint 4.3, 4.4, D21).

A cached module reads more than a live one (``/etc``, ``/usr/lib``, ``/run``, following
links, regular files only), may ask for file system usage, and may start only the programs
it lists. The probe command prints one document in the built-in probe form.
"""

import io
import os
import sys
from pathlib import Path

import pytest

from motp.collect import child, context
from motp.collect.context import MAX_DIR_ENTRIES, RUN_STDOUT_CAP, ProbeContext
from motp.core import proc, safepath, strictjson
from motp.core.model import ContractError, HintRef, Item, Visibility, ref
from motp.modules import registry
from motp.modules.base import Context, Detection, parse_os_release

from .support import trusted_python

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux")


def _raises(msg_id: str, call: "object") -> None:
    with pytest.raises(ContractError) as exc:
        call()  # type: ignore[operator]
    assert exc.value.message.id == msg_id


# --- the context -----------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/home/x", "/root/x", "etc/x", "/etc/../root/x", "/etc//x"])
def test_reads_stay_below_the_probe_roots(path: str) -> None:
    _raises("context.error.path", lambda: ProbeContext().read_text(path))


def test_live_context_keeps_its_narrow_roots() -> None:
    _raises("context.error.path", lambda: Context().read_text("/etc/os-release"))
    _raises("context.error.statvfs", lambda: Context().statvfs("/"))


@pytest.mark.parametrize("path", ["relative", "/a/../b", "/a//b", "/a\0"])
def test_statvfs_needs_a_normalised_absolute_path(path: str) -> None:
    _raises("context.error.path", lambda: ProbeContext().statvfs(path))


@pytest.mark.parametrize("argv", [[], ["/bin/sh", "-c", "id"], ["sh"], ["/bin/echo/../sh"]])
def test_only_listed_programs_may_start(argv: "list[str]") -> None:
    ctx = ProbeContext(binaries=("/bin/echo",))
    _raises("context.error.binary", lambda: ctx.run(argv))


@linux
def test_a_listed_program_runs_through_proc() -> None:
    # The interpreter, not /bin/echo: on AlmaLinux that is a link to the coreutils
    # multi-call program, which check_program refuses for root as a launcher. Not
    # always sys.executable: run() refuses one below a directory others can write.
    python = trusted_python()
    ctx = ProbeContext(binaries=(python,))
    assert ctx.run([python, "-I", "-S", "-c", "print('hi')"]) == b"hi\n"
    _raises(
        "context.error.run_failed",
        lambda: ctx.run([python, "-I", "-S", "-c", "raise SystemExit(1)"]),
    )


@linux
def test_other_exit_codes_count_only_when_the_module_names_them() -> None:
    python = trusted_python()
    ctx = ProbeContext(binaries=(python,))
    argv = [python, "-I", "-S", "-c", "print('x'); raise SystemExit(100)"]
    assert ctx.run(argv, ok_codes=(0, 100)).rstrip() == b"x"
    _raises("context.error.run_failed", lambda: ctx.run(argv))
    _raises("context.error.run_failed", lambda: ctx.run(argv, ok_codes=(0, 1)))


@linux
def test_a_program_that_writes_too_much_is_rejected() -> None:
    python = trusted_python()
    ctx = ProbeContext(binaries=(python,))
    program = "import sys; sys.stdout.write('x' * {})"
    fits = [python, "-I", "-S", "-c", program.format(RUN_STDOUT_CAP)]
    assert len(ctx.run(fits)) == RUN_STDOUT_CAP
    more = [python, "-I", "-S", "-c", program.format(RUN_STDOUT_CAP + 1)]
    _raises("context.error.run_failed", lambda: ctx.run(more))
    code = (
        "import itertools, sys; any(sys.stdout.write('x' * 65536) < 0 for _ in itertools.count())"
    )
    endless = [python, "-I", "-S", "-c", code]
    _raises("context.error.run_failed", lambda: ctx.run(endless))


@linux
def test_listing_and_file_times(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("b", "a"):
        (tmp_path / name).write_text("")
    ctx = ProbeContext()
    if getattr(os, "geteuid", lambda: 1)() == 0:  # as root: never below the world-writable /tmp
        _raises("context.error.read", lambda: ctx._list_dir(str(tmp_path)))
        _raises("context.error.read", lambda: ctx._mtime(str(tmp_path / "a")))
    monkeypatch.setattr(context, "_as_root", lambda: False)  # as the user motp
    assert sorted(ctx._list_dir(str(tmp_path))) == ["a", "b"]
    os.utime(tmp_path / "a", (1_000_000, 1_000_000))
    assert ctx._mtime(str(tmp_path / "a")) == 1_000_000
    _raises("context.error.read", lambda: ctx._list_dir(str(tmp_path / "a")))
    _raises("context.error.read", lambda: ctx._mtime(str(tmp_path / "gone")))


class _Listing(ProbeContext):
    def _list_dir(self, path: str) -> "list[str]":
        return [f"n{n}" for n in range(MAX_DIR_ENTRIES + 1)]


def test_a_directory_with_too_many_entries_is_refused() -> None:
    _raises("context.error.read", lambda: _Listing().list_dir("/var/cache/dnf"))


@pytest.mark.parametrize("path", ["/var/spool/x", "/var/cache/../log", "/home/x", "relative"])
def test_listing_and_file_times_stay_below_the_roots(path: str) -> None:
    _raises("context.error.path", lambda: ProbeContext().list_dir(path))
    _raises("context.error.path", lambda: ProbeContext().mtime(path))


@linux
def test_reads_follow_links_but_only_into_regular_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "real"
    target.write_text("ok\n")
    (tmp_path / "link").symlink_to(target)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    ctx = ProbeContext()
    if os.geteuid() == 0:  # a root probe never reads below the world-writable /tmp
        _raises("context.error.read", lambda: ctx._read_bytes(str(tmp_path / "link"), 100))
    monkeypatch.setattr(context, "_as_root", lambda: False)  # as the user motp
    assert ctx._read_bytes(str(tmp_path / "link"), 100) == b"ok\n"
    _raises("context.error.read", lambda: ctx._read_bytes(str(fifo), 100))
    _raises("context.error.read", lambda: ctx._read_bytes(str(tmp_path), 100))


@linux
def test_statvfs_reports_bytes_and_inodes() -> None:
    usage = ProbeContext().statvfs("/")
    assert usage.size > 0 and 0 <= usage.available <= usage.size


def test_os_release_parser_handles_quotes_and_skips_junk() -> None:
    text = 'A="x \\"y\\" z"\nB=\'single\'\nc=lower\nnoequals\nD=plain\n'
    assert parse_os_release(text) == {"A": 'x "y" z', "B": "single", "D": "plain"}


# --- the probe command -----------------------------------------------------------------


class _Fake:
    name = "fake"
    section = "host"
    mode = "cached"
    needs_root = False
    interval = 300
    max_age = 3600
    timeout = 3.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(True)

    def collect(self, ctx: Context) -> "list[Item]":
        return [Item(key="fake.one", value="x", label=ref("label.os"))]


class _Broken(_Fake):
    def collect(self, ctx: Context) -> "list[Item]":
        raise ZeroDivisionError


def test_probe_command_prints_a_valid_document(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "cached_module", lambda name: _Fake())
    out, err = io.StringIO(), io.StringIO()
    assert child.main("fake", out, err) == 0
    doc = strictjson.loads(out.getvalue().encode(), max_bytes=65536, max_depth=8)
    assert doc == {
        "api": 1,
        "module": "fake",
        "items": [
            {
                "key": "fake.one",
                "unit": "text",
                "visibility": "public",
                "value": "x",
                "label": {"id": "label.os"},
            }
        ],
    }


@pytest.mark.parametrize(("module_time", "program_time"), [(3.0, 3.0), (30.0, 30.0)])
def test_a_program_gets_the_modules_time(
    monkeypatch: pytest.MonkeyPatch, module_time: float, program_time: float
) -> None:
    """A package manager may need longer than the context's default of 5 seconds."""
    seen: list[float] = []

    class _Slow(_Fake):
        timeout = module_time

        def collect(self, ctx: Context) -> "list[Item]":
            assert isinstance(ctx, ProbeContext)
            seen.append(ctx.run_timeout)
            return []

    monkeypatch.setattr(registry, "cached_module", lambda name: _Slow())
    assert child.main("fake", io.StringIO(), io.StringIO()) == 0
    assert seen == [program_time]


def test_probe_command_reports_failures_on_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    out, err = io.StringIO(), io.StringIO()
    assert child.main("no_such_module", out, err) == 2
    assert err.getvalue() == "probe.error.unknown_module\n"
    monkeypatch.setattr(registry, "cached_module", lambda name: _Broken())
    out, err = io.StringIO(), io.StringIO()
    assert child.main("fake", out, err) == 1
    assert (out.getvalue(), err.getvalue()) == ("", "ZeroDivisionError\n")


def test_probe_items_use_plain_hint_ids() -> None:
    item = Item(key="hw_disks.root", hint=HintRef("disk.space"))
    assert child.probe_item(item)["hint"] == "disk.space"


def test_the_probe_command_skips_argparse() -> None:
    from motp import entry

    assert entry.main(["_probe"]) == 2
    assert entry.main(["_probe", "a", "b"]) == 2


def _program_times(monkeypatch: pytest.MonkeyPatch, ctx: ProbeContext, runs: int) -> list[float]:
    seen: list[float] = []

    def fake_run(spec: proc.Spec) -> proc.Result:
        seen.append(spec.timeout)
        return proc.Result(0, b"", b"", False, False, False, 0.0)

    monkeypatch.setattr(proc, "run", fake_run)
    monkeypatch.setattr(safepath, "check_program", lambda path, runs_as_root: _Program(path))
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    for _ in range(runs):
        ctx.run(["/usr/bin/true"])
    return seen


class _Program:
    def __init__(self, path: str) -> None:
        self.path = path


def test_two_programs_share_the_probes_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """dnf is asked twice: both together must end before the collector ends the probe."""
    now = [100.0]
    ctx = ProbeContext(
        binaries=("/usr/bin/true",), run_timeout=29.0, deadline=129.0, clock=lambda: now[0]
    )

    seen = _program_times(monkeypatch, ctx, 1)
    now[0] += 20.0
    seen += _program_times(monkeypatch, ctx, 1)
    assert seen == [29.0, 9.0]
    now[0] += 9.0
    _raises("context.error.run_failed", lambda: ctx.run(["/usr/bin/true"]))


@pytest.mark.parametrize(
    ("given", "module_time", "left"),
    [("30.0", 5.0, 29.0), ("2.0", 30.0, 1.5), (None, 30.0, 29.0), ("junk", 10.0, 9.0),
     ("nan", 10.0, 9.0), ("1e9", 10.0, 9.0)],
)  # fmt: skip
def test_the_probes_time_comes_from_the_collector(
    monkeypatch: pytest.MonkeyPatch, given: "str | None", module_time: float, left: float
) -> None:
    """A configured ``timeout_s`` reaches the probe, so its programs end in time."""
    seen: list[float] = []

    class _Timed(_Fake):
        timeout = module_time

        def collect(self, ctx: Context) -> "list[Item]":
            assert isinstance(ctx, ProbeContext) and ctx.deadline is not None
            seen.append(ctx.deadline - ctx.clock())
            return []

    monkeypatch.setattr(registry, "cached_module", lambda name: _Timed())
    monkeypatch.delenv("MOTP_TIMEOUT", raising=False)
    if given is not None:
        monkeypatch.setenv("MOTP_TIMEOUT", given)
    assert child.main("fake", io.StringIO(), io.StringIO()) == 0
    assert seen == [pytest.approx(left, abs=0.2)]


@linux
def test_a_scratch_directory_is_private_and_removed() -> None:
    with ProbeContext().scratch_dir() as path:
        assert os.stat(path).st_mode & 0o777 == 0o700
        Path(path, "log").write_text("x")
    assert not os.path.exists(path)

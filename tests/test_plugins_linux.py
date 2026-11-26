"""Exec plugins and the ``file_age`` row as root, with real files (phase 12).

These run inside the containers of ``tools/container_test.py`` (``needs_linux_owner``), in
the root-owned tree of ``test_collect.World``: what discovery accepts and refuses (proved by
a mark a refused plugin would have written), the user a plugin runs as, hostile output, a
hung, flooding, forking or failing plugin,
the limits a plugin gets, the cap on plugins and a plugin directory that is not one (both
used to end the whole run), checks of the ``#!`` line, visibility for an admin and an
unprivileged reader, ``motp doctor``'s listing, the shim, and the ``file_age`` row as
``motp``. What isolates one plugin from the next (its own transient unit) needs systemd and
is checked by ``tools/systemd_test.py``.
"""

import io
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

import pytest

from motp.collect import plugins
from motp.core import cache, config, proc
from motp.core.model import ContractError, Item, LiteralText, ModuleState, Status, Visibility, ref
from motp.install import doctor
from motp.modules.rows_file_age import RowsFileAge

from .conftest import ADMIN_GROUP, OTHER_USER, PLUGIN_USER, TEST_USER, account
from .test_collect import World, as_user, show_code

pytestmark = pytest.mark.needs_linux_owner


@pytest.fixture
def world(trusted_dir: Path) -> Iterator[World]:
    yield World(trusted_dir)


HELLO = '#!/bin/sh\n# Prints one line; exit code 0 means ok.\necho "Hello from a plugin"\n'


def install(world: World, name: str, text: str, mode: int = 0o755) -> Path:
    directory = world.etc / "plugins.d"
    directory.mkdir(mode=0o755, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def marks(world: World) -> Path:
    """A directory any probe may write a mark into, outside the swept places."""
    path = world.root / "marks"
    path.mkdir(exist_ok=True)
    path.chmod(0o1777)
    return path


def discovered(world: World, settings: Optional[config.Config] = None) -> dict[str, plugins.Found]:
    found = plugins.discover(str(world.etc), settings or config.defaults())
    return {f.name: f for f in found}


def admin_items(world: World, name: str) -> list[Item]:
    return list(world.tier().modules[name].items)


def plugin_places(world: World) -> doctor.Places:
    return doctor.Places(config_root=str(world.etc), cache_dir=str(world.cache_dir))


def test_discovery_accepts_a_root_plugin_and_ignores_other_names(world: World) -> None:
    install(world, "50-hello", HELLO)
    install(world, "README", "not a plugin\n", 0o644)
    install(world, "50-hello.dpkg-old", HELLO)
    install(world, "5-short", HELLO)
    entries = discovered(world)
    assert entries["50-hello"].state == plugins.ACCEPTED
    assert entries["50-hello"].path == str(world.etc / "plugins.d" / "50-hello")
    for name in ("README", "50-hello.dpkg-old", "5-short"):
        assert entries[name].state == plugins.IGNORED


def refused_world(world: World) -> dict[str, Path]:
    """Plugins that must be refused, each writing a mark if it ever ran."""
    box = marks(world)
    uid, gid = account(TEST_USER)
    out: dict[str, Path] = {}

    def plant(name: str, mode: int = 0o755, interpreter: str = "/bin/sh") -> Path:
        mark = box / name
        text = f"#!{interpreter}\n: > {mark}\necho ran\n"
        out[name] = mark
        return install(world, name, text, mode)

    os.chown(plant("10-owner"), uid, gid)  # not root's
    plant("11-groupwrite", 0o775)
    plant("12-worldwrite", 0o757)
    writable = world.root / "open"
    writable.mkdir()
    writable.chmod(0o777)
    shutil.copy2("/bin/sh", writable / "sh")
    plant("13-interpreter", interpreter=str(writable / "sh"))
    plant("14-relative", interpreter="sh")
    plant("15-noexec", 0o644)
    plant("16-setuid", 0o4755)
    target = plant("17-target")
    link = world.etc / "plugins.d" / "18-userlink"
    os.symlink(target, link)
    os.lchown(link, uid, gid)
    out["18-userlink"] = out["17-target"]
    data = world.etc / "plugins.d" / "19-data"
    data.write_bytes(b"echo no format line\n")
    data.chmod(0o755)
    out["19-data"] = box / "19-data"
    return out


REFUSALS = {
    "10-owner": "safepath.error.owner",
    "11-groupwrite": "safepath.error.writable",
    "12-worldwrite": "safepath.error.writable",
    "13-interpreter": "safepath.error.writable",
    "14-relative": "safepath.error.interpreter_relative",
    "15-noexec": "safepath.error.not_executable",
    "16-setuid": "safepath.error.setid",
    "18-userlink": "safepath.error.link_owner",
    "19-data": "safepath.error.unknown_format",
}


def test_wrong_owner_mode_or_interpreter_is_refused_and_never_runs(world: World) -> None:
    planted = refused_world(world)
    entries = discovered(world)
    for name, msg_id in REFUSALS.items():
        entry = entries[name]
        assert entry.state == plugins.REFUSED and entry.reason is not None, name
        assert entry.reason.id == msg_id, (name, entry.reason)
    assert entries["17-target"].state == plugins.ACCEPTED
    assert world.run() == 0, world.log.getvalue()
    modules = world.tier().modules
    for name in REFUSALS:
        assert modules[name].state is ModuleState.FAILED, name
        if name != "18-userlink":  # its target runs under its own name
            assert not planted[name].exists(), f"{name} ran"
    assert modules["17-target"].state is ModuleState.OK
    assert planted["17-target"].exists()  # the mark works: an accepted plugin leaves it
    # motp doctor names every refused one with its reason.
    report = doctor.Report()
    doctor.check_plugins(report, config.defaults(), plugin_places(world), int(time.time()))
    lines = {dict(m.params).get("name"): (level, m) for level, m in report.lines}
    for name in REFUSALS:
        level, message = lines[name]
        assert level == "warn" and message.id == "doctor.plugin_refused", name
    assert lines["17-target"][1].id == "doctor.plugin"
    assert dict(lines["17-target"][1].params)["user"] == PLUGIN_USER


def test_a_root_plugin_may_not_use_an_env_line(world: World) -> None:
    install(world, "50-env", "#!/usr/bin/env sh\necho hi\n")
    world.config('[plugins."50-env"]\nrun_as = "root"\n')
    loaded = config.load(str(world.etc))
    reason = discovered(world, loaded.config)["50-env"].reason
    assert reason is not None and reason.id == "safepath.error.launcher_as_root"
    assert discovered(world)["50-env"].state == plugins.ACCEPTED  # as motp-plugin it may


def test_a_plugin_directory_others_can_write_refuses_every_plugin(world: World) -> None:
    install(world, "50-hello", HELLO)
    (world.etc / "plugins.d").chmod(0o777)
    (entry,) = discovered(world).values()
    assert entry.state == plugins.REFUSED and entry.reason is not None
    assert entry.reason.id == "safepath.error.writable"


def test_at_most_32_plugins_run(world: World) -> None:
    for n in range(10, 10 + plugins.MAX_PLUGINS + 1):
        install(world, f"{n}-p", HELLO)
    states = [f.state for f in plugins.discover(str(world.etc), config.defaults())]
    assert states.count(plugins.ACCEPTED) == plugins.MAX_PLUGINS
    assert states[-1] == plugins.REFUSED


def test_the_three_line_example_shows_to_admins_only(world: World) -> None:
    install(world, "50-hello", HELLO)
    world.config(f'[visibility]\nadmin_group = "{ADMIN_GROUP}"\n')
    assert world.run() == 0, world.log.getvalue()
    (item,) = admin_items(world, "50-hello")
    assert item.text == LiteralText("Hello from a plugin") and item.status is Status.OK
    assert item.visibility is Visibility.ADMIN
    assert "50-hello" not in world.tier(cache.PUBLIC).modules
    admin = as_member(OTHER_USER, ADMIN_GROUP, show_code(world)).decode()
    public = as_user(TEST_USER, show_code(world)).stdout.decode()
    assert "[plugin 50-hello]" in admin and "Hello from a plugin" in admin
    assert "Hello from a plugin" not in public and "50-hello" not in public


EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "plugins"


def test_the_example_plugins_run_as_documented(world: World) -> None:
    hello = (EXAMPLES / "50-hello").read_text(encoding="utf-8")
    assert len(hello.splitlines()) == 3  # docs/plugins.md: "three lines of shell"
    install(world, "50-hello", hello)
    install(world, "60-load-trend", (EXAMPLES / "60-load-trend").read_text(encoding="utf-8"))
    assert world.run() == 0, world.log.getvalue()
    modules = world.tier().modules
    assert modules["50-hello"].state is ModuleState.OK
    assert modules["60-load-trend"].state is ModuleState.OK, modules["60-load-trend"].error
    (trend,) = modules["60-load-trend"].items
    assert trend.key == "plugin.60-load-trend.trend" and len(trend.detail) == 1
    assert isinstance(trend.text, LiteralText) and dict(trend.text.i18n)["de"]  # item 13
    assert isinstance(trend.hint, LiteralText) and dict(trend.hint.i18n)["de"]


def test_a_public_plugin_reaches_the_public_tier(world: World) -> None:
    install(world, "50-hello", HELLO)
    world.config('[plugins."50-hello"]\nvisibility = "public"\n')
    assert world.run() == 0, world.log.getvalue()
    (item,) = world.tier(cache.PUBLIC).modules["50-hello"].items
    assert item.visibility is Visibility.PUBLIC


def test_a_plugin_runs_as_motp_plugin_unless_granted_root(world: World) -> None:
    whoami = "#!/bin/sh\nid -un\n"
    install(world, "50-who", whoami)
    install(world, "51-root", whoami)
    world.config('[plugins."51-root"]\nrun_as = "root"\n')
    assert world.run() == 0, world.log.getvalue()
    assert admin_items(world, "50-who")[0].text == LiteralText(PLUGIN_USER)
    assert admin_items(world, "51-root")[0].text == LiteralText("root")


# A JSON plugin (Python) whose strings carry escape sequences, a bell, a bidi override, a
# built-in key, a catalogue id and a hint id; and a line plugin (shell) with raw escapes.
HOSTILE_JSON = """#!/usr/bin/python3 -I
import json
esc, bell, rlo = chr(27), chr(7), chr(0x202E)
text = esc + "[2J" + esc + "]0;owned" + bell + " updates.summary " + rlo + "evil"
item = {"key": "updates.pending", "label": "label.updates", "text": text,
        "status": "crit", "hint": "updates.install", "visibility": "public"}
print(json.dumps({"api": 1, "items": [item]}))
"""
HOSTILE_LINE = "#!/bin/sh\nprintf '\\033[31mred\\033]0;title\\007 label.os\\n'\nexit 2\n"


def as_member(name: str, group: str, code: str) -> bytes:
    """Run ``code`` as ``name`` with ``group`` as a supplementary group, as a login would
    (``proc.Drop`` gives a probe none)."""
    import grp  # Linux only; the module is collected on Windows too

    uid, gid = account(name)
    done = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code],
        user=uid,
        group=gid,
        extra_groups=[grp.getgrnam(group).gr_gid],
        capture_output=True,
        timeout=60,
        check=False,
    )
    return done.stdout


def test_hostile_output_renders_as_prefixed_inert_text(world: World) -> None:
    install(world, "50-evil", HOSTILE_JSON)
    install(world, "51-line", HOSTILE_LINE)
    world.config(f'[visibility]\nadmin_group = "{ADMIN_GROUP}"\n')
    assert world.run() == 0, world.log.getvalue()
    (item,) = admin_items(world, "50-evil")
    assert item.key == "plugin.50-evil.updates.pending" and item.status is Status.CRIT
    assert item.hint == LiteralText("updates.install")
    assert item.label == LiteralText("label.updates")
    (line,) = admin_items(world, "51-line")
    assert line.status is Status.CRIT
    screen = as_member(OTHER_USER, ADMIN_GROUP, show_code(world))
    assert b"[plugin 50-evil]" in screen and b"[plugin 51-line]" in screen
    for bad in (b"\x1b]", b"\x1b[2J", b"\x1b[31m", b"\x07", chr(0x202E).encode()):
        assert bad not in screen, bad
    for text_line in screen.decode().splitlines():
        words = ("updates.summary", "updates.install", "label.updates", "label.os")
        if any(w in text_line for w in words):
            # Rows carry the prefix; a hint line says "Plugin hint:" (final review, item 9);
            # a wrapped line starts with "(plugin)" or "(hint)" (phase 14c).
            leads = ("(plugin) ", "(hint) ")
            marked = "[plugin 5" in text_line or "Plugin hint: " in text_line
            assert marked or text_line.strip("|│ ").startswith(leads), text_line


def test_hung_flooding_forking_and_failing_plugins_cost_only_their_rows(world: World) -> None:
    install(world, "10-ok", HELLO)
    install(world, "20-hang", "#!/bin/sh\nsleep 60\n")
    install(world, "30-flood", "#!/bin/sh\nhead -c 1048576 /dev/zero | tr '\\0' x\n")
    install(world, "40-fork", "#!/bin/sh\n(setsid sleep 60 &)\necho forked\n")
    install(world, "50-exit", "#!/bin/sh\necho bad\nexit 7\n")
    install(world, "60-ok", HELLO)
    world.config('[plugins."20-hang"]\ntimeout_s = 1\n')
    started = time.monotonic()
    assert world.run() == 0, world.log.getvalue()
    assert time.monotonic() - started < 30
    modules = world.tier().modules
    reasons = {n: (m.state, m.error.id if m.error else None) for n, m in modules.items()}
    assert reasons["10-ok"] == (ModuleState.OK, None)
    assert reasons["20-hang"] == (ModuleState.FAILED, "collect.error.timeout")
    assert reasons["30-flood"] == (ModuleState.FAILED, "collect.error.too_large")
    assert reasons["40-fork"] == (ModuleState.OK, None)
    assert reasons["50-exit"] == (ModuleState.FAILED, "collect.error.exit")
    assert reasons["60-ok"] == (ModuleState.OK, None)
    assert not proc.live_processes(account(PLUGIN_USER)[0])
    assert world.tier(cache.PUBLIC).failed == 0  # admin-only plugins are not counted there
    assert world.tier().failed == 3


def test_a_root_plugins_leftover_is_ended_without_the_unit(world: World) -> None:
    install(world, "50-root", "#!/bin/sh\n(setsid sleep 60 &)\necho left\n")
    world.config('[plugins."50-root"]\nrun_as = "root"\n')
    before = set(proc.live_processes(0, ancestor=os.getpid()))
    assert world.run() == 0, world.log.getvalue()
    assert admin_items(world, "50-root")[0].text == LiteralText("left")
    assert set(proc.live_processes(0, ancestor=os.getpid())) <= before


def test_a_plugin_changed_after_discovery_is_refused_at_its_start(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = install(world, "50-late", HELLO)
    real = plugins.discover

    def then_change(root: str, settings: config.Config) -> list[plugins.Found]:
        out = real(root, settings)
        path.chmod(0o777)
        return out

    monkeypatch.setattr(plugins, "discover", then_change)
    assert world.run() == 0, world.log.getvalue()
    entry = world.tier().modules["50-late"]
    assert entry.state is ModuleState.FAILED and entry.error is not None
    assert entry.error.id == "safepath.error.writable"


def test_the_shim_runs_a_plugin_and_reports_by_exit_code(world: World) -> None:
    install(world, "50-two", "#!/bin/sh\necho two\nexit 2\n")
    out, err = io.BytesIO(), io.BytesIO()
    code = plugins.shim_main("50-two", str(world.etc), {"MOTP_TIMEOUT": "2"}, out, err)
    assert code == plugins.SHIM_BASE + 2 and out.getvalue() == b"two\n"
    install(world, "51-slow", "#!/bin/sh\nsleep 30\n")
    started = time.monotonic()
    code = plugins.shim_main("51-slow", str(world.etc), {"MOTP_TIMEOUT": "0.5"}, out, err)
    assert code == plugins.SHIM_TIMEOUT and time.monotonic() - started < 5
    install(world, "52-env", "#!/usr/bin/env sh\necho hi\n")
    code = plugins.shim_main("52-env", str(world.etc), {}, out, err)
    assert code == plugins.SHIM_REFUSED and b"safepath.error.launcher_as_root" in err.getvalue()
    assert plugins.shim_main("../x", str(world.etc), {}, out, err) == plugins.SHIM_REFUSED


def test_a_plugin_directory_that_is_no_directory_costs_no_run(world: World) -> None:
    """Code review (high): a refused plugins.d became a module named "plugins.d", which
    the cache writer refused, so every run ended without writing the cache."""
    (world.etc / "plugins.d").write_text("not a directory")
    (world.etc / "plugins.d").chmod(0o644)
    assert world.run() == 0, world.log.getvalue()
    assert "collect: stopped" not in world.log.getvalue()
    assert "plugins.d" not in world.tier().modules
    report = doctor.Report()
    doctor.check_plugins(report, config.defaults(), plugin_places(world), int(time.time()))
    assert [m.id for _level, m in report.lines] == ["doctor.plugin_refused"]


def test_sixty_plugin_files_cost_no_run(world: World) -> None:
    """Code review (high): every name past 32 became a module too, and past 64 modules
    the cache writer raised."""
    for n in range(10, 70):
        install(world, f"{n}-p", HELLO)
    assert world.run() == 0, world.log.getvalue()
    names = [n for n in world.tier().modules if n[:2].isdigit()]
    assert len(names) == plugins.MAX_PLUGINS


LIMITS = """#!/usr/bin/python3 -I
import resource
score = open("/proc/self/oom_score_adj").read().strip()
print("oom", score, "mq", resource.getrlimit(resource.RLIMIT_MSGQUEUE)[0])
"""


def test_plugins_get_no_message_queue_and_root_the_highest_oom_score(world: World) -> None:
    install(world, "50-user", LIMITS)
    install(world, "51-root", LIMITS)
    world.config('[plugins."51-root"]\nrun_as = "root"\n')
    assert world.run() == 0, world.log.getvalue()
    # Without a drop (the shim in its own unit, a root plugin here) the score is set; with
    # a drop it is not, so the child never becomes dumpable before exec.
    assert admin_items(world, "51-root")[0].text == LiteralText("oom 1000 mq 0")
    user = admin_items(world, "50-user")[0].text
    assert isinstance(user, LiteralText) and user.text.endswith("mq 0")


def test_the_argument_on_a_shebang_line_is_checked(world: World) -> None:
    open_dir = world.root / "open"
    open_dir.mkdir()
    open_dir.chmod(0o777)
    (open_dir / "x.sh").write_text("echo planted\n")
    install(world, "50-script", f"#!/bin/sh {open_dir / 'x.sh'}\necho real\n")
    install(world, "51-option", "#!/usr/bin/python3 -I/tmp\nprint(1)\n")
    install(world, "52-setting", "#!/usr/bin/python3 -Xpycache_prefix=x\nprint(1)\n")
    install(world, "53-plain", "#!/usr/bin/python3 -I\nprint(1)\n")
    entries = discovered(world)
    assert entries["50-script"].reason is not None
    assert entries["50-script"].reason.id == "safepath.error.writable"
    for name in ("51-option", "52-setting"):
        reason = entries[name].reason
        assert reason is not None and reason.id == "safepath.error.shebang_argument", name
    assert entries["53-plain"].state == plugins.ACCEPTED


def test_an_interpreter_in_no_known_format_is_refused(world: World) -> None:
    """Code review (low): known_format stopped at the first level of the #! chain."""
    tools = world.root / "tools"
    tools.mkdir(mode=0o755)
    odd = tools / "odd"
    odd.write_text("not a program\n")
    odd.chmod(0o755)
    install(world, "50-odd", f"#!{odd}\n")
    reason = discovered(world)["50-odd"].reason
    assert reason is not None and reason.id == "safepath.error.unknown_format"


def test_file_age_rows_as_the_user_motp(world: World) -> None:
    stamps = world.root / "stamps"
    stamps.mkdir(mode=0o755)
    fresh = stamps / "fresh"
    fresh.write_text("")
    old = stamps / "old"
    old.write_text("")
    os.utime(old, (time.time() - 5 * 3600, time.time() - 5 * 3600))
    private = world.root / "private"
    private.mkdir(mode=0o700)
    (private / "stamp").write_text("")
    rows = (
        (fresh, "Fresh"),
        (old, "Old"),
        (stamps / "none", "Missing"),
        (private / "stamp", "Hidden"),
    )
    world.config(
        "".join(
            f"[[rows.file_age]]\npath = '{path}'\nlabel = '{label}'\n"
            "warn_after = '1h'\ncrit_after = '4h'\n"
            for path, label in rows
        )
    )
    collector = world.collector(modules=[RowsFileAge()])
    assert collector.run() == 0, world.log.getvalue()
    items = {i.key: i for i in world.tier(cache.PUBLIC).modules["rows_file_age"].items}
    assert items["rows_file_age.fresh"].status is Status.OK
    assert items["rows_file_age.old"].status is Status.CRIT
    assert items["rows_file_age.missing"].text == ref("file_age.missing")
    assert items["rows_file_age.hidden"].text == ref("file_age.unreadable")
    assert items["rows_file_age.hidden"].status is Status.UNKNOWN
    assert str(world.root) not in (world.cache_dir / "public.json").read_text()


def test_a_root_probe_may_not_ask_for_a_file_time() -> None:
    from motp.collect.context import ProbeContext

    with pytest.raises(ContractError):
        ProbeContext(now=1).file_mtime("/etc/shadow")

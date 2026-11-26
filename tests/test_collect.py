"""The collector as root, with real probe processes (blueprint 4.1, 4.4, 4.9, 4.14, D21, D32).

These run inside the containers of ``tools/container_test.py``, where
``tools/container/accounts.sh`` created the probe users ``motp`` and ``motp-plugin``, the
test users and the admin group ``motp-admin``. Each test works in a root-owned tree under
``/var/lib`` (``trusted_dir``): the program tree the probes run (unpacked like
``/opt/motp/lib``), a cache directory, a state directory and a config directory.

Covered: modes, owners and groups of every file (4.1); the privilege drop of probes; a
sleeping probe and the total budget (4.14); hostile probes (escape sequences, 1 MiB of
output, ``NaN``, a pipe held by a descendant, a fork bomb) against clean cache files and a
bounded run (T8, T23); leftover processes; restoring the cache after it was emptied (4.4);
overlapping runs (4.14, T19); planted links and unsafe directories (T12); no fallback to
root without the account (4.9); the per-user file read back by its owner (D32).
"""

import errno
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import unicodedata
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Optional

import pytest

from motp.collect import errlog, listing, runner, store
from motp.collect.runner import Collector, Log, Paths, Probe
from motp.core import cache, config, i18n, proc
from motp.core.model import LiteralText, ModuleState, ref
from motp.modules import registry

from .conftest import ADMIN_GROUP, OTHER_USER, PLUGIN_USER, PROBE_USER, SRC, TEST_USER, account

pytestmark = pytest.mark.needs_linux_owner

import build_pyz  # noqa: E402  (tools/ is on sys.path through conftest)

PY = sys.executable
FILES = (store.PUBLIC_NAME, store.ADMIN_NAME, store.RENDER_NAME)


# --- fixtures --------------------------------------------------------------------------


def _tree(root: Path) -> Path:
    """The program tree as the installer will unpack it: root-owned, 0755 and 0644."""
    lib = root / "lib"
    for name, data in build_pyz.collect(SRC).items():
        path = lib / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for path in [lib, *lib.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)
    return lib


@pytest.fixture
def world(trusted_dir: Path) -> Iterator["World"]:
    yield World(trusted_dir)


class World:
    """A root-owned tree with program, cache, state and config for one test."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.lib = _tree(root)
        self.etc = root / "etc"
        self.etc.mkdir(mode=0o755)
        self.paths = Paths(
            cache_dir=str(root / "run"),
            state_dir=str(root / "state"),
            config_root=str(self.etc),
        )
        self.log = io.StringIO()

    @property
    def cache_dir(self) -> Path:
        return Path(self.paths.cache_dir)

    def config(self, text: str) -> None:
        path = self.etc / "config.toml"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o644)

    def collector(self, probes: Optional[list[Probe]] = None, **kwargs: object) -> Collector:
        return Collector(
            self.paths,
            probes=probes,
            program=str(self.lib),
            log=Log(self.log, i18n.translator("en")),
            **kwargs,  # type: ignore[arg-type]
        )

    def run(self, probes: Optional[list[Probe]] = None, **kwargs: object) -> int:
        return self.collector(probes, **kwargs).run()

    def tier(self, tier: str = cache.ADMIN) -> cache.TierCache:
        return cache.read_tier_file(str(self.cache_dir / f"{tier}.json"), tier, 0)


def code_probe(
    name: str, code: str, timeout: float = 5, user: str = PROBE_USER, interval: int = 300
) -> Probe:
    return Probe(
        name=name,
        argv=(PY, "-I", "-S", "-c", code),
        user=user,
        timeout=timeout,
        interval=interval,
        max_age=3600,
    )


def doc_code(name: str, value: str = "'fine'", extra: str = "") -> str:
    """Python code that prints a valid document whose one item has ``value`` (an expression)."""
    return (
        "import json, os, sys\n"
        f"{extra}\n"
        f"doc = {{'api': 1, 'module': {name!r}, 'items': "
        f"[{{'key': {name + '.x'!r}, 'value': {value}, 'label': {{'id': 'label.os'}}}}]}}\n"
        "sys.stdout.write(json.dumps(doc))\n"
        "sys.stdout.flush()\n"
    )


def strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def assert_clean(path: Path) -> None:
    """Every string in the file is free of control, format and bidi characters."""
    data = json.loads(path.read_bytes())
    for text in strings(data):
        bad = [c for c in text if unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs")]
        assert not bad, f"{path.name}: {text!r}"


def uid_of(name: str) -> int:
    return account(name)[0]


def group_id(name: str) -> int:
    import grp

    return grp.getgrnam(name).gr_gid


# --- modes, owners and contents --------------------------------------------------------


def test_collect_writes_every_file_with_its_mode_owner_and_group(world: World) -> None:
    world.config(f'[visibility]\nadmin_group = "{ADMIN_GROUP}"\n')
    assert world.run() == 0, world.log.getvalue()
    expected = {
        store.PUBLIC_NAME: (0o644, 0, 0),
        store.ADMIN_NAME: (0o640, 0, group_id(ADMIN_GROUP)),
        store.RENDER_NAME: (0o644, 0, 0),
        store.LOCK_NAME: (0o600, 0, 0),
    }
    for name, (mode, uid, gid) in expected.items():
        st = os.lstat(world.cache_dir / name)
        assert stat.S_ISREG(st.st_mode), name
        assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (mode, uid, gid), name
    for path, mode in (
        (world.cache_dir, 0o755),
        (world.cache_dir / store.USER_DIR, 0o711),
        (Path(world.paths.state_dir), 0o700),
        (Path(world.paths.state_dir) / store.STATE_NAME, 0o600),
    ):
        st = os.lstat(path)
        assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (mode, 0, 0), path
    assert not [p for p in world.cache_dir.iterdir() if p.name.endswith(".tmp")]


def test_collect_runs_the_built_in_modules_and_both_tiers_read_back(world: World) -> None:
    assert world.run() == 0, world.log.getvalue()
    admin, public = world.tier(cache.ADMIN), world.tier(cache.PUBLIC)
    chosen = runner.choose(registry.cached_modules(), config.defaults(), int(time.time()))
    names = {c.module.name for c in chosen if c.state == "active"}
    # In a plain container (no systemd, no utmp, on Fedora no lastlog or wtmp either) the
    # service and login modules are not detected; the seven of phases 6 and 9 always are.
    assert set(admin.modules) == names and len(names) >= 7
    assert all(r.state is ModuleState.OK for r in admin.modules.values()), world.log.getvalue()
    host = {i.key: i.value for i in admin.modules["os_host"].items}
    assert host["os_host.hostname"] == Path("/proc/sys/kernel/hostname").read_text().strip()
    assert "hw_disks.root" in {i.key for i in admin.modules["hw_disks"].items}
    assert public.modules["os_host"].state is None  # 5.4: states are admin-only
    settings = cache.read_render_file(str(world.cache_dir / store.RENDER_NAME))
    assert "inode_used_percent" in settings.thresholds
    for name in FILES:
        assert_clean(world.cache_dir / name)
    log = world.log.getvalue()
    assert f"collect: done, {len(names)} probes run" in log
    # T11: the journal gets counts and stage names only, never module names.
    for name in names:
        assert name not in log, log


def test_an_ignored_config_file_is_counted_in_admin_json_only(world: World) -> None:
    """Final review, usability item 6: the admin's attention row needs the count."""
    world.config("[limits]\nrender_ms = 'fast'\n")
    assert world.run([code_probe("whoami", doc_code("whoami"))]) == 0
    assert world.tier(cache.ADMIN).config_ignored == 1
    assert world.tier(cache.PUBLIC).config_ignored == 0
    assert b"config_ignored" not in (world.cache_dir / store.PUBLIC_NAME).read_bytes()


def test_probes_run_as_motp_without_groups(world: World) -> None:
    value = "f'{os.getuid()} {os.getgid()} {os.getgroups()}'"
    assert world.run([code_probe("whoami", doc_code("whoami", value))]) == 0
    item = world.tier().modules["whoami"].items[0]
    uid, gid = account(PROBE_USER)
    assert item.value == f"{uid} {gid} []"


def test_render_and_public_tiers_hold_no_admin_items(world: World) -> None:
    admin_item = (
        "'secret'",
        "",
    )
    code = doc_code("tiers", *admin_item).replace("'label': {", "'visibility': 'admin', 'label': {")
    assert world.run([code_probe("tiers", code)]) == 0
    assert "tiers" in world.tier(cache.ADMIN).modules
    assert "tiers" not in world.tier(cache.PUBLIC).modules
    assert b"secret" not in (world.cache_dir / store.PUBLIC_NAME).read_bytes()


# --- time limits and the budget --------------------------------------------------------


def test_a_sleeping_probe_is_killed_and_the_others_finish(world: World) -> None:
    probes = [
        code_probe("sleeper", "import time; time.sleep(60)", timeout=1),
        code_probe("quick", doc_code("quick")),
    ]
    started = time.monotonic()
    assert world.run(probes) == 0
    assert time.monotonic() - started < 6
    modules = world.tier().modules
    assert modules["sleeper"].state is ModuleState.FAILED
    assert modules["sleeper"].error is not None
    assert modules["sleeper"].error.id == "collect.error.timeout"
    assert modules["quick"].state is ModuleState.OK


def test_the_total_budget_ends_the_run(world: World) -> None:
    world.config("[limits]\ncollect_total_s = 10\n")
    probes = [
        code_probe("sleeper", "import time; time.sleep(60)", timeout=30),
        code_probe("late", doc_code("late")),
    ]
    started = time.monotonic()
    assert world.run(probes, pool=1) == 0
    elapsed = time.monotonic() - started
    assert 9 < elapsed < 14, elapsed
    modules = world.tier().modules
    assert modules["sleeper"].error is not None
    assert modules["sleeper"].error.id == "collect.error.timeout"
    assert modules["late"].error is not None
    assert modules["late"].error.id == "collect.error.budget"
    state = store.decode_state((Path(world.paths.state_dir) / store.STATE_NAME).read_bytes())
    assert state["late"].attempted == 0  # never started: due again at the next run


# --- hostile probes --------------------------------------------------------------------

ESCAPES = "chr(27) + '[2J' + chr(27) + ']0;owned' + chr(7) + 'evil' + chr(0x202E) + chr(0)"
FLOOD = "import os\nos.write(1, b'{' + b' ' * (1 << 20))\n"
NAN = (
    'print(\'{"api": 1, "module": "hostile_nan", "items": '
    '[{"key": "hostile_nan.x", "value": NaN, "unit": "ratio"}]}\')'
)
PIPE_HOLDER = doc_code(
    "hostile_pipe",
    extra=(
        "import subprocess\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],"
        " start_new_session=True)"
    ),
)
FORK_BOMB = (
    "import os\n"
    "while True:\n"
    "    try:\n"
    "        if os.fork() == 0:\n"
    "            os.setsid()\n"
    "    except OSError:\n"
    "        pass\n"
)


def test_hostile_probes_leave_clean_files_and_a_bounded_run(world: World) -> None:
    probes = [
        code_probe("hostile_esc", doc_code("hostile_esc", ESCAPES)),
        code_probe("hostile_flood", FLOOD),
        code_probe("hostile_nan", NAN),
        code_probe("hostile_pipe", PIPE_HOLDER, timeout=10),
        code_probe("quick", doc_code("quick")),
    ]
    started = time.monotonic()
    assert world.run(probes) == 0, world.log.getvalue()
    elapsed = time.monotonic() - started
    assert elapsed < 10, elapsed
    modules = world.tier().modules
    reasons = {name: (r.state, r.error.id if r.error else None) for name, r in modules.items()}
    assert reasons == {
        "hostile_esc": (ModuleState.OK, None),
        "hostile_flood": (ModuleState.FAILED, "collect.error.too_large"),
        "hostile_nan": (ModuleState.FAILED, "json.error.not_finite"),
        "hostile_pipe": (ModuleState.OK, None),
        "quick": (ModuleState.OK, None),
    }, world.log.getvalue()
    assert modules["hostile_pipe"].duration_ms is not None
    assert modules["hostile_pipe"].duration_ms < 5000, "the held pipe stalled the read"
    value = str(modules["hostile_esc"].items[0].value)
    assert value.startswith("[2J]0;ownedevil"), value
    assert_all_clean(world)
    assert not proc.live_processes(uid_of(PROBE_USER)), world.log.getvalue()
    log = world.log.getvalue()
    assert "\x1b" not in log and "\x07" not in log


def test_a_fork_bomb_is_bounded_and_cleaned_up(world: World) -> None:
    # Built-in probes share the user motp (D21), so a bomb also starves the other probes
    # of the same pool; it runs alone here, and only its own outcome is checked.
    started = time.monotonic()
    assert world.run([code_probe("hostile_bomb", FORK_BOMB, timeout=2)]) == 0
    assert time.monotonic() - started < 10
    entry = world.tier().modules["hostile_bomb"]
    assert entry.state is ModuleState.FAILED and entry.error is not None
    assert entry.error.id == "collect.error.timeout"
    assert_all_clean(world)
    assert not proc.live_processes(uid_of(PROBE_USER)), world.log.getvalue()
    assert "could not be ended" not in world.log.getvalue()


def assert_all_clean(world: World) -> None:
    for name in FILES:
        assert_clean(world.cache_dir / name)
    assert_clean(Path(world.paths.state_dir) / store.STATE_NAME)


def test_a_probe_that_leaves_a_process_behind_is_cleaned_up(world: World) -> None:
    escape = doc_code(
        "leaver",
        extra=(
            "if os.fork() == 0:\n"
            "    os.setsid()\n"
            "    if os.fork() == 0:\n"
            "        os.closerange(0, 3)\n"
            "        import time; time.sleep(60)\n"
            "    os._exit(0)\n"
            "os.wait()"
        ),
    )
    assert world.run([code_probe("leaver", escape)]) == 0
    assert world.tier().modules["leaver"].state is ModuleState.OK, world.log.getvalue()
    assert not proc.live_processes(uid_of(PROBE_USER))


LEAVER = doc_code(
    "leaver",
    extra=(
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    if os.fork() == 0:\n"
        "        os.closerange(0, 3)\n"
        "        import time; time.sleep(60)\n"
        "    os._exit(0)\n"
        "os.wait()"
    ),
)


def test_cleanup_spares_other_processes_of_the_same_uid(world: World) -> None:
    """Security review (high): a container's service user can share the uid of motp on
    the host. The collector, run as its own process, ends what its probe left behind
    and nothing else of that uid."""
    uid, gid = account(PROBE_USER)
    foreign = subprocess.Popen(
        [PY, "-I", "-S", "-c", "import time; time.sleep(60)"],
        user=uid,
        group=gid,
        extra_groups=[],
        start_new_session=True,
    )
    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(world.lib)!r})\n"
        "from motp.collect.runner import Collector, Paths, Probe\n"
        f"paths = Paths(cache_dir={world.paths.cache_dir!r}, state_dir={world.paths.state_dir!r},"
        f" config_root={world.paths.config_root!r})\n"
        f"probe = Probe('leaver', ({PY!r}, '-I', '-S', '-c', {LEAVER!r}), 'motp', 5, 300, 3600)\n"
        "sys.exit(Collector(paths, probes=[probe]).run())\n"
    )
    try:
        done = subprocess.run([PY, "-I", "-S", "-c", script], capture_output=True, timeout=60)
        assert done.returncode == 0, done.stderr
        assert world.tier().modules["leaver"].state is ModuleState.OK, done.stderr
        assert foreign.poll() is None, "the cleanup killed a process it did not start"
        assert proc.live_processes(uid) == [foreign.pid], "the probe's leftover survived"
    finally:
        foreign.kill()
        foreign.wait()


def test_a_cleanup_that_cannot_finish_fails_the_modules(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(proc, "cleanup_user", lambda drop, **kw: proc.Cleanup(False, 2))
    assert world.run([code_probe("quick", doc_code("quick"))]) == 0
    entry = world.tier().modules["quick"]
    assert entry.state is ModuleState.FAILED and entry.error is not None
    assert entry.error.id == "collect.error.cleanup"
    assert [i.value for i in entry.items] == ["fine"]  # fresh items are kept
    assert "2 processes of motp could not be ended" in world.log.getvalue()


def test_plugins_run_one_at_a_time_and_are_cleaned_after_each(world: World) -> None:
    code = (
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],"
        " start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "time.sleep(0.3)\n"
        "print(time.monotonic())\n"
    )
    probes = [
        replace(code_probe(name, code, user=PLUGIN_USER), plugin=True)
        for name in ("10-plug-a", "20-plug-b")
    ]
    assert world.run(probes) == 0, world.log.getvalue()
    modules = world.tier().modules
    texts = []
    for name in ("10-plug-a", "20-plug-b"):
        assert modules[name].state is ModuleState.OK, world.log.getvalue()
        text = modules[name].items[0].text
        assert isinstance(text, LiteralText)
        texts.append(float(text.text))
    assert abs(texts[1] - texts[0]) >= 0.3, "plugins overlapped"
    assert not proc.live_processes(uid_of(PLUGIN_USER))


# --- restore after the cache was emptied -----------------------------------------------


def test_an_emptied_cache_is_restored_at_the_next_run(world: World) -> None:
    assert world.run() == 0
    before = {name: [i.key for i in r.items] for name, r in world.tier().modules.items()}
    shutil.rmtree(world.cache_dir)  # after a reboot /run is empty
    assert world.run() == 0, world.log.getvalue()
    after = {name: [i.key for i in r.items] for name, r in world.tier().modules.items()}
    assert after == before
    last = world.log.getvalue().splitlines()[-1]
    assert f"collect: done, {len(before)} probes run" in last


def test_a_module_not_due_is_carried_without_running(world: World) -> None:
    probes = [code_probe("slow", doc_code("slow"), interval=3600)]
    assert world.run(probes) == 0
    first = world.tier().modules["slow"]
    assert world.run(probes) == 0
    assert world.tier().modules["slow"] == first
    assert "collect: done, 0 probes run" in world.log.getvalue().splitlines()[-1]


def test_a_failing_module_is_restored_from_the_state(world: World) -> None:
    assert world.run([code_probe("keeper", doc_code("keeper", "'old'"))]) == 0
    collected = world.tier().modules["keeper"].collected
    shutil.rmtree(world.cache_dir)
    assert world.run([code_probe("keeper", "import sys; sys.exit(1)")]) == 0
    entry = world.tier().modules["keeper"]
    assert entry.state is ModuleState.FAILED
    assert [i.value for i in entry.items] == ["old"]
    assert entry.collected == collected  # the age stays, so the renderer marks it stale
    public = world.tier(cache.PUBLIC)
    assert public.failed == 1 and [i.value for i in public.modules["keeper"].items] == ["old"]


# --- overlap, links and directories ----------------------------------------------------


def test_a_second_run_ends_at_once_without_writing(world: World) -> None:
    world.cache_dir.mkdir(mode=0o755)
    lock = str(world.cache_dir / store.LOCK_NAME)
    holder = subprocess.Popen(
        [
            PY,
            "-I",
            "-S",
            "-c",
            "import fcntl, os, sys, time\n"
            f"fd = os.open({lock!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('locked', flush=True)\n"
            "time.sleep(30)\n",
        ],
        stdout=subprocess.PIPE,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline() == b"locked\n"
        started = time.monotonic()
        assert world.run() == 0
        assert time.monotonic() - started < 1.0
    finally:
        holder.kill()
        holder.wait()
    assert sorted(p.name for p in world.cache_dir.iterdir()) == [store.LOCK_NAME]
    assert not Path(world.paths.state_dir).exists()
    assert "another run is active" in world.log.getvalue()


def test_a_planted_link_is_replaced_not_followed(world: World) -> None:
    world.cache_dir.mkdir(mode=0o755)
    target = world.root / "target"
    target.write_text("keep")
    (world.cache_dir / store.PUBLIC_NAME).symlink_to(target)
    assert world.run([code_probe("quick", doc_code("quick"))]) == 0
    assert target.read_text() == "keep"
    assert stat.S_ISREG(os.lstat(world.cache_dir / store.PUBLIC_NAME).st_mode)


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o1777])
def test_a_cache_directory_others_can_write_is_refused(world: World, mode: int) -> None:
    world.cache_dir.mkdir()
    world.cache_dir.chmod(mode)
    assert world.run([code_probe("quick", doc_code("quick"))]) == 1
    assert list(world.cache_dir.iterdir()) == []
    assert "is not a directory that only root can write" in world.log.getvalue()


def test_a_cache_directory_of_another_user_is_refused(world: World) -> None:
    world.cache_dir.mkdir(mode=0o755)
    os.chown(world.cache_dir, uid_of(TEST_USER), -1)
    assert world.run([code_probe("quick", doc_code("quick"))]) == 1
    assert list(world.cache_dir.iterdir()) == []


def test_a_linked_cache_directory_is_refused(world: World) -> None:
    real = world.root / "elsewhere"
    real.mkdir(mode=0o755)
    world.cache_dir.symlink_to(real)
    assert world.run([code_probe("quick", doc_code("quick"))]) == 1
    assert list(real.iterdir()) == []


def test_a_lock_file_of_another_user_is_refused(world: World) -> None:
    world.cache_dir.mkdir(mode=0o755)
    lock = world.cache_dir / store.LOCK_NAME
    lock.write_text("")
    os.chown(lock, uid_of(TEST_USER), -1)
    assert world.run([code_probe("quick", doc_code("quick"))]) == 1
    assert not (world.cache_dir / store.PUBLIC_NAME).exists()


# --- accounts --------------------------------------------------------------------------


def test_probes_never_fall_back_to_root(world: World) -> None:
    passwd = world.root / "passwd"
    passwd.write_text(
        "".join(
            line
            for line in Path("/etc/passwd").read_text().splitlines(keepends=True)
            if not line.startswith(f"{PROBE_USER}:")
        )
    )
    paths = replace(world.paths, accounts_file=str(passwd))
    marker = world.root / "ran"
    code = f"open({str(marker)!r}, 'w').close()\n" + doc_code("quick")
    collector = Collector(
        paths,
        probes=[code_probe("quick", code)],
        log=Log(world.log, i18n.translator("en")),
    )
    assert collector.run() == 0
    entry = world.tier().modules["quick"]
    assert entry.state is ModuleState.FAILED and entry.error is not None
    assert entry.error.id == "collect.error.no_account"
    assert not marker.exists(), "the probe ran although its account is missing"


def test_an_unknown_admin_group_leaves_admin_json_to_root(world: World) -> None:
    world.config('[visibility]\nadmin_group = "no-such-group"\n')
    assert world.run([code_probe("quick", doc_code("quick"))]) == 0
    assert os.lstat(world.cache_dir / store.ADMIN_NAME).st_gid == 0
    assert "admin group no-such-group not found" in world.log.getvalue()


@pytest.mark.parametrize("group", [PROBE_USER, PLUGIN_USER])
def test_the_probe_users_group_is_never_the_admin_group(world: World, group: str) -> None:
    world.config(f'[visibility]\nadmin_group = "{group}"\n')
    assert world.run([code_probe("quick", doc_code("quick"))]) == 0
    assert os.lstat(world.cache_dir / store.ADMIN_NAME).st_gid == 0
    assert f"admin group {group} is the group of {group}" in world.log.getvalue()


def test_an_untrusted_program_tree_refuses_every_probe(world: World) -> None:
    world.lib.chmod(0o777)
    assert world.run() == 0
    modules = world.tier().modules
    assert modules and all(r.state is ModuleState.FAILED for r in modules.values())
    assert {r.error.id for r in modules.values() if r.error} == {"safepath.error.writable"}


# --- the per-user file, read back by its owner -----------------------------------------


def users_code(entries: "list[tuple[int, int, str]]", module: str = "os_login") -> str:
    """Python code that prints an ``os_login``-shaped document: ``(uid, started, host)``."""
    users = [
        {"uid": uid, "logins": [{"started": started, "source": host, "tty": "pts/0"}]}
        for uid, started, host in entries
    ]
    doc = {"api": 1, "module": module, "items": [], "users": users}
    return f"import sys\nsys.stdout.write({json.dumps(doc)!r})\nsys.stdout.flush()\n"


def login_probe(
    entries: "list[tuple[int, int, str]]", interval: int = 1, user: str = "root"
) -> Probe:
    return code_probe("os_login", users_code(entries), interval=interval, user=user)


def as_user(name: str, code: str) -> proc.Result:
    result = proc.run(
        proc.Spec(argv=(PY, "-I", "-S", "-c", code), timeout=20, drop=proc.Drop(*account(name)))
    )
    assert isinstance(result, proc.Result)
    return result


def show_code(world: World) -> str:
    return (
        "import sys\n"
        f"sys.path.insert(0, {str(world.lib)!r})\n"
        "from motp import show\n"
        f"sys.exit(show.main(login=True, cache_dir={str(world.cache_dir)!r}, width=80))\n"
    )


def user_files(world: World) -> set[str]:
    return set(os.listdir(world.cache_dir / store.USER_DIR))


def test_a_per_user_file_is_roots_and_readable_by_its_user_alone(world: World) -> None:
    uid = uid_of(TEST_USER)
    before = int(time.time()) - 7380
    assert world.run([login_probe([(uid, before, "198.51.100.7")])]) == 0
    path = world.cache_dir / store.USER_DIR / f"{uid}.json"
    st = os.lstat(path)
    # Root's file; the group bits show the ACL mask (read), and the ACL names one user.
    assert (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (0, 0, 0o440)
    assert os.getxattr(path, store.ACL_XATTR) == store.reader_acl(uid)
    # Its user reads it, and sees the previous login at login.
    owner_reads = as_user(TEST_USER, f"print(len(open({str(path)!r}, 'rb').read()))")
    assert owner_reads.ok, owner_reads
    shown = as_user(TEST_USER, show_code(world))
    assert shown.ok and b"198.51.100.7" in shown.stdout
    # Another user cannot open it, list the directory, or see it at login.
    other = as_user(OTHER_USER, f"open({str(path)!r}, 'rb')")
    assert other.returncode == 1 and b"PermissionError" in other.stderr
    listing = as_user(OTHER_USER, f"import os; os.listdir({str(path.parent)!r})")
    assert listing.returncode == 1
    assert b"198.51.100.7" not in as_user(OTHER_USER, show_code(world)).stdout
    # The user cannot make it writable: it is not theirs (the D32 amendment).
    chmod = as_user(TEST_USER, f"import os; os.chmod({str(path)!r}, 0o600)")
    assert chmod.returncode == 1 and b"PermissionError" in chmod.stderr


def test_files_of_accounts_no_longer_sent_are_removed(world: World) -> None:
    a, b = uid_of(TEST_USER), uid_of(OTHER_USER)
    now = int(time.time())
    assert world.run([login_probe([(a, now - 99, "192.0.2.1"), (b, now - 98, "192.0.2.2")])]) == 0
    assert user_files(world) == {f"{a}.json", f"{b}.json"}
    (world.cache_dir / store.USER_DIR / "stray.json").write_text("{}")
    time.sleep(1.2)
    assert world.run([login_probe([(a, now - 99, "192.0.2.1")])]) == 0
    assert user_files(world) == {f"{a}.json"}
    assert "per-user files: 1 written, 0 failed, 2 removed" in world.log.getvalue()


def test_without_os_login_no_per_user_file_stays(world: World) -> None:
    uid = uid_of(TEST_USER)
    assert world.run([login_probe([(uid, int(time.time()) - 60, "")])]) == 0
    assert user_files(world) == {f"{uid}.json"}
    assert world.run([code_probe("quick", doc_code("quick"))]) == 0
    assert user_files(world) == set()


def test_a_failed_os_login_leaves_the_files_as_they_are(world: World) -> None:
    uid = uid_of(TEST_USER)
    assert world.run([login_probe([(uid, int(time.time()) - 60, "")])]) == 0
    time.sleep(1.2)
    broken = code_probe(
        "os_login", "import sys; sys.stdout.write('{not json')", interval=1, user="root"
    )
    assert world.run([broken]) == 0
    assert world.tier().modules["os_login"].state is ModuleState.FAILED
    assert user_files(world) == {f"{uid}.json"}


def test_without_acls_no_per_user_file_is_written(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    uid = uid_of(TEST_USER)
    assert world.run([login_probe([(uid, int(time.time()) - 60, "192.0.2.4")])]) == 0
    assert user_files(world) == {f"{uid}.json"}

    def refuse(*_args: object) -> None:
        raise OSError(errno.EOPNOTSUPP, "Operation not supported")

    monkeypatch.setattr(os, "setxattr", refuse)
    time.sleep(1.2)
    assert world.run([login_probe([(uid, int(time.time()) - 60, "192.0.2.4")])]) == 0
    assert user_files(world) == set()  # the old file is gone too: fail closed
    result = world.tier().modules["os_login"]
    assert result.state is ModuleState.FAILED and result.error == ref("collect.error.user_acl")
    assert "refuses POSIX ACLs" in world.log.getvalue()


def test_only_os_login_may_send_per_user_data(world: World) -> None:
    uid = uid_of(TEST_USER)
    sneaky = code_probe("quick", users_code([(uid, int(time.time()) - 60, "")], module="quick"))
    assert world.run([sneaky]) == 0
    assert world.tier().modules["quick"].state is ModuleState.FAILED
    assert user_files(world) == set()


def test_per_user_data_counts_only_from_a_root_probe(world: World) -> None:
    uid = uid_of(TEST_USER)
    assert world.run([login_probe([(uid, int(time.time()) - 60, "")], user=PROBE_USER)]) == 0
    assert user_files(world) == set()


def test_per_user_data_never_reaches_the_tier_files(world: World) -> None:
    uid = uid_of(TEST_USER)
    assert world.run([login_probe([(uid, int(time.time()) - 60, "203.0.113.77")])]) == 0
    for name in FILES:
        assert b"203.0.113.77" not in (world.cache_dir / name).read_bytes()


# --- motp modules after a run ----------------------------------------------------------


def test_modules_shows_failures_from_admin_json(world: World) -> None:
    assert world.run() == 0
    tier = world.tier()
    broken = replace(
        tier,
        modules={
            **tier.modules,
            "hw_disks": replace(
                tier.modules["hw_disks"],
                state=ModuleState.FAILED,
                error=ref("collect.error.timeout"),
            ),
        },
    )
    rows = {r.name: r for r in listing.module_rows(config.defaults(), broken, 0)}
    assert rows["hw_disks"].state == "failed"
    assert rows["os_host"].state == "active"


# --- the command line ------------------------------------------------------------------


def test_collect_without_the_unit_says_to_use_no_sandbox(world: World) -> None:
    """Outside the unit, plain ``collect`` starts the unit; without one it exits 2."""
    result = subprocess.run(
        [PY, "-I", "-S", str(world.lib), "collect"], capture_output=True, timeout=30
    )
    assert result.returncode == 2
    assert b"--no-sandbox" in result.stderr


def test_collect_refuses_a_user_other_than_root(world: World) -> None:
    spec = proc.Spec(
        argv=(PY, "-I", "-S", str(world.lib), "collect", "--no-sandbox"),
        timeout=30,
        drop=proc.Drop(*account(TEST_USER)),
    )
    result = proc.run(spec)
    assert result.returncode == 1
    assert b"must run as root" in result.stderr


def test_the_probe_command_runs_a_module_from_the_tree(world: World) -> None:
    spec = proc.Spec(
        argv=(PY, "-I", "-S", str(world.lib), "_probe", "os_host"),
        timeout=30,
        drop=proc.Drop(*account(PROBE_USER)),
    )
    result = proc.run(spec)
    assert result.ok, result
    doc = json.loads(result.stdout)
    assert doc["module"] == "os_host" and doc["items"][0]["key"] == "os_host.hostname"


# --- phase 7: log split (T11), probe users' groups, cleanup under hidepid --------------


def test_probe_stderr_goes_to_the_root_only_log_not_the_journal(world: World) -> None:
    code = (
        "import sys\nsys.stderr.write('secret-path /etc/shadow\\x1b[31m red\\n' * 3)\nsys.exit(3)\n"
    )
    assert world.run([code_probe("noisy", code)]) == 0
    log = world.log.getvalue()
    assert "noisy" not in log and "secret-path" not in log, log
    assert "1 failed" in log
    path = Path(world.paths.state_dir) / errlog.NAME
    st = os.lstat(path)
    assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == 0 and st.st_gid == 0
    kept = errlog.decode(path.read_bytes())
    assert list(kept) == ["noisy"]
    assert kept["noisy"].lines and all("\x1b" not in line for line in kept["noisy"].lines)
    assert "secret-path /etc/shadow" in kept["noisy"].lines[0]
    entry = world.tier().modules["noisy"]
    assert entry.error is not None and entry.error.id == "collect.error.exit"


def test_a_module_that_recovers_leaves_the_stderr_log(world: World) -> None:
    fail = "import sys\nsys.stderr.write('broken\\n')\nsys.exit(1)\n"
    assert world.run([code_probe("flaky", fail, interval=1)]) == 0
    assert "flaky" in errlog.decode((Path(world.paths.state_dir) / errlog.NAME).read_bytes())
    time.sleep(1.1)
    assert world.run([code_probe("flaky", doc_code("flaky"), interval=1)]) == 0
    assert errlog.decode((Path(world.paths.state_dir) / errlog.NAME).read_bytes()) == {}


def test_a_probe_user_with_a_foreign_primary_group_is_refused(world: World) -> None:
    """The primary group of ``motp`` must be ``motp`` (phase 7, security review of phase 6):
    a probe user in ``disk`` or ``shadow`` would hand that group to every probe."""
    foreign = group_id("motp-test-x")
    lines = []
    for line in Path("/etc/passwd").read_text().splitlines(keepends=True):
        fields = line.split(":")
        if fields[0] == PROBE_USER:
            fields[3] = str(foreign)
            line = ":".join(fields)
        lines.append(line)
    passwd = world.root / "passwd"
    passwd.write_text("".join(lines))
    marker = world.root / "ran"
    code = f"open({str(marker)!r}, 'w').close()\n" + doc_code("quick")
    collector = Collector(
        replace(world.paths, accounts_file=str(passwd)),
        probes=[code_probe("quick", code)],
        log=Log(world.log, i18n.translator("en")),
    )
    assert collector.run() == 0
    entry = world.tier().modules["quick"]
    assert entry.state is ModuleState.FAILED and entry.error is not None
    assert entry.error.id == "collect.error.no_account"
    assert "is not its own group" in world.log.getvalue()
    assert not marker.exists()


def test_a_blind_process_view_fails_the_stage_instead_of_calling_it_clean(world: World) -> None:
    """Under ``hidepid`` outside the unit the cleanup by ``/proc`` would see nothing."""
    assert world.run([code_probe("quick", doc_code("quick"))], blind=True) == 0
    entry = world.tier().modules["quick"]
    assert entry.state is ModuleState.FAILED and entry.error is not None
    assert entry.error.id == "collect.error.cleanup"
    assert "/proc hides the processes of motp" in world.log.getvalue()


def test_inside_the_unit_the_cleanup_kills_by_control_group(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a control group the cleanup ignores ``/proc`` (blind or not) and ends every
    process the group lists except the collector itself."""
    procs = world.root / "cgroup.procs"
    leave = (
        "import subprocess, sys\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],"
        " start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        f"open({str(procs)!r}, 'a').write(str(p.pid) + '\\n')\n"
    ) + doc_code("leaver")
    procs.write_text(f"{os.getpid()}\n")
    procs.chmod(0o666)  # the probe (user motp) appends the pid it leaves behind
    calls: list[str] = []
    real = proc.cleanup_cgroup

    def counting(path: str, timeout: float = proc.CLEANUP_SECONDS) -> proc.Cleanup:
        calls.append(path)
        return real(path, timeout)

    monkeypatch.setattr(proc, "cleanup_cgroup", counting)
    collector = world.collector([code_probe("leaver", leave)], cgroup_procs=str(procs), blind=True)
    assert collector.run() == 0, world.log.getvalue()
    assert calls == [str(procs)]
    assert world.tier().modules["leaver"].state is ModuleState.OK, world.log.getvalue()
    assert not proc.live_processes(uid_of(PROBE_USER)), "the left process survived"


def test_an_unexpected_error_logs_only_its_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    """T11: a traceback would put paths and values into the journal."""
    from motp.collect import runner

    def boom(self: Collector) -> int:
        raise ValueError("/etc/secret-path module hw_disks")

    monkeypatch.setattr(Collector, "run", boom)
    out = io.StringIO()
    assert runner.main(no_sandbox=True, out=out) == 1
    text = out.getvalue()
    assert "ValueError" in text and "secret" not in text and "hw_disks" not in text


def test_in_the_unit_collect_runs_and_never_starts_the_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both reviews: inside the unit, collect must not call systemctl start on itself
    (cgroup v1 or a missing cgroup.procs used to send it there)."""
    from motp.collect import runner, viaunit

    def refuse() -> int:
        raise AssertionError("the unit started itself")

    monkeypatch.setattr(viaunit, "main", refuse)
    monkeypatch.setattr(Collector, "run", lambda self: 7)
    monkeypatch.setattr(proc, "service_cgroup_procs", lambda unit: None)
    assert runner.main(no_sandbox=False, out=io.StringIO(), in_unit=True) == 7


# --- static mode (phase 8: 4.10, D7) ----------------------------------------------------


def static_world(world: World, mode: str = "static") -> Path:
    motd = world.root / "motd.d"
    world.paths = replace(world.paths, motd_dir=str(motd))
    # colour forced in the config: the static file must still have none
    world.config(f'[general]\nmode = "{mode}"\n[layout]\ncolor = "always"\n')
    return motd


def test_static_mode_writes_the_public_text_for_pam_motd(world: World) -> None:
    motd = static_world(world)
    assert world.run() == 0, world.log.getvalue()
    path = motd / store.MOTD_NAME
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode)
    assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o644, 0, 0)
    assert stat.S_IMODE(os.lstat(motd).st_mode) == 0o755
    data = path.read_bytes()
    assert b"\x1b" not in data and b"Uptime" in data
    assert all(len(line) <= 80 for line in data.decode().splitlines())
    assert not [p for p in motd.iterdir() if p.name.endswith(".tmp")]


def test_hybrid_mode_writes_no_static_file(world: World) -> None:
    motd = static_world(world, "hybrid")
    assert world.run() == 0, world.log.getvalue()
    assert not motd.exists()


def test_a_shared_directory_others_can_write_is_refused(world: World) -> None:
    motd = static_world(world)
    motd.mkdir(mode=0o755)
    motd.chmod(0o777)
    assert world.run() == 0  # the cache is written; only the static file is not
    assert not (motd / store.MOTD_NAME).exists()
    assert (world.cache_dir / store.PUBLIC_NAME).exists()
    assert "static MOTD file could not be written" in world.log.getvalue()


def test_an_existing_shared_directory_keeps_its_mode(world: World) -> None:
    motd = static_world(world)
    motd.mkdir()
    motd.chmod(0o750)
    assert world.run() == 0, world.log.getvalue()
    assert stat.S_IMODE(os.lstat(motd).st_mode) == 0o750
    assert (motd / store.MOTD_NAME).exists()


@pytest.mark.parametrize("error", [RuntimeError("bug"), "control"])
def test_a_failed_static_render_removes_the_old_file_and_ends_nothing(
    world: World, monkeypatch: pytest.MonkeyPatch, error: object
) -> None:
    """Security review, phase 8: an old static file would keep showing a stale state, and
    an unexpected error must not fail the whole run."""
    from motp.collect import runner

    motd = static_world(world)
    assert world.run() == 0, world.log.getvalue()
    assert (motd / store.MOTD_NAME).exists()

    def broken(*_args: object) -> bytes:
        if isinstance(error, Exception):
            raise error
        return runner.check_static("\x1b[31m\n")

    monkeypatch.setattr(runner, "static_text", broken)
    assert world.run() == 0, world.log.getvalue()
    assert not (motd / store.MOTD_NAME).exists()
    assert (world.cache_dir / store.PUBLIC_NAME).exists()
    log = world.log.getvalue()
    assert "collect: done" in log.splitlines()[-1]
    if isinstance(error, Exception):
        assert "(RuntimeError)" in log and "bug" not in log

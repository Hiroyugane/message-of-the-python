"""Exec plugins and the ``file_age`` row (blueprint 4.9, D10, D26, D27, T7, T9, T21, T23).

These run anywhere: the plugin document rules, the shim's exit codes, the ``systemd-run``
command of a plugin's own unit, the probes built from discovery (and their cap), the item
visibility, and the ``file_age`` module against a fake context. The same with real files,
as root, is ``tests/test_plugins_linux.py``.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest

from motp.collect import plugins, runner
from motp.collect.runner import Probe
from motp.core import cache, config, proc
from motp.core.model import (
    ContractError,
    Item,
    LiteralText,
    ModuleState,
    Status,
    Unit,
    Visibility,
    ref,
)
from motp.core.probe import validate_plugin
from motp.install import units
from motp.modules import registry
from motp.modules.base import Context
from motp.modules.rows_file_age import RowsFileAge, rows_of, status_of

from .conftest import PLUGIN_USER, PROBE_USER

PY = sys.executable
ESC = "\x1b"


# --- the document rules (D26, D27, 4.4, T7) ---------------------------------------------


def test_a_plugin_document_may_leave_out_its_module() -> None:
    data = json.dumps({"api": 1, "items": [{"key": "age", "value": 3, "unit": "count"}]})
    doc = validate_plugin(data.encode(), 0, "50-backup", public=False)
    assert [i.key for i in doc.items] == ["plugin.50-backup.age"]


def test_a_plugin_document_naming_another_module_is_refused() -> None:
    data = json.dumps({"api": 1, "module": "os_updates", "items": []})
    with pytest.raises(ContractError) as info:
        validate_plugin(data.encode(), 0, "50-backup", public=False)
    assert info.value.message.id == "probe.error.module_mismatch"


def test_built_in_keys_catalogue_ids_and_hint_ids_stay_plain_prefixed_text() -> None:
    item = {
        "key": "os_updates.pending",
        "label": "label.updates",
        "text": f"{ESC}[31mupdates.summary{ESC}[0m",
        "hint": "updates.install",
        "status": "crit",
        "visibility": "public",
    }
    data = json.dumps({"api": 1, "items": [item]}).encode()
    (got,) = validate_plugin(data, 0, "50-evil", public=False).items
    assert got.key == "plugin.50-evil.os_updates.pending"
    assert got.origin == "50-evil"
    assert got.label == LiteralText("label.updates")
    assert got.text == LiteralText("[31mupdates.summary[0m")
    assert got.hint == LiteralText("updates.install")
    assert got.visibility is Visibility.ADMIN  # not made public by the admin (D27)


@pytest.mark.parametrize(
    "item",
    [
        {"key": "x", "label": {"id": "label.updates"}},
        {"key": "x", "text": {"id": "updates.summary"}},
        {"key": "x", "hint": {"id": "updates.install"}},
        {"key": "x", "command": "rm -rf /"},
    ],
)
def test_ids_and_commands_refuse_the_whole_document(item: dict[str, object]) -> None:
    data = json.dumps({"api": 1, "items": [item]}).encode()
    with pytest.raises(ContractError):
        validate_plugin(data, 0, "50-evil", public=True)


def test_the_line_form_is_one_inert_line() -> None:
    out = f"{ESC}]0;title{ESC}\\OK {ESC}[2J\x07done | perf=1\nsecond line\n".encode()
    (got,) = validate_plugin(out + b"\xff\xfe", 1, "50-line", public=False).items
    assert got.key == "plugin.50-line.status" and got.status is Status.WARN
    assert isinstance(got.text, LiteralText)
    assert ESC not in got.text.text and "\x07" not in got.text.text
    assert "second" not in got.text.text and "perf" not in got.text.text


# --- the root shim's exit codes and the transient unit ----------------------------------


def result(code: Optional[int], **kw: object) -> proc.Result:
    fields: dict[str, object] = {
        "returncode": code,
        "stdout": b"out",
        "stderr": b"",
        "timed_out": False,
        "stdout_overflow": False,
        "stderr_truncated": False,
        "duration": 0.1,
    }
    fields.update(kw)
    return proc.Result(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize("code", [0, 1, 2, 3, 5, 89])
def test_the_shim_gives_back_the_plugins_exit_code(code: int) -> None:
    assert plugins.shim_code(result(code)) == plugins.SHIM_BASE + code
    back = plugins.from_shim(result(plugins.SHIM_BASE + code))
    assert isinstance(back, proc.Result) and back.returncode == code and back.stdout == b"out"


@pytest.mark.parametrize(
    ("outcome", "shim"),
    [
        (result(90), plugins.SHIM_HIGH),
        (result(-9), plugins.SHIM_SIGNAL),
        (result(None, timed_out=True), plugins.SHIM_TIMEOUT),
        (result(0, stdout_overflow=True), plugins.SHIM_OVERFLOW),
    ],
)
def test_the_shim_names_what_ended_the_plugin(outcome: proc.Result, shim: int) -> None:
    assert plugins.shim_code(outcome) == shim


@pytest.mark.parametrize(
    ("code", "msg_id"),
    [
        (plugins.SHIM_HIGH, "collect.error.exit_high"),
        (plugins.SHIM_SIGNAL, "collect.error.signal"),
        (plugins.SHIM_REFUSED, "collect.error.refused_in_unit"),
        (plugins.SHIM_START, "proc.error.start"),
        (1, "collect.error.root_unit"),  # systemd-run's own failure, never "warning"
        (203, "collect.error.root_unit"),  # systemd's exec failure inside the unit
    ],
)
def test_other_codes_of_systemd_run_are_failures(code: int, msg_id: str) -> None:
    back = plugins.from_shim(result(code))
    assert isinstance(back, proc.ProcError) and back.message.id == msg_id


def test_the_collectors_own_limits_come_before_the_shims_code() -> None:
    late = plugins.from_shim(result(None, timed_out=True))
    assert isinstance(late, proc.Result) and late.timed_out
    assert plugins.from_shim(result(plugins.SHIM_TIMEOUT)).timed_out  # type: ignore[union-attr]
    flood = plugins.from_shim(result(plugins.SHIM_OVERFLOW))
    assert isinstance(flood, proc.Result) and flood.stdout_overflow


def unit_props(root: bool) -> tuple[tuple[str, ...], list[str], list[str]]:
    argv = units.plugin_unit_argv("/usr/bin/systemd-run", "50-x", 5.0, root, ("/py", "_x"))
    props = [argv[i + 1] for i, a in enumerate(argv) if a == "--property"]
    env = [argv[i + 1] for i, a in enumerate(argv) if a == "--setenv"]
    return argv, props, env


@pytest.mark.parametrize("root", [True, False])
def test_every_plugin_unit_is_private_and_read_only(root: bool) -> None:
    argv, props, env = unit_props(root)
    assert argv[0] == "/usr/bin/systemd-run" and argv[-3:] == ("--", "/py", "_x")
    assert props[: len(units.PLUGIN_PROPERTIES)] == list(units.PLUGIN_PROPERTIES)
    for wanted in (
        "ProtectSystem=strict",
        "ReadOnlyPaths=/run",
        "InaccessiblePaths=-/run/motp -/var/lib/motp",
        "PrivateIPC=yes",
        "PrivateNetwork=yes",
        "MemoryMax=128M",
        "RuntimeMaxSec=9",
    ):
        assert wanted in props, wanted
    tmp = next(p for p in props if p.startswith("TemporaryFileSystem=/tmp"))
    # PrivateDevices alone keeps the host's /dev/shm (measured), so it gets a tmpfs too.
    assert "/var/tmp:" in tmp and "/dev/shm:" in tmp  # noqa: S108
    assert not any(
        p.startswith(("ReadWritePaths", "RuntimeDirectory", "StateDirectory")) for p in props
    )
    assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in env and "MOTP_TIMEOUT=5" in env
    assert "--unit=motp-plugin-50-x" in argv and "--wait" in argv and "--pipe" in argv


def test_a_root_plugin_unit_hides_root_sockets_and_keeps_only_reading() -> None:
    _argv, props, _env = unit_props(True)
    assert "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in props
    # An empty /run below which paths are hidden fails the unit on systemd 252 (226).
    assert not any(p.startswith("TemporaryFileSystem=/run") for p in props)
    hidden = next(p for p in props if p.startswith("InaccessiblePaths=-/run/systemd/private"))
    for path in ("/run/dbus", "/run/docker.sock", "/run/containerd", "/run/podman"):
        assert "-" + path in hidden
    # Security review of phase 14: root's user manager and the other root runtimes too.
    more = next(p for p in props if p.startswith("InaccessiblePaths=-/run/user "))
    for path in ("/run/snapd.socket", "/run/crio", "/run/k3s", "/run/libvirt", "/run/incus",
                 "/run/lxd", "/run/udev/control"):  # fmt: skip
        assert "-" + path in more
    assert not any(p.startswith("User=") for p in props)


def test_a_user_plugin_unit_runs_as_motp_plugin_without_capabilities() -> None:
    _argv, props, _env = unit_props(False)
    assert "User=motp-plugin" in props and "Group=motp-plugin" in props
    assert "CapabilityBoundingSet=" in props
    assert not any(p.startswith("CapabilityBoundingSet=CAP") for p in props)


# --- probes built from discovery, visibility ---------------------------------------------


LAUNCH = ("/usr/bin/python3", "/opt/motp/lib")


def found(name: str = "50-x", run_as: str = "motp-plugin", **kw: object) -> plugins.Found:
    return plugins.Found(name, plugins.ACCEPTED, None, "/etc/motp/plugins.d/" + name, run_as, **kw)  # type: ignore[arg-type]


def test_a_plugin_runs_its_real_path_as_motp_plugin_and_is_admin_only() -> None:
    (p,) = runner.plugin_probes([found()], LAUNCH, None, None)
    assert p.argv == ("/etc/motp/plugins.d/50-x",) and p.user == PLUGIN_USER
    assert p.plugin and not p.public and p.visibility is Visibility.ADMIN and not p.in_unit


@pytest.mark.parametrize("run_as", ["root", "motp-plugin"])
def test_inside_the_unit_every_plugin_runs_the_shim_in_its_own_unit(run_as: str) -> None:
    (p,) = runner.plugin_probes([found(run_as=run_as)], LAUNCH, None, "/usr/bin/systemd-run")
    assert p.user == run_as and p.in_unit and p.refused is None
    assert p.argv[0] == "/usr/bin/systemd-run"
    assert p.argv[-6:] == ("/usr/bin/python3", "-I", "-S", "/opt/motp/lib", "_plugin", "50-x")
    assert ("User=motp-plugin" in p.argv) == (run_as == "motp-plugin")
    assert p.timeout == plugins.DEFAULT_TIMEOUT + units.PLUGIN_SLACK


@pytest.mark.parametrize("run_as", ["root", "motp-plugin"])
def test_without_a_trusted_systemd_run_a_plugin_is_refused_never_run_here(run_as: str) -> None:
    (p,) = runner.plugin_probes([found(run_as=run_as)], LAUNCH, None, "")
    assert p.refused is not None and p.refused.id == "collect.error.no_systemd_run"
    (q,) = runner.plugin_probes([found(run_as=run_as)], None, None, "/usr/bin/systemd-run")
    assert q.refused is not None


def test_only_the_first_32_plugin_names_become_modules() -> None:
    """Code review (high): every refused name used to become a module, and more than 64
    modules made the cache writer raise, ending the whole run."""
    too_many = ref("plugin.error.too_many", max=plugins.MAX_PLUGINS)
    entries = [plugins.Found(f"{n}-p", plugins.REFUSED, ref("safepath.error.owner", path="/x"))
               for n in range(10, 42)]  # fmt: skip
    entries += [plugins.Found(f"{n}-p", plugins.REFUSED, too_many) for n in range(42, 99)]
    entries.append(plugins.Found("plugins.d", plugins.REFUSED, ref("plugin.error.unreadable_dir")))
    probes = runner.plugin_probes(entries, LAUNCH, None, None)
    assert len(probes) == plugins.MAX_PLUGINS
    assert len(probes) + len(registry.CACHED) + 1 <= cache.MAX_MODULES


def test_ignored_names_get_no_probe_and_refused_plugins_keep_their_reason() -> None:
    entries = [
        plugins.Found("README", plugins.IGNORED, ref("plugin.ignored.name")),
        plugins.Found("10-bad", plugins.REFUSED, ref("safepath.error.owner", path="/x")),
    ]
    probes = runner.plugin_probes(entries, LAUNCH, None, None)
    assert [p.name for p in probes] == ["10-bad"]
    assert probes[0].refused is not None and probes[0].refused.id == "safepath.error.owner"


def plugin_probe(public: bool = False) -> Probe:
    return Probe("50-x", ("/x",), PLUGIN_USER, 5, 300, 1800, plugin=True, public=public)


def test_old_items_of_a_plugin_made_admin_only_leave_the_public_tier() -> None:
    item = Item("plugin.50-x.a", 1, Unit.COUNT, visibility=Visibility.PUBLIC, origin="50-x")
    (kept,) = runner.admin_only(plugin_probe(public=False), [item])
    assert kept.visibility is Visibility.ADMIN
    assert runner.admin_only(plugin_probe(public=True), [item]) == (item,)
    module = Probe("os_host", ("/x",), PROBE_USER, 5, 300, 1800)
    assert runner.admin_only(module, [item]) == (item,)


@pytest.mark.parametrize(
    ("code", "status"), [(0, Status.OK), (2, Status.CRIT), (3, Status.UNKNOWN)]
)
def test_settle_reads_both_forms_of_a_plugin(code: int, status: Status) -> None:
    got = runner.settle(plugin_probe(), result(code, stdout=b"fine\n"), None, 100, {})
    assert got.state is ModuleState.OK
    (item,) = got.items
    assert item.status is status and item.visibility is Visibility.ADMIN


@pytest.mark.parametrize(
    ("outcome", "msg_id"),
    [
        (result(4), "collect.error.exit"),
        (result(None, timed_out=True), "collect.error.timeout"),
        (result(0, stdout_overflow=True), "collect.error.too_large"),
    ],
)
def test_a_plugin_that_fails_costs_only_its_own_row(outcome: proc.Result, msg_id: str) -> None:
    got = runner.settle(plugin_probe(), outcome, None, 100, {})
    assert got.state is ModuleState.FAILED and got.error is not None and got.error.id == msg_id


# --- the file_age row ---------------------------------------------------------------------


class AgeContext(Context):
    def __init__(self, now: int, times: dict[str, object], config: "dict[str, object]") -> None:
        super().__init__(now=now, config=config)
        object.__setattr__(self, "times", times)

    def file_mtime(self, path: str) -> int:
        value = self.times[path]  # type: ignore[attr-defined]
        if isinstance(value, str):
            raise ContractError(ref(value))
        return int(str(value))


ROWS: "dict[str, object]" = {
    "rows": [
        ["/var/backups/a", "Backup", 3600, 7200],
        ["/var/backups/b", "Backup", 3600, 7200],
        ["/srv/missing", "Gone", 60, 120],
        ["/root/stamp", "Hidden", 60, 120],
    ]
}


def test_file_age_rows_classify_age_missing_and_unreadable() -> None:
    times = {
        "/var/backups/a": 10_000 - 4000,
        "/var/backups/b": 10_000 + 50,  # in the future: just now
        "/srv/missing": "context.error.missing",
        "/root/stamp": "context.error.read",
    }
    items = RowsFileAge().collect(AgeContext(10_000, times, ROWS))
    assert [i.key for i in items] == [
        "rows_file_age.backup", "rows_file_age.backup-2", "rows_file_age.gone",
        "rows_file_age.hidden",
    ]  # fmt: skip
    assert [i.status for i in items] == [Status.WARN, Status.OK, Status.CRIT, Status.UNKNOWN]
    assert [i.value for i in items] == [4000, 0, None, None]
    assert items[2].text == ref("file_age.missing")
    assert items[3].text == ref("file_age.unreadable")
    assert all("/" not in i.key and i.visibility is Visibility.PUBLIC for i in items)


def test_file_age_limits() -> None:
    assert [status_of(a, 10, 20) for a in (0, 9, 10, 19, 20)] == [
        Status.OK, Status.OK, Status.WARN, Status.WARN, Status.CRIT,
    ]  # fmt: skip


@pytest.mark.parametrize(
    "row",
    [
        ["relative/path", "B", 1, 2],
        ["/a/../etc/shadow", "B", 1, 2],
        ["/a/./b", "B", 1, 2],
        ["/a/", "B", 1, 2],
        ["//a", "B", 1, 2],
        ["/", "B", 1, 2],
        ["/a\0b", "B", 1, 2],
        ["/a", "", 1, 2],
        ["/a", "B", 2, 1],
        ["/a", "B", -1, 2],
        ["/a", "B", 1],
    ],
)
def test_the_module_checks_every_row_again(row: list[object]) -> None:
    with pytest.raises(ContractError):
        rows_of({"rows": [row]})


@pytest.mark.parametrize("path", ["/a/../b", "/a/./b", "/a//b", "/a/", "/", "rel", "//a"])
def test_the_config_refuses_a_path_not_in_its_normal_form(path: str) -> None:
    text = (
        f"[[rows.file_age]]\npath = {json.dumps(path)}\nlabel = 'B'\n"
        "warn_after = '1h'\ncrit_after = '2h'\n"
    )
    problems = config.check_content(text.encode())
    assert any(p.id == "config.error.absolute_path" for p in problems)


def test_the_runner_hands_the_rows_to_the_module_in_seconds() -> None:
    raw, _ = config.parse(
        b"[[rows.file_age]]\npath = '/var/backups/s'\nlabel = 'B'\n"
        b"warn_after = '26h'\ncrit_after = '3d'\n"
    )
    assert raw is not None
    settings = config.build(config.merge(config._default_raw(), raw))
    own = runner.module_config("rows_file_age", settings)
    assert own == {"rows": [["/var/backups/s", "B", 26 * 3600, 3 * 86400]]}
    assert rows_of(own) == [("/var/backups/s", "B", 26 * 3600, 3 * 86400)]


def test_the_config_and_discovery_agree_on_plugin_names() -> None:
    from motp.core import probe

    assert config.PLUGIN_NAME.pattern == probe.PLUGIN_NAME.pattern


# --- the plugin account's groups (security review of phase 14) ---------------------------


def _account_tree(tmp_path: Path, members: str) -> runner.Paths:
    from motp.collect import runner

    (tmp_path / "passwd").write_text(
        "root:x:0:0::/root:/bin/sh\nmotp-plugin:x:982:982::/:/usr/sbin/nologin\n"
    )
    (tmp_path / "group").write_text(f"root:x:0:\nmotp-plugin:x:982:\nadm:x:4:{members}\n")
    (tmp_path / "login.defs").write_text("SYS_UID_MAX 999\n")
    return runner.Paths(
        accounts_file=str(tmp_path / "passwd"),
        group_file=str(tmp_path / "group"),
        login_defs=str(tmp_path / "login.defs"),
    )


def test_supplementary_groups_of_the_plugin_user(tmp_path: Path) -> None:
    from motp.collect import runner

    paths = _account_tree(tmp_path, "syslog,motp-plugin")
    assert runner.supplementary_groups("motp-plugin", paths.group_file) == ["adm"]
    assert runner.supplementary_groups("motp-plugin", str(tmp_path / "missing")) == ["?"]


@pytest.mark.parametrize(("members", "refused"), [("syslog", False), ("motp-plugin", True)])
def test_plugins_are_refused_while_their_account_has_other_groups(
    tmp_path: Path, members: str, refused: bool
) -> None:
    """systemd's User= in a plugin's unit hands it every supplementary group (initgroups);
    the direct drop gives none. A motp-plugin in adm would give every plugin the logs."""
    from motp.collect import runner

    paths = _account_tree(tmp_path, members)
    fake = SimpleNamespace(paths=paths)
    if refused:
        with pytest.raises(ContractError) as err:
            runner.Collector._drop(fake, "motp-plugin")  # type: ignore[arg-type]
        assert err.value.message.id == "collect.error.account_groups"
    else:
        assert runner.Collector._drop(fake, "motp-plugin") is not None  # type: ignore[arg-type]

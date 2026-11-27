"""Collector logic that needs no processes and no root (blueprint 4.4, 4.8, 4.14).

Scheduling, turning process outcomes into module results, classification, the state file
format, the status line, the probe command and ``motp modules``. The root-only parts (real
probe processes, modes and owners, the lock) are in ``test_collect.py``.
"""

import io
from dataclasses import replace
from pathlib import Path
from typing import Optional

import pytest

from motp.collect import listing, runner, store
from motp.core import cache, config, i18n, proc
from motp.core.model import (
    Item,
    ModuleResult,
    ModuleState,
    Status,
    Unit,
    Visibility,
    ref,
)
from motp.core.thresholds import Direction, Rule
from motp.modules import registry
from motp.modules.base import Context, Detection

NOW = 1795600000
RULES = {"disk_used_percent": Rule("disk_used_percent", 80, 90, Direction.HIGHER_IS_WORSE)}


def _probe(name: str = "os_host", interval: int = 300) -> runner.Probe:
    return runner.Probe(
        name=name, argv=("/bin/true",), user="motp", timeout=5, interval=interval, max_age=3600
    )


def _result(
    stdout: bytes = b"",
    code: Optional[int] = 0,
    timed_out: bool = False,
    overflow: bool = False,
) -> proc.Result:
    return proc.Result(code, stdout, b"", timed_out, overflow, False, 0.25)


def _doc(name: str, items: str) -> bytes:
    return f'{{"api": 1, "module": "{name}", "items": [{items}]}}'.encode()


DISK = '{"key": "hw_disks.root", "value": 85, "unit": "percent", "rule": "disk_used_percent"}'
OLD_ITEM = Item(key="hw_disks.root", value=50, unit=Unit.PERCENT, rule="disk_used_percent")


def _entry(attempted: int = NOW - 60, collected: int = NOW - 60) -> store.Entry:
    return store.Entry(
        attempted,
        ModuleResult(collected=collected, interval=300, max_age=3600, items=(OLD_ITEM,)),
    )


# --- scheduling ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "present", "due"),
    [
        (None, {"os_host"}, True),  # the state does not know it
        (_entry(NOW - 60), set(), True),  # missing from the cache (after a reboot)
        (_entry(NOW - 60), {"os_host"}, False),  # ran a minute ago
        (_entry(NOW - 300), {"os_host"}, True),  # the interval has passed
        (_entry(NOW - 299), {"os_host"}, True),  # a run that started a moment early
        (_entry(NOW - 270), {"os_host"}, True),  # within a tenth of the interval
        (_entry(NOW - 269), {"os_host"}, False),
        (_entry(NOW + 600), {"os_host"}, True),  # the clock went back
    ],
)
def test_a_module_is_due_by_interval_cache_and_state(
    entry: Optional[store.Entry], present: set[str], due: bool
) -> None:
    assert runner.Collector._due(_probe(), entry, present, NOW) is due


# --- outcomes --------------------------------------------------------------------------


def test_a_good_document_gives_fresh_classified_items() -> None:
    result = runner.settle(_probe("hw_disks"), _result(_doc("hw_disks", DISK)), None, NOW, RULES)
    assert result.state is ModuleState.OK and result.collected == NOW
    assert result.items[0].status is Status.WARN
    assert result.duration_ms == 250 and result.error is None


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (_result(timed_out=True, code=None), "collect.error.timeout"),
        (_result(overflow=True), "collect.error.too_large"),
        (_result(code=3), "collect.error.exit"),
        (None, "collect.error.budget"),
        (proc.ProcError(ref("proc.error.start", program="/x")), "proc.error.start"),
        (_result(b'{"api": 1, "module": "hw_disks", "items": [NaN]}'), "json.error.not_finite"),
        (_result(_doc("os_host", "")), "probe.error.module_mismatch"),
    ],
)
def test_a_failed_probe_keeps_the_last_good_items(outcome: proc.Outcome, reason: str) -> None:
    result = runner.settle(_probe("hw_disks"), outcome, _entry(), NOW, RULES)
    assert result.state is ModuleState.FAILED
    assert result.error is not None and result.error.id == reason
    assert result.collected == NOW - 60, "carried items keep their age, so they turn stale"
    assert result.items[0].value == 50 and result.items[0].status is Status.OK


def test_a_failed_probe_without_history_has_no_items() -> None:
    result = runner.settle(_probe(), _result(code=1), None, NOW, RULES)
    assert result.state is ModuleState.FAILED and result.items == ()


def test_classification_uses_the_current_rules() -> None:
    unknown_rule = Item(key="a.b", value=5, rule="nope")
    kept = Item(key="a.c", status=Status.CRIT)
    items = runner.classified([OLD_ITEM, unknown_rule, kept], RULES)
    assert [i.status for i in items] == [Status.OK, Status.UNKNOWN, Status.CRIT]


def test_state_entries_drop_gone_modules_and_keep_attempts() -> None:
    state = {"os_host": _entry(NOW - 60), "gone": _entry()}
    results = {"hw_disks": runner.settle(_probe("hw_disks"), None, None, NOW, RULES)}
    entries = runner.Collector._entries(
        [_probe("os_host"), _probe("hw_disks")], results, set(), state, RULES, NOW
    )
    assert set(entries) == {"os_host", "hw_disks"}
    assert entries["os_host"].attempted == NOW - 60  # carried
    assert entries["hw_disks"].attempted == 0  # never reached: due again next time


def test_probe_timeout_takes_module_config_or_the_larger_default() -> None:
    settings = config.defaults()
    module = registry.cached_module("hw_disks")
    assert module is not None
    assert runner.probe_timeout(module, settings) == 10.0  # its own need beats 5 s
    own = replace(settings, modules={"hw_disks": config.ModuleConfig("auto", 2.0)})
    assert runner.probe_timeout(module, own) == 2.0


class _Fake:
    """A cached module whose detection is fixed."""

    def __init__(self, name: str, found: bool, needs_root: bool = False) -> None:
        self.name = name
        self.section = "host"
        self.mode = "cached"
        self.needs_root = needs_root
        self.interval = 600
        self.max_age = 3600
        self.timeout = 3.0
        self.binaries: tuple[str, ...] = ()
        self.default_visibility = Visibility.PUBLIC
        self.found = found

    def detect(self, ctx: Context) -> Detection:
        return Detection(self.found, ref("modules.reason.disabled") if not self.found else None)

    def collect(self, ctx: Context) -> "list[Item]":
        return []


def test_choose_applies_enabled_and_detection() -> None:
    settings = replace(
        config.defaults(),
        modules={
            "off": config.ModuleConfig(False, None),
            "forced": config.ModuleConfig(True, None),
        },
    )
    mods = [_Fake("off", True), _Fake("forced", False), _Fake("auto_no", False), _Fake("yes", True)]
    states = {c.module.name: c.state for c in runner.choose(mods, settings, NOW)}
    assert states == {
        "off": "disabled",
        "forced": "active",
        "auto_no": "not_detected",
        "yes": "active",
    }


def test_probes_are_refused_when_the_launch_check_failed() -> None:
    settings = config.defaults()
    choices = runner.choose([_Fake("a", True), _Fake("r", True, needs_root=True)], settings, NOW)
    reason = ref("collect.error.program", path="-")
    probes = runner.builtin_probes(choices, settings, None, reason)
    assert [(p.name, p.user, p.refused) for p in probes] == [
        ("a", "motp", reason),
        ("r", "root", reason),
    ]
    ok = runner.builtin_probes(choices, settings, ("/usr/bin/python3", "/opt/motp/lib"), None)
    assert ok[0].argv == ("/usr/bin/python3", "-I", "-S", "/opt/motp/lib", "_probe", "a")


def test_local_group_reads_only_the_local_file(tmp_path: Path) -> None:
    groups = tmp_path / "group"
    groups.write_text("root:x:0:\nsudo:x:27:a\ntwice:x:5:\ntwice:x:6:\nzero:x:0:\n")
    assert runner.local_group("sudo", str(groups)) == 27
    assert runner.local_group("twice", str(groups)) is None
    assert runner.local_group("zero", str(groups)) is None  # never root's group by another name
    assert runner.local_group("missing", str(groups)) is None
    assert runner.local_group("sudo", str(tmp_path / "none")) is None


def test_render_settings_carry_the_config() -> None:
    settings = config.defaults()
    rendered = runner.render_settings(settings, NOW, "dnf")
    data = cache.decode_render_file(cache.encode_render_file(rendered))
    assert data.package_manager == "dnf" and data.timer_period == runner.TIMER_PERIOD
    assert set(data.thresholds) == set(settings.thresholds)
    assert "inode_used_percent" in data.thresholds


def test_heartbeat_prints_counts_at_its_interval() -> None:
    out = io.StringIO()
    moments = iter([0.0, 5.0, 10.0, 12.0, 21.0])
    beat = runner.Heartbeat(runner.Log(out, i18n.translator("en")), 3, 10.0, lambda: next(moments))
    beat.done, beat.failed = 1, 1
    for _ in range(4):
        beat.tick()
    assert out.getvalue().splitlines() == [
        "progress: collect done=1/3 failed=1 elapsed=10s",
        "progress: collect done=1/3 failed=1 elapsed=21s",
    ]


def test_log_lines_are_sanitised() -> None:
    out = io.StringIO()
    log = runner.Log(out, i18n.translator("en"))
    log.line("collect.log.module_failed", module="x", reason="r", stderr="\x1b[31mred\x07")
    assert "\x1b" not in out.getvalue() and "\x07" not in out.getvalue()


# --- motp modules ----------------------------------------------------------------------


def _tier(state: ModuleState) -> cache.TierCache:
    result = ModuleResult(
        collected=NOW, interval=300, max_age=3600, state=state, error=ref("collect.error.timeout")
    )
    return cache.TierCache(tier="admin", generated=NOW, modules={"hw_disks": result}, failed=1)


def test_modules_lists_every_module_and_shows_failures_to_admins_only() -> None:
    settings = config.defaults()
    public_rows = {r.name: r for r in listing.module_rows(settings, None, NOW)}
    admin_rows = {r.name: r for r in listing.module_rows(settings, _tier(ModuleState.FAILED), NOW)}
    names = ["os_uptime", "hw_load", "hw_memory", "os_host", "net_addresses", "hw_disks"]
    names += ["os_updates", "os_reboot", "os_autoupdates", "os_eol"]
    names += ["os_units", "rows_unit", "rows_file_age", "os_sessions", "os_login"]
    names += ["sec_logins", "sec_fail2ban", "sec_firewall", "app_containers"]
    assert list(public_rows) == names
    assert public_rows["os_uptime"].user == "reader" and public_rows["os_uptime"].interval is None
    assert public_rows["hw_disks"].user == "motp" and public_rows["hw_disks"].interval == 300
    if public_rows["hw_disks"].state == "active":  # detection depends on the machine
        assert admin_rows["hw_disks"].state == "failed"
        assert admin_rows["hw_disks"].reason == ref("collect.error.timeout")


def test_modules_table_is_aligned_and_from_the_catalogue() -> None:
    rows = [
        listing.Row("os_host", "active", "motp", 300, "public"),
        listing.Row("hw_disks", "failed", "motp", 300, "public", ref("collect.error.timeout")),
        listing.Row("hw_load", "not_detected", "reader", None, "public"),
    ]
    lines = listing.format_rows(rows, i18n.translator("en"))
    assert lines[0].split() == ["MODULE", "STATE", "USER", "INTERVAL", "VISIBLE", "TO", "REASON"]
    assert lines[2].startswith("hw_disks  failed")
    assert lines[2].endswith("the probe took longer than its time limit")
    assert "not detected  reader  live" in lines[3]
    for column, words in (
        ("STATE", ["active", "failed", "not detected"]),
        ("USER", ["motp", "motp", "reader"]),
    ):
        start = lines[0].index(column)
        assert [line[start:].split("  ")[0] for line in lines[1:]] == words

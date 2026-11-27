"""The module interface, the live modules and the registry (blueprint 4.3, phase 5)."""

import ast
import re
from pathlib import Path

import pytest

from motp.core.i18n import translator
from motp.core.model import ContractError, Item, Status, Unit
from motp.core.thresholds import classify
from motp.modules import hw_load, hw_memory, registry
from motp.modules.base import Context, ContextError, Detection, format_bytes
from motp.modules.hw_load import HwLoad
from motp.modules.hw_memory import HwMemory
from motp.modules.os_uptime import OsUptime
from motp.render import view

from .conftest import ROOT, SRC
from .support import FixtureContext


def only(items: list[Item], key: str) -> Item:
    found = [i for i in items if i.key == key]
    assert len(found) == 1
    return found[0]


def params(item: Item) -> dict[str, object]:
    assert item.text is not None and hasattr(item.text, "param_dict")
    return dict(item.text.param_dict())


# --- Context ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "proc/loadavg",
        "/proc/../etc/passwd",
        "/proc//loadavg",
        "/procx/a",
        "",
        "/proc/\0",
    ],
)
def test_context_refuses_paths_outside_proc_and_sys(path: str) -> None:
    ctx = Context(now=1)
    with pytest.raises(ContextError):
        ctx.read_text(path)
    with pytest.raises(ContextError):
        ctx.exists(path)


def test_context_run_raises_for_live_modules() -> None:
    with pytest.raises(ContextError) as caught:
        Context(now=1).run(["/usr/bin/true"])
    assert caught.value.message.id == "context.error.run"


def test_context_read_is_bounded() -> None:
    ctx = FixtureContext("debian12")
    full = ctx.read_text("/proc/meminfo")
    assert len(full) > 100
    assert ctx.read_text("/proc/meminfo", 20) == full[:20]
    with pytest.raises(ContextError):
        ctx.read_text("/proc/meminfo", 0)
    with pytest.raises(ContextError):
        ctx.read_text("/proc/meminfo", 10**9)


def test_context_missing_file_is_a_context_error() -> None:
    with pytest.raises(ContextError):
        FixtureContext("debian12").read_text("/proc/nothing")


@pytest.mark.skipif(not Path("/proc/loadavg").exists(), reason="needs /proc")
def test_real_context_reads_proc() -> None:
    ctx = Context(now=1)
    assert ctx.exists("/proc/loadavg")
    assert len(ctx.read_text("/proc/loadavg", 256).split()) == 5
    assert len(ctx.read_text("/proc/meminfo", 64)) <= 64


# --- live modules on fixture trees -------------------------------------------------------


def test_hw_load_debian() -> None:
    item = only(HwLoad().collect(FixtureContext("debian12")), "hw_load.per_core")
    assert item.rule == "load_per_core"
    assert isinstance(item.value, float)
    assert item.value == pytest.approx(0.37 / 4, abs=0.001)
    assert item.unit is Unit.RATIO
    assert params(item) == {"one": "0.42", "five": "0.37", "fifteen": "0.31"}
    assert classify(item.value, registry.LIVE_RULES["load_per_core"]) is Status.OK


def test_hw_load_alma_is_overloaded() -> None:
    item = only(HwLoad().collect(FixtureContext("almalinux9")), "hw_load.per_core")
    assert item.value == pytest.approx(3.10 / 2, abs=0.001)
    assert classify(item.value, registry.LIVE_RULES["load_per_core"]) is Status.CRIT


def test_cpu_count_falls_back_to_cpuinfo() -> None:
    assert hw_load.cpu_count(FixtureContext("oldkernel")) == 2
    assert hw_load.cpu_count(FixtureContext("debian12")) == 4


@pytest.mark.parametrize(
    "text,count",
    [("0-3", 4), ("0", 1), ("0-1,4-5", 4), ("", 0), ("a-b", 0), ("3-1", 0), ("0-", 0)],
)
def test_cpu_list(text: str, count: int) -> None:
    assert hw_load.parse_cpu_list(text) == count


@pytest.mark.parametrize("text", ["", "x y z", "nan 1 2", "-1 0 0", "1 2"])
def test_loadavg_garbage_is_a_contract_error(text: str) -> None:
    with pytest.raises(ContractError):
        hw_load.parse_loadavg(text)


def test_hw_memory_debian_has_memory_and_swap() -> None:
    items = HwMemory().collect(FixtureContext("debian12"))
    used = only(items, "hw_memory.used")
    # 8266856 kB total, 2000000 kB available -> 6266856 kB used = 75.8 %
    assert isinstance(used.value, float)
    assert used.value == pytest.approx(75.8, abs=0.05)
    assert used.rule == "memory_used_percent" and used.unit is Unit.PERCENT
    assert params(used) == {"used": "6 GiB", "total": "7.9 GiB"}
    swap = only(items, "hw_memory.swap")
    assert swap.rule == "swap_used_percent"
    assert isinstance(swap.value, float)
    assert swap.value == pytest.approx(10.0, abs=0.1)


def test_hw_memory_without_swap_has_no_swap_row() -> None:
    items = HwMemory().collect(FixtureContext("almalinux9"))
    assert [i.key for i in items] == ["hw_memory.used"]
    assert classify(items[0].value, registry.LIVE_RULES["memory_used_percent"]) is Status.WARN


def test_hw_memory_old_kernel_estimates_available() -> None:
    items = HwMemory().collect(FixtureContext("oldkernel"))
    # available = free + buffers + cached = 1200000 kB of 2048000 kB -> 41.4 % used
    used = only(items, "hw_memory.used")
    assert isinstance(used.value, float)
    assert used.value == pytest.approx(41.4, abs=0.05)
    assert only(items, "hw_memory.swap").value == 0.0


def test_hw_memory_without_total_is_a_contract_error() -> None:
    class Empty(FixtureContext):
        def _read_bytes(self, path: str, max_bytes: int) -> bytes:
            return b"MemFree: 5 kB\n"

    with pytest.raises(ContractError):
        HwMemory().collect(Empty("debian12"))


def test_parse_meminfo_ignores_odd_lines() -> None:
    fields = hw_memory.parse_meminfo("A: 5 kB\nnonsense\nB: x kB\nC: 99999999999999999999999 kB\n")
    assert fields == {"A": 5}


def test_os_uptime() -> None:
    item = only(OsUptime().collect(FixtureContext("debian12")), "os_uptime.uptime")
    assert (item.value, item.unit) == (3553200, Unit.SECONDS)
    assert item.key == view.UPTIME_KEY


@pytest.mark.parametrize("tree", ["debian12", "almalinux9", "oldkernel"])
def test_every_module_detects_and_collects_on_every_tree(tree: str) -> None:
    ctx = FixtureContext(tree)
    for module in registry.live_modules():
        assert module.detect(ctx) == Detection(True)
        assert module.collect(ctx)


def test_modules_not_detected_without_proc(tmp_path: Path) -> None:
    ctx = FixtureContext("nothing", root=tmp_path)
    assert all(not m.detect(ctx).available for m in registry.live_modules())


def test_module_memory_text_matches_the_renderer() -> None:
    tr = translator("en")
    for value in (0, 512, 1024, 1536, 7 * 2**30, 123 * 2**20, 5 * 2**40):
        assert format_bytes(value) == view.format_bytes(tr, value)


# --- the interface and the registry ---------------------------------------------------


def test_live_modules_satisfy_the_interface() -> None:
    for module in registry.live_modules():
        assert module.mode == "live" and not module.needs_root
        assert module.binaries == () and module.interval >= 1 and module.max_age >= 1
        assert re.fullmatch(r"[a-z]{2}_[a-z]+", module.name)
        assert registry.section_of(module.name) == module.section


def test_registry_is_an_explicit_list() -> None:
    tree = ast.parse((SRC / "motp/modules/registry.py").read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "LIVE_MODULES" in names
    for forbidden in (
        "listdir",
        "scandir",
        "glob",
        "import_module",
        "walk_packages",
        "iter_modules",
    ):
        assert forbidden not in names | attrs


def test_section_of() -> None:
    assert registry.section_of("hw_disks") == "disks"
    assert registry.section_of("50-backup") == "plugins"
    assert registry.section_of("nonsense") is None


def test_default_rules_match_the_default_config() -> None:
    text = (ROOT / "src/motp/data/default-config.toml").read_text(encoding="utf-8")
    for name, rule in registry.LIVE_RULES.items():
        block = text.split(f"[thresholds.{name}]", 1)[1].split("[", 1)[0]
        warn = re.search(r"warn = ([\d.]+)", block)
        crit = re.search(r"crit = ([\d.]+)", block)
        direction = re.search(r'direction = "(\w+)"', block)
        assert warn and crit and direction
        assert (float(warn.group(1)), float(crit.group(1))) == (rule.warn, rule.crit)
        assert direction.group(1) == "higher" and rule.direction.value == "higher"

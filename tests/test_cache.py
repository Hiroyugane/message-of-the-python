"""Cache schemas, encoders and the bounded reader (blueprint 4.1, 4.4, D22, D32, T4, T10, T12)."""

import json
import os
import random
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

import pytest

from motp.core import cache
from motp.core.cache import (
    ADMIN,
    PUBLIC,
    Layout,
    RenderSettings,
    decode_render_file,
    decode_tier_file,
    decode_user_file,
    encode_render_file,
    encode_tier_file,
    encode_user_file,
    previous_login,
    read_bounded,
    read_tier_file,
)
from motp.core.model import (
    ContractError,
    Detail,
    HintRef,
    Item,
    LiteralText,
    Login,
    MessageRef,
    ModuleResult,
    ModuleState,
    Status,
    Unit,
    UserLogins,
    Visibility,
)
from motp.core.probe import validate_plugin
from motp.core.thresholds import make_rule

POSIX = os.name == "posix"
OWNER: Optional[int] = os.getuid() if POSIX else None

UPDATES = ModuleResult(
    collected=1795599700,
    interval=3600,
    max_age=86400,
    state=ModuleState.OK,
    duration_ms=180,
    items=(
        Item(
            key="updates.pending",
            value=12,
            unit=Unit.COUNT,
            label=MessageRef("status.warn"),
            rule="updates_pending",
            status=Status.WARN,
            text=MessageRef("modules.failed", (("count", 12),)),
            hint=HintRef("updates.install"),
            detail=(Detail("updates.packages", "openssl, curl"),),
        ),
        Item(key="updates.names", value="secret", visibility=Visibility.ADMIN),
    ),
)
PLUGIN = ModuleResult(
    collected=1795599800,
    interval=300,
    max_age=3600,
    state=ModuleState.OK,
    duration_ms=12,
    items=(
        Item(
            key="plugin.50-backup.age",
            value=3.5,
            unit=Unit.SECONDS,
            label=LiteralText("Backup", (("de", "Sicherung"),)),
            text=LiteralText("ok"),
            hint=LiteralText("check the disk"),
            visibility=Visibility.PUBLIC,
            origin="50-backup",
            bar=0.25,
            detail=(Detail("plugin.50-backup.path", "/srv", visibility=Visibility.PUBLIC),),
        ),
    ),
)
FAILED = ModuleResult(
    collected=1795599000,
    interval=300,
    max_age=3600,
    state=ModuleState.FAILED,
    duration_ms=5000,
    error=MessageRef("probe.error.exit_code", (("code", 2),)),
)
MODULES = {"os_updates": UPDATES, "50-backup": PLUGIN, "sec_firewall": FAILED}


def test_admin_file_round_trip() -> None:
    data = encode_tier_file(ADMIN, 1795600000, MODULES, failed=1)
    parsed = decode_tier_file(data, ADMIN)
    assert parsed.generated == 1795600000 and parsed.failed == 1
    assert dict(parsed.modules) == MODULES


def test_public_file_holds_public_data_only() -> None:
    data = encode_tier_file(PUBLIC, 1795600000, MODULES, failed=1)
    raw = json.loads(data)
    assert set(raw["modules"]) == {"os_updates", "50-backup"}  # failed module: count only
    assert all(
        set(m) == {"collected", "interval", "max_age", "items"} for m in raw["modules"].values()
    )
    assert b"secret" not in data and b"openssl" not in data
    parsed = decode_tier_file(data, PUBLIC)
    updates = parsed.modules["os_updates"]
    assert [i.key for i in updates.items] == ["updates.pending"]
    assert updates.items[0].detail == ()
    assert updates.state is None and updates.error is None
    assert parsed.modules["50-backup"].items[0].detail == PLUGIN.items[0].detail


def test_encoding_is_deterministic() -> None:
    a = encode_tier_file(ADMIN, 1, MODULES, 1)
    b = encode_tier_file(ADMIN, 1, dict(reversed(list(MODULES.items()))), 1)
    assert a == b and a.endswith(b"\n")


def _tier(modules: dict[str, Any], tier: str = PUBLIC, **top: Any) -> bytes:
    obj = {"schema": 1, "tier": tier, "generated": 1, "modules": modules, "failed": 0, **top}
    return json.dumps(obj).encode()


def _module(items: list[Any], **extra: Any) -> dict[str, Any]:
    return {"collected": 1, "interval": 300, "max_age": 600, "items": items, **extra}


def _reason(data: bytes, tier: str = PUBLIC) -> str:
    with pytest.raises(ContractError) as info:
        decode_tier_file(data, tier)
    return info.value.message.id


def _module_reason(raw: dict[str, Any], name: str = "x", tier: str = PUBLIC) -> str:
    with pytest.raises(ContractError) as info:
        cache._module(raw, name, tier)
    return info.value.message.id


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (_tier({}, tier=ADMIN), "cache.error.tier"),
        (_tier({}, schema=2), "cache.error.schema_version"),
        (_tier({}, schema="1"), "cache.error.schema_version"),
        (_tier({}, extra=1), "cache.error.schema"),
        (_tier({"Bad Name": _module([])}), "cache.error.schema"),
        (_tier({}, failed=-1), "cache.error.schema"),
        (b'{"schema": 1, "tier": "public", "generated": NaN}', "json.error.not_finite"),
    ],
)
def test_tier_file_schema(data: bytes, reason: str) -> None:
    assert _reason(data) == reason


PLUGIN_LABEL_ID = {"key": "plugin.50-b.c", "origin": "50-b", "label": {"id": "status.ok"}}
PLUGIN_HINT_ID = {"key": "plugin.50-b.c", "origin": "50-b", "hint": {"id": "updates.install"}}
WITH_ORIGIN = {"key": "plugin.50-b.c", "origin": "50-b"}


@pytest.mark.parametrize(
    ("raw", "name", "reason"),
    [
        (_module([{"key": "a.b", "visibility": "admin"}]), "x", "cache.error.admin_in_public"),
        (_module([{"key": "a.b", "detail": [{"key": "c.d"}]}]), "x", "cache.error.admin_in_public"),
        (_module([], state="ok"), "x", "cache.error.schema"),
        (_module([], error={"id": "status.ok"}), "x", "cache.error.schema"),
        (_module([], interval=0), "x", "cache.error.schema"),
        (_module([], collected=-1), "x", "cache.error.schema"),
        (_module([], collected=True), "x", "cache.error.schema"),
        (_module([{"key": "a.b"}] * 33), "x", "cache.error.schema"),
        (_module([{"key": "a.b", "command": "x"}]), "x", "probe.error.command"),
        (_module([PLUGIN_LABEL_ID]), "50-b", "probe.error.plugin_message_id"),
        (_module([PLUGIN_HINT_ID]), "50-b", "probe.error.plugin_message_id"),
        (_module([{"key": "plugin.60-x.c", "origin": "50-b"}]), "50-b", "probe.error.bad_value"),
        (_module([{"key": "a.b", "hint": {"id": "no.such"}}]), "x", "probe.error.unknown_hint"),
        # a built-in entry cannot carry plugin keys or a plugin's origin, and the reverse
        (_module([{"key": "plugin.10-x.status"}]), "x", "probe.error.bad_value"),
        (_module([WITH_ORIGIN]), "x", "cache.error.schema"),
        (_module([WITH_ORIGIN]), "60-c", "cache.error.schema"),
        (_module([{"key": "a.b"}]), "50-b", "cache.error.schema"),
    ],
)
def test_module_entry_schema(raw: dict[str, Any], name: str, reason: str) -> None:
    assert _module_reason(raw, name) == reason


def test_a_broken_module_is_skipped_not_the_whole_file() -> None:
    good = _module([{"key": "host.name", "value": "web01"}])
    bad = _module([{"key": "a.b", "visibility": "admin"}])
    parsed = decode_tier_file(_tier({"os_host": good, "os_units": bad}), PUBLIC)
    assert set(parsed.modules) == {"os_host"} and parsed.unreadable == 1


def test_admin_fields_are_checked_in_the_admin_file() -> None:
    assert _module_reason(_module([], state="maybe"), tier=ADMIN) == "cache.error.schema"
    bad_error = _module([], error={"id": "no.such.id"})
    assert _module_reason(bad_error, tier=ADMIN) == "cache.error.schema"


def _big_plugin(name: str) -> ModuleResult:
    """A plugin result at every limit: 32 items with 16 long details each."""
    text = "\u65e5\u0301\u0302" * 40
    items = tuple(
        Item(
            key=f"plugin.{name}.k{i:02d}",
            value=text,
            label=LiteralText(text, (("de", text),)),
            text=LiteralText(text),
            hint=LiteralText(text),
            origin=name,
            detail=tuple(Detail(f"plugin.{name}.d{j:02d}", text) for j in range(16)),
        )
        for i in range(32)
    )
    return ModuleResult(collected=1, interval=300, max_age=600, items=items)


def test_oversized_modules_are_shrunk_so_the_file_stays_readable() -> None:
    modules = {f"{n:02d}-p": _big_plugin(f"{n:02d}-p") for n in range(10, 42)}
    modules["os_updates"] = UPDATES
    data = encode_tier_file(ADMIN, 1, modules, failed=0)
    assert len(data) <= cache.MAX_TIER_BYTES
    parsed = decode_tier_file(data, ADMIN)
    assert parsed.unreadable == 0 and parsed.modules["os_updates"] == UPDATES
    shrunk = [r for r in parsed.modules.values() if r.state is ModuleState.FAILED]
    assert shrunk and parsed.failed == len(shrunk)
    assert all(r.error == MessageRef("cache.error.module_too_large") for r in shrunk)
    public_data = encode_tier_file(PUBLIC, 1, modules, failed=0)
    assert len(public_data) <= cache.MAX_TIER_BYTES
    public = decode_tier_file(public_data, PUBLIC)
    assert public.unreadable == 0 and "os_updates" in public.modules
    assert public.failed == len(modules) - len(public.modules)  # dropped ones are counted


@pytest.mark.parametrize(
    "result",
    [
        ModuleResult(collected=1, interval=10**8, max_age=600),
        ModuleResult(collected=1, interval=300, max_age=0),
        ModuleResult(collected=-1, interval=300, max_age=600),
        ModuleResult(collected=1, interval=300, max_age=600, items=(Item("a.b"),) * 33),
        ModuleResult(collected=1, interval=300, max_age=600, items=(Item("a.b", origin="50-x"),)),
    ],
)
def test_encoder_refuses_what_the_reader_would_refuse(result: ModuleResult) -> None:
    with pytest.raises(ValueError):
        encode_tier_file(ADMIN, 1, {"x": result}, failed=0)


HOSTILE_TEXTS = [
    "\u0958" + "\u1161" * 1023,
    "a" + "\u0301" * 1023,
    "\U00010000" * 1023,
    "\ufdfa" * 1000,
    "x" * 1024,
    "\u2026" * 1024,
    "\x1b[2J" * 200,
]


def test_whatever_the_collector_accepts_the_reader_accepts() -> None:
    """Property: validated plugin output always survives a cache round trip."""
    rng = random.Random(11)
    for round_ in range(80):
        texts = [
            rng.choice(HOSTILE_TEXTS)
            if rng.random() < 0.5
            else "".join(chr(rng.randint(0, 0x10FFFF)) for _ in range(rng.randint(0, 1024)))
            for _ in range(4)
        ]
        item = {
            "key": "a",
            "label": {"text": texts[0], "i18n": {"de": texts[1]}},
            "text": texts[2],
            "hint": texts[3],
            "value": texts[0],
            "visibility": "public",
            "detail": [{"key": "d", "value": texts[1], "visibility": "public"}],
        }
        raw = json.dumps({"api": 1, "module": "50-p", "items": [item]}).encode()
        if len(raw) > 65536:
            continue
        validated = validate_plugin(raw, 0, "50-p", public=True)
        result = ModuleResult(collected=1, interval=300, max_age=600, items=validated.items)
        for tier in (PUBLIC, ADMIN):
            parsed = decode_tier_file(encode_tier_file(tier, 1, {"50-p": result}, 0), tier)
            assert parsed.unreadable == 0, round_
            assert parsed.modules["50-p"].items == validated.items


def test_strings_are_sanitised_again_on_read() -> None:
    item = {
        "key": "host.name",
        "value": "web01\x1b]52;c;eA==\x07\u2502",
        "label": {"text": "\u202eLabel\u2588", "i18n": {"de": "\x9bX"}},
        "text": {"id": "plugin.prefix", "params": {"name": "\x1b[2Jx"}},
    }
    parsed = decode_tier_file(_tier({"os_host": _module([item])}), PUBLIC)
    (read,) = parsed.modules["os_host"].items
    assert read.value == "web01]52;c;eA==\ufffd"
    assert read.label == LiteralText("Label\ufffd", (("de", "X"),))
    assert read.text == MessageRef("plugin.prefix", (("name", "[2Jx"),))


SETTINGS = RenderSettings(
    generated=1795600000,
    layout=Layout(header="text", header_text="web01"),
    language="auto",
    thresholds={"load_per_core": make_rule("load_per_core", 0.7, 1.0)},
    timer_period=300,
    render_ms=1000,
    package_manager="apt",
)


def test_render_file_round_trip() -> None:
    assert decode_render_file(encode_render_file(SETTINGS)) == SETTINGS


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("layout", "sections"), ["host", "weather"]),
        (("layout", "sections"), ["host", "host"]),
        (("layout", "charset"), "ebcdic"),
        (("layout", "header_text"), 5),
        (("language",), "../../etc/passwd"),
        (("language",), "DE"),
        (("thresholds",), {"load": {"warn": 2, "crit": 1, "direction": "higher"}}),
        (("thresholds",), {"load": {"warn": 1, "crit": 2}}),
        (("thresholds",), {"Bad": {"warn": 1, "crit": 2, "direction": "higher"}}),
        (("timer_period",), 0),
        (("package_manager",), "pacman"),
    ],
)
def test_render_file_schema(path: tuple[str, ...], value: Any) -> None:
    obj = json.loads(encode_render_file(SETTINGS))
    target = obj
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ContractError):
        decode_render_file(json.dumps(obj).encode())


def test_render_file_header_text_is_sanitised() -> None:
    obj = json.loads(encode_render_file(SETTINGS))
    obj["layout"]["header_text"] = "\x1b[5mweb\u2588"
    assert decode_render_file(json.dumps(obj).encode()).layout.header_text == "[5mweb\ufffd"


USER = UserLogins(
    uid=1000,
    generated=1795600000,
    logins=(Login(1795599995, "192.0.2.10", "pts/1"), Login(1795500000, "192.0.2.11", "pts/0")),
)


def test_user_file_round_trip_and_previous_login() -> None:
    parsed = decode_user_file(encode_user_file(USER), 1000)
    assert parsed == USER
    # the newest login started 5 s ago: that is the current session
    assert previous_login(parsed, 1795600000, login=True) == USER.logins[1]
    assert previous_login(parsed, 1795600100, login=True) == USER.logins[0]
    assert previous_login(parsed, 1795600000, login=False) is None


def test_an_old_per_user_file_is_not_shown() -> None:
    # os_login rewrites the file every run; one an hour old means the module is failing
    assert previous_login(USER, 1795600000 + 3600, login=True) is not None
    assert previous_login(USER, 1795600000 + 3601, login=True) is None
    assert previous_login(USER, 1795600000 - 5, login=True) is None  # from the future


def test_user_file_sorts_newest_first_and_checks_uid() -> None:
    reordered = UserLogins(1000, 1, tuple(reversed(USER.logins)))
    assert decode_user_file(encode_user_file(reordered), 1000).logins == USER.logins
    with pytest.raises(ContractError) as info:
        decode_user_file(encode_user_file(USER), 1001)
    assert info.value.message.id == "cache.error.owner"


def test_user_file_limits_and_sanitising() -> None:
    entry = {"started": 1, "source": "host\x1b[2J\u202e", "tty": "pts/0"}
    obj = {"schema": 1, "uid": 7, "generated": 1, "logins": [entry]}
    assert decode_user_file(json.dumps(obj).encode(), 7).logins[0].source == "host[2J"
    obj["logins"] = [entry] * 4
    with pytest.raises(ContractError):
        decode_user_file(json.dumps(obj).encode(), 7)


# --- the bounded reader -----------------------------------------------------------------


def _write(path: Path, data: bytes, mode: int = 0o644) -> Path:
    path.write_bytes(data)
    if POSIX:
        path.chmod(mode)
    return path


def _read_reason(path: Path, max_bytes: int = 1024, owner: Optional[int] = OWNER) -> str:
    with pytest.raises(ContractError) as info:
        read_bounded(str(path), max_bytes, owner)
    return info.value.message.id


@pytest.mark.skipif(not POSIX, reason="Windows reports every file as writable by others")
def test_reads_a_regular_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "public.json", encode_tier_file(PUBLIC, 1, MODULES, 1))
    parsed = read_tier_file(str(path), PUBLIC, owner=OWNER)
    assert set(parsed.modules) == {"os_updates", "50-backup"}


@pytest.mark.skipif(not POSIX, reason="Windows reports every file as writable by others")
def test_refuses_files_over_the_cap(tmp_path: Path) -> None:
    path = _write(tmp_path / "big.json", b" " * 1025)
    assert _read_reason(path) == "cache.error.too_large"
    assert read_bounded(str(_write(tmp_path / "ok.json", b" " * 1024)), 1024, OWNER) == b" " * 1024
    huge = _write(tmp_path / "public.json", b" " * (cache.MAX_TIER_BYTES + 1))
    with pytest.raises(ContractError):
        read_tier_file(str(huge), PUBLIC, owner=OWNER)


def test_refuses_a_missing_file_and_a_directory(tmp_path: Path) -> None:
    assert _read_reason(tmp_path / "absent.json") == "cache.error.open"
    assert _read_reason(tmp_path) in {"cache.error.open", "cache.error.not_regular"}


@pytest.mark.skipif(not POSIX, reason="needs O_NOFOLLOW and symlinks")
def test_refuses_a_symlink(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.json", b"{}")
    link = tmp_path / "public.json"
    link.symlink_to(target)
    assert _read_reason(link) == "cache.error.open"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "public.json"
    os.mkfifo(fifo)
    result: list[str] = []
    worker = threading.Thread(target=lambda: result.append(_read_reason(fifo)), daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "reading a FIFO blocked"
    assert time.monotonic() - started < 2
    assert result == ["cache.error.not_regular"]


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
def test_refuses_group_or_other_writable_files(tmp_path: Path, mode: int) -> None:
    path = _write(tmp_path / "public.json", b"{}", mode)
    assert stat.S_IMODE(path.stat().st_mode) == mode
    assert _read_reason(path) == "cache.error.writable"


@pytest.mark.skipif(not POSIX, reason="POSIX owners")
def test_refuses_a_foreign_owner(tmp_path: Path) -> None:
    path = _write(tmp_path / "public.json", b"{}")
    assert _read_reason(path, owner=os.getuid() + 1) == "cache.error.owner"


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_admin_mode_0640_and_user_mode_0400_are_accepted(tmp_path: Path) -> None:
    assert read_bounded(str(_write(tmp_path / "a.json", b"{}", 0o640)), 10, OWNER) == b"{}"
    assert read_bounded(str(_write(tmp_path / "u.json", b"{}", 0o400)), 10, OWNER) == b"{}"


@pytest.mark.skipif(sys.platform != "linux", reason="needs /dev/zero")
def test_refuses_a_device() -> None:
    assert _read_reason(Path("/dev/zero"), owner=None) == "cache.error.not_regular"


def test_config_ignored_travels_in_the_admin_tier_only() -> None:
    """Final review, usability item 6: the count of ignored config files is admin-only."""
    admin = cache.encode_tier_file(cache.ADMIN, 1, {}, 0, config_ignored=2)
    assert cache.decode_tier_file(admin, cache.ADMIN).config_ignored == 2
    public = cache.encode_tier_file(cache.PUBLIC, 1, {}, 0)
    assert b"config_ignored" not in public
    with pytest.raises(ValueError):
        cache.encode_tier_file(cache.PUBLIC, 1, {}, 0, config_ignored=1)
    forged = public.replace(b'"failed":0', b'"config_ignored":1,"failed":0')
    assert forged != public
    with pytest.raises(ContractError):
        cache.decode_tier_file(forged, cache.PUBLIC)
    old = admin.replace(b'"config_ignored":2,', b"")
    assert cache.decode_tier_file(old, cache.ADMIN).config_ignored == 0

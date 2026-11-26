"""The service and login modules of phase 10: ``os_units``, ``rows_unit``, ``os_sessions``
and ``os_login``, against the records and output captured from each tier-1 image, and
against hostile records (escape bytes, oversized and cut records)."""

import json
import re
import struct
from collections.abc import Sequence
from pathlib import Path

import pytest

from motp.collect import child
from motp.core import cache, config, probe, strictjson
from motp.core.model import ContractError, Login, Status, UserLogins, Visibility
from motp.modules import os_login, records, rows_unit, services
from motp.modules.base import context_error
from motp.modules.os_login import OsLogin
from motp.modules.os_sessions import OsSessions
from motp.modules.os_units import OsUnits
from motp.modules.rows_unit import RowsUnit

from .login_system import (
    DISTROS,
    LASTLOG,
    PASSWD,
    UTMP,
    WTMP,
    LoginSystem,
    capture,
    captured_system,
    lastlog_record,
    utmp_record,
)
from .packages_system import detail_of, everything, only, render_for, text_of, through_the_contract
from .support import NOW, render_settings, write_cache
from .test_show import demo_results, posix_modes, run  # noqa: F401  (autouse fixture)

HOSTILE = b"\x1b]0;owned\x07\x1b[2J\x1b[31mevil\xe2\x80\xae\xff\xfe"
DAY = 86400


def inert(text: str) -> bool:
    return not any(mark in text for mark in ("\x1b", "\x07", "\\x1b", "\\x07", "\u202e", "\\u202e"))


# --- the record parser -----------------------------------------------------------------


def test_the_record_layouts_have_glibcs_sizes() -> None:
    assert (records.COMPAT32.utmp_size, records.COMPAT32.lastlog_size) == (384, 292)
    assert (records.WIDE.utmp_size, records.WIDE.lastlog_size) == (400, 296)
    # glibc's offsets: host at 76, the seconds of ut_tv at 340 (compat) or 344 (wide)
    rec = utmp_record(b"u", b"l", b"h", 1795600000)
    assert rec[76:77] == b"h" and struct.unpack_from("=i", rec, 340)[0] == 1795600000


@pytest.mark.parametrize(
    ("machine", "shape"),
    [
        ("x86_64", records.COMPAT32),
        ("i686", records.COMPAT32),
        ("armv7l", records.COMPAT32),
        ("aarch64", records.WIDE),
        ("s390x", records.WIDE),
        ("riscv64", None),
        ("ppc64le", None),
    ],
)
def test_the_layout_follows_the_machine(machine: str, shape: object) -> None:
    assert records.layout(machine) is shape


def test_a_wide_record_is_read_with_the_wide_layout() -> None:
    user = b"alice"
    rec = records.WIDE.utmp.pack(
        records.USER_PROCESS, 7, b"pts/2", b"ts/2", user, b"192.0.2.9", 0, 0, 0, NOW - 9, 0,
        0, 0, 0, 0, b"",
    )  # fmt: skip
    assert len(rec) == 400
    (found,) = (
        records.utmp_logins(rec * 2, NOW, records.WIDE)[:1]
        if False
        else list(records.utmp_logins(rec, NOW, records.WIDE))
    )
    assert (found.user, found.host, found.started) == ("alice", "192.0.2.9", NOW - 9)
    last = records.WIDE.lastlog.pack(NOW - 3, b"pts/1", b"198.51.100.3")
    entries = list(records.lastlog_entries([(296 * 7, last)], NOW, 0, records.WIDE))
    assert [(uid, r.host) for uid, r in entries] == [(7, "198.51.100.3")]


def test_an_unknown_machine_fails_the_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(records, "layout", lambda machine=None: None)
    with pytest.raises(ContractError):
        OsSessions().collect(LoginSystem({UTMP: b""}, now=NOW))
    with pytest.raises(ContractError):
        OsLogin().collect_users(captured_system("debian12", OsLogin.binaries))


def test_a_name_that_fills_the_field_may_be_cut_and_is_left_out() -> None:
    full = b"a" * 32  # no NUL: a longer name cut at 32 bytes
    data = utmp_record(full, b"pts/0", b"", NOW - 5) + utmp_record(b"bob", b"pts/1", b"", NOW - 4)
    assert [r.user for r in records.utmp_logins(data, NOW)] == ["bob"]


def test_a_host_cannot_fake_another_entry_in_the_admin_list() -> None:
    data = utmp_record(b"eve", b"pts/1", b"x), root (192.0.2.66", NOW - 60)
    item = only(OsSessions().collect(LoginSystem({UTMP: data}, now=NOW)))
    listed = detail_of(item, "os_sessions.users")
    assert listed.count("(") == 1 and listed.count(")") == 1 and "," not in listed


@pytest.mark.parametrize("distro", DISTROS)
def test_the_captured_utmp_holds_the_open_session(distro: str) -> None:
    c = capture(distro)
    found = list(records.utmp_logins(bytes.fromhex(c["utmp"]), c["captured"]))
    assert [(r.user, r.line, r.host) for r in found] == [("motp-cap-b", "pts/0", "127.0.0.1")]


def test_hostile_text_in_a_record_is_sanitised() -> None:
    data = utmp_record(b"alice", b"pts/1\x1b[2J", b"203.0.113.5" + HOSTILE, NOW - 60)
    (found,) = records.utmp_logins(data, NOW)
    assert inert(found.host) and inert(found.line)
    assert found.host.startswith("203.0.113.5") and "evil" in found.host


def test_records_that_are_not_logins_are_skipped() -> None:
    data = b"".join(
        (
            utmp_record(b"reboot", b"~", b"", NOW - 99, kind=2),  # a boot record
            utmp_record(b"", b"pts/2", b"", NOW - 50, kind=8),  # a logout
            utmp_record(b"-rf", b"pts/3", b"", NOW - 40),  # not a user name
            utmp_record(b"bob", b"pts/4", b"", 12),  # 1970
            utmp_record(b"bob", b"pts/5", b"", NOW + 9 * DAY),  # far ahead of the clock
            utmp_record(b"carol", b"pts/6", b"198.51.100.2", NOW - 30),
        )
    )
    assert [r.user for r in records.utmp_logins(data, NOW)] == ["carol"]


def test_a_cut_record_at_the_end_is_left_out() -> None:
    whole = utmp_record(b"dave", b"pts/0", b"", NOW - 5)
    cut = utmp_record(b"erin", b"pts/1", b"", NOW - 4)[:100]
    assert [r.user for r in records.utmp_logins(whole + cut, NOW)] == ["dave"]
    assert list(records.utmp_logins(cut, NOW)) == []


def test_lastlog_regions_must_start_on_a_record() -> None:
    rec = lastlog_record(NOW - 10, b"pts/0", b"192.0.2.8")
    assert [uid for uid, _r in records.lastlog_entries([(5 * 292, rec)], NOW, 0)] == [5]
    assert list(records.lastlog_entries([(5 * 292 + 1, rec)], NOW, 0)) == []
    assert list(records.lastlog_entries([(5 * 292, rec[:200])], NOW, 0)) == []


# --- os_sessions -----------------------------------------------------------------------


@pytest.mark.parametrize("distro", DISTROS)
def test_sessions_count_is_public_and_names_are_for_admins(distro: str) -> None:
    item = only(OsSessions().collect(captured_system(distro)))
    assert (item.value, text_of(item)) == (1, "1 session")
    assert detail_of(item, "os_sessions.users") == "motp-cap-b (127.0.0.1)"
    items = list(through_the_contract("os_sessions", [item]))
    public = everything(render_for("os_sessions", items, admin=False))
    admin = everything(render_for("os_sessions", items, admin=True))
    assert "1 session" in public and "motp-cap-b" not in public and "127.0.0.1" not in public
    assert "motp-cap-b (127.0.0.1)" in admin


def test_a_session_from_a_hostile_host_renders_inert() -> None:
    data = utmp_record(b"alice", b"pts/1", HOSTILE * 3, NOW - 60)
    item = only(OsSessions().collect(LoginSystem({UTMP: data}, now=NOW)))
    items = list(through_the_contract("os_sessions", [item]))
    assert inert(everything(render_for("os_sessions", items, admin=True)))


def test_a_huge_utmp_is_read_up_to_its_cap() -> None:
    data = utmp_record(b"frank", b"pts/9", b"", NOW - 5) * 10_000
    ctx = LoginSystem({UTMP: data}, now=NOW)
    item = only(OsSessions().collect(ctx))
    assert item.value == 4096
    assert len(child.document("os_sessions", [item])) < 4096


def test_no_sessions_is_a_zero_count() -> None:
    item = only(OsSessions().collect(LoginSystem({UTMP: b""}, now=NOW)))
    assert (item.value, text_of(item), item.detail) == (0, "0 sessions", ())


# --- os_units --------------------------------------------------------------------------


def units_system(distro: str, output: str) -> LoginSystem:
    return LoginSystem(
        {services.SYSTEMCTL: b"", services.SYSTEMD_RUNNING: b""},
        outputs={tuple(__import__("motp.modules.os_units", fromlist=["ARGV"]).ARGV): output},
        binaries=OsUnits.binaries,
    )


@pytest.mark.parametrize("distro", DISTROS)
def test_a_failed_unit_is_a_count_for_everyone_and_a_name_for_admins(distro: str) -> None:
    item = only(OsUnits().collect(units_system(distro, capture(distro)["systemctl_failed"])))
    assert (item.value, item.status, text_of(item)) == (1, Status.WARN, "1 failed unit")
    assert detail_of(item, "os_units.names") == "motp-capture-fail.service"
    items = list(through_the_contract("os_units", [item]))
    public = everything(render_for("os_units", items, admin=False))
    admin = everything(render_for("os_units", items, admin=True))
    assert "1 failed unit" in public and "motp-capture-fail" not in public
    assert "motp-capture-fail.service" in admin and "systemctl --failed" in admin


def test_no_failed_unit_says_none() -> None:
    item = only(OsUnits().collect(units_system("debian12", "")))
    assert (item.value, item.status, text_of(item), item.hint) == (0, Status.OK, "none", None)


@pytest.mark.parametrize(
    "line",
    [
        "evil\x1b[31m.service loaded failed failed boom",
        "-H.service loaded failed failed x",
        "nginx.service loaded active running x",
        "no-type loaded failed failed x",
        "short.service failed",
    ],
)
def test_output_of_another_shape_fails_the_module(line: str) -> None:
    with pytest.raises(ContractError):
        OsUnits().collect(units_system("debian12", f"ok.service loaded failed failed x\n{line}\n"))


def test_many_failed_units_are_cut_with_a_count() -> None:
    lines = "".join(f"unit-number-{n}.service loaded failed failed d\n" for n in range(500))
    item = only(OsUnits().collect(units_system("debian12", lines)))
    assert item.value == 500 and re.search(r"\+\d+$", detail_of(item, "os_units.names"))
    assert len(child.document("os_units", [item])) < 4096


def test_os_units_needs_a_running_systemd() -> None:
    assert not OsUnits().detect(LoginSystem({services.SYSTEMCTL: b""})).available
    assert OsUnits().detect(units_system("debian12", "")).available


# --- rows_unit -------------------------------------------------------------------------


def rows_config(distro: str) -> dict[str, object]:
    labels = ("Nightly job", "Gone", "Bus")
    return {"rows": [[n, lab] for n, lab in zip(capture(distro)["row_units"], labels)]}


@pytest.mark.parametrize("distro", DISTROS)
def test_unit_rows_show_each_units_state(distro: str) -> None:
    c = capture(distro)
    ctx = LoginSystem(
        {services.SYSTEMCTL: b""},
        outputs={rows_unit.argv(c["row_units"]): c["systemctl_show"]},
        binaries=RowsUnit.binaries,
        config=rows_config(distro),
    )
    items = RowsUnit().collect(ctx)
    assert [(i.key, i.status, text_of(i)) for i in items] == [
        ("rows_unit.motp-capture-fail-service", Status.CRIT, "failed"),
        ("rows_unit.motp-capture-missing-service", Status.WARN, "not found"),
        ("rows_unit.dbus-socket", Status.OK, "active (running)"),
    ]
    contract = list(through_the_contract("rows_unit", items))
    public = everything(render_for("rows_unit", contract, admin=False))
    assert "Nightly job" in public and "active (running)" in public


@pytest.mark.parametrize(
    "name", ["-H.service", "--host=x.service", ".hidden.service", "a b.service", "x.scope", ""]
)
def test_a_unit_name_that_could_be_an_option_never_reaches_systemctl(name: str) -> None:
    ctx = LoginSystem(
        {services.SYSTEMCTL: b""}, binaries=RowsUnit.binaries, config={"rows": [[name, "x"]]}
    )
    with pytest.raises(ContractError):
        RowsUnit().collect(ctx)
    assert ctx.calls == []
    assert not config.UNIT_NAME.match(name)


def test_the_argument_list_ends_the_options_before_the_names() -> None:
    argv = rows_unit.argv(["nginx.service"])
    assert argv[0] == services.SYSTEMCTL and argv[-2:] == ("--", "nginx.service")


def test_the_config_and_the_module_check_unit_names_alike() -> None:
    assert config.UNIT_NAME.pattern == services.ROW_UNIT_NAME.pattern


def test_a_short_answer_from_systemctl_fails_the_rows() -> None:
    names = ["a.service", "b.service"]
    ctx = LoginSystem(
        {services.SYSTEMCTL: b""},
        outputs={rows_unit.argv(names): "Id=a.service\nActiveState=active\n"},
        binaries=RowsUnit.binaries,
        config={"rows": [[n, n] for n in names]},
    )
    with pytest.raises(ContractError):
        RowsUnit().collect(ctx)


def test_unknown_states_and_keys_stay_unique_and_inert() -> None:
    names = ["a.service", "A.service", "c.service"]
    out = (
        "Id=a.service\nLoadState=loaded\nActiveState=\x1b[31mweird\nSubState=x\n\n"
        "Id=A.service\nLoadState=masked\nActiveState=inactive\nSubState=dead\n\n"
        "Id=c.service\nLoadState=loaded\nActiveState=activating\nSubState=\x1b]0;t\x07\n"
    )
    ctx = LoginSystem(
        {services.SYSTEMCTL: b""},
        outputs={rows_unit.argv(names): out},
        binaries=RowsUnit.binaries,
        config={"rows": [[n, f"Label {n}"] for n in names]},
    )
    items = RowsUnit().collect(ctx)
    assert [i.key for i in items] == [
        "rows_unit.a-service",
        "rows_unit.a-service-2",
        "rows_unit.c-service",
    ]
    assert [(i.status, text_of(i)) for i in items] == [
        (Status.UNKNOWN, "state unknown"),
        (Status.WARN, "masked"),
        (Status.WARN, "activating"),
    ]
    assert inert(
        everything(
            render_for("rows_unit", list(through_the_contract("rows_unit", items)), admin=True)
        )
    )


def test_rows_are_detected_only_when_configured() -> None:
    assert not RowsUnit().detect(LoginSystem({services.SYSTEMCTL: b""})).available
    ctx = LoginSystem({services.SYSTEMCTL: b""}, config={"rows": [["a.service", "A"]]})
    assert RowsUnit().detect(ctx).available


def test_the_collector_hands_the_config_rows_to_the_probe() -> None:
    from motp.collect import runner

    settings = config.Config(
        **{
            **config.defaults().__dict__,
            "unit_rows": (config.UnitRow("nginx.service", "Web server"),),
        }
    )
    assert runner.module_config("rows_unit", settings) == {
        "rows": [["nginx.service", "Web server"]]
    }
    assert runner.module_config("os_units", settings) == {}
    env = {child.CONFIG_VARIABLE: json.dumps({"rows": [["nginx.service", "Web server"]]})}
    assert child.module_config(env) == {"rows": [["nginx.service", "Web server"]]}
    assert child.module_config({}) == {}
    for bad in ("[1", "[1]", "x" * (child.MAX_CONFIG_BYTES + 1)):
        with pytest.raises(ContractError):  # the module fails instead of showing no rows
            child.module_config({child.CONFIG_VARIABLE: bad})


def test_thirty_two_long_rows_fit_the_config_limit() -> None:
    from motp.collect import runner

    name = "a" + "\\x2d" * 61 + ".service"  # 250 characters, systemd escapes
    rows = tuple(config.UnitRow(name, "\u00e4" * 40) for _ in range(32))
    settings = config.Config(**{**config.defaults().__dict__, "unit_rows": rows})
    text = json.dumps(runner.module_config("rows_unit", settings))
    assert child.module_config({child.CONFIG_VARIABLE: text})["rows"]


# --- os_login --------------------------------------------------------------------------


@pytest.mark.parametrize("distro", DISTROS)
def test_each_account_gets_its_newest_login_from_lastlog(distro: str) -> None:
    c = capture(distro)
    ctx = captured_system(distro, OsLogin.binaries)
    users = OsLogin().collect_users(ctx)
    assert sorted(u.uid for u in users) == sorted(c["users"].values())
    for user in users:
        (login,) = user.logins
        assert (login.source, login.tty) == ("127.0.0.1", "pts/0")
        assert c["captured"] - 60 < login.started <= c["captured"]
    assert ctx.calls == []  # both accounts are local: no name service call


@pytest.mark.parametrize("distro", DISTROS)
def test_the_logins_travel_in_the_document_and_never_as_items(distro: str) -> None:
    ctx = captured_system(distro, OsLogin.binaries)
    module = OsLogin()
    assert module.collect(ctx) == []
    data = child.document("os_login", [], module.collect_users(ctx))
    doc = probe.validate_builtin(data, "os_login", Visibility.ADMIN, generated=NOW)
    assert doc.items == () and doc.users is not None and len(doc.users) == 2
    assert all(u.generated == NOW for u in doc.users)


@pytest.mark.parametrize("distro", DISTROS)
def test_without_lastlog_wtmp_gives_up_to_three_logins(distro: str) -> None:
    c = capture(distro)
    ctx = captured_system(distro, OsLogin.binaries, lastlog=None)
    users = {u.uid: u for u in OsLogin().collect_users(ctx)}
    a, b = c["users"]["motp-cap-a"], c["users"]["motp-cap-b"]
    assert len(users[a].logins) == 2 and len(users[b].logins) == 2
    assert users[a].logins[0].started >= users[a].logins[1].started


def test_a_lastlog_of_another_record_size_falls_back_to_wtmp() -> None:
    ctx = captured_system("debian12", OsLogin.binaries, lastlog=(292 * 10 + 4, {}))
    assert len(OsLogin().collect_users(ctx)) == 2


def test_directory_accounts_are_asked_of_the_name_service() -> None:
    known, unknown = 1_500_001, 1_500_002
    last = {
        known: lastlog_record(NOW - 100, b"pts/3", b"192.0.2.10"),
        unknown: lastlog_record(NOW - 50, b"pts/4", b"192.0.2.11"),
    }
    argv = (os_login.GETENT, "passwd", "--", str(unknown), str(known))  # newest first
    ctx = LoginSystem(
        {PASSWD: b"root:x:0:0:root:/root:/bin/bash\n"},
        lastlog=(292 * (unknown + 1), last),
        outputs={argv: (2, f"dir-user:*:{known}:100::/home/dir-user:/bin/bash\n")},
        binaries=OsLogin.binaries,
        now=NOW,
    )
    users = OsLogin().collect_users(ctx)
    assert [u.uid for u in users] == [known]  # a uid nobody has any more gets no file
    assert ctx.calls == [argv]


def test_when_the_name_service_cannot_answer_only_local_accounts_count() -> None:
    last = {
        1000: lastlog_record(NOW - 100, b"pts/3", b""),
        2_000_000: lastlog_record(NOW - 50, b"pts/4", b""),
    }
    ctx = LoginSystem(
        {PASSWD: b"a:x:1000:1000::/home/a:/bin/sh\n"},
        lastlog=(292 * 2_000_001, last),
        binaries=OsLogin.binaries,
        now=NOW,
    )
    assert [u.uid for u in OsLogin().collect_users(ctx)] == [1000]


def test_logins_older_than_the_window_get_no_file() -> None:
    last = {
        1000: lastlog_record(NOW - (os_login.RECENT_DAYS + 1) * DAY, b"pts/0", b""),
        1001: lastlog_record(NOW - 3 * DAY, b"pts/0", b""),
    }
    ctx = LoginSystem(
        {PASSWD: b"a:x:1000:1000::/h:/bin/sh\nb:x:1001:1001::/h:/bin/sh\n"},
        lastlog=(292 * 1002, last),
        binaries=OsLogin.binaries,
        now=NOW,
    )
    assert [u.uid for u in OsLogin().collect_users(ctx)] == [1001]


def many_accounts(count: int, host: bytes = b"") -> LoginSystem:
    last = {1000 + n: lastlog_record(NOW - n, b"pts/0", host) for n in range(count)}
    passwd = "".join(f"u{n}:x:{1000 + n}:100::/h:/bin/sh\n" for n in range(count))
    return LoginSystem(
        {PASSWD: passwd.encode()},
        lastlog=(292 * (1000 + count), last),
        binaries=OsLogin.binaries,
        now=NOW,
    )


def test_at_most_the_newest_accounts_get_a_file_and_the_document_fits() -> None:
    users = OsLogin().collect_users(many_accounts(400, host="ä".encode() * 120))
    assert len(users) == os_login.MAX_USERS == probe.MAX_USERS
    assert users[0].uid == 1000  # the most recent login first
    data = child.document("os_login", [], users)
    assert len(data) <= probe.PER_USER_DOCUMENT_BYTES
    doc = probe.validate_builtin(data, "os_login", Visibility.ADMIN)
    assert doc.users is not None and 0 < len(doc.users) <= os_login.MAX_USERS
    assert doc.users[0].uid == 1000


def test_an_oversized_lastlog_fails_the_module() -> None:
    big = {n: lastlog_record(NOW - 5, b"pts/0", b"") for n in range(30_000)}
    ctx = LoginSystem(
        {PASSWD: b""}, lastlog=(292 * 30_000, big), binaries=OsLogin.binaries, now=NOW
    )
    with pytest.raises(ContractError):
        OsLogin().collect_users(ctx)


# --- a hostile host from the record to the screen --------------------------------------


UID = 4242


def test_a_record_whose_host_holds_escape_bytes_renders_inert(tmp_path: Path) -> None:
    last = {UID: lastlog_record(NOW - 7380, b"pts/0\x1b[5m", b"198.51.100.7" + HOSTILE * 8)}
    ctx = LoginSystem(
        {PASSWD: f"h:x:{UID}:{UID}::/h:/bin/sh\n".encode()},
        lastlog=(292 * (UID + 1), last),
        binaries=OsLogin.binaries,
        now=NOW,
    )
    # probe -> document -> collector -> per-user file -> show --login
    doc = probe.validate_builtin(
        child.document("os_login", [], OsLogin().collect_users(ctx)), "os_login", generated=NOW
    )
    assert doc.users is not None
    (user,) = doc.users
    folder = tmp_path / "user"
    folder.mkdir()
    (folder / f"{UID}.json").write_bytes(cache.encode_user_file(user))
    write_cache(tmp_path, demo_results(skip=("os_login",)), settings=render_settings())
    code, out = run(tmp_path, login=True, uid=UID, width=100)
    assert code == 0 and "198.51.100.7" in out and "evil" in out
    # Every escape left is one of the theme's colours (SGR); nothing from the record.
    assert all(re.fullmatch(r"\[[0-9;]*m", e) for e in re.findall(r"\S{0,12}?[A-Za-z]", out))
    for mark in ("", "]", "[2J", "[5m", "‮"):
        assert mark not in out


def test_user_logins_survive_the_file_round_trip() -> None:
    user = UserLogins(1000, NOW, (Login(NOW - 5, "192.0.2.1", "pts/0"),))
    assert cache.decode_user_file(cache.encode_user_file(user), 1000) == user


def test_os_login_shows_nothing_to_anyone() -> None:
    assert OsLogin.default_visibility is Visibility.ADMIN and OsLogin.needs_root


class Refusing(LoginSystem):
    """A system whose record files exist but cannot be read (the ownership check)."""

    def _file_size(self, path: str) -> int:
        if path in (LASTLOG, WTMP):
            raise context_error("context.error.read")
        return super()._file_size(path)


@pytest.mark.parametrize("present", [LASTLOG, WTMP])
def test_a_record_file_that_cannot_be_read_fails_the_module(present: str) -> None:
    ctx = Refusing({PASSWD: b"a:x:1000:1000::/h:/bin/sh\n", present: b""}, now=NOW)
    with pytest.raises(ContractError):  # not "no logins", which would remove every file
        OsLogin().collect_users(ctx)


def test_without_a_recent_lastlog_record_wtmp_is_read() -> None:
    c = capture("debian12")
    old = {1000: lastlog_record(c["captured"] - 400 * DAY, b"pts/0", b"")}
    ctx = captured_system("debian12", OsLogin.binaries, lastlog=(292 * 1001, old))
    assert len(OsLogin().collect_users(ctx)) == 2  # both accounts, from wtmp


def test_name_service_lookups_go_to_the_most_recent_accounts_first() -> None:
    count = 600
    last = {2_000_000 + n: lastlog_record(NOW - (count - n), b"pts/0", b"") for n in range(count)}

    class AnswersAll(LoginSystem):
        def run(self, argv: "Sequence[str]", ok_codes: "tuple[int, ...]" = (0,)) -> bytes:
            self.calls.append(tuple(argv))
            keys = list(argv)[3:]
            return "".join(f"d{k}:*:{k}:1::/h:/bin/sh\n" for k in keys).encode()

    ctx = AnswersAll(
        {PASSWD: b""}, lastlog=(292 * (2_000_000 + count), last), binaries=OsLogin.binaries, now=NOW
    )
    users = OsLogin().collect_users(ctx)
    assert users[0].uid == 2_000_000 + count - 1  # the newest login, the highest uid
    assert len(users) == os_login.MAX_USERS


def test_the_probe_cuts_an_oversized_document_in_few_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    real = strictjson.dumps

    def counting(obj: object) -> bytes:
        calls.append(1)
        return bytes(real(obj))

    monkeypatch.setattr(strictjson, "dumps", counting)
    users = [
        UserLogins(n, NOW, tuple(Login(NOW - n, "\u00e4" * 256, "t" * 32) for _ in range(3)))
        for n in range(probe.MAX_USERS)
    ]
    data = child.document("os_login", [], users)
    assert len(data) <= probe.PER_USER_DOCUMENT_BYTES and len(calls) <= 12


# --- systems without utmp (phase 14) ----------------------------------------------------


def test_a_systemd_system_without_utmp_says_sessions_are_not_recorded() -> None:
    """Debian 13 builds systemd without /run/utmp: the row says so instead of vanishing."""
    ctx = LoginSystem({"/run/systemd/system": b""}, now=NOW)
    assert OsSessions().detect(ctx).available
    item = only(list(through_the_contract("os_sessions", OsSessions().collect(ctx))))
    assert item.value is None and item.status is Status.UNKNOWN
    assert text_of(item) == "not recorded on this system"


def test_without_utmp_and_without_systemd_the_module_is_not_detected() -> None:
    assert not OsSessions().detect(LoginSystem({}, now=NOW)).available

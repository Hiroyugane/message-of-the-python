"""The security modules of phase 11: ``sec_logins``, ``sec_fail2ban``, ``sec_firewall`` and
``app_containers``, against what ``tools/capture_security_fixtures.py`` recorded in each
tier-1 image (Docker's answer is built from its API reference, Podman's was captured on
the WSL host), and against hostile input: escape sequences in names and addresses, cut
and oversized records and answers, answers of another shape."""

import json
import struct
from collections.abc import Mapping, Sequence
from typing import Any, Optional, Union

import pytest

from motp.collect import child
from motp.core import strictjson
from motp.core.model import ContractError, Item, Status, Visibility
from motp.modules import app_containers, records, rows_unit, sec_fail2ban, sec_firewall, sec_logins
from motp.modules.app_containers import AppContainers
from motp.modules.base import context_error
from motp.modules.sec_fail2ban import SecFail2ban
from motp.modules.sec_firewall import SecFirewall
from motp.modules.sec_logins import SecLogins

from .login_system import LoginSystem
from .packages_system import (
    detail_of,
    everything,
    only,
    render_for,
    text_of,
    through_the_contract,
)
from .support import FIXTURES

DISTROS = ("debian12", "ubuntu2204", "almalinux9", "fedora45")
SECURITY = FIXTURES / "security"
HOSTILE = "\x1b]0;owned\x07\x1b[2J\x1b[31mevil‮"
DAY = 86400


def capture(distro: str) -> "dict[str, Any]":
    with open(SECURITY / f"{distro}.json", encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def api(name: str) -> "list[dict[str, Any]]":
    with open(SECURITY / f"{name}-api.json", encoding="utf-8") as f:
        return json.load(f)["answer"]  # type: ignore[no-any-return]


def inert(text: str) -> bool:
    return not any(mark in text for mark in ("\x1b", "\x07", "‮", "\\u001b", "\\u202e"))


class SecuritySystem(LoginSystem):
    """Files, program output and the answers of local sockets."""

    sockets: "dict[str, Union[bytes, Exception]]"
    requests: "list[tuple[str, str, int]]"

    def __init__(
        self,
        files: Optional[Mapping[str, bytes]] = None,
        *,
        sockets: "Optional[Mapping[str, Union[bytes, Exception]]]" = None,
        outputs: Optional[Mapping[tuple[str, ...], Any]] = None,
        binaries: Sequence[str] = (),
        now: int = 0,
    ) -> None:
        super().__init__(files, outputs=outputs, binaries=binaries, now=now)
        object.__setattr__(self, "sockets", dict(sockets or {}))
        object.__setattr__(self, "requests", [])

    def _exists(self, path: str) -> bool:
        return super()._exists(path) or path in self.sockets

    def _unix_get(self, path: str, target: str, max_bytes: int, timeout: float) -> bytes:
        self.requests.append((path, target, max_bytes))
        answer = self.sockets.get(path)
        if answer is None or isinstance(answer, Exception):
            raise context_error("context.error.socket")
        if len(answer) > max_bytes:
            raise context_error("context.error.socket")
        return answer


def document(name: str, items: object) -> str:
    return child.document(name, items).decode("utf-8")  # type: ignore[arg-type]


def contract(name: str, items: "list[Item]") -> "list[Item]":
    return list(through_the_contract(name, items))


# --- sec_logins ------------------------------------------------------------------------


def logins_system(distro: str, **kw: Any) -> SecuritySystem:
    c = capture(distro)
    files = {sec_logins.BTMP: bytes.fromhex(c["btmp"]), **kw.pop("files", {})}
    return SecuritySystem(files, now=kw.pop("now", c["captured"]), **kw)


@pytest.mark.parametrize("distro", DISTROS)
def test_failed_logins_are_counted_per_attempt(distro: str) -> None:
    c = capture(distro)
    ctx = logins_system(distro)
    assert SecLogins().detect(ctx).available
    item = only(contract("sec_logins", SecLogins().collect(ctx)))
    # five attempts: two wrong passwords, two unknown names (two records each), one key-only
    assert len(bytes.fromhex(c["btmp"])) // records.UTMP_SIZE >= 7
    assert item.value == 5 and item.status is Status.OK
    assert text_of(item) == "5 in the last 24 hours"
    assert item.visibility is Visibility.PUBLIC
    assert detail_of(item, "sec_logins.sources") == "192.0.2.10 (4), 198.51.100.20 (1)"
    assert all(d.visibility is Visibility.ADMIN for d in item.detail)


@pytest.mark.parametrize("distro", DISTROS)
def test_attempted_user_names_never_leave_the_probe(distro: str) -> None:
    c = capture(distro)
    raw = bytes.fromhex(c["btmp"])
    for name in c["names"].values():
        assert name.encode() in raw  # the fixture really holds them
    out = document("sec_logins", SecLogins().collect(logins_system(distro)))
    for name in c["names"].values():
        assert name not in out


@pytest.mark.parametrize("distro", DISTROS)
def test_the_public_screen_has_the_count_and_not_the_sources(distro: str) -> None:
    items = list(through_the_contract("sec_logins", SecLogins().collect(logins_system(distro))))
    plain = everything(render_for("sec_logins", items, admin=False))
    admin = everything(render_for("sec_logins", items, admin=True))
    assert "5 in the last 24 hours" in plain
    assert "192.0.2.10" not in plain and "198.51.100.20" not in plain
    assert "192.0.2.10 (4)" in admin


def test_only_the_last_24_hours_count() -> None:
    c = capture("debian12")
    ctx = logins_system("debian12", now=c["captured"] + DAY + 60)
    assert only(SecLogins().collect(ctx)).value == 0


def _btmp(pid: int, host: bytes, started: int, addr: bytes = b"", user: bytes = b"x") -> bytes:
    words = struct.unpack("=4i", addr.ljust(16, b"\0"))
    return records.COMPAT32.utmp.pack(
        records.LOGIN_PROCESS, pid, b"ssh:notty", b"", user, host, 0, 0, 0, started, 0, *words, b""
    )


NOW = 1795600000


def test_records_of_one_process_close_in_time_are_one_attempt() -> None:
    data = (
        _btmp(100, b"192.0.2.5", NOW - 50, bytes([192, 0, 2, 5]))
        + _btmp(100, b"192.0.2.5", NOW - 49, bytes([192, 0, 2, 5]))
        + _btmp(100, b"192.0.2.5", NOW - 49 + sec_logins.SAME_ATTEMPT + 5, bytes([192, 0, 2, 5]))
        + _btmp(101, b"192.0.2.5", NOW - 40, bytes([192, 0, 2, 5]))
    )
    ctx = SecuritySystem({sec_logins.BTMP: data}, now=NOW + 1000)
    assert only(SecLogins().collect(ctx)).value == 3


def test_the_address_wins_over_a_hostile_host_name() -> None:
    data = _btmp(7, HOSTILE.encode(), NOW - 5, bytes([198, 51, 100, 9]))
    data += _btmp(8, HOSTILE.encode() + b"\xff\xfe", NOW - 4)  # no address: the name, sanitised
    data += _btmp(9, b"", NOW - 3, b"\x20\x01\x0d\xb8" + bytes(11) + b"\x09")  # 2001:db8::9
    item = only(
        contract(
            "sec_logins", SecLogins().collect(SecuritySystem({sec_logins.BTMP: data}, now=NOW))
        )
    )
    sources = detail_of(item, "sec_logins.sources")
    assert "198.51.100.9 (1)" in sources and "2001:db8::9 (1)" in sources
    assert inert(sources) and "evil" in sources


def test_a_cut_record_and_implausible_times_are_ignored() -> None:
    good = _btmp(1, b"192.0.2.1", NOW - 10, bytes([192, 0, 2, 1]))
    future = _btmp(2, b"192.0.2.2", NOW + 3 * DAY, bytes([192, 0, 2, 2]))
    ancient = _btmp(3, b"192.0.2.3", 1000, bytes([192, 0, 2, 3]))
    other_kind = records.COMPAT32.utmp.pack(
        records.USER_PROCESS - 5,
        4,
        b"",
        b"",
        b"",
        b"192.0.2.4",
        0,
        0,
        0,
        NOW - 1,
        0,
        0,
        0,
        0,
        0,
        b"",
    )
    data = future + ancient + other_kind + good + good[:100]
    ctx = SecuritySystem({sec_logins.BTMP: data}, now=NOW)
    item = only(SecLogins().collect(ctx))
    assert item.value == 1
    assert detail_of(item, "sec_logins.sources") == "192.0.2.1 (1)"


def test_a_large_btmp_is_read_backwards_and_stops_at_the_window() -> None:
    old = _btmp(1, b"192.0.2.1", NOW - 3 * DAY, bytes([192, 0, 2, 1])) * 20000
    new = b"".join(
        _btmp(1000 + i, b"192.0.2.2", NOW - 100 + i, bytes([192, 0, 2, 2])) for i in range(50)
    )
    ctx = SecuritySystem({sec_logins.BTMP: old + new}, now=NOW)
    reads: list[tuple[int, int]] = []
    original = ctx._read_slice

    def spy(path: str, offset: int, size: int) -> bytes:
        reads.append((offset, size))
        return original(path, offset, size)

    object.__setattr__(ctx, "_read_slice", spy)
    assert only(SecLogins().collect(ctx)).value == 50
    assert len(reads) == 1  # the newest part held the start of the window


def test_more_records_than_the_limit_give_a_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sec_logins, "MAX_RECORDS", 30)
    monkeypatch.setattr(sec_logins, "CHUNK_RECORDS", 7)
    data = b"".join(
        _btmp(i, b"192.0.2.2", NOW - 1000 + i, bytes([192, 0, 2, 2])) for i in range(80)
    )
    item = only(SecLogins().collect(SecuritySystem({sec_logins.BTMP: data}, now=NOW)))
    assert item.value == 30
    assert text_of(item) == "more than 30 in the last 24 hours"


def test_a_btmp_of_zeros_is_not_read_to_the_limit() -> None:
    """Security review of phase 11: ``truncate -s 1T /var/log/btmp`` by the utmp group made
    every run read 96 MiB of zeros."""
    new = _btmp(1, b"192.0.2.2", NOW - 10, bytes([192, 0, 2, 2]))
    ctx = SecuritySystem({sec_logins.BTMP: new + bytes(records.UTMP_SIZE * 200_000)}, now=NOW)
    reads: list[int] = []
    original = ctx._read_slice

    def spy(path: str, offset: int, size: int) -> bytes:
        reads.append(size)
        return original(path, offset, size)

    object.__setattr__(ctx, "_read_slice", spy)
    item = only(SecLogins().collect(ctx))
    assert len(reads) == sec_logins.MAX_EMPTY_PARTS and item.value == 0


def test_several_passwords_on_one_connection_are_one_failed_connection() -> None:
    one = b"".join(
        _btmp(300, b"192.0.2.9", NOW - 60 + 3 * i, bytes([192, 0, 2, 9])) for i in range(6)
    )
    item = only(SecLogins().collect(SecuritySystem({sec_logins.BTMP: one}, now=NOW)))
    assert item.value == 1


def test_without_btmp_the_module_does_not_apply() -> None:
    assert not SecLogins().detect(SecuritySystem({}, now=NOW)).available


# --- sec_fail2ban ----------------------------------------------------------------------


def fail2ban_system(distro: str, **kw: Any) -> SecuritySystem:
    f = capture(distro)["fail2ban"]
    outputs: dict[tuple[str, ...], Any] = {(sec_fail2ban.CLIENT, "status"): f["status"]}
    for key, text in f.items():
        if key.startswith("status "):
            outputs[(sec_fail2ban.CLIENT, "status", key.split(" ", 1)[1])] = text
    outputs.update(kw.pop("outputs", {}))
    files = {sec_fail2ban.CLIENT: b"", sec_fail2ban.SOCKET: b"", **kw.pop("files", {})}
    return SecuritySystem(files, outputs=outputs, binaries=(sec_fail2ban.CLIENT,), **kw)


@pytest.mark.parametrize("distro", DISTROS)
def test_bans_are_counted_and_listed_for_admins(distro: str) -> None:
    ctx = fail2ban_system(distro)
    assert SecFail2ban().detect(ctx).available
    item = only(contract("sec_fail2ban", SecFail2ban().collect(ctx)))
    assert item.value == 4 and item.visibility is Visibility.PUBLIC
    assert text_of(item) == "4 addresses banned"
    rows = {d.label.params[0][1]: d.value for d in item.detail}  # type: ignore[union-attr]
    assert rows == {"sshd": "192.0.2.77, 198.51.100.23, 2001:db8::7", "motp-web": "203.0.113.5"}
    assert all(d.visibility is Visibility.ADMIN for d in item.detail)
    assert sorted(ctx.calls) == sorted(
        [
            (sec_fail2ban.CLIENT, "status"),
            (sec_fail2ban.CLIENT, "status", "sshd"),
            (sec_fail2ban.CLIENT, "status", "motp-web"),
        ]
    )


@pytest.mark.parametrize("distro", DISTROS)
def test_the_public_screen_has_the_ban_count_only(distro: str) -> None:
    items = list(
        through_the_contract("sec_fail2ban", SecFail2ban().collect(fail2ban_system(distro)))
    )
    plain = everything(render_for("sec_fail2ban", items, admin=False))
    admin = everything(render_for("sec_fail2ban", items, admin=True))
    assert "4 addresses banned" in plain and "jails" not in plain
    for address in ("192.0.2.77", "198.51.100.23", "2001:db8::7", "203.0.113.5", "motp-web"):
        assert address not in plain and address in admin


def test_a_server_that_is_not_running_is_said_to_admins() -> None:
    ctx = fail2ban_system("debian12")
    del ctx.files[sec_fail2ban.SOCKET]
    item = only(SecFail2ban().collect(ctx))
    assert item.status is Status.WARN and item.visibility is Visibility.ADMIN
    assert text_of(item) == "fail2ban is installed but not running"
    assert ctx.calls == []


STATUS = "Status\n|- Number of jail:\t{n}\n`- Jail list:\t{jails}\n"
JAIL = (
    "Status for the jail: {name}\n|- Filter\n|  |- Currently failed:\t0\n"
    "|  `- File list:\t/var/log/x.log\n`- Actions\n   |- Currently banned:\t{count}\n"
    "   |- Total banned:\t{count}\n   `- Banned IP list:\t{ips}\n"
)


@pytest.mark.parametrize(
    "answer",
    [
        STATUS.format(n=1, jails="--help"),
        STATUS.format(n=1, jails="-x"),
        STATUS.format(n=1, jails="ssh d"),
        STATUS.format(n=1, jails=HOSTILE),
        STATUS.format(n=2, jails="sshd"),
        STATUS.format(n=65, jails=", ".join(f"j{i}" for i in range(65))),
        "Sorry but the jail 'x' does not exist\n",
        "",
    ],
)
def test_a_status_answer_of_another_shape_fails_before_any_jail_is_asked(answer: str) -> None:
    ctx = fail2ban_system("debian12", outputs={(sec_fail2ban.CLIENT, "status"): answer})
    with pytest.raises(ContractError):
        SecFail2ban().collect(ctx)
    assert ctx.calls == [(sec_fail2ban.CLIENT, "status")]


def test_more_jails_than_rows_still_count_every_ban() -> None:
    """Code review of phase 11: 16 jails failed the module and lost the public count."""
    names = [f"jail{i:02d}" for i in range(20)]
    outputs: dict[tuple[str, ...], Any] = {
        (sec_fail2ban.CLIENT, "status"): STATUS.format(n=20, jails=", ".join(names))
    }
    for i, name in enumerate(names):
        ips = " ".join(f"198.51.100.{n}" for n in range(i))
        outputs[(sec_fail2ban.CLIENT, "status", name)] = JAIL.format(name=name, count=i, ips=ips)
    item = only(
        contract(
            "sec_fail2ban", SecFail2ban().collect(fail2ban_system("debian12", outputs=outputs))
        )
    )
    assert item.value == sum(range(20))
    rows = [d.label.params[0][1] for d in item.detail]  # type: ignore[union-attr]
    assert len(rows) == sec_fail2ban.MAX_ROWS and rows[0] == "jail19" and "jail04" not in rows


def test_hostile_and_oversized_ban_lists() -> None:
    many = " ".join(f"198.51.100.{i}" for i in range(200))
    junk = f"{HOSTILE} 192.0.2.0/24 not-an-address 203.0.113.9/32 {many}"
    outputs = {
        (sec_fail2ban.CLIENT, "status"): STATUS.format(n=1, jails="sshd"),
        (sec_fail2ban.CLIENT, "status", "sshd"): JAIL.format(name="sshd", count=203, ips=junk),
    }
    ctx = fail2ban_system("debian12", outputs=outputs)
    item = only(contract("sec_fail2ban", SecFail2ban().collect(ctx)))
    value = str(item.detail[0].value)
    assert item.value == 203
    assert value.startswith("192.0.2.0/24, 203.0.113.9, 198.51.100.0")
    assert value.split(", ")[-1].startswith("+") and len(value) <= 120
    assert inert(value) and "evil" not in value and "not-an-address" not in value


def test_a_jail_answer_without_its_counts_fails() -> None:
    outputs = {
        (sec_fail2ban.CLIENT, "status"): STATUS.format(n=1, jails="sshd"),
        (sec_fail2ban.CLIENT, "status", "sshd"): "Status for the jail: sshd\n",
    }
    with pytest.raises(ContractError):
        SecFail2ban().collect(fail2ban_system("debian12", outputs=outputs))


def test_the_client_is_the_only_program_and_never_gets_a_changing_command() -> None:
    assert SecFail2ban.binaries == (sec_fail2ban.CLIENT,)
    ctx = fail2ban_system("almalinux9")
    SecFail2ban().collect(ctx)
    assert {call[1] for call in ctx.calls} == {"status"}


# --- sec_firewall ----------------------------------------------------------------------


def firewall_system(distro: str, **kw: Any) -> SecuritySystem:
    f = capture(distro)["firewall"]
    files = {"/usr/bin/systemctl": b"", "/run/systemd/system": b""}
    for path, entry in f["files"].items():
        if entry["user_can_read"]:  # the module runs as motp
            files[path] = entry["text"].encode()
    files.update(kw.pop("files", {}))
    outputs = {sec_firewall.ARGV: kw.pop("show", f["show"])}
    return SecuritySystem(files, outputs=outputs, binaries=SecFirewall.binaries, now=NOW)


@pytest.mark.parametrize(
    ("distro", "active", "text", "hint"),
    [
        ("debian12", True, "nftables active", None),
        ("ubuntu2204", True, "ufw active", None),  # enabled, service not restarted
        ("almalinux9", True, "firewalld active", None),  # /etc/firewalld is 0750
        ("fedora45", False, "Firewall is not active", "firewall.nftables"),
    ],
)
def test_the_firewall_state_per_image(
    distro: str, active: bool, text: str, hint: Optional[str]
) -> None:
    ctx = firewall_system(distro)
    assert SecFirewall().detect(ctx).available
    item = only(contract("sec_firewall", SecFirewall().collect(ctx)))
    assert item.value is active and text_of(item) == text
    assert (item.hint.id if item.hint else None) == hint  # type: ignore[union-attr]
    assert item.status is (Status.OK if active else Status.WARN)
    assert item.visibility is Visibility.ADMIN
    assert not everything(render_for("sec_firewall", [item], admin=False)).count("irewall")


def test_firewalld_names_its_zone_where_the_file_is_readable() -> None:
    conf = capture("almalinux9")["firewall"]["files"]["/etc/firewalld/firewalld.conf"]["text"]
    ctx = firewall_system("almalinux9", files={sec_firewall.FIREWALLD_CONF: conf.encode()})
    assert text_of(only(SecFirewall().collect(ctx))) == "firewalld active, zone public"
    hostile = f"DefaultZone={HOSTILE}\n".encode()
    ctx = firewall_system("almalinux9", files={sec_firewall.FIREWALLD_CONF: hostile})
    assert text_of(only(SecFirewall().collect(ctx))) == "firewalld active"


def test_ufw_switched_off_is_not_active_even_with_its_service_running() -> None:
    show = capture("ubuntu2204")["firewall"]["show"].replace(
        "ActiveState=inactive\nSubState=dead", "ActiveState=active\nSubState=exited", 1
    )
    ctx = firewall_system("ubuntu2204", show=show, files={sec_firewall.UFW_CONF: b"ENABLED=no\n"})
    item = only(SecFirewall().collect(ctx))
    assert item.value is False and item.hint.id == "firewall.ufw"  # type: ignore[union-attr]


def test_ufw_stopped_after_boot_is_not_active() -> None:
    """Code review of phase 11: ``systemctl stop ufw`` removes the rules, ENABLED stays."""
    show = capture("ubuntu2204")["firewall"]["show"].replace(
        "Id=ufw.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead",
        "Id=ufw.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        "InactiveEnterTimestampMonotonic=912345678",
    )
    assert "InactiveEnterTimestampMonotonic" in show
    item = only(SecFirewall().collect(firewall_system("ubuntu2204", show=show)))
    assert item.value is False and item.status is Status.WARN


def test_a_failed_unit_does_not_hide_an_active_firewall() -> None:
    show = capture("almalinux9")["firewall"]["show"].replace(
        "Id=nftables.service\nLoadState=loaded\nActiveState=inactive",
        "Id=nftables.service\nLoadState=loaded\nActiveState=failed",
    )
    assert "ActiveState=failed" in show
    item = only(SecFirewall().collect(firewall_system("almalinux9", show=show)))
    assert item.value is True and item.status is Status.OK


def test_a_firewall_unit_that_failed_is_an_error() -> None:
    show = capture("debian12")["firewall"]["show"].replace(
        "Id=nftables.service\nLoadState=loaded\nActiveState=active",
        "Id=nftables.service\nLoadState=loaded\nActiveState=failed",
    )
    item = only(SecFirewall().collect(firewall_system("debian12", show=show)))
    assert item.status is Status.CRIT and text_of(item) == "Firewall nftables failed to start"


@pytest.mark.parametrize(
    "show",
    ["", "Id=ufw.service\nActiveState=active\n", "Id=sshd.service\n\nId=x\n\nId=y\n"],
)
def test_a_show_answer_of_another_shape_fails(show: str) -> None:
    with pytest.raises(ContractError):
        SecFirewall().collect(firewall_system("debian12", show=show))


def test_nothing_installed_gives_no_hint() -> None:
    show = "\n\n".join(
        f"Id={unit}\nLoadState=not-found\nActiveState=inactive\nSubState=dead"
        for _name, unit, _hint in sec_firewall.FIREWALLS
    )
    item = only(SecFirewall().collect(firewall_system("fedora45", show=show)))
    assert item.value is False and item.hint is None


# --- app_containers --------------------------------------------------------------------


SHOW_RUNTIMES = ("docker.service", "podman.service")


def containers_system(
    docker_state: str = "active", systemd: bool = True, **sockets: "Union[bytes, Exception]"
) -> SecuritySystem:
    paths = {path: sockets[key] for key, path, *_rest in app_containers.RUNTIMES if key in sockets}
    show = "\n\n".join(
        f"Id={unit}\nLoadState=loaded\n"
        f"ActiveState={docker_state if 'docker' in unit else 'inactive'}\nSubState=x"
        for unit in SHOW_RUNTIMES
    )
    files = {"/run/systemd/system": b""} if systemd else {}
    return SecuritySystem(
        files,
        sockets=paths,
        outputs={rows_unit.argv(SHOW_RUNTIMES): show},
        binaries=AppContainers.binaries,
        now=NOW,
    )


def _body(entries: object) -> bytes:
    return json.dumps(entries).encode()


def test_docker_counts_running_unhealthy_and_stopped() -> None:
    ctx = containers_system(docker=_body(api("docker")))
    assert AppContainers().detect(ctx).available
    item = only(contract("app_containers", AppContainers().collect(ctx)))
    assert item.key == "app_containers.docker" and item.value == 2
    assert text_of(item) == "2 running (1 unhealthy), 1 restarting, 1 stopped"
    assert item.status is Status.WARN and item.visibility is Visibility.PUBLIC
    assert detail_of(item, "app_containers.docker_problems") == (
        "qzdb-backend (sha256:3e2f21a89f8c), qzloop-worker (example.com/qzimage-worker:3)"
    )
    running = detail_of(item, "app_containers.docker_running")
    assert (
        running.startswith("qzdb-backend")
        and "qzweb-frontend (example.com/qzimage-web:1.27)" in running
    )
    assert ctx.requests == [
        ("/run/docker.sock", "/containers/json?all=1", app_containers.MAX_ANSWER)
    ]


def test_podmans_captured_answer() -> None:
    ctx = containers_system(podman=_body(api("podman")))
    item = only(contract("app_containers", AppContainers().collect(ctx)))
    assert item.key == "app_containers.podman" and item.value == 2
    assert text_of(item) == "2 running, 1 stopped" and item.status is Status.OK


def test_both_runtimes_give_one_row_each() -> None:
    ctx = containers_system(docker=_body(api("docker")), podman=_body(api("podman")))
    items = AppContainers().collect(ctx)
    assert [i.key for i in items] == ["app_containers.docker", "app_containers.podman"]


def test_the_public_screen_has_counts_and_no_names_or_images() -> None:
    ctx = containers_system(docker=_body(api("docker")), podman=_body(api("podman")))
    items = list(through_the_contract("app_containers", AppContainers().collect(ctx)))
    plain = everything(render_for("app_containers", items, admin=False))
    admin = everything(render_for("app_containers", items, admin=True))
    assert "2 running (1 unhealthy), 1 restarting, 1 stopped" in plain
    for word in ("qzweb-frontend", "qzdb-backend", "qzloop-worker", "qzimage", "debian:12"):
        assert word not in plain
    assert "qzweb-frontend" in admin and "qzimage-web" in admin


def test_hostile_names_and_images_are_inert() -> None:
    entries = [
        {"Names": [f"/{HOSTILE}web"], "Image": HOSTILE + "img", "State": "running",
         "Status": "Up 1 minute (unhealthy)"},
        {"Names": ["/" + "a" * 5000], "Image": "b" * 5000, "State": "running", "Status": "Up"},
        {"Names": "not-a-list", "Image": 7, "State": "running"},
    ]  # fmt: skip
    ctx = containers_system(docker=_body(entries))
    item = only(contract("app_containers", AppContainers().collect(ctx)))
    out = document("app_containers", [item])
    assert inert(out) and "evil" in out
    assert len(str(item.detail[-1].value)) <= 120
    assert item.value == 3


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b'[{"Names": ["/x"]}]',
        b'[{"State": 1}]',
        b"[1, 2]",
        b"not json",
        b'[{"State": "running", "State": "exited"}]',
        b"[" * 100 + b"]" * 100,
        b"",
    ],
)
def test_an_answer_of_another_shape_fails(body: bytes) -> None:
    with pytest.raises(ContractError):
        AppContainers().collect(containers_system(docker=body))


def test_a_runtime_that_does_not_answer_fails_the_module() -> None:
    ctx = containers_system(docker=OSError("never answers"))
    with pytest.raises(ContractError):
        AppContainers().collect(ctx)


def test_an_oversized_answer_fails() -> None:
    ctx = containers_system(docker=b" " * (app_containers.MAX_ANSWER + 1))
    with pytest.raises(ContractError):
        AppContainers().collect(ctx)


def test_a_stopped_docker_is_never_woken_by_its_socket() -> None:
    """Security review of phase 11: systemd keeps docker.sock open after ``systemctl stop
    docker``; a connection would start Docker and its containers again."""
    ctx = containers_system(docker_state="inactive", docker=_body(api("docker")))
    item = only(AppContainers().collect(ctx))
    assert ctx.requests == []
    assert item.status is Status.UNKNOWN and item.visibility is Visibility.ADMIN
    assert text_of(item) == "service stopped"


def test_without_systemd_the_socket_is_asked_directly() -> None:
    ctx = containers_system(docker_state="inactive", systemd=False, docker=_body(api("docker")))
    assert only(AppContainers().collect(ctx)).value == 2
    assert [r[0] for r in ctx.requests] == ["/run/docker.sock"]


def test_podman_is_asked_through_socket_activation() -> None:
    ctx = containers_system(podman=_body(api("podman")))  # podman.service inactive
    assert only(AppContainers().collect(ctx)).key == "app_containers.podman"


def test_one_runtime_that_does_not_answer_leaves_the_other() -> None:
    """Code review of phase 11: Podman's silence hid Docker's row."""
    ctx = containers_system(docker=_body(api("docker")), podman=OSError("never answers"))
    docker, podman = AppContainers().collect(ctx)
    assert docker.value == 2 and podman.status is Status.WARN
    assert text_of(podman) == "the runtime did not answer"
    assert podman.visibility is Visibility.ADMIN


def test_without_a_socket_the_module_does_not_apply() -> None:
    assert not AppContainers().detect(containers_system()).available


def test_the_request_is_fixed() -> None:
    assert app_containers.TARGET == "/containers/json?all=1"
    assert AppContainers.binaries == ("/usr/bin/systemctl",)


def test_the_module_document_passes_the_strict_reader() -> None:
    ctx = containers_system(docker=_body(api("docker")))
    raw = child.document("app_containers", AppContainers().collect(ctx))
    assert isinstance(strictjson.loads(raw, max_bytes=65536, max_depth=8), dict)


# --- systems that no longer keep btmp (phase 14) ----------------------------------------


def test_an_empty_btmp_without_utmp_says_not_recorded_instead_of_zero() -> None:
    """Debian 13: sshd writes no btmp and there is no /run/utmp; "0" would be a lie."""
    ctx = SecuritySystem({sec_logins.BTMP: b""}, now=1_700_000_000)
    assert SecLogins().detect(ctx).available
    item = only(contract("sec_logins", SecLogins().collect(ctx)))
    assert item.value is None and item.status is Status.UNKNOWN
    assert text_of(item) == "not recorded on this system"
    plain = everything(render_for("sec_logins", [item], admin=False))
    assert "not recorded on this system" in plain and "0 in the last" not in plain


def test_an_empty_btmp_with_utmp_is_still_a_count_of_zero() -> None:
    ctx = SecuritySystem({sec_logins.BTMP: b"", sec_logins.UTMP: b""}, now=1_700_000_000)
    item = only(contract("sec_logins", SecLogins().collect(ctx)))
    assert item.value == 0 and text_of(item) == "0 in the last 24 hours"


@pytest.mark.parametrize("distro", DISTROS)
def test_a_btmp_with_records_is_counted_without_utmp(distro: str) -> None:
    item = only(contract("sec_logins", SecLogins().collect(logins_system(distro))))
    assert item.value == 5


def test_a_systemd_system_without_btmp_and_utmp_says_not_recorded() -> None:
    """Code review of phase 14: a Debian 13 install may have no btmp file at all; the row
    must not vanish then."""
    ctx = SecuritySystem({"/run/systemd/system": b""}, now=1_700_000_000)
    assert SecLogins().detect(ctx).available
    item = only(contract("sec_logins", SecLogins().collect(ctx)))
    assert text_of(item) == "not recorded on this system"


def test_without_btmp_utmp_or_systemd_the_module_is_not_detected() -> None:
    assert not SecLogins().detect(SecuritySystem({}, now=1_700_000_000)).available

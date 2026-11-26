"""``os_autoupdates``: whether updates get installed without a person (5.4: admin only)."""

from typing import Optional

import pytest

from motp.core import hints
from motp.core.model import ContractError, Item, Status, Visibility
from motp.modules import os_autoupdates
from motp.modules.os_autoupdates import OsAutoupdates
from motp.render.layout import render
from motp.render.theme import UNICODE, ColorLevel, themed

from .packages_system import (
    APT_DISTROS,
    alerts,
    captured,
    hint_of,
    only,
    render_for,
    system,
    text_of,
    through_the_contract,
)

# --- os_autoupdates ------------------------------------------------------------------------

APT_WANTED = "/etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer"
APT_LISTS_TIMER = "/etc/systemd/system/timers.target.wants/apt-daily.timer"
APT_BOTH = {APT_WANTED: "[Timer]\n", APT_LISTS_TIMER: "[Timer]\n"}
SYSTEMD = {"/run/systemd/system/units": ""}


def auto(
    distro: str, files: dict[str, str], periodic: Optional[str] = None
) -> "tuple[bool, str, str]":
    """(on, the text, the hint id) the module reports."""
    outputs = {}
    if periodic is not None:
        outputs[os_autoupdates.APT_CONFIG_ARGV] = captured(distro, periodic)
    item = only(OsAutoupdates().collect(system(distro, OsAutoupdates, files, outputs)))
    assert item.visibility is Visibility.ADMIN
    assert item.status is (Status.OK if item.value else Status.WARN)
    through_the_contract("os_autoupdates", [item])
    return bool(item.value), text_of(item), hint_of(item)


@pytest.mark.parametrize("distro", APT_DISTROS)
def test_apt_without_unattended_upgrades(distro: str) -> None:
    assert auto(distro, {}) == (
        False,
        "Automatic updates are not installed",
        "autoupdates.install",
    )


def test_debian_with_unattended_upgrades() -> None:
    installed = {os_autoupdates.UNATTENDED: "", **APT_BOTH, **SYSTEMD}
    assert auto("debian12", installed, "apt_periodic_on.txt")[:2] == (True, "on")
    assert auto("debian12", installed, "apt_periodic_unset.txt") == (
        False,
        "Automatic updates are off",
        "autoupdates.enable",
    )


def test_ubuntu_container_has_the_periodic_run_switched_off() -> None:
    """The captured image sets ``APT::Periodic::Enable "0"``."""
    installed = {os_autoupdates.UNATTENDED: "", **APT_BOTH, **SYSTEMD}
    assert auto("ubuntu2204", installed, "apt_periodic_on.txt")[0] is False
    settings = os_autoupdates.parse_apt_periodic(captured("ubuntu2204", "apt_periodic_on.txt"))
    del settings["Enable"]
    assert os_autoupdates.apt_periodic_on(settings)


def test_apt_needs_its_timers_on_systemd() -> None:
    installed = {os_autoupdates.UNATTENDED: "", **SYSTEMD}
    assert auto("debian12", installed, "apt_periodic_on.txt") == (
        False,
        "Automatic updates are off",
        "autoupdates.timer",
    )
    del installed["/run/systemd/system/units"]  # without systemd, cron runs it
    assert auto("debian12", installed, "apt_periodic_on.txt")[0] is True


@pytest.mark.parametrize(
    ("value", "on"), [("1", True), ("7", True), ("always", True), ("1d", True), ("0", False),
                      ("", False), ("no", False), ("-1", False)],
)  # fmt: skip
def test_apt_intervals(value: str, on: bool) -> None:
    settings = {"Update-Package-Lists": "1", "Unattended-Upgrade": value}
    assert os_autoupdates.apt_periodic_on(settings) is on


def test_malformed_apt_config_output_is_rejected() -> None:
    files = {os_autoupdates.UNATTENDED: ""}
    outputs = {os_autoupdates.APT_CONFIG_ARGV: "\x1b[31mE: broken\n"}
    with pytest.raises(ContractError):
        OsAutoupdates().collect(system("debian12", OsAutoupdates, files, outputs))


def wanted(*timers: str) -> dict[str, str]:
    return {f"/etc/systemd/system/timers.target.wants/{t}": "[Timer]\n" for t in timers}


def dnf4_files(conf: Optional[str] = None) -> dict[str, str]:
    stock = captured("almalinux9", "conf_etc_dnf_automatic.conf")
    return {
        os_autoupdates.DNF4_UNIT: "[Timer]\n",
        "/etc/dnf/automatic.conf": stock if conf is None else conf,
    }


def test_dnf4_not_installed_and_off() -> None:
    assert auto("almalinux9", {}) == (
        False,
        "Automatic updates are not installed",
        "autoupdates.install",
    )
    assert auto("almalinux9", dnf4_files()) == (
        False,
        "Automatic updates are off",
        "autoupdates.enable",
    )


def test_dnf4_timers_decide() -> None:
    """The captured image enabled the install timer; its config says apply_updates = no."""
    enabled = captured("almalinux9", "timers_wanted.txt").split()
    assert "dnf-automatic-install.timer" in enabled
    assert auto("almalinux9", {**dnf4_files(), **wanted(*enabled)})[:2] == (True, "on")
    download = (False, "Automatic updates only download", "autoupdates.enable")
    for timer in ("dnf-automatic.timer", *os_autoupdates.DNF4_FETCH):
        assert auto("almalinux9", {**dnf4_files(), **wanted(timer)}) == download, timer
    applying = dnf4_files("[commands]\napply_updates = yes\n")
    assert auto("almalinux9", {**applying, **wanted("dnf-automatic.timer")})[0] is True
    assert auto("almalinux9", {**applying, **wanted(os_autoupdates.DNF4_FETCH[0])})[0] is False


def dnf5_files(**extra: str) -> dict[str, str]:
    stock = captured("fedora45", "conf_usr_share_dnf5_dnf5-plugins_automatic.conf")
    return {
        os_autoupdates.DNF5_UNIT: "[Timer]\n",
        "/usr/share/dnf5/dnf5-plugins/automatic.conf": stock,
        **extra,
    }


def test_dnf5_needs_the_timer_and_apply_updates() -> None:
    enabled = captured("fedora45", "timers_wanted.txt").split()
    assert "dnf5-automatic.timer" in enabled
    assert auto("fedora45", dnf5_files()) == (
        False,
        "Automatic updates are off",
        "autoupdates.enable_dnf5",
    )
    stock = {**dnf5_files(), **wanted(*enabled)}
    assert auto("fedora45", stock)[1:] == ("Set apply_updates = yes", "autoupdates.apply_dnf5")
    local = {"/etc/dnf/automatic.conf": "[commands]\napply_updates = True\n"}
    assert auto("fedora45", {**stock, **local})[0] is True
    # A drop-in comes last and wins.
    dropin = {"/etc/dnf/automatic.conf.d/99-off.conf": "[commands]\napply_updates = no\n"}
    assert auto("fedora45", {**stock, **local, **dropin})[0] is False


def test_apply_updates_is_read_from_the_commands_section_only() -> None:
    assert os_autoupdates.apply_updates("[emitters]\napply_updates = yes\n") is None
    assert os_autoupdates.apply_updates("# apply_updates = yes\n[commands]\n") is None
    assert os_autoupdates.apply_updates("[commands]\napply_updates = maybe\n") is None
    assert os_autoupdates.apply_updates("[commands]\n apply_updates=1\n") is True
    assert os_autoupdates.apply_updates("\x1b[commands]\napply_updates = yes\n") is None


def test_only_admins_see_that_updates_are_off() -> None:
    item = only(OsAutoupdates().collect(system("debian12", OsAutoupdates)))
    assert alerts(render_for("os_autoupdates", [item], admin=False)) == []
    assert render_for("os_autoupdates", [item], admin=False).sections == ()
    shown = alerts(render_for("os_autoupdates", [item], admin=True))
    assert [(a.text, a.command) for a in shown] == [
        ("Automatic updates are not installed", "sudo apt install unattended-upgrades")
    ]


# --- review: the hint has to fix what is wrong ------------------------------------------------


def test_apt_needs_the_timer_that_refreshes_the_lists_too() -> None:
    """Without apt-daily.timer unattended-upgrade works from lists that never change."""
    installed = {os_autoupdates.UNATTENDED: "", APT_WANTED: "[Timer]\n", **SYSTEMD}
    assert auto("debian12", installed, "apt_periodic_on.txt") == (
        False,
        "Automatic updates are off",
        "autoupdates.timer",
    )
    found = hints.lookup("autoupdates.timer", "apt")
    assert found is not None and found[1] is not None
    assert "apt-daily.timer" in found[1] and "apt-daily-upgrade.timer" in found[1]


@pytest.mark.parametrize("timer", ["apt-daily.timer", "apt-daily-upgrade.timer"])
def test_a_masked_apt_timer_has_to_be_unmasked(timer: str) -> None:
    """systemctl refuses to enable a masked unit."""
    installed = {os_autoupdates.UNATTENDED: "", **APT_BOTH, **SYSTEMD}
    installed[f"/etc/systemd/system/{timer}"] = ""
    assert auto("debian12", installed, "apt_periodic_on.txt")[2] == "autoupdates.unmask"


def test_periodic_switched_off_is_not_fixed_by_reconfiguring() -> None:
    """dpkg-reconfigure leaves another file's APT::Periodic::Enable "0" in place."""
    installed = {os_autoupdates.UNATTENDED: "", **APT_BOTH, **SYSTEMD}
    assert auto("ubuntu2204", installed, "apt_periodic_on.txt") == (
        False,
        "APT::Periodic::Enable is 0",
        "autoupdates.periodic",
    )


def test_a_masked_dnf_timer_has_to_be_unmasked() -> None:
    masked = {"/etc/systemd/system/dnf-automatic-install.timer": ""}
    assert auto("almalinux9", {**dnf4_files(), **masked})[2] == "autoupdates.unmask"
    masked = {"/etc/systemd/system/dnf5-automatic.timer": ""}
    assert auto("fedora45", {**dnf5_files(), **masked})[2] == "autoupdates.unmask_dnf5"


def screen_80(items: "list[Item]", manager: str) -> str:
    shown = render_for("os_autoupdates", items, admin=True, manager=manager)
    return "\n".join(render(shown, 80, themed(UNICODE, ColorLevel.OFF)))


@pytest.mark.parametrize(
    ("distro", "files", "periodic", "words", "command"),
    [
        (
            "fedora45",
            {**dnf5_files(), **wanted("dnf5-automatic.timer")},
            None,
            "apply_updates = yes",
            "sudoedit /etc/dnf/automatic.conf",
        ),
        (
            "ubuntu2204",
            {os_autoupdates.UNATTENDED: "", **APT_BOTH, **SYSTEMD},
            "apt_periodic_on.txt",
            "APT::Periodic::Enable is 0",
            "grep -r APT::Periodic::Enable /etc/apt/apt.conf.d",
        ),
    ],
)
def test_an_edit_the_command_cannot_make_is_named_on_screen(
    distro: str, files: dict[str, str], periodic: Optional[str], words: str, command: str
) -> None:
    """An alert with a command shows no hint sentence, so what has to be edited must be
    in the row's own text. Enabling dnf 5's timer alone never installs anything."""
    outputs = {}
    if periodic is not None:
        outputs[os_autoupdates.APT_CONFIG_ARGV] = captured(distro, periodic)
    items = OsAutoupdates().collect(system(distro, OsAutoupdates, files, outputs))
    shown = screen_80(items, "dnf" if distro == "fedora45" else "apt")
    assert words in shown, shown
    assert command in shown, shown

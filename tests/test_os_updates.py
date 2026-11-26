"""``os_updates``: pending and security updates from local state (blueprint D28, 5.4)."""

import posixpath

import pytest

from motp.collect import child
from motp.core import cache
from motp.core.model import ContractError, ModuleResult, Status, Visibility
from motp.modules import os_updates, packages
from motp.modules.os_updates import OsUpdates, parse_apt, parse_dnf

from .packages_system import (
    ALL_DISTROS,
    APT_DISTROS,
    DAY,
    System,
    alerts,
    base_files,
    captured,
    detail_of,
    everything,
    hint_of,
    only,
    render_for,
    system,
    text_of,
    through_the_contract,
)
from .support import NOW

# Counted from the captured files with grep, not with the parser under test.
PENDING = {"debian12": (23, 8), "ubuntu2204": (22, 17), "almalinux9": (5, 5), "fedora45": (21, 13)}


def update_outputs(distro: str) -> dict[tuple[str, ...], str]:
    if distro in APT_DISTROS:
        return {os_updates.APT_ARGV: captured(distro, "apt_upgrade.txt")}
    dnf5 = distro == "fedora45"
    argv = os_updates.dnf5_argv(System.SCRATCH) if dnf5 else os_updates.DNF4_ARGV
    return {
        argv: captured(distro, "dnf_check.txt"),
        (*argv, "--security"): captured(distro, "dnf_check_security.txt"),
    }


# --- os_updates ---------------------------------------------------------------------------


@pytest.mark.parametrize("distro", ALL_DISTROS)
def test_updates_per_distribution(distro: str) -> None:
    ctx = system(distro, OsUpdates, outputs=update_outputs(distro))
    item = only(OsUpdates().collect(ctx))
    total, security = PENDING[distro]
    assert (item.key, item.value, item.status) == ("os_updates.pending", total, Status.WARN)
    assert text_of(item) == f"{total} updates, {security} security"
    assert hint_of(item) == "updates.security"
    assert item.visibility is Visibility.PUBLIC
    checked = only(list(through_the_contract("os_updates", [item])))
    assert [d.visibility for d in checked.detail] == [Visibility.ADMIN]
    assert detail_of(checked, "os_updates.packages")


def test_security_names_come_first() -> None:
    ctx = system("fedora45", OsUpdates, outputs=update_outputs("fedora45"))
    listed = detail_of(only(OsUpdates().collect(ctx)), "os_updates.packages")
    assert listed.startswith("curl, dnf5, dnf5-plugins, libcurl, libdnf5")
    assert "vim-data" not in listed and listed.split(", ")[-1].startswith("+")
    assert len(listed) <= 120 and ".x86_64" not in listed


def test_the_apt_parser_tells_security_from_other_updates() -> None:
    found = {u.name: u.security for u in parse_apt(captured("debian12", "apt_upgrade.txt"))[0]}
    assert found["libssl3"] is True  # Debian-Security
    assert found["base-files"] is False
    assert found["libgnutls30"] is True  # one of two origins is the security suite
    found = {u.name: u.security for u in parse_apt(captured("ubuntu2204", "apt_upgrade.txt"))[0]}
    assert found["bash"] is True and found["e2fsprogs"] is False


def test_new_dependencies_are_not_counted_as_updates() -> None:
    text = (
        "Inst libnew (1.0 Debian:12/stable [amd64])\n"
        "Inst tool [0.9] (1.0 Debian:12/stable [amd64]) []\n"
        "1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
    )
    updates, held = parse_apt(text)
    assert ([u.name for u in updates], held) == (["tool"], 0)


@pytest.mark.parametrize("distro", APT_DISTROS)
def test_nothing_pending_is_said_so(distro: str) -> None:
    outputs = {os_updates.APT_ARGV: captured(distro, "apt_upgrade_none.txt")}
    item = only(OsUpdates().collect(system(distro, OsUpdates, outputs=outputs)))
    assert (item.value, item.status, item.detail) == (0, Status.OK, ())
    assert text_of(item) == "none pending"
    assert alerts(render_for("os_updates", [item], admin=True)) == []


def test_updates_without_security_do_not_ask_for_attention() -> None:
    outputs: dict[tuple[str, ...], str] = {}
    outputs[os_updates.DNF4_ARGV] = captured("almalinux9", "dnf_check.txt")
    security = (*os_updates.DNF4_ARGV, "--security")
    outputs[security] = ""
    item = only(OsUpdates().collect(system("almalinux9", OsUpdates, outputs=outputs)))
    assert (item.value, item.status, text_of(item)) == (5, Status.OK, "5 updates")
    assert alerts(render_for("os_updates", [item], admin=True, manager="dnf")) == []


def test_dnf_asks_for_security_only_when_something_is_pending() -> None:
    ctx = system("almalinux9", OsUpdates, outputs={os_updates.DNF4_ARGV: ""})
    assert only(OsUpdates().collect(ctx)).value == 0
    assert ctx.calls == [os_updates.DNF4_ARGV]


@pytest.mark.parametrize(("distro", "manager"), [("debian12", "apt"), ("fedora45", "dnf")])
def test_public_cache_has_counts_and_no_package_name(distro: str, manager: str) -> None:
    ctx = system(distro, OsUpdates, outputs=update_outputs(distro))
    items = through_the_contract("os_updates", OsUpdates().collect(ctx))
    result = ModuleResult(collected=NOW, interval=900, max_age=DAY, items=items)
    public = cache.encode_tier_file(cache.PUBLIC, NOW, {"os_updates": result}, 0)
    admin = cache.encode_tier_file(cache.ADMIN, NOW, {"os_updates": result}, 0)
    for name in ("libgnutls30", "libssl3", "libcurl", "os_updates.packages"):
        assert name.encode() not in public
    assert b"os_updates.packages" in admin
    assert b'"value":%d' % PENDING[distro][0] in public.replace(b": ", b":")
    # The screen of a user without admin rights: the counts, and no name.
    plain = everything(render_for("os_updates", list(items), admin=False, manager=manager))
    assert f"{PENDING[distro][0]} updates" in plain and "libcurl" not in plain
    shown = render_for("os_updates", list(items), admin=True, manager=manager)
    assert "Packages" in everything(shown)
    assert [a.command for a in alerts(shown)] == [
        "sudo apt upgrade" if manager == "apt" else "sudo dnf upgrade --security"
    ]


@pytest.mark.parametrize("distro", ALL_DISTROS)
def test_without_package_lists_the_count_is_unknown(distro: str) -> None:
    """apt would report "0 upgraded" here, which would read as "up to date"."""
    files = {k: v for k, v in base_files(distro).items() if not k.startswith("/var/")}
    if distro in APT_DISTROS:
        files["/var/lib/apt/lists/lock"] = ""
    ctx = System(files, binaries=OsUpdates.binaries)
    item = only(OsUpdates().collect(ctx))
    assert (item.value, item.status) == (None, Status.UNKNOWN)
    assert text_of(item) == "unknown, no package lists yet"
    assert ctx.calls == []
    through_the_contract("os_updates", [item])


@pytest.mark.parametrize(
    ("distro", "mark"),
    [
        ("debian12", "/var/lib/apt/lists/partial"),
        ("almalinux9", "/var/cache/dnf/baseos-09b2e93483836b7c/repodata/repomd.xml"),
        ("fedora45", "/var/cache/libdnf5/updates-6f655cd2c39e9765"),
    ],
)
def test_old_package_lists_show_their_age(distro: str, mark: str) -> None:
    """D28: if the data is old, MOTP shows its age; the newest refresh counts."""
    old = NOW - 40 * DAY
    marks = [mark]
    files = base_files(distro)
    if distro in APT_DISTROS:
        marks += list(os_updates.APT_REFRESH_MARKS)
        files["/var/lib/apt/lists/partial/.keep"] = ""
    else:
        marks += [k for k in files if k.endswith("repomd.xml")]
        marks += [posixpath.dirname(posixpath.dirname(k)) for k in marks]
    mtimes = dict.fromkeys(marks, old)
    ctx = system(distro, OsUpdates, files=files, outputs=update_outputs(distro), mtimes=mtimes)
    item = only(OsUpdates().collect(ctx))
    age = item.detail[-1]
    assert (age.key, age.value, age.visibility) == ("os_updates.lists", old, Visibility.PUBLIC)
    shown = render_for("os_updates", list(through_the_contract("os_updates", [item])), admin=False)
    assert "40 days" in everything(shown)
    mtimes[mark] = NOW - DAY  # one recent refresh
    ctx = system(distro, OsUpdates, files=files, outputs=update_outputs(distro), mtimes=mtimes)
    assert "os_updates.lists" not in [d.key for d in only(OsUpdates().collect(ctx)).detail]


def test_dnf4_entries_may_wrap_and_obsoletes_are_not_updates() -> None:
    text = (
        "\n"
        "a-very-long-package-name-that-dnf-wraps.noarch\n"
        "                                    1:2.0-3.el9                  appstream\n"
        "bash.x86_64                         5.1.8-9.el9                  baseos\n"
        "kernel.x86_64                       5.14.0-1.el9                 baseos\n"
        "kernel.x86_64                       5.14.0-2.el9                 baseos\n"
        "Security: kernel-core-5.14.0-2.el9.x86_64 is an installed security update\n"
        "Obsoleting Packages\n"
        "grub2-tools.x86_64                  1:2.06-1.el9                 baseos\n"
        "    grub2-tools.x86_64              1:2.06-0.el9                 @baseos\n"
    )
    assert parse_dnf(text) == [
        "a-very-long-package-name-that-dnf-wraps.noarch",
        "bash.x86_64",
        "kernel.x86_64",
    ]


APT_END = "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
APT_LINE = "Inst tool [0.9] (1.0 Debian:12/stable [amd64])\n"


@pytest.mark.parametrize(
    "text",
    [
        "",
        APT_LINE,  # no summary: cut output
        APT_END,  # the summary names an update that is not listed
        APT_LINE + APT_LINE + APT_END,
        "Inst \x1b[31mevil [0.9] (1.0 Debian:12/stable [amd64])\n" + APT_END,
        "Inst ev\x1b]0;x\x07il [0.9] (1.0 Debian:12/stable [amd64])\n" + APT_END,
        "Inst tool [0.9]\n" + APT_END,
        "Inst tool [0.9] (1.0 " + "x" * 5000 + " [amd64])\n" + APT_END,
        "Inst " + "n" * 200 + " [0.9] (1.0 Debian:12/stable [amd64])\n" + APT_END,
        "\x00\x01\x02" * 1000,
    ],
)
def test_malformed_apt_output_is_rejected(text: str) -> None:
    ctx = system("debian12", OsUpdates, outputs={os_updates.APT_ARGV: text})
    with pytest.raises(ContractError) as caught:
        OsUpdates().collect(ctx)
    assert caught.value.message.id == "module.error.parse"


@pytest.mark.parametrize(
    "text",
    [
        "Error: something went wrong with the repository today\n",
        "bash.x86_64 5.1.8-9.el9\n",  # cut: two fields left over
        "\x1b[31mevil.x86_64 1.0-1 baseos\n",
        "evil.x86_64 1.0-1 base\x1bos\n",
        "noarch-missing 1.0-1 baseos\n",
        "pkg.x86_64 version-without-digits!! baseos\n",
        "x" * 5000 + "\n",
        "a.noarch 1-1 r b.noarch 1-1 r\n",
    ],
)
def test_malformed_dnf_output_is_rejected(text: str) -> None:
    ctx = system("almalinux9", OsUpdates, outputs={os_updates.DNF4_ARGV: text})
    with pytest.raises(ContractError):
        OsUpdates().collect(ctx)


def test_thousands_of_updates_stay_within_the_document() -> None:
    lines = [f"Inst lib{n} [1] (2 Debian-Security:12/stable-security [amd64])" for n in range(5000)]
    lines.append("5000 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
    ctx = system("debian12", OsUpdates, outputs={os_updates.APT_ARGV: "\n".join(lines)})
    items = OsUpdates().collect(ctx)
    assert len(child.document("os_updates", items)) < 4096
    assert only(items).value == 5000
    listed = detail_of(only(items), "os_updates.packages")
    assert len(listed) <= 120 and listed.endswith(f"+{5000 - listed.count(', ')}")


def test_a_failed_program_fails_the_module() -> None:
    with pytest.raises(ContractError) as caught:
        OsUpdates().collect(system("debian12", OsUpdates, outputs={}))
    assert caught.value.message.id == "context.error.run_failed"


# --- review: when security updates cannot be told apart ------------------------------------

RASPBIAN = (
    "Inst libssl3 [3.0.15-1~deb12u1] (3.0.17-1~deb12u2 Raspbian:12/stable [armhf])\n"
    "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
)


def test_without_a_security_source_every_update_may_be_one() -> None:
    """32-bit Raspberry Pi OS ships security fixes in its main archive; a Debian with no
    security source configured looks the same. "1 update" without a warning would hide
    a security fix."""
    files = {k: v for k, v in base_files("debian12").items() if not k.startswith("/var/")}
    files["/var/lib/apt/lists/raspbian.example.com_raspbian_dists_bookworm_main_Packages"] = ""
    files[packages.APT_GET] = ""
    ctx = System(files, outputs={os_updates.APT_ARGV: RASPBIAN}, binaries=OsUpdates.binaries)
    item = only(OsUpdates().collect(ctx))
    assert (item.value, item.status) == (1, Status.WARN)
    assert text_of(item) == "1 update, may include security fixes"
    assert hint_of(item) == "updates.install"
    through_the_contract("os_updates", [item])


def test_dnf_without_advisory_data_cannot_tell_either() -> None:
    files = {k: v for k, v in base_files("almalinux9").items() if "updateinfo" not in k}
    outputs: dict[tuple[str, ...], str] = {}
    outputs[os_updates.DNF4_ARGV] = captured("almalinux9", "dnf_check.txt")
    security = (*os_updates.DNF4_ARGV, "--security")
    outputs[security] = ""
    ctx = System(files, outputs=outputs, binaries=OsUpdates.binaries)
    item = only(OsUpdates().collect(ctx))
    assert (item.value, item.status) == (5, Status.WARN)
    assert text_of(item) == "5 updates, may include security fixes"


def test_nothing_pending_needs_no_security_source() -> None:
    files = {packages.APT_GET: "", "/var/lib/apt/lists/x_dists_stable_main_Packages": ""}
    empty = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
    ctx = System(files, outputs={os_updates.APT_ARGV: empty}, binaries=OsUpdates.binaries)
    item = only(OsUpdates().collect(ctx))
    assert (item.status, text_of(item)) == (Status.OK, "none pending")


# --- review: packages apt holds back --------------------------------------------------------


def test_held_back_packages_are_not_called_none_pending() -> None:
    text = "0 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.\n"
    item = only(
        OsUpdates().collect(system("debian12", OsUpdates, outputs={os_updates.APT_ARGV: text}))
    )
    assert (item.value, item.status, text_of(item)) == (0, Status.OK, "2 updates held back")
    through_the_contract("os_updates", [item])


def test_held_back_packages_get_a_row_beside_the_pending_ones() -> None:
    text = (
        "Inst tool [0.9] (1.0 Debian:12/stable [amd64])\n"
        "1 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n"
    )
    item = only(
        OsUpdates().collect(system("debian12", OsUpdates, outputs={os_updates.APT_ARGV: text}))
    )
    held = next(d for d in item.detail if d.key == "os_updates.held")
    assert (item.value, held.value, held.visibility) == (1, 3, Visibility.PUBLIC)


# --- review: dnf 5's log directory ------------------------------------------------------------


def test_dnf5_logs_into_a_directory_of_its_own() -> None:
    """A fixed name below /var/tmp could be taken by any user where there is no sandbox."""
    ctx = system("fedora45", OsUpdates, outputs=update_outputs("fedora45"))
    OsUpdates().collect(ctx)
    logs = [a for call in ctx.calls for a in call if a.startswith("--setopt=logdir=")]
    assert logs == [f"--setopt=logdir={System.SCRATCH}"] * 2
    assert ctx.scratch == ["made", "removed"]

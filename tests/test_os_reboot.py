"""``os_reboot``: the flag file and, on the RHEL family, rpm's install times (O5)."""

import pytest

from motp.collect import child
from motp.core.model import ContractError, Status
from motp.modules import os_reboot
from motp.modules.os_reboot import OsReboot

from .packages_system import (
    APT_DISTROS,
    DAY,
    DNF_DISTROS,
    alerts,
    captured,
    detail_of,
    everything,
    only,
    render_for,
    system,
    text_of,
    through_the_contract,
)
from .support import NOW

# --- os_reboot -----------------------------------------------------------------------------

BOOT = NOW - 1000 * DAY


def proc_files(boot: int = BOOT, init_started_ticks: int = 150) -> dict[str, str]:
    fields = ["S", "0", "1", "1"] + ["0"] * 15 + [str(init_started_ticks)] + ["0"] * 20
    return {
        "/proc/stat": f"cpu 1 2 3\nintr {'0 ' * 2000}\nbtime {boot}\nprocesses 10\n",
        "/proc/1/stat": "1 (systemd) " + " ".join(fields) + "\n",
    }


@pytest.mark.parametrize("distro", APT_DISTROS)
def test_the_flag_file_asks_for_a_reboot(distro: str) -> None:
    files = {os_reboot.FLAG: "", os_reboot.FLAG_PACKAGES: "linux-base\nlibc6\nlibc6\n"}
    item = only(OsReboot().collect(system(distro, OsReboot, files=files)))
    assert (item.value, item.status, text_of(item)) == (True, Status.WARN, "Reboot required")
    assert detail_of(item, "os_reboot.packages") == "linux-base, libc6"
    items = list(through_the_contract("os_reboot", [item]))
    shown = render_for("os_reboot", items, admin=False)
    assert [(a.text, a.command) for a in alerts(shown)] == [("Reboot required", "sudo reboot")]
    assert "linux-base" not in everything(shown)
    assert "linux-base" in everything(render_for("os_reboot", items, admin=True))


def test_a_hostile_list_of_packages_renders_inert() -> None:
    files = {
        os_reboot.FLAG: "",
        os_reboot.FLAG_PACKAGES: (
            "\x1b[2J\x1b[31mevil\nlinux\x1b]0;owned\x07\nrm -rf /\n"
            "‮gnp.exe\n" + "x" * 5000 + "\nlibc6\n"
        ),
    }
    item = only(OsReboot().collect(system("debian12", OsReboot, files=files)))
    assert detail_of(item, "os_reboot.packages") == "libc6"
    text = everything(render_for("os_reboot", [item], admin=True))
    assert "\\x1b" not in text and "\\x07" not in text and "\\u202e" not in text


def test_a_huge_list_of_packages_is_cut() -> None:
    listed = "".join(f"package-number-{n}\n" for n in range(100_000))
    files = {os_reboot.FLAG: "", os_reboot.FLAG_PACKAGES: listed}
    items = OsReboot().collect(system("ubuntu2204", OsReboot, files=files))
    assert len(child.document("os_reboot", items)) < 4096


def test_the_flag_counts_without_a_list() -> None:
    item = only(OsReboot().collect(system("debian12", OsReboot, files={os_reboot.FLAG: ""})))
    assert item.value is True and item.detail == ()


@pytest.mark.parametrize("writer", os_reboot.FLAG_WRITERS)
def test_not_required_needs_something_that_would_set_the_flag(writer: str) -> None:
    assert OsReboot().collect(system("debian12", OsReboot)) == []
    item = only(OsReboot().collect(system("debian12", OsReboot, files={writer: ""})))
    assert (item.value, item.status, text_of(item)) == (False, Status.OK, "not required")


@pytest.mark.parametrize("distro", DNF_DISTROS)
def test_rpm_tells_what_was_installed_since_the_start(distro: str) -> None:
    outputs = {os_reboot.RPM_ARGV: captured(distro, "rpm_installed.txt")}
    times = [int(line.split()[0]) for line in outputs[os_reboot.RPM_ARGV].splitlines()]
    after = system(distro, OsReboot, files=proc_files(boot=max(times) + 10), outputs=outputs)
    item = only(OsReboot().collect(after))
    assert (item.value, text_of(item), item.detail) == (False, "not required", ())
    before = system(distro, OsReboot, files=proc_files(boot=min(times) - 10), outputs=outputs)
    item = only(OsReboot().collect(before))
    assert item.value is True
    assert "glibc" in detail_of(item, "os_reboot.packages")
    through_the_contract("os_reboot", [item])


def test_a_container_is_started_when_its_first_process_started() -> None:
    """The host booted long before: only what was installed since the start counts."""
    files = proc_files(boot=BOOT, init_started_ticks=500 * DAY * 100)
    outputs = {os_reboot.RPM_ARGV: f"{BOOT + 499 * DAY} glibc\n{BOOT + 501 * DAY} systemd\n"}
    ctx = system("almalinux9", OsReboot, files=files, outputs=outputs)
    assert detail_of(only(OsReboot().collect(ctx)), "os_reboot.packages") == "systemd"
    del files["/proc/1/stat"]  # hidden by hidepid: the boot time alone
    ctx = system("almalinux9", OsReboot, files=files, outputs=outputs)
    assert detail_of(only(OsReboot().collect(ctx)), "os_reboot.packages") == "glibc, systemd"


@pytest.mark.parametrize(
    "text",
    ["", "glibc 1\n", "1 gli\x1bbc\n", "12 glibc extra\n", "package kernel is not installed\n"],
)
def test_malformed_rpm_output_is_rejected(text: str) -> None:
    ctx = system("fedora45", OsReboot, files=proc_files(), outputs={os_reboot.RPM_ARGV: text})
    with pytest.raises(ContractError):
        OsReboot().collect(ctx)


def test_a_missing_boot_time_fails_the_module() -> None:
    outputs = {os_reboot.RPM_ARGV: "1 glibc\n"}
    ctx = system("fedora45", OsReboot, files={"/proc/stat": "cpu 1\n"}, outputs=outputs)
    with pytest.raises(ContractError):
        OsReboot().collect(ctx)

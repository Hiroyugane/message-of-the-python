"""What the four package modules of phase 9 share: the registry, hints and helpers."""

import pytest

from motp.collect import runner
from motp.core import config, hints
from motp.core.i18n import translator
from motp.core.model import ContractError
from motp.modules import os_autoupdates, os_reboot, os_updates, packages, registry
from motp.modules.base import Context
from motp.modules.os_autoupdates import OsAutoupdates
from motp.modules.os_reboot import OsReboot
from motp.modules.os_updates import OsUpdates

from .packages_system import (
    System,
)

# --- the registry ------------------------------------------------------------------------


def test_the_four_modules_are_registered_with_their_sections() -> None:
    names = [module.name for module in registry.cached_modules()]
    for name in ("os_updates", "os_reboot", "os_autoupdates", "os_eol"):
        assert name in names
        module = registry.cached_module(name)
        assert module is not None and not module.needs_root
        assert module.interval >= 300 and module.max_age > 3 * module.interval
        # The module's time fits inside the run's budget and the probe's cap.
        assert runner.probe_timeout(module, config.defaults()) <= runner.MAX_PROBE_TIMEOUT


def test_every_program_a_module_starts_is_one_it_lists() -> None:
    assert os_updates.APT_ARGV[0] in OsUpdates.binaries
    assert os_updates.DNF4_ARGV[0] in OsUpdates.binaries
    assert os_updates.DNF5_ARGV[0] in OsUpdates.binaries
    assert os_reboot.RPM_ARGV[0] in OsReboot.binaries
    assert os_autoupdates.APT_CONFIG_ARGV[0] in OsAutoupdates.binaries


def test_updates_are_only_read_from_local_state() -> None:
    """D28: simulate and cache-only; nothing that refreshes or installs."""
    assert "-s" in os_updates.APT_ARGV and "update" not in os_updates.APT_ARGV
    for argv in (os_updates.DNF4_ARGV, os_updates.DNF5_ARGV):
        assert "-C" in argv and not {"makecache", "--refresh", "update"} & set(argv)
    # Without build_cache=false, dnf 5 fails on a missing index file it cannot write.
    assert "--setopt=build_cache=false" in os_updates.DNF5_ARGV


@pytest.mark.parametrize(
    ("hint_id", "managers"),
    [
        ("updates.install", ("apt", "dnf")),
        ("updates.security", ("apt", "dnf")),
        ("reboot.required", ("apt", "dnf")),
        ("autoupdates.install", ("apt", "dnf")),
        ("autoupdates.enable", ("apt", "dnf")),
        ("autoupdates.enable_dnf5", ("dnf",)),
        ("autoupdates.apply_dnf5", ("dnf",)),
        ("autoupdates.timer", ("apt",)),
        ("autoupdates.unmask", ("apt", "dnf")),
        ("autoupdates.unmask_dnf5", ("dnf",)),
        ("autoupdates.periodic", ("apt",)),
        ("os.eol", ("apt", "dnf")),
    ],
)
def test_every_hint_the_modules_name_has_a_command(hint_id: str, managers: tuple[str, ...]) -> None:
    for manager in managers:
        found = hints.lookup(hint_id, manager)
        assert found is not None and found[1], (hint_id, manager)
        assert translator("en").message(found[0]) != found[0]


def test_a_system_without_a_package_manager_has_no_rows() -> None:
    ctx = System({"/etc/os-release": "ID=other\n"}, binaries=OsUpdates.binaries)
    for module in (OsUpdates(), OsReboot(), OsAutoupdates()):
        assert not module.detect(ctx).available
        assert module.collect(ctx) == []


def test_the_live_context_has_no_listing_and_no_file_times() -> None:
    for call in (Context().list_dir, Context().mtime):
        with pytest.raises(ContractError):
            call("/proc/self")


def test_name_list() -> None:
    assert packages.name_list(["a", "b"]) == "a, b"
    assert packages.name_list([]) == ""
    assert packages.name_list(["aaaa", "bbbb", "cccc"], limit=6) == "aaaa, +2"
    assert packages.name_list(["x" * 130], limit=6) == "x" * 6  # at least one name


def test_a_long_first_name_leaves_room_for_the_count() -> None:
    listed = packages.name_list(["x" * 191, "b"])
    assert len(listed) <= 120 and listed.endswith(", +1")

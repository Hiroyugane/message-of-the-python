"""The cached modules of phase 6: ``os_host``, ``net_addresses``, ``hw_disks`` (4.3, 5.4, T26).

Each runs against fixture trees in the shape of Debian 12, AlmaLinux 9 (as a Podman
container) and Ubuntu 22.04 with systemd-resolved; file system usage comes from a table.
The documents they produce must pass the built-in probe validation.
"""

import ipaddress

import pytest

from motp.collect import child
from motp.collect.context import read_os_release
from motp.core import probe
from motp.core.model import ContractError, HintRef, Item, MessageRef, Unit, Visibility
from motp.modules import registry
from motp.modules.base import Context
from motp.modules.hw_disks import (
    HwDisks,
    Mount,
    key_part,
    parent_disk,
    parse_mountinfo,
    private,
    used_percent,
    wanted,
)
from motp.modules.net_addresses import (
    NetAddresses,
    parse_fib_trie,
    parse_if_inet6,
    parse_nameservers,
)
from motp.modules.os_host import OsHost, os_name

from .support import FixtureProbeContext, usage


def _ctx(tree: str, **kwargs: object) -> FixtureProbeContext:
    base = FixtureProbeContext(tree)
    return FixtureProbeContext(tree, os_release=read_os_release(base), **kwargs)  # type: ignore[arg-type]


def _values(items: "list[Item]") -> dict[str, object]:
    return {item.key: item.value for item in items}


def _valid(name: str, items: "list[Item]") -> None:
    """The document the probe would print passes the collector's validation unchanged."""
    doc = probe.validate_builtin(child.document(name, items), name)
    assert [i.key for i in doc.items] == [i.key for i in items]


# --- os_host ---------------------------------------------------------------------------


def test_os_host_reads_name_os_and_kernel() -> None:
    items = OsHost().collect(_ctx("debian12"))
    assert _values(items) == {
        "os_host.hostname": "web01",
        "os_host.os": "Debian GNU/Linux 12 (bookworm)",
        "os_host.kernel": "6.1.0-28-amd64",
    }
    _valid("os_host", items)


def test_os_host_falls_back_to_name_and_version() -> None:
    items = OsHost().collect(_ctx("ubuntu2204"))
    assert _values(items)["os_host.os"] == "Ubuntu 22.04.5 LTS (Jammy Jellyfish)"
    assert os_name({}) == "Linux"


def test_hostile_os_name_is_sanitised_by_the_probe_contract() -> None:
    hostile = {"PRETTY_NAME": "Evil\x1b]0;owned\x07\x1b[31m OS‮"}
    ctx = FixtureProbeContext("debian12", os_release=hostile)
    doc = probe.validate_builtin(child.document("os_host", OsHost().collect(ctx)), "os_host")
    value = str(next(i.value for i in doc.items if i.key == "os_host.os"))
    assert "\x1b" not in value and "\x07" not in value and "‮" not in value


# --- net_addresses ----------------------------------------------------------------------


def test_addresses_skip_loopback_link_local_tentative_and_deprecated() -> None:
    items = NetAddresses().collect(_ctx("debian12"))
    assert _values(items) == {
        "net_addresses.local": "192.0.2.10, 192.0.2.11, 2001:db8::10",
        "net_addresses.dns": "192.0.2.53, 2001:db8::53",
    }
    _valid("net_addresses", items)


def test_container_addresses_and_search_line() -> None:
    items = NetAddresses().collect(_ctx("almalinux9"))
    assert _values(items) == {
        "net_addresses.local": "198.51.100.20",
        "net_addresses.dns": "198.51.100.53",
    }


def test_resolved_upstream_servers_win_over_the_stub() -> None:
    items = NetAddresses().collect(_ctx("ubuntu2204"))
    assert _values(items) == {
        "net_addresses.local": "2001:db8::30",
        "net_addresses.dns": "203.0.113.1, 203.0.113.2, fe80::1",
    }


def test_address_parsers_ignore_garbage() -> None:
    assert parse_fib_trie("|-- 999.1.1.1\n   /32 host LOCAL\n|-- \x1b[31m\n/32 host LOCAL\n") == []
    assert parse_if_inet6("zz short\n" + "g" * 32 + " 02 40 00 80 eth0\n") == []
    assert [str(a) for a in parse_nameservers("nameserver 192.0.2.1;rm\nnameserver\n")] == []


def test_unspecified_and_link_local_addresses_are_left_out() -> None:
    # Built from numbers: the repository scan allows no such address as text (invariant 3).
    unspecified = str(ipaddress.IPv4Address(0))
    link_local = str(ipaddress.IPv4Address((169 << 24) | (254 << 16) | 257))
    trie = "".join(f"|-- {a}\n   /32 host LOCAL\n" for a in (unspecified, link_local, "192.0.2.7"))
    assert [str(a) for a in parse_fib_trie(trie)] == ["192.0.2.7"]


def test_no_addresses_gives_no_rows() -> None:
    assert NetAddresses().collect(FixtureProbeContext("oldkernel")) == []


# --- hw_disks --------------------------------------------------------------------------

DEBIAN_USAGE = {
    "/": usage(40, 96),
    "/home": usage(200, 41),
    "/var": usage(20, 71, inodes=1000, inodes_used=60),
    "/boot/efi": usage(0.5, 6),
    "/media/user1/USB STICK": usage(16, 10),
    "/srv/usb": usage(64, 20),
    "/data": usage(500, 30),
}


def test_disks_list_local_file_systems_once() -> None:
    mounts = wanted(parse_mountinfo(_ctx("debian12").read_text("/proc/self/mountinfo")))
    assert [m.mount_point for m in mounts] == [
        "/",
        "/boot/efi",
        "/data",
        "/home",
        "/media/user1/USB STICK",
        "/srv/usb",
        "/var",
    ]


def test_disk_items_carry_rule_bar_text_and_hint() -> None:
    items = HwDisks().collect(_ctx("debian12", usage=DEBIAN_USAGE))
    by_key = {i.key: i for i in items}
    assert list(by_key) == [
        "hw_disks.root",
        "hw_disks.boot_efi",
        "hw_disks.data",
        "hw_disks.home",
        "hw_disks.var",
        "hw_disks.var-inodes",
        "hw_disks.media_user1_usb_stick",  # private mounts come last
        "hw_disks.srv_usb",
    ]
    root = by_key["hw_disks.root"]
    assert (root.value, root.unit, root.rule, root.bar) == (
        96,
        Unit.PERCENT,
        "disk_used_percent",
        0.96,
    )
    assert root.text == MessageRef(
        "disk.usage", (("free", "1.6 GiB"), ("percent", "96%"), ("size", "40 GiB"))
    )
    assert root.label == MessageRef("label.mount", (("mount", "/"),))
    assert root.hint == HintRef("disk.space")
    inodes = by_key["hw_disks.var-inodes"]
    assert (inodes.value, inodes.rule, inodes.hint) == (
        60,
        "inode_used_percent",
        HintRef("disk.inodes"),
    )
    _valid("hw_disks", items)


def test_removable_and_per_user_mounts_are_admin_only() -> None:
    items = HwDisks().collect(_ctx("debian12", usage=DEBIAN_USAGE))
    hidden = {i.key for i in items if i.visibility is Visibility.ADMIN}
    # /srv/usb is a partition of a removable disk; /data is a fixed whole disk
    assert hidden == {"hw_disks.media_user1_usb_stick", "hw_disks.srv_usb"}
    for path in ("/media/a/b", "/run/media/a/b", "/run/user/1000", "/home/a/x", "/root"):
        assert private(path), path
    for path in ("/", "/home", "/srv/media", "/var"):
        assert not private(path), path


def test_partitions_map_to_their_disk() -> None:
    assert parent_disk("sdb1") == "sdb"
    assert parent_disk("vda12") == "vda"
    assert parent_disk("nvme0n1p2") == "nvme0n1"
    assert parent_disk("mmcblk0p1") == "mmcblk0"
    assert parent_disk("dm-0") is None


def test_private_mounts_cannot_push_system_disks_out() -> None:
    lines = ["1 0 8:1 / / rw - ext4 /dev/sda1 rw"]
    lines += [f"{n + 2} 1 8:{n + 16} / /media/u/stick{n:02} rw - vfat /dev/x rw" for n in range(15)]
    lines.append("40 1 8:3 / /var rw - ext4 /dev/sda3 rw")
    text = "\n".join(lines) + "\n"
    table = {"/": usage(10, 10), "/var": usage(10, 97)}
    table.update({f"/media/u/stick{n:02}": usage(1, 1) for n in range(15)})
    ctx = FixtureProbeContext("debian12", usage=table)
    object.__setattr__(ctx, "_read_bytes", lambda path, n: text.encode()[:n])
    items = HwDisks().collect(ctx)
    keys = [i.key for i in items]
    assert keys[:2] == ["hw_disks.root", "hw_disks.var"]
    assert sum(1 for i in items if i.visibility is Visibility.ADMIN) == 4


def test_a_container_shows_only_its_root() -> None:
    items = HwDisks().collect(_ctx("almalinux9", usage={"/": usage(60, 30)}))
    assert [i.key for i in items] == ["hw_disks.root"]


def test_unreachable_mounts_are_skipped() -> None:
    items = HwDisks().collect(_ctx("debian12", usage={"/": usage(40, 50)}))
    assert [i.key for i in items] == ["hw_disks.root"]


def test_disk_keys_and_percentages() -> None:
    assert key_part("/") == "root"
    assert key_part("/var/log") == "var_log"
    assert key_part("/Data Disk/ü") == "data_disk"
    assert used_percent(1, 199) == 1  # rounded up like df
    assert used_percent(0, 0) == 0
    assert used_percent(5, 0) == 100


def test_duplicate_keys_get_a_suffix() -> None:
    text = (
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
        "2 1 8:2 / /a_b rw - ext4 /dev/sda2 rw\n"
        "3 1 8:3 / /a\\040b rw - ext4 /dev/sda3 rw\n"
    )
    ctx = FixtureProbeContext("debian12", usage={p: usage(1, 1) for p in ("/", "/a_b", "/a b")})
    object.__setattr__(ctx, "_read_bytes", lambda path, n: text.encode())
    keys = [i.key for i in HwDisks().collect(ctx)]
    assert keys == ["hw_disks.root", "hw_disks.a_b", "hw_disks.a_b-2"]


def test_inode_keys_never_collide_with_a_mount_key() -> None:
    text = (
        "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
        "2 1 8:2 / /data rw - ext4 /dev/sda2 rw\n"
        "3 1 8:3 / /data-inodes rw - ext4 /dev/sda3 rw\n"
    )
    full = usage(1, 1, inodes=100, inodes_used=90)
    ctx = FixtureProbeContext(
        "debian12", usage={"/": usage(1, 1), "/data": full, "/data-inodes": full}
    )
    object.__setattr__(ctx, "_read_bytes", lambda path, n: text.encode()[:n])
    items = HwDisks().collect(ctx)
    keys = [i.key for i in items]
    assert len(keys) == len(set(keys)) == 5, keys
    _valid("hw_disks", items)


def test_a_cut_mountinfo_fails_the_module() -> None:
    line = "9 1 0:99 / /home/u/" + "x" * 3000 + " rw - fuse.sshfs r rw\n"
    big = ("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" + line * 400).encode()
    assert len(big) > 1024 * 1024
    ctx = FixtureProbeContext("debian12", usage={"/": usage(1, 1)})
    object.__setattr__(ctx, "_read_bytes", lambda path, n: big[:n])
    with pytest.raises(ContractError) as exc:
        HwDisks().collect(ctx)
    assert exc.value.message.id == "module.error.parse"
    # below the cap, a large table is read whole
    object.__setattr__(ctx, "_read_bytes", lambda path, n: big[: 200 * 1024][:n])
    assert [i.key for i in HwDisks().collect(ctx)] == ["hw_disks.root"]


def test_mountinfo_escapes_and_overlay_rules() -> None:
    mounts = parse_mountinfo("1 0 0:1 / /a\\040b\\134c rw - overlay o rw\n")
    assert mounts == [Mount("0:1", "/a b\\c", "overlay")]
    assert wanted(mounts) == []  # overlay only as the root


def test_live_context_refuses_file_system_usage() -> None:
    ctx = Context()
    try:
        ctx.statvfs("/")
    except ValueError as exc:
        assert "context.error.statvfs" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("statvfs must raise for live modules")


# --- registry --------------------------------------------------------------------------


def test_registry_sections_match_the_cached_table() -> None:
    table = dict(registry.CACHED)
    for module in registry.cached_modules():
        assert table[module.name] == module.section
        assert module.mode == "cached" and module.interval >= 300
        assert registry.cached_module(module.name) is module
    assert registry.cached_module("hw_load") is None

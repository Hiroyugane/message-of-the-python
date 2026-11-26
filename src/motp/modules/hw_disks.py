"""``hw_disks``: space and inodes per file system (blueprint 4.3, 5.4, T26).

Runs as a cached module in a probe process as the user ``motp``, never at login (D22: one
stale network mount would hang every login). The mounts come from
``/proc/self/mountinfo``; only local, disk-backed file system types are listed, so pseudo
file systems, ``tmpfs``, FUSE and every network file system are left out (T26, and a hung
NFS server cannot stall the probe). ``overlay`` counts only as the root file system (a
container). Mount points below ``/proc``, ``/sys``, ``/dev``, ``/etc`` and ``/run`` (except
``/run/media``) are system paths, never a disk of their own: containers bind single files
such as ``/etc/hosts`` there. A file system mounted twice (bind mounts) is listed once,
under its shortest mount point.

Visibility (5.4, T26): system file systems are public; removable and per-user mounts
(below ``/media``, ``/run/media``, ``/run/user``, a home directory, or on a disk the kernel
marks removable) are admin-only. The kernel keeps ``removable`` on the whole disk only, so
for a partition the parent disk is found from the partition's ``uevent`` name. A USB disk
that reports itself as fixed is not caught by this; mount it below ``/media``.

Each file system is one item: the used share in percent like ``df`` (used against used plus
available to users), the rule ``disk_used_percent``, a bar, and the hint ``disk.space``,
which the renderer shows only when the rule warns. Inodes get an item of their own only
when at least ``INODE_FLOOR`` percent are used, under the rule ``inode_used_percent``, so a
normal screen keeps one row per file system.
"""

import math
import re
from dataclasses import dataclass
from typing import Optional

from motp.core.model import HintRef, Item, Unit, Visibility, ref
from motp.modules.base import CACHED, Context, Detection, FsUsage, format_bytes, parse_error

MOUNTINFO = "/proc/self/mountinfo"
MOUNTINFO_MAX = 1024 * 1024  # a larger table fails the module instead of losing mounts
UEVENT = "/sys/dev/block/{device}/uevent"
DISK_REMOVABLE = "/sys/block/{disk}/removable"
MAX_FILESYSTEMS = 16  # two items each at most, within the 32 items of a document
MAX_PRIVATE = 4  # removable and per-user mounts, listed after every system one
INODE_FLOOR = 50  # percent of inodes used before the inode row appears
KEY_CHARS = 40
INODE_SUFFIX = "-inodes"
LOCAL_TYPES = frozenset(
    {
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "bcachefs",
        "nilfs2", "vfat", "exfat", "ntfs", "ntfs3", "hfsplus", "ufs",
    }
)  # fmt: skip
ROOT_ONLY_TYPES = frozenset({"overlay"})
PRIVATE_PREFIXES = ("/media/", "/run/media/", "/run/user/", "/home/", "/root/")
SYSTEM_PREFIXES = ("/proc/", "/sys/", "/dev/", "/etc/", "/run/")
_ESCAPE = re.compile(r"\\([0-7]{3})")
_KEY_UNSAFE = re.compile(r"[^a-z0-9_-]+")
_DEVICE = re.compile(r"[0-9]{1,10}:[0-9]{1,10}\Z")
_DISK_NAME = re.compile(r"[a-z][a-z0-9]{0,31}\Z")
# nvme0n1p2 -> nvme0n1, mmcblk0p1 -> mmcblk0; then sdb1 -> sdb, vda3 -> vda
_PARTITION_NAMES = (
    re.compile(r"((?:nvme|mmcblk|loop|nbd)[0-9]+(?:n[0-9]+)?)p[0-9]+\Z"),
    re.compile(r"([a-z]+)[0-9]+\Z"),
)


@dataclass(frozen=True)
class Mount:
    device: str  # major:minor
    mount_point: str
    fs_type: str


def _unescape(field: str) -> str:
    """Mount points escape space, tab, newline and backslash as three octal digits."""
    return _ESCAPE.sub(lambda m: chr(int(m.group(1), 8)), field)


def parse_mountinfo(text: str) -> list[Mount]:
    """The mounts of ``mountinfo(5)`` lines, in file order; malformed lines are skipped."""
    mounts: list[Mount] = []
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        fields, tail = left.split(), right.split()
        if not sep or len(fields) < 5 or not tail or not _DEVICE.match(fields[2]):
            continue
        mount_point = _unescape(fields[4])
        if not mount_point.startswith("/"):
            continue
        mounts.append(Mount(fields[2], mount_point, tail[0]))
    return mounts


def wanted(mounts: list[Mount]) -> list[Mount]:
    """Local file systems, each device once under its shortest mount point."""
    best: dict[str, Mount] = {}
    for mount in mounts:
        local = mount.fs_type in LOCAL_TYPES or (
            mount.fs_type in ROOT_ONLY_TYPES and mount.mount_point == "/"
        )
        system = mount.mount_point.startswith(SYSTEM_PREFIXES) and not (
            mount.mount_point.startswith("/run/media/")
        )
        if not local or system:
            continue
        known = best.get(mount.device)
        if known is None or (len(mount.mount_point), mount.mount_point) < (
            len(known.mount_point),
            known.mount_point,
        ):
            best[mount.device] = mount
    return sorted(best.values(), key=lambda m: (m.mount_point != "/", m.mount_point))


def private(mount_point: str) -> bool:
    """Removable media and per-user mounts (T26); ``/home`` itself is a system mount."""
    return mount_point.startswith(PRIVATE_PREFIXES) or mount_point == "/root"


def key_part(mount_point: str) -> str:
    """``/`` is ``root``, ``/var/log`` is ``var_log``: a key never holds a ``/`` (phase 5)."""
    part = _KEY_UNSAFE.sub("_", mount_point.strip("/").lower()).strip("_-")
    return (part or "root")[:KEY_CHARS]


def used_percent(used: int, available: int) -> int:
    """Like ``df``: used against used plus available to users, rounded up."""
    total = used + available
    if total <= 0:
        return 0
    return min(100, math.ceil(used * 100 / total))


def parent_disk(partition: str) -> Optional[str]:
    """The whole disk a partition belongs to, by the kernel's naming; ``None`` if unknown."""
    for pattern in _PARTITION_NAMES:
        match = pattern.match(partition)
        if match:
            return match.group(1)
    return None


def _removable(ctx: Context, device: str) -> bool:
    """The kernel marks the disk under ``device`` (or under its partition) removable."""
    try:
        uevent = ctx.read_text(UEVENT.format(device=device), 4096)
    except ValueError:
        return False
    fields = {}
    for line in uevent.splitlines():
        name, _eq, value = line.partition("=")
        fields[name] = value.strip()
    disk: Optional[str] = fields.get("DEVNAME", "")
    if fields.get("DEVTYPE") == "partition":
        disk = parent_disk(disk or "")
    if not disk or not _DISK_NAME.match(disk):
        return False
    try:
        return ctx.read_text(DISK_REMOVABLE.format(disk=disk), 16).strip() == "1"
    except ValueError:
        return False


class HwDisks:
    name = "hw_disks"
    section = "disks"
    mode = CACHED
    needs_root = False
    interval = 300
    max_age = 3600
    timeout = 10.0
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(MOUNTINFO))

    def collect(self, ctx: Context) -> list[Item]:
        text = ctx.read_text(MOUNTINFO, MOUNTINFO_MAX)
        if len(text.encode("utf-8")) >= MOUNTINFO_MAX:
            raise parse_error(self.name)  # cut: later mounts would vanish without a word
        mounts = wanted(parse_mountinfo(text))
        if not mounts:
            raise parse_error(self.name)
        # System file systems first: private mounts, which a user can add (a stick, a
        # loop image), must not push them out of the list (security review).
        marked = [(m, private(m.mount_point) or _removable(ctx, m.device)) for m in mounts]
        ordered = [pair for pair in marked if not pair[1]] + [pair for pair in marked if pair[1]]
        items: list[Item] = []
        keys: set[str] = set()
        seen_fsid: set[tuple[int, int]] = set()
        listed = hidden_listed = 0
        for mount, hidden in ordered:
            if listed >= MAX_FILESYSTEMS or (hidden and hidden_listed >= MAX_PRIVATE):
                continue
            try:
                usage = ctx.statvfs(mount.mount_point)
            except ValueError:
                continue  # not reachable as the probe user, or gone meanwhile
            identity = (usage.fsid, usage.size)
            if usage.size <= 0 or (usage.fsid and identity in seen_fsid):
                continue  # empty, or another subvolume of a file system already listed
            seen_fsid.add(identity)
            # Each file system reserves its space key and its inode key, so /data (with
            # an inode row) and /data-inodes cannot both claim hw_disks.data-inodes.
            key = key_part(mount.mount_point)
            base, n = key, 2
            while key in keys or f"{key}{INODE_SUFFIX}" in keys:
                key, n = f"{base}-{n}", n + 1
            keys.update((key, f"{key}{INODE_SUFFIX}"))
            listed += 1
            hidden_listed += hidden
            visibility = Visibility.ADMIN if hidden else Visibility.PUBLIC
            items.append(self._space(mount, key, usage, visibility))
            inodes = self._inodes(mount, key, usage, visibility)
            if inodes is not None:
                items.append(inodes)
        return items

    @staticmethod
    def _space(mount: Mount, key: str, usage: FsUsage, visibility: Visibility) -> Item:
        percent = used_percent(usage.size - usage.free, usage.available)
        return Item(
            key=f"hw_disks.{key}",
            value=percent,
            unit=Unit.PERCENT,
            label=ref("label.mount", mount=mount.mount_point),
            rule="disk_used_percent",
            text=ref(
                "disk.usage",
                percent=f"{percent}%",
                size=format_bytes(usage.size),
                free=format_bytes(usage.available),
            ),
            bar=percent / 100,
            visibility=visibility,
            hint=HintRef("disk.space"),
        )

    @staticmethod
    def _inodes(mount: Mount, key: str, usage: FsUsage, visibility: Visibility) -> Optional[Item]:
        if usage.inodes <= 0:
            return None  # btrfs and others have no fixed inode count
        percent = used_percent(usage.inodes - usage.inodes_free, usage.inodes_available)
        if percent < INODE_FLOOR:
            return None
        return Item(
            key=f"hw_disks.{key}{INODE_SUFFIX}",
            value=percent,
            unit=Unit.PERCENT,
            label=ref("label.mount_inodes", mount=mount.mount_point),
            rule="inode_used_percent",
            text=ref(
                "disk.inode_usage",
                percent=f"{percent}%",
                total=usage.inodes,
                free=usage.inodes_available,
            ),
            bar=percent / 100,
            visibility=visibility,
            hint=HintRef("disk.inodes"),
        )

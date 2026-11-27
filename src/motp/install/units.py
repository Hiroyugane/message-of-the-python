"""The files the installer writes besides the program: units, cron entry, wrapper (4.11, 4.12).

Every text is a constant here, so tests can read what gets installed and
``systemd-analyze`` can check it in the systemd test images.

The sandbox of ``motp-collect.service`` is the baseline of 4.11 plus the additions settled
in phase 7. Each line that is not in the baseline names its reason in ``ADDITIONS``; the
directives that keep the exposure score of ``systemd-analyze security`` from going lower
are listed with their reason in ``KEPT_EXPOSURE``. The per-module table of 4.11 lives in
``MODULE_ADDITIONS``: a module that needs more than the baseline adds its line there.
"""

PREFIX = "/opt/motp"
LIB_DIR = PREFIX + "/lib"
BIN_DIR = PREFIX + "/bin"
WRAPPER = BIN_DIR + "/motp"
SYSTEM_PYTHON = "/usr/bin/python3"
SERVICE_NAME = "motp-collect.service"
TIMER_NAME = "motp-collect.timer"
UNIT_DIR = "/etc/systemd/system"
CRON_FILE = "/etc/cron.d/motp"
LOCAL_BIN_LINK = "/usr/local/bin/motp"
SYSTEMD_MARKER = "/run/systemd/system"  # exists only when systemd is the running init

# The program every MOTP process runs: the system interpreter, isolated and without the
# site module, on the unpacked tree (D24, D31, T2).
WRAPPER_TEXT = f"""\
#!/bin/sh
# Message of the Python, written by motp install. Runs the unpacked, compiled tree with
# the system interpreter, isolated from the environment and from site directories.
exec {SYSTEM_PYTHON} -I -S {LIB_DIR} "$@"
"""

SERVICE_TEXT = f"""\
# Message of the Python: the collector (blueprint 4.11). Written by motp install, which
# overwrites it on the next install; put local changes into a drop-in instead.
[Unit]
Description=Message of the Python: collect the MOTD cache
After=local-fs.target

[Service]
Type=oneshot
ExecStart={WRAPPER} collect --in-unit
TimeoutStartSec=90
KillMode=control-group
UMask=0077
RuntimeDirectory=motp
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
StateDirectory=motp
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadOnlyPaths=/run
ReadWritePaths=/run/motp
TemporaryFileSystem=/tmp:size=16M,mode=1777 /var/tmp:size=16M,mode=1777
PrivateDevices=yes
PrivateIPC=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_CHOWN
TasksMax=128
MemoryMax=256M
Nice=10
IOSchedulingClass=idle
"""

TIMER_TEXT = """\
# Message of the Python: runs the collector 20 seconds after boot and every 5 minutes
# (blueprint 4.11). Written by motp install.
[Unit]
Description=Message of the Python: collect the MOTD cache every 5 minutes

[Timer]
OnBootSec=20s
OnUnitActiveSec=5min
AccuracySec=10s

[Install]
WantedBy=timers.target
"""

# Without systemd (4.11): the same command from cron, without the sandbox. ``collect``
# outside the unit would start the unit, so the entry asks for the direct run.
CRON_TEXT = f"""\
# Message of the Python: the collector without systemd (blueprint 4.11). Written by
# motp install. There is no sandbox here; motp doctor says so.
SHELL=/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
@reboot root {WRAPPER} collect --no-sandbox
*/5 * * * * root {WRAPPER} collect --no-sandbox
"""

# Lines beyond the baseline of 4.11, each with its reason (phase 7, decision log).
ADDITIONS = {
    "ExecStart=/opt/motp/bin/motp collect --in-unit": (
        "the unit runs the collection; collect typed by an admin starts the unit"
    ),
    "KillMode=control-group": "a crashed run's leftovers die with the unit (4.9, phase 6 note)",
    "RuntimeDirectoryMode=0755": "the cache directory mode of 4.1, set by systemd too",
    "StateDirectoryMode=0700": "the state directory mode of 4.1, set by systemd too",
    "ReadOnlyPaths=/run": (
        "on systemd 252 ProtectSystem=strict with ProtectKernelTunables= or "
        "ProtectControlGroups= leaves /run writable; root probes must not write there "
        "(phase 12 measurement, phase 14)"
    ),
    "ReadWritePaths=/run/motp": "the cache directory stays writable below the read-only /run",
    "TemporaryFileSystem=/tmp:size=16M,mode=1777 /var/tmp:size=16M,mode=1777": (
        "the small /tmp of the baseline, writable by probes, and /var/tmp too (T23)"
    ),
    "PrivateDevices=yes": "a private /dev with its own small /dev/shm (phase 6, security low)",
    "PrivateIPC=yes": "no System V IPC or message queues shared with the host",
    "ProtectKernelLogs=yes": "no probe reads the kernel log",
    "ProtectClock=yes": "no probe sets the clock",
    "ProtectHostname=yes": "no probe sets the host name",
    "RestrictRealtime=yes": "no probe needs real-time scheduling",
    "RestrictSUIDSGID=yes": "nothing in the run creates setuid or setgid files",
    "SystemCallFilter=@system-service": "the system calls of an ordinary service",
    "SystemCallErrorNumber=EPERM": "a filtered call fails instead of killing the run",
}

# Every item ``systemd-analyze security`` still flags (systemd 249 to 262, score 2.4 of
# 10, phase 7 check), and why it stays.
KEPT_EXPOSURE = {
    "PrivateNetwork=": "probes read the host's addresses from /proc/net (net_addresses)",
    "PrivateTmp=": "16 MiB tmpfs instead; PrivateTmp is on disk and cannot be combined (249)",
    "User=/DynamicUser=": "the collector is root: it drops each probe to motp or motp-plugin",
    "CapabilityBoundingSet=~CAP_SET(UID|GID|PCAP)": "the drop to the probe users (D21)",
    "CapabilityBoundingSet=~CAP_(CHOWN|FSETID|SETFCAP)": "the group of admin.json (4.1)",
    "CapabilityBoundingSet=~CAP_KILL": "ending what probes leave behind (4.9)",
    "SystemCallFilter=~@privileged": "setuid, setgroups and chown for the drop and admin.json",
    "SystemCallFilter=~@resources": "setrlimit for the limits of every probe (4.9)",
    "PrivateUsers=": "probes run as real host users, so ownership checks hold",
    "ProtectHome=": "read-only, not hidden: hw_disks measures the /home file system",
    "ProtectProc=": "later probes count other users' processes (sessions, containers)",
    "ProcSubset=": "os_host reads /proc/sys/kernel",
    "RestrictAddressFamilies=~AF_UNIX": (
        "local sockets: the system bus, fail2ban's client, the container runtimes (O4)"
    ),
    "RestrictAddressFamilies=~AF_NETLINK": "netlink for the local addresses",
    "DeviceAllow=": "PrivateDevices leaves only the pseudo devices (null, zero, random)",
    "RootDirectory=/RootImage=": "probes read the host's own /etc, /proc and /sys",
}

# The per-module table of 4.11: what a module adds to the unit, when, and who owns it.
# Empty: no module so far needs more than the baseline. The package modules of phase 9
# run apt, dnf and rpm inside it: without a network, writing only to /var/tmp, with the
# unit's memory peaking between 69 and 136 MiB of the 256 MiB allowed (the four tier-1
# images with their base repositories). The security modules of phase 11 need nothing
# more either; what each of them uses of the baseline is in MODULE_EXPOSURE.
MODULE_ADDITIONS: dict[str, tuple[str, str]] = {}

# What the modules that run as root or open a socket use of the baseline, so a later
# tightening of the unit knows whom it breaks (phase 11, systemd test images).
MODULE_EXPOSURE = {
    "os_login": "reads /var/log/lastlog and wtmp as root; ProtectSystem=strict keeps it read-only",
    "sec_logins": "reads /var/log/btmp as root (0660 root:utmp); nothing written",
    "sec_fail2ban": (
        "starts /usr/bin/fail2ban-client status as root, which connects to the AF_UNIX "
        "socket /run/fail2ban/fail2ban.sock; no other command"
    ),
    "sec_firewall": (
        "as motp: systemctl show over the system bus (AF_UNIX) and two config files; no "
        "CAP_NET_ADMIN, so the live ruleset is not read (O12)"
    ),
    "app_containers": (
        "as root: one GET /containers/json?all=1 on the AF_UNIX sockets /run/docker.sock "
        "and /run/podman/podman.sock, root's and served by root (SO_PEERCRED); that socket "
        "is equal to root on the host, so the request is fixed in code (collect.unixhttp)"
    ),
}

# Static mode (4.10, D7, phase 8): the collector writes the rendered public text into
# /run/motd.d, which ProtectSystem=strict leaves read-only. The "-" lets the unit start
# when the directory is missing (the collector then logs that the file was not written)
# instead of failing the hybrid part of the run too.
MOTD_DIR = "/run/motd.d"
STATIC_LINE = f"ReadWritePaths=-{MOTD_DIR}"
STATIC_AFTER = "ProtectHome=read-only\n"
MODE_ADDITIONS = {
    "static": (STATIC_LINE, "the static file for pam_motd; only when mode = static (4.11)"),
}
TMPFILES_FILE = "/etc/tmpfiles.d/motp.conf"
# Recreates the directory at every boot, before the timer's first run.
TMPFILES_TEXT = f"""\
# Message of the Python, static mode (blueprint 4.10). Written by motp install.
d {MOTD_DIR} 0755 root root -
"""


# Plugins (phase 12). Inside the collector unit no plugin runs in the unit itself: every
# plugin gets a transient unit of its own, started with ``systemd-run --wait --pipe`` over
# the service manager's private socket (AF_UNIX, which the collector unit allows). So each
# plugin has its own /tmp, /var/tmp, /dev/shm, IPC namespace, task and memory limit, and
# nothing it leaves there outlives it or reaches the next plugin; and a root plugin never
# shares the collector's write access to /run/motp, /var/lib/motp and /run/motd.d.
# ``PLUGIN_PROPERTIES`` apply to every plugin, ``ROOT_PLUGIN_EXTRA`` or
# ``USER_PLUGIN_EXTRA`` by its user. ``-`` before a path lets the unit start without it.
# Measured on systemd 249, 252 and 262 (decision log, phase 12): ``PrivateDevices=`` alone
# keeps the host's /dev/shm; ``ProtectKernelTunables=`` with ``ProtectSystem=strict`` left
# /run writable on 252 until ``ReadOnlyPaths=/run`` was added; an empty /run for root
# plugins took effect on 252 and 262 but not on 249, and paths hidden below it failed the
# unit with 226/NAMESPACE on 252, so root's sockets are hidden by name instead.
SYSTEMD_RUN = "/usr/bin/systemd-run"
PLUGIN_UNIT_PREFIX = "motp-plugin-"
PLUGIN_SLACK = 3.0  # seconds systemd-run and the shim's start may add to a plugin's limit
PLUGIN_USER = "motp-plugin"
PLUGIN_PROPERTIES = {
    "ProtectSystem=strict": "the whole file system read-only",
    "ProtectHome=read-only": "as the collector unit",
    "ReadOnlyPaths=/run": "/run read-only too (with ProtectKernelTunables, strict alone did not)",
    "InaccessiblePaths=-/run/motp -/var/lib/motp": (
        "the cache and the state stay out of reach: nothing to read, nothing to plant"
    ),
    "TemporaryFileSystem=/tmp:size=16M,mode=1777 /var/tmp:size=16M,mode=1777 "
    "/dev/shm:size=16M,mode=1777": (
        "small temporary places of its own, gone with the unit (T9, T23)"
    ),
    "PrivateDevices=yes": "only the pseudo devices",
    "PrivateIPC=yes": "System V IPC and message queues of its own, gone with the unit",
    "PrivateNetwork=yes": "no network, and no abstract sockets shared with the host (D25)",
    "ProtectKernelTunables=yes": "as the collector unit",
    "ProtectKernelModules=yes": "as the collector unit",
    "ProtectKernelLogs=yes": "as the collector unit",
    "ProtectControlGroups=yes": "as the collector unit",
    "ProtectClock=yes": "as the collector unit",
    "ProtectHostname=yes": "as the collector unit",
    "RestrictAddressFamilies=AF_UNIX": "local sockets only (D25)",
    "IPAddressDeny=any": "a second barrier against IP traffic",
    "RestrictNamespaces=yes": "as the collector unit",
    "RestrictRealtime=yes": "as the collector unit",
    "RestrictSUIDSGID=yes": "as the collector unit",
    "LockPersonality=yes": "as the collector unit",
    "MemoryDenyWriteExecute=yes": "as the collector unit (no JIT runtimes, 4.9)",
    "SystemCallArchitectures=native": "as the collector unit",
    "SystemCallFilter=@system-service": "the system calls of an ordinary service",
    "SystemCallErrorNumber=EPERM": "a filtered call fails instead of killing the plugin",
    "NoNewPrivileges=yes": "no setuid program regains what the sandbox took",
    "KeyringMode=private": "a session keyring of its own",
    "TasksMax=64": "a fork bomb stays inside the unit (T23)",
    "MemoryMax=128M": "its memory, shared memory included, is its own, not the collector's",
    "UMask=0077": "as the collector unit",
    "WorkingDirectory=/": "as every probe (4.9)",
    "Nice=10": "as the collector unit",
    "IOSchedulingClass=idle": "as the collector unit",
}
ROOT_PLUGIN_EXTRA = {
    "CapabilityBoundingSet=CAP_DAC_READ_SEARCH": (
        "root may read files of other owners, which is what a root plugin is for, and has "
        "no other capability"
    ),
    "InaccessiblePaths=-/run/systemd/private -/run/systemd/io.systemd.Manager -/run/dbus "
    "-/run/docker.sock -/run/docker -/run/containerd -/run/podman": (
        "no way to ask the service manager, the bus or a container runtime for anything"
    ),
    "InaccessiblePaths=-/run/user -/run/snapd.socket -/run/snapd-snap.socket -/run/crio "
    "-/run/k3s -/run/libvirt -/run/incus -/run/lxd -/run/udev/control": (
        "nor root's own user manager and bus (/run/user/0), snapd, CRI-O, k3s, libvirt, "
        "Incus, LXD or udev (security review of phase 14; measured on systemd 249, 252, 257 "
        "and 262: the unit starts with each path present or missing, and none is reachable)"
    ),
}
USER_PLUGIN_EXTRA = {
    f"User={PLUGIN_USER}": "the plugin user (D21)",
    f"Group={PLUGIN_USER}": "its own group only",
    "CapabilityBoundingSet=": "no capability at all",
}
PLUGIN_ENV = ("PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C.UTF-8")


def plugin_unit_argv(
    systemd_run: str, name: str, timeout: float, root: bool, command: "tuple[str, ...]"
) -> "tuple[str, ...]":
    """The ``systemd-run`` command that runs ``command`` (the shim for plugin ``name``) in a
    transient unit of its own, as root (``root``) or as ``motp-plugin``.

    The unit has a fixed name, so a plugin never runs twice at once; ``RuntimeMaxSec`` ends
    it shortly after the plugin's own limit even if the collector is gone. Its environment
    is set here: the service manager's own would put ``/usr/local`` into ``PATH``.
    """
    limit = int(timeout + PLUGIN_SLACK) + 1
    argv = [
        systemd_run, "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
        f"--unit={PLUGIN_UNIT_PREFIX}{name}",
        f"--description=Message of the Python: plugin {name}",
    ]  # fmt: skip
    extra = ROOT_PLUGIN_EXTRA if root else USER_PLUGIN_EXTRA
    for prop in (*PLUGIN_PROPERTIES, *extra, f"RuntimeMaxSec={limit}"):
        argv += ["--property", prop]
    for pair in (*PLUGIN_ENV, f"MOTP_TIMEOUT={timeout:g}", "MOTP_PLUGIN_API=1"):
        argv += ["--setenv", pair]
    return (*argv, "--", *command)


def service_text_for(mode: str, wrapper: str = WRAPPER) -> str:
    """The collector unit for ``mode``: the baseline, plus the static mode line."""
    text = SERVICE_TEXT.replace(WRAPPER, wrapper)
    if mode == "static":
        text = text.replace(STATIC_AFTER, STATIC_AFTER + STATIC_LINE + "\n", 1)
    return text

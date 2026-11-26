#!/usr/bin/env python3
"""The phase 7 checks inside a systemd test container (blueprint 7.1 level 3, phase 7).

Run by ``tools/systemd_test.py`` with ``podman exec`` as root, in two parts around a
restart of the container, because the timer check needs a boot:

``before`` (after the container booted the first time):
  copy the repository, build the archive, snapshot the file system; an existing foreign
  ``motp`` account stops the installer; ``motp install``; ``systemd-analyze verify`` and
  ``systemd-analyze security``; the sandbox check unit (subreaper, pidfds and the control-
  group cleanup inside the collector's sandbox); then the cache is removed so that only the
  timer can bring it back.

``after`` (after the restart):
  the timer wrote the cache files within two minutes of boot, with the modes, owners and
  group of 4.1; the package modules (phase 9) and the service and login modules (phase 10:
  a failing unit counted and named, a unit row, a session, the per-user file root-owned
  with its ACL entry and readable by its user alone) give values in the unit's sandbox,
  and their probes ask for local sockets only; exec plugins (phase 12: the example for the
  admin only, ``motp-plugin`` unless granted root, a root plugin in its own transient unit
  that cannot write ``/run/motp``, ``/var/lib/motp``, ``/run/motd.d`` or ``/run``, read the
  cache or reach the service manager and other root sockets, hung plugins ended at their
  limit, nothing in ``/tmp``, ``/var/tmp`` or ``/dev/shm`` left for the next plugin, a
  refused plugin, ``motp doctor``'s list, the capability set and the exposure
  score unchanged); the journal holds no module name (T11);
  ``motp collect`` starts the unit and prints the result; ``motp doctor`` as root and as an
  ordinary user shows a root-only search path (invariant 7); the sandbox check again with
  ``ProtectProc=invisible`` and a group other than root's, so ``/proc`` hides the probe
  user's processes as on a host mounted ``hidepid=2,gid=<group>``;
  ``motp uninstall`` leaves only the config; a tampered manifest deletes nothing outside the
  installer's prefixes, and one that lists a foreign account is refused as a whole.

Every check prints one line ``CHECK <name> PASS|FAIL <detail>``; the host counts them. A
status line goes out at least every ``HEARTBEAT_SECONDS`` while the script waits.
"""

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

WORK = Path("/work")
PYZ = WORK / "dist" / "motp.pyz"
STATE = Path("/var/lib/motp")
CACHE = Path("/run/motp")
SNAPSHOT = WORK / "snapshot.json"
ROOTS = ("/opt", "/etc", "/var/lib/motp", "/run/motp", "/usr/local/bin")
# Files the system's account tools and systemd change by themselves.
VOLATILE = (
    "/etc/passwd-", "/etc/group-", "/etc/shadow-", "/etc/gshadow-", "/etc/.pwd.lock",
    "/etc/subuid-", "/etc/subgid-", "/etc/ld.so.cache", "/etc/machine-id",
)  # fmt: skip
PACKAGE_MODULES = ("os_updates", "os_reboot", "os_autoupdates", "os_eol")
MODULES = (
    "os_host", "net_addresses", "hw_disks", *PACKAGE_MODULES,
    "os_units", "rows_unit", "os_sessions", "os_login",
    "sec_logins", "sec_firewall", "app_containers",
)  # fmt: skip
# What a denied or failed attempt to reach the network would leave in the journal.
NETWORK_WORDS = (
    "Address family not supported", "Network is unreachable", "Could not resolve",
    "Temporary failure in name resolution", "Failed to download", "Cannot download",
    "Failed to fetch", "Permission denied",
)  # fmt: skip
LOCAL_FAMILIES = ("AF_UNIX", "AF_LOCAL", "AF_FILE", "AF_NETLINK")
PROBE_USER = "motp"
HEARTBEAT_SECONDS = 15.0
TIMER_LIMIT = 120.0
SCORE_LIMIT = 3.0
TESTER = "motp-tester"
CHECK_UNIT = "motp-sandbox-check.service"
HIDE_GROUP = "motp-hide"
# A root-only socket like Docker's or fail2ban's (O4): can a root probe reach it?
LISTENER = (
    "import os, socket\n"
    "p = '/run/motp-o4.sock'\n"
    "s = socket.socket(socket.AF_UNIX)\n"
    "s.bind(p); os.chmod(p, 0o660); s.listen(4)\n"
    "while True:\n"
    "    c, _ = s.accept(); c.close()\n"
)

failures = 0


def check(name: str, ok: bool, detail: str = "") -> bool:
    global failures
    if not ok:
        failures += 1
    print(f"CHECK {name} {'PASS' if ok else 'FAIL'} {detail}".rstrip(), flush=True)
    return ok


def stage(name: str) -> None:
    print(f"MOTP-STAGE {name}", flush=True)


def sh(
    *argv: str, user: Optional[int] = None, timeout: float = 300
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=timeout, check=False, user=user
    )


def snapshot() -> list[str]:
    out = []
    for root in ROOTS:
        for dirpath, dirnames, filenames in os.walk(root):
            for name in [*dirnames, *filenames]:
                path = os.path.join(dirpath, name)
                if path not in VOLATILE:
                    out.append(path)
    return sorted(out)


def refresh_package_lists() -> None:
    """Test setup only, while the container still has a network: MOTP itself never
    refreshes the lists (D28). The images are built without any. A fresh Debian or Ubuntu
    image has nothing pending, so one installed version is made slightly older in dpkg's
    status file: otherwise the count check would compare nothing with nothing."""
    if os.path.exists("/usr/bin/apt-get"):
        done = sh("apt-get", "update", "-qq", timeout=600)
        status = Path("/var/lib/dpkg/status")
        text = status.read_text()
        older = re.sub(r"(?m)^(Package: tar\n(?:.+\n)*?Version: .*)$", r"\1~0", text)
        status.write_text(older)
        check("test_setup_pending_update", older != text)
    else:
        done = sh("dnf", "-q", "makecache", timeout=600)
    check("test_setup_package_lists", done.returncode == 0, done.stderr[-200:])


def install(*extra: str) -> subprocess.CompletedProcess[str]:
    return sh("/usr/bin/python3", "-I", "-S", str(PYZ), "install", *extra)


# --- before the restart ------------------------------------------------------------------


def before() -> None:
    stage("copy")
    shutil.copytree(
        "/src",
        WORK,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            "__pycache__",
            ".mypy_cache",
            ".ruff_cache",
            ".pytest_cache",
            "dist",
            "scratch",
            "*.mo",
            "*.pyc",
        ),
    )
    stage("package-lists")
    refresh_package_lists()
    stage("build")
    built = sh("/usr/bin/python3", "-I", str(WORK / "tools/build_pyz.py"), "--output", str(PYZ))
    check("build", built.returncode == 0, built.stdout.strip()[:80] or built.stderr[-300:])
    SNAPSHOT.write_text(json.dumps(snapshot()))

    stage("foreign-account")
    sh("/usr/sbin/useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "motp")
    refused = install()
    check(
        "foreign_account_stops_installer",
        refused.returncode == 1
        and "was not created by MOTP" in refused.stdout
        and not os.path.exists("/opt/motp")
        and not STATE.exists(),
        refused.stdout.strip().splitlines()[-1]
        if refused.stdout.strip()
        else refused.stderr[-200:],
    )
    sh("/usr/sbin/userdel", "motp")

    stage("install")
    done = install()
    print(done.stdout, done.stderr, flush=True)
    check("install", done.returncode == 0, f"exit {done.returncode}")
    config = Path("/etc/motp/config.toml").read_text()
    group = (
        "sudo"
        if 'admin_group = "sudo"' in config
        else "wheel"
        if 'admin_group = "wheel"' in config
        else ""
    )
    check("admin_group_chosen", group in ("sudo", "wheel"), group or "none")

    stage("verify")
    units = ["/etc/systemd/system/motp-collect.service", "/etc/systemd/system/motp-collect.timer"]
    verify = sh("systemd-analyze", "verify", *units)
    noise = (verify.stdout + verify.stderr).strip()
    check("systemd_analyze_verify", verify.returncode == 0 and not noise, noise[:300])
    sec = sh("systemd-analyze", "security", "--no-pager", "motp-collect.service")
    score = None
    for line in sec.stdout.splitlines():
        if "Overall exposure level" in line:
            score = float(line.split(":")[1].split()[0])
        if line.startswith("✗"):
            print("  " + " ".join(line.split()[:2]), flush=True)
    check("exposure_score", score is not None and score <= SCORE_LIMIT, f"{score}")

    stage("sandbox")
    listener = subprocess.Popen(["/usr/bin/python3", "-I", "-c", LISTENER])  # O4
    try:
        time.sleep(1)
        sandbox_check("plain")
    finally:
        listener.kill()
        listener.wait()

    stage("prepare-restart")
    for name in ("public.json", "admin.json", "render.json"):
        (CACHE / name).unlink(missing_ok=True)


def sandbox_check(label: str) -> None:
    """Run tools/container/systemd/sandbox_check.py as a unit with the collector's own
    sandbox: subreaper, pidfds and the control-group cleanup must work there."""
    text = Path("/etc/systemd/system/motp-collect.service").read_text()
    exec_line = "ExecStart=/opt/motp/bin/motp collect"
    script = WORK / "tools/container/systemd/sandbox_check.py"
    unit = text.replace(exec_line, f"ExecStart=/usr/bin/python3 -I -S {script}")
    if label == "hidepid":  # hide other users' processes from this unit's /proc
        # hidepid exempts group 0 unless gid= names another; run in a group of its own.
        sh("/usr/sbin/groupadd", "--system", HIDE_GROUP)
        extra = f"ProtectHome=read-only\nProtectProc=invisible\nGroup={HIDE_GROUP}"
        unit = unit.replace("ProtectHome=read-only", extra)
    Path(f"/etc/systemd/system/{CHECK_UNIT}").write_text(unit)
    sh("systemctl", "daemon-reload")
    started = sh("systemctl", "start", CHECK_UNIT, timeout=120)
    log = sh("journalctl", "-u", CHECK_UNIT, "-o", "cat", "--no-pager").stdout
    last = [ln for ln in log.splitlines() if ln.startswith("SANDBOX ")]
    result = last[-1] if last else "no output"
    ok = started.returncode == 0 and result.startswith("SANDBOX ok")
    if label == "hidepid":  # the cleanup must work although /proc shows nothing
        ok = ok and "hidden=True" in result and "seen_in_proc=0" in result
    check(f"sandbox_{label}", ok, result)
    Path(f"/etc/systemd/system/{CHECK_UNIT}").unlink()
    sh("systemctl", "daemon-reload")
    sh("journalctl", "--rotate")


# --- after the restart -------------------------------------------------------------------


def booted_seconds_ago() -> float:
    """Seconds since this container's init started: ``/proc/uptime`` is the host's in some
    images, so the start time of PID 1 is subtracted."""
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    fields = Path("/proc/1/stat").read_text().rsplit(")", 1)[1].split()
    started = int(fields[19]) / os.sysconf("SC_CLK_TCK")
    return uptime - started


def wait_for_cache() -> float:
    """Seconds from boot until the timer's run wrote all three files (or the limit)."""
    names = ("public.json", "admin.json", "render.json")
    last = time.monotonic()
    while True:
        up = booted_seconds_ago()
        if all((CACHE / n).exists() for n in names):
            return up
        if up > TIMER_LIMIT + 30:
            return up
        if time.monotonic() - last >= HEARTBEAT_SECONDS:
            last = time.monotonic()
            print(f"progress: waiting for the timer, booted {int(up)}s ago", flush=True)
        time.sleep(1)


def after() -> None:
    stage("timer")
    up = wait_for_cache()
    check("timer_writes_cache_within_two_minutes", up <= TIMER_LIMIT, f"{up:.0f} s after boot")
    config = Path("/etc/motp/config.toml").read_text()
    group = "sudo" if 'admin_group = "sudo"' in config else "wheel"
    import grp

    gid = grp.getgrnam(group).gr_gid
    expect = {"public.json": (0o644, 0), "admin.json": (0o640, gid), "render.json": (0o644, 0)}
    for name, (mode, want_gid) in expect.items():
        st = os.lstat(CACHE / name)
        got = (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
        check(f"cache_{name}", got == (mode, 0, want_gid), f"{oct(got[0])} {got[1]}:{got[2]}")
    admin = json.loads((CACHE / "admin.json").read_text())
    failed = [n for n, m in admin["modules"].items() if m.get("state") != "ok"]
    check("modules_ok_in_the_unit", not failed and len(admin["modules"]) >= 3, ",".join(failed))

    stage("package-modules")
    package_modules()

    stage("service-and-login-modules")
    service_modules()

    stage("security-modules")
    security_modules()

    stage("plugins")
    plugins_stage()
    plugin_groups_stage()
    private_modes_stage()

    stage("journal")
    journal = sh("journalctl", "-u", "motp-collect.service", "-o", "cat", "--no-pager").stdout
    named = [m for m in MODULES if m in journal]
    check("journal_has_counts_only", "collect: done" in journal and not named, ",".join(named))

    stage("collect-via-unit")
    run = sh("/opt/motp/bin/motp", "collect", timeout=200)
    print(run.stdout, run.stderr, flush=True)
    check(
        "collect_starts_the_unit",
        run.returncode == 0 and "unit finished: success" in run.stdout,
        run.stdout.strip().splitlines()[0] if run.stdout.strip() else run.stderr[-200:],
    )

    stage("invariant-7")
    sh("/usr/sbin/useradd", "--create-home", "--shell", "/bin/sh", TESTER)
    import pwd

    tester = pwd.getpwnam(TESTER).pw_uid
    for who, uid in (("root", None), ("user", tester)):
        doc = sh("/opt/motp/bin/motp", "doctor", user=uid)
        line = next((ln for ln in doc.stdout.splitlines() if "search path" in ln), "")
        check(f"invariant_7_{who}", line.startswith("[ok] Python search path:"), line)
        if who == "root":
            print(doc.stdout, flush=True)
            check("doctor_as_root", doc.returncode == 0, f"exit {doc.returncode}")

    stage("hidepid")
    sandbox_check("hidepid")

    stage("uninstall")
    gone = sh("/opt/motp/bin/motp", "uninstall")
    print(gone.stdout, gone.stderr, flush=True)
    check("uninstall", gone.returncode == 0, f"exit {gone.returncode}")
    old = set(json.loads(SNAPSHOT.read_text()))
    new = set(snapshot())
    extra = sorted(p for p in new - old if not p.startswith(f"/etc/{TESTER}"))
    home = [p for p in extra if "/home/" in p]
    extra = [p for p in extra if p not in home]
    check(
        "uninstall_leaves_only_the_config",
        bool(extra) and all(p == "/etc/motp" or p.startswith("/etc/motp/") for p in extra),
        " ".join(extra),
    )
    missing = sorted(old - new)
    check("uninstall_removed_nothing_else", not missing, " ".join(missing[:10]))
    users = sh("getent", "passwd", "motp", "motp-plugin").stdout.strip()
    check("accounts_removed", not users, users)

    stage("tampered-manifest")
    tampered()


def pending_as_root() -> int:
    """The number of pending updates by the package manager's own account, asked by
    root, to compare with what the sandboxed probe counted."""
    if os.path.exists("/usr/bin/apt-get"):
        out = sh("apt-get", "-s", "-q", "upgrade", "--with-new-pkgs", timeout=600).stdout
        return sum(1 for ln in out.splitlines() if re.match(r"Inst \S+ \[", ln))
    program = "dnf5" if os.path.exists("/usr/bin/dnf5") else "dnf"
    query = "%{name}.%{arch}\n" if program == "dnf5" else "%{name}.%{arch}"
    out = sh(
        program, "-C", "-q", "repoquery", "--upgrades", "--latest-limit=1",
        "--queryformat", query, timeout=600,
    ).stdout  # fmt: skip
    return len(set(out.split()))


def fresh_collection() -> dict[str, dict[str, object]]:
    """Every module due again, one run of the unit; the admin tier's modules."""
    (STATE / "state.json").unlink(missing_ok=True)
    for name in ("public.json", "admin.json"):
        (CACHE / name).unlink(missing_ok=True)
    sh("systemctl", "start", "motp-collect.service", timeout=200)
    return json.loads((CACHE / "admin.json").read_text())["modules"]  # type: ignore[no-any-return]


def package_modules() -> None:
    """Phase 9: the package modules in the unit's sandbox, with no network at all."""
    devices = Path("/proc/net/dev").read_text().splitlines()[2:]
    interfaces = [line.split(":")[0].strip() for line in devices]
    check("container_has_no_network", set(interfaces) <= {"lo"}, " ".join(interfaces))
    # The unit's peak memory, which includes the package manager's.
    dropin = Path("/etc/systemd/system/motp-collect.service.d")
    dropin.mkdir(parents=True, exist_ok=True)
    (dropin / "motp-test-peak.conf").write_text(
        "[Service]\nExecStartPost=+/bin/sh -c 'cat /sys/fs/cgroup/system.slice/"
        "motp-collect.service/memory.peak > /run/motp-test-peak'\n"
    )
    sh("systemctl", "daemon-reload")
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    modules = fresh_collection()
    peak = Path("/run/motp-test-peak")
    if peak.exists():
        print(f"NOTE unit memory peak: {int(peak.read_text()) // (1024 * 1024)} MiB", flush=True)
        peak.unlink()
    shutil.rmtree(dropin)
    sh("systemctl", "daemon-reload")
    for name in PACKAGE_MODULES:
        entry = modules.get(name, {})
        items = entry.get("items", [])
        shown = ", ".join(f"{i['key']}={i.get('value')}" for i in items)  # type: ignore[attr-defined]
        ok = entry.get("state") == "ok"
        if name != "os_reboot":  # no row where nothing would set the flag (a bare Debian)
            ok = ok and bool(items) and items[0].get("value") is not None  # type: ignore[index]
        detail = f"state={entry.get('state')} {shown} {entry.get('error', '')}"
        check(f"sandbox_{name}", ok, detail)
    items = modules.get("os_updates", {}).get("items") or [{}]
    counted = items[0].get("value")  # type: ignore[index]
    expected = pending_as_root()
    ok = counted == expected and (expected > 0 or not os.path.exists("/usr/bin/apt-get"))
    check("updates_match_the_package_manager", ok, f"{counted} vs {expected}")
    journal = sh("journalctl", "-o", "cat", "--no-pager", "--since", started).stdout
    bad = [ln for ln in journal.splitlines() if any(w in ln for w in NETWORK_WORDS)]
    check("journal_has_no_network_attempt", not bad, " | ".join(bad[:3])[:300])
    for name in PACKAGE_MODULES:
        socket_check(name)
    # The control: the same trace must see a program that does ask for a network socket.
    opens_one = "import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"
    _code, families = traced(["/usr/bin/python3", "-I", "-c", opens_one])
    check("trace_sees_a_network_socket", "AF_INET" in families, ",".join(families))


def traced(argv: list[str], as_root: bool = False) -> tuple[int, list[str]]:
    """Run ``argv`` as the probe user (or root) under strace: its exit code and the
    address families it and its children asked for."""
    import pwd

    account = pwd.getpwnam("root" if as_root else PROBE_USER)
    trace = Path("/tmp/motp-trace")  # noqa: S108  (a test container)
    trace.unlink(missing_ok=True)
    done = subprocess.run(
        ["/usr/bin/strace", "-f", "-qq", "-e", "trace=socket,connect,sendto,sendmsg",
         "-o", str(trace), *argv],
        capture_output=True, timeout=120, check=False, cwd="/", stdin=subprocess.DEVNULL,
        user=account.pw_uid, group=account.pw_gid, extra_groups=[],
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"},
    )  # fmt: skip
    lines = trace.read_text().splitlines() if trace.exists() else []
    families = sorted({f for ln in lines for f in re.findall(r"\b(AF_[A-Z0-9]+)", ln)})
    traced_at_all = trace.exists()
    trace.unlink(missing_ok=True)
    return (done.returncode if traced_at_all else -1), families


def socket_check(module: str, as_root: bool = False) -> None:
    """The probe and everything it starts, traced: only local sockets may be asked for.
    The unit would refuse the others without a word, so the journal alone could not
    tell."""
    code, families = traced(["/opt/motp/bin/motp", "_probe", module], as_root)
    remote = [f for f in families if f not in LOCAL_FAMILIES]
    named = ",".join(families) or "-"
    check(f"no_network_socket_{module}", code == 0 and not remote, f"exit={code} families={named}")


# --- phase 10: the service and login modules in the unit ----------------------------------

FAIL_UNIT = "motp-p10-fail.service"
ROWS_CONF = Path("/etc/motp/conf.d/50-p10-rows.toml")
P10_MODULES = ("os_units", "rows_unit", "os_sessions", "os_login")
P10_HOST = "198.51.100.23"  # the lastlog record: per-user file only
SESSION_HOST = "198.51.100.24"  # the utmp session: admin tier only
LASTLOG = Path("/var/log/lastlog")
UTMP = Path("/run/utmp")


def lastlog_record(uid: int, started: int) -> None:
    """A login of ``uid`` as sshd would record it (the image has no sshd)."""
    import struct

    if not LASTLOG.exists():
        LASTLOG.touch(mode=0o664)
    with LASTLOG.open("r+b") as f:
        f.seek(uid * 292)
        f.write(struct.pack("=i32s256s", started, b"pts/7", P10_HOST.encode()))


def utmp_session(user: str, started: int) -> None:
    import struct

    record = struct.pack(
        "=h2xi32s4s32s256s2hi2i4i20s",
        7, os.getpid(), b"pts/7", b"ts/7", user.encode(), SESSION_HOST.encode(),
        0, 0, 0, started, 0, 0, 0, 0, 0, b"",
    )  # fmt: skip
    with UTMP.open("ab") as f:
        f.write(record)


def service_modules() -> None:
    """Phase 10: the four modules in the unit's sandbox, and the per-user file."""
    import pwd

    Path(f"/etc/systemd/system/{FAIL_UNIT}").write_text(
        "[Unit]\nDescription=MOTP test: fails\n\n[Service]\nType=oneshot\nExecStart=/bin/false\n"
    )
    sh("systemctl", "daemon-reload")
    sh("systemctl", "start", FAIL_UNIT)
    ROWS_CONF.write_text(f'[[rows.unit]]\nname = "{FAIL_UNIT}"\nlabel = "P10 job"\n')
    ROWS_CONF.chmod(0o644)
    sh("/usr/sbin/useradd", "--create-home", "--shell", "/bin/sh", TESTER)
    tester = pwd.getpwnam(TESTER).pw_uid
    now = int(time.time())
    lastlog_record(tester, now - 600)
    utmp_session(TESTER, now - 60)
    modules = fresh_collection()
    for name in P10_MODULES:
        entry = modules.get(name, {})
        items = entry.get("items", [])
        shown = ", ".join(f"{i['key']}={i.get('value')}" for i in items)  # type: ignore[attr-defined]
        check(f"sandbox_{name}", entry.get("state") == "ok", f"{shown} {entry.get('error', '')}")
    units: Any = (modules.get("os_units", {}).get("items") or [{}])[0]  # type: ignore[index]
    names = {str(d.get("value")) for d in units.get("detail", [])}
    count = units.get("value")
    check(
        "failed_unit_counted_and_named",
        isinstance(count, int) and count >= 1 and FAIL_UNIT in "".join(names),
        f"{count} {names}",
    )
    rows: Any = modules.get("rows_unit", {}).get("items") or [{}]
    check("unit_row_is_failed", rows[0].get("value") == "failed", str(rows[0].get("value")))
    path = CACHE / "user" / f"{tester}.json"
    st = os.lstat(path) if path.exists() else None
    acl = os.getxattr(path, "system.posix_acl_access") if st else b""
    check(
        "per_user_file_root_owned_with_acl",
        st is not None
        and (st.st_uid, stat.S_IMODE(st.st_mode)) == (0, 0o440)
        and int.from_bytes(acl[16:20], "little") == tester,  # the second entry's id
        f"{oct(stat.S_IMODE(st.st_mode)) if st else 'missing'} acl={acl.hex()[:48]}",
    )
    owner = sh("cat", str(path), user=tester)
    other = sh("cat", str(path), user=pwd.getpwnam("nobody").pw_uid)
    check(
        "per_user_file_readable_by_its_user_alone",
        owner.returncode == 0 and P10_HOST in owner.stdout and other.returncode != 0,
        f"owner={owner.returncode} other={other.returncode} {other.stderr.strip()[:80]}",
    )
    public = (CACHE / "public.json").read_text()
    admin = (CACHE / "admin.json").read_text()
    check("no_login_record_in_the_tier_files", P10_HOST not in public + admin)
    check("session_host_for_admins_only", SESSION_HOST in admin and SESSION_HOST not in public)
    for name in ("os_units", "os_sessions"):
        socket_check(name)
    socket_check("os_login", as_root=True)
    sh("systemctl", "reset-failed", FAIL_UNIT)
    Path(f"/etc/systemd/system/{FAIL_UNIT}").unlink()
    ROWS_CONF.unlink()
    sh("systemctl", "daemon-reload")


# --- phase 11: the security modules in the unit -------------------------------------------

DOCKER_SOCK = "/run/docker.sock"
FAKE_RUNTIME = WORK / "tools/container/fake_runtime.py"
DOCKER_FIXTURE = WORK / "tests/fixtures/security/docker-api.json"
HOSTILE_FIXTURE = Path("/root/motp-docker-hostile.json")
BTMP = Path("/var/log/btmp")
TRIED_NAME = "qzsecretname"  # an attempted user name: in no cache or state file at all
FAILED_FROM = "203.0.113.44"  # a failed login's source: admin tier only
# Names and images of the fixture's containers; the admin's lists are cut at 100
# characters, so only the first ones are sure to be shown there.
CONTAINER_NAMES = ("qzweb-frontend", "qzdb-backend", "qzloop-worker", "qzold-job", "qzimage")
ADMIN_SHOWN = ("qzdb-backend", "qzloop-worker")
CAPABILITIES = {"cap_setuid", "cap_setgid", "cap_kill", "cap_chown"}  # the table of 4.11
APP_TIMEOUT = 10.0  # app_containers.timeout


def btmp_failure(started: int) -> None:
    """A failed SSH login as sshd records it (the image has no sshd)."""
    import ipaddress
    import struct

    addr = struct.unpack("=i", ipaddress.IPv4Address(FAILED_FROM).packed)[0]
    record = struct.pack(
        "=h2xi32s4s32s256s2hi2i4i20s",
        6, 4242, b"ssh:notty", b"", TRIED_NAME.encode(), FAILED_FROM.encode(),
        0, 0, 0, started, 0, addr, 0, 0, 0, b"",
    )  # fmt: skip
    if not BTMP.exists():
        BTMP.touch(mode=0o660)
    with BTMP.open("ab") as f:
        f.write(record + record)  # an unknown name: two records, one attempt


class FakeDocker:
    """The stand-in runtime as the unit ``docker.service`` (``systemd-run``), so the module
    sees an active Docker; ``stop()`` ends it."""

    def __init__(self, argv: "list[str]") -> None:
        subprocess.run(["systemctl", "reset-failed", "docker.service"], capture_output=True)
        subprocess.run(
            ["systemd-run", "--unit=docker", "--service-type=simple", "--quiet", *argv],
            capture_output=True,
            check=False,
        )

    def stop(self) -> None:
        subprocess.run(["systemctl", "stop", "docker.service"], capture_output=True)
        subprocess.run(["systemctl", "reset-failed", "docker.service"], capture_output=True)


def fake_runtime(mode: str) -> FakeDocker:
    argv = ["/usr/bin/python3", "-I", str(FAKE_RUNTIME), mode, DOCKER_SOCK]
    if mode == "answer":
        data = json.loads(DOCKER_FIXTURE.read_text())
        data["answer"].append(
            {"Names": ["/\x1b]0;owned\x07qzhostile\x1b[2J"], "Image": "\x1b[31mevil",
             "State": "running", "Status": "Up 1 second"}
        )  # fmt: skip
        HOSTILE_FIXTURE.write_text(json.dumps(data))
        argv.append(str(HOSTILE_FIXTURE))
    Path(DOCKER_SOCK).unlink(missing_ok=True)
    started = FakeDocker(argv)
    for _ in range(50):
        if os.path.exists(DOCKER_SOCK):
            break
        time.sleep(0.1)
    return started


def files_holding(word: str) -> "list[str]":
    found = []
    for top in (CACHE, STATE):
        for path in top.rglob("*"):
            if path.is_file() and word.encode() in path.read_bytes():
                found.append(str(path))
    return found


def security_modules() -> None:
    """Phase 11: the security modules in the unit's sandbox, the capability set, and a
    runtime socket that never answers."""
    caps = sh("systemctl", "show", "-p", "CapabilityBoundingSet", "--value", "motp-collect.service")
    got = set(caps.stdout.split())
    check("capability_set_is_the_table_of_4_11", got == CAPABILITIES, " ".join(sorted(got)))

    btmp_failure(int(time.time()) - 30)
    runtime = fake_runtime("answer")
    try:
        modules = fresh_collection()
    finally:
        runtime.stop()
    for name in ("sec_logins", "sec_firewall", "app_containers"):
        entry = modules.get(name, {})
        items = entry.get("items", [])
        shown = ", ".join(f"{i['key']}={i.get('value')}" for i in items)  # type: ignore[attr-defined]
        check(f"sandbox_{name}", entry.get("state") == "ok", f"{shown} {entry.get('error', '')}")
    public = (CACHE / "public.json").read_text()
    admin = (CACHE / "admin.json").read_text()
    render = (CACHE / "render.json").read_text()
    check("failed_login_source_for_admins_only",
          FAILED_FROM in admin and FAILED_FROM not in public + render)  # fmt: skip
    holding = files_holding(TRIED_NAME)
    check("attempted_name_in_no_file", not holding, " ".join(holding))
    leaked = [n for n in CONTAINER_NAMES if n in public + render]
    check("container_names_for_admins_only",
          all(n in admin for n in ADMIN_SHOWN) and not leaked, " ".join(leaked))  # fmt: skip
    check("hostile_container_name_inert",
          "qzhostile" in admin and "\\u001b" not in admin and "\x1b" not in admin)  # fmt: skip
    asked = Path(DOCKER_SOCK + ".log").read_text().splitlines()
    check("runtime_got_one_fixed_get", set(asked) == {"GET /containers/json?all=1 HTTP/1.0"},
          " | ".join(sorted(set(asked)))[:200])  # fmt: skip
    check("firewall_for_admins_only", "sec_firewall" in admin and "sec_firewall" not in public)
    socket_check("sec_firewall")
    socket_check("sec_logins", as_root=True)

    # Docker stopped, its socket file left behind (as docker.socket keeps it): the module
    # must not connect, since that would start Docker again (security review).
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    Path(DOCKER_SOCK).unlink(missing_ok=True)  # the stand-in leaves its file behind
    sock.bind(DOCKER_SOCK)  # a root socket nobody serves
    log = Path(DOCKER_SOCK + ".log")
    asked_before = len(log.read_text().splitlines()) if log.exists() else 0
    modules = fresh_collection()
    sock.close()
    rows: Any = modules.get("app_containers", {}).get("items", [])
    asked_after = len(log.read_text().splitlines()) if log.exists() else 0
    check(
        "stopped_docker_is_not_woken",
        asked_after == asked_before and any(i.get("value") is None for i in rows),
        f"requests {asked_before}->{asked_after} {rows}"[:200],
    )
    Path(DOCKER_SOCK).unlink(missing_ok=True)

    # A runtime that accepts and never answers: the module fails within its time limit,
    # the other modules still run, the whole run stays short.
    runtime = fake_runtime("hang")
    try:
        started = time.monotonic()
        modules = fresh_collection()
        took = time.monotonic() - started
    finally:
        runtime.stop()
    entry = modules.get("app_containers", {})
    ms = entry.get("duration_ms")
    others = [n for n, m in modules.items() if n != "app_containers" and m.get("state") != "ok"]
    check(
        "hung_runtime_fails_within_the_module_limit",
        entry.get("state") == "failed" and isinstance(ms, int) and ms <= APP_TIMEOUT * 1000 + 1500,
        f"state={entry.get('state')} {ms} ms run={took:.1f}s",
    )
    check("hung_runtime_keeps_other_modules", not others, ",".join(others))
    check("hung_runtime_run_is_short", took < APP_TIMEOUT + 30, f"{took:.1f}s")
    Path(DOCKER_SOCK).unlink(missing_ok=True)
    Path(DOCKER_SOCK + ".log").unlink(missing_ok=True)


# --- phase 12: exec plugins in the sandboxed unit -------------------------------------

PLUGIN_DIR = Path("/etc/motp/plugins.d")
PLUGIN_CONF = Path("/etc/motp/conf.d/60-p12-plugins.toml")
PLANTED = (
    "/run/motp/p12-planted", "/var/lib/motp/p12-planted", "/run/motd.d/p12-planted",
    "/run/lock/p12-planted", "/run/p12-planted",
)  # fmt: skip
# A root plugin that tries to write where it must not, to read the cache and to reach the
# service manager; it prints "root" and nothing else when every attempt fails.
ROOT_WRITER = (
    "#!/bin/sh\n"
    "r=$(id -un)\n"
    f"for p in {' '.join(PLANTED)}; do\n"
    '    if ( : > "$p" ) 2>/dev/null; then r="$r wrote:$p"; fi\n'
    "done\n"
    'if [ -r /run/motp/admin.json ]; then r="$r reads-cache"; fi\n'
    'if systemctl is-system-running >/dev/null 2>&1; then r="$r bus"; fi\n'
    'if [ -S /run/docker.sock ] || [ -S /run/dbus/system_bus_socket ]; then r="$r sockets"; fi\n'
    'echo "$r"\n'
)
LEFT = "/tmp/p12-left /var/tmp/p12-left /dev/shm/p12-left /run/lock/p12-left"  # noqa: S108
PLUGINS = {
    "51-who": '#!/bin/sh\necho "$(id -un) $(id -G)"\n',
    "52-root-writer": ROOT_WRITER,
    "53-hang": "#!/bin/sh\nsleep 60\n",
    "54-root-hang": "#!/bin/sh\nsleep 60\n",
    "55-leave": f'#!/bin/sh\nfor p in {LEFT}; do : > "$p" 2>/dev/null; done\necho left\n',
    "56-look": (
        f"#!/bin/sh\nn=0\nfor p in {LEFT}; do\n"
        '    [ -e "$p" ] && n=$((n + 1))\ndone\necho "seen $n"\n'
    ),
    "57-refused": "#!/bin/sh\necho ran\n",
}
PLUGIN_TABLES = (
    '[plugins."52-root-writer"]\nrun_as = "root"\n'
    '[plugins."54-root-hang"]\nrun_as = "root"\ntimeout_s = 2\n'
)


def plugin_text(modules: dict[str, Any], name: str) -> str:
    items = modules.get(name, {}).get("items", [])
    text = items[0].get("text", {}) if items else {}
    return str(text.get("text", "")) if isinstance(text, dict) else ""


def plugin_groups_stage() -> None:
    """Security review of phase 14: with motp-plugin in another group, systemd's User= would
    hand that group to every plugin, so plugins are refused and doctor names the group.
    Runs after ``plugins_stage``, which removes its plugins, so it puts 51-who back."""
    who = PLUGIN_DIR / "51-who"
    who.write_text(PLUGINS["51-who"])
    os.chmod(who, 0o755)  # noqa: S103  (a plugin is 0755 root)
    sh("gpasswd", "-a", "motp-plugin", "adm")
    try:
        modules: Any = fresh_collection()
        entry = modules.get("51-who", {})
        doctor = sh("/opt/motp/bin/motp", "doctor").stdout
        check("plugin_refused_while_its_account_has_other_groups",
              entry.get("state") == "failed" and not plugin_text(modules, "51-who")
              and "motp-plugin is a member of adm" in doctor,
              f"{entry.get('state')} {entry.get('error', {}).get('id', '')}")  # fmt: skip
    finally:
        sh("gpasswd", "-d", "motp-plugin", "adm")
    modules = fresh_collection()
    again = plugin_text(modules, "51-who")
    check("plugin_runs_again_without_the_group", again.startswith("motp-plugin "), again)
    who.unlink()


def private_modes_stage() -> None:
    """Final review, security item 4: the stricter modes of ``docs/plugins.md`` work, and
    ``motp install`` keeps them. Plugins and the config end the stage as before."""
    import grp

    etc = Path("/etc/motp")
    hello, root_plugin = PLUGIN_DIR / "50-hello", PLUGIN_DIR / "58-root-id"
    shutil.copy2(WORK / "examples/plugins/50-hello", hello)
    root_plugin.write_text("#!/bin/sh\nid -un\n")
    PLUGIN_CONF.write_text('[plugins."58-root-id"]\nrun_as = "root"\n')
    plugin_gid = grp.getgrnam("motp-plugin").gr_gid
    modes = {etc: 0o711, etc / "conf.d": 0o700, etc / "config.toml": 0o600, PLUGIN_CONF: 0o600,
             PLUGIN_DIR: 0o710, hello: 0o750, root_plugin: 0o700}  # fmt: skip
    for path in (PLUGIN_DIR, hello):
        os.chown(path, 0, plugin_gid)
    for path, mode in modes.items():
        os.chmod(path, mode)
    done = install("--no-start")
    kept = [str(p) for p, m in modes.items() if stat.S_IMODE(p.stat().st_mode) != m]
    check("install_keeps_stricter_config_modes", done.returncode == 0 and not kept,
          f"exit {done.returncode} {' '.join(kept)}")  # fmt: skip
    modules: Any = fresh_collection()
    texts = plugin_text(modules, "50-hello"), plugin_text(modules, "58-root-id")
    check("plugins_run_with_private_modes", texts == ("Hello from a plugin", "root"), str(texts))
    nobody = pwd_uid("nobody")
    as_user = sh("/opt/motp/bin/motp", "doctor", user=nobody).stdout
    check("doctor_as_user_says_config_is_root_only", "only root can read /etc/motp" in as_user,
          next((ln for ln in as_user.splitlines() if "config" in ln), ""))  # fmt: skip
    as_root = sh("/opt/motp/bin/motp", "doctor").stdout
    line = next((ln for ln in as_root.splitlines() if "config:" in ln), "")
    check("doctor_as_root_reads_the_private_config",
          line.startswith("[ok] config:") and "no problem" in line, line)  # fmt: skip
    for path in (hello, root_plugin, PLUGIN_CONF):
        path.unlink()
    os.chown(PLUGIN_DIR, 0, 0)
    for path, mode in ((etc, 0o755), (etc / "conf.d", 0o755), (etc / "config.toml", 0o644),
                       (PLUGIN_DIR, 0o755)):  # fmt: skip
        os.chmod(path, mode)


def pwd_uid(name: str) -> int:
    import pwd

    return pwd.getpwnam(name).pw_uid


def plugins_stage() -> None:
    """Phase 12 "Done when", in the unit: users, each plugin in its own unit, the root
    plugin's narrower one, hung plugins, nothing left for the next plugin, refusal,
    visibility, doctor; the capability set and the exposure score after it."""
    shutil.copy2(WORK / "examples/plugins/50-hello", PLUGIN_DIR / "50-hello")
    os.chmod(PLUGIN_DIR / "50-hello", 0o755)  # noqa: S103  (a plugin is 0755 root)
    for name, text in PLUGINS.items():
        (PLUGIN_DIR / name).write_text(text)
        os.chmod(PLUGIN_DIR / name, 0o775 if name == "57-refused" else 0o755)
    PLUGIN_CONF.write_text(PLUGIN_TABLES)
    os.chmod(PLUGIN_CONF, 0o644)
    Path("/run/motd.d").mkdir(mode=0o755, exist_ok=True)
    started = time.monotonic()
    modules: Any = fresh_collection()
    took = time.monotonic() - started
    public = (CACHE / "public.json").read_text()
    hello = plugin_text(modules, "50-hello")
    check("plugin_example_for_admins_only",
          hello == "Hello from a plugin" and "50-hello" not in public, hello)  # fmt: skip
    who = plugin_text(modules, "51-who")
    who_user, *who_groups = who.split() or [""]
    # Security review of phase 14: one group, its own; no supplementary group in the unit.
    check("plugin_runs_as_motp_plugin_with_its_group_only",
          who_user == "motp-plugin" and len(who_groups) == 1, who)  # fmt: skip
    root = plugin_text(modules, "52-root-writer")
    check("root_plugin_runs_as_root_in_its_own_sandbox", root == "root", root)
    planted = [p for p in PLANTED if os.path.lexists(p)]
    check("root_plugin_writes_nothing_of_motp", not planted, " ".join(planted))
    for name in ("53-hang", "54-root-hang"):
        entry = modules.get(name, {})
        error = entry.get("error", {}).get("id", "")
        check(f"hung_plugin_{name}_ends_at_its_limit",
              entry.get("state") == "failed" and error == "collect.error.timeout",
              f"{entry.get('state')} {error} {entry.get('duration_ms')} ms")  # fmt: skip
    check("plugin_run_within_its_budget", took < 60, f"{took:.1f}s")
    others = [n for n, m in modules.items() if "-" not in n and m.get("state") != "ok"]
    check("plugins_keep_the_other_modules", not others, ",".join(others))
    look = plugin_text(modules, "56-look")
    check("plugin_files_swept_before_the_next", look == "seen 0", look)
    refused = modules.get("57-refused", {})
    reason = refused.get("error", {}).get("id", "")
    check("refused_plugin_never_ran",
          refused.get("state") == "failed" and not refused.get("items")
          and reason == "safepath.error.writable", reason)  # fmt: skip
    leftover = sh("pgrep", "-u", "motp-plugin").stdout.split()
    check("no_plugin_process_left", not leftover, " ".join(leftover))
    deadline = time.monotonic() + 15
    units = ""
    while time.monotonic() < deadline:
        units = sh("systemctl", "list-units", "--all", "--plain", "--no-legend",
                   "motp-plugin-*").stdout.strip()  # fmt: skip
        if not units:
            break
        time.sleep(1)
    check("plugin_units_gone", not units, units[:200])
    doctor = sh("/opt/motp/bin/motp", "doctor").stdout
    print(doctor, flush=True)
    check("doctor_lists_plugins",
          "plugin 57-refused: refused" in doctor
          and "plugin 51-who: runs as motp-plugin" in doctor
          and "plugin 52-root-writer: runs as root" in doctor, "")  # fmt: skip
    caps = sh("systemctl", "show", "-p", "CapabilityBoundingSet", "--value", "motp-collect.service")
    got = set(caps.stdout.split())
    check("plugins_keep_the_capability_set", got == CAPABILITIES, " ".join(sorted(got)))
    sec = sh("systemd-analyze", "security", "--no-pager", "motp-collect.service").stdout
    score = re.search(r"Overall exposure level for \S+: ([0-9.]+)", sec)
    value = float(score.group(1)) if score else None
    check("plugins_exposure_score", value is not None and value <= SCORE_LIMIT, str(value))
    journal = sh("journalctl", "-u", "motp-collect.service", "-o", "cat", "--no-pager").stdout
    named = [n for n in (*PLUGINS, "50-hello") if n in journal]
    check("journal_has_no_plugin_name", not named, ",".join(named))
    for plugin in PLUGIN_DIR.iterdir():
        plugin.unlink()
    PLUGIN_CONF.unlink()
    for planted_path in PLANTED:
        Path(planted_path).unlink(missing_ok=True)


def foreign_account(path: Path, original: str) -> None:
    """Final review, security item 1: a manifest that lists an account other than MOTP's
    own is refused as a whole, so uninstall deletes neither that account nor anything else."""
    victim_user = "motp-victim"
    sh("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", victim_user)
    uid, gid = (
        sh("id", "-u", victim_user).stdout.strip(),
        sh("id", "-g", victim_user).stdout.strip(),
    )
    doc = json.loads(original)
    doc["accounts"].append({"name": victim_user, "uid": int(uid or 0), "gid": int(gid or 0)})
    path.write_text(json.dumps(doc))
    os.chmod(path, 0o600)
    refused = sh("/usr/bin/python3", "-I", "-S", str(PYZ), "uninstall")
    print(refused.stdout, flush=True)
    kept = sh("id", "-u", victim_user).returncode == 0 and Path("/opt/motp/lib/motp").is_dir()
    check(
        "foreign_account_in_manifest_is_refused",
        refused.returncode != 0 and kept and uid != "",
        f"exit {refused.returncode} uid {uid or '?'}",
    )
    sh("userdel", victim_user)
    path.write_text(original)
    os.chmod(path, 0o600)


def tampered() -> None:
    """T25 on the real system: forged entries and a swapped link delete nothing outside."""
    done = install("--no-start")
    check("reinstall", done.returncode == 0, f"exit {done.returncode}")
    decoy = Path("/etc/motp-decoy")
    decoy.write_text("keep me\n")
    trap = Path("/etc/motp-trap")
    trap.mkdir()
    victim = trap / "cli.py"
    shutil.copy2("/opt/motp/lib/motp/cli.py", victim)
    import hashlib

    digest = hashlib.sha256(b"keep me\n").hexdigest()
    path = STATE / "install-manifest.json"
    original = path.read_text()
    foreign_account(path, original)
    doc = json.loads(original)
    doc["entries"] += [
        {"path": str(decoy), "kind": "file", "role": "program", "sha256": digest},
        {"path": "/opt/motp/../etc/motp-decoy", "kind": "file", "role": "program",
         "sha256": digest},
        {"path": "/etc/passwd", "kind": "file", "role": "program",
         "sha256": hashlib.sha256(Path("/etc/passwd").read_bytes()).hexdigest()},
        {"path": "/etc", "kind": "dir", "role": "program"},
    ]  # fmt: skip
    path.write_text(json.dumps(doc))
    os.chmod(path, 0o600)
    Path("/opt/motp/lib/motp").rename("/opt/motp/lib/motp-moved")
    os.symlink(trap, "/opt/motp/lib/motp")
    gone = sh("/usr/bin/python3", "-I", "-S", str(PYZ), "uninstall")
    print(gone.stdout, flush=True)
    root_entry = Path("/etc/passwd").read_text().startswith("root:")
    kept = decoy.exists() and victim.exists() and root_entry and Path("/etc/motp-trap").is_dir()
    check(
        "tampered_manifest_deletes_nothing_outside",
        gone.returncode == 1 and kept,
        f"exit {gone.returncode}",
    )


def main() -> int:
    part = sys.argv[1] if len(sys.argv) > 1 else ""
    if part == "before":
        before()
    elif part == "after":
        after()
    else:
        print("usage: checks.py before|after", file=sys.stderr)
        return 2
    print(f"CHECKS-DONE failures={failures}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

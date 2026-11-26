#!/usr/bin/env python3
"""The level-3 login checks inside a login test container (blueprint 7.1, phase 8).

Run by ``tools/login_test.py`` with ``podman exec`` as root, after the container booted
with systemd as its first process. Every login goes over SSH to the container's own sshd
(``127.0.0.1``, the container's network), with a key pair made here at test time; no key
leaves the container. Users: ``motp-user`` (bash, no admin rights), ``motp-admin`` (bash,
in the admin group the installer picks), ``motp-zsh`` and ``motp-fish``. The rc snippets of
``motp shell-init`` are in their rc files, so every login also shows that the hook and the
snippet together print the message once.

Checks (each prints ``CHECK <name> PASS|FAIL <detail>``; the host counts them):

- before install: a baseline login per user (time, output);
- package modules (phase 9): with a pending update, every user sees the count and only the
  admin a package name; after ``/run/reboot-required`` is created, the timer's own next run
  puts the reboot line into the attention block of a login;
- service and login modules (phase 10): a unit that fails shows as a count for the
  unprivileged user and by name for the admin, a ``[[rows.unit]]`` row shows its state;
  a second login shows the first one's time as the previous login; the per-user file is
  root's with one ACL reader, readable over SSH by its user and refused to another;
- hybrid mode: the MOTD appears exactly once per login for every user and shell; the
  admin sees the admin-only fixture (a per-user mount), the unprivileged user does not;
  ``ssh host true`` and ``ssh host echo`` print nothing extra; scp (both protocols), sftp
  and rsync work; non-interactive ``bash``, ``zsh`` and ``fish`` with the rc snippets print
  nothing, also with a terminal; the hook keeps the terminal (O11);
- languages (phase 13): a login that sends a German ``LANG`` gets German, another
  user with an English one gets English, and ``motp explain`` speaks German too;
- robustness: with the collector stopped and the cache removed the login shows live
  values; with the cache unreadable or corrupt, with ``motp`` removed, with a hostile
  ``TERM`` and locale, the login reaches the prompt without an error line and without a
  measurable delay; a hung program is ended by the hook's limit;
- static mode: the file under ``/run/motd.d`` holds no escape byte and none of the admin
  fixture, one SSH login prints it once, ``ssh host true`` stays silent, the unit passes
  ``systemd-analyze verify``; O13 (does pam_motd read drop-ins with the user's rights);
- security modules (phase 11): fail2ban with the dummy ban action and three banned
  documentation addresses, real failed SSH logins from a documentation address on the
  loopback device, a stand-in for Docker's socket; the unprivileged user sees the counts
  and none of the addresses, jail or container names, images or the firewall row, the
  admin sees them; ``public.json`` and ``render.json`` hold none of them; no file under
  ``/run/motp`` holds an attempted user name; with the runtime hung, a login is as fast
  as before and the module fails within its limit;
- exec plugins (phase 12): the three-line example shows for the admin and not for the
  unprivileged user; a plugin's escape sequences never reach the SSH stream and its rows
  carry the prefix; with a plugin that sleeps 60 s, logins during a collector run stay
  within 0.5 s of a normal login and the run ends within its budget; in static mode a
  root plugin cannot write into ``/run/motd.d``;
- ``motp uninstall``: the next login shows nothing and no error.

A status line goes out at least every ``HEARTBEAT_SECONDS``.
"""

import grp
import json
import os
import re
import shutil
import stat
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

WORK = Path("/work")
PYZ = WORK / "dist" / "motp.pyz"
CACHE = Path("/run/motp")
MOTD_FILE = Path("/run/motd.d/10-motp")
KEY = Path("/root/.ssh/motp_test_key")
KNOWN = Path("/root/.ssh/motp_known_hosts")
HOST = "127.0.0.1"
HEARTBEAT_SECONDS = 15.0
USERS = {"motp-user": "bash", "motp-admin": "bash", "motp-zsh": "zsh", "motp-fish": "fish"}
ADMIN_LABEL = "QZADM"  # a per-user mount: admin tier only (5.4, T26)
ADMIN_MOUNT = Path("/media/q") / ADMIN_LABEL  # short: the row label is cut at its width
PROMPT = "MOTP-PROMPT-OK"
# One line of every rendered message: the label of the uptime row (a live value, so it
# shows without any cache too).
MOTD_MARK = re.compile(r"Uptime[ .:]")
REBOOT_FLAG = Path("/run/reboot-required")
REBOOT_LINE = re.compile(r"Reboot required[^\n]*sudo reboot")
TIMER_LIMIT = 420.0  # one timer period of 5 minutes, its accuracy and the run
ERROR_WORDS = ("Traceback", "rror", "No such file", "not found", "denied", "motp:")
DELAY_LIMIT = 0.3  # seconds a robustness login may take beyond a normal one
RUNS = 3
SSH_OPTS = (
    "-i", str(KEY), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
    "-o", f"UserKnownHostsFile={KNOWN}", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
)  # fmt: skip

failures = 0
_last_status = time.monotonic()


def check(name: str, ok: bool, detail: str = "") -> bool:
    global failures
    if not ok:
        failures += 1
    detail = " ".join(detail.split())[:300]
    print(f"CHECK {name} {'PASS' if ok else 'FAIL'} {detail}".rstrip(), flush=True)
    return ok


def note(name: str, detail: str) -> None:
    print(f"NOTE {name} {detail}", flush=True)


def stage(name: str) -> None:
    print(f"MOTP-STAGE {name}", flush=True)


def heartbeat(what: str) -> None:
    global _last_status
    if time.monotonic() - _last_status >= HEARTBEAT_SECONDS:
        _last_status = time.monotonic()
        print(f"progress: login stage={what} failures={failures}", flush=True)


def sh(*argv: str, timeout: float = 300, **kw: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # type: ignore[call-overload,no-any-return]
        list(argv), capture_output=True, text=True, timeout=timeout, check=False, **kw
    )


# --- setup ------------------------------------------------------------------------------


def admin_group() -> str:
    for name in ("sudo", "wheel"):
        try:
            grp.getgrnam(name)
            return name
        except KeyError:
            continue
    raise SystemExit("no sudo or wheel group")


def setup() -> None:
    stage("copy")
    shutil.copytree(
        "/src",
        WORK,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache",
            "dist", "scratch", "*.mo", "*.pyc", ".env*",
        ),
    )  # fmt: skip
    stage("build")
    built = sh("/usr/bin/python3", "-I", str(WORK / "tools/build_pyz.py"), "--output", str(PYZ))
    check("build", built.returncode == 0, built.stdout.strip()[:80] or built.stderr[-300:])

    stage("sshd")
    sh("ssh-keygen", "-A")
    unit = "ssh.service" if Path("/lib/systemd/system/ssh.service").exists() else "sshd.service"
    if not Path(f"/lib/systemd/system/{unit}").exists():
        unit = "sshd.service"
    sh("systemctl", "reset-failed", unit)  # the boot-time start had no host keys
    started = sh("systemctl", "restart", unit)
    check("sshd_started", started.returncode == 0, unit + " " + started.stderr[-200:])
    KEY.parent.mkdir(mode=0o700, exist_ok=True)
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(KEY))
    scan = ""
    for _ in range(30):
        scan = sh("ssh-keyscan", "-T", "3", HOST).stdout
        if scan.strip():
            break
        time.sleep(1)
    KNOWN.write_text(scan)

    stage("users")
    group = admin_group()
    for user, shell in USERS.items():
        path = shutil.which(shell) or f"/bin/{shell}"
        extra = ["-G", group] if user == "motp-admin" else []
        sh("useradd", "-m", "-s", path, *extra, user)
        sh("usermod", "-p", "*", user)  # no password, not locked: key login only
        home = Path(f"/home/{user}")
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        (ssh_dir / "authorized_keys").write_text(Path(str(KEY) + ".pub").read_text())
        rc = {"bash": ".bashrc", "zsh": ".zshrc", "fish": ".config/fish/config.fish"}[shell]
        rc_path = home / rc
        rc_path.parent.mkdir(parents=True, exist_ok=True)
        if rc_path.exists():
            rc_path.write_text(rc_path.read_text() + "\n")
        else:
            rc_path.write_text("")
        sh("chown", "-R", f"{user}:{user}", str(home))
    # login_test.py mounts a Podman volume (a local file system) there: a per-user mount.
    mounts = Path("/proc/self/mountinfo").read_text()
    check("admin_fixture_mounted", f" {ADMIN_MOUNT} " in mounts, str(ADMIN_MOUNT))


def pending_update() -> None:
    """Test setup only, with the container's network: package lists (MOTP never fetches
    them, D28) and, on Debian and Ubuntu, one installed version made slightly older in
    dpkg's status file so that an update is pending."""
    stage("package-lists")
    if Path("/usr/bin/apt-get").exists():
        done = sh("apt-get", "update", "-qq", timeout=600)
        status = Path("/var/lib/dpkg/status")
        text = status.read_text()
        older = re.sub(r"(?m)^(Package: tar\n(?:.+\n)*?Version: .*)$", r"\1~0", text)
        status.write_text(older)
        check("test_setup_pending_update", older != text and done.returncode == 0)
    else:
        done = sh("dnf", "-q", "makecache", timeout=600)
        check("test_setup_pending_update", done.returncode == 0, done.stderr[-200:])


def cached_items(module: str) -> list[dict[str, object]]:
    try:
        admin = json.loads((CACHE / "admin.json").read_text())
    except (OSError, ValueError):
        return []
    return admin["modules"].get(module, {}).get("items", [])  # type: ignore[no-any-return]


def screen(user: str) -> str:
    """A login's output without terminal escape sequences."""
    out = login(user).out
    return re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[A-Za-z]", "", out)


def package_health() -> None:
    stage("package-health")
    items = cached_items("os_updates")
    count = items[0].get("value") if items else None
    note("pending_updates", str(count))
    if isinstance(count, int) and count > 0:
        details = {d["key"]: d["value"] for d in items[0].get("detail", [])}  # type: ignore[attr-defined]
        name = str(details.get("os_updates.packages", "")).split(",")[0]
        plain, admin = screen("motp-user"), screen("motp-admin")
        counted = re.compile(rf"\b{count} updates?\b")
        check(
            "user_sees_the_count_and_no_package_name",
            bool(name) and bool(counted.search(plain)) and "Packages" not in plain,
            f"count={count}",
        )
        check(
            "admin_sees_a_package_name",
            bool(name) and "Packages" in admin and name in admin,
        )
        public = (CACHE / "public.json").read_text()
        check("public_cache_has_no_package_detail", "os_updates.packages" not in public)
    else:
        check("pending_update_is_counted", False, f"count={count}")
    for module in ("os_reboot", "os_eol", "os_autoupdates"):
        note(module, json.dumps([i.get("value") for i in cached_items(module)]))

    # The reboot line: absent, then the flag, then one run of the timer's own.
    before = screen("motp-user")
    check("no_reboot_line_without_the_flag", not REBOOT_LINE.search(before))
    REBOOT_FLAG.write_text("*** System restart required ***\n")
    Path(str(REBOOT_FLAG) + ".pkgs").write_text("linux-image-qzflag\n\x1b[31mhostile\n")
    started = time.monotonic()
    while time.monotonic() - started < TIMER_LIMIT:
        found = cached_items("os_reboot")
        if found and found[0].get("value") is True:
            break
        heartbeat("waiting-for-the-timer")
        time.sleep(2)
    waited = time.monotonic() - started
    shown = screen("motp-user")
    attention = shown.split("Attention", 1)[-1].split("Host", 1)[0]
    check(
        "reboot_line_in_attention_after_one_timer_run",
        "Attention" in shown and bool(REBOOT_LINE.search(attention)),
        f"after {waited:.0f}s",
    )
    admin = screen("motp-admin")
    check(
        "reboot_packages_for_admins_only",
        "linux-image-qzflag" in admin and "linux-image-qzflag" not in shown,
    )
    check("hostile_flag_list_is_inert", "hostile" not in admin and "\x1b" not in admin)
    REBOOT_FLAG.unlink()
    Path(str(REBOOT_FLAG) + ".pkgs").unlink()


def add_rc_snippets() -> None:
    """``motp shell-init`` output into the rc files of all users but the admin."""
    for user, shell in USERS.items():
        if user == "motp-admin":
            continue
        snippet = sh("/opt/motp/bin/motp", "shell-init", shell).stdout
        rc = {"bash": ".bashrc", "zsh": ".zshrc", "fish": ".config/fish/config.fish"}[shell]
        path = Path(f"/home/{user}") / rc
        path.write_text(path.read_text() + snippet)
        check(f"shell_init_{shell}_{user}", "/opt/motp/bin/motp show" in snippet, rc)


# --- logins -----------------------------------------------------------------------------


class Login:
    def __init__(self, out: str, seconds: float, code: int) -> None:
        self.out = out
        self.seconds = seconds
        self.code = code

    @property
    def motd_count(self) -> int:
        return len(MOTD_MARK.findall(self.out))

    @property
    def prompt(self) -> bool:
        # The command echoed by the terminal and its output: at least two.
        return self.out.count(PROMPT) >= 2


def login(
    user: str,
    commands: str = "",
    term: str = "xterm-256color",
    env: Optional[dict[str, str]] = None,
    timeout: float = 60,
) -> Login:
    """An interactive login over SSH with a terminal (``ssh -tt``); the commands typed
    ahead run at the prompt, then ``exit``."""
    argv = ["ssh", "-tt", *SSH_OPTS]
    child_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TERM": term, "HOME": "/root"}
    if env:
        argv += ["-o", "SendEnv=" + " ".join(env)]
        child_env.update(env)
    argv.append(f"{user}@{HOST}")
    typed = f"{commands}echo {PROMPT}; exit\n"
    started = time.monotonic()
    try:
        done = subprocess.run(
            argv,
            input=typed,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=child_env,
            check=False,
        )
        code, out = done.returncode, done.stdout + done.stderr
    except subprocess.TimeoutExpired as exc:
        code = -1
        raw = exc.stdout or b""
        out = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    heartbeat("login")
    return Login(out.replace("\r", ""), time.monotonic() - started, code)


def logins(user: str, runs: int = RUNS, **kw: object) -> tuple[Login, float]:
    """``runs`` logins; the last one and the median time."""
    done = [login(user, **kw) for _ in range(runs)]  # type: ignore[arg-type]
    return done[-1], statistics.median(d.seconds for d in done)


def error_lines(out: str, baseline: str) -> list[str]:
    known = set(baseline.splitlines())
    return [
        ln for ln in out.splitlines() if ln not in known and any(word in ln for word in ERROR_WORDS)
    ]


def ssh_cmd(user: str, *command: str, timeout: float = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["ssh", *SSH_OPTS, f"{user}@{HOST}", *command],
        capture_output=True,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
    )


# --- the parts --------------------------------------------------------------------------


baseline: dict[str, Login] = {}
base_time: dict[str, float] = {}


def before_install() -> None:
    stage("baseline")
    for user in USERS:
        last, median = logins(user)
        baseline[user], base_time[user] = last, median
        check(
            f"baseline_login_{user}",
            last.prompt and last.motd_count == 0,
            f"{median:.2f}s exit={last.code}",
        )


def install_hybrid() -> None:
    stage("install")
    done = sh("/usr/bin/python3", "-I", "-S", str(PYZ), "install")
    print(done.stdout, done.stderr, flush=True)
    check("install_hybrid", done.returncode == 0, f"exit {done.returncode}")
    hook = Path("/etc/profile.d/motp.sh")
    check("hook_installed", hook.is_file() and oct(hook.stat().st_mode)[-3:] == "644")
    uses_timeout = "--foreground" in hook.read_text()
    check("o11_hook_uses_timeout", uses_timeout, "GNU timeout --foreground accepted")
    zsh_files = [p for p in (Path("/etc/zsh/zprofile"), Path("/etc/zprofile")) if p.exists()]
    blocks = {str(p): "# BEGIN motp" in p.read_text() for p in zsh_files}
    note("o10_zprofile", json.dumps(blocks))
    add_rc_snippets()
    ran = sh("systemctl", "start", "motp-collect.service", timeout=200)
    check("collector_ran", ran.returncode == 0 and (CACHE / "public.json").exists())


def hybrid_logins() -> dict[str, float]:
    stage("hybrid-logins")
    normal: dict[str, float] = {}
    for user in USERS:
        last, median = logins(user)
        normal[user] = median
        errors = error_lines(last.out, baseline[user].out)
        check(
            f"motd_once_{user}",
            last.prompt and last.motd_count == 1 and not errors,
            f"count={last.motd_count} {median:.2f}s (baseline {base_time[user]:.2f}s) {errors}",
        )
    admin = login("motp-admin")
    plain = login("motp-user")
    check(
        "admin_sees_admin_detail_user_does_not",
        ADMIN_LABEL in admin.out and ADMIN_LABEL not in plain.out,
        f"admin={ADMIN_LABEL in admin.out} user={ADMIN_LABEL in plain.out}",
    )
    # O11: after the hook ran under timeout --foreground the shell still runs jobs in the
    # foreground of its terminal (ps sees its own group as the terminal's), and the
    # terminal is in its normal mode.
    fg = login("motp-user", commands="sh -c 'exec ps -o pgid= -o tpgid= -p $$'; stty -a; ")
    # Fedora's profile.d wraps commands in OSC 3008 context sequences: drop escapes first.
    bare = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[A-Za-z]", "", fg.out)
    pairs = re.findall(r"^\s*(\d+)\s+(\d+)\s*$", bare, re.M)
    in_front = bool(pairs) and all(a == b for a, b in pairs)
    sane = " icanon" in fg.out and " echo" in fg.out
    check("o11_terminal_kept", fg.prompt and in_front and sane, f"pgid/tpgid={pairs}")
    return normal


GERMAN_MARK = re.compile(r"Laufzeit[ .:]")


def languages() -> None:
    """The reader's own locale picks the language (D19): over SSH the client sends LANG,
    which the test images' sshd accepts (``prepare.sh`` adds that where the image's
    configuration lacks it). MOTP itself needs only the variable and
    its catalogue; Debian passes it on without a German system locale. The RHEL family
    resets a LANG without an installed locale to C.UTF-8 in its own login scripts, so
    its test image installs the German language pack."""
    stage("languages")
    german = login("motp-user", env={"LANG": "de_DE.UTF-8"})
    english = login("motp-admin", env={"LANG": "en_US.UTF-8"})
    check(
        "german_locale_gets_german",
        german.prompt
        and len(GERMAN_MARK.findall(german.out)) == 1
        and german.motd_count == 0
        and "Rechner" in german.out,
        f"german={len(GERMAN_MARK.findall(german.out))} english={german.motd_count}",
    )
    check(
        "other_locale_gets_english",
        english.prompt and english.motd_count == 1 and not GERMAN_MARK.search(english.out),
        f"english={english.motd_count}",
    )
    got = ssh_cmd("motp-user", "LANG=de_DE.UTF-8 /opt/motp/bin/motp explain load")
    unknown = ssh_cmd("motp-user", "/opt/motp/bin/motp explain nothing")
    check(
        "explain_over_ssh",
        got.returncode == 0 and got.stdout.startswith(b"Auslastung") and unknown.returncode == 2,
        f"exit={got.returncode}/{unknown.returncode} {got.stdout[:40]!r}",
    )


def quiet_sessions() -> None:
    stage("non-interactive")
    for user in USERS:
        done = ssh_cmd(user, "true")
        check(
            f"ssh_true_silent_{user}",
            done.returncode == 0 and done.stdout == b"" and done.stderr == b"",
            f"exit={done.returncode} out={done.stdout[:60]!r} err={done.stderr[:60]!r}",
        )
        echo = ssh_cmd(user, "echo", "x")
        check(f"ssh_echo_exact_{user}", echo.stdout == b"x\n", repr(echo.stdout[:60]))
    data = os.urandom(200_000)
    src = Path("/root/motp-transfer.bin")
    src.write_bytes(data)
    target = f"motp-user@{HOST}"
    for name, argv in (
        ("scp", ["scp", *SSH_OPTS, str(src), f"{target}:copy-scp.bin"]),
        ("scp_legacy", ["scp", "-O", *SSH_OPTS, str(src), f"{target}:copy-scp-o.bin"]),
        ("rsync", ["rsync", "-a", "-e", "ssh " + " ".join(SSH_OPTS), str(src),
                   f"{target}:copy-rsync.bin"]),
    ):  # fmt: skip
        moved = sh(*argv, timeout=120)
        remote = Path("/home/motp-user") / argv[-1].split(":")[1]
        ok = moved.returncode == 0 and remote.exists() and remote.read_bytes() == data
        check(f"{name}_works", ok, moved.stderr[-200:])
    batch = Path("/root/motp-sftp.batch")
    batch.write_text(f"put {src} copy-sftp.bin\nget copy-sftp.bin /root/motp-back.bin\n")
    fetched = sh("sftp", "-b", str(batch), *SSH_OPTS, target, timeout=120)
    back = Path("/root/motp-back.bin")
    check(
        "sftp_works",
        fetched.returncode == 0 and back.exists() and back.read_bytes() == data,
        fetched.stderr[-200:],
    )
    # Non-interactive shells with the rc snippets: nothing, also with a terminal.
    cases = {
        "bash": "BASH_ENV=$HOME/.bashrc bash -c true",
        "zsh": "zsh -c 'source ~/.zshrc'",
        "fish": "fish -c true",
    }
    owner = {"bash": "motp-user", "zsh": "motp-zsh", "fish": "motp-fish"}
    for shell, command in cases.items():
        plain = sh("su", "-", owner[shell], "-c", command)
        check(
            f"non_interactive_{shell}_silent",
            plain.returncode == 0 and plain.stdout == "" and plain.stderr == "",
            f"{plain.stdout[:60]!r} {plain.stderr[:60]!r}",
        )
        tty = sh("su", "-", owner[shell], "-c", f'script -qec "{command}" /dev/null')
        check(
            f"non_interactive_{shell}_on_a_tty_silent",
            tty.returncode == 0 and tty.stdout.strip() == "",
            repr(tty.stdout[:80]),
        )


def robustness(normal: dict[str, float]) -> None:
    stage("robustness")
    user = "motp-user"
    limit = normal[user] + DELAY_LIMIT

    def scenario(name: str, expect_motd: bool, own_baseline: bool = False, **kw: object) -> None:
        known = baseline[user].out
        if own_baseline:  # what the system's own shells print for this login, without MOTP
            hook = Path("/etc/profile.d/motp.sh")
            hook.rename(hook.with_suffix(".off"))
            try:
                known += "\n" + login(user, **kw).out  # type: ignore[arg-type]
            finally:
                hook.with_suffix(".off").rename(hook)
        last, median = logins(user, **kw)  # type: ignore[arg-type]
        errors = error_lines(last.out, known)
        shown = last.motd_count == 1 if expect_motd else last.motd_count == 0
        check(
            f"login_{name}",
            last.prompt and shown and not errors and median <= limit,
            f"count={last.motd_count} {median:.2f}s limit={limit:.2f}s {errors[:2]}",
        )

    sh("systemctl", "stop", "motp-collect.timer", "motp-collect.service")
    for name in ("public.json", "admin.json", "render.json"):
        (CACHE / name).unlink(missing_ok=True)
    scenario("cache_missing_shows_live_values", True)

    sh("systemctl", "start", "motp-collect.service", timeout=200)
    for name in ("public.json", "render.json"):
        os.chmod(CACHE / name, 0o600)
    scenario("cache_unreadable", True)
    for name in ("public.json", "admin.json", "render.json"):
        (CACHE / name).write_bytes(b'{"api": 1, "broken": [' + os.urandom(64))
        os.chmod(CACHE / name, 0o644)
    scenario("cache_corrupt", True)

    sh("systemctl", "start", "motp-collect.service", timeout=200)
    scenario("hostile_term", True, term="\x1b]0;pwned\x07xterm")
    # bash (and Fedora's sh) warn about the bogus locale themselves; only lines that a login
    # without MOTP does not print count against MOTP (seen on debian:13 and fedora:45).
    hostile = {"LANG": "xx_YY.bogus@x", "LC_ALL": "zz.ÿ"}
    scenario("hostile_locale", True, own_baseline=True, env=hostile)

    wrapper = Path("/opt/motp/bin/motp")
    wrapper.rename("/opt/motp/bin/motp.away")
    try:
        scenario("motp_removed", False)
    finally:
        Path("/opt/motp/bin/motp.away").rename(wrapper)

    python_gone = Path("/opt/motp/lib/__main__.py")
    python_gone.rename("/opt/motp/lib/__main__.away")
    try:
        scenario("program_tree_broken", False)
    finally:
        Path("/opt/motp/lib/__main__.away").rename(python_gone)

    # A program that hangs: the hook's outer limit (timeout) ends it.
    saved = wrapper.read_bytes()
    wrapper.write_text("#!/bin/sh\nexec sleep 120\n")
    try:
        hung = login(user, timeout=60)
        check(
            "hung_program_ended_by_the_hook_limit",
            hung.prompt and hung.motd_count == 0 and hung.seconds < 11 + 1 + normal[user] + 2,
            f"{hung.seconds:.1f}s",
        )
    finally:
        wrapper.write_bytes(saved)
        os.chmod(wrapper, 0o755)  # noqa: S103  (the installed wrapper's own mode)
    sh("systemctl", "start", "motp-collect.timer")


def static_mode() -> None:
    stage("static")
    gone = sh("/opt/motp/bin/motp", "uninstall")
    check("uninstall_before_static", gone.returncode == 0, gone.stdout[-200:])
    conf = Path("/etc/motp/config.toml")
    conf.write_text(conf.read_text().replace('# mode = "hybrid"', 'mode = "static"'))
    done = sh("/usr/bin/python3", "-I", "-S", str(PYZ), "install", "--mode", "static")
    print(done.stdout, done.stderr, flush=True)
    check("install_static", done.returncode == 0, f"exit {done.returncode}")
    check("static_no_hook", not Path("/etc/profile.d/motp.sh").exists())
    verify = sh(
        "systemd-analyze",
        "verify",
        "/etc/systemd/system/motp-collect.service",
        "/etc/systemd/system/motp-collect.timer",
    )
    noise = (verify.stdout + verify.stderr).strip()
    check("static_unit_verifies", verify.returncode == 0 and not noise, noise[:200])
    sec = sh("systemd-analyze", "security", "--no-pager", "motp-collect.service").stdout
    score = re.search(r"Overall exposure level for \S+: ([0-9.]+)", sec)
    value = float(score.group(1)) if score else None
    check("static_exposure_score", value is not None and value <= 3.0, str(value))
    ran = sh("systemctl", "start", "motp-collect.service", timeout=200)
    data = MOTD_FILE.read_bytes() if MOTD_FILE.exists() else b""
    st = MOTD_FILE.stat() if MOTD_FILE.exists() else None
    check(
        "static_file_written",
        ran.returncode == 0 and bool(data) and st is not None and oct(st.st_mode)[-3:] == "644",
        f"{len(data)} bytes",
    )
    admin_json = (CACHE / "admin.json").read_bytes()
    escape = b"\x1b" in data
    label = ADMIN_LABEL.encode()
    check(
        "static_file_plain_and_public",
        not escape and label not in data and label in admin_json,
        f"escape={escape} admin_label_in_file={label in data} in_admin={label in admin_json}",
    )
    for user in USERS:
        last = login(user)
        errors = error_lines(last.out, baseline[user].out)
        check(
            f"static_motd_once_{user}",
            last.prompt and last.motd_count == 1 and ADMIN_LABEL not in last.out and not errors,
            f"count={last.motd_count} {errors[:2]}",
        )
        quiet = ssh_cmd(user, "true")
        check(
            f"static_ssh_true_silent_{user}",
            quiet.stdout == b"" and quiet.stderr == b"" and quiet.returncode == 0,
            repr(quiet.stdout[:60]),
        )
    # O13: does pam_motd read drop-ins with the user's rights?
    private = Path("/run/motd.d/05-motp-o13-private")
    public = Path("/run/motd.d/06-motp-o13-public")
    private.write_text("MOTP-O13-PRIVATE\n")
    os.chmod(private, 0o600)
    public.write_text("MOTP-O13-PUBLIC\n")
    os.chmod(public, 0o644)
    seen = login("motp-user").out
    private_shown = "MOTP-O13-PRIVATE" in seen
    public_shown = "MOTP-O13-PUBLIC" in seen
    note("o13_pam_motd", f"private_0600_shown={private_shown} public_0644_shown={public_shown}")
    check("o13_public_dropin_shown", "MOTP-O13-PUBLIC" in seen)
    private.unlink()
    public.unlink()


# --- phase 12: exec plugins over SSH -----------------------------------------------------

PLUGIN_DIR = Path("/etc/motp/plugins.d")
PLUGIN_CONF = Path("/etc/motp/conf.d/60-p12-plugins.toml")
HELLO_TEXT = "Hello from a plugin"
# A line plugin whose output carries escape sequences of its own, marked so they can be
# told from the theme's colours on the SSH stream, and a catalogue id as its text.
HOSTILE = (
    "#!/bin/sh\n"
    "printf '\\033]0;p12owned\\007\\033[2Jp12-evil label.updates \\033[31mred\\n'\n"
    "exit 2\n"
)
HANG_SECONDS = 60
STATIC_PLANT = Path("/run/motd.d/05-p12-planted")


def put_plugin(name: str, text: str) -> None:
    path = PLUGIN_DIR / name
    path.write_text(text)
    os.chmod(path, 0o755)  # noqa: S103  (an installed plugin: root's, 0755)


def plugins_over_ssh(normal: dict[str, float]) -> None:
    """Phase 12 "Done when" over SSH: the three-line example for the admin only, hostile
    output inert on the SSH stream, and a plugin that sleeps 60 s costing no login time."""
    stage("plugins")
    shutil.copy2(WORK / "examples/plugins/50-hello", PLUGIN_DIR / "50-hello")
    os.chmod(PLUGIN_DIR / "50-hello", 0o755)  # noqa: S103
    put_plugin("51-hostile", HOSTILE)
    collect_now()
    admin, user = login("motp-admin"), login("motp-user")
    check(
        "plugin_example_admin_sees_it",
        "[plugin 50-hello]" in admin.out and HELLO_TEXT in admin.out,
        f"prefix={'[plugin 50-hello]' in admin.out} text={HELLO_TEXT in admin.out}",
    )
    check(
        "plugin_example_unprivileged_user_does_not",
        HELLO_TEXT not in user.out and "50-hello" not in user.out and "p12-evil" not in user.out,
    )
    evil = [ln for ln in admin.out.splitlines() if "p12-evil" in ln]
    raw = "".join(evil)
    check(
        "plugin_escapes_inert_on_the_ssh_stream",
        bool(evil)
        and all("[plugin 51-hostile]" in ln for ln in evil)
        # The escape bytes are gone; what printable text remains ("]0;p12owned") is inert.
        # The shell's own prompt may set the title (Debian's bashrc), so only the plugin's
        # marked sequence counts.
        and "\x1b]0;p12owned" not in admin.out
        and "\x1b]" not in raw
        and "\x1b[2J" not in admin.out
        and "\x1b[31m" not in raw
        and "\x07" not in raw,
        repr(raw[:160]),
    )
    check("plugin_catalogue_id_stays_text", "label.updates" in raw, repr(raw[:120]))

    # A plugin that sleeps 60 seconds: logins during a collector run are as fast as
    # without it, and the run ends within its budget with the other rows intact.
    put_plugin("52-hang", f"#!/bin/sh\nsleep {HANG_SECONDS}\n")
    Path("/var/lib/motp/state.json").unlink(missing_ok=True)
    started = time.monotonic()
    sh("systemctl", "start", "--no-block", "motp-collect.service")
    last, median = logins("motp-user")
    limit = normal["motp-user"] + 0.5
    check(
        "hung_plugin_costs_no_login_time",
        last.prompt and last.motd_count == 1 and median <= limit,
        f"{median:.2f}s limit={limit:.2f}s",
    )
    while time.monotonic() - started < 120:
        state = sh("systemctl", "is-active", "motp-collect.service").stdout.strip()
        if state not in ("activating", "active"):
            break
        heartbeat("plugin-run")
        time.sleep(0.5)
    took = time.monotonic() - started
    modules = json.loads((CACHE / "admin.json").read_text())["modules"]
    hang = modules.get("52-hang", {})
    others = [n for n, m in modules.items() if n != "52-hang" and m.get("state") != "ok"]
    check(
        "hung_plugin_run_ends_within_its_budget",
        hang.get("state") == "failed"
        and hang.get("error", {}).get("id") == "collect.error.timeout"
        and took < 60
        and not others,
        f"run={took:.1f}s others_failed={others}",
    )
    for plugin in PLUGIN_DIR.iterdir():
        plugin.unlink()
    collect_now()


def static_root_plugin() -> None:
    """Static mode (phase 8 issue): a root plugin cannot put a file in front of pam_motd,
    and an admin-only plugin's text stays out of the static file."""
    stage("static-root-plugin")
    writer = (
        f"#!/bin/sh\nif ( : > {STATIC_PLANT} ) 2>/dev/null; then echo wrote; else echo kept; fi\n"
    )
    put_plugin("50-root-writer", writer)
    PLUGIN_CONF.write_text('[plugins."50-root-writer"]\nrun_as = "root"\n')
    os.chmod(PLUGIN_CONF, 0o644)
    collect_now()
    modules = json.loads((CACHE / "admin.json").read_text())["modules"]
    items = modules.get("50-root-writer", {}).get("items", [])
    text = items[0].get("text", {}).get("text", "") if items else ""
    static = MOTD_FILE.read_text() if MOTD_FILE.exists() else ""
    check(
        "static_root_plugin_cannot_write_motd_d",
        text == "kept" and not STATIC_PLANT.exists() and "kept" not in static,
        f"plugin said {text!r}, planted={STATIC_PLANT.exists()}",
    )
    STATIC_PLANT.unlink(missing_ok=True)
    (PLUGIN_DIR / "50-root-writer").unlink()
    PLUGIN_CONF.unlink()


def uninstall_last() -> None:
    stage("uninstall")
    gone = sh("/opt/motp/bin/motp", "uninstall")
    check("uninstall", gone.returncode == 0, gone.stdout[-200:])
    check("uninstall_removes_static_file", not MOTD_FILE.exists())
    for user in ("motp-user", "motp-zsh"):
        last = login(user)
        errors = error_lines(last.out, baseline[user].out)
        check(
            f"after_uninstall_{user}",
            last.prompt and last.motd_count == 0 and not errors,
            f"count={last.motd_count} {errors[:2]}",
        )


# --- phase 10: failed units, unit rows, the previous login, per-user files -------------

FAIL_UNIT = "motp-p10-fail.service"
ROWS_CONF = Path("/etc/motp/conf.d/50-p10-rows.toml")
ROW_LABEL = "P10 job"
# "Last login ....... 23 seconds ago": the previous-login row, not "Last login from".
PREVIOUS = re.compile(r"Last login(?! from| terminal)[ .:]+([0-9][^\n|]*?) ago")
DURATION_PART = re.compile(r"([0-9]+) (day|hour|minute|second)s?")
SECONDS = {"day": 86400, "hour": 3600, "minute": 60, "second": 1}
GAP = 25.0  # seconds between the two logins, so the two are told apart


def seconds_of(text: str) -> int:
    return sum(int(n) * SECONDS[unit] for n, unit in DURATION_PART.findall(text))


def collect_now() -> None:
    """One collector run with every module due (as after a timer period has passed)."""
    Path("/var/lib/motp/state.json").unlink(missing_ok=True)
    done = sh("/opt/motp/bin/motp", "collect", timeout=200)
    note("collect", (done.stdout.strip().splitlines() or [""])[0][:100])


def service_and_login() -> None:
    """Phase 10 in the login image (blueprint "Done when")."""
    import pwd

    stage("service-and-login")
    Path(f"/etc/systemd/system/{FAIL_UNIT}").write_text(
        "[Unit]\nDescription=MOTP test: fails\n\n[Service]\nType=oneshot\nExecStart=/bin/false\n"
    )
    sh("systemctl", "daemon-reload")
    sh("systemctl", "start", FAIL_UNIT)
    ROWS_CONF.write_text(f'[[rows.unit]]\nname = "{FAIL_UNIT}"\nlabel = "{ROW_LABEL}"\n')
    ROWS_CONF.chmod(0o644)

    # The previous login: a first login, a collector run, a second login.
    first = time.time()
    login("motp-user")
    time.sleep(GAP)
    collect_now()
    second_started = time.time()
    shown = screen("motp-user")
    found = PREVIOUS.search(shown)
    ago = seconds_of(found.group(1)) if found else -1
    previous = second_started - ago
    check(
        "second_login_shows_the_first_logins_time",
        found is not None and abs(previous - first) <= 8 and ago >= GAP - 5,
        f"shown {ago}s ago, first login {second_started - first:.0f}s before the second",
    )

    # Failed units: a count for everyone, the name for admins; the watched row for all.
    admin = screen("motp-admin")
    counted = re.search(r"\b[0-9]+ failed units?\b", shown)
    check(
        "failed_unit_is_a_count_for_the_user",
        counted is not None and FAIL_UNIT not in shown,
        counted.group(0) if counted else "no count",
    )
    check("failed_unit_is_named_for_the_admin", FAIL_UNIT in admin)
    row = re.search(rf"{ROW_LABEL}[ .:]+failed", shown)
    check("unit_row_shows_the_state", row is not None)

    # The per-user file: readable by its user, refused to another, really tried as both.
    uid = pwd.getpwnam("motp-user").pw_uid
    path = CACHE / "user" / f"{uid}.json"
    own = ssh_cmd("motp-user", "cat", str(path))
    other = ssh_cmd("motp-zsh", "cat", str(path))
    check(
        "per_user_file_readable_by_its_user",
        own.returncode == 0 and f'"uid":{uid}'.encode() in own.stdout,
        f"exit {own.returncode}",
    )
    check(
        "per_user_file_unreadable_for_another_user",
        other.returncode != 0 and b"Permission denied" in other.stderr and not other.stdout,
        f"exit {other.returncode} {other.stderr.decode(errors='replace').strip()[:80]}",
    )
    st = os.lstat(path)
    check(
        "per_user_file_is_roots_with_one_reader",
        (st.st_uid, stat.S_IMODE(st.st_mode)) == (0, 0o440)
        and int.from_bytes(os.getxattr(path, "system.posix_acl_access")[16:20], "little") == uid,
        oct(stat.S_IMODE(st.st_mode)),
    )
    tiers = (CACHE / "public.json").read_text() + (CACHE / "admin.json").read_text()
    check("no_login_record_in_the_tier_files", '"pts/' not in tiers and "Last login" not in tiers)

    sh("systemctl", "reset-failed", FAIL_UNIT)
    Path(f"/etc/systemd/system/{FAIL_UNIT}").unlink()
    ROWS_CONF.unlink()
    sh("systemctl", "daemon-reload")
    collect_now()


# --- phase 11: the security modules over SSH ----------------------------------------------

FAILED_FROM = "192.0.2.10"  # on the container's own loopback device (NET_ADMIN)
TRIED_NAMES = ("qzsecretname", "qzrealuser")  # attempted names: in no cache file at all
REAL_USER = "qzrealuser"
BANNED = {"sshd": ("192.0.2.77", "198.51.100.23"), "motp-web": ("203.0.113.5",)}
DOCKER_SOCK = "/run/docker.sock"
FAKE_RUNTIME = WORK / "tools/container/fake_runtime.py"
DOCKER_FIXTURE = WORK / "tests/fixtures/security/docker-api.json"
# What only admins may see: sources, banned addresses, jail and container names, images,
# and the firewall row as a whole.
ADMIN_ONLY = (
    FAILED_FROM, "192.0.2.77", "198.51.100.23", "203.0.113.5", "motp-web",
    "qzweb-frontend", "qzdb-backend", "qzloop-worker", "qzold-job", "qzimage", "Firewall",
)  # fmt: skip
ADMIN_SHOWN = (FAILED_FROM, "192.0.2.77", "203.0.113.5", "motp-web", "qzdb-backend", "Firewall")
JAIL_LOCAL = """\
[DEFAULT]
banaction = dummy
banaction_allports = dummy
backend = polling

[sshd]
enabled = true
backend = polling
logpath = /var/log/motp-f2b.log

[motp-web]
enabled = true
filter = sshd
port = 80
backend = polling
logpath = /var/log/motp-f2b.log
"""
APP_LIMIT = 10.0 + 1.5  # app_containers.timeout and the runner's slack


def install_packages(*names: str) -> bool:
    """Test setup only, with the container's network."""
    if Path("/usr/bin/apt-get").exists():
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        done = sh("apt-get", "install", "-y", "-qq", "--no-install-recommends", *names,
                  timeout=600, env=env)  # fmt: skip
    else:
        done = sh("dnf", "install", "-y", "-q", *names, timeout=600)
    return done.returncode == 0


def fail2ban_with_bans() -> bool:
    apt = Path("/usr/bin/apt-get").exists()
    ok = install_packages(*(("fail2ban", "python3-systemd") if apt else ("fail2ban-server",)))
    Path("/etc/fail2ban/jail.local").write_text(JAIL_LOCAL)
    Path("/var/log/motp-f2b.log").write_text("")
    sh("systemctl", "restart", "fail2ban")
    for _ in range(60):
        if sh("fail2ban-client", "ping").returncode == 0:
            break
        time.sleep(1)
    for jail, addresses in BANNED.items():
        ok = sh("fail2ban-client", "set", jail, "banip", *addresses).returncode == 0 and ok
    return ok


def failed_ssh_logins() -> bool:
    """Real failed SSH logins from a documentation address: a wrong password for an
    account, two attempts for a name that does not exist."""
    apt = Path("/usr/bin/apt-get").exists()
    ok = install_packages("iproute2" if apt else "iproute")
    ok = sh("ip", "address", "add", f"{FAILED_FROM}/32", "dev", "lo").returncode == 0 and ok
    sh("useradd", "-m", REAL_USER)
    sh("chpasswd", input=f"{REAL_USER}:Right-Pass-1\n")
    askpass = Path("/root/motp-askpass")
    askpass.write_text("#!/bin/sh\necho wrong-pass\n")
    askpass.chmod(0o700)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SSH_ASKPASS": str(askpass),
           "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "none"}  # fmt: skip
    for user in (REAL_USER, TRIED_NAMES[0], TRIED_NAMES[0]):
        sh("setsid", "-w", "ssh", "-b", FAILED_FROM, "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
           "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1",
           f"{user}@{HOST}", "true", env=env, stdin=subprocess.DEVNULL, timeout=60)  # fmt: skip
    # The address is a local one now, which net_addresses shows to everyone by design (5.4):
    # gone again before the collector runs, so only the security modules can show it.
    ok = sh("ip", "address", "del", f"{FAILED_FROM}/32", "dev", "lo").returncode == 0 and ok
    return ok


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
        argv.append(str(DOCKER_FIXTURE))
    Path(DOCKER_SOCK).unlink(missing_ok=True)
    started = FakeDocker(argv)
    for _ in range(50):
        if os.path.exists(DOCKER_SOCK):
            break
        time.sleep(0.1)
    return started


def security_modules() -> None:
    """Phase 11 in the login image (blueprint "Done when")."""
    stage("security-modules")
    check("test_setup_fail2ban", fail2ban_with_bans())
    check("test_setup_failed_logins", failed_ssh_logins())
    runtime = fake_runtime("answer")
    try:
        collect_now()
        plain, admin = screen("motp-user"), screen("motp-admin")
    finally:
        runtime.stop()
    # Debian 13 keeps no btmp and no utmp (phase 14): the row says so instead of a count,
    # and there is no source for admins to see.
    utmp_family = Path("/run/utmp").exists()
    failed_text = r"[0-9]+ in the last 24 hours" if utmp_family else r"not recorded on this system"
    counts = {
        "failed_logins": re.search(failed_text, plain),
        "bans": re.search(r"\b3 addresses banned\b", plain),
        "containers": re.search(r"2 running \(1 unhealthy\), 1 restarting, 1 stopped", plain),
    }
    check("user_sees_the_security_counts", all(counts.values()),
          " ".join(f"{k}={bool(v)}" for k, v in counts.items()))  # fmt: skip
    leaked = [word for word in ADMIN_ONLY if word in plain]
    check("user_sees_no_address_or_name", not leaked, " ".join(leaked))
    shown = ADMIN_SHOWN if utmp_family else tuple(w for w in ADMIN_SHOWN if w != FAILED_FROM)
    missing = [word for word in shown if word not in admin]
    check("admin_sees_addresses_and_names", not missing, " ".join(missing))
    tiers = (CACHE / "public.json").read_text() + (CACHE / "render.json").read_text()
    in_tiers = [word for word in ADMIN_ONLY if word in tiers]
    check("public_and_render_hold_no_detail", not in_tiers, " ".join(in_tiers))
    holding = [
        f"{path}:{name}"
        for path in CACHE.rglob("*")
        if path.is_file()
        for name in TRIED_NAMES
        if name.encode() in path.read_bytes()
    ]
    check("attempted_names_in_no_cache_file", not holding, " ".join(holding))

    # A runtime that never answers: the collector's module fails within its limit, and a
    # login during that run is as fast as one before it.
    _before, normal = logins("motp-user")
    runtime = fake_runtime("hang")
    try:
        Path("/var/lib/motp/state.json").unlink(missing_ok=True)
        sh("systemctl", "start", "--no-block", "motp-collect.service")
        time.sleep(1)
        during, slow = logins("motp-user")
        running = sh("systemctl", "is-active", "motp-collect.service").stdout.strip()
        for _ in range(120):
            if sh("systemctl", "is-active", "motp-collect.service").stdout.strip() != "activating":
                break
            time.sleep(1)
    finally:
        runtime.stop()
    check(
        "hung_runtime_never_delays_a_login",
        during.prompt and during.motd_count == 1 and slow <= normal + DELAY_LIMIT,
        f"{slow:.2f}s against {normal:.2f}s, collector {running} during the logins",
    )
    entry = json.loads((CACHE / "admin.json").read_text())["modules"].get("app_containers", {})
    ms = entry.get("duration_ms")
    check(
        "hung_runtime_fails_within_the_module_limit",
        entry.get("state") == "failed" and isinstance(ms, int) and ms <= APP_LIMIT * 1000,
        f"state={entry.get('state')} {ms} ms",
    )
    Path(DOCKER_SOCK).unlink(missing_ok=True)
    collect_now()


def main() -> int:
    setup()
    pending_update()
    before_install()
    install_hybrid()
    package_health()
    service_and_login()
    security_modules()
    normal = hybrid_logins()
    languages()
    quiet_sessions()
    robustness(normal)
    plugins_over_ssh(normal)
    static_mode()
    static_root_plugin()
    uninstall_last()
    print(f"CHECKS-DONE failures={failures}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

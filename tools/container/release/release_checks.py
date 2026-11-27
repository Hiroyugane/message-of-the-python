"""The release check inside a fresh systemd container (phase 14 "Done when"). Run by
``tools/release_check.py``; the repository is mounted read-only at ``/src``.

Pastes the README's own commands, as written, on a system without MOTP:

1. builds ``motp.pyz`` from a copy of the tree (the build is byte-identical everywhere, so
   this is the archive a release would carry), writes ``SHA256SUMS`` as the release
   workflow does, and serves both on ``127.0.0.1:8000``;
2. pastes each README block the way a person does: as an ordinary user with sudo, the
   block fed to ``bash -s`` with nothing added (no ``set -e`` from outside), only the
   release download address replaced by the local server. First the prerequisites block
   of this package manager (``release-check:prereq-apt`` or ``-dnf``); then the install
   block with a damaged archive served, which must fail and install nothing (security
   review of phase 14); then, with a fake ``gh`` that is logged in but whose attestation
   check fails, the install block must stop and install nothing; then the install block
   with the real archive and a fake ``gh`` that is not logged in, which must skip the
   attestation, say so, and install (final review, usability item 14);
3. checks an SSH login with a terminal shows the MOTD exactly once, ``ssh host true``
   prints nothing at all, ``motp doctor`` reports no error, and the README's
   ``release-check:doctor`` block runs;
4. pastes the ``release-check:uninstall`` block and checks that only the config is left
   and a login is silent again.

Prints ``CHECK``, ``NOTE`` and ``MOTP-STAGE`` lines and ends with ``CHECKS-DONE``.
"""

import hashlib
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/src/tools/container/login")
import login_checks as lc  # the helpers: check, sh, login, ssh_cmd, the key

SERVE = Path("/srv/motp-release")
README = lc.WORK / "README.md"
RELEASE_URL = "https://github.com/Hiroyugane/message-of-the-python/releases/download/v$VERSION"
LOCAL_URL = "http://127.0.0.1:8000"
USER = "motp-user"
SUDOERS = Path("/etc/sudoers.d/90-motp-release-check")
CONFIG = Path("/etc/motp/config.toml")
LEFT_AFTER_UNINSTALL = (
    "/opt/motp", "/etc/profile.d/motp.sh", "/etc/systemd/system/motp-collect.service",
    "/etc/systemd/system/motp-collect.timer", "/var/lib/motp", "/run/motp",
    "/usr/local/bin/motp",
)  # fmt: skip


def readme_block(name: str) -> str:
    """The text of the fenced block after ``<!-- release-check:<name> -->``, as pasted."""
    text = README.read_text(encoding="utf-8")
    marker = f"<!-- release-check:{name} -->"
    if text.count(marker) != 1:
        raise SystemExit(f"README: expected one {marker}")
    after = text.split(marker, 1)[1]
    fence = re.search(r"```[a-z]*\n(.*?)```", after, re.DOTALL)
    if fence is None:
        raise SystemExit(f"README: no code block after {marker}")
    return fence.group(1)


FAKE_GH = Path("/usr/local/bin/gh")
NOT_CHECKED = "Attestation not checked"


def fake_gh(logged_in: bool) -> None:
    """A ``gh`` that answers ``auth status`` as logged in or not, and fails every
    attestation check (a real one would, for an archive built here)."""
    status = 0 if logged_in else 1
    FAKE_GH.write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = auth ]; then echo "fake gh: auth {status}" >&2; exit {status}; fi\n'
        'echo "fake gh: attestation refused" >&2; exit 1\n'
    )
    os.chmod(FAKE_GH, 0o755)  # noqa: S103  (a test program in a root-only directory)


def paste(name: str, check_name: str = "", expect_ok: bool = True, expect_text: str = "") -> bool:
    """Paste one README block into ``bash -s`` as the ordinary user ``USER`` in their home
    directory, as a person does; only the release address points at the local server.
    ``expect_text`` must then appear in what the block printed."""
    text = readme_block(name).replace(RELEASE_URL, LOCAL_URL)
    done = subprocess.run(
        ["/usr/sbin/runuser", "-u", USER, "--", "/bin/bash", "-s"], input=text,
        cwd=f"/home/{USER}", capture_output=True, text=True, timeout=600, check=False,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": f"/home/{USER}",
             "USER": USER, "LANG": "C.UTF-8", "TERM": "dumb"},
    )  # fmt: skip
    print(done.stdout[-3000:], done.stderr[-3000:], sep="\n", flush=True)
    ok = (done.returncode == 0) is expect_ok and expect_text in done.stdout + done.stderr
    lines = len(text.splitlines())
    return lc.check(check_name or f"readme_{name}", ok, f"exit {done.returncode}, {lines} lines")


def serve_archive(data: bytes) -> None:
    (SERVE / "motp.pyz").write_bytes(data)
    os.chmod(SERVE / "motp.pyz", 0o644)


def setup() -> "tuple[subprocess.Popen[bytes], bytes]":
    lc.stage("copy")
    shutil.copytree(
        "/src", lc.WORK,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache",
            "dist", "*.mo", "*.pyc", ".env*",
        ),
    )  # fmt: skip
    lc.stage("build")
    SERVE.mkdir(parents=True)
    pyz = SERVE / "motp.pyz"
    build = str(lc.WORK / "tools/build_pyz.py")
    built = lc.sh("/usr/bin/python3", "-I", build, "--output", str(pyz))
    lc.check("build", built.returncode == 0, built.stdout.strip()[:80] or built.stderr[-300:])
    archive = pyz.read_bytes()
    digest = hashlib.sha256(archive).hexdigest()
    (SERVE / "SHA256SUMS").write_text(f"{digest}  motp.pyz\n")
    lc.note("archive_sha256", digest)
    os.chmod(SERVE, 0o755)  # noqa: S103  (read by the server as nobody)
    for f in SERVE.iterdir():
        os.chmod(f, 0o644)
    nobody = pwd.getpwnam("nobody")
    server = subprocess.Popen(
        ["/usr/bin/python3", "-I", "-m", "http.server", "8000", "--bind", "127.0.0.1",
         "--directory", str(SERVE)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, user=nobody.pw_uid,
        group=nobody.pw_gid, extra_groups=[],
    )  # fmt: skip

    lc.stage("sshd")
    lc.sh("ssh-keygen", "-A")
    unit = "ssh.service" if Path("/lib/systemd/system/ssh.service").exists() else "sshd.service"
    if not Path(f"/lib/systemd/system/{unit}").exists():
        unit = "sshd.service"
    lc.sh("systemctl", "reset-failed", unit)
    started = lc.sh("systemctl", "restart", unit)
    lc.check("sshd_started", started.returncode == 0, unit + " " + started.stderr[-200:])
    lc.KEY.parent.mkdir(mode=0o700, exist_ok=True)
    lc.sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(lc.KEY))
    scan = ""
    for _ in range(30):
        scan = lc.sh("ssh-keyscan", "-T", "3", lc.HOST).stdout
        if scan.strip():
            break
        time.sleep(1)
    lc.KNOWN.write_text(scan)
    lc.sh("useradd", "-m", "-s", "/bin/bash", USER)
    lc.sh("usermod", "-p", "*", USER)
    ssh_dir = Path(f"/home/{USER}/.ssh")
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    (ssh_dir / "authorized_keys").write_text(Path(str(lc.KEY) + ".pub").read_text())
    lc.sh("chown", "-R", f"{USER}:{USER}", f"/home/{USER}")
    # The person who pastes the README: an ordinary account that may use sudo. A rule for
    # the user, not a group, so the installer's choice of admin group is not touched.
    SUDOERS.write_text(f"{USER} ALL=(ALL) NOPASSWD: ALL\n")
    os.chmod(SUDOERS, 0o440)
    return server, archive


def logged_in_once(name: str, expect: int) -> None:
    last = lc.login(USER)
    lc.check(
        name,
        last.prompt and last.motd_count == expect,
        f"MOTD {last.motd_count} times (want {expect}), exit {last.code}",
    )
    quiet = lc.ssh_cmd(USER, "true")
    lc.check(
        f"{name}_ssh_true_silent",
        quiet.returncode == 0 and quiet.stdout == b"" and quiet.stderr == b"",
        f"exit {quiet.returncode} out={quiet.stdout[:80]!r} err={quiet.stderr[:80]!r}",
    )


def uninstalled() -> None:
    left = [p for p in LEFT_AFTER_UNINSTALL if os.path.lexists(p)]
    only_config = not left and CONFIG.is_file()
    lc.check("uninstall_leaves_only_the_config", only_config, str(left))
    for account in ("motp", "motp-plugin"):
        try:
            pwd.getpwnam(account)
            gone = False
        except KeyError:
            gone = True
        lc.check(f"uninstall_removes_account_{account}", gone)
    zsh = [p for p in ("/etc/zsh/zprofile", "/etc/zprofile") if Path(p).exists()]
    lc.check(
        "uninstall_removes_zsh_block",
        not any("# BEGIN motp" in Path(p).read_text() for p in zsh),
        str(zsh),
    )
    logged_in_once("login_after_uninstall", 0)


def main() -> int:
    server, archive = setup()
    try:
        lc.stage("before")
        logged_in_once("login_before_install", 0)
        lc.stage("prerequisites")
        paste("prereq-apt" if shutil.which("apt-get") else "prereq-dnf")
        lc.stage("damaged-download")
        serve_archive(archive[:-1] + bytes([archive[-1] ^ 0xFF]))
        paste("install", "readme_install_stops_on_a_wrong_checksum", expect_ok=False)
        lc.check("nothing_installed_after_a_wrong_checksum", not os.path.lexists("/opt/motp"))
        serve_archive(archive)
        lc.stage("attestation-refused")
        fake_gh(logged_in=True)
        paste("install", "readme_install_stops_on_a_refused_attestation", expect_ok=False)
        lc.check("nothing_installed_after_a_refused_attestation", not os.path.lexists("/opt/motp"))
        lc.stage("install")
        fake_gh(logged_in=False)
        installed = paste("install", "readme_install_without_login_skips_attestation",
                          expect_text=NOT_CHECKED)  # fmt: skip
        FAKE_GH.unlink()
        if installed:
            for _ in range(60):  # the installer started one collector run
                if (lc.CACHE / "public.json").exists():
                    break
                time.sleep(1)
            lc.check("cache_written", (lc.CACHE / "public.json").exists())
            lc.stage("login")
            logged_in_once("login_after_install", 1)
            lc.stage("doctor")
            doctor = lc.sh("/opt/motp/bin/motp", "doctor")
            fails = [ln for ln in doctor.stdout.splitlines() if ln.startswith("[FAIL]")]
            warns = [ln for ln in doctor.stdout.splitlines() if ln.startswith("[warn]")]
            lc.check("doctor_no_error", doctor.returncode == 0 and not fails, " | ".join(fails))
            lc.note("doctor_warnings", " | ".join(warns) or "none")
            paste("doctor")
            lc.stage("uninstall")
            if paste("uninstall"):
                uninstalled()
    finally:
        server.terminate()
        SUDOERS.unlink(missing_ok=True)
    print(f"CHECKS-DONE failures={lc.failures}", flush=True)
    return 1 if lc.failures else 0


if __name__ == "__main__":
    sys.exit(main())

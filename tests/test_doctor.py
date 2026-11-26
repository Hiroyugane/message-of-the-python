"""``motp doctor`` details settled in phase 14 that need no installed system: the zsh side
of the login hook, the charset test line only on a terminal, and plural forms."""

import io
import os
from pathlib import Path

import pytest

from motp.core import config, i18n
from motp.core.model import MessageRef, ref
from motp.install import doctor, hooks


def _plain_read(path: str) -> bytes:
    return Path(path).read_bytes()


def _zsh_lines(tmp_path: Path, files: dict[str, bytes]) -> list[tuple[str, str]]:
    paths = []
    for name in ("zsh-zprofile", "zprofile"):
        path = tmp_path / name
        if name in files:
            path.write_bytes(files[name])
        paths.append(str(path))
    report = doctor.Report()
    doctor.check_zsh(report, doctor.Places(zprofiles=tuple(paths)), read=_plain_read)
    return [(level, message.id) for level, message in report.lines]


def test_a_zprofile_without_the_block_is_a_warning(tmp_path: Path) -> None:
    """A zsh installed after MOTP: Debian's zprofile without the block (phase 8 issue)."""
    lines = _zsh_lines(tmp_path, {"zsh-zprofile": b"# /etc/zsh/zprofile\n"})
    assert lines == [("warn", "doctor.zsh_missing")]


def test_a_zprofile_with_the_block_is_ok(tmp_path: Path) -> None:
    block = hooks.zsh_block().encode()
    lines = _zsh_lines(tmp_path, {"zsh-zprofile": b"# admin's line\n" + block})
    assert lines == [("ok", "doctor.zsh_block")]


def test_a_zprofile_that_runs_etc_profile_needs_no_block(tmp_path: Path) -> None:
    text = b"_src_etc_profile()\n{\n    emulate -L ksh\n    source /etc/profile\n}\n"
    assert _zsh_lines(tmp_path, {"zprofile": text}) == [("ok", "doctor.zsh_profile")]


def test_a_damaged_block_is_named(tmp_path: Path) -> None:
    block = hooks.zsh_block().encode()
    lines = _zsh_lines(tmp_path, {"zsh-zprofile": block + block})
    assert lines == [("warn", "doctor.zsh_broken")]


def test_no_zprofile_means_no_zsh_and_no_line(tmp_path: Path) -> None:
    assert _zsh_lines(tmp_path, {}) == []


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize(("stream", "shown"), [(io.StringIO(), False), (_Tty(), True)])
def test_the_charset_line_is_written_only_to_a_terminal(
    monkeypatch: pytest.MonkeyPatch, stream: io.StringIO, shown: bool
) -> None:
    """Phase 8 issue: piped into the installer's output, the frame characters became
    replacement characters; the line tests the terminal, so it needs one."""
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setattr(doctor, "run_checks", lambda *a: (doctor.Report(), "+-+ | ###"))
    assert doctor.main(stream) == 0
    assert ("charset test: +-+ | ###" in stream.getvalue()) is shown


@pytest.mark.parametrize(
    ("language", "one", "two"),
    [
        ("en", "config: 1 file used, no problem", "config: 2 files used, no problem"),
        ("de", "Konfiguration: 1 Datei verwendet", "Konfiguration: 2 Dateien verwendet"),
    ],
)
def test_the_config_line_has_plural_forms(language: str, one: str, two: str) -> None:
    tr = i18n.translator(language)
    assert tr.text(ref("doctor.config", count=1)).startswith(one)
    assert tr.text(ref("doctor.config", count=2)).startswith(two)
    assert tr.text(ref("doctor.config_problems", count=1)).count("problems") == 0


def test_static_mode_says_which_logins_show_nothing(tmp_path: Path) -> None:
    """Phase 8 issue: in static mode only pam_motd prints the file; doctor says so."""
    from dataclasses import replace

    from motp.core import config

    settings = config.defaults()
    static = replace(settings, general=replace(settings.general, mode="static"))
    places = doctor.Places(
        prefix=str(tmp_path / "opt"),
        unit_dir=str(tmp_path / "units"),
        systemd_marker=str(tmp_path / "no-systemd"),
        profile_hook=str(tmp_path / "motp.sh"),
        motd_dir=str(tmp_path / "motd.d"),
        cache_dir=str(tmp_path / "cache"),
    )
    report = doctor.Report()
    doctor.check_login(report, static, places, 0)
    assert ("info", "doctor.static_gap") in [(lvl, m.id) for lvl, m in report.lines]
    hybrid = doctor.Report()
    doctor.check_login(hybrid, settings, places, 0)
    assert "doctor.static_gap" not in [m.id for _, m in hybrid.lines]


MOUNTINFO = r"""22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 0:41 / /opt/motp rw,nosuid shared:20 - fuse.sshfs host:/x rw,user_id=0
41 22 0:42 / /etc/motp\040x rw shared:21 - nfs4 192.0.2.5:/e rw
42 22 0:43 / /run rw shared:22 - tmpfs tmpfs rw
"""


def test_mount_type_takes_the_longest_mount_point() -> None:
    assert doctor.mount_type("/opt/motp/lib", MOUNTINFO) == "fuse.sshfs"
    assert doctor.mount_type("/opt/motpx", MOUNTINFO) == "ext4"
    assert doctor.mount_type("/etc/motp x", MOUNTINFO) == "nfs4"
    assert doctor.mount_type("/run/motp", MOUNTINFO) == "tmpfs"


def test_motp_places_on_fuse_or_network_file_systems_are_warned(tmp_path: Path) -> None:
    """Phase 3 issue: a FUSE or network mount can report root as the owner of anything."""
    info = tmp_path / "mountinfo"
    info.write_text(MOUNTINFO)
    report = doctor.Report()
    places = doctor.Places(prefix="/opt/motp", config_root="/etc/motp x", cache_dir="/run/motp")
    doctor.check_file_systems(report, places, str(info))
    warned = [dict(m.params)["path"] for lvl, m in report.lines if lvl == "warn"]
    assert warned == ["/opt/motp", "/etc/motp x"]
    assert all(m.id == "doctor.untrusted_fs" for _, m in report.lines)


def test_of_mounts_stacked_on_one_point_the_last_is_used() -> None:
    """Code review of phase 14: mountinfo lists the mount in use last."""
    stacked = MOUNTINFO + "50 22 0:50 / /opt rw - ext4 /dev/sda2 rw\n"
    stacked += "51 50 0:51 / /opt rw - fuse.sshfs host:/o rw\n"
    assert doctor.mount_type("/opt/thing", stacked) == "fuse.sshfs"


def test_a_zprofile_the_installer_would_refuse_is_named(tmp_path: Path) -> None:
    def refuse(path: str) -> bytes:
        raise ValueError(path)

    (tmp_path / "zprofile").write_bytes(b"# group-writable\n")
    report = doctor.Report()
    doctor.check_zsh(report, doctor.Places(zprofiles=(str(tmp_path / "zprofile"),)), read=refuse)
    assert [(lvl, m.id) for lvl, m in report.lines] == [("warn", "doctor.zsh_unsafe")]


@pytest.mark.needs_linux_owner
def test_the_zprofile_is_read_with_the_installers_checks() -> None:
    import os
    import shutil
    import tempfile

    base = Path(tempfile.mkdtemp(prefix="motp-test-", dir="/var/lib"))
    os.chmod(base, 0o755)
    try:
        good = base / "zprofile"
        good.write_bytes(hooks.zsh_block().encode())
        os.chmod(good, 0o644)
        assert doctor.read_zprofile(str(good)).startswith(b"# BEGIN motp")
        os.chmod(good, 0o664)  # group-writable: the installer leaves it alone
        with pytest.raises(ValueError):
            doctor.read_zprofile(str(good))
        report = doctor.Report()
        doctor.check_zsh(report, doctor.Places(zprofiles=(str(good),)))
        assert [m.id for _, m in report.lines] == ["doctor.zsh_unsafe"]
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_a_config_file_that_fails_the_ownership_check_is_named_by_doctor(tmp_path: Path) -> None:
    """T17 as settled in phase 14: an unsafe config file is ignored (the defaults grant
    nothing) and doctor says so; tmp_path is never root's alone, so the check refuses it."""
    (tmp_path / "config.toml").write_text('[general]\nlanguage = "de"\n')
    report = doctor.Report()
    settings = doctor.check_config(report, doctor.Places(config_root=str(tmp_path)))
    assert ("warn", "doctor.config_problems") in [(lvl, m.id) for lvl, m in report.lines]
    assert settings.general.language == "auto", "the refused file changed nothing"


def test_a_config_closed_to_the_user_is_not_reported_as_problems(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Final review, security item 4: an admin's stricter modes on /etc/motp are fine."""
    unreadable = [config.Problem("/etc/motp/config.toml", MessageRef("safepath.error.unreadable"))]
    syntax = [config.Problem("/etc/motp/config.toml", MessageRef("config.error.syntax_end"))]
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert config.closed_to_user(str(tmp_path), unreadable)
    assert not config.closed_to_user(str(tmp_path), syntax)
    assert not config.closed_to_user(str(tmp_path), [])
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert not config.closed_to_user(str(tmp_path), unreadable)


def test_every_warning_and_failure_names_the_next_step() -> None:
    """Final review, usability item 12: six of them said what was wrong, not what to do."""
    import re

    source = (Path(doctor.__file__)).read_text(encoding="utf-8")
    ids = set(re.findall(r'r\.add\(\s*"(?:warn|fail)",\s*"(doctor\.[a-z_]+)"', source))
    assert len(ids) >= 20
    english = i18n.translator("en")
    steps: tuple[str, ...] = (
        "run ",
        "sudo ",
        "motp ",
        "set ",
        "fix ",
        "remove ",
        "make ",
        "move ",
        "README",
    )
    steps += ("nothing to do", "gpasswd")
    lacking = []
    for msg_id in sorted(ids):
        text = english.message(msg_id, {"count": 1})
        if not any(step in text for step in steps):
            lacking.append(f"{msg_id}: {text}")
    assert not lacking, lacking


def test_root_programs_are_left_to_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Code review of phase 14b: a user cannot see root's user site, so no false "ok"."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    r = doctor.Report()
    doctor.check_root_programs(r)
    assert [(level, m.id) for level, m in r.lines] == [("info", "doctor.root_programs_as_root")]

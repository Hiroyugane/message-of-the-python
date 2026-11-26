"""Python import paths of programs root starts (T2, final review security item 2).

The ownership tests need Linux and root; they run in ``tools/container_test.py`` on the
container's own filesystem (fixture ``trusted_dir``). A fake interpreter tree is built
there with a version no system has (``python3.99``), so the real ``/usr/local`` adds only
directories that do not exist and whose ancestors are root's.
"""

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from motp.collect.context import ProbeContext
from motp.core import importpath, safepath
from motp.core.model import (
    ContractError,
    HintRef,
    MessageRef,
    Status,
    Visibility,
    contract_error,
)
from motp.core.safepath import Program, TrustedFile
from motp.modules import sec_fail2ban
from motp.modules.base import ImportPathError
from motp.modules.sec_fail2ban import SecFail2ban

linux_root = pytest.mark.needs_linux_owner


def _program(
    path: str, interpreter: "Program | None" = None, arg: "str | None" = None, named: str = ""
) -> Program:
    return Program(TrustedFile(path, 0, 0, 0o755, 0), interpreter, arg, named or None)


def test_only_a_chain_that_ends_in_python_is_python() -> None:
    py = _program("/usr/bin/python3.11", named="/usr/bin/python3")
    assert importpath.python_of(_program("/usr/bin/fail2ban-client", py)) == (
        "/usr/bin/python3.11",
        "/usr/bin/python3",
        None,
    )
    assert importpath.python_of(_program("/x", py, "-IS"))[2] == "-IS"  # type: ignore[index]
    assert importpath.python_of(_program("/x", _program("/usr/bin/bash"))) is None
    assert importpath.python_of(_program("/usr/bin/apt-get")) is None
    assert importpath.python_of(_program("/usr/bin/python3"))[:2] == ("/usr/bin/python3",) * 2  # type: ignore[index]


@pytest.mark.parametrize(
    "name", ["python3.13t", "python3.12d", "platform-python3.6", "pypy3", "pypy3.10", "Python3"]
)
def test_unusual_python_builds_are_checked_too(name: str) -> None:
    """Security review of phase 14b: the old name pattern let these through unchecked."""
    assert importpath.python_of(_program("/x", _program(f"/usr/bin/{name}"))) is not None


def test_a_venv_named_on_the_line_adds_its_own_site_directory() -> None:
    """Security review of phase 14b: the venv sits next to the name, not the real path."""
    found = importpath.candidates("/usr/bin/python3.11", named="/opt/tool/venv/bin/python3")
    assert "/opt/tool/venv/lib/python3.11/site-packages" in found
    assert "/opt/tool/venv/pyvenv.cfg" in found and "/opt/tool/venv/bin/pyvenv.cfg" in found


def test_roots_user_site_is_a_site_directory() -> None:
    assert "/root/.local/lib/python3.11/site-packages" in importpath.candidates(
        "/usr/bin/python3.11"
    )


@pytest.mark.parametrize(
    ("arg", "off"),
    [(None, False), ("-I", False), ("-S", True), ("-IS", True), ("-sS", True),
     ("--S", False), ("-u", False), ("/x", False)],
)  # fmt: skip
def test_site_is_off_only_with_an_s_flag(arg: "str | None", off: bool) -> None:
    assert importpath.site_disabled(arg) is off


def test_the_candidates_cover_local_and_shared_site_directories() -> None:
    found = importpath.candidates("/usr/bin/python3.11")
    for path in (
        "/usr/lib/python3.11",
        "/usr/lib/python3.11/lib-dynload",
        "/usr/lib64/python3.11/site-packages",
        "/usr/lib/python3/dist-packages",
        "/usr/local/lib/python3.11/dist-packages",
        "/usr/local/lib64/python3.11/site-packages",
        "/root/.local",
    ):
        assert path in found, path
    without_site = importpath.candidates("/usr/bin/python3.11", with_site=False)
    assert "/usr/local/lib/python3.11/dist-packages" not in without_site
    assert "/root/.local" not in without_site
    assert "/usr/lib/python3.11/lib-dynload" in without_site


def test_pth_lines_add_directories_and_import_lines_are_skipped() -> None:
    data = b"# comment\n\nextra\n/opt/abs\nimport os; os.system('x')\n../up\n"
    assert importpath.pth_entries("/usr/lib/python3/dist-packages", data) == [
        "/usr/lib/python3/dist-packages/extra",
        "/opt/abs",
        "/usr/lib/python3/up",
    ]


def test_pth_files_are_read_like_site_or_refused() -> None:
    """Security review of phase 14b: a byte-order mark, bad UTF-8, too many lines."""
    assert importpath.pth_entries("/s", b"\xef\xbb\xbf/home/u/x\n") == ["/home/u/x"]
    with pytest.raises(ContractError):
        importpath.pth_entries("/s", b"\xff\xfe/x\n")
    with pytest.raises(ContractError):
        importpath.pth_entries("/s", b"a\n" * (importpath.MAX_PTH_LINES + 1))


def test_relative_entries_fail() -> None:
    for entry in ("", "relative/dir"):
        with pytest.raises(ContractError):
            importpath.check_entry(entry)


# --- sec_fail2ban says "not checked" -----------------------------------------------------


class _Refusing(ProbeContext):
    def run(self, argv: Any, ok_codes: tuple[int, ...] = (0,)) -> bytes:
        raise ImportPathError(contract_error("safepath.error.import_path", path="/d").message)

    def _exists(self, path: str) -> bool:
        return True


def test_fail2ban_says_not_checked_when_its_import_path_is_unsafe() -> None:
    items = SecFail2ban().collect(_Refusing(binaries=(sec_fail2ban.CLIENT,)))
    assert len(items) == 1
    item = items[0]
    assert item.status is Status.UNKNOWN and item.visibility is Visibility.ADMIN
    assert isinstance(item.text, MessageRef) and item.text.id == "fail2ban.not_checked"
    assert isinstance(item.hint, HintRef) and item.hint.id == "import_path.check"


# --- ownership (Linux, root) -------------------------------------------------------------


def _tree(root: Path) -> tuple[Path, Path]:
    """A fake prefix with an interpreter (a copy of ``/bin/sh``) and its site directory."""
    bin_dir = root / "usr/bin"
    bin_dir.mkdir(parents=True)
    interp = bin_dir / "python3.99"
    shutil.copyfile(Path("/bin/sh").resolve(), interp)
    os.chmod(interp, 0o755)
    site = root / "usr/lib/python3.99/site-packages"
    site.mkdir(parents=True)
    for d in (root / "usr", root / "usr/lib", root / "usr/lib/python3.99", site, bin_dir):
        os.chmod(d, 0o755)
    return interp, site


def _script(path: Path, line: str, body: str = "") -> Path:
    path.write_text(f"#!{line}\n{body}")
    os.chmod(path, 0o755)
    return path


@linux_root
def test_a_root_only_import_path_passes(trusted_dir: Path) -> None:
    interp, site = _tree(trusted_dir)
    (site / "ok.pth").write_text("sub\n")
    (site / "sub").mkdir()
    os.chmod(site / "ok.pth", 0o644)
    prog = safepath.check_program(str(_script(trusted_dir / "p", str(interp))), True)
    importpath.check_program(prog)


@linux_root
@pytest.mark.parametrize("what", ["user_package", "group_writable_module", "user_link"])
def test_a_users_file_inside_a_site_directory_refuses_the_program(
    trusted_dir: Path, what: str
) -> None:
    """Security review of phase 14b: a fixed directory may still hold a user's package."""
    from .conftest import OTHER_USER, account

    interp, site = _tree(trusted_dir)
    package = site / "fail2ban"
    package.mkdir()
    os.chmod(package, 0o755)
    bad = package / "client.py"
    bad.write_text("x = 1\n")
    os.chmod(bad, 0o644)
    if what == "user_package":
        os.chown(bad, *account(OTHER_USER))
    elif what == "group_writable_module":
        os.chmod(bad, 0o664)
    else:
        bad.unlink()
        os.symlink(str(trusted_dir), bad)
        os.lchown(bad, *account(OTHER_USER))
    prog = safepath.check_program(str(_script(trusted_dir / "p", str(interp))), True)
    with pytest.raises(ContractError) as exc:
        importpath.check_program(prog)
    assert exc.value.message.id == "safepath.error.import_path"


@linux_root
@pytest.mark.parametrize("what", ["site_dir", "pth_file", "pth_target"])
def test_anything_others_can_change_on_the_import_path_refuses_the_program(
    trusted_dir: Path, what: str
) -> None:
    interp, site = _tree(trusted_dir)
    if what == "site_dir":
        os.chmod(site, 0o775)
        bad = site
    elif what == "pth_file":
        bad = site / "x.pth"
        bad.write_text("\n")
        os.chmod(bad, 0o664)
    else:
        bad = trusted_dir / "open"
        bad.mkdir()
        os.chmod(bad, 0o777)
        (site / "x.pth").write_text(f"{bad}\n")
        os.chmod(site / "x.pth", 0o644)
    prog = safepath.check_program(str(_script(trusted_dir / "p", str(interp))), True)
    with pytest.raises(ContractError) as exc:
        importpath.check_program(prog)
    assert exc.value.message.id == "safepath.error.import_path"
    shown = str(exc.value.message.param_dict()["path"])  # parameters are cut at 64 cells
    assert shown == str(bad) or (shown.endswith("…") and str(bad).startswith(shown[:-1]))


@linux_root
def test_with_dash_s_only_the_standard_library_counts(trusted_dir: Path) -> None:
    interp, site = _tree(trusted_dir)
    os.chmod(site, 0o775)
    prog = safepath.check_program(str(_script(trusted_dir / "p", f"{interp} -S")), True)
    importpath.check_program(prog)
    os.chmod(site.parent, 0o775)
    with pytest.raises(ContractError):
        importpath.check_program(prog)


@linux_root
def test_a_root_probe_does_not_start_a_python_script_with_an_unsafe_path(
    trusted_dir: Path,
) -> None:
    """The probe context refuses before anything runs; the old code started the script."""
    interp, site = _tree(trusted_dir)
    os.chmod(site, 0o775)
    marker = trusted_dir / "ran"
    script = _script(trusted_dir / "p", str(interp), f"echo ran > {marker}\n")
    ctx = ProbeContext(binaries=(str(script),))
    with pytest.raises(ImportPathError):
        ctx.run((str(script),))
    assert not marker.exists()
    os.chmod(site, 0o755)
    ctx.run((str(script),))
    assert marker.exists()


@linux_root
def test_a_root_plugin_in_python_with_an_unsafe_path_is_refused(trusted_dir: Path) -> None:
    from motp.collect import plugins

    interp, site = _tree(trusted_dir)
    os.chmod(site, 0o775)
    script = _script(trusted_dir / "p", str(interp))
    plugins.validate(str(script), "motp-plugin")
    with pytest.raises(ContractError) as exc:
        plugins.validate(str(script), "root")
    assert exc.value.message.id == "safepath.error.import_path"


@linux_root
def test_doctor_names_the_directory(trusted_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from motp.install import doctor
    from motp.modules import registry

    interp, site = _tree(trusted_dir)
    os.chmod(site, 0o775)
    script = _script(trusted_dir / "p", str(interp))

    class Fake:
        name = "fake"
        needs_root = True
        binaries = (str(script),)

    monkeypatch.setattr(registry, "cached_modules", lambda: (Fake(),))
    r = doctor.Report()
    doctor.check_root_programs(r)
    assert [(level, m.id) for level, m in r.lines] == [("fail", "doctor.root_program_bad")]
    assert str(site) in str(r.lines[0][1].param_dict()["reason"])
    # Code review of phase 14b: a module the config switched off is not reported.
    from dataclasses import replace

    from motp.core import config

    off = replace(config.defaults(), modules={"fake": config.ModuleConfig(False, None)})
    quiet = doctor.Report()
    doctor.check_root_programs(quiet, off)
    assert quiet.lines == []


@linux_root
def test_a_link_to_a_directory_is_walked_too(trusted_dir: Path) -> None:
    """Security re-check of phase 14b: a root link to a directory with a user's file."""
    from .conftest import OTHER_USER, account

    interp, site = _tree(trusted_dir)
    elsewhere = trusted_dir / "elsewhere"
    elsewhere.mkdir()
    os.chmod(elsewhere, 0o755)
    module = elsewhere / "m.py"
    module.write_text("x = 1\n")
    os.chown(module, *account(OTHER_USER))
    os.symlink(elsewhere, site / "pkg")
    prog = safepath.check_program(str(_script(trusted_dir / "p", str(interp))), True)
    with pytest.raises(ContractError):
        importpath.check_program(prog)


@linux_root
def test_a_copied_venv_brings_its_base_library_into_the_check(trusted_dir: Path) -> None:
    """Security re-check of phase 14b: pyvenv.cfg's home names the base installation."""
    base, base_site = _tree(trusted_dir / "base")
    venv = trusted_dir / "venv"
    (venv / "bin").mkdir(parents=True)
    for d in (venv, venv / "bin"):
        os.chmod(d, 0o755)
    copy = venv / "bin" / "python3.99"
    shutil.copyfile(base, copy)
    os.chmod(copy, 0o755)
    (venv / "pyvenv.cfg").write_text(f"home = {base.parent}\n")
    os.chmod(venv / "pyvenv.cfg", 0o644)
    prog = safepath.check_program(str(_script(trusted_dir / "p", str(copy))), True)
    importpath.check_program(prog)
    os.chmod(base_site, 0o775)
    with pytest.raises(ContractError):
        importpath.check_program(prog)

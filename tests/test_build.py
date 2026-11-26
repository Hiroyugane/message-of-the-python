import hashlib
import json
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

from motp import __version__

from .conftest import ROOT, SRC, TOOLS

sys.path.insert(0, str(TOOLS))
import build_pyz
import compile_catalogs


def test_two_builds_are_byte_identical(tmp_path: Path) -> None:
    a, b = tmp_path / "a" / "motp.pyz", tmp_path / "b" / "motp.pyz"
    digest_a = build_pyz.build(SRC, a)
    digest_b = build_pyz.build(SRC, b)
    assert digest_a == digest_b
    assert a.read_bytes() == b.read_bytes()
    assert hashlib.sha256(a.read_bytes()).hexdigest() == digest_a


def test_archive_layout_is_normalised(tmp_path: Path) -> None:
    out = tmp_path / "motp.pyz"
    build_pyz.build(SRC, out)
    with zipfile.ZipFile(out) as zf:
        infos = zf.infolist()
    names = [i.filename for i in infos]
    assert names == sorted(names)
    assert "__main__.py" in names and "motp/__init__.py" in names
    assert not any(n.endswith((".pyc", ".pyo")) or "__pycache__" in n for n in names)
    for info in infos:
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.date_time == (1980, 1, 1, 0, 0, 0)
        assert info.create_system == 3
        assert stat.S_IMODE(info.external_attr >> 16) == 0o644
        assert info.extra == b"" and info.comment == b""


def test_crlf_sources_build_the_same_bytes(tmp_path: Path) -> None:
    tree = tmp_path / "src" / "motp"
    tree.mkdir(parents=True)
    (tree / "__init__.py").write_bytes(b"x = 1\r\ny = 2\r\n")
    lf = tmp_path / "lf"
    (lf / "motp").mkdir(parents=True)
    (lf / "motp" / "__init__.py").write_bytes(b"x = 1\ny = 2\n")
    assert build_pyz.build(tmp_path / "src", tmp_path / "1.pyz") == build_pyz.build(
        lf, tmp_path / "2.pyz"
    )


def test_archive_runs_under_isolated_mode(tmp_path: Path) -> None:
    out = tmp_path / "motp.pyz"
    build_pyz.build(SRC, out)
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(out), "version"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"motp {__version__}\n"


def test_build_script_cli(tmp_path: Path) -> None:
    out = tmp_path / "x" / "motp.pyz"
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools" / "build_pyz.py"), "--output", str(out)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split()[0] == hashlib.sha256(out.read_bytes()).hexdigest()


def test_catalogues_are_compiled_into_the_archive(tmp_path: Path) -> None:
    out = tmp_path / "motp.pyz"
    build_pyz.build(SRC, out)
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        en_mo = zf.read("motp/locale/en.mo")
    assert en_mo == compile_catalogs.compile_file(SRC / "motp" / "locale" / "en.po")
    assert not any(n.endswith(".po") for n in names)


def test_only_catalogues_with_a_source_are_packed(tmp_path: Path) -> None:
    """A stale or foreign .mo in the tree never reaches the archive."""
    tree = tmp_path / "src" / "motp"
    (tree / "locale").mkdir(parents=True)
    (tree / "__init__.py").write_text("")
    po = (SRC / "motp" / "locale" / "en.po").read_bytes()
    (tree / "locale" / "en.po").write_bytes(po)
    (tree / "locale" / "en.mo").write_bytes(b"stale")
    (tree / "locale" / "xx.mo").write_bytes(b"foreign")
    entries = build_pyz.collect(tmp_path / "src")
    assert sorted(n for n in entries if "/locale/" in n) == ["motp/locale/en.mo"]
    assert entries["motp/locale/en.mo"] != b"stale"


def test_archive_carries_the_vendored_parser_and_the_data_files(tmp_path: Path) -> None:
    out = tmp_path / "motp.pyz"
    build_pyz.build(SRC, out)
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        manifest = zf.read("motp/_vendor/manifest.json")
    vendored = json.loads(manifest)["tomli"]["files"]
    assert {f"motp/_vendor/{name}" for name in vendored} <= names
    assert {"motp/data/default-config.toml", "motp/data/starter-config.toml"} <= names


def test_config_commands_run_from_the_archive(tmp_path: Path) -> None:
    out = tmp_path / "motp.pyz"
    build_pyz.build(SRC, out)
    starter = tmp_path / "config.toml"

    def motp(*args: str) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(
            [sys.executable, "-I", "-S", str(out), *args],
            capture_output=True,
            text=True,
            env={"LANG": "C"},
        )

    assert motp("config", "init", "--path", str(starter)).returncode == 0
    checked = motp("config", "check", str(starter))
    assert checked.returncode == 0, checked.stderr
    assert (
        checked.stdout.splitlines()[0]
        == f"{starter}: valid (checked on its own, on top of the defaults)"
    )
    bad = tmp_path / "bad.toml"
    bad.write_text("[visibility]\nadmin_group = 'adm'\n")
    refused = motp("config", "check", str(bad))
    assert refused.returncode == 1
    assert "visibility.admin_group may not be" in refused.stdout

"""Open item O15: what ``sys.path`` looks like under ``python3 -I -S``.

The program is run once as the archive and once as an unpacked directory, which is the
installed form (D31). Each run prints its ``sys.path`` (visible with ``pytest -s``), and the
test asserts the expected shape: the program first, then only the interpreter's own
standard library; no site directory, no current directory, nothing a user can write to.
"""

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from .conftest import SRC, TOOLS

sys.path.insert(0, str(TOOLS))
import build_pyz

# Same root program as the real archive, plus a dump of the interpreter state.
PROBE_MAIN = """\
import json
import sys

import motp

print(json.dumps({
    "path": sys.path,
    "isolated": sys.flags.isolated,
    "no_site": sys.flags.no_site,
    "motp_file": motp.__file__,
    "site_loaded": "site" in sys.modules,
}))
"""


def _run(program: Path, cwd: Path) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(program)],
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    data: dict[str, Any] = json.loads(result.stdout)
    print(f"\nsys.path under -I -S for {program.name}:")
    for entry in data["path"]:
        print(f"  {entry}")
    return data


def _check_shape(data: dict[str, Any], program: Path) -> None:
    path: list[str] = data["path"]
    assert data["isolated"] == 1 and data["no_site"] == 1
    assert data["site_loaded"] is False
    # The program itself is importable: first entry, and ``motp`` was found inside it.
    assert os.path.samefile(path[0], program)
    assert Path(data["motp_file"]).as_posix().startswith(program.as_posix())
    rest = path[1:]
    assert rest, "the interpreter's standard library must follow the program"
    prefixes = {os.path.realpath(p) for p in (sys.base_prefix, sys.base_exec_prefix)}
    for entry in rest:
        real = os.path.realpath(entry)
        lowered = entry.replace("\\", "/").lower()
        assert entry not in ("", "."), "current directory on sys.path"
        assert "site-packages" not in lowered and "dist-packages" not in lowered
        assert any(real == p or real.startswith(p + os.sep) for p in prefixes), entry
        if os.name == "posix" and os.path.exists(real):
            assert os.stat(real).st_mode & 0o022 == 0, f"group/other-writable: {entry}"


@pytest.fixture
def hostile_cwd(tmp_path: Path) -> Path:
    """A working directory with look-alike modules that must never be imported."""
    cwd = tmp_path / "cwd"
    (cwd / "motp").mkdir(parents=True)
    (cwd / "motp" / "__init__.py").write_text("raise SystemExit('imported from cwd')\n")
    (cwd / "json.py").write_text("raise SystemExit('imported json from cwd')\n")
    return cwd


@pytest.fixture
def probe_archive(tmp_path: Path) -> Path:
    out = tmp_path / "probe.pyz"
    build_pyz.build(SRC, out, main_source=PROBE_MAIN)
    return out


def test_sys_path_for_archive(probe_archive: Path, hostile_cwd: Path) -> None:
    _check_shape(_run(probe_archive, hostile_cwd), probe_archive)


def test_sys_path_for_unpacked_directory(
    probe_archive: Path, hostile_cwd: Path, tmp_path: Path
) -> None:
    unpacked = tmp_path / "lib"
    with zipfile.ZipFile(probe_archive) as zf:
        zf.extractall(unpacked)
    _check_shape(_run(unpacked, hostile_cwd), unpacked)

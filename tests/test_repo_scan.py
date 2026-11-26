"""Invariant 3: the repository hygiene scan under tools/ runs as part of the test suite."""

import shutil
import subprocess
import sys

import pytest

from .conftest import ROOT, TOOLS


def test_repository_scan_is_clean() -> None:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout (the scan reads `git ls-files`)")
    result = subprocess.run(
        [sys.executable, "-I", str(TOOLS / "scan_repo.py")], capture_output=True, text=True
    )
    assert result.returncode == 0, f"scan found problems:\n{result.stdout}{result.stderr}"

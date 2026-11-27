"""The release (phase 14, D13): the version, the tag rule and the changelog."""

import sys

import pytest

from motp import __version__

from .conftest import ROOT, TOOLS

sys.path.insert(0, str(TOOLS))
import check_tag


def test_the_source_version_is_a_release_candidate_of_1_0() -> None:
    assert __version__ == check_tag.source_version() == "1.0.0rc1"


@pytest.mark.parametrize(
    ("tag", "version", "ok"),
    [
        ("v1.0.0rc1", "1.0.0rc1", True),
        ("v1.0.0", "1.0.0", True),
        ("1.0.0", "1.0.0", False),  # no leading v
        ("v1.0.0", "1.0.0rc1", False),  # tag and source disagree
        ("v1.0.0-rc.1", "1.0.0rc1", False),  # not PEP 440's spelling
        ("v0.1.0.dev0", "0.1.0.dev0", False),  # development versions are not released
        ("v1.0.0+local", "1.0.0+local", False),
        ("v01.0.0", "01.0.0", False),
    ],
)
def test_a_tag_releases_only_the_exact_source_version(tag: str, version: str, ok: bool) -> None:
    assert (check_tag.problem(tag, version) is None) is ok


def test_check_tag_exits_non_zero_for_a_wrong_tag(capsys: pytest.CaptureFixture[str]) -> None:
    assert check_tag.main(["v9.9.9"]) == 1
    assert "expected v" in capsys.readouterr().err
    assert check_tag.main([f"v{__version__}"]) == 0


def test_the_changelog_and_the_readme_status_name_this_version() -> None:
    """docs/release.md relies on this: moving from a candidate to the release means
    changing the version, the README's status line and the changelog heading together."""
    import re as _re

    release, _, candidate = __version__.partition("rc")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = _re.search(r"^## (\S+)(.*)$", changelog, _re.MULTILINE)
    assert heading and heading.group(1) == release, "the newest changelog entry"
    assert ("release candidate" in heading.group(2)) is bool(candidate)
    status = _re.search(r"^Status: (.*)$", (ROOT / "README.md").read_text(encoding="utf-8"), _re.M)
    assert status and f" {__version__}." in status.group(1)
    assert ("release candidate" in status.group(1)) is bool(candidate)


# --- tools/repro_check.py -----------------------------------------------------------------

import io as _io  # noqa: E402
import tarfile as _tarfile  # noqa: E402
from pathlib import Path  # noqa: E402

import repro_check  # noqa: E402


def test_wsl_paths() -> None:
    assert repro_check.wsl_path(Path("C:/work/motp/dist")) == "/mnt/c/work/motp/dist"
    # Strings, so the test means the same on Linux, where Path would not split at "\".
    assert repro_check.wsl_path("C:\\x y\\z") == "/mnt/c/x y/z"
    assert repro_check.wsl_path("L:\\") == "/mnt/l"
    assert repro_check.wsl_path("/mnt/c/already") == "/mnt/c/already"


def _tar(entries: dict[str, bytes]) -> bytes:
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in entries.items():
            info = _tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, _io.BytesIO(data))
    return buf.getvalue()


def test_safe_extract_keeps_files_inside(tmp_path: Path) -> None:
    assert repro_check.safe_extract(_tar({"a/b.py": b"x"}), tmp_path) == 1
    assert (tmp_path / "a" / "b.py").read_bytes() == b"x"
    for bad in ("../evil", "/abs"):
        with pytest.raises(ValueError):
            repro_check.safe_extract(_tar({bad: b"x"}), tmp_path / "t")


def test_compare_needs_identical_bytes(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"same")
    b.write_bytes(b"same")
    assert repro_check.compare(a, b)[2]
    b.write_bytes(b"diff")
    assert not repro_check.compare(a, b)[2]


# --- README ---------------------------------------------------------------------------------


def test_the_readme_installs_this_version_from_the_real_repository() -> None:
    import re as _re

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"VERSION={__version__}\n" in text
    urls = _re.findall(r"https://github\.com/[^\s\"/]+/[^\s\"/]+/releases/download/[^\s\"]+", text)
    base = "https://github.com/Hiroyugane/message-of-the-python/releases/download/v$VERSION"
    assert urls and all(u == base for u in urls)
    install = text.split("<!-- release-check:install -->", 1)[1].split("```")[1]
    # Security review of phase 14: a pasted block must stop at the first failure, run in a
    # fresh private directory, check before the root step and run Python isolated.
    lines = [ln.strip() for ln in install.splitlines() if ln.strip()]
    assert lines[1] == "(" and lines[2] == "set -eu" and lines[-1] == ")"
    assert 'cd "$(mktemp -d)"' in lines and "umask 022" in lines
    assert lines.index("sha256sum --check SHA256SUMS") < lines.index(
        "sudo /usr/bin/python3 -I -S ./motp.pyz install"
    )
    assert "--signer-workflow" in install and '--source-ref "refs/tags/v$VERSION"' in install
    for block in ("prereq-apt", "prereq-dnf", "install", "doctor", "uninstall"):
        assert text.count(f"<!-- release-check:{block} -->") == 1
    for placeholder in ("<owner>", "OWNER", "<version>", "x.y.z", "YOUR_", "example/"):
        assert placeholder not in text

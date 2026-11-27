"""The vendored code is exactly what the manifest records (blueprint T16)."""

import hashlib
import json

from .conftest import SRC

VENDOR = SRC / "motp" / "_vendor"


def _manifest() -> dict[str, dict[str, object]]:
    data = json.loads((VENDOR / "manifest.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_every_vendored_file_matches_its_recorded_hash() -> None:
    for package, entry in _manifest().items():
        files = entry["files"]
        assert isinstance(files, dict) and files, package
        for rel, info in files.items():
            digest = hashlib.sha256((VENDOR / rel).read_bytes()).hexdigest()
            assert digest == info["sha256"], rel


def test_no_unrecorded_file_in_a_vendored_package() -> None:
    for package, entry in _manifest().items():
        files = entry["files"]
        assert isinstance(files, dict)
        recorded = set(files)
        present = {
            p.relative_to(VENDOR).as_posix()
            for p in (VENDOR / package).rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        }
        assert present == recorded, package


def test_manifest_records_version_and_source_hash() -> None:
    tomli = _manifest()["tomli"]
    assert tomli["version"] == "2.3.2"
    assert len(str(tomli["source_sha256"])) == 64
    init = (VENDOR / "tomli" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{tomli["version"]}"' in init

"""Shared pytest setup: the Linux-ownership marker, root fixtures and paths."""

import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TOOLS = ROOT / "tools"

# Accounts that tools/container/accounts.sh creates inside the container (names and ids
# are fixed there). TEST_USER is also a member of EXTRA_GROUP, so a child that kept its
# supplementary groups would show it. OTHER_USER is a member of ADMIN_GROUP. PROBE_USER and
# PLUGIN_USER are the real names the collector looks up (D21).
TEST_USER = "motp-test"
OTHER_USER = "motp-test2"
EXTRA_GROUP = "motp-test-x"
PROBE_USER = "motp"
PLUGIN_USER = "motp-plugin"
ADMIN_GROUP = "motp-admin"
# Set by the container script: tests that need Linux and root must run, not be skipped.
REQUIRE_ROOT_ENV = "MOTP_REQUIRE_ROOT_TESTS"
# Root-owned, 0755 parent of trusted fixture trees (the chain /, /var, /var/lib is root's).
TRUSTED_PARENT = "/var/lib"


sys.path.insert(0, str(TOOLS))
import compile_catalogs  # noqa: E402


def pytest_sessionstart(session: pytest.Session) -> None:
    """Compile the catalogues so the unpacked tree under test has its ``.mo`` files."""
    compile_catalogs.write_all()


def _can_test_ownership() -> bool:
    """Ownership, user and group tests need Linux and root (the CI containers)."""
    return sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _can_test_ownership():
        return
    if os.environ.get(REQUIRE_ROOT_ENV) == "1":
        raise pytest.UsageError(f"{REQUIRE_ROOT_ENV}=1 but not running on Linux as root")
    skip = pytest.mark.skip(reason="needs Linux and root (runs inside the CI containers)")
    for item in items:
        if "needs_linux_owner" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def trusted_dir() -> Iterator[Path]:
    """A fresh directory whose whole chain belongs to root and is writable by root only.

    ``tmp_path`` lives below a world-writable ``/tmp`` and would fail every ownership
    check, so trusted trees are made on the container's own filesystem under /var/lib.
    """
    path = Path(tempfile.mkdtemp(prefix="motp-test-", dir=TRUSTED_PARENT))
    os.chmod(path, 0o755)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def account(name: str) -> tuple[int, int]:
    """uid and primary gid of a test account; fails the test if the container lacks it."""
    import pwd

    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        pytest.fail(f"test account {name} missing; run inside tools/container_test.py")
    return entry.pw_uid, entry.pw_gid

"""Cache and state files on disk (blueprint 4.1, 4.4, T12, T19).

The state file format runs everywhere; directories, atomic writes and the lock need Linux
and root (the containers of ``tools/container_test.py``).
"""

import os
import stat
from pathlib import Path

import pytest

from motp.collect import store
from motp.core.model import Item, ModuleResult, Unit

from .conftest import TEST_USER, account

NOW = 1795600000
ITEM = Item(key="hw_disks.root", value=50, unit=Unit.PERCENT, rule="disk_used_percent")
RESULT = ModuleResult(collected=NOW - 60, interval=300, max_age=3600, items=(ITEM,))
ENTRY = store.Entry(NOW - 60, RESULT)
root = pytest.mark.needs_linux_owner


def test_state_round_trips_and_drops_broken_entries() -> None:
    data = store.encode_state(NOW, {"hw_disks": ENTRY})
    assert store.decode_state(data) == {"hw_disks": ENTRY}
    assert store.decode_state(data.replace(b'"attempted":', b'"attempted":-')) == {}
    with pytest.raises(ValueError):
        store.decode_state(b'{"schema": 2, "modules": {}}')
    with pytest.raises(ValueError):
        store.decode_state(b"[]")


def test_a_large_state_shrinks_to_what_the_reader_accepts() -> None:
    items = tuple(Item(key=f"big.k{n}", value="x" * 1000) for n in range(32))
    big = {
        f"mod{m:02}": store.Entry(NOW, ModuleResult(NOW, 300, 3600, items=items)) for m in range(40)
    }
    data = store.encode_state(NOW, big)
    assert len(data) <= store.MAX_STATE_BYTES
    decoded = store.decode_state(data)
    assert set(decoded) == set(big)  # every attempt time survives
    assert any(e.result.items for e in decoded.values())  # as many items as fit
    assert any(not e.result.items for e in decoded.values())


def test_user_file_names_need_a_real_uid() -> None:
    assert store.user_file_name(1000) == "1000.json"
    for bad in (-1, 2**32, "1000", True):
        with pytest.raises(ValueError):
            store.user_file_name(bad)  # type: ignore[arg-type]


def _open(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY)


@root
def test_prepare_dir_creates_and_sets_the_mode(trusted_dir: Path) -> None:
    fd = store.prepare_dir(str(trusted_dir / "run"), 0o755)
    os.close(fd)
    st = os.lstat(trusted_dir / "run")
    assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o755, 0, 0)
    fd = store.prepare_dir(str(trusted_dir / "run"), 0o700)  # adopting changes the mode
    os.close(fd)
    assert stat.S_IMODE(os.lstat(trusted_dir / "run").st_mode) == 0o700


@root
@pytest.mark.parametrize("problem", ["link", "file", "foreign", "writable"])
def test_prepare_dir_refuses_what_it_did_not_make_safe(trusted_dir: Path, problem: str) -> None:
    target = trusted_dir / "run"
    if problem == "link":
        (trusted_dir / "real").mkdir(mode=0o755)
        target.symlink_to(trusted_dir / "real")
    elif problem == "file":
        target.write_text("")
    else:
        target.mkdir(mode=0o755)
        if problem == "foreign":
            os.chown(target, account(TEST_USER)[0], -1)
        else:
            target.chmod(0o777)
    with pytest.raises(store.StoreError):
        store.prepare_dir(str(target), 0o755)


@root
def test_prepare_dir_refuses_an_unsafe_parent(trusted_dir: Path) -> None:
    parent = trusted_dir / "open"
    parent.mkdir()
    parent.chmod(0o777)
    with pytest.raises(store.StoreError):
        store.prepare_dir(str(parent / "run"), 0o755)
    assert not (parent / "run").exists()


@root
def test_write_atomic_sets_owner_group_mode_and_replaces_links(trusted_dir: Path) -> None:
    uid, gid = account(TEST_USER)
    outside = trusted_dir / "outside"
    outside.write_text("keep")
    (trusted_dir / "public.json").symlink_to(outside)
    fd = _open(trusted_dir)
    try:
        store.write_atomic(fd, "public.json", b"{}", mode=0o640, uid=uid, gid=gid)
    finally:
        os.close(fd)
    st = os.lstat(trusted_dir / "public.json")
    assert stat.S_ISREG(st.st_mode)
    assert (stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid) == (0o640, uid, gid)
    assert (trusted_dir / "public.json").read_bytes() == b"{}"
    assert outside.read_text() == "keep"
    assert sorted(p.name for p in trusted_dir.iterdir()) == ["outside", "public.json"]


@root
def test_the_lock_is_taken_once(trusted_dir: Path) -> None:
    fd = _open(trusted_dir)
    try:
        first = store.acquire_lock(fd)
        assert first is not None
        assert store.acquire_lock(fd) is None  # another open file of the same lock
        os.close(first)
        again = store.acquire_lock(fd)
        assert again is not None
        os.close(again)
        st = os.lstat(trusted_dir / store.LOCK_NAME)
        assert (stat.S_IMODE(st.st_mode), st.st_uid) == (0o600, 0)
        os.chmod(trusted_dir / store.LOCK_NAME, 0o644)
        with pytest.raises(store.StoreError):
            store.acquire_lock(fd)
    finally:
        os.close(fd)


@root
def test_state_is_read_only_from_a_file_of_root(trusted_dir: Path) -> None:
    fd = _open(trusted_dir)
    try:
        data = store.encode_state(NOW, {"hw_disks": ENTRY})
        store.write_atomic(fd, store.STATE_NAME, data, mode=0o600, uid=0, gid=0)
        assert store.read_state(fd) == {"hw_disks": ENTRY}
        os.chown(trusted_dir / store.STATE_NAME, account(TEST_USER)[0], -1)
        assert store.read_state(fd) == {}
    finally:
        os.close(fd)

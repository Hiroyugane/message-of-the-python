"""Reads of a probe that runs as root (phase 10): every file outside ``/proc`` and ``/sys``
goes through the ownership check, a group-writable record file is accepted, and the parts
of a sparse file that hold data are found without reading its holes."""

import os
import sys
from pathlib import Path

import pytest

from motp.collect import context
from motp.collect.context import ProbeContext
from motp.core import safepath
from motp.core.model import ContractError

root_only = pytest.mark.skipif(
    not sys.platform.startswith("linux") or getattr(os, "geteuid", lambda: 1)() != 0,
    reason="needs Linux and root (runs inside the CI containers)",
)


@root_only
def test_root_reads_a_group_writable_record_file(
    trusted_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = trusted_dir / "wtmp"
    path.write_bytes(b"x" * 384)
    path.chmod(0o664)
    monkeypatch.setattr(context, "RECORD_FILES", frozenset({str(path)}))
    ctx = ProbeContext()  # the paths are outside the read roots: the checked opener itself
    assert ctx._file_size(str(path)) == 384  # wtmp is 0664 root:utmp by design
    assert ctx._read_slice(str(path), 380, 10) == b"xxxx"


@root_only
def test_group_write_is_allowed_for_the_record_files_alone(trusted_dir: Path) -> None:
    path = trusted_dir / "passwd"
    path.write_text("root:x:0:0::/root:/bin/sh\n")
    path.chmod(0o664)
    with pytest.raises(ContractError):  # not a login record: the full check
        ProbeContext()._file_size(str(path))


@root_only
def test_a_record_file_in_a_group_writable_log_directory(trusted_dir: Path) -> None:
    log = trusted_dir / "log"
    log.mkdir()
    log.chmod(0o775)  # Ubuntu with rsyslog: /var/log is 0775 root:syslog
    lastlog = log / "lastlog"
    lastlog.write_bytes(bytes(292))
    lastlog.chmod(0o664)
    fd, _trusted = safepath.open_trusted(str(lastlog), group_writable=True)
    os.close(fd)
    with pytest.raises(ContractError):  # without the record rule the directory is refused
        safepath.open_trusted(str(lastlog))
    log.chmod(0o777)  # writable by others: never
    with pytest.raises(ContractError):
        safepath.open_trusted(str(lastlog), group_writable=True)
    log.chmod(0o775)
    inner = log / "sub"
    inner.mkdir()
    inner.chmod(0o755)
    (inner / "wtmp").write_bytes(bytes(384))
    deeper = trusted_dir / "open"
    deeper.mkdir()
    deeper.chmod(0o775)
    (deeper / "sub").mkdir()
    (deeper / "sub").chmod(0o755)
    (deeper / "sub" / "wtmp").write_bytes(bytes(384))
    with pytest.raises(ContractError):  # only the directory that holds the file
        safepath.open_trusted(str(deeper / "sub" / "wtmp"), group_writable=True)


@root_only
def test_root_never_reads_through_a_users_link(trusted_dir: Path) -> None:
    secret = trusted_dir / "secret"
    secret.write_text("root only")
    secret.chmod(0o600)
    open_dir = trusted_dir / "log"
    open_dir.mkdir(mode=0o755)
    link = open_dir / "wtmp"
    link.symlink_to(secret)
    os.lchown(link, 1000, 1000)  # a link that a user planted
    ctx = ProbeContext()
    with pytest.raises(ContractError):
        ctx._read_slice(str(link), 0, 10)


@root_only
def test_root_never_reads_below_a_directory_others_can_write(trusted_dir: Path) -> None:
    shared = trusted_dir / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    target = shared / "lastlog"
    target.write_bytes(b"\0" * 292)
    with pytest.raises(ContractError):
        ProbeContext()._file_size(str(target))


@root_only
def test_root_refuses_a_file_others_can_write_or_another_user_owns(trusted_dir: Path) -> None:
    path = trusted_dir / "lastlog"
    path.write_bytes(b"\0" * 292)
    path.chmod(0o646)
    with pytest.raises(ContractError):
        ProbeContext()._file_size(str(path))
    path.chmod(0o644)
    os.chown(path, 1000, 0)
    with pytest.raises(ContractError):
        ProbeContext()._file_size(str(path))


@root_only
def test_the_parts_of_a_sparse_file_that_hold_data(trusted_dir: Path) -> None:
    path = trusted_dir / "lastlog"
    record = b"\x01" * 292
    with open(path, "wb") as f:
        f.seek(292 * 5000)
        f.write(record)
        f.seek(292 * 900_000)
        f.write(record)
    path.chmod(0o644)
    regions = ProbeContext()._data_regions(str(path), 292, 1024 * 1024)
    assert all(offset % 292 == 0 for offset, _data in regions)
    found = [
        offset // 292 + i
        for offset, data in regions
        for i in range(len(data) // 292)
        if data[i * 292 : (i + 1) * 292] == record
    ]
    assert found == [5000, 900_000]
    assert sum(len(data) for _offset, data in regions) < 64 * 1024  # holes are skipped


# --- phase 11: the other context calls of a root probe walk the same chain ---------------


@root_only
def test_root_exists_refuses_a_path_below_a_directory_others_can_write(
    trusted_dir: Path,
) -> None:
    shared = trusted_dir / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    (shared / "btmp").write_bytes(bytes(384))
    ctx = ProbeContext()
    with pytest.raises(ContractError):
        ctx._exists(str(shared / "btmp"))
    assert ctx._exists(str(trusted_dir / "missing")) is False
    assert ctx._exists(str(trusted_dir)) is True


@root_only
def test_root_exists_does_not_follow_a_users_link(trusted_dir: Path) -> None:
    link = trusted_dir / "docker.sock"
    link.symlink_to("/etc/passwd")
    os.lchown(link, 1000, 1000)
    with pytest.raises(ContractError):
        ProbeContext()._exists(str(link))


@root_only
def test_root_list_dir_mtime_and_statvfs_check_the_chain(trusted_dir: Path) -> None:
    shared = trusted_dir / "shared"
    shared.mkdir()
    (shared / "a").write_text("x")
    (shared / "a").chmod(0o644)
    ctx = ProbeContext()
    assert ctx._list_dir(str(shared)) == ["a"]
    assert ctx._mtime(str(shared / "a")) > 0
    assert ctx._statvfs(str(shared)).size > 0
    shared.chmod(0o777)
    with pytest.raises(ContractError):
        ctx._list_dir(str(shared))
    with pytest.raises(ContractError):
        ctx._mtime(str(shared / "a"))
    with pytest.raises(ContractError):
        ctx._statvfs(str(shared))
    shared.chmod(0o755)
    (shared / "a").chmod(0o666)  # a file others can write: its time says nothing
    with pytest.raises(ContractError):
        ctx._mtime(str(shared / "a"))


@root_only
def test_btmp_is_a_record_file() -> None:
    assert "/var/log/btmp" in context.RECORD_FILES

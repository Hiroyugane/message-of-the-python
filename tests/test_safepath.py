"""Ownership-chain checks (blueprint 4.7, 4.9, T1, T17, T21).

Tests that build ownership chains need Linux and root; they run inside the containers of
``tools/container_test.py`` on the container's own filesystem (fixture ``trusted_dir``).
"""

import os
from pathlib import Path

import pytest

from motp.core import safepath
from motp.core.safepath import UnsafePath

from .conftest import OTHER_USER, account

linux_root = pytest.mark.needs_linux_owner


def reason(exc: pytest.ExceptionInfo[UnsafePath]) -> tuple[str, str]:
    params = exc.value.message.param_dict()
    return exc.value.message.id, str(params.get("path", ""))


def write(path: Path, text: str = "x = 1\n", mode: int = 0o644) -> Path:
    path.write_text(text)
    os.chmod(path, mode)
    return path


# --- pure parts, everywhere -----------------------------------------------------------


@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"#!/bin/sh\necho", ("/bin/sh", None)),
        (b"#! /usr/bin/python3 -I -S\n", ("/usr/bin/python3", "-I -S")),
        (b"#!/usr/bin/env  python3 \n", ("/usr/bin/env", "python3")),
        (b"#!/bin/sh\t\n", ("/bin/sh", None)),
        (b"#!/bin/sh", ("/bin/sh", None)),  # a short file without line end is one line
        (b"\x7fELF\x02\x01", None),
        (b"", None),
    ],
)
def test_shebang_is_split_like_the_kernel(head: bytes, expected: object) -> None:
    assert safepath.parse_shebang(head, "/x") == expected


@pytest.mark.parametrize(
    ("head", "msg_id"),
    [
        (b"#!/" + b"a" * 300 + b"\n", "safepath.error.shebang_too_long"),
        (b"#!/" + b"a" * 130 + b"\n", "safepath.error.shebang_too_long"),  # kernels < 5.1
        (b"#!/" + b"a" * 200, "safepath.error.shebang_too_long"),
        (b"#!  \n", "safepath.error.shebang_empty"),
        (b"#!/bin/\xff\n", "safepath.error.shebang_encoding"),
    ],
)
def test_bad_shebang_lines_are_refused(head: bytes, msg_id: str) -> None:
    with pytest.raises(UnsafePath) as exc:
        safepath.parse_shebang(head, "/x")
    assert exc.value.message.id == msg_id


def test_overlong_paths_are_refused_as_such() -> None:
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file("/" + "a/" * 2100)
    assert exc.value.message.id == "safepath.error.too_long"


@pytest.mark.parametrize("path", ["etc/motp/config.toml", "", "./x", "a\x00b"])
def test_relative_or_malformed_paths_are_refused(path: str) -> None:
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(path)
    assert exc.value.message.id == "safepath.error.not_absolute"


@pytest.mark.skipif(os.name == "posix", reason="the refusal is for systems without owners")
def test_systems_without_owners_refuse_everything() -> None:
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file("/etc/motp/config.toml")
    assert exc.value.message.id == "safepath.error.unsupported"


# --- ownership chains, Linux as root --------------------------------------------------


@linux_root
def test_a_root_owned_chain_is_accepted(trusted_dir: Path) -> None:
    conf = trusted_dir / "conf.d"
    conf.mkdir(mode=0o755)
    f = write(conf / "10-a.toml")
    trusted = safepath.check_file(str(f))
    assert trusted.path == str(f)
    assert safepath.check_directory(str(conf)) == str(conf)
    data, again = safepath.read_trusted(str(f), 1024)
    assert data == b"x = 1\n" and again.ino == trusted.ino


@linux_root
def test_group_writable_parent_is_refused(trusted_dir: Path) -> None:
    conf = trusted_dir / "conf.d"
    conf.mkdir()
    os.chmod(conf, 0o775)
    f = write(conf / "10-a.toml")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(f))
    assert reason(exc) == ("safepath.error.writable", str(conf))


@linux_root
def test_other_writable_file_is_refused(trusted_dir: Path) -> None:
    f = write(trusted_dir / "a.toml", mode=0o646)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(f))
    assert reason(exc) == ("safepath.error.writable", str(f))


@linux_root
def test_world_writable_sticky_directory_is_refused(trusted_dir: Path) -> None:
    tmp = trusted_dir / "tmp"
    tmp.mkdir()
    os.chmod(tmp, 0o1777)
    f = write(tmp / "a.toml")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(f))
    assert reason(exc) == ("safepath.error.writable", str(tmp))


@linux_root
def test_foreign_owner_is_refused_for_file_and_directory(trusted_dir: Path) -> None:
    uid, gid = account(OTHER_USER)
    f = write(trusted_dir / "a.toml")
    os.chown(f, uid, gid)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(f))
    assert reason(exc) == ("safepath.error.owner", str(f))

    sub = trusted_dir / "sub"
    sub.mkdir(mode=0o755)
    os.chown(sub, uid, gid)
    g = write(sub / "b.toml")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(g))
    assert reason(exc) == ("safepath.error.owner", str(sub))


@linux_root
def test_root_owned_file_with_foreign_group_but_no_group_write_is_accepted(
    trusted_dir: Path,
) -> None:
    _uid, gid = account(OTHER_USER)
    f = write(trusted_dir / "a.toml", mode=0o640)
    os.chown(f, 0, gid)
    assert safepath.check_file(str(f)).path == str(f)


@linux_root
@pytest.mark.parametrize("kind", ["fifo", "directory", "socket", "device"])
def test_non_regular_files_are_refused(trusted_dir: Path, kind: str) -> None:
    target = trusted_dir / "x.toml"
    real = str(target)
    if kind == "fifo":
        os.mkfifo(target, 0o644)
    elif kind == "directory":
        target.mkdir(mode=0o755)
    elif kind == "socket":
        import socket

        sock = socket.socket(socket.AF_UNIX)
        sock.bind(real)
        sock.close()
        os.chmod(target, 0o644)
    else:
        target.symlink_to("/dev/null")  # containers may not create device nodes
        real = "/dev/null"
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(target))
    assert reason(exc) == ("safepath.error.not_regular", real)


@linux_root
def test_a_fifo_does_not_block_the_trusted_open(trusted_dir: Path) -> None:
    fifo = trusted_dir / "f"
    os.mkfifo(fifo, 0o644)
    with pytest.raises(UnsafePath):
        safepath.read_trusted(str(fifo), 100)


@linux_root
def test_symlinked_directory_into_a_writable_place_is_refused(trusted_dir: Path) -> None:
    outside = trusted_dir / "outside"
    outside.mkdir()
    os.chmod(outside, 0o777)
    write(outside / "a.toml")
    link = trusted_dir / "conf.d"
    link.symlink_to(outside)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(link / "a.toml"))
    assert reason(exc) == ("safepath.error.writable", str(outside))


@linux_root
def test_symlink_owned_by_another_user_is_refused(trusted_dir: Path) -> None:
    uid, gid = account(OTHER_USER)
    real = trusted_dir / "real"
    real.mkdir(mode=0o755)
    write(real / "a.toml")
    link = trusted_dir / "conf.d"
    link.symlink_to(real)
    os.lchown(link, uid, gid)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(link / "a.toml"))
    assert reason(exc) == ("safepath.error.link_owner", str(link))


@linux_root
def test_root_owned_links_in_a_trusted_chain_resolve_to_the_real_path(trusted_dir: Path) -> None:
    real = trusted_dir / "real"
    real.mkdir(mode=0o755)
    f = write(real / "a.toml")
    (trusted_dir / "abs").symlink_to(real)
    (trusted_dir / "rel").symlink_to("real")
    (real / "file-link").symlink_to("a.toml")
    for path in ("abs/a.toml", "rel/a.toml", "rel/../real/file-link", "abs/./a.toml"):
        assert safepath.check_file(str(trusted_dir / path)).path == str(f), path


@linux_root
def test_link_loops_are_refused(trusted_dir: Path) -> None:
    (trusted_dir / "a").symlink_to("b")
    (trusted_dir / "b").symlink_to("a")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(trusted_dir / "a"))
    assert exc.value.message.id == "safepath.error.too_many_links"


@linux_root
def test_missing_file_and_file_as_directory(trusted_dir: Path) -> None:
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(trusted_dir / "nope.toml"))
    assert exc.value.message.id == "safepath.error.missing"
    f = write(trusted_dir / "f")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(f / "x"))
    assert reason(exc) == ("safepath.error.not_directory", str(f))


@linux_root
def test_hard_link_in_a_writable_directory_is_refused(trusted_dir: Path) -> None:
    f = write(trusted_dir / "a.toml")
    open_dir = trusted_dir / "open"
    open_dir.mkdir()
    os.chmod(open_dir, 0o777)
    os.link(f, open_dir / "a.toml")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_file(str(open_dir / "a.toml"))
    assert reason(exc) == ("safepath.error.writable", str(open_dir))


@linux_root
def test_oversized_file_is_refused(trusted_dir: Path) -> None:
    f = write(trusted_dir / "big.toml", "x" * 2000)
    with pytest.raises(UnsafePath) as exc:
        safepath.read_trusted(str(f), 1000)
    assert exc.value.message.id == "safepath.error.too_large"


# --- programs and interpreter lines ---------------------------------------------------


def script(path: Path, interpreter_line: str, mode: int = 0o755) -> Path:
    return write(path, f"#!{interpreter_line}\necho ok\n", mode)


@linux_root
def test_system_shell_script_is_accepted(trusted_dir: Path) -> None:
    prog = safepath.check_program(str(script(trusted_dir / "p", "/bin/sh")), runs_as_root=True)
    assert prog.path == str(trusted_dir / "p")
    assert prog.interpreter is not None
    assert prog.interpreter.interpreter is None
    assert os.path.realpath("/bin/sh") == prog.interpreter.path


@linux_root
def test_interpreter_in_a_writable_directory_is_refused(trusted_dir: Path) -> None:
    open_dir = trusted_dir / "bin"
    open_dir.mkdir()
    os.chmod(open_dir, 0o777)
    interp = open_dir / "sh"
    interp.write_bytes(Path("/bin/sh").resolve().read_bytes())
    os.chmod(interp, 0o755)
    prog = script(trusted_dir / "p", str(interp))
    for as_root in (True, False):
        with pytest.raises(UnsafePath) as exc:
            safepath.check_program(str(prog), runs_as_root=as_root)
        assert reason(exc) == ("safepath.error.writable", str(open_dir))


@linux_root
def test_interpreter_owned_by_another_user_is_refused(trusted_dir: Path) -> None:
    uid, gid = account(OTHER_USER)
    interp = trusted_dir / "interp"
    interp.write_bytes(Path("/bin/sh").resolve().read_bytes())
    os.chmod(interp, 0o755)
    os.chown(interp, uid, gid)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(script(trusted_dir / "p", str(interp))), runs_as_root=False)
    assert reason(exc) == ("safepath.error.owner", str(interp))


@linux_root
def test_env_line_is_refused_only_for_root(trusted_dir: Path) -> None:
    prog = script(trusted_dir / "p", "/usr/bin/env sh")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(prog), runs_as_root=True)
    assert exc.value.message.id == "safepath.error.launcher_as_root"
    checked = safepath.check_program(str(prog), runs_as_root=False)
    assert checked.interpreter is not None and checked.interpreter_arg == "sh"


@linux_root
def test_env_behind_another_name_is_refused_for_root(trusted_dir: Path) -> None:
    alias = trusted_dir / "python"
    alias.symlink_to("/usr/bin/env")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(script(trusted_dir / "p", str(alias))), runs_as_root=True)
    assert exc.value.message.id == "safepath.error.launcher_as_root"


@linux_root
def test_relative_interpreter_and_missing_execute_bit_are_refused(trusted_dir: Path) -> None:
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(script(trusted_dir / "p", "sh")), runs_as_root=False)
    assert exc.value.message.id == "safepath.error.interpreter_relative"
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(script(trusted_dir / "q", "/bin/sh", 0o644)), False)
    assert exc.value.message.id == "safepath.error.not_executable"


@linux_root
def test_interpreter_chains_are_checked_and_bounded(trusted_dir: Path) -> None:
    inner = script(trusted_dir / "inner", "/bin/sh")
    outer = script(trusted_dir / "outer", str(inner))
    prog = safepath.check_program(str(outer), runs_as_root=True)
    assert prog.interpreter is not None and prog.interpreter.path == str(inner)
    previous = outer
    for i in range(5):
        previous = script(trusted_dir / f"s{i}", str(previous))
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(previous), runs_as_root=False)
    assert exc.value.message.id == "safepath.error.interpreter_depth"


@linux_root
@pytest.mark.parametrize("line", ["/usr/bin/nice sh", "/bin/sh script", "/usr/bin/timeout 5"])
def test_path_searching_launchers_are_refused_for_root(trusted_dir: Path, line: str) -> None:
    prog = script(trusted_dir / "p", line)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(prog), runs_as_root=True)
    assert exc.value.message.id == "safepath.error.launcher_as_root"


@linux_root
def test_options_and_absolute_arguments_are_fine_for_root(trusted_dir: Path) -> None:
    helper = trusted_dir / "helper.sh"
    helper.write_text("echo helper\n")
    helper.chmod(0o644)
    for i, line in enumerate(["/bin/sh -e", f"/bin/sh {helper}"]):
        prog = safepath.check_program(str(script(trusted_dir / f"p{i}", line)), True)
        assert prog.interpreter_arg == line.split(" ", 1)[1]


@linux_root
def test_an_absolute_argument_must_pass_the_ownership_check_too(trusted_dir: Path) -> None:
    """Phase 12 security review: the argument can name the code that really runs."""
    helper = trusted_dir / "helper.sh"
    helper.write_text("echo helper\n")
    helper.chmod(0o666)
    prog = script(trusted_dir / "p", f"/bin/sh {helper}")
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(prog), runs_as_root=True, known_format=True)
    assert exc.value.message.id == "safepath.error.writable"
    # Only a plugin's own line (known_format, depth 0): system programs further down a
    # chain keep their arguments (coreutils-single's env passes one with "=").
    plain = script(trusted_dir / "q", f"/bin/sh {helper}")
    assert safepath.check_program(str(plain), runs_as_root=True).interpreter_arg is not None
    wrapper = script(trusted_dir / "w", "/bin/sh --x=y")
    outer = script(trusted_dir / "o", str(wrapper))
    assert safepath.check_program(str(outer), runs_as_root=False, known_format=True)


@linux_root
@pytest.mark.parametrize("mode", [0o4755, 0o2755])
def test_setuid_and_setgid_programs_are_refused(trusted_dir: Path, mode: int) -> None:
    prog = script(trusted_dir / "p", "/bin/sh", mode)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(prog), runs_as_root=False)
    assert exc.value.message.id == "safepath.error.setid"


@linux_root
def test_root_programs_must_be_elf_or_start_with_a_shebang(trusted_dir: Path) -> None:
    text = write(trusted_dir / "p", "echo no interpreter line\n", 0o755)
    with pytest.raises(UnsafePath) as exc:
        safepath.check_program(str(text), runs_as_root=True)
    assert exc.value.message.id == "safepath.error.unknown_format"
    assert safepath.check_program(str(text), runs_as_root=False).interpreter is None
    elf = trusted_dir / "elf"
    elf.write_bytes(Path("/bin/sh").resolve().read_bytes())
    os.chmod(elf, 0o755)
    assert safepath.check_program(str(elf), runs_as_root=True).interpreter is None

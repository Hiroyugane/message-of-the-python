import os
import subprocess
import sys
from pathlib import Path

import pytest

from motp import __version__, cli
from motp.cli import build_parser, main
from motp.core import i18n

from .conftest import ROOT, SRC, _can_test_ownership


def test_version_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert capsys.readouterr().out == f"motp {__version__}\n"


def test_no_command_shows_the_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """``motp`` alone is ``motp show`` (4.13)."""
    from motp import show

    calls: list[tuple[bool, bool]] = []

    def fake(login: bool, debug: bool) -> int:
        calls.append((login, debug))
        return 0

    monkeypatch.setattr(show, "main", fake)
    assert main([]) == 0
    assert main(["show", "--login", "--debug"]) == 0
    assert calls == [(False, False), (True, True)]


def test_unknown_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["nonsense"])
    assert stop.value.code == 2
    assert "usage: motp" in capsys.readouterr().err


def test_module_entry_point_runs_in_isolated_mode() -> None:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            f"import sys; sys.path.insert(0, {str(SRC)!r}); "
            "import runpy; sys.argv = ['motp', 'version']; "
            "runpy.run_module('motp', run_name='__main__')",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )
    assert result.stdout == f"motp {__version__}\n", result.stderr


@pytest.mark.needs_linux_owner
def test_ownership_marker_runs_with_real_chown(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Proves the marker's environment works: a file can be handed to another user."""
    assert _can_test_ownership()
    target = tmp_path / "owned"
    target.write_text("x")
    os.chown(target, 65534, 65534)
    st = target.stat()
    assert (st.st_uid, st.st_gid) == (65534, 65534)


def test_help_survives_a_percent_sign_in_a_translation() -> None:
    tr = i18n.Translator("en")
    tr._catalogs = [i18n.Catalog("en", {"cli.version.help": ("100% sure, %(prog)s",)})]
    assert "100% sure, %(prog)s" in build_parser(tr).format_help()


# --- motp config ----------------------------------------------------------------------

STARTER = (SRC / "motp" / "data" / "starter-config.toml").read_bytes()


def test_config_check_names_file_key_and_expected_type(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[limits]\nrender_ms = 'fast'\n[general]\nmode = 'loud'\n")
    assert main(["config", "check", str(bad)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out == [  # with the line of each key (final review, usability item 6)
        f"{bad}, line 2: limits.render_ms must be a whole number from 100 to 10000",
        f"{bad}, line 4: general.mode must be one of: hybrid, static",
    ]


def test_config_init_writes_a_starter_that_check_accepts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "config.toml"
    assert main(["config", "init", "--path", str(target)]) == 0
    assert target.read_bytes() == STARTER
    assert capsys.readouterr().out == f"Wrote {target}. Check it with: motp config check\n"
    assert main(["config", "check", str(target)]) == 0
    assert (
        capsys.readouterr().out.splitlines()[0]
        == f"{target}: valid (checked on its own, on top of the defaults)"
    )


def test_config_init_never_overwrites(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "config.toml"
    target.write_text("# mine\n")
    assert main(["config", "init", "--path", str(target)]) == 1
    assert target.read_text() == "# mine\n"
    assert capsys.readouterr().err == f"{target} already exists and was left unchanged.\n"
    missing = tmp_path / "nodir" / "config.toml"
    assert main(["config", "init", "--path", str(missing)]) == 1
    assert not missing.parent.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs POSIX links")
def test_config_init_does_not_follow_a_link(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep\n")
    (tmp_path / "config.toml").symlink_to(victim)
    assert main(["config", "init", "--path", str(tmp_path / "config.toml")]) == 1
    assert victim.read_text() == "keep\n"
    dangling = tmp_path / "dangling.toml"
    dangling.symlink_to(tmp_path / "created-through-link")
    assert main(["config", "init", "--path", str(dangling)]) == 1
    assert not (tmp_path / "created-through-link").exists()


def test_config_check_refuses_unreadable_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["config", "check", str(tmp_path / "missing.toml")]) == 1
    assert capsys.readouterr().out.endswith(": the file cannot be read\n")
    big = tmp_path / "big.toml"
    big.write_bytes(b"#" * 70_000)
    assert main(["config", "check", str(big)]) == 1
    assert "larger than 65536 bytes" in capsys.readouterr().out
    assert main(["config", "check", str(tmp_path)]) == 1


@pytest.mark.needs_linux_owner
def test_config_check_without_path_loads_the_tree_like_the_collector(
    trusted_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from motp.core import config

    monkeypatch.setattr(config, "DEFAULT_ROOT", str(trusted_dir))
    target = trusted_dir / "config.toml"
    assert main(["config", "init", "--path", str(target)]) == 0
    st = target.stat()
    assert (st.st_uid, oct(st.st_mode & 0o7777)) == (0, "0o644")
    capsys.readouterr()
    assert main(["config", "check"]) == 0
    assert capsys.readouterr().out == (
        f"The configuration under {trusted_dir} is valid (1 file used).\n"
    )
    # A drop-in with a wrong value, and one in a group-writable place.
    (trusted_dir / "conf.d").mkdir(mode=0o755)
    (trusted_dir / "conf.d" / "10-x.toml").write_text("[limits]\ncollect_total_s = 120\n")
    os.chmod(trusted_dir / "conf.d" / "10-x.toml", 0o664)
    assert main(["config", "check"]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out == [
        f"{trusted_dir}/conf.d/10-x.toml: {trusted_dir}/conf.d/10-x.toml is writable by group"
        " or others",
        "Files with problems are ignored; defaults and the other files apply.",
    ]
    os.chmod(trusted_dir / "conf.d" / "10-x.toml", 0o644)
    assert main(["config", "check"]) == 1
    assert capsys.readouterr().out.splitlines()[0] == (
        f"{trusted_dir}/conf.d/10-x.toml, line 2: limits.collect_total_s must be a whole number"
        " from 10 to 80"
    )


@pytest.mark.needs_linux_owner
def test_config_check_of_a_single_file_notes_an_untrusted_place(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    draft = tmp_path / "draft.toml"
    draft.write_bytes(STARTER)
    assert main(["config", "check", str(draft)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == f"{draft}: valid (checked on its own, on top of the defaults)"
    assert out[1].startswith(f"{draft}: note: MOTP would ignore this file where it is now: ")
    assert out[1].endswith("is writable by group or others")


@pytest.mark.needs_linux_owner
def test_config_check_of_a_file_in_the_tree_reports_what_the_collector_sees(
    trusted_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from motp.core import config

    monkeypatch.setattr(config, "DEFAULT_ROOT", str(trusted_dir))
    (trusted_dir / "conf.d").mkdir(mode=0o755)
    main_file = trusted_dir / "config.toml"
    main_file.write_text("[thresholds.disk_used_percent]\ncrit = 85\n")
    dropin = trusted_dir / "conf.d" / "10-x.toml"
    dropin.write_text("[thresholds.disk_used_percent]\nwarn = 88\n")
    for f in (main_file, dropin):
        os.chmod(f, 0o644)
    # On its own the drop-in is fine; on top of config.toml its limits are out of order.
    assert main(["config", "check", str(dropin)]) == 1
    assert capsys.readouterr().out == (
        f"{dropin}: threshold rule disk_used_percent has its limits in the wrong order\n"
    )
    dropin.write_text("[thresholds.disk_used_percent]\nwarn = 70\n")
    assert main(["config", "check", str(dropin)]) == 0
    assert capsys.readouterr().out == f"{dropin}: valid; the collector uses it\n"


@pytest.mark.parametrize("command", ["install", "uninstall"])
def test_install_and_uninstall_refuse_to_run_without_isolation_and_site(
    command: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Security review of phase 14: the root commands need ``python3 -I -S`` (T2)."""
    from motp.install import installer

    ran: list[str] = []

    def fake(name: str) -> object:
        def call(**kw: object) -> int:
            ran.append(name)
            return 0

        return call

    monkeypatch.setattr(installer, "install", fake("install"))
    monkeypatch.setattr(installer, "uninstall", fake("uninstall"))
    monkeypatch.setattr(cli, "isolated_without_site", lambda: False)
    assert cli.main([command]) == 2
    assert ran == [] and "-I -S" in capsys.readouterr().err
    monkeypatch.setattr(cli, "isolated_without_site", lambda: True)
    assert cli.main([command]) == 0 and ran == [command]


# --- help, exit codes and errors (final review, usability items 11, 12 and 15) -----------


def _commands() -> "list[list[str]]":
    return [[key] if " " not in key else key.split() for key in cli.HELP]


@pytest.mark.parametrize("command", _commands(), ids=" ".join)
def test_every_command_has_a_description_and_examples(
    command: "list[str]", capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as done:
        main([*command, "--help"])
    assert done.value.code == 0
    out = capsys.readouterr().out
    help_text = i18n.translator("en").message(cli.HELP[" ".join(command)])
    assert help_text[1:] in out, "the description"
    assert "Examples:" in out or "Example:" in out
    assert out.count("motp") >= 2


def test_the_main_help_lists_the_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "Exit codes:" in out and "  2  wrong usage" in out and "MOTP_DEBUG=1" in out


def test_bare_config_prints_its_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["config"]) == 2
    out = capsys.readouterr().out
    assert "check" in out and "init" in out and "Examples:" in out


def test_an_unexpected_error_is_one_line_with_exit_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(*args: object, **kwargs: object) -> int:
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(cli, "explain", broken)
    monkeypatch.delenv("MOTP_DEBUG", raising=False)
    assert main(["explain"]) == 1
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "RuntimeError: disk on fire" in err
    assert "Traceback" not in err
    monkeypatch.setenv("MOTP_DEBUG", "1")
    with pytest.raises(RuntimeError):
        main(["explain"])


def test_modules_keys_lists_every_item_key(capsys: pytest.CaptureFixture[str]) -> None:
    from motp.modules import registry

    assert main(["modules", "--keys"]) == 0
    out = capsys.readouterr().out
    assert all(key in out for key in registry.all_keys())
    assert "os_host.kernel" in out and "plugin.<plugin name>" in out

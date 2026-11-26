"""The login hooks, the rc snippets and static mode's text (blueprint 4.10, D7, D8, T4,
T5, T20).

The text checks run everywhere. The shell checks run where the shell exists (the
containers of ``tools/container_test.py`` have ``sh`` and ``bash``; the level-3 login
images of ``tools/login_test.py`` add zsh and fish and log in over SSH for real): a
hook or snippet sourced by a non-interactive shell, or by one whose output is not a
terminal, prints nothing; an interactive shell on a terminal runs the program once, even
when the hook is read twice; a missing program, or one that fails, leaves no trace.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from motp import cli
from motp.collect import runner
from motp.core import config
from motp.core.model import ContractError
from motp.install import hooks

POSIX = pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX shell and a pty")
SH_SHELLS = ("sh", "bash", "zsh")
MARK = "MOTP-RAN"


# --- the texts ------------------------------------------------------------------------


@pytest.mark.parametrize("timeout", [None, hooks.TIMEOUT_PROGRAM])
def test_the_login_hook_runs_only_in_interactive_shells_with_a_terminal(timeout: object) -> None:
    text = hooks.profile_hook("/opt/motp/bin/motp", timeout)  # type: ignore[arg-type]
    assert "[ -t 1 ]" in text and "case $- in" in text and "*i*)" in text
    assert '[ -z "${MOTP_LOGIN_SHOWN-}" ]' in text and "MOTP_LOGIN_SHOWN=1" in text
    assert "export" not in text  # child shells and new tabs still show it (D8)
    assert text.count("/opt/motp/bin/motp show --login </dev/null 2>/dev/null || :") == (
        1 if timeout is None else 2
    )
    assert "[ -x /opt/motp/bin/motp ]" in text
    if timeout is None:
        assert "timeout" not in text
    else:
        assert f"[ -x {timeout} ]" in text and "--foreground" in text


def test_the_hook_limit_lies_above_every_render_deadline_the_config_accepts() -> None:
    assert hooks.HOOK_LIMIT_S * 1000 > config.RENDER_MS_MAX


@pytest.mark.parametrize("shell", hooks.SHELLS)
def test_rc_snippets_check_interactive_and_terminal_and_swallow_errors(shell: str) -> None:
    text = hooks.rc_snippet(shell)
    assert "/opt/motp/bin/motp show </dev/null 2>/dev/null" in text
    assert "--login" not in text and "MOTP_LOGIN_SHOWN=1" not in text and "export" not in text
    if shell == "fish":
        assert "status is-interactive" in text and "test -t 1" in text and "or true" in text
        assert "not set -q MOTP_LOGIN_SHOWN" in text
    else:
        assert "[ -t 1 ]" in text and "*i*)" in text and "|| :" in text


def test_an_unknown_shell_has_no_snippet() -> None:
    with pytest.raises(ValueError):
        hooks.rc_snippet("csh")


def test_shell_init_prints_the_snippet(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["shell-init", "zsh"]) == 0
    assert capsys.readouterr().out == hooks.rc_snippet("zsh")
    with pytest.raises(SystemExit) as stop:
        cli.main(["shell-init", "tcsh"])
    assert stop.value.code == 2


# --- static mode's text (4.10, D7) ----------------------------------------------------------


def test_static_text_is_plain() -> None:
    assert runner.check_static("a\nb\n") == b"a\nb\n"
    for bad in ("\x1b[31m", "\r", "\x07", "\x9b", "\x7f", "\t"):
        with pytest.raises(ContractError):
            runner.check_static("ok " + bad + "\n")


def test_static_env_never_has_colour_and_keeps_only_the_locale() -> None:
    env = {"LANG": "C.UTF-8", "TERM": "xterm-256color", "MOTP_COLOR": "always", "HOME": "/x"}
    assert runner.static_env(env) == {"LANG": "C.UTF-8", "MOTP_COLOR": "never"}


def test_static_text_reads_the_public_tier_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from motp.core import cache

    read: list[str] = []
    real = cache.read_tier_file

    def spy(path: str, tier: str, owner: object = None) -> cache.TierCache:
        read.append(tier)
        return real(path, tier, owner)  # type: ignore[arg-type]

    monkeypatch.setattr(cache, "read_tier_file", spy)
    monkeypatch.setattr("motp.show._dir_trusted", lambda path, owner: True)
    env = {"LANG": "C.UTF-8", "MOTP_COLOR": "always", "TERM": "xterm-256color"}
    data = runner.static_text(str(tmp_path), 1_700_000_000, env)
    assert read == [cache.PUBLIC]
    assert b"\x1b" not in data and data.endswith(b"\n")
    assert max(len(line) for line in data.decode().splitlines()) <= runner.STATIC_WIDTH


def _static_with_charset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, charset: str, lang: str
) -> str:
    from motp.core.cache import Layout, RenderSettings

    settings = RenderSettings(1, Layout(charset=charset), "auto", {}, 300, 1000, "")
    monkeypatch.setattr("motp.show._dir_trusted", lambda path, owner: True)
    monkeypatch.setattr("motp.show.Gatherer.render_settings", lambda self: settings)
    env = {"LANG": lang, "MOTP_CHARSET": "unicode"}
    return runner.static_text(str(tmp_path), 1_700_000_000, env).decode("utf-8")


def test_static_text_is_ascii_on_a_utf8_system_unless_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """4.6: the static file is ASCII unless the config says Unicode. The system locale is
    UTF-8 almost everywhere, but pam_motd prints the file to every kind of terminal."""
    auto = _static_with_charset(tmp_path, monkeypatch, "auto", "C.UTF-8")
    assert auto.isascii(), "a UTF-8 locale alone must not make the static file Unicode"
    assert "+" in auto and "|" in auto, "the ASCII frame is drawn"
    forced = _static_with_charset(tmp_path, monkeypatch, "unicode", "C")
    assert not forced.isascii() and "│" in forced
    assert _static_with_charset(tmp_path, monkeypatch, "ascii", "C.UTF-8").isascii()


# --- the shells ---------------------------------------------------------------------------


def _fake_program(tmp_path: Path, body: str) -> Path:
    prog = tmp_path / "motp"
    prog.write_text(f"#!/bin/sh\n{body}\n")
    prog.chmod(0o755)
    return prog


def _run_in_pty(argv: list[str], timeout: float = 20.0) -> str:
    """Run ``argv`` with a pseudo-terminal as stdin, stdout and stderr; return the output."""
    import pty
    import select

    pid, fd = pty.fork()
    if pid == 0:  # the child: exec the shell
        env = {"PATH": "/usr/bin:/bin", "TERM": "dumb", "HOME": "/"}
        os.execvpe(argv[0], argv, env)  # noqa: S606  (a test shell on a pty)
    out = b""
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], timeout)
            if not ready:
                break
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    finally:
        os.waitpid(pid, 0)
        os.close(fd)
    return out.decode("utf-8", "replace")


@POSIX
@pytest.mark.parametrize("shell", SH_SHELLS)
def test_the_hook_is_silent_without_a_terminal_or_interactivity(tmp_path: Path, shell: str) -> None:
    path = shutil.which(shell)
    if path is None:
        pytest.skip(f"no {shell} here")
    prog = _fake_program(tmp_path, f"echo {MARK}")
    hook = tmp_path / "hook.sh"
    hook.write_text(hooks.profile_hook(str(prog), None))
    for argv in ([path, "-c", f". {hook}"], [path, "-i", "-c", f". {hook}"]):
        done = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        assert done.stdout == "" and done.returncode == 0, (argv, done)


@POSIX
@pytest.mark.parametrize("shell", SH_SHELLS)
def test_the_hook_runs_once_in_an_interactive_shell_on_a_terminal(
    tmp_path: Path, shell: str
) -> None:
    path = shutil.which(shell)
    if path is None:
        pytest.skip(f"no {shell} here")
    prog = _fake_program(tmp_path, f"echo {MARK}")
    hook = tmp_path / "hook.sh"
    hook.write_text(hooks.profile_hook(str(prog), shutil.which("timeout")))
    rc = tmp_path / "rc.sh"
    rc.write_text(hooks.rc_snippet("bash", str(prog)))
    # The hook read twice (zsh's zprofile and /etc/profile), then the user's rc snippet.
    out = _run_in_pty([path, "-i", "-c", f". {hook}; . {hook}; . {rc}; echo DONE"])
    assert out.count(MARK) == 1 and "DONE" in out, out


@POSIX
@pytest.mark.parametrize("body", ["exit 3", "echo oops >&2; exit 1", "kill -SEGV $$"])
def test_a_failing_or_missing_program_leaves_no_trace(tmp_path: Path, body: str) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash here")
    prog = _fake_program(tmp_path, body)
    for wrapper in (str(prog), str(tmp_path / "missing")):
        hook = tmp_path / "hook.sh"
        hook.write_text(hooks.profile_hook(wrapper, shutil.which("timeout")))
        out = _run_in_pty([bash, "--norc", "-i", "-c", f". {hook}; echo DONE $?"])
        assert out.strip().splitlines()[-1].strip() == "DONE 0", out
        assert "oops" not in out and "rror" not in out, out


@POSIX
@pytest.mark.parametrize("shell", hooks.SHELLS)
def test_the_rc_snippet_is_silent_in_non_interactive_shells(tmp_path: Path, shell: str) -> None:
    path = shutil.which(shell)
    if path is None:
        pytest.skip(f"no {shell} here")
    prog = _fake_program(tmp_path, f"echo {MARK}")
    rc = tmp_path / "rc"
    rc.write_text(hooks.rc_snippet(shell, str(prog)))
    source = "source" if shell == "fish" else "."
    done = subprocess.run(
        [path, "-c", f"{source} {rc}"], capture_output=True, text=True, timeout=20, check=False
    )
    assert done.stdout == "" and done.stderr == "" and done.returncode == 0, done
    out = _run_in_pty([path, "-i", "-c", f"{source} {rc}; echo DONE"])
    assert out.count(MARK) == 1, out


@POSIX
@pytest.mark.parametrize("shell", hooks.SHELLS)
def test_a_login_shell_skips_the_rc_snippet_while_the_static_file_exists(
    tmp_path: Path, shell: str
) -> None:
    """Static mode: pam_motd printed the file at this login; the snippet must not repeat
    it. A non-login shell (a new terminal tab) still shows the message (D8)."""
    path = shutil.which(shell)
    if path is None:
        pytest.skip(f"no {shell} here")
    prog = _fake_program(tmp_path, f"echo {MARK}")
    static = tmp_path / "10-motp"
    rc = tmp_path / "rc"
    rc.write_text(hooks.rc_snippet(shell, str(prog), str(static)))
    source = "source" if shell == "fish" else "."
    login = [path, "-l", "-i", "-c", f"{source} {rc}; echo DONE"]
    tab = [path, "-i", "-c", f"{source} {rc}; echo DONE"]
    assert _run_in_pty(login).count(MARK) == 1  # no static file: shown
    static.write_text("static text\n")
    assert _run_in_pty(login).count(MARK) == 0
    assert _run_in_pty(tab).count(MARK) == 1

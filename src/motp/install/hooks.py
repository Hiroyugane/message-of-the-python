"""The login hooks and the rc snippets (blueprint 4.10, D7, D8, T4, T5, T20).

Hybrid mode installs ``/etc/profile.d/motp.sh`` for sh-style login shells and a marked
block in the system ``zprofile`` that runs the same file for zsh. ``motp shell-init`` prints
the snippet a user adds to their own rc file (bash, zsh, fish).

Every snippet follows the same rules, so a login can never be delayed, blocked or broken
by MOTP and nothing is printed into a non-interactive session (scp, sftp, rsync, git):

- it runs only in an interactive shell whose standard output is a terminal;
- it calls the installed program by its absolute path and only when that is executable;
- the program's stdin is ``/dev/null`` and its stderr is discarded, and any exit code is
  ignored (``show --login`` exits 0 on every error anyway);
- the login hook sets ``MOTP_LOGIN_SHOWN``, a plain shell variable that is not exported,
  so the same shell does not show the message twice (zsh may read the hook twice, the
  user's rc snippet runs after it), while child shells and new terminal tabs do (D8);
- where GNU ``timeout`` works with a terminal (open item O11), the login hook wraps the
  call in it as a second limit behind the program's own render deadline.

The texts are shell code, not language, so they are constants here and not catalogue
entries (like the unit files in ``units``).
"""

from typing import Optional

from motp.install import units

PROFILE_HOOK = "/etc/profile.d/motp.sh"
# The system zprofile per distribution (open item O10, measured in phase 8): Debian and
# Ubuntu build zsh with /etc/zsh as its directory, the RHEL family and Fedora with /etc.
ZPROFILE_CANDIDATES = ("/etc/zsh/zprofile", "/etc/zprofile")
TIMEOUT_PROGRAM = "/usr/bin/timeout"
# Outer limit of the login hook in seconds: above the largest render deadline the config
# accepts (limits.render_ms up to 10000), so it only ends what the deadline cannot reach
# (a hang before the interpreter armed it).
HOOK_LIMIT_S = 11
HOOK_KILL_AFTER_S = 1
SHOWN_VARIABLE = "MOTP_LOGIN_SHOWN"
SHELLS = ("bash", "zsh", "fish")
STATIC_FILE = "/run/motd.d/10-motp"  # static mode's file (collect/store.py: MOTD_DIR, MOTD_NAME)

BLOCK_BEGIN = "# BEGIN motp: written by motp install, removed by motp uninstall"
BLOCK_END = "# END motp"


def login_command(wrapper: str, timeout: Optional[str]) -> str:
    call = f"{wrapper} show --login </dev/null 2>/dev/null || :"
    if timeout is None:
        return call
    limit = f"--foreground -k {HOOK_KILL_AFTER_S} {HOOK_LIMIT_S}"
    return f"{timeout} {limit} {call}"


def profile_hook(wrapper: str = units.WRAPPER, timeout: Optional[str] = TIMEOUT_PROGRAM) -> str:
    """``/etc/profile.d/motp.sh``: POSIX sh, also run by zsh in sh emulation."""
    if timeout is not None:
        run = (
            f"        if [ -x {timeout} ]; then\n"
            f"            {login_command(wrapper, timeout)}\n"
            "        else\n"
            f"            {login_command(wrapper, None)}\n"
            "        fi\n"
        )
    else:
        run = f"        {login_command(wrapper, None)}\n"
    return (
        "# Message of the Python, written by motp install (blueprint 4.10): shows the MOTD\n"
        "# once per login, in interactive shells with a terminal only; silent otherwise.\n"
        f'if [ -z "${{{SHOWN_VARIABLE}-}}" ] && [ -t 1 ] && [ -x {wrapper} ]; then\n'
        "    case $- in\n"
        "    *i*)\n"
        f"        {SHOWN_VARIABLE}=1\n"
        f"{run}"
        "        ;;\n"
        "    esac\n"
        "fi\n"
    )


def zsh_block(hook: str = PROFILE_HOOK) -> str:
    """The block appended to the system zprofile: runs the sh hook in sh emulation."""
    return f"{BLOCK_BEGIN}\nif [ -r {hook} ]; then emulate sh -c '. {hook}'; fi\n{BLOCK_END}\n"


def rc_snippet(shell: str, wrapper: str = units.WRAPPER, static_file: str = STATIC_FILE) -> str:
    """What ``motp shell-init <shell>`` prints for the user's own rc file (D8).

    A login shell skips it while static mode's file exists, because an SSH or console
    login printed that file through pam_motd already (measured in phase 8: the snippet
    and pam_motd showed it twice). Login shells that do not pass pam_motd (``su -``,
    ``bash -l``, tmux panes, terminals set to start login shells) then show nothing in
    static mode; a known gap, listed in the decision log.
    """
    if shell == "fish":
        return (
            f"# Message of the Python: the MOTD in every new interactive terminal\n"
            f"# (motp shell-init fish, for ~/.config/fish/config.fish).\n"
            f"if status is-interactive; and test -t 1; and not set -q {SHOWN_VARIABLE}"
            f"; and test -x {wrapper}\\\n"
            f"        ; and not begin; status is-login; and test -e {static_file}; end\n"
            f"    {wrapper} show </dev/null 2>/dev/null; or true\n"
            "end\n"
        )
    if shell not in SHELLS:
        raise ValueError(shell)
    rc = "~/.bashrc" if shell == "bash" else "~/.zshrc"
    is_login = "shopt -q login_shell" if shell == "bash" else "[[ -o login ]]"
    return (
        f"# Message of the Python: the MOTD in every new interactive terminal\n"
        f"# (motp shell-init {shell}, for {rc}).\n"
        f'if [ -z "${{{SHOWN_VARIABLE}-}}" ] && [ -t 1 ] && [ -x {wrapper} ] \\\n'
        f"    && ! {{ {is_login} && [ -e {static_file} ]; }}; then\n"
        f"    case $- in *i*) {wrapper} show </dev/null 2>/dev/null || : ;; esac\n"
        "fi\n"
    )

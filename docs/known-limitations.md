# Known limitations of 1.0

What MOTP 1.0 does not do, or does only in part, and why. Each line comes from an open item
the maintainer recorded while building it.

## Showing the message

- **Static mode shows nothing in login shells that skip pam_motd** (`su -`, `bash -l`, tmux panes,
  terminals that start login shells). Only pam_motd prints the static file, and the rc snippet
  stays quiet while that file exists so SSH logins do not show it twice. Hybrid mode, the default,
  has no such gap. `motp doctor` says so in static mode.
- **Static mode is one text for everyone**: public rows only, 80 columns, no colour, the system's
  language unless the config fixes one, ASCII unless the config says `charset = "unicode"`.
- **sshd's own "Last login" line** appears beside MOTP's. Switch it off with `PrintLastLog no` in
  `sshd_config` if you want one only (MOTP does not change system files it does not own).
- **The distribution's own MOTD** (Ubuntu's news, `/etc/motd`) stays; quieting it is a later
  installer option.
- **Terminals that claim UTF-8 but cannot draw box characters**, or that draw them two cells wide
  (East Asian legacy widths): set `charset = "ascii"` or `MOTP_CHARSET=ascii`.
- **Right-to-left text** in names collected from the system (a host, user or container name) is
  shown as replacement characters, so it cannot reorder a row in a terminal with bidi support.
  Plugin output and config labels keep it; a terminal with bidi support may reorder the neutral
  characters of such a row.
- **argparse's own usage and error lines** stay English in a German session.

## Data sources

- **Debian 13 keeps no `btmp` and no `/run/utmp`.** Its systemd is built without utmp and its sshd
  writes no failed-login record, so "Failed logins" and "Sessions" say "not recorded on this
  system" there. The journal (`journalctl -u ssh`) and `loginctl` still have them; readers for
  those are planned after 1.0. `lastlog` and `wtmp` are still written, so the previous login works.
- **Failed logins** count only the current `btmp`: for a day after its monthly rotation the count is
  too low.
- **A reused user id** (an account removed and a new one created with its id) can show the old
  account's previous login to the new account until it logs in once, where `useradd` does not
  reset `lastlog` (Fedora). sshd's own "Last login" line shows the same record, so MOTP discloses
  nothing new; telling the two accounts apart needs history MOTP does not keep.
- **Rootless Podman** and Podman without its API socket are not seen; Podman's health states are not
  reported.
- **The firewall row** reads the firewall's unit state and config files, not the live ruleset, so
  rules loaded by other means are not seen.
- **Package managers**: apt, dnf 4 and dnf 5 only. pacman, zypper, apk, snap and flatpak follow
  after 1.0. MOTP never refreshes package lists; it says when they are older than seven days.
- **End-of-support dates** come from a table in the program with its check date; a release the
  table does not know gets no row. Fedora's and Red Hat's dates were not checked against their own
  pages for 1.0 (those pages refused automated clients).
- **Not yet built**: certificate expiry, disk health (SMART, RAID, ZFS, btrfs), temperature and
  Raspberry Pi power state, backup presets, the public address, `--json` output.

## Installation and platforms

- **No native packages** (`.deb`, `.rpm`) yet; install from the release archive.
- **Without systemd** (Alpine and other tier-2 systems) the collector runs from cron with no
  sandbox, and root plugins run unconfined there; `motp doctor` says so.
- **The zsh block and dpkg**: on Debian and Ubuntu the block lives in `/etc/zsh/zprofile`, a
  conffile, so a zsh update that ships a new file asks about the local change. Keep your version
  or take the new one and run `motp install` again; `motp doctor` reports a missing block.
- **A file system that reports owners it does not enforce** (FUSE with `user_allow_other`, NFS,
  CIFS) defeats the ownership check for paths on it; `motp doctor` warns when MOTP's own places
  sit on one.
- **The classic theme at 16 colours** draws warnings and critical values in two close shades of
  red; `[theme.colors] warn` changes it.
- **No per-user config file**: users choose with `NO_COLOR`, `MOTP_COLOR`, `MOTP_CHARSET`,
  `MOTP_PLAIN` and their locale.

## The collector's sandbox

- **Root probes run inside the collector unit, not in units of their own.** `os_login`,
  `sec_logins`, `sec_fail2ban` and `app_containers` must read root-only files or sockets. They run
  as root inside `motp-collect.service`, whose sandbox (no network, read-only system and `/run`,
  four capabilities) keeps them from writing anything, but which they share with the collector:
  they can reach the service manager's socket and the container runtimes' sockets, as the
  collector itself needs to. They are reviewed parsers, not foreign code; giving each its own
  transient unit, as plugins have, is a design change after 1.0 (security review, phase 14).

- **The import-path check sees only what lies on disk.** Before root starts a Python script
  (fail2ban's client, a root plugin), every directory its interpreter imports from must be root's
  alone. An `import` line in a root-owned `.pth` file, or an editable install's path finder, can
  add more at start-up; that code is root's own, and MOTP cannot see where it looks. A Python
  program started through a shell wrapper (`#!/bin/sh` running `exec python3 ...`, a pyenv shim)
  is not recognised as Python and gets no such check. A system with more than 200000 files below
  its Python site directories has fail2ban "not checked" and root Python plugins refused.

## Plugins

- **A root plugin is root.** Its own sandbox keeps it from writing anywhere and hides the service
  manager and the container runtimes, but it can signal other root processes and reach root
  daemons whose sockets lie elsewhere. Without systemd, or with `motp collect --no-sandbox`, it
  runs unconfined.
- **JIT runtimes** (Node, Java) cannot run as plugins: the sandbox forbids writable and executable
  memory.

## Not verified for 1.0

No Raspberry Pi, no physical server, no SELinux in enforcing mode, no AppArmor, no real Docker
daemon and no fail2ban with a real ban action were available; the containers stand in for them.
Still to be checked by a person or on real hardware: a Raspberry Pi (64-bit and 32-bit), a real
server of each family run for weeks, a real Debian 13 install, real terminals (PuTTY, tmux, the
Linux console and others), and a native speaker's reading of the German text.

# Changelog

All notable changes are listed here. Versions follow [PEP 440](https://peps.python.org/pep-0440/):
`1.0.0rc1` is the first release candidate of `1.0.0`.

## 1.0.0 (release candidate 1, not yet published)

The first release of the rewrite. Everything below is new compared with the 2019 script.

### What you see at login

- A framed message of the day at SSH login and, if you want, in every new local terminal:
  host name, operating system, kernel, uptime, load, memory, local addresses, DNS servers and
  one bar per disk that shows the used and the free part.
- An **Attention** block on top with one line per problem and the command that fixes it.
- Package health: pending updates and security updates (apt, dnf 4, dnf 5), a needed reboot,
  whether automatic security updates are on, and a warning before the operating system release
  reaches its end of support.
- Services and logins: failed systemd units, services you name in the config, the number of
  sessions, your own previous login, and failed logins of the last 24 hours.
- Security: fail2ban bans, the firewall state (ufw, firewalld, nftables) and Docker or Podman
  containers by state.
- Values turn yellow or red at configurable limits, and `[!]` and `[!!]` mark them with or
  without colour (`[theme] markers = "no-color"` shows the marks without colour only).
- The layout adapts to the terminal: a header, frames and bars from 80 columns, a compact frame
  from 60, plain `label: value` lines from 40, and only the warnings below that. The label column
  grows for long labels as far as the values still fit; hints wrap; a command is shown whole or
  not at all. A plugin row that does not fit wraps too, each further line marked `(plugin)`.
- Unicode frames where the terminal's locale is UTF-8, ASCII otherwise; `charset` and
  `MOTP_CHARSET` force one.
- English and German, following each reader's locale. `MOTP_PLAIN=1` gives a reader the
  message without header, frame and dotted leaders.

### Who sees what

- Everyone sees counts and states. Names and addresses (who is logged in and from where, banned
  addresses, container names, sources of failed logins, failing unit names, package names) are
  shown only to root and to one admin group, chosen at install time (`sudo` or `wheel`, never
  `adm`).
- Your previous login is shown to you alone.

### Configuring and extending

- One TOML file, `/etc/motp/config.toml`, plus drop-ins in `/etc/motp/conf.d/`. `motp config
  check` names the file, the line, the key and what was expected, and warns about module,
  threshold and row names that do not exist, with the closest one. Admins see "Config: N files
  ignored" in the attention block when a file was ignored.
- Themes: the `default` look and the `classic` look of the 2019 picture, every colour, character
  and section configurable, header fonts bundled or your own FIGlet font.
- Rows without code: `[[rows.unit]]` for a systemd unit's state, `[[rows.file_age]]` for the age
  of a file (a backup stamp, for example).
- Exec plugins: a small program in any language in `/etc/motp/plugins.d/` that prints one line or
  one JSON document. Plugins run as their own unprivileged user in a sandbox of their own; their
  rows are for admins unless you make them public. Label, text and hint take translations.

### Commands

- `motp show`, `motp preview`, `motp modules` (`--keys` lists every row key), `motp doctor`,
  `motp explain <topic or row label>`. Every command has `--help` with examples; the exit codes
  are 0, 1 and 2 as `motp --help` lists them.
- `motp install` and `motp uninstall` (from the downloaded `motp.pyz`), `motp collect`,
  `motp config check`, `motp config init`, `motp shell-init bash|zsh|fish`.
- Hybrid mode (default): a timer collects every five minutes, the login shell shows the result.
  Static mode: the timer writes a plain file that the system's own MOTD prints.

### Safety

- No network access: the collector's sandbox allows only local sockets, and nothing asks a
  server anything.
- A login never waits for MOTP: the login path starts no process and reads only memory-backed
  files, with a time limit of one second (configurable) and an outer limit in the hook.
- Text from the system (host names, login sources, container names, plugin output) is cleaned of
  control and escape sequences before it reaches a terminal, and names collected from the system
  lose right-to-left letters, so a terminal with bidi support cannot reorder a row.
- Root reads config and plugins only from files and directories that root alone can write, and
  starts a Python script (fail2ban's client, a root plugin) only if every directory its
  interpreter imports from is root's alone. `motp install` keeps stricter modes an admin set on
  `/etc/motp`, and `motp uninstall` removes no account but MOTP's own two.
- Releases are built reproducibly, with a checksum file and a GitHub build attestation.

### Supported systems

Tier 1: Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, Raspberry Pi OS, AlmaLinux and Rocky
Linux 9 and 10, Fedora 44 and 45 (Python 3.9 or newer, systemd). The README says which of them
were tested how for this release.

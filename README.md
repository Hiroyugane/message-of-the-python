# Message of the Python (MOTP)

A customisable message of the day for Linux, written in Python. At SSH login (and, if you want,
in every new local terminal) it shows what a server's admin should know at a glance: host and
system, updates and reboots, failed services, logins, fail2ban, containers and disk space, with a
line for each problem and the command that fixes it.

![MOTP at 80 columns with demo data: header, attention block, host, system, security, login,
disks, services, containers and plugins sections](docs/images/demo-unicode.svg)

*Demo data; addresses are documentation addresses. ASCII and narrow versions:
[`docs/images/`](docs/images/).*

- **Fast and safe at login.** The login only reads a cache in memory; a slow or broken part can
  never delay or block a login, and nothing prints in `scp`, `sftp`, `rsync` or `ssh host cmd`.
- **No network.** MOTP asks no server anything.
- **Two audiences.** Everyone sees counts and states; names and addresses are for admins only.
- **English and German**, following each reader's locale. `motp explain <topic>` says what a row
  means and what to do.
- **Python 3.9 or newer, standard library only.** One file to download, verified before install.

Status: **release candidate 1.0.0rc1.** See [`CHANGELOG.md`](CHANGELOG.md).

## Supported systems

| Tier | Releases | Tested for this release |
|---|---|---|
| 1 | Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, Raspberry Pi OS (Debian 12 and 13 based), AlmaLinux 9 and 10, Rocky Linux 9 and 10, Fedora 44 and 45 | Debian 12 and 13, Ubuntu 22.04, AlmaLinux 9 and 10, Fedora 45: unit tests, the sandboxed collector under systemd and real SSH logins in containers; on Debian 13 and AlmaLinux 10 also the install below, pasted as written, in fresh containers. Rocky Linux 10: the archive runs (`motp version`, demo, `show`, `doctor`). Ubuntu 24.04 and 26.04, Rocky Linux 9, Fedora 44: not yet, the nightly workflow covers them. No real hardware yet: no Raspberry Pi, no physical server. |
| 2 | Arch Linux, openSUSE Leap 16.0 and Tumbleweed, Alpine 3.22 to 3.24 | best effort: the archive runs on Arch, Tumbleweed and Alpine 3.22; no updates, sandbox or login hook support yet |

Not supported: RHEL 8 and its rebuilds (Python 3.6), Ubuntu 20.04 (Python 3.8). MOTP needs
systemd for its sandbox; without systemd it falls back to cron without a sandbox.

## Install

You need `python3` (3.9 or newer), `curl` and `sudo`. On Debian, Ubuntu and Raspberry Pi OS:

<!-- release-check:prereq-apt -->
```sh
sudo apt-get update && sudo apt-get install -y python3 curl
```

On AlmaLinux, Rocky Linux and Fedora:

<!-- release-check:prereq-dnf -->
```sh
sudo dnf install -y python3 curl
```

Then download, verify and install. Paste the whole block: it runs in a new private directory and
stops at the first step that fails, so nothing is installed unless the checks pass.

<!-- release-check:install -->
```sh
(
  set -eu
  umask 022
  cd "$(mktemp -d)"
  VERSION=1.0.0rc1
  BASE="https://github.com/Hiroyugane/message-of-the-python/releases/download/v$VERSION"
  curl -fL --proto-redir '=https' -O "$BASE/motp.pyz"
  curl -fL --proto-redir '=https' -O "$BASE/SHA256SUMS"
  sha256sum --check SHA256SUMS
  if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
    gh attestation verify motp.pyz --repo Hiroyugane/message-of-the-python \
      --signer-workflow Hiroyugane/message-of-the-python/.github/workflows/release.yml \
      --source-ref "refs/tags/v$VERSION"
  else
    echo "Attestation not checked (no GitHub CLI, or not logged in); the checksum was."
  fi
  sudo /usr/bin/python3 -I -S ./motp.pyz install
)
```

**1. Download.** The two `curl` lines fetch the archive and its checksum file of this release into
a directory only you can write (`mktemp -d`), with files readable by everyone but writable by you
alone (`umask 022`; the installer refuses an archive others can change).

**2. Verify** before anything runs as root. `sha256sum --check` must print `motp.pyz: OK`;
anything else stops the block. What else is checked depends on the [GitHub
CLI](https://cli.github.com/):

| `gh` | Checked |
|---|---|
| installed and logged in (`gh auth status` succeeds) | the checksum and the build attestation; a failed attestation stops the block |
| installed but not logged in, or not installed | the checksum only; the block says "Attestation not checked" and goes on |

The attestation means GitHub signed that this file was built by this repository's release
workflow from the tag `v1.0.0rc1`. That shows where the file came from, not
that the code was reviewed (see [`SECURITY.md`](SECURITY.md)). The build is reproducible as well:
`python3 tools/build_pyz.py` on a checkout of the tag gives the same SHA-256.

**3. Install.** `/usr/bin/python3 -I -S` runs the archive with no environment and no site
directories (the installer refuses to run otherwise). `install` unpacks the program to `/opt/motp`, creates two locked system accounts
(`motp` and `motp-plugin`) that run the collectors, writes `/etc/motp/config.toml` if there is
none, starts a systemd timer that collects every five minutes, adds the login hook
`/etc/profile.d/motp.sh` (and a marked block in zsh's system `zprofile` where needed), runs the
collector once and prints `motp doctor`. `--dry-run` shows what it would do; `--mode static`
writes a plain file for the system's own MOTD instead of a login hook (see below).

Log in again over SSH to see it. To upgrade, run `install` from the newer archive; your config
stays.

What `install` creates or changes, and what `uninstall` removes again:

| Path or name | What it is | Removed by `uninstall` |
|---|---|---|
| `/opt/motp/` | the program (`lib/`) and the command `/opt/motp/bin/motp` | yes |
| accounts `motp` and `motp-plugin` | locked system accounts without a home or shell, for the collectors and plugins | yes |
| `/etc/motp/` | `config.toml` (written only if missing), `conf.d/`, `plugins.d/` | only with `--purge`, and only files the installer wrote and you did not change |
| `/etc/systemd/system/motp-collect.service` and `.timer` | the collector unit and its five-minute timer, enabled and started | yes |
| `/etc/cron.d/motp` | instead of the units, on a system without systemd | yes |
| `/etc/profile.d/motp.sh` | the login hook (hybrid mode) | yes |
| a marked block in `/etc/zsh/zprofile` or `/etc/zprofile` | runs the hook for zsh, where zsh does not read `/etc/profile` | yes, if unchanged |
| `/usr/local/bin/motp` | a link to `/opt/motp/bin/motp`, only when root alone can write `/usr/local/bin` | yes |
| `/var/lib/motp/` | the collector's state and the install manifest | yes |
| `/run/motp/` | the cache the login reads (in memory, written by the collector) | yes |
| `/run/motd.d/10-motp` | the static file, in static mode only | yes |

`motp` is on your `PATH` when the installer could add the `/usr/local/bin/motp` link (it says so
in its output; `motp doctor` works either way); otherwise call `/opt/motp/bin/motp`.

The admin group (the one that sees names and addresses) is `sudo` or `wheel`, whichever your
sudoers configuration grants; the installer prints which one it chose.

## Check it

<!-- release-check:doctor -->
```sh
sudo /opt/motp/bin/motp doctor
```

`motp doctor` checks the program, the config, the accounts, the timer and its sandbox, the cache,
plugins and the login hook, and says what to do about each problem. Run without `sudo` it checks
what your account can see.

Other commands, for everyone:

```sh
/opt/motp/bin/motp                    # show the message now
/opt/motp/bin/motp modules            # every module: active, not detected or failed, and why
/opt/motp/bin/motp modules --keys     # the key of every row, for hide_rows and row_order
/opt/motp/bin/motp explain load       # what a row means; "motp explain" lists the topics
/opt/motp/bin/motp preview            # the demo data, at any --width
```

Every command has `--help` with examples. Exit codes: `0` success, `1` a check failed, a problem
was found or the command failed, `2` wrong usage (an unknown command, option or topic);
`motp show --login`, which the login hook runs, always exits 0. An unexpected error is one line;
`MOTP_DEBUG=1` shows the traceback.

Each reader can choose for their own terminal: `NO_COLOR=1` or `MOTP_COLOR=never|always`,
`MOTP_CHARSET=ascii|unicode`, and `MOTP_PLAIN=1` for no header, frame or dotted leaders.

To see it in every new local terminal too (off by default), add the snippet to your own shell
setup: `/opt/motp/bin/motp shell-init bash >> ~/.bashrc` (also `zsh` and `fish`).

## Configure

The config is `/etc/motp/config.toml` (and drop-ins in `/etc/motp/conf.d/*.toml`). Every key is
listed, commented out, in the starter file the installer wrote
([`src/motp/data/starter-config.toml`](src/motp/data/starter-config.toml); `motp config init
--path FILE` writes a fresh copy). After a change:

```sh
sudo /opt/motp/bin/motp config check
```

The next timer run (within five minutes) applies it; `sudo /opt/motp/bin/motp collect` applies it
now. The config is readable by everyone: put no secret in it. Examples:

```toml
[layout]
tips = true                  # one tip per day under the message
# sections in this order; leave one out to hide it
sections = ["attention", "system", "disks", "host", "security", "login", "services", "containers", "plugins"]
hide_rows = ["os_host.kernel"]   # single rows, by key: motp modules --keys

[theme]
preset = "classic"           # the 2019 look; every colour and character can be set

[thresholds.disk_used_percent]
warn = 85
crit = 95

[[rows.unit]]                # a service's state, no code needed
name = "nginx.service"
label = "Web server"

[[rows.file_age]]            # warn when a file gets old, e.g. a backup stamp
path = "/var/backups/last-success"
label = "Backup"
warn_after = "26h"
crit_after = "3d"

[modules.app_containers]     # switch a module off, by its id (the table below)
enabled = false
```

`motp config check` warns about a module, threshold or row key that does not exist and suggests
the closest one; a file with an error is ignored as a whole, and admins then see "Config: 1 file
ignored" in the attention block.

## Modules and who sees what

Optional modules switch on by themselves when their program is installed (`enabled = "auto"`);
`motp modules` says why one is missing.

| Module | Id (`[modules.<id>]`) | Everyone sees | Only root and the admin group see |
|---|---|---|---|
| Host, OS, kernel, uptime, load, memory, addresses, DNS servers | `os_host`, `os_uptime`, `hw_load`, `hw_memory`, `net_addresses` | all | |
| Disks | `hw_disks` | system file systems with use and free space | removable and per-user mounts |
| Updates (apt, dnf) | `os_updates` | counts, security updates apart | package names |
| Reboot required | `os_reboot` | yes or no | |
| Automatic updates, firewall | `os_autoupdates`, `sec_firewall` | nothing | the state and the fix |
| End of support of the OS release | `os_eol` | the date | |
| Failed systemd units | `os_units` | the count | the unit names |
| Your services (`[[rows.unit]]`), file ages (`[[rows.file_age]]`) | `rows_unit`, `rows_file_age` | label and state | |
| Sessions | `os_sessions` | the count | who and from where |
| Previous login | `os_login` | your own only | |
| Failed logins (24 hours) | `sec_logins` | the count | the top five sources; attempted user names are never read |
| fail2ban | `sec_fail2ban` | the number of bans | jails and banned addresses |
| Docker, Podman containers | `app_containers` | counts by state | names and images |
| Plugins | the file name (`[plugins.<name>]`) | nothing, unless you set `visibility = "public"` | everything |

## Plugins

Your own rows come from a small program in any language in `/etc/motp/plugins.d/`, owned by root,
named like `50-backup`. It prints one line (with exit code 0 to 3 for ok, warning, critical,
unknown) or one JSON document. Plugins run as the user `motp-plugin` in a sandbox of their own,
with no network and a time limit; `run_as = "root"` in the config is the one way to give one
more. [`docs/plugins.md`](docs/plugins.md) is the contract;
[`examples/plugins/`](examples/plugins/) has a three-line shell plugin and a Python one.

## Languages

English and German, chosen by each reader's locale (`LANG`, `LC_MESSAGES`, `LC_ALL`), or fixed with
`[general] language = "de"`. [`docs/languages.md`](docs/languages.md) says what a server needs for
a German SSH login and how to add a language.

## Uninstall

<!-- release-check:uninstall -->
```sh
sudo /opt/motp/bin/motp uninstall
```

This removes everything the installer wrote, if unchanged, plus the accounts and the cache, and
keeps `/etc/motp`. `uninstall --purge` also removes the config files the installer wrote, if you
did not change them; files you added stay.

## Security model in short

- Collecting runs from a systemd timer in a sandboxed unit: no network (only local sockets), a
  read-only system, four capabilities, memory and task limits. Each check runs in its own process
  as the unprivileged user `motp`; only the few that must read root-only files (login records,
  fail2ban, the container sockets) run as root, inside that same unit. For those root checks the
  unit limits mistakes more than it confines: they can still reach root's local sockets.
- The login hook runs as the user who logs in. It starts no process, opens no socket and reads
  only `/opt/motp`, `/proc`, `/sys` and `/run/motp`, with a time limit.
- Text that comes from outside (host names, login sources, container names, plugin output) is
  stripped of control and escape sequences before it reaches any terminal.
- Root reads the config and runs plugins only from files that root alone can write.

[`SECURITY.md`](SECURITY.md) has the full trust model and how to report a vulnerability.

## Known limitations of 1.0

- **Static mode** only shows the message where pam_motd runs (SSH, the console); `su -`,
  `bash -l` and tmux panes show nothing. Hybrid mode, the default, has no such gap.
- **Debian 13** keeps no `btmp` and no `/run/utmp`: failed logins and sessions say "not recorded
  on this system" there.
- The few root checks run inside the collector's unit, not in units of their own as plugins do.
- No tier-2 package managers (pacman, zypper, apk), no certificates, SMART or temperature rows yet.

The full list, with the reason for each, is [`docs/known-limitations.md`](docs/known-limitations.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The architecture is described in
[`docs/adr/`](docs/adr/), the threat model in [`docs/threats.md`](docs/threats.md).

## Origin

This project is a from-scratch rewrite. It started as a fork of
[fedya/fastmotd](https://github.com/fedya/fastmotd), whose idea and look it carries on; no code from
the earlier versions is reused.

## Licence

GPL-3.0-or-later, see [`LICENSE`](LICENSE). The bundled TOML parser (MIT) and FIGlet fonts
(BSD-3-Clause) keep their own notices.

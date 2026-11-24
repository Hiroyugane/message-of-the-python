# MOTP blueprint: reviving "Message of the Python"

Status: reviewed, and the phase list in section 11 was confirmed by the maintainer on 2026-11-24. Phases run one per session, starting with phase 0. Every step that changes something on GitHub still waits for a separate go-ahead.

MOTP is a message of the day for Linux, written in Python. It is shown at SSH login and, on request, in local terminals. Anyone can install it from GitHub and add their own sections. This document is the construction plan: what was researched, what was decided and why, the architecture, the threat model, the distro matrix, the feature cut and the phases.

Conventions in this document: example addresses come from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), example names from `example.com`. Facts marked *(unverified)* were not checked against a primary source during planning and are re-checked in the phase that depends on them.

Contents: 1 starting point, 2 research, 3 decisions, 4 architecture, 5 threat model, 6 open items, 7 distribution matrix, 8 detected software, 9 features, 10 rules for every phase, 11 phases, 12 review record.

---

## 1. Starting point

The 2021 repository holds about 950 lines of Python 3 without tests, packaging, installer or CI.

| Part | State | Verdict |
|---|---|---|
| `motp/baselib/base.py` | colour table read from INI, byte formatting, `run_cmd` with `shell=True`, a stack inspection on every call for logging | not reusable |
| `motp/scraper/hw_cpu.py`, `hw_ram.py` | work, by shelling out to `cat /proc/loadavg` and `free -bt` | logic is a few lines once `/proc` is read directly |
| 11 `.py.d` stubs | disabled copies of the upstream script (fail2ban, docker, certificates, temperature, storage, hotplug, IP, services, sysinfo, users) | upstream code without a licence |
| `motp/baselib/motd.py` | imports every `.py` file found in `scraper/`, prints two raw dicts | conflicts with safe plugin loading |
| Config | INI with raw escape bytes for colours | replaced |
| `docs/help/scheme.md`, `Todo.md` | naming scheme, data scheme (value plus rule set), roadmap | ideas carried over |
| `docs/images/roadmap-preview.png` | target look | carried over as a specification, not as a file |

Ideas that carry over:

- A module returns raw values plus the name of a threshold rule; the core decides colour and layout.
- Module groups by prefix (`hw_`, `os_`, `net_`, and third-party software).
- Fallback values when a source fails, and one line that says "errors occurred, see the log" instead of a traceback.
- The target look: figlet header, framed sections, dotted key labels, threshold-coloured values, disk usage bars.

Repository hygiene findings (all in the pushed history of the old fork):

- Three source files carry a personal e-mail address in a `__email__` field.
- `docs/images/original.png` shows upstream's real hostname and public address.
- `docs/help/documentation.md` holds addresses from a private network and account names.
- The roadmap picture contains one address that is routable on the internet.

None of these files move to the new repository.

---

## 2. Research

Read on 2026-11-24. Stars and dates come from the GitHub API on that day.

### 2.1 Comparison table

| Project | Language, licence | Adoption | Shows | Config | Extension model | Login hook | Caching |
|---|---|---|---|---|---|---|---|
| [fedya/fastmotd](https://github.com/fedya/fastmotd) (upstream of the old fork) | Go since 2026-03 (bash 2016, Python 2018); no licence file | 8 stars, one author | OS, load, memory, disks, temperatures, docker, fail2ban, certificates, traffic, users | TOML `/etc/fastmotd.toml`, section on/off | edit the source | `/etc/profile.d` script (Go); systemd timer writing `/etc/motd` (Python era) | Go: none. Python: timer every 5 min |
| [bcyran/fancy-motd](https://github.com/bcyran/fancy-motd) | Bash, MIT | 182 stars, archived 2025 | banner, OS, addresses, public address, load, temperatures, memory, disks, services, docker, RAID, SMART, updates | shell variables in a sourced `config.sh` | drop-in `modules/NN-name` scripts | line in `~/.profile` | none |
| [yboetz/motd](https://github.com/yboetz/motd) | Bash, no licence file | 974 stars, last code change 2020 | banner, system info, zpool, disks, SMART, services, fail2ban, docker, lxd | variables inside each script | copy a script | `/etc/update-motd.d` (root, pam_motd) | none; one probe uses `timeout` |
| [rust-motd](https://github.com/rust-motd/rust-motd) | Rust, MIT | 272 stars, active | uptime, load, memory, filesystems, services, user services, docker, compose, certificates, fail2ban, last login, weather, cgroup stats | KDL (TOML still read) | a `command` component run through `sh -c`; no plugin API | root cron writes `/etc/motd`; alternatives documented | whole output cached by cron |
| [Armbian motd scripts](https://github.com/armbian/build/tree/main/packages/bsp/common/etc/update-motd.d) | Bash, GPL-2.0 | ships with Armbian | header, addresses, containers, load, memory, temperatures, storage, tips, update hint | `/etc/default/armbian-motd` (`MOTD_DISABLE="..."`) | add an `update-motd.d` script | `/etc/update-motd.d` | update count cached daily by cron; login only reads it |
| [Ubuntu update-motd](https://manpages.ubuntu.com/manpages/noble/man5/update-motd.5.html) with landscape-sysinfo | shell and Python, GPL | default on Ubuntu Server | header, help links, system info, news, updates, release upgrade, reboot required | `/etc/default/*`, script permissions | add an `NN-name` script | pam_motd runs the scripts as root at each login | stamp files for updates; sysinfo cached 1 min; news cached |
| [fastfetch](https://github.com/fastfetch-cli/fastfetch) | C, MIT | 25k stars, active | hardware and OS summary, many modules | JSONC with a schema, `--gen-config` | `Command` module runs a shell command | none official; users call it from `profile.d` | not documented |
| [ar51an/raspberrypi-motd](https://github.com/ar51an/raspberrypi-motd) | Bash, MIT | 89 stars | welcome, system, update count | edit scripts | `update-motd.d` scripts | `/etc/update-motd.d` | update count written daily by a timer |
| [desbma/motd](https://github.com/desbma/motd) | Rust, GPL-3.0 | 15 stars, active | load, memory, filesystems, temperatures, bandwidth, failed units | optional TOML | none | not documented | not documented |
| [taylorthurlow/panda-motd](https://github.com/taylorthurlow/panda-motd) | Ruby, MIT | 135 stars, archived | art, fail2ban, filesystems, last login, services, certificates, uptime | YAML in a user's home | Ruby classes | `update-motd.d` wrapper | none |
| [dsnet/motd-generator](https://github.com/dsnet/motd-generator) | Python 2, no licence file | 43 stars, dead since 2018 | warnings, CPU, load, memory, disks, network | flags and constants in the source | edit the source | line in `/etc/profile` | daemon on a local port |

The other forks of fedya/fastmotd (`optionalg/omv_motd`, `djdagovs/omv_motd`, `Inf3rnus187/omv_motd`) are mirrors or carry 2017 edits to the bash script only. The one idea in them is counting failed SSH logins.

### 2.2 What to copy

- **Cache slow data, read it at login** (Armbian, rust-motd, raspberrypi-motd, Ubuntu's update-notifier). Login then costs a file read.
- **`NN-name` drop-ins** (fancy-motd, update-motd): order by number, remove a file to disable it.
- **Warn and critical thresholds per value** with sensible defaults (rust-motd: load warns at the CPU count).
- **Show only what is abnormal** (desbma/motd, dsnet).
- **One line for collected errors** (panda-motd logs stderr and prints a single notice).
- **Most modules optional, with a way to list everything** (fastfetch).
- **Strip control characters and cap the length of external text** (Ubuntu's `50-motd-news`).
- **Check the locale before drawing non-ASCII characters** (dsnet).

### 2.3 What to avoid

- **Config that is code.** fancy-motd sources `config.sh`; fastfetch and rust-motd run configured strings through a shell.
- **Root reading a file in a user's home.** panda-motd runs as root and loads a YAML file from a home directory.
- **Network calls in the login path.** fancy-motd calls `curl ifconfig.me` by default, without a time limit.
- **Slow probes at login without a time limit** (`docker ps`, `fail2ban-client` in several projects). Ubuntu measured about 0.45 s extra per login from its own scripts ([Launchpad bug 1893716](https://bugs.launchpad.net/ubuntu/+bug/1893716)).
- **No licence.** fastmotd, yboetz/motd and dsnet cannot be reused legally.
- **Settings inside the scripts** (yboetz): every update overwrites them.
- **Ignoring the terminal.** No project in the table honours `NO_COLOR`; all use a fixed width.

### 2.4 How distributions show a MOTD

| Mechanism | Runs as | Blocks login when slow | Works for | Available on |
|---|---|---|---|---|
| pam_motd running `/etc/update-motd.d/*` | root | yes, also for scp and sftp sessions | every PAM login | Debian and Ubuntu only (a downstream patch) |
| pam_motd reading `/etc/motd`, `/etc/motd.d/`, `/run/motd.d/` | inside the PAM session *(whether with the user's rights: unverified)* | no | every PAM login | Debian, Ubuntu, RHEL family, Arch, openSUSE |
| sshd `PrintMotd` reading `/etc/motd` | sshd | no | interactive SSH logins | Alpine (default sshd is built without PAM) *(unverified for the shipped config)* |
| `/etc/profile.d/*.sh` | the user | yes | login shells of sh-style shells | all; zsh and fish need their own snippet |
| shell rc files | the user | yes | every interactive shell, including new terminal tabs | per user |
| timer or cron writing a file that pam_motd reads | root | never | as the reading mechanism | all with systemd or cron |

Details that shape the design:

- On Debian and Ubuntu the first pam_motd line passes `motd=/run/motd.dynamic`, which switches off the directory defaults for that line. The second line (`noupdate`) reads `/run/motd.d/`.
- Any byte printed in a non-interactive session breaks scp, sftp, rsync and git over SSH. A shell hook must check for an interactive shell and a terminal.
- zsh does not read `/etc/profile`; fish has its own `conf.d`.
- Two historical privilege escalations sit exactly here: [CVE-2010-0832](https://ubuntu.com/security/CVE-2010-0832) (pam_motd followed a symlink in a user's home as root) and [CVE-2011-3628](https://ubuntu.com/security/CVE-2011-3628) (update-motd inherited the user's `PATH`). Both come from root code touching user-controlled state at login.

Primary sources: [update-motd(5)](https://manpages.ubuntu.com/manpages/noble/man5/update-motd.5.html), [pam_motd(8)](https://manpages.debian.org/trixie/libpam-runtime/pam_motd.8.en.html), the [Debian pam_motd source](https://sources.debian.org/data/main/p/pam/1.7.0-5/modules/pam_motd/pam_motd.c), the [Fedora sshd PAM file](https://src.fedoraproject.org/rpms/openssh/raw/rawhide/f/sshd.pam), the [Arch pambase file](https://gitlab.archlinux.org/archlinux/packaging/packages/pambase/-/raw/main/system-login).

---

## 3. Decisions

Each decision lists what was chosen, what was rejected and why. D1 to D20 come from the interview on 2026-11-24. D21 to D34 are design decisions that follow from them, from the constraints and from the two reviews in section 12.

### D1 Rewrite, keep the ideas

**Chosen:** a new package from an empty tree. The old state stays reachable in the old repository.

- *Rejected: evolve step by step.* Nearly every line would be replaced anyway, and the upstream licence question would stay attached to the code.
- *Rejected: rewrite but port the two scrapers line by line.* Both shrink to a few lines once `/proc` is read directly.

### D2 Distribution tiers

**Chosen:** tier 1 is the Debian family (Debian, Ubuntu, Raspberry Pi OS) and the RHEL family (AlmaLinux, Rocky Linux, Fedora). Tier 1 blocks every PR. Tier 2 is Arch, openSUSE and Alpine: tested nightly, best effort.

- *Rejected: all six families in tier 1.* Alpine has no PAM in its default sshd, no systemd, busybox tools and musl; that work would delay the first release.
- *Rejected: Debian family only.* The package-manager and hook abstractions would be shaped by apt alone and need rework.

### D3 Python 3.9 or newer

**Chosen:** 3.9. It covers every tier-1 release with its default `python3` (AlmaLinux and Rocky 9 ship 3.9, Ubuntu 22.04 ships 3.10).

- *Rejected: 3.11.* Users on two very common server releases would have to install another Python first.
- *Rejected: 3.6 for RHEL 8.* No dataclasses, old subprocess API, no current test tooling.

Consequence: `subprocess` accepts `user=`, `group=` and `extra_groups=` from 3.9, which the collector uses to drop privileges.

### D4 Licence GPL-3.0-or-later

**Chosen:** keep GPL-3.0-or-later. Stand-alone plugin executables are separate programs and are not affected.

- *Rejected: MIT.* It is the norm among comparable tools and has the lowest friction, but it changes the terms of a project published under the GPL since 2020 for no need the maintainer has.
- *Rejected: Apache-2.0.* More text, no practical gain here.

The bundled TOML parser (MIT) and the bundled header font (licence checked in phase 4) are compatible and keep their own notices.

### D5 New standalone repository `message-of-the-python`

**Chosen:** a fresh repository with a history that starts at the rewrite. Upstream is credited in the README. The old fork is renamed first (GitHub treats names that differ only in case as the same) and then archived, made private or deleted by the maintainer.

- *Rejected: detach the fork and keep the history.* The e-mail address, addresses and the screenshot stay in old commits.
- *Rejected: detach and rewrite the history.* Every hash changes and old objects can stay reachable in the fork network.
- *Rejected: stay a fork.* Issues are off by default, the banner points at an unrelated Go project, and code search skips forks.

Nothing on GitHub is renamed, created, pushed or deleted without the maintainer's explicit go-ahead in phase 0.

### D6 Commits use the GitHub noreply address

**Chosen:** the maintainer's `users.noreply.github.com` address, set in this repository's git config only.

- *Rejected: the current local placeholder identity.* Commits would not link to the profile.
- *Rejected: a public project mailbox.* It would be published in every commit. Security reports go through GitHub's private vulnerability reporting instead.

### D7 Hybrid login model: root timer collects, the user's shell renders

**Chosen:** a sandboxed root timer collects slow and privileged data into a cache. At login a shell hook renders as the logging-in user. No root code runs because of a login. A static mode (the timer writes finished text for pam_motd) stays available as a setting.

- *Rejected: static text only.* Fixed 80 columns, no colour, the same output for every user.
- *Rejected: live as root through `update-motd.d`.* Debian and Ubuntu only, slow modules delay login, module code runs as root at each login, and it fires for scp and sftp.

### D8 Local terminals: opt-in per user, every new shell

**Chosen:** off by default. `motp shell-init <shell>` prints a snippet that a user adds to their own rc file. It shows the MOTD in every new interactive shell.

- *Rejected: throttled to once per interval.* Recommended in the interview; the maintainer prefers seeing it in each new shell. No throttle setting ships in 1.0.
- *Rejected: system-wide by default.* It would change every user's terminals without asking them.
- *Rejected: login shells only.* Desktop users would never see it.

### D9 Config is TOML with a bundled fallback parser

**Chosen:** `/etc/motp/config.toml` plus `/etc/motp/conf.d/*.toml`. `tomllib` on Python 3.11 and newer; a bundled copy of [tomli](https://github.com/hukkin/tomli) (MIT, pure Python, the code `tomllib` was made from) on 3.9 and 3.10.

- *Rejected: INI.* Everything is a string; thresholds, rows and per-module tables would need invented syntax.
- *Rejected: JSON.* No comments.
- *Rejected: YAML.* Needs a third-party parser, which breaks the "runs with only python3" rule.

Config is data only. No value is ever passed to a shell or evaluated.

### D10 Extensions: exec plugins and config rows

**Chosen:** built-in modules are reviewed Python inside the package. Third parties add an executable in any language to a root-owned directory. Two common cases need no code: config rows for a systemd unit and for a file's age. An in-process Python API may follow after 1.0.

- *Rejected: Python drop-in modules.* Foreign code inside the root process; one bad import breaks the whole run.
- *Rejected: both from 1.0.* Two public interfaces to keep stable from the first release.
- *Rejected: pip entry points.* Any installed package could register root-run code, and system-wide pip installs are blocked on current distributions (PEP 668).
- *Rejected after review: a `command` config row.* A three-line plugin does the same, and one way to run foreign commands is easier to secure than two.

### D11 Detected software is enabled automatically

**Chosen:** every optional module defaults to `enabled = "auto"`: active when its program exists at a known absolute path. `motp modules` lists each module's state and the reason.

- *Rejected: ask during installation.* Software installed later would stay invisible.
- *Rejected: core only until switched on.* Least helpful for beginners.

### D12 Two visibility tiers

**Chosen:** everyone sees counts and states. Details (banned addresses, other users' names and hosts, container names, sources of failed logins) go into a second cache file that only root and one admin group can read.

- *Rejected: counts only for everyone.* Admins lose the details that make the screen useful.
- *Rejected: details for everyone.* Leaks names and addresses on multi-user machines.

### D13 Install from a release zipapp that installs itself

**Chosen:** CI builds one `motp.pyz` per release with a checksum file and a build attestation. `sudo python3 -I motp.pyz install` unpacks it into place, writes config, timer and hooks, and records a manifest for `motp uninstall`.

- *Rejected: native packages first.* Packaging work would land before the tool is stable. `.deb` and `.rpm` are a later phase.
- *Rejected: PyPI with pipx.* System-wide installs need `pipx install --global`, which arrived in pipx 1.5 (2024); Debian 12 and Ubuntu 22.04 ship older versions *(package versions unverified)*. The name `motp` belongs to an unrelated project on PyPI.
- *Rejected: git clone plus an install script.* Unversioned code from a branch, updated by pulling as root.

### D14 Unicode frames when the locale supports them

**Chosen:** box-drawing lines and block bars when the locale reports UTF-8, the ASCII look of the roadmap picture otherwise. `charset = "ascii"` and the environment variable `MOTP_CHARSET` force a choice.

- *Rejected: ASCII by default.* Recommended during the interview for its predictability; the maintainer prefers the modern look where it works.
- *Rejected: ASCII only.* No choice for users.

Known risks: a terminal can claim UTF-8 and still fail to draw the characters, and terminals set up for East Asian legacy widths draw box characters two cells wide. The override exists for both, and `motp doctor` prints a test line.

### D15 Header from a built-in font reader

**Chosen:** a small FIGfont reader in the package with one or two bundled fonts. The header text defaults to the short hostname. When the rendered header is wider than the terminal, the renderer tries the smaller font and then drops the header.

- *Rejected: a banner text file only.* Beginners would start without a header.
- *Rejected: require figlet or pyfiglet.* The main visual element would be missing on a fresh system.

### D16 Adaptive layout

**Chosen:** four width classes.

| Columns | Layout |
|---|---|
| 80 and more | header, framed sections, bars |
| 60 to 79 | compact frame, shorter labels and bars, no header |
| 40 to 59 | plain `label: value` lines, no frame |
| under 40 | the attention block only; if it is empty, one line with host and uptime |

- *Rejected: truncate lines.* Values on the right disappear.
- *Rejected: fixed 80 columns.* Unreadable on a phone.

### D17 Markers replace colour when colour is off

**Chosen:** with colour, values are green, yellow or red. Without colour, `[!]` (warning) or `[!!]` (critical) follows the value. Warnings appear in the attention block either way.

- *Rejected: markers always.* Noisier than the target look.
- *Rejected: colour only.* A full disk would look like an empty one.

Colour is off when `NO_COLOR` is set to a non-empty value, `TERM` is `dumb`, or the output is not a terminal. `MOTP_COLOR=always|never` overrides.

### D18 Scope of 1.0 is the wider cut

**Chosen:** the proposed must-have list plus three security basics: firewall state, automatic security updates, and end-of-life warning for the OS release. See section 9.

- *Rejected: the list as first proposed.* The three additions are of high value to beginners.
- *Rejected: a leaner first release.* fail2ban, containers and logins are what people expect from the picture.

### D19 Beginner helpers: `motp explain`, rotating tips, German output

**Chosen:** `motp explain <topic>`, rotating tips (off by default) and German as a second output language from 1.0.

- *Not selected: a status line on top ("All good" or "3 things need attention").* The attention block already carries that information.

Consequence: every user-visible string goes through a message catalogue from phase 2 on.

### D20 Repository name `message-of-the-python`, command `motp`

**Chosen:** the lower-case name, which is also free on PyPI.

- *Rejected: `motp`.* Shorter, but taken on PyPI.
- *Rejected: `Message-of-the-Python`.* Same name as the old fork with different case only.

### D21 Every probe runs in its own process, under one of two unprivileged users

**Chosen:** the collector starts each built-in module and each plugin as a separate process and reads a JSON document from its stdout. Built-in probes run as the system user `motp` unless they declare a need for root. Plugins run as a second system user, `motp-plugin`, unless the config grants root.

Why: a hard time limit means killing a process, a crash stays contained, most probes need no privileges, built-ins and plugins share one protocol, and foreign code never shares a user with built-in probes.

- *Rejected: modules in the collector process.* A hung call cannot be interrupted, and all module code would run as root.
- *Rejected after review: one shared user.* A plugin that escapes its process group could interfere with built-in probes of the same user.

### D22 The login path reads its program files and memory-backed state, nothing else

**Chosen:** `motp show` reads the interpreter and its own files under `/opt/motp`, plus `/proc`, `/sys` and `/run/motp`. It starts no process, opens no socket, resolves no user or group name, and does not read `/etc/motp`: the collector copies the settings the renderer needs into `/run/motp/render.json`.

Why: disk usage on a stale network mount, a config directory on remote storage, or a name lookup against a directory server can each block for seconds, and the render timer may not be able to interrupt such a call. The guarantee is therefore worded honestly: login-path time is bounded except while the kernel itself blocks on the files of the program.

- *Rejected: live disk usage at login.* One stale network mount would hang every login.
- *Rejected after review: reading `/etc/motp` at login.* It can sit on remote storage.

### D23 Optional third-party packages

The core runs with only `python3`. Every MOTP interpreter starts as `python3 -I -S`: isolated mode, and no site directories at all. A probe that needs an optional package adds exactly one distribution package directory to its own path, after the ownership-chain check, and never a path under `/usr/local`.

| Package | Reason | Used where | Status |
|---|---|---|---|
| tomli (MIT) | TOML on Python 3.9 and 3.10 | config loader | bundled copy at a pinned version in `_vendor/` |
| python3-apt (ships with apt on Debian and Ubuntu) | exact counts of pending and security updates on Debian, where no stamp file exists | `os_updates` probe, which runs unprivileged | optional in 1.0, with a fallback to `apt-get -s` |
| [pyfiglet](https://pypi.org/project/pyfiglet/) (MIT, release 2025-08) | more header fonts | `motp banner`, an admin command | candidate for 1.x |
| [cryptography](https://pypi.org/project/cryptography/) (Apache-2.0/BSD, release 2026-09) | certificate expiry where the `openssl` binary is absent | certificate rows | candidate for 1.x, decided in that phase |

Considered and not used:

- **rich:** import time is too high for the login path, and the renderer is small enough to own.
- **psutil:** `/proc` and `/sys` cover Linux; reconsidered for sensors after 1.0.
- **distro:** `/etc/os-release` is a few lines to parse.
- **docker SDK:** the CLI at an absolute path is enough.
- **systemd-python:** `journalctl --output=json` is enough, and the last PyPI release is from 2023.
- **PyYAML:** see D9.

### D24 Installation prefix `/opt/motp`

**Chosen:** everything root executes lives under `/opt/motp`. Units and hooks call `/opt/motp/bin/motp`. The installer adds `/usr/local/bin/motp` as a convenience only if that directory chain is writable by root alone. Documentation writes `sudo /opt/motp/bin/motp`.

Why: on Debian, `/usr/local` and the Python directories below it can be writable by the group `staff` *(checked per release in phase 7)*, and sudo's default path on the RHEL family leaves out `/usr/local/bin`. Native packages later install to `/usr/lib/motp`.

- *Rejected: `/usr/local/lib/motp` everywhere.* It would depend on the outcome of that check on each system.

### D25 The collector never uses the network

**Chosen:** the collector unit allows only local sockets, and probes perform no name resolution. The public-address lookup (after 1.0) is a separate, opt-in unit that runs unprivileged, names its provider in the config and in the output, and hands its result to the collector as untrusted input.

- *Rejected: a network switch inside the collector.* One unit would need both root and network access.

### D26 Two output forms for plugins

**Chosen:** a plugin either prints a JSON document, or it follows the monitoring-plugin convention: one line of text and an exit code (0 ok, 1 warning, 2 critical, 3 unknown). A three-line shell script is a valid plugin.

- *Rejected: JSON only.* Too much for a beginner's first plugin.

### D27 Plugin output is admin-only until made public

**Chosen:** items from a plugin are visible to the admin tier unless the config sets `visibility = "public"` for that plugin.

- *Rejected: public by default.* The author of a plugin does not know who else has an account on the machine.

### D28 The tool never refreshes package metadata

**Chosen:** update counts come from what the system already has: Ubuntu's stamp file, `apt` and `dnf` in cache-only mode. If the data is old, MOTP shows its age.

- *Rejected: running `apt update` or `dnf makecache` from the collector.* It needs the network and competes with the system's own timers.

### D29 The distribution's own MOTD is left alone by default

**Chosen:** the installer does not touch `/etc/update-motd.d`, `/etc/motd` or existing drop-ins. `motp doctor` explains how to quiet them, and notes that sshd prints its own "Last login" line. An installer flag that records and reverts such changes is planned after 1.0.

- *Rejected: disabling them at install.* Surprising, and hard to undo cleanly.

### D30 No per-user config file in 1.0

**Chosen:** users steer presentation through environment variables (`NO_COLOR`, `MOTP_COLOR`, `MOTP_CHARSET`, the locale). System config lives in `/etc/motp` only.

- *Rejected for 1.0: `~/.config/motp/config.toml`.* It adds a file that the tool reads from a user-controlled location; it can follow once the rules for it are written and reviewed.

### D31 The installed form is an unpacked, precompiled tree

**Chosen:** the release artefact stays one verifiable `motp.pyz`. The installer unpacks it to `/opt/motp/lib/` and compiles bytecode with the system interpreter. Running the archive directly keeps working for trying it out.

Why: Python never caches bytecode for code imported from a zip archive, so every login would recompile every module. That makes a 150 ms target unrealistic on a Raspberry Pi.

- *Rejected: running the archive at login.* See above.

After a distribution upgrade changes the Python version, the bytecode no longer matches; `motp doctor` reports it and `motp install` rebuilds it.

### D32 Per-user data lives in per-user files

**Chosen:** data that only one user may see (their previous login) is written by a root probe to `/run/motp/user/<uid>.json`, owned by that user with mode 0400, inside a root-owned directory.

- *Rejected: the public cache.* It would show every user's logins to everyone.
- *Rejected: reading `wtmp` or the lastlog database at login.* Those files are outside the paths D22 allows.

### D33 The admin group is fixed at install time and is never `adm`

**Chosen:** the installer picks `sudo` or `wheel` only when an active sudoers rule grants that group, writes the choice into the config, and prints it. Without such a group the admin tier is readable by root alone, and `motp doctor` says so.

- *Rejected: detection at run time with `adm` as a fallback.* `adm` holds log readers and service accounts on many systems.

### D34 Hints are ids; plugins cannot supply commands

**Chosen:** a built-in probe names a hint by id, and the renderer takes the command from a fixed table in the package. Plugins may supply a plain-text hint, which is shown as text under the plugin's name and never as a command.

- *Rejected after review: a free-text `command` field in the probe document.* Collected text could then end up displayed as a command to run.

---

## 4. Architecture

### 4.1 Overview

```
                 every 5 min (systemd timer, or cron without systemd)
                          |
                 motp collect  (root, sandboxed unit, local sockets only)
                    |                         |
        built-in probes                 exec plugins
        one process each                one process each
        user "motp" unless              user "motp-plugin" unless root
        the module needs root           is granted in the config
                    \                         /
                 JSON over stdout, size-capped, validated, sanitised
                          |
             /run/motp/public.json      0644 root:root
             /run/motp/admin.json       0640 root:<admin group>
             /run/motp/render.json      0644 root:root   (renderer settings)
             /run/motp/user/<uid>.json  0400 <uid>       (per-user data)
             (static mode: /run/motd.d/10-motp)
                          |
   login ->  /etc/profile.d/motp.sh  ->  motp show --login   (the logging-in user)
                          reads the cache, adds live values from /proc,
                          fits width, colour, charset and language,
                          writes once to the terminal
```

Three trust domains:

1. **Collector (root).** Small, reviewed, no network, never triggered by a login.
2. **Probes and plugins (unprivileged users, or root by explicit declaration).** Their output is untrusted input to the collector.
3. **Renderer (the logging-in user).** Reads files only root can write, plus its own per-user file. Has no privilege to lose.

### 4.2 Package layout

```
src/motp/
  __main__.py        entry point; arms the render deadline before anything else
  cli.py             show, collect, preview, modules, doctor, explain, config,
                     install, uninstall, shell-init, version, _probe
  core/
    model.py         Item, ModuleResult, Status, Visibility
    sanitize.py      the only place external text is cleaned
    thresholds.py    rules and classification
    cache.py         schemas, bounded reads, atomic tiered writes
    i18n.py          message catalogue and substitution
    hints.py         fixed table: hint id -> text id and command per package manager
    config.py        load, merge, validate
    safepath.py      ownership-chain checks
    proc.py          the only module that may start processes
    deadline.py      wall-clock limit for the render path
  modules/           one file per built-in probe (hw_, os_, net_, sec_, app_)
    registry.py      explicit list of built-in modules
  collect/
    runner.py        scheduling, time limits, privilege drop, cleanup
    plugins.py       discovery and validation of exec plugins
    rows.py          config rows
  render/
    view.py layout.py theme.py bars.py figfont.py fonts/
  install/
    installer.py units.py hooks.py manifest.py
  data/              default-config.toml explain.toml eol.toml tips.toml
  locale/            en and de catalogues (.po sources, .mo built)
  _vendor/tomli/
```

The 2020 naming scheme stays: module files carry a group prefix. `custom_` becomes `app_` (third-party software) and `sec_` is new.

### 4.3 Module interface

```python
class Module(Protocol):
    name: str                      # "os_updates"
    section: str                   # where it renders: "system", "security", ...
    mode: Literal["live", "cached"]
    needs_root: bool               # cached modules only; live modules never
    interval: int                  # seconds between runs, at least the timer period
    max_age: int                   # seconds after which old items are dropped
    timeout: float                 # seconds before the probe is killed
    binaries: tuple[str, ...]      # absolute paths the module may execute
    default_visibility: Visibility

    def detect(self, ctx: Context) -> Detection: ...
    def collect(self, ctx: Context) -> list[Item]: ...
```

`Context` is the only door to the system:

- `ctx.read_text(path, max_bytes)` reads a bounded amount.
- `ctx.run(argv)` starts a program. It raises in live mode, and it refuses any `argv[0]` that is not listed in the module's `binaries`.
- `ctx.config` is the module's own config table.
- `ctx.os_release` and `ctx.now` complete it.

Tests replace `Context` with one that serves files from a fixture tree and recorded command output per distribution.

Rules for modules:

- **Live** modules read `/proc` and `/sys` only. They exist for values that change by the second.
- **Cached** modules run in the collector. Each one is started with the running interpreter and the running program path: `<python> -I -S <program> _probe <name>`.
- `detect()` looks at absolute paths (`/usr/bin/fail2ban-client`), unit files or directories. It never searches `PATH`.
- A module returns values, rule names and hint ids. It never returns colour codes, commands or finished layout.

Built-in modules of 1.0:

| Module | Content | Mode | Section | Runs as | Phase |
|---|---|---|---|---|---|
| `hw_load` | load averages against the CPU count | live | system | reader | 5 |
| `hw_memory` | memory and swap | live | system | reader | 5 |
| `os_uptime` | uptime | live | system | reader | 5 |
| `os_host` | hostname, OS name, kernel | cached | host | motp | 6 |
| `net_addresses` | local addresses, DNS servers | cached | host | motp | 6 |
| `hw_disks` | space, inodes and bars per filesystem | cached | disks | motp | 6 |
| `os_updates` | pending and security updates | cached | system | motp | 9 |
| `os_reboot` | reboot required | cached | system | motp | 9 |
| `os_autoupdates` | automatic security updates on or off | cached | security | motp | 9 |
| `os_eol` | end of life of the OS release | cached | system | motp | 9 |
| `os_units` | failed systemd units | cached | services | motp | 10 |
| `os_sessions` | logged-in sessions | cached | login | motp | 10 |
| `os_login` | the user's previous login | cached, per user | login | root | 10 |
| `sec_logins` | failed SSH logins in the last 24 hours | cached | security | root | 11 |
| `sec_fail2ban` | bans | cached | security | root | 11 |
| `sec_firewall` | firewall active or not | cached | security | root | 11 |
| `app_containers` | Docker container states | cached | containers | root | 11 |
| row `unit` | state of a named unit | cached | services | motp | 10 |
| row `file_age` | age of a file against limits | cached | services | motp | 12 |
| exec plugins | anything | cached | plugins | motp-plugin, or root | 12 |

### 4.4 Data scheme (probe protocol, version 1)

A built-in probe prints one JSON document:

```json
{
  "api": 1,
  "module": "os_updates",
  "items": [
    {
      "key": "updates.pending",
      "label": {"id": "label.updates"},
      "value": 12,
      "unit": "count",
      "rule": "updates_pending",
      "text": {"id": "updates.summary", "params": {"count": 12, "security": 3}},
      "visibility": "public",
      "hint": "updates.install",
      "detail": [
        {"key": "updates.packages", "value": "openssl, curl, libc6", "visibility": "admin"}
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `key` | stable identifier, `module.name`; plugin keys are forced into `plugin.<plugin name>.*` |
| `label` | built-ins: a message id. Plugins: a literal string, or `{"text": "Backup", "i18n": {"de": "Sicherung"}}` |
| `value`, `unit` | raw value and its unit: `count`, `bytes`, `percent`, `ratio`, `seconds`, `timestamp`, `celsius`, `text`, `bool` |
| `rule` | name of a threshold rule; the core classifies the value |
| `status` | `ok`, `warn`, `crit`, `unknown`; a probe sets it only when no rule fits |
| `text` | built-ins: a message id with parameters; `count` selects the plural form. Plugins: a literal string |
| `bar` | optional fill ratio for a usage bar |
| `visibility` | `public` or `admin` |
| `hint` | built-ins: a hint id from the fixed table. Plugins: a plain-text sentence |
| `detail` | extra rows, usually admin-only |

This is the old "value plus rule set" scheme with a defined shape.

Rules that keep collected text from becoming a template or a command:

- Only catalogue strings are templates. Substitution replaces `{name}` and nothing else: no attribute access, no indexing, no format specification. It is a small function of its own, not `str.format`.
- Every parameter is reduced to a number or a sanitised string before substitution.
- Plugins cannot use catalogue ids or hint ids. Their rows carry the fixed prefix `[plugin <name>]`, also in the attention block.

The collector accepts a document only if it passes all of these:

- at most 64 KiB, valid UTF-8 after replacement, valid JSON without `NaN` or infinities;
- known fields with the expected types, at most 32 items, strings within length limits;
- the `module` name matches the probe that was started.

Anything else marks the module as failed for this run.

Cache files:

```json
{
  "schema": 1,
  "generated": 1795600000,
  "modules": {
    "os_updates": {"collected": 1795599700, "state": "ok", "duration_ms": 180, "items": []}
  },
  "failed": 0
}
```

- `public.json` holds only public items. `admin.json` holds the admin items and details.
- `render.json` holds the settings the renderer needs: layout, charset and colour defaults, thresholds for live values, language.
- `user/<uid>.json` holds that user's three most recent logins. With `show --login`, the previous login is the newest entry that started more than ten seconds ago; without `--login`, the login section is left out.

Scheduling and ageing:

- A module runs when its interval has passed, or when its items are missing from the cache (after a reboot `/run` is empty).
- The last good items of every module are kept in `/var/lib/motp/state.json` (root only) and carried into each cache write, so a module that did not run this time is still shown.
- Items are **stale** when older than three times the module's interval: they are shown with their age. They are **expired** after the module's `max_age` and are replaced by "unknown".
- If the whole cache is older than three timer periods, the MOTD says how old it is. Without any cache, live values are shown with one notice.

### 4.5 Threshold rules

A rule has a direction and two limits:

```toml
[thresholds.disk_used_percent]
warn = 80
crit = 90

[thresholds.load_per_core]
warn = 0.7
crit = 1.0

[thresholds.cert_days_left]     # lower is worse
warn = 21
crit = 7
```

Defaults ship in `default-config.toml`. The collector classifies cached values, the renderer classifies live values with the limits from `render.json`, and both use the same function.

### 4.6 Renderer

Pipeline: cache and live values, then a view model (sections with rows), then layout for the width class, then theme, then one write.

- **Width:** `shutil.get_terminal_size()`, classes as in D16.
- **Charset:** Unicode when `LC_ALL`, `LC_CTYPE` or `LANG` names UTF-8 and the output encoding agrees; ASCII otherwise.
- **Colour:** off, 16 colours, or 256 colours when `TERM` or `COLORTERM` says so. Rules in D17.
- **Text width:** computed with `unicodedata`. Wide characters count two cells; the theme's own frame characters and other ambiguous-width characters count one. Values are one line and are truncated, never wrapped.
- **Language:** from the reader's locale at render time, English as fallback. Catalogues are loaded as bytes through the package loader, so they work from the unpacked tree and from the archive.
- **Escape sequences** come from the theme table only. Every other string has passed the sanitiser.

Static mode is a separate, simpler output: public items only, no colour, 80 columns, the configured language, ASCII unless the config asks for Unicode.

Target look at 80 columns with Unicode (demo data):

```
┌─────────────────────────────────────────────────────────────┐
│   <header: short hostname in the bundled font>              │
├──────────┤ Attention ├──────────────────────────────────────┤
│  12 updates, 3 security ........ sudo apt upgrade           │
│  Reboot required ............... sudo reboot                │
├──────────┤ Host ├───────────────────────────────────────────┤
│  Hostname.........:  web01.example.com                      │
│  Local address....:  192.0.2.10                             │
│  Operating system.:  Debian GNU/Linux 13                    │
│  Uptime...........:  41 days 3 hours                        │
│  Load.............:  0.42, 0.37, 0.31                       │
│  Memory...........:  5.9 GiB of 7.9 GiB                     │
├──────────┤ Disks ├──────────────────────────────────────────┤
│  /  ................................ 56% of 40 GiB          │
│  ██████████████████████░░░░░░░░░░░░░░░░░                    │
└─────────────────────────────────────────────────────────────┘
```

The ASCII theme uses `+`, `-`, `|` and `/` as in the roadmap picture.

Sections and their order are configurable:

```toml
[layout]
sections = ["attention", "host", "system", "security", "login", "disks", "services", "containers", "plugins"]
header = "hostname"     # hostname | text | off
charset = "auto"        # auto | ascii | unicode
color = "auto"          # auto | always | never
```

### 4.7 Configuration

- Files: `/etc/motp/config.toml`, then `/etc/motp/conf.d/*.toml` in name order. Later files override earlier ones, table by table.
- Only the collector and the admin commands read these files. The renderer reads `render.json` (D22).
- A file is used only if it and every directory above it belong to root and are not writable by group or others. A file that fails the check is ignored, defaults apply, and one visible line says so.
- Unknown keys and wrong types are errors with the file name, the key and the expected type. `motp config check` runs the same validation.
- `motp config init` writes a commented starter file and never overwrites an existing one.
- The config is world-readable. The documentation says: no secrets in it.

```toml
[general]
mode = "hybrid"            # hybrid | static
language = "auto"

[limits]
render_ms = 1000
probe_timeout_s = 5
collect_total_s = 60

[visibility]
admin_group = "sudo"       # written by the installer (D33); "" means root only

[modules.sec_fail2ban]
enabled = "auto"           # auto | true | false

[[rows.unit]]
name = "nginx.service"
label = "Web server"

[[rows.file_age]]
path = "/var/backups/last-success"
label = "Backup"
warn_after = "26h"
crit_after = "3d"

[plugins."50-backup-status"]
run_as = "motp-plugin"     # motp-plugin | root
timeout_s = 5
visibility = "admin"       # admin | public
```

### 4.8 Detection

Each optional module lists the absolute paths it looks for. A program found there is used only if the file and the directories above it belong to root and are not writable by others.

`motp modules` prints one line per module: name, state (active, not detected, disabled, failed), reason, user it runs as, interval and visibility. That table is the answer to "why don't I see docker?".

### 4.9 Running probes and plugins

Every process the collector starts goes through `core/proc.py`, which always sets all of these:

- an argument list with an absolute program path; no shell;
- `user=`, `group=` and `extra_groups=[]` together, so the child has no trace of group 0;
- a new session, working directory `/`, stdin from `/dev/null`;
- an environment built from scratch: `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C.UTF-8`, and `MOTP_PLUGIN_API=1` for plugins;
- limits on CPU time, file size and number of processes;
- a deadline: output is read with a timeout and never waits for the end of file from descendants; on expiry the process group is killed.

After each plugin, and at the end of the run, the runner kills every process still owned by `motp-plugin` and then by `motp`. It does this from a helper that has dropped to that user. This also catches a child that left its process group.

Exec plugins:

- **Location:** `/etc/motp/plugins.d/`. Names match `NN-name` (two digits, a dash, lower-case letters, digits, dash, underscore). Other files are ignored and listed by `motp doctor`. At most 32 plugins run.
- **Validation before each run:** the real path is resolved and that resolved path is what gets executed. The file must be a regular, executable file owned by root and not writable by group or others. Every directory from `/` down to it must meet the same ownership rule.
- **Interpreter:** the runner reads the `#!` line and applies the same check to the interpreter. A plugin that runs as root may not use an `env` line.
- **User:** `motp-plugin`, with no groups. Root only when the config says `run_as = "root"` for that plugin by name.
- **Limits:** a time limit per plugin, 64 KiB of stdout, 8 KiB of stderr kept for the log.
- **Order:** plugins run after all built-in probes have finished.
- **Output:** JSON, or one line plus exit code (D26). Rules from 4.4 apply.
- **Without the system users** (the archive run without installation) plugins are skipped. They never fall back to root.

`docs/plugins.md` documents the protocol with a three-line shell example, a Python example, a checklist, and the sandbox a plugin inherits: no network, no writable-and-executable memory (which rules out JIT runtimes such as Node or Java), a small `/tmp`, and for root plugins a reduced set of capabilities.

### 4.10 Login hook

Hybrid mode installs `/etc/profile.d/motp.sh` for sh-style login shells:

```sh
# Message of the Python: show the MOTD in interactive login shells only.
if [ -t 1 ] && [ -x /opt/motp/bin/motp ]; then
    case $- in *i*) /opt/motp/bin/motp show --login 2>/dev/null || : ;; esac
fi
```

- zsh gets the same logic in the system `zprofile` location, where one exists (open item O10).
- fish users add the snippet from `motp shell-init fish`, which checks `status is-interactive`. A system-wide fish hook follows after 1.0.
- Where the `timeout` program is available and behaves with a terminal, the hook wraps the call in it as a second limit (open item O11).
- `--login` tells `show` that it runs from a login hook: the login section is shown, and on any error or timeout it exits silently with code 0.

The hook prints nothing in non-interactive sessions. Tests check that with `ssh host true`, scp, sftp and rsync.

Static mode installs no shell hook. The collector writes `/run/motd.d/10-motp` and pam_motd prints it. On Alpine (tier 2) static mode writes `/etc/motd`, after a backup recorded in the manifest.

Local terminals: `motp shell-init bash|zsh|fish` prints a snippet for the user's own rc file with the same interactive and terminal checks. The login hook sets a plain shell variable that is not exported, so the rc snippet of the same shell does not print a second time, while child shells and new tabs do print (D8).

### 4.11 Collector unit

`motp-collect.timer` starts 20 seconds after boot and then every 5 minutes. `motp-collect.service` is a one-shot unit. Baseline:

```ini
[Service]
Type=oneshot
ExecStart=/opt/motp/bin/motp collect
TimeoutStartSec=90
UMask=0077
RuntimeDirectory=motp
RuntimeDirectoryPreserve=yes
StateDirectory=motp
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
TemporaryFileSystem=/tmp:size=16M
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_CHOWN
TasksMax=128
MemoryMax=256M
Nice=10
IOSchedulingClass=idle
```

Notes:

- `RestrictAddressFamilies` is what blocks IP traffic everywhere. `IPAddressDeny` adds a second barrier where the system uses the unified cgroup hierarchy.
- Capabilities: `CAP_SETUID`, `CAP_SETGID` for the drop to the two system users, `CAP_KILL` to end their processes, `CAP_CHOWN` for the group of `admin.json` and the owner of per-user files.
- Additions are made per module and listed in a table next to the unit, so each loosening has an owner:

| Addition | Needed by | Condition |
|---|---|---|
| `ReadWritePaths=/run/motd.d` plus a tmpfiles entry | static mode | only when `mode = "static"` |
| `CAP_NET_ADMIN` | `sec_firewall` | only if no source without it is found (open item O12) |
| access to the system bus socket | `os_units`, service rows | verified in phase 7 (open item O4) |

- The exact set is settled in phase 7 against the oldest tier-1 systemd (249 on Ubuntu 22.04) and recorded with the output of `systemd-analyze security`.

Without systemd (Alpine, tier 2) a cron entry runs the same command. The sandbox is then missing, which `motp doctor` states. The collector itself still sets umask 077, changes to `/`, and sets every file's mode and owner explicitly.

`motp collect` typed by an admin does not run in the admin's shell environment: it starts the unit (`systemctl start --wait motp-collect.service`) and prints the result. `--no-sandbox` runs it directly, for containers and debugging.

### 4.12 Installation and removal

The README tells the user to verify the download first and then run `sudo python3 -I motp.pyz install [--dry-run] [--mode hybrid|static] [--no-start]`. The installer:

1. Checks: effective user is root, Python is 3.9 or newer, the target directories meet the ownership rule.
2. Opens its own archive once and works from that open file from then on. It unpacks to `/opt/motp/lib/`, compiles bytecode, and writes `/opt/motp/bin/motp`, which runs `/usr/bin/python3 -I -S /opt/motp/lib`.
3. Creates the system users `motp` and `motp-plugin`: local entries in the system range, no home directory, no login shell, locked password. If an account of that name already exists and was not created by MOTP, the installer stops.
4. Determines the admin group (D33).
5. Creates `/etc/motp/` with `config.toml` (only if missing), `conf.d/` and `plugins.d/`.
6. Writes and enables the units when `/run/systemd/system` exists; otherwise the cron entry.
7. Writes the login hooks.
8. Records every created path with a content hash in `/var/lib/motp/install-manifest.json`.
9. Starts the collector unit once and prints the result of `motp doctor`.

`motp uninstall` removes only manifest paths that lie under a fixed list of prefixes, are not symlinks, and still have the recorded content. Changed files are reported and left. Config stays unless `--purge` is given. Upgrading means running `install` from the new archive.

There is no self-update and no version check over the network.

Release artefacts: `motp.pyz`, `SHA256SUMS` and a GitHub build attestation. The archive is written with `zipfile` directly: stored without compression, sorted entries, fixed timestamps and file attributes, no bytecode. That makes builds byte-identical across machines, so anyone can rebuild a tag and compare the hash.

### 4.13 Commands

| Command | Purpose | Runs as |
|---|---|---|
| `motp` / `motp show [--login] [--debug]` | render the MOTD | anyone |
| `motp preview --demo [--width N] [--charset ..] [--color ..]` | render fixed demo data | anyone |
| `motp modules` | list modules, state and reason | anyone (admin tier sees more) |
| `motp doctor` | check installation, permissions, cache age, failed modules, bytecode, terminal | anyone; more as root |
| `motp explain <topic>` | plain explanation of a value or warning | anyone |
| `motp config init`, `motp config check` | write a starter config, validate config | root |
| `motp collect [--no-sandbox]` | run the collector once | root |
| `motp install`, `motp uninstall` | set up or remove | root |
| `motp shell-init <shell>` | print the rc snippet | anyone |

### 4.14 Time budgets

| Path | Limit | Enforced by | On expiry |
|---|---|---|---|
| Render at login | 1.0 s wall clock (configurable); target under 150 ms on a Raspberry Pi 4 | an interval timer armed first thing in `__main__`, whose handler calls `os._exit(0)`; a `timeout` wrapper in the hook where available | exit 0 without output |
| One probe or plugin | 5 s default, 30 s maximum | the runner kills the process group, then the user's remaining processes | module marked failed, last good value kept |
| Whole collector run | 60 s | runner deadline plus `TimeoutStartSec=90` | remaining probes killed, cache written with what exists |

Limits of the render deadline, stated plainly: the timer takes effect between Python instructions and in interruptible system calls. Interpreter start and the first imports happen before it is armed. D22 removes the calls that could block for long, which leaves the program's own files on the root filesystem.

A lock file in `/run/motp` keeps two collector runs from overlapping.

### 4.15 Errors and logs

- The renderer writes no log and prints no traceback. With `--debug` it prints both to the terminal.
- The collector logs to stderr, which the journal or cron captures.
- Failed modules are counted in the cache. The MOTD shows one line ("2 modules failed, run `motp doctor`"), which is the 2019 idea of a single error notice.

---

## 5. Threat model

### 5.1 What is protected

1. **Root on the machine.** The collector is the only part that runs as root.
2. **Login availability.** No failure or delay in MOTP may delay or block a login or break a file transfer.
3. **Confidentiality** of admin-tier details and of anything secret on the system.
4. **Integrity of the screen.** What an admin reads, including suggested commands, must come from the system and not from an attacker.
5. **The terminal** of every person who logs in.
6. **The release artefact** that users run as root.

### 5.2 Who attacks

| Id | Adversary | Capability |
|---|---|---|
| A1 | local unprivileged user | shell account; wants root, other users' data, or to disturb logins |
| A2 | remote party without an account | controls strings that reach the screen: reverse DNS of a client, attempted user names, banned hosts, DHCP-provided names, certificate subjects, container and image names |
| A3 | author of a plugin the admin installed | code that runs under the collector |
| A4 | supply chain | release pipeline, GitHub account, bundled code, optional packages |
| A5 | network attacker | relevant only when the public-address lookup is enabled |
| A6 | honest admin making mistakes | world-writable config, plugin copied with wrong permissions |

### 5.3 Threats and mitigations

| Id | Threat | Mitigation | Verified by |
|---|---|---|---|
| T1 | A1 replaces or edits config, a plugin or the program and gets code run as root | every file root reads or executes, and each directory above it, must belong to root and not be writable by group or others; the resolved path is what gets executed; prefix `/opt/motp` | tests that build bad ownership chains inside a container; `motp doctor` |
| T2 | A1 influences a MOTP process through the environment or Python's search path (`PATH`, `PYTHONPATH`, `LD_PRELOAD`, working directory, a `.pth` file in a group-writable site directory) | every interpreter runs with `-I -S`; optional package directories are added one by one after the ownership check and never from `/usr/local`; child environments are built from scratch; programs are called by absolute path; a manual `collect` starts the unit | test that no `sys.path` entry is writable by any non-root user or group, on every tier-1 image; audit-hook test over the environment of started processes |
| T3 | shell injection through values | no shell anywhere: `core/proc.py` is the only module that starts processes, takes argument lists and refuses relative paths; config values are never interpreted | AST test forbids `subprocess`, `os.system`, `os.popen`, `shell=True`, `eval`, `exec`, `pickle` outside the allow-list |
| T4 | A slow or hung source delays login | the login path starts no process, opens no socket, resolves no names, and reads only program files, `/proc`, `/sys` and `/run/motp`; cache files are opened without following links and without blocking, must be regular files, and are read up to a cap; a wall-clock limit ends rendering | audit-hook test with an explicit allow-list of paths; AST test forbids `pwd`, `grp` and `socket` in the render path; sshd test with a hung collector |
| T5 | Output in non-interactive sessions breaks scp, sftp, rsync, git | the hook requires an interactive shell and a terminal | container test: `ssh host true` prints nothing extra; scp, sftp and rsync succeed |
| T6 | A2 injects terminal escape sequences, bidirectional overrides, or look-alike frames | one sanitiser (rules in 5.5) runs when the collector accepts probe output and again when the renderer reads a cache file; only the theme emits escapes | corpus test over every listed class; golden test that hostile fixtures render inert |
| T7 | A2 or A3 makes the screen show a harmful "fix command" | commands exist only in a fixed table in the package and are selected by id; plugins cannot supply commands or catalogue ids; plugin rows carry a fixed prefix | unit test: the hint table takes no parameter from collected data; schema test rejects plugin documents with ids |
| T8 | A probe returns oversized or malformed output to crash or stall the root collector | size caps, read deadline, strict schema, item and string limits, `NaN` rejected, standard `json` only | hostile-probe fixtures: 1 MiB output, deep nesting, wrong types, a descendant that keeps the pipe open |
| T9 | A3: a malicious plugin | a plugin is code the admin chose to install; MOTP limits damage: its own unprivileged user without groups, no network, time, output and resource limits, all leftover processes killed after it runs; root only by explicit per-plugin config | tests for user and group ids in the child, timeout, cleanup of a process that left its group |
| T10 | Sensitive details reach unprivileged users | separate cache files per audience; each module declares what is public; plugin items default to admin; per-user data goes to per-user files | visibility test: an unprivileged user's output contains none of the fixture details; table in 5.4 |
| T11 | Secrets reach the screen or the log | modules read no secret-bearing file content; certificate rows read certificates, never keys; attempted user names of failed logins are never stored; stderr of probes is truncated and goes to the root-readable log only | review checklist per module; test that fixture secrets never appear in any cache file |
| T12 | A1 plants a symlink or races a cache write | `/run/motp` and `/var/lib/motp` are writable by root only; files are created with exclusive, no-follow flags, get mode and owner set on the open file, and are renamed into place | permission test in a container |
| T13 | The collector reaches out to the network | the unit allows only local and netlink sockets; probes do no name resolution; an AST test forbids `socket`, `urllib`, `http`, `ssl` in the package | `systemd-analyze security` output; AST test |
| T14 | A5 tampers with the public-address answer | opt-in, separate unprivileged unit, HTTPS, result parsed with `ipaddress` and treated as untrusted, provider named in config and output, cached | ships after 1.0 with its own review |
| T15 | A4 ships a tampered release | releases built by CI from a tag; workflow actions pinned by commit hash; minimal token permissions; byte-identical archive; `SHA256SUMS` plus build attestation; two-factor login and branch protection | a rebuild on a second machine compares hashes (this shows the build is reproducible; it does not prove the pipeline is honest) |
| T16 | A4 through bundled or optional code | tomli is vendored at a pinned version with its hash recorded; no site directory is loaded; the root collector imports no third-party package | vendor manifest check; test as T2 |
| T17 | A6 leaves config or plugins writable | the same ownership check refuses them and says why, in the MOTD (one line) and in `motp doctor` | tests as T1 |
| T18 | Root runs `motp show` (root login) and the tool trusts something it should not | the renderer loads no plugins and executes nothing; it reads the cache only from a root-owned directory | audit-hook test run as root |
| T19 | A1 fills or blocks the cache directory | only root can write there; a lock prevents overlapping runs; the unit has a start timeout | unit review |
| T20 | Local-terminal snippet prints into non-interactive shells | the snippet carries the same interactive and terminal checks as the system hook | shell tests for bash, zsh and fish |
| T21 | A root plugin's interpreter line points at a program A1 can replace | the ownership check also covers the interpreter; `env` lines are refused for root plugins | test with a plugin whose interpreter sits in a writable directory |
| T22 | Collected text is used as a format template and reads internal data | only catalogue strings are templates; substitution accepts plain `{name}` only; parameters are scalars | unit test with attribute and index templates in parameters and plugin labels |
| T23 | A probe or plugin exhausts processes, memory or disk | unit limits on tasks and memory, a small `/tmp`, per-child limits, a cap on the number of plugins | fork-bomb and output-flood fixtures |
| T24 | The installer adopts an existing account named `motp` (a person, or a directory account) | the installer stops unless the account is in its own manifest; it requires a local entry, a system id, no login shell and a locked password | installer test with a pre-existing account |
| T25 | `motp uninstall` is tricked into deleting other files | only manifest paths under fixed prefixes, never through links, only with unchanged content | test with a tampered manifest and a swapped symlink |
| T26 | Mount points or labels disclose other users' paths | removable-media and per-user mounts are admin-only; pseudo and FUSE filesystems are not listed | fixture test for `/media/<user>/<label>` and `/run/user/*` |

### 5.4 What each audience sees

| Module | Public | Admin tier only |
|---|---|---|
| host, OS, kernel, uptime, load, memory | all | none |
| local addresses, DNS servers | all | none |
| disks | system filesystems with usage | removable and per-user mounts |
| updates | counts | package names |
| reboot required | yes or no | packages that ask for it |
| failed units | count | unit names |
| watched services (config rows) | label and state | none |
| sessions | count | user names and hosts |
| previous login | the user's own, from their per-user file | does not apply |
| failed logins | count over 24 hours | sources; attempted user names are never stored |
| fail2ban | number of bans | banned addresses, jail names |
| containers | counts by state | names, images |
| firewall, automatic updates | nothing | state and hint |
| end of life | all | none |
| plugins | nothing unless set public | all |
| module failures | count | module names and reasons |

`public.json` contains nothing beyond what the rendered public output shows.

### 5.5 Untrusted strings and the sanitiser

Treated as hostile wherever they appear: hostname and domain, DNS and DHCP data, reverse-resolved client hosts, user names, unit names and descriptions, mount points, container and image names, jail names, certificate subjects, package names, everything a plugin prints, and the content of every cache file when read back.

The sanitiser, specified in phase 2 with a test corpus:

- decodes with replacement; NUL and lone surrogates become the replacement character;
- removes C0 and C1 control characters, DEL, line and paragraph separators;
- removes Unicode format characters (including bidirectional controls and zero-width characters), private-use and unassigned code points, variation selectors, and the invisible filler letters;
- allows at most two combining marks per base character;
- replaces box-drawing and block characters and collapses long runs of dots in values, so a value cannot draw a fake row or frame;
- replaces emoji, counts wide characters as two cells, and truncates to the field's limit;
- in the ASCII theme, replaces every non-ASCII character.

### 5.6 Residual risks

- A plugin that the admin installs with `run_as = "root"` is root. MOTP cannot change that; the documentation says so.
- On Debian, members of `staff` can write below `/usr/local`, and members of `docker` control the Docker daemon. Both groups are equivalent to root by the distribution's own design. MOTP adds no new route for them and cannot remove the existing ones.
- Local sockets let a probe talk to daemons that themselves use the network. Probes are written not to ask them to.
- A root login renders text that other users or remote parties influenced. The sanitiser bounds what that text can do.
- Without systemd the sandbox is absent.
- A process that is blocked inside the kernel on the program's own files cannot be ended by the render timer.
- A compromised GitHub account can publish a bad release with a matching checksum. The attestation and reproducible builds raise the bar; they do not remove the risk.
- The old fork's history keeps the personal e-mail address public for as long as that repository is public.

---

## 6. Open items

Each is settled in the phase named, and the answer is recorded in the decision log.

| # | Question | Phase |
|---|---|---|
| O1 | Which directories under `/usr/local` (including Python's) are group-writable on current Debian, Ubuntu and Raspberry Pi OS | 7 |
| O2 | Licence of the candidate header fonts (FIGlet's standard fonts are expected to be BSD-3-Clause) | 4 |
| O3 | Source for login records: `wtmp`, `lastlog`, or `lastlog2` on newer releases | 10 |
| O4 | Which sandbox directives the oldest tier-1 systemd accepts; whether unprivileged probes reach the system bus and root probes reach the Docker and fail2ban sockets inside the sandbox | 7 |
| O5 | Cache-only update counts on dnf 4 and dnf 5 without root; how to detect a pending reboot on the RHEL family | 9 |
| O6 | When PyPI with pipx becomes a documented route | after 1.0 |
| O7 | Default `python3` on openSUSE Tumbleweed; Alpine's shipped sshd config | tier-2 phase |
| O8 | Fate of the old fork: archive with a pointer, make private, or delete | 0, maintainer's call |
| O9 | Release signing beyond the build attestation | 14 |
| O10 | System-wide zsh startup file per distribution | 8 |
| O11 | Whether `timeout` can wrap the hook without disturbing the terminal, on coreutils and busybox | 8 |
| O12 | Firewall state without `CAP_NET_ADMIN` (config files and unit states for ufw, firewalld, nftables) | 11 |
| O13 | Whether pam_motd reads drop-in files with the user's rights (matters for static mode permissions) | 8 |
| O14 | Docker or Podman on the maintainer's Windows machine for local container tests | 1 |
| O15 | `-I -S` with a directory and with an archive as the program: contents of `sys.path` on Python 3.9 to 3.15 | 1 |

---

## 7. Distribution matrix

Default `python3` versions as read on 2026-11-24.

| Release | python3 | Tier | Container image | python3 in the image | Updates backend | Notes |
|---|---|---|---|---|---|---|
| Debian 12 | 3.11 | 1 | `debian:12` | no, installed in the test image | apt | |
| Debian 13 | 3.13 | 1 | `debian:13` | no | apt | |
| Ubuntu 22.04 | 3.10 | 1 | `ubuntu:22.04` | no | apt, stamp file | bundled TOML parser in use |
| Ubuntu 24.04 | 3.12 | 1 | `ubuntu:24.04` | no | apt, stamp file | |
| Ubuntu 26.04 | 3.14 | 1 | `ubuntu:26.04` | no | apt, stamp file | |
| Raspberry Pi OS (Debian 12 and 13 based) | 3.11, 3.13 | 1 | `debian:12`, `debian:13` on an arm64 runner | no | apt | no official image; 32-bit and real hardware in the verification log |
| AlmaLinux 9 | 3.9 | 1 | `almalinux:9` | yes | dnf 4 | oldest Python; bundled TOML parser in use |
| AlmaLinux 10 | 3.12 | 1 | `almalinux:10` | yes | dnf | |
| Rocky Linux 9, 10 | 3.9, 3.12 | 1, tested nightly | `rockylinux:9`, `rockylinux:10` | yes | dnf | binary-compatible with AlmaLinux |
| Fedora 44, 45 | 3.14, 3.15 | 1 | `fedora:44`, `fedora:45` | *(unverified)* | dnf 5 | newest Python |
| Arch Linux | 3.14 | 2 | `archlinux:latest` | no | pacman (`checkupdates`) | |
| openSUSE Leap 16.0 | 3.13 | 2 | `opensuse/leap:16.0` | *(unverified)* | zypper | |
| openSUSE Tumbleweed | *(unverified)* | 2 | `opensuse/tumbleweed` | *(unverified)* | zypper | |
| Alpine 3.22 to 3.24 | 3.12 to 3.14 | 2 | `alpine:3.22`, `alpine:3.24` | no | apk | musl, busybox, OpenRC, sshd without PAM |

Not supported: RHEL 8 and its rebuilds (Python 3.6), Ubuntu 20.04 (3.8), openSUSE Leap 15.6 (end of life). Debian 11 has Python 3.9 and may work, but it is not tested.

### 7.1 How each distribution is tested

Three levels. CI on GitHub Actions is the reference. Local runs need Docker or Podman; on the maintainer's Windows machine that means WSL or Docker Desktop (open item O14).

**Level 1: unit tests.**

- pytest. Python 3.11 and newer come from the runner; 3.9 and 3.10 run inside `almalinux:9` and `ubuntu:22.04`, because those are the versions users have.
- Modules are tested against fixture trees per distribution (`tests/fixtures/<distro>/proc/...`) and recorded command output.
- Includes the sanitiser corpus, the AST guards and the golden renders.
- Tests that need Linux ownership, users or groups carry a marker and run only inside a container. Their fixtures are created on the container's own filesystem, never on a mount from Windows.
- `.gitattributes` forces LF line endings for scripts and fixtures.

**Level 2: container smoke, every tier-1 image on every PR, tier 2 nightly.**

- The job builds `motp.pyz` once and mounts it into each image.
- It installs `python3` where the image lacks it.
- It runs `motp preview --demo`, `motp show`, `motp collect --no-sandbox` as root and `motp doctor`.
- It asserts: exit code 0, no traceback, no escape byte when `NO_COLOR` is set, no line wider than the requested width, every cache file with the right mode, owner and group.

**Level 3: login integration, tier 1 on every PR.**

- One test image per release, built once per workflow and cached in the project's container registry. It adds `openssh-server`, rsync, host keys, a test user and an admin user.
- The container runs under Podman with systemd as its first process, so the timer, the unit and its sandbox are exercised for real.
- After `motp install` the test logs in with `ssh -tt` and asserts:
  - the MOTD appears exactly once;
  - `ssh host true` prints no extra bytes; scp, sftp and rsync succeed;
  - with the collector unit stopped and the cache removed, login still works and shows live values;
  - `motp uninstall` leaves only the config behind.
- Visibility assertions (unprivileged user versus admin user) and the hung-plugin assertion are added by the phases that bring those features (11 and 12).
- Unit files are checked with `systemd-analyze verify`.

Raspberry Pi OS is covered by the Debian images on a native arm64 runner. 32-bit systems and real hardware are checked by hand and recorded in `docs/notes/verification-log.md`, together with the measured start-up time on a Raspberry Pi.

---

## 8. Optional software detected at runtime

| Module | Detected by | Runs as | Shipped in |
|---|---|---|---|
| `os_updates` | `/usr/bin/apt-get`, `/usr/bin/dnf`, Ubuntu's stamp file | motp | 1.0 |
| `os_reboot` | `/run/reboot-required`, RHEL-family check (O5) | motp | 1.0 |
| `os_autoupdates` | unattended-upgrades config, `dnf-automatic.timer` | motp | 1.0 |
| `os_units`, `unit` rows | `/usr/bin/systemctl` | motp | 1.0 |
| `sec_fail2ban` | `/usr/bin/fail2ban-client` | root | 1.0 |
| `sec_firewall` | ufw, firewalld, nftables (sources per O12) | root | 1.0 |
| `sec_logins` | journal or `btmp` | root | 1.0 |
| `app_containers` | `/usr/bin/docker` | root | 1.0 |
| Podman containers | `/usr/bin/podman` | root | 1.x (rootful Podman needs write locks the sandbox denies) |
| certificates | certbot's directory, config rows | root | 1.x |
| disk health | `/usr/sbin/smartctl`, `/proc/mdstat`, `zpool`, `btrfs` | root | 1.x |
| Raspberry Pi power state | `/usr/bin/vcgencmd` | motp | 1.x |

---

## 9. Features

Ranked by value for a beginner: does it reveal something they must act on, and can they act with one command.

### Must (1.0)

1. System block: host, OS, kernel, uptime, load, memory, swap, local addresses, DNS servers, disk bars.
2. Attention block on top, one line per warning with the command that fixes it.
3. Pending and security updates (apt, dnf).
4. Reboot required.
5. Failed systemd units.
6. Disk space and inode thresholds.
7. Firewall active or not.
8. Automatic security updates enabled or not.
9. End-of-life warning for the OS release, from bundled data with a visible data date.
10. The user's previous login; failed SSH logins in the last 24 hours; logged-in sessions.
11. fail2ban, Docker container states, watched services.
12. Exec plugins and config rows (`unit`, `file_age`).
13. `motp doctor`, `motp modules`, `motp preview --demo`, `motp explain`.
14. Rotating tips (off by default), English and German output.
15. Installer, uninstaller, hybrid and static mode, opt-in local terminals for bash, zsh and fish.

### Should (1.x)

16. Native `.deb` and `.rpm` packages.
17. Certificate expiry.
18. Disk health: SMART verdict, RAID, ZFS and btrfs pool state.
19. Backup age presets for restic and borg (plain file age is already a config row).
20. Temperature; Raspberry Pi undervoltage and throttling.
21. Podman containers; time synchronisation state; `--json` output.
22. Tier-2 backends: pacman, zypper, apk; snap and flatpak counts.
23. Public address (opt-in unit, cached, provider named).
24. Per-user presentation config; `motp banner` with optional pyfiglet fonts; a system-wide fish hook.
25. Installer flag to quiet the distribution's own MOTD.
26. Failed attempts on the user's own account since their previous login.

### Later

27. Network throughput averages, hotplug devices, out-of-memory kills since boot, unread root mail.
28. SSH hardening hints.
29. In-process Python plugin API.
30. Theme gallery; AUR, COPR, PPA; PyPI as `message-of-the-python`.
31. More languages.

### Rejected

- Weather, news, quotes: network calls or noise, not system state.
- Self-update and update checks over the network.
- A background daemon.
- A config row that runs a command (D10).

---

## 10. Rules for every phase

**Workflow**

- One phase is one branch (`feat/pN-short-name`) and one pull request, merged without squashing.
- Commits follow Conventional Commits with a body that says what and why. Tests ship in the commit of the code they cover.
- Each phase starts in a fresh session with only this blueprint, the decision log and the repository. The context brief of the phase is enough to start.
- After the code is written: a code review agent (opus). Phases marked "security review" also get the security-reviewer agent (opus) before merge.
- A phase has **checks** (a fresh agent can tell pass from fail) and sometimes a **gate** (a person decides).
- Decisions made during a phase go into `docs/notes/chat-log.md` the same day. Checks that need real hardware or a person go into `docs/notes/verification-log.md`.
- Long-running scripts print a status line at a fixed interval.
- Nothing is pushed, published or changed on GitHub without the maintainer's go-ahead for that step.

**Invariants, each checked in CI from the phase that introduces it**

| # | Invariant | From phase |
|---|---|---|
| 1 | No process start outside `core/proc.py`; no `shell=True`, `eval`, `exec`, `pickle` (AST test) | 1 |
| 2 | No network module imported in the package (AST test) | 1 |
| 3 | The repository contains no address outside RFC 5737 and loopback, no e-mail address outside `example.com` and the noreply domain, no secret (scan in CI and before every push) | 1 |
| 4 | `python3 -I -S` runs the demo render on Python 3.9 and on the newest tested version | 4 |
| 5 | Every user-visible string has a message id | 2 |
| 6 | `motp show` starts no process, opens no socket, imports no name-lookup module, and opens no file outside its allow-list: interpreter prefix, `/opt/motp` or the test tree, `/proc`, `/sys`, `/run/motp` (audit-hook and AST tests) | 5 |
| 7 | No `sys.path` entry of any MOTP process is writable by a non-root user or group | 7 |
| 8 | The German catalogue has no missing entry | 13 |

**Rollback:** each phase is one merge commit and can be reverted as one.

---

## 11. Phases

Model and effort name the session that executes the phase. The planning session is the only one that runs on the top-tier model.

### Dependency order

```
P0 -> P1 -> P2 -> P3 -> P5 -> P6 -> P7 -> P8 -> P9, P10, P11, P12 -> P13 -> P14
             \--> P4 --^
```

- P3 and P4 both need only P2 and touch different directories; they can run in parallel.
- P9 to P12 can run in parallel after P8. Each touches its own module files and adds one line to `modules/registry.py`.

### Phase list

| # | Phase | Model, effort | Security review |
|---|---|---|---|
| 0 | Repository bootstrap | sonnet, low | no |
| 1 | Skeleton, CI, build | sonnet, medium | no |
| 2 | Core data contracts | opus, high | yes |
| 3 | Core system contracts | opus, high | yes |
| 4 | Renderer, themes, header, demo | opus, medium | no |
| 5 | Live modules and `motp show` | sonnet, medium | no |
| 6 | Collector, probe runner, cache | opus, high | yes |
| 7 | Installer, units, doctor | opus, high | yes |
| 8 | Login hooks, static mode, login tests | opus, medium | yes |
| 9 | Package health modules | sonnet, medium | no |
| 10 | Service and login modules | opus, medium | yes |
| 11 | Security modules | opus, medium | yes |
| 12 | Exec plugins and config rows | opus, high | yes |
| 13 | German output, `motp explain`, tips | sonnet, medium | no |
| 14 | Release 1.0 | opus, high | yes |

### Phase 0: repository bootstrap

- **Context:** the old fork holds history that must not move (section 1). The new repository starts clean (D5, D6, D20).
- **Tasks:**
  1. Maintainer: log in again with `gh auth login`; decide the fate of the old fork (O8).
  2. Rename the old fork to `Message-of-the-Python-legacy`, and the local folder likewise.
  3. Create the local repository `message-of-the-python` with the noreply identity.
  4. First commit: README (what it is, target look as a text mock, credit to fedya/fastmotd), `LICENSE`, `.gitignore`, `.gitattributes`, `SECURITY.md` (GitHub private vulnerability reporting), `CONTRIBUTING.md`, `plans/`, `docs/notes/`.
  5. Create the GitHub repository; enable issues, private vulnerability reporting, secret scanning with push protection, and branch protection.
- **Check:** a fresh clone contains none of the strings from the hygiene findings (a scan script prints zero matches); the secret scan is clean; the GitHub API reports `fork: false`.
- **Model, effort:** sonnet, low. Every GitHub-side step waits for the maintainer's go-ahead.

### Phase 1: skeleton, CI, build

- **Context:** empty repository from phase 0. Layout from 4.2. Open items O14 and O15.
- **Tasks:** `pyproject.toml` (project name `message-of-the-python`, package `motp`), `src/` layout, `motp version`, ruff, mypy and pytest configuration with the Linux-only marker, the deterministic build script (4.12), the AST guard tests (invariants 1 and 2), the repository scan (invariant 3), GitHub Actions for lint, unit tests (3.11 and newer on the runner, 3.9 and 3.10 in containers) and a first container job, actions pinned by hash, read-only token, `run` commands `test`, `lint`, `build`.
- **Check:** CI is green; `python3 -I -S dist/motp.pyz version` prints the version inside `debian:12` and `almalinux:9`; two builds on different runners give the same hash; a test prints `sys.path` under `-I -S` for the archive and for an unpacked directory on every tested Python version and asserts its expected shape.
- **Model, effort:** sonnet, medium.

### Phase 2: core data contracts

- **Context:** sections 4.4, 4.5, 5.5, D19, D34. Pure logic, no system access.
- **Tasks:** data model, sanitiser with its corpus, threshold rules, probe document validation (built-in and plugin forms), cache schemas with the bounded reader, message catalogue with English entries, the `{name}` substitution, plural handling, the build step that compiles catalogues, the hint table, ADR-0001 (architecture) and ADR-0002 (probe protocol and message contract).
- **Check:** unit tests pass on 3.9 and newest; every class of character listed in 5.5 is covered by a corpus test; documents with `NaN`, 1 MiB size, deep nesting, catalogue ids in plugin form or a `command` field are rejected; a template with attribute or index access in a parameter renders as literal text; invariant 5 holds.
- **Model, effort:** opus, high. Security review.

### Phase 3: core system contracts

- **Context:** sections 4.7, 4.9 (the `proc.py` rules), D9, D23, threats T1 to T3 and T21.
- **Tasks:** ownership-chain check including interpreter lines, `core/proc.py` (argument lists, absolute paths, user and group drop, clean environment, limits, read deadline, group kill and per-user cleanup), config loader with the bundled parser and validation, `motp config check`, `motp config init` with the commented starter file.
- **Check:** inside a container as root: a child started by `proc.py` reports the target user, the target group and no supplementary groups; a child that leaves its process group is gone after cleanup; ownership tests refuse a group-writable parent, a symlinked directory and a foreign owner; `motp config check` names file, key and expected type for a wrong value.
- **Model, effort:** opus, high. Security review.

### Phase 4: renderer, themes, header, demo

- **Context:** sections 4.6 and D14 to D17. Input is the data model from phase 2; no system access. Open item O2.
- **Tasks:** view model, four width classes, Unicode and ASCII themes, colour levels, dotted labels, frames, bars, attention block with hints from the table, markers without colour, FIGfont reader with bundled font, its licence file and the too-wide fallback, `motp preview --demo` with fixed demo data.
- **Check:** golden files match for widths 80, 70, 50 and 30 in both charsets with and without colour; `NO_COLOR=1` output contains no escape byte; no line exceeds the width; a 40-character hostname produces no header and no overflow; invariant 4 holds.
- **Gate:** the maintainer approves a screenshot of the demo, after a design second opinion from other model families on that screenshot.
- **Model, effort:** opus, medium.

### Phase 5: live modules and `motp show`

- **Context:** D22, D31, 4.14. Renderer from phase 4, cache reader from phase 2.
- **Tasks:** `hw_load`, `hw_memory`, `os_uptime` from `/proc`, the render deadline with `os._exit`, `show` with and without cache files, `--login` and `--debug`, lazy imports on the render path, invariant 6.
- **Check:** in `debian:12` and `almalinux:9`, `motp show` prints the system block from live values and from a fixture cache; the median of 20 runs, measured inside the container from an unpacked and compiled tree, stays under 300 ms; a module patched to sleep ends at the deadline with exit code 0 and no output; a cache path that is a FIFO or a symlink is ignored without delay.
- **Model, effort:** sonnet, medium.

### Phase 6: collector, probe runner, cache

- **Context:** D21, D32, sections 4.4 (scheduling and ageing), 4.9, 4.14 and threats T8, T12, T23.
- **Tasks:** probe runner (one process per probe, pool, time limits, total budget, lock, intervals, stale and expired items), the cache writers for `public.json`, `admin.json`, `render.json` and per-user files, the state file, `motp collect --no-sandbox`, `motp modules`, modules `os_host`, `net_addresses`, `hw_disks`, a test harness that creates the two system users, a test user and an admin group inside the container.
- **Check:** as root in a container, `motp collect --no-sandbox` writes each cache file with the mode, owner and group from 4.1; a probe that sleeps is killed and the run ends inside the budget; hostile probes (escape sequences, 1 MiB output, `NaN`, an open pipe held by a descendant, a fork bomb) leave every cache file clean and the run bounded; after the cache directory is emptied, the next run restores every module's items; `motp show` renders Host and Disks from the cache.
- **Model, effort:** opus, high. Security review.

### Phase 7: installer, units, doctor

- **Context:** sections 4.11, 4.12, D24, D31, D33; open items O1 and O4; threats T2, T24, T25.
- **Tasks:** `motp install` and `uninstall` with manifest, `--dry-run` and `--no-start`, unpack and bytecode, the two system users, admin-group selection, units with the sandbox and the per-module table, cron fallback, `motp collect` starting the unit, `motp doctor`, invariant 7, the systemd test images.
- **Check:** on every tier-1 image under Podman with systemd: after `motp install` the timer produces the cache files within two minutes; `systemd-analyze verify` is clean; the exposure score of `systemd-analyze security motp-collect.service` is at most 3.0, or each directive that prevents it is listed with its reason; invariant 7 passes; an existing foreign `motp` account stops the installer; `motp uninstall` leaves only the config, and with a tampered manifest it deletes nothing outside its prefixes.
- **Model, effort:** opus, high. Security review.

### Phase 8: login hooks, static mode, login tests

- **Context:** sections 4.10, D7, D8, D29; open items O10, O11, O13; threats T4, T5, T20.
- **Tasks:** hooks for sh and zsh, `motp shell-init` for bash, zsh and fish, static mode with its unit addition, the level-3 test images with sshd.
- **Check:** the level-3 assertions of section 7.1 pass on every tier-1 image; in static mode the file under `/run/motd.d` contains no escape byte and none of the admin fixture details, and one SSH login prints it once; a non-interactive `bash -c`, `zsh -c` and `fish -c` with the rc snippets installed print nothing.
- **Model, effort:** opus, medium. Security review.

### Phase 9: package health modules

- **Context:** D28, O5. Modules `os_updates`, `os_reboot`, `os_autoupdates`, `os_eol` with hint entries for apt and dnf.
- **Tasks:** the four modules, fixtures captured from each tier-1 image, the bundled end-of-life table with its data date.
- **Check:** fixture tests per distribution; in the `debian:12` login image, creating `/run/reboot-required` and waiting for one collector run makes the attention block show the reboot line; the modules run under the unit's sandbox without a denied network attempt in the journal.
- **Model, effort:** sonnet, medium.

### Phase 10: service and login modules

- **Context:** D32, O3, section 5.4. Modules `os_units`, `os_sessions`, `os_login`, and the `unit` row.
- **Tasks:** the modules and row, fixtures, the decision on the login-record source, per-user files for accounts with recent logins.
- **Check:** in the login image a deliberately failing unit appears as a count for the unprivileged user and by name for the admin user; user A's per-user file is unreadable for user B; the previous-login line of a second login shows the first login's time; a fixture record whose host contains escape bytes renders inert.
- **Model, effort:** opus, medium. Security review.

### Phase 11: security modules

- **Context:** D12, section 5.4, O12. Modules `sec_logins`, `sec_fail2ban`, `sec_firewall`, `app_containers`.
- **Tasks:** the four modules as root probes, fixtures, the visibility assertions in the level-3 tests.
- **Check:** with fixtures for bans, containers and failed logins, the unprivileged user's SSH output contains counts and none of the fixture addresses or names; the admin user's output contains them; attempted user names appear in no cache file; the unit's capability set after this phase matches the table in 4.11.
- **Model, effort:** opus, medium. Security review.

### Phase 12: exec plugins and config rows

- **Context:** D10, D26, D27, sections 4.4 and 4.9, threats T7, T9, T21, T23.
- **Tasks:** plugin discovery and validation, both output forms, key namespacing and the fixed prefix, the `file_age` row, `docs/plugins.md`, example plugins in shell and Python, the hung-plugin assertion in the level-3 tests.
- **Check:** the three-line shell example renders a row for the admin user and nothing for the unprivileged user; a plugin with a wrong owner, mode or interpreter is refused and named by `motp doctor`; a plugin reports user `motp-plugin` unless the config grants root; a plugin that prints escape sequences, a built-in key or a catalogue id renders as prefixed inert text; with a plugin that sleeps 60 seconds installed, the time to the SSH prompt stays within 0.5 seconds of the baseline.
- **Model, effort:** opus, high. Security review.

### Phase 13: German output, `motp explain`, tips

- **Context:** D19. All modules exist, so the string set is complete.
- **Tasks:** German catalogue, `motp explain` entries for every label and warning, tips list, invariant 8.
- **Check:** with `LANG=de_DE.UTF-8` the demo render matches its German golden file; `motp explain load` prints the explanation in both languages; the catalogue check reports no missing entry; plural forms render correctly for 0, 1 and 2 in both languages.
- **Model, effort:** sonnet, medium.

### Phase 14: release 1.0

- **Context:** D13, threats T15 and T16, open item O9.
- **Tasks:** release workflow (tag, build, checksums, attestation), README with verify and install steps and a generated demo screenshot, `SECURITY.md` final, tier-2 nightly smoke jobs, a full security review against section 5, the real-hardware verification log (a Raspberry Pi and one server).
- **Check:** a release candidate tag produces the three artefacts, and a rebuild on a second machine matches the hash; on a fresh Debian 13 and a fresh AlmaLinux 10 machine, the README's commands, typed as written, end with: an SSH login that shows the MOTD once, `ssh host true` printing nothing extra, and `motp doctor` reporting no error; every threat in 5.3 has a passing test or a recorded acceptance in the decision log.
- **Gate:** the maintainer publishes the release.
- **Model, effort:** opus, high. Security review.

### After 1.0

| Phase | Content | Model, effort |
|---|---|---|
| 15 | `.deb` and `.rpm` packages built in CI | sonnet, medium |
| 16 | certificates, disk health, backup presets, temperature and Raspberry Pi power state | sonnet, medium |
| 17 | tier-2 backends and hooks (pacman, zypper, apk, OpenRC), Podman | sonnet, medium |
| 18 | public-address unit, per-user presentation config, `--json`, `motp banner`, installer flag for the distribution MOTD | opus, medium, security review |

---

## 12. Review record

Two independent reviews ran on the first draft on 2026-11-24, both on opus: a security review of the threat model and the plugin design, and an architecture review of feasibility and the phase plan. Every finding is resolved in this document or listed as open.

### 12.1 Security review

| Id | Severity | Finding | Resolution |
|---|---|---|---|
| S1 | high | Isolated mode still loads site directories; on Debian one of them can be writable by `staff`, and sudo's path can pick a replaceable wrapper | D23, D24, T2, invariant 7: `-I -S`, no path under `/usr/local`, wrapper only on a root-only chain |
| S2 | high | The privilege drop kept group 0; missing and unexplained capabilities; static mode could not write under a strict sandbox; inherited memory rule breaks JIT plugins | 4.9 (all three ids always set, tested), 4.11 (capability list with reasons, per-module table), plugin docs |
| S3 | medium | A plugin could escape its process group and interfere with built-in probes of the same user | D21: separate user `motp-plugin`; 4.9 cleanup of leftover processes |
| S4 | medium | A plugin could reuse built-in ids and keys or supply a command | D34, 4.4: namespaced keys, literal text only, fixed prefix |
| S5 | medium | The interpreter of a plugin was not checked | 4.9, T21 |
| S6 | medium | The login path could still block: config on remote storage, name lookups, special files, work before the timer is armed | D22, 4.14, T4, invariant 6; O11 for the `timeout` wrapper |
| S7 | medium | Sanitiser specification incomplete | 5.5 |
| S8 | medium | Collected text could reach a format template | 4.4, T22 |
| S9 | medium | Mount points, last login and the admin-group fallback disclosed too much | T26, 5.4, D32, D33 |
| S10 | medium | An existing `motp` account would be adopted | 4.12 step 3, T24 |
| S11 | medium | No resource limits for probes and plugins | 4.9, 4.11, T23 |
| S12 | medium | A manual `collect` ran outside the sandbox with the admin's environment | 4.11 |
| S13 | low | Uninstall trusted its manifest | 4.12, T25 |
| S14 | low | Static mode content not specified | 4.6 |
| S15 | low | Supply-chain claims overstated | 4.12, T15 |

Corrections of fact from that review, applied: the wording about unkillable processes (D22), the limits of the render timer (4.14), what blocks IP traffic (4.11), and the unverified note on how pam_motd reads files (2.4, O13).

Accepted as residual risk: see 5.6.

### 12.2 Architecture review

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | blocker | No bytecode cache for code in an archive makes the start-up target unrealistic | D31; phase 5 measures from the compiled tree; Raspberry Pi number in the verification log |
| 2 | blocker | Per-user login data had no place to live | D32, 4.4, phase 10 on opus |
| 3 | blocker | Several phase checks needed later phases | section 11 reordered: cache reader in phase 2, linear order to phase 8, feature assertions moved to phases 11 and 12 |
| 4 | should-fix | Sandbox gaps for firewall, static mode, JIT plugins | 4.11 table, O12, plugin docs |
| 5 | should-fix | Interval, staleness and state rules undefined | 4.3 (`max_age`), 4.4 scheduling and ageing |
| 6 | should-fix | Message contract incomplete | 4.4, 4.6, phase 2, invariants 5 and 8 |
| 7 | should-fix | Free-text hint command contradicted the threat model | D34 |
| 8 | should-fix | Shell marker and throttle contradicted D8 | 4.10, D8 |
| 9 | should-fix | No table of modules, sections and phases; orphan commands | 4.3 table, 4.13 |
| 10 | should-fix | Static mode unspecified | 4.6 |
| 11, 12 | should-fix | First collect ran unsandboxed; probe command assumed an installed path | 4.12 step 9, 4.3 |
| 13 | should-fix | Build not deterministic as described | 4.12 |
| 14 | should-fix | Audit-hook test needed an allow-list | invariant 6 |
| 15 to 18 | should-fix | Test strategy: systemd in containers, arm64, old Python versions, Windows | 7.1 |
| 19 | should-fix | Two phases too large | split into phases 2 and 3, and 7 and 8 |
| 20 | should-fix | Checks that needed judgement | gates separated from checks; thresholds set |
| 21 to 23 | nit | Character widths and header overflow; deadline handler; sudo path on the RHEL family | D14, D15, 4.6, 4.14, D24 |

Scope cuts suggested by that review and applied to the planner's own additions (not to D18 or D19): the `command` row, Podman, `motp banner`, the system-wide fish hook, the throttle setting, Rocky Linux in the per-PR matrix. The per-user previous login stays in 1.0, as the maintainer confirmed "last and failed logins" in the interview; "failed logins since then" became a system-wide count over 24 hours, with the per-account variant listed under Should.

# Decision log

Newest topic on top. Entry types: `decision`, `spec`, `deviation`, `issue`, `note`.
The full reasoning, with every rejected option, is in `plans/motp-blueprint.md` section 3 (D1 to D34).

## 2026-11-24 · Revival plan (blueprint session)

### decision · Phase list P0 to P14 confirmed

The maintainer confirmed the phase list of blueprint section 11 as shown, including the two deviations named with it: failed logins as a system-wide count over 24 hours, and Podman, `motp banner` and the system-wide fish hook moved to 1.x. The confirmation covers the plan, not any action on GitHub: renaming the old fork, creating the new repository and every push still need their own go-ahead in phase 0. The fate of the old fork (open item O8) is not decided yet.

### decision · Rewrite from an empty tree, keep the ideas (D1)

About 60 of the 950 lines from 2021 do real work; the rest uses `shell=True`, imports every `.py` file it finds, and the disabled stubs are upstream code without a licence. The data scheme (value plus threshold rule), the module prefixes, the target look and the single error notice carry over. Rejected: evolving the code in place, and porting the two working scrapers line by line.

### decision · Tier 1 is the Debian and RHEL families; Python 3.9 or newer (D2, D3)

Tier 1 (Debian, Ubuntu, Raspberry Pi OS, AlmaLinux, Rocky Linux, Fedora) blocks every PR; Arch, openSUSE and Alpine are tier 2 and tested nightly. Python 3.9 is the default on AlmaLinux and Rocky 9, so it is the floor. Rejected: all six families in tier 1 (Alpine's missing PAM and systemd would delay 1.0), Debian only, Python 3.11 (locks out two common server releases) and Python 3.6.

### decision · Licence stays GPL-3.0-or-later (D4)

No change to the terms the project has been published under since 2020. Stand-alone plugin executables are separate programs. Rejected: MIT and Apache-2.0.

### decision · New standalone repository `message-of-the-python`, noreply commit identity (D5, D6, D20)

The old fork's pushed history contains a personal e-mail address, a screenshot with upstream's real host and address, and private-network addresses. The rewrite starts in a fresh repository with a clean history; the old fork is renamed first and then archived, made private or deleted by the maintainer. Rejected: detaching the fork with or without a history rewrite, staying a fork, the names `motp` (taken on PyPI) and `Message-of-the-Python` (differs only in case).

### decision · Hybrid login model: root timer collects, the user's shell renders (D7)

A sandboxed root timer writes a cache; a `profile.d` hook renders at login as the logging-in user. No root code runs because of a login. Static mode (finished text for pam_motd) stays available as a setting. Rejected: static text only, and live collection as root through `update-motd.d` (Debian-only, blocks login, fires for scp and sftp).

### decision · Local terminals are opt-in per user and show in every new shell (D8)

`motp shell-init` prints a snippet for the user's own rc file. The maintainer chose "every new shell" over the recommended throttle; a `min_interval` setting with default 0 remains. Rejected: system-wide by default, login shells only.

### decision · TOML config with a bundled fallback parser (D9)

`tomllib` on Python 3.11 and newer, a vendored copy of tomli on 3.9 and 3.10. Config is data only. Rejected: INI, JSON, YAML.

### decision · Extensions are exec plugins and config rows (D10)

Third parties add an executable to a root-owned directory; common cases are config rows. Built-in modules stay inside the package. Rejected: Python drop-in modules, both models at once, pip entry points. An in-process Python API may follow after 1.0.

### decision · Auto-enable detected software; two visibility tiers (D11, D12)

Optional modules default to `auto`. Everyone sees counts and states; details go to a cache file readable by root and one admin group. Rejected: asking at install, core only, counts only, details for everyone.

### decision · Install from a release zipapp that installs itself (D13)

One `motp.pyz` per release with checksums and a build attestation; `sudo python3 motp.pyz install`. Rejected for the first release: native packages, PyPI with pipx, git clone plus a script.

### decision · Layout: Unicode when the locale supports it, built-in header font, adaptive widths, markers without colour (D14 to D17)

The maintainer chose Unicode frames over the recommended ASCII default; `charset = "ascii"` and `MOTP_CHARSET` override. Four width classes replace a fixed 80 columns. Without colour, `[!]` and `[!!]` mark warnings.

### decision · Scope of 1.0 is the wider cut; helpers are `motp explain`, tips and German output (D18, D19)

Firewall state, automatic security updates and the end-of-life warning join the must-have list. A status line on top was offered and not selected. German output from 1.0 means every user-visible string is a message id from phase 2 on.

### decision · Planner's design choices (D21 to D34)

One process per probe, with the unprivileged users `motp` (built-in probes) and `motp-plugin` (plugins). The login path reads its program files, `/proc`, `/sys` and `/run/motp`, and nothing else: no `/etc/motp`, no name lookups. Every interpreter runs as `python3 -I -S`. The only optional package in 1.0 is python3-apt; pyfiglet and cryptography are candidates for 1.x. The collector never uses the network, plugin output is admin-only until made public, MOTP never refreshes package metadata, the distribution's own MOTD is left alone, and there is no per-user config file in 1.0. The installed form is an unpacked, precompiled tree under `/opt/motp`. Rejected alternatives are listed with each decision in the blueprint.

### decision · Security review findings resolved in the design (S1 to S15)

An opus security review of the first draft found two high and ten medium issues; none gave an ordinary local user a route to root. The high ones: isolated mode still loads site directories that the group `staff` can write on Debian, and the privilege drop kept group 0. Resolutions are `-I -S` with no path under `/usr/local`, user, group and supplementary groups always set together, a second system user for plugins with cleanup of leftover processes, hints selected by id from a fixed table, an interpreter check for plugins, per-user files for login data, an admin group fixed at install time and never `adm`, and resource limits. The full table is section 12.1 of the blueprint.

### decision · Architecture review findings resolved (23 findings, 3 blockers)

The blockers were: no bytecode cache for code run from an archive (now an unpacked, compiled tree, D31), no place for per-user login data (D32), and phase checks that depended on later phases (phases reordered to a linear chain up to phase 8, two large phases split, now P0 to P14). Rejected on that review's advice: a `command` config row, a throttle setting for local terminals, and running the archive at login.

### spec · Failed logins are a system-wide count over 24 hours

The interview wording was "last login and failed SSH logins since then". Per-user "since then" needs per-account journal queries; 1.0 shows the user's previous login from a per-user file and a system-wide count of failed SSH logins in the last 24 hours. Failed attempts on the user's own account since their previous login are listed under Should.

### deviation · Planner's additions cut from 1.0 after review

Podman support, `motp banner` with pyfiglet fonts and a system-wide fish hook move to 1.x. Docker, the built-in header font and `motp shell-init fish` stay in 1.0. Rocky Linux is tested nightly instead of on every PR because it is binary-compatible with AlmaLinux.

### issue · Old fork keeps the hygiene findings public

Until the maintainer archives, hides or deletes the old fork, its history still shows the items listed above. Tracked as open item O8 in the blueprint.

### note · Upstream changed under the fork

`fedya/fastmotd` was rewritten in Go in March 2026 and has no licence file; its Python script never carried a licence line. Nothing from upstream is reused.

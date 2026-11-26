# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| 1.0.x (from 1.0.0rc1) | yes |
| anything older (the 2019 to 2021 script) | no; it is a different program |

Fixes go into the newest 1.0.x release. There is no self-update: upgrade by running `install` from
the new archive.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: open the **Security** tab of this repository
and choose **Report a vulnerability**. Do not open a public issue and do not post details publicly
before a fix is released. There is no e-mail address for reports.

Please include the MOTP version (`/opt/motp/bin/motp version`), the distribution and release, and
what an attacker needs (an account on the machine, control of a host name, a plugin the admin
installed, ...). You should get a first answer within two weeks.

## In scope

- Anything that lets someone without root gain root, change what root runs, or read what only
  root or the admin group may read, through MOTP.
- A login that MOTP delays, blocks or breaks, including `scp`, `sftp`, `rsync` and `ssh host cmd`.
- Text that reaches a terminal with a working escape or control sequence, or a fake row or command,
  from a host name, a login record, a container, a plugin or any other outside source.
- The collector reaching the network.
- The installer or uninstaller writing, adopting or deleting something it should not.
- The release archive, its checksum, its attestation and the workflows that build them.

Out of scope: what a plugin does that the admin installed with `run_as = "root"` (it is root by the
admin's choice; see below), what root or members of groups that are root-equivalent by the
distribution's design (`docker`, Debian's `staff`) can do anyway, and systems without systemd,
where MOTP runs without a sandbox by design.

## Trust model

| Who | Can | Cannot |
|---|---|---|
| **root** | everything; installs MOTP, writes `/etc/motp`, installs plugins and chooses which run as root | |
| **the admin group** (`sudo` or `wheel`, fixed at install; never `adm`) | read `admin.json`: names, addresses and failure reasons on the screen | change config, plugins or the program |
| **a plugin author** (code the admin installed in `/etc/motp/plugins.d`) | print rows for admins (or for everyone, if the admin sets `visibility = "public"`) and a hint text | supply a command, a message id or a built-in key; reach the network; write MOTP's files; outlive its time limit; run as root unless the config grants it by name |
| **an unprivileged user** | read the public rows and their own previous login; read the program and the public cache | see admin details or another user's login; change anything root reads or runs; make the collector or a login hang |
| **a remote party without an account** | influence strings that reach the screen: a client's host name, the source of a failed login, a banned address, container and image names | get an escape sequence, a fake row or a fake command onto a terminal; get an attempted user name stored anywhere |

Rules that hold this up:

- Every file root reads or runs, and every directory above it, must belong to root and be writable
  by root alone; links are followed only where root owns them, and the resolved path is what is
  opened or run. A file that fails is ignored and named by `motp doctor`.
- No shell anywhere: programs are started by absolute path with an argument list, a fresh
  environment, resource limits and a deadline, from one module (`core/proc.py`). Config values are
  data; none is evaluated or passed to a shell.
- Every MOTP interpreter runs as `python3 -I -S` (no user site, no site directories, no
  environment). The program lives in `/opt/motp`; `/usr/local` is used only for a convenience link,
  and only when root alone can write there. Root starts a system program that is a Python script
  (fail2ban's client) or a root plugin in Python only if every directory its interpreter imports
  from, every `.pth` file there and every directory such a file adds is root's alone; otherwise
  the row says "not checked" and `motp doctor` names the directory.
- The login path (`motp show --login`, run by the login hook as the user) starts no process, opens
  no socket, resolves no name and reads only `/opt/motp`, `/proc`, `/sys` and `/run/motp`, under a
  one-second deadline and an outer `timeout` in the hook.
- One sanitiser strips control characters, escape sequences, bidi and zero-width characters, frame
  characters and look-alike runs from every outside string, when the collector accepts it and
  again when the renderer reads the cache. Names collected from the system also lose
  right-to-left letters, so a terminal with bidi support cannot reorder a row around them. Only the theme code writes escape sequences, from
  validated config values.
- Commands shown beside warnings come from a fixed table in the program, selected by id. Plugins
  cannot supply them.
- The config tree is created readable by everyone (`/etc/motp` 0755, `config.toml` 0644). Admins who
  want plugin code, root grants and watched paths private can make it root's alone (recommended
  modes in [`docs/plugins.md`](docs/plugins.md#keeping-plugins-and-the-config-private)); `motp
  install` never widens a mode an admin made stricter.
- Cache files: `public.json` and `render.json` 0644, `admin.json` 0640 with the admin group,
  per-user files 0400 root with a read ACL for that one user, the state directory 0700; written
  with exclusive, no-follow opens and renamed into place.

## Hardening of the collector unit

`motp-collect.service` runs once every five minutes from a timer, as root, with:

- `ProtectSystem=strict`, `ReadOnlyPaths=/run` with only `/run/motp` writable (and `/run/motd.d`
  in static mode), `ProtectHome=read-only`, 16 MiB private `/tmp` and `/var/tmp`,
  `PrivateDevices`, `PrivateIPC`;
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK` and `IPAddressDeny=any`: no network;
- `CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL CAP_CHOWN` (dropping to the probe users,
  ending their leftovers, the group of `admin.json`), `NoNewPrivileges`, `RestrictSUIDSGID`;
- `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, `LockPersonality`,
  `RestrictNamespaces`, `RestrictRealtime`, `ProtectKernelTunables`, `ProtectKernelModules`,
  `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`;
- `TasksMax=128`, `MemoryMax=256M`, `TimeoutStartSec=90`, `KillMode=control-group`, `UMask=0077`.

`systemd-analyze security motp-collect.service` scores it 2.4; every item it still flags is listed
with its reason in `src/motp/install/units.py` (`KEPT_EXPOSURE`). Each check runs in its own
process as `motp` (or as root for the few that must), and each plugin in a transient unit of its
own as `motp-plugin` with `PrivateNetwork`, a read-only `/run`, MOTP's directories hidden, its own
`/tmp`, 64 tasks and 128 MiB.

## The release

Releases are built by the repository's release workflow from a version tag on `main`, with every
action pinned by commit hash and a token that can write only in the job that creates the draft.
The archive is reproducible byte for byte; each release carries `SHA256SUMS` and a GitHub build
attestation, and the README shows how to check both before installing.

What the attestation proves: GitHub signed (with Sigstore, no long-lived key) that this exact
file was built by `.github/workflows/release.yml` of this repository, running for the tag you
name with `--source-ref`. What it does not prove: that the code at that tag was reviewed, or that
the workflow file at that tag is the reviewed one, since the workflow runs from the tagged commit.
A ruleset restricts creating `v*` tags to the maintainer, and the workflow refuses a tag whose
commit is not on `main`; a compromised maintainer account could still publish a bad release with
a matching checksum and attestation. Rebuilding the tag yourself (`python3 tools/build_pyz.py`
gives the same SHA-256) checks the file against the source you can read.

Every threat, with the test or decision that covers it, is listed in
[`docs/threats.md`](docs/threats.md).

# Writing a plugin

A plugin adds rows of your own to the message of the day: the state of a backup, a queue
length, a certificate, anything a small program can find out. It is an executable file in
any language. It prints one line of text, or one JSON document, and MOTP shows the result
in the **Plugins** section, every row marked with `[plugin <name>]`.

This page is the whole contract. Read the checklist at the end before you install a plugin
on a machine other people log in to.

## Your first plugin

Three lines of shell (`examples/plugins/50-hello`):

```sh
#!/bin/sh
# One line of text; the exit code is the status: 0 ok, 1 warning, 2 critical, 3 unknown.
echo "Hello from a plugin"
```

It is in the repository as `examples/plugins/50-hello`. Without a clone, write the three lines
into a file named `50-hello` in any directory of yours (`nano 50-hello`, or a `cat > 50-hello`
here-document), or fetch it from the release's source: `curl -fLO
https://raw.githubusercontent.com/Hiroyugane/message-of-the-python/v1.0.0rc1/examples/plugins/50-hello`.

Install it as root, owned by root and writable by root only:

```sh
sudo install -o root -g root -m 0755 50-hello /etc/motp/plugins.d/50-hello
sudo /opt/motp/bin/motp collect      # run the collector now instead of waiting 5 minutes
sudo /opt/motp/bin/motp doctor       # lists the plugin, the user it ran as, and the result
```

Log in again as a member of the admin group, or run `motp`, and the Plugins section shows
a row that starts with `[plugin 50-hello]` and says `Hello from a plugin`.

Users outside the admin group do not see it: plugin rows are admin-only until you say
otherwise (see [Who sees the rows](#who-sees-the-rows)).

## Where plugins live

- **Directory:** `/etc/motp/plugins.d/`. It must belong to root and be writable by root
  only, and so must every directory above it. If it is not, no plugin in it runs.
- **Name:** two digits, a dash, then lower-case letters, digits, `-` or `_`:
  `50-backup`, `70-mail_queue`. At most 48 characters. The digits set the order.
  Any other name (`README`, `50-backup.sh`, `50-backup.dpkg-old`, `backup`) is ignored and
  listed by `motp doctor` as ignored.
- **Number:** the first 32 names that match, by name, are looked at; any further ones are refused
  and listed by `motp doctor` only.
- **The file** must be a regular file (or a link that root owns, to such a file), owned by
  root, not writable by its group or others, executable, and not setuid or setgid.
- **The first line** is `#!` with an absolute path (`#!/bin/sh`, `#!/usr/bin/python3 -I`),
  or the file is a compiled program (ELF). The interpreter on that line must pass the same
  ownership check, so `#!/home/alice/bin/python` is refused. A file without either is
  refused: the kernel would hand it to a program nobody checked. An argument after the
  interpreter may be a plain option (`-I`, `-e`); one that names a path must pass the same
  check, and one with a `/` or `=` inside an option (`-I/tmp`, `-Xkey=value`) is refused.

### Keeping plugins and the config private

`motp install` creates `/etc/motp`, `conf.d` and `plugins.d` as 0755 and a new `config.toml` as
0644, so every local user can read the config (root grants, watched paths) and the plugins'
code. That is safe (nobody but root can change them) but often more than needed. Stricter
modes work, and `motp install` keeps them on every upgrade: it never widens an existing
directory's mode, it only removes bits beyond 0755.

| Path | Recommended | Why it still works |
|---|---|---|
| `/etc/motp` | `0711 root:root` | users and `motp-plugin` may pass through but not list it |
| `/etc/motp/config.toml`, `conf.d/` and its files | `0600` / `0700`, root's | only the collector (root) reads the config |
| `/etc/motp/plugins.d` | `0710 root:motp-plugin` | `motp-plugin` may reach its plugins, nobody else may look in |
| a plugin that runs as `motp-plugin` | `0750 root:motp-plugin` | its user may read and run it; it stays root's and not group-writable |
| a plugin with `run_as = "root"` | `0700 root:root` | root runs it |

```sh
sudo chmod 0711 /etc/motp
sudo chmod 0600 /etc/motp/config.toml
sudo chmod 0700 /etc/motp/conf.d
sudo chgrp motp-plugin /etc/motp/plugins.d /etc/motp/plugins.d/50-hello
sudo chmod 0710 /etc/motp/plugins.d
sudo chmod 0750 /etc/motp/plugins.d/50-hello
```

With these modes `motp doctor` and `motp config check` read the config only when run with
`sudo`; as an ordinary user `motp doctor` says "only root can read /etc/motp" instead of
reporting problems.

MOTP checks all of this before every run, and once more right before the plugin starts.
A plugin that fails a check never runs; `motp doctor` names it and says why:

```
[warn] plugin 50-backup: refused, it does not run: /etc/motp/plugins.d/50-backup is writable by users other than root
```

## What a plugin prints

### The line form

Print one line. The exit code is the status:

| Exit code | Status |
|---|---|
| 0 | ok |
| 1 | warning |
| 2 | critical |
| 3 | unknown |

Only the first line counts, and anything after a `|` on it is dropped (the performance
data of monitoring plugins). Any other exit code, or a plugin that is killed, counts as a
failure (see [When a plugin fails](#when-a-plugin-fails)).

Plugins written for Nagios, Icinga or similar monitoring systems usually work unchanged.

### The JSON form

When the output starts with `{`, it is read as one JSON document
(`examples/plugins/60-load-trend`):

```json
{
  "api": 1,
  "items": [
    {
      "key": "age",
      "label": {"text": "Backup", "i18n": {"de": "Sicherung"}},
      "value": 7200,
      "unit": "seconds",
      "status": "ok",
      "text": {"text": "last run complete", "i18n": {"de": "letzter Lauf vollständig"}},
      "hint": "Check the backup job's log in /var/log/backup.",
      "detail": [{"key": "size", "label": "Size", "value": 1073741824, "unit": "bytes"}]
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `api` | yes | always `1` |
| `module` | no | the plugin's file name; if given, it must match |
| `items` | yes | at most 32 rows |
| `key` | yes | a name for the row: letters `a-z`, digits, `-`, `_`, up to four parts joined by dots. MOTP turns it into `plugin.<name>.<key>`, so it never clashes with a built-in row |
| `label` | no | the row's label: a string, or `{"text": ..., "i18n": {"de": ...}}` with translations by language code |
| `value` | no | a number, a string, `true`/`false`, or `null` |
| `unit` | no | `count`, `bytes`, `percent`, `ratio`, `seconds`, `timestamp`, `celsius`, `text` (the default) or `bool`; the renderer formats the value by it |
| `status` | no | `ok`, `warn`, `crit` or `unknown` |
| `rule` | no | instead of `status`: the name of a threshold rule from the config (`[thresholds.<name>]`); MOTP classifies `value` with it |
| `text` | no | a sentence shown with the value: a string, or `{"text": ..., "i18n": {"de": ...}}` like `label` |
| `hint` | no | a sentence shown under a warning, as `text`; it is shown as "Plugin hint: ...", never as a command |
| `visibility` | no | `public` or `admin`; only used when the admin made the plugin public |
| `detail` | no | up to 16 extra rows (`key`, `label`, `value`, `unit`, `visibility`), admin-only by default |

The document may be at most 64 KiB, strings at most 1,024 characters. JSON with `NaN`,
repeated keys, unknown fields or a wrong type is refused as a whole, and the plugin
counts as failed for that run. The exit code must be 0 to 3 in this form too.

### Everything a plugin prints is treated as untrusted

MOTP is shown at every login, sometimes to root, so plugin output can never act on the
terminal or pass for something else:

- Escape sequences, control characters, bidirectional overrides, invisible characters
  and invalid UTF-8 are removed or replaced before anything is stored or shown. A plugin
  cannot colour, move the cursor, change the window title or ring the bell.
- No line is wider than the terminal. A row or attention line that does not fit wraps at
  its spaces, and every further line starts with `(plugin)` (`(Plugin)` in German), one
  step deeper; a single word too long for its line is cut. The text holds no line breaks
  of its own, so a plugin can neither start a line nor remove the mark. Box-drawing
  characters are replaced, so a value cannot draw a frame of its own.
- Every row carries `[plugin <name>]`, in the Plugins section and in the attention block.
  A plugin cannot look like a built-in row.
- Labels, texts and hints are plain text, never templates and never message ids.
  `"label": "label.updates"` shows the words `label.updates`. A field such as
  `{"id": ...}` refuses the document.
- A plugin cannot suggest a command. MOTP shows commands only from its own fixed table,
  for its own rows. A `command` field anywhere refuses the document; a hint is shown as a
  sentence, under the plugin's name.

## How a plugin runs

On systems with systemd the collector runs in a sandboxed unit, and every plugin runs in a
short-lived unit of its own (`motp-plugin-<name>.service`, started with `systemd-run`).
Without systemd (cron) the time, output and resource limits still apply; the rest of the
table does not, and plugins share the system's `/tmp`.

| | |
|---|---|
| **When** | every collector run (every 5 minutes, and at boot), after the built-in modules, one plugin at a time |
| **User** | `motp-plugin`, a system account without a home, a shell or supplementary groups; root only when the config says so (below) |
| **Program** | the file's real path, without a shell |
| **Arguments** | none |
| **Standard input** | `/dev/null` |
| **Working directory** | `/` |
| **Environment** | `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C.UTF-8`, `MOTP_TIMEOUT` (the seconds the plugin has), `MOTP_PLUGIN_API=1`; nothing else, no `HOME` |
| **Time** | 5 seconds by default (`limits.probe_timeout_s`), up to 30 per plugin (`timeout_s`); then the plugin and everything it started are killed |
| **Output** | 64 KiB on standard output; 8 KiB of standard error is kept for `motp doctor` and `motp collect` when the plugin fails |
| **Resources** | 30 s of CPU, files of at most 1 MiB, 64 processes, 64 open files, 128 MiB of memory (shared memory included), no POSIX message queues |
| **Network** | none: no network at all, no IP sockets; local sockets (`AF_UNIX`) by path only |
| **Memory** | no memory that is writable and executable at once, so runtimes with a JIT compiler (Node.js, Java) do not work |
| **Files** | the whole file system and `/run` are read-only; `/tmp`, `/var/tmp` and `/dev/shm` are the plugin's own (16 MiB each); MOTP's cache and state do not exist for it |

When a plugin ends, its unit ends with everything in it: its processes, its files in
`/tmp`, `/var/tmp` and `/dev/shm`, its System V IPC objects. Nothing a plugin leaves there
is seen by the next plugin or kept until the next run; use `MOTP_TIMEOUT`, not files, to
pace yourself.

A plugin that needs to read a file `motp-plugin` cannot read: prefer giving that one file
to the account (for example `setfacl -m u:motp-plugin:r /path/to/file`, or a group) over
running the plugin as root. Every plugin that runs as `motp-plugin` can then read it.

### Running a plugin as root

Only when there is no other way. Give the plugin a table in `/etc/motp/config.toml` (or a
file in `/etc/motp/conf.d/`), named after the file:

```toml
[plugins."50-backup"]
run_as = "root"        # motp-plugin (default) | root
timeout_s = 10         # 0.5 to 30; default: limits.probe_timeout_s
visibility = "admin"   # admin (default) | public
```

A root plugin runs in its own unit like any other, with these differences:

- its only capability is `CAP_DAC_READ_SEARCH`: it may read any file, and change none;
- the sockets of the service manager (also root's own user manager under `/run/user/0`), the
  system bus, the container runtimes (Docker, containerd, Podman, CRI-O, k3s, Incus, LXD),
  libvirt, snapd and udev are hidden, so it cannot ask them for anything.

Its `#!` line may not use `env` or another program that looks its argument up in `PATH`
(`#!/usr/bin/env python3` is refused; write `#!/usr/bin/python3`). If `systemd-run` is
missing, plugins do not run inside the collector unit.

What this sandbox is for: it keeps a careless or broken root plugin from changing MOTP's
files, `/run/motd.d` or anything else on disk. It is not a wall around hostile code. The
plugin still runs as user id 0, so it can send signals to other processes of root, and it
can reach a root daemon whose socket is not on that list (one outside `/run`, or one under
`/run` that MOTP does not know). Code you install as root is
code you trust. Without systemd (cron) and with `motp collect --no-sandbox` there is no
sandbox for anything, root plugins included, and their leftovers are only partly found.

## Who sees the rows

Plugin rows are for the admin group only (the group MOTP chose at install time, shown by
`motp doctor`). The author of a plugin does not know who else has an account on the
machine, so nothing a plugin prints reaches other users until the admin decides it may:

```toml
[plugins."50-backup"]
visibility = "public"
```

Then the rows use the `visibility` the plugin gives them (public when it gives none), and
`detail` rows stay admin-only unless they say `"visibility": "public"`. Making a plugin
admin-only again takes its rows out of the public part at the next run.

## When a plugin fails

A plugin fails for a run when it takes longer than its time limit, prints more than
64 KiB, exits with a code other than 0 to 3, is killed, or prints a JSON document MOTP
refuses. Only its own rows suffer: the last good rows are kept, marked with their age
once they are 15 minutes old, and replaced by "unknown" after 30 minutes. The other modules and plugins are not
affected, and the login is never delayed: plugins run in the background collector, never
at login.

`sudo /opt/motp/bin/motp collect` shows each failed module and plugin with the reason and
the plugin's standard error; `sudo /opt/motp/bin/motp doctor` lists every plugin with the
user it ran as and its last result.

## What a plugin must never print

What a plugin prints is shown on a login screen, stored in files under `/run/motp`, and
may reach everyone who logs in if the plugin is made public. Never print:

- passwords, keys, tokens, cookies, connection strings or anything else secret;
- personal data: names, mail addresses, login names of other people, client addresses;
- internal host names or addresses you would not put on a notice board;
- commands for the reader to run (MOTP shows them as plain text anyway).

## Without a plugin: watching a file's age

The common "is my backup recent?" needs no plugin. A config row warns when a file has not
changed for a while:

```toml
[[rows.file_age]]
path = "/var/backups/last-success"
label = "Backup"
warn_after = "26h"
crit_after = "3d"
```

The file is looked at as the user `motp`, which needs to enter its directory but not to
read the file. A file `motp` cannot reach shows as "unreadable"; make the directory
searchable for it, or watch the file with a root plugin instead. Label and age are shown
to everyone; the path is not. Name a file in a directory only root can write: in one that
others can write, a user could replace the file or touch it to fake its age. The collector
has its own /tmp, so a file there always shows as missing. Service states have a row of their own,
`[[rows.unit]]`.

## Checklist

- [ ] The name is `NN-name`, and the file is root's, mode 0755 or stricter.
- [ ] The `#!` line names an absolute interpreter that root owns.
- [ ] It prints one line and exits 0 to 3, or one JSON document with `"api": 1`.
- [ ] It finishes in well under 5 seconds (or you set `timeout_s`), also when a server it
      asks does not answer.
- [ ] It needs no network, no home directory, no files it wrote in an earlier run.
- [ ] It prints nothing secret or personal.
- [ ] It runs as `motp-plugin`; root only if it truly must, and then without `env`.
- [ ] Rows meant for everyone have `visibility = "public"` in the config, and only those.
- [ ] `sudo /opt/motp/bin/motp doctor` lists it as accepted, and its last run as ok.

# Contributing

The architecture is described in [`docs/adr/`](docs/adr/), the threats and the tests that cover
them in [`docs/threats.md`](docs/threats.md), and what 1.0 leaves out in
[`docs/known-limitations.md`](docs/known-limitations.md). Read the parts that touch your change
before you start.

Comments and documents cite a design document as "the blueprint", with section numbers,
decisions (D1 and up) and threats (T1 and up), and a "decision log". Both were the maintainer's
working papers during the rewrite and are not part of this repository. The threat ids are
listed in `docs/threats.md`; where a citation leaves a question open, ask in an issue.

## Rules

- One change is one branch and one pull request, merged without squashing.
- Commits follow Conventional Commits (`feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`,
  `ci`, `build`) with a body that says what changed and why. Tests ship in the commit of the code
  they cover; a fix comes with a test that fails without it.
- Nothing in the repository may contain real host names, IP addresses, user names, e-mail
  addresses or secrets: not in code, tests, fixtures, screenshots or commit messages. Use RFC 5737
  addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `example.com`. Commits use your
  GitHub noreply address (`ID+name@users.noreply.github.com`).
- The program uses the Python standard library only, on Python 3.9 and newer. No new dependency
  without a decision in the blueprint (D23).
- The invariants of blueprint section 10 are tests; do not weaken a guard to make a change pass.
- Workflows use official or widely used actions only, pinned by commit hash with the version and
  the reason in a comment (`tests/test_workflows.py`).
- Licence: GPL-3.0-or-later; contributions are made under the same terms.

## Set up and check

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"        # on Windows: .venv\Scripts\pip
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
.venv/bin/python tools/scan_repo.py      # must print "scan: 0 match(es)"
.venv/bin/python tools/build_pyz.py      # writes dist/motp.pyz and prints its SHA-256
```

Most tests run anywhere. Tests marked `needs_linux_owner` need Linux and root and are skipped
elsewhere; the container runs below run them.

## Tests on Linux

All container tools use Podman as root (on Windows: inside WSL, `wsl.exe -u root -- python3
/mnt/<drive>/<path>/tools/<tool>.py ...`). They print a status line at least every 15 seconds and
share a host-wide lock, so runs queue instead of disturbing each other. Images are kept for
reuse; `--rebuild` builds them again after a change to the images' scripts.

| Tool | What it runs | Time per image |
|---|---|---|
| `tools/container_test.py <image>` | the unit tests as root, with test accounts (level 1) | 2 to 5 min |
| `tools/systemd_test.py [images]` | install, the sandboxed unit and its timer under systemd, every module in the sandbox, plugins in their own units (level 3) | 5 to 8 min |
| `tools/login_test.py [images]` | real SSH logins with bash, zsh and fish as a user and an admin: the MOTD once, silent `ssh host true`, scp, sftp, rsync, static mode, languages, plugins, uninstall (level 3) | 8 to 10 min |
| `tools/release_check.py [debian:13 almalinux:10]` | the README's install, doctor and uninstall commands, typed as written, in fresh containers | 3 to 4 min |
| `tools/repro_check.py [--image debian:13]` | builds `motp.pyz` here and in a Linux container from the same commit and compares the bytes | 1 min |

The tier-1 images are `debian:12`, `debian:13`, `ubuntu:22.04`, `almalinux:9`, `almalinux:10` and
`fedora:45`. CI runs the same tools (`.github/workflows/ci.yml`); `tools/container/smoke.sh` is
the archive smoke test of CI and of the nightly tier-2 jobs.

## Adding a module

1. Write `src/motp/modules/<group>_<name>.py` with a class that has the attributes of
   `modules/base.py` (`name`, `section`, `mode`, `needs_root`, `interval`, `max_age`, `timeout`,
   `binaries`, `default_visibility`) and `detect(ctx)` and `collect(ctx)`. Read only through the
   context (`ctx.read`, `ctx.run`, `ctx.read_slice`, ...); it enforces the paths, the ownership
   checks and the time limit. Run as `motp` unless the module cannot work without root; say why in
   the docstring.
2. Decide what everyone may see and what only admins may (blueprint 5.4): set `visibility` on each
   item and detail, and keep names, addresses and paths out of public items.
3. Add the class to the explicit list in `modules/registry.py`.
4. Every text is a message id: add it to both catalogues (`src/motp/locale/en.po` and `de.po`), to
   a topic in `src/motp/explain.py`, and add the module's states to
   `tests/test_german.py::_module_items`. A command shown beside a warning is a hint id in
   `core/hints.py`, never text from the module.
5. Tests: fixtures captured from the real images (see the `tools/capture_*_fixtures.py` scripts),
   the contract (`through_the_contract`), what an unprivileged reader and an admin see, and hostile
   strings. If the module runs in the unit and needs more than its baseline, add the line with its
   reason to `install/units.py` (`MODULE_ADDITIONS`) and to the table in blueprint 4.11.

## Adding a language

[`docs/languages.md`](docs/languages.md) describes it step by step: a new
`src/motp/locale/<code>.po` with every id of `en.po`, the plural rule in `PLURAL_RULES` of
`core/i18n.py`, ASCII spellings in `core/sanitize.py` where the language has them, and the checks
of `tests/test_german.py` extended to the new language (invariant 8).

## Writing a plugin

Plugins are not part of this repository; [`docs/plugins.md`](docs/plugins.md) is the contract for
plugin authors, with examples in [`examples/plugins/`](examples/plugins/).

## Releasing

[`docs/release.md`](docs/release.md) is the maintainer's runbook.

# ADR-0001: Architecture

- **Status:** accepted, 2026-11-24 (phase 2)
- **Source of truth:** the blueprint (the maintainer's design document, not part of this repository), sections 4.1 to 4.3, decisions D7, D12, D21, D22, D31, D32, and the threat model in section 5.

This record fixes the shape the blueprint describes, so later phases can point at it. It adds nothing the blueprint does not already settle, except the two module additions under "Package layout".

## Context

MOTP shows a message of the day at login. Two goals pull against each other: the screen should show slow and privileged facts (pending updates, failed logins, bans), and a login must never wait for them or run root code because of them (blueprint 5.1).

## Decision

**Hybrid model (D7, 4.1).** A sandboxed root timer runs `motp collect` every five minutes. It starts every built-in probe and every plugin as its own process under an unprivileged user (D21), validates and sanitises their JSON output, and writes cache files to `/run/motp`. At login a shell hook runs `motp show --login` as the logging-in user, which reads the cache, adds live values from `/proc`, and writes once to the terminal.

**Three trust domains (4.1).** The collector (root, small, no network), probes and plugins (unprivileged, untrusted output), and the renderer (the reader, no privilege to lose). Data crosses each boundary only as validated, sanitised JSON.

**Login path (D22).** The renderer reads its program files, `/proc`, `/sys` and `/run/motp`, and nothing else. It starts no process, opens no socket, resolves no name, and does not read `/etc/motp`: the collector copies what it needs into `render.json`.

**Audiences (D12, D32).** `public.json` holds what everyone may see; `admin.json` holds the complete picture for root and one admin group; per-user data goes to `user/<uid>.json`.

**Installed form (D31).** One verifiable `motp.pyz` per release, unpacked and compiled under `/opt/motp` by the installer.

**Package layout (4.2)** with one rule per module: `core/sanitize.py` is the only place external text is cleaned, `core/proc.py` the only module that starts processes (invariant 1), and no module imports a network library (invariant 2). Phase 2 adds two core modules the table in 4.2 does not list:

- `core/probe.py`: validation of probe documents in the built-in and plugin forms. 4.2 lists schemas under `cache.py`; the probe contract is large enough to stand alone, and the cache reader reuses its item parser.
- `core/strictjson.py`: the bounded JSON decoder shared by probe validation and the cache reader.

**Module interface (4.3).** Modules return values, rule names and hint ids, never colour codes, commands or layout. `Context` is their only door to the system.

## Consequences

- Every check of a trust boundary lives in one place and has its own tests: the sanitiser corpus, the probe validation tests, the cache reader tests.
- Data shapes are frozen dataclasses in `core/model.py`; changing one is a contract change and needs a new ADR or an update of ADR-0002.

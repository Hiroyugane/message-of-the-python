"""Probe stderr, kept for root only (T11, phase 7).

The journal can be read by ``adm`` and ``wheel``, which D33 keeps out of the admin tier.
So the collector logs counts and stage names only; module names and failure reasons stay
in ``admin.json``; and what a failed probe wrote to stderr goes here:
``/var/lib/motp/probe-stderr.json``, 0600 root, in the root-only state directory.

The file holds the stderr of each module's last failed attempt: a run replaces the entry
of every module it started (an ``ok`` result removes it) and drops modules that no longer
exist. Each entry keeps at most ``MAX_LINES`` lines of ``LINE_CELLS`` cells, each passed
through the sanitiser, so the file is bounded (``MAX_BYTES``) and safe to print.
"""

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Optional

from motp.core import cache, strictjson
from motp.core.model import ContractError
from motp.core.sanitize import sanitize

NAME = "probe-stderr.json"
MODE = 0o600
SCHEMA = 1
MAX_LINES = 40
LINE_CELLS = 160
MAX_BYTES = 512 * 1024
MAX_DEPTH = 5
MAX_NAME = 64


@dataclass(frozen=True)
class Entry:
    time: int
    lines: tuple[str, ...]


def lines_of(stderr: bytes) -> tuple[str, ...]:
    """Sanitised, bounded lines of a probe's stderr; blank lines dropped."""
    text = stderr.decode("utf-8", "replace")
    out = []
    for raw in text.splitlines():
        line = sanitize(raw, LINE_CELLS)
        if line.strip():
            out.append(line)
        if len(out) >= MAX_LINES:
            break
    return tuple(out)


def encode(entries: Mapping[str, Entry]) -> bytes:
    doc = {
        "schema": SCHEMA,
        "modules": {
            name: {"time": e.time, "lines": list(e.lines)} for name, e in sorted(entries.items())
        },
    }
    data = strictjson.dumps(doc)
    if len(data) > MAX_BYTES:  # cannot happen with the caps above; never write more
        return encode(dict(sorted(entries.items(), key=lambda kv: kv[1].time)[1:]))
    return data


def decode(data: bytes) -> dict[str, Entry]:
    """The entries of a file; anything malformed gives an empty log (it is only a log)."""
    try:
        doc = strictjson.loads(data, max_bytes=MAX_BYTES, max_depth=MAX_DEPTH)
    except ContractError:
        return {}
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return {}
    modules = doc.get("modules")
    if not isinstance(modules, dict) or len(modules) > cache.MAX_MODULES:
        return {}
    out: dict[str, Entry] = {}
    for name, raw in modules.items():
        if not isinstance(raw, dict) or len(name) > MAX_NAME:
            continue
        when, lines = raw.get("time"), raw.get("lines")
        if type(when) is not int or not isinstance(lines, list):
            continue
        clean = tuple(sanitize(x, LINE_CELLS) for x in lines[:MAX_LINES] if isinstance(x, str))
        out[name] = Entry(when, clean)
    return out


def read(state_fd: int) -> dict[str, Entry]:
    """The current log in the open state directory, or an empty one."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(NAME, flags | getattr(os, "O_NONBLOCK", 0), dir_fd=state_fd)
    except OSError:
        return {}
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or st.st_mode & 0o077 or not st.st_size <= MAX_BYTES:
            return {}
        data = os.read(fd, MAX_BYTES + 1)
    except OSError:
        return {}
    finally:
        os.close(fd)
    return decode(data)


def merge(
    old: Mapping[str, Entry],
    ran: Mapping[str, Optional[tuple[str, ...]]],
    current: Iterable[str],
    now: int,
) -> dict[str, Entry]:
    """The log after a run. ``ran`` maps each module started in this run to its stderr
    lines (``None`` or empty: nothing to keep); ``current`` names the modules that still
    exist."""
    keep = set(current)
    out = {name: e for name, e in old.items() if name in keep and name not in ran}
    for name, lines in ran.items():
        if lines and name in keep:
            out[name] = Entry(now, lines)
    return out

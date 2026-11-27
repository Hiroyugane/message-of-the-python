"""``motp _probe <name>``: one cached module in its own process (blueprint 4.3, 4.4, D21).

The collector starts ``<python> -I -S <program> _probe <name>`` as the module's user. This
process builds the probe context, runs ``collect`` and prints one probe document
(protocol version 1) to stdout. On failure it prints nothing to stdout, writes the
message id of the reason to stderr (which the collector keeps, truncated, for its log) and
exits with 1. The collector validates the document as untrusted input either way.
"""

import math
import os
import sys
import time
from collections.abc import Mapping, Sequence
from typing import Optional, TextIO

from motp.collect.context import ProbeContext, read_os_release
from motp.core import cache, strictjson
from motp.core.cache import MAX_LOGIN_FIELD, MAX_LOGINS
from motp.core.model import ContractError, Item, UserLogins, ref
from motp.core.probe import (
    API_VERSION,
    MAX_USERS,
    PER_USER_DOCUMENT_BYTES,
    PER_USER_MODULES,
    USERS_FIELD,
)
from motp.modules import registry
from motp.modules.base import Module

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
UNKNOWN_MODULE = "probe.error.unknown_module"
ENCODING = "utf-8"
# How long the collector gives this probe, in seconds (``core.proc`` passes ``MOTP_*``).
TIMEOUT_VARIABLE = "MOTP_TIMEOUT"
# The module's own config table as JSON (``rows_unit`` gets its rows this way).
CONFIG_VARIABLE = "MOTP_CONFIG"
# 32 rows of a 250-character unit name (JSON doubles its backslashes) and a label of 40
# four-byte characters fit with room to spare.
MAX_CONFIG_BYTES = 64 * 1024
MAX_PROBE_SECONDS = 30.0
LINE_END = "\n"


def probe_item(item: Item) -> dict[str, object]:
    """An item in the built-in probe form: the cache form, with the hint as a plain id."""
    out = cache.item_json(item)
    out.pop("origin", None)
    hint = out.get("hint")
    if isinstance(hint, dict) and "id" in hint:
        out["hint"] = hint["id"]
    return out


def document(
    name: str, items: "list[Item]", users: "Optional[Sequence[UserLogins]]" = None
) -> bytes:
    """The probe document; with ``users`` (``os_login`` only), as many accounts as fit
    under the collector's limit, in the order given (the most recent logins first)."""
    obj: dict[str, object] = {
        "api": API_VERSION,
        "module": name,
        "items": [probe_item(i) for i in items],
    }
    if users is None:
        return strictjson.dumps(obj)
    encoded = [user_json(u) for u in users[:MAX_USERS]]
    obj[USERS_FIELD] = encoded
    data = strictjson.dumps(obj)
    while len(data) > PER_USER_DOCUMENT_BYTES and encoded:
        # Drop the least recent accounts: a cut in proportion to the excess, at least one.
        keep = min(len(encoded) * PER_USER_DOCUMENT_BYTES // len(data), len(encoded) - 1)
        encoded = encoded[: max(keep, 0)]
        obj[USERS_FIELD] = encoded
        data = strictjson.dumps(obj)
    return data


def user_json(user: UserLogins) -> dict[str, object]:
    return {
        "uid": user.uid,
        "logins": [
            {
                "started": login.started,
                "source": login.source[:MAX_LOGIN_FIELD],
                "tty": login.tty[:MAX_LOGIN_FIELD],
            }
            for login in user.logins[:MAX_LOGINS]
        ],
    }


def module_config(environ: "Mapping[str, str]") -> dict[str, object]:
    """The module's own config table, which the collector passes as JSON (``MOTP_CONFIG``);
    an empty table when there is none. One that does not parse raises ``ContractError``,
    so the module fails instead of showing nothing (review of phase 10)."""
    raw = environ.get(CONFIG_VARIABLE, "")
    if not raw:
        return {}
    obj = strictjson.loads(raw.encode(ENCODING), max_bytes=MAX_CONFIG_BYTES, max_depth=4)
    if not isinstance(obj, dict):
        raise ContractError(ref("probe.error.wrong_type", field=CONFIG_VARIABLE))
    return obj


def probe_seconds(module: Module) -> float:
    """The time this probe has: what the collector said, else the module's own need."""
    try:
        given = float(os.environ.get(TIMEOUT_VARIABLE, ""))
    except ValueError:
        return module.timeout
    if not math.isfinite(given) or not 0 < given <= MAX_PROBE_SECONDS:
        return module.timeout
    return given


def main(name: str, out: Optional[TextIO] = None, err: Optional[TextIO] = None) -> int:
    stdout = sys.stdout if out is None else out
    stderr = sys.stderr if err is None else err
    module = registry.cached_module(name)
    if module is None:
        stderr.write(UNKNOWN_MODULE + LINE_END)
        return EXIT_USAGE
    try:
        config = module_config(os.environ)
    except ContractError as exc:
        stderr.write(exc.message.id + LINE_END)
        return EXIT_FAILED
    ctx = ProbeContext(now=int(time.time()), binaries=tuple(module.binaries), config=config)
    seconds = probe_seconds(module)
    # All programs of the probe end a little before the collector ends the probe, so the
    # module still reports a program that took too long as its own failure.
    deadline = time.monotonic() + seconds - min(1.0, seconds / 4)
    try:
        ctx = ProbeContext(
            now=ctx.now,
            config=config,
            os_release=read_os_release(ctx),
            binaries=tuple(module.binaries),
            run_timeout=seconds,
            deadline=deadline,
        )
        items = module.collect(ctx)
        users = None
        collect_users = getattr(module, "collect_users", None)
        if name in PER_USER_MODULES and callable(collect_users):
            users = collect_users(ctx)
        data = document(name, items, users)
    except ContractError as exc:
        stderr.write(exc.message.id + LINE_END)
        return EXIT_FAILED
    except Exception as exc:  # a module bug: the collector marks the module failed
        stderr.write(type(exc).__name__ + LINE_END)
        return EXIT_FAILED
    buffer = getattr(stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:
        stdout.write(data.decode(ENCODING))
        stdout.flush()
    return EXIT_OK

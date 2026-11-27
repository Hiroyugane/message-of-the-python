"""``motp show``: the message of the day at login (blueprint D22, 4.4, 4.14, 4.15).

This is the render path. It reads, as the reader, only the cache files in one directory
(``/run/motp``) through the bounded reader, plus ``/proc`` and ``/sys`` through the module
context. It starts no process, opens no socket, resolves no name, reads no file of
``/etc/motp``, and writes the finished message once. The imports are kept small: no TOML
parser, no ``subprocess``, no ``argparse``, no ``pwd`` or ``grp``. Tests enforce this with
an audit hook and an AST check of every module reachable from here (invariant 6).

Order of work: read ``render.json`` (settings and thresholds), ``public.json`` and, where
the reader may, ``admin.json``; add the live values; with ``--login`` add the reader's
previous login from their own per-user file; classify, build the view, render, write.

Failure rules (4.10, 4.15): with ``--login`` any error exits 0 without a word, unless
``--debug`` is given. Without ``--login`` a one-line error goes to stderr and the exit code
is 1; ``--debug`` adds the traceback and the reasons why cache files were ignored. The
deadline (``core.deadline``) ends a slow run with exit code 0 and no output.
"""

import contextlib
import os
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Optional, TextIO

from motp import render as renderer
from motp.core import cache, deadline, i18n, look
from motp.core.cache import Layout, RenderSettings, TierCache
from motp.core.model import (
    ContractError,
    Item,
    ModuleResult,
    Unit,
    ref,
)
from motp.core.sanitize import sanitize
from motp.core.thresholds import Rule
from motp.modules import registry
from motp.modules.base import Context
from motp.render import theme, view

DEFAULT_DIR = "/run/motp"
DEFAULT_TIMER_PERIOD = 300
STALE_PERIODS = 3  # the whole cache is old after three timer periods (4.4)
HOSTNAME_FILE = "/proc/sys/kernel/hostname"
DEFAULT_WIDTH = 80
MAX_WIDTH = 1000
NOTE_CELLS = 120
LOGIN_MODULE = "os_login"
LOGIN_SECTION = "login"
LOGIN_MAX_AGE = 60
OUTPUT_ENCODING = "utf-8"
ENCODE_ERRORS = "replace"
LINE_END = "\n"
ROOT_UID = 0


@dataclass
class Notes:
    """Why something was left out; shown with ``--debug`` only."""

    lines: list[tuple[str, dict[str, str]]] = field(default_factory=list)

    def add(self, msg_id: str, **texts: str) -> None:
        self.lines.append((msg_id, texts))


def _dir_trusted(path: str, owner: Optional[int]) -> bool:
    """The directory belongs to ``owner`` and nobody else can write to it (T18)."""
    if owner is None:
        return True
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_uid == owner and not st.st_mode & 0o022


def _reason(exc: Exception, tr: i18n.Translator) -> str:
    return tr.text(exc.message) if isinstance(exc, ContractError) else type(exc).__name__


class Gatherer:
    """Reads the cache files; each may fail without hiding the others."""

    def __init__(
        self, cache_dir: str, owner: Optional[int], notes: Notes, tr: i18n.Translator
    ) -> None:
        self.dir = cache_dir
        self.owner = owner
        self.notes = notes
        self.tr = tr

    def _ignored(self, name: str, exc: ContractError) -> None:
        self.notes.add("show.debug.ignored", file=name, reason=_reason(exc, self.tr))

    def render_settings(self) -> Optional[RenderSettings]:
        try:
            return cache.read_render_file(os.path.join(self.dir, "render.json"), self.owner)
        except ContractError as exc:
            self._ignored("render.json", exc)
            return None

    def tier(self, tier: str) -> Optional[TierCache]:
        name = f"{tier}.json"
        try:
            return cache.read_tier_file(os.path.join(self.dir, name), tier, self.owner)
        except ContractError as exc:
            self._ignored(name, exc)
            return None

    def previous_login(self, uid: int, now: int) -> Optional[ModuleResult]:
        """The reader's previous login as a module result (D32); ``None`` if there is none."""
        folder = os.path.join(self.dir, "user")
        name = f"user/{uid}.json"
        if not _dir_trusted(folder, self.owner):
            self.notes.add(
                "show.debug.ignored", file=name, reason=self.tr.message("cache.error.owner")
            )
            return None
        try:
            user = cache.read_user_file(os.path.join(folder, f"{uid}.json"), uid, self.owner)
        except ContractError as exc:
            self._ignored(name, exc)
            return None
        entry = cache.previous_login(user, now, True)
        if entry is None:
            return None
        items = [
            Item(
                key="os_login.previous",
                value=entry.started,
                unit=Unit.TIMESTAMP,
                label=ref("label.previous_login"),
            )
        ]
        for key, label, text in (
            ("os_login.source", "label.login_from", entry.source),
            ("os_login.tty", "label.login_tty", entry.tty),
        ):
            if text:
                items.append(Item(key=key, value=text, label=ref(label)))
        return ModuleResult(collected=now, interval=1, max_age=LOGIN_MAX_AGE, items=tuple(items))


def live_sources(ctx: Context, notes: Notes, tr: i18n.Translator) -> tuple[list[view.Source], int]:
    """Run the live modules; a module that raises counts as failed, the rest still show."""
    sources: list[view.Source] = []
    failed = 0
    for module in registry.live_modules():
        try:
            if not module.detect(ctx).available:
                continue
            items = module.collect(ctx)
        except Exception as exc:
            failed += 1
            notes.add("show.debug.module_failed", module=module.name, reason=_reason(exc, tr))
            continue
        result = ModuleResult(
            collected=ctx.now,
            interval=module.interval,
            max_age=module.max_age,
            items=tuple(items),
        )
        sources.append(view.Source(module.name, module.section, result))
    return sources, failed


def _hostname(ctx: Context, tr: i18n.Translator) -> str:
    try:
        name = ctx.read_text(HOSTNAME_FILE, 256).strip()
    except ContractError:
        name = ""
    return name or tr.message("status.unknown")


def build_input(
    ctx: Context,
    *,
    cache_dir: str,
    owner: Optional[int],
    login: bool,
    uid: Optional[int],
    env: Mapping[str, str],
    notes: Notes,
    public_only: bool = False,
) -> view.RenderInput:
    """Everything the renderer needs: live values, the cache files and the previous login.

    ``public_only`` reads ``public.json`` alone, whoever runs this: the static file of
    static mode is the same text for every reader (4.10, D7).
    """
    now = ctx.now
    language = i18n.language_from_env(env)
    tr = i18n.translator(language)
    trusted = _dir_trusted(cache_dir, owner)
    gather = Gatherer(cache_dir, owner, notes, tr)
    settings = public = admin = None
    if trusted:
        settings = gather.render_settings()
        public = gather.tier(cache.PUBLIC)
        admin = None if public_only else gather.tier(cache.ADMIN)
    else:
        notes.add("show.debug.ignored", file=cache_dir, reason=tr.message("cache.error.owner"))

    layout = Layout()
    chosen_look = look.DEFAULT_LOOK
    rules: dict[str, Rule] = dict(registry.LIVE_RULES)
    timer_period = DEFAULT_TIMER_PERIOD
    package_manager = ""
    if settings is not None:
        layout = settings.layout
        chosen_look = settings.look
        rules.update(settings.thresholds)
        timer_period = settings.timer_period
        package_manager = settings.package_manager
        if settings.language != "auto":
            language = settings.language
            tr = i18n.translator(language)
        deadline.limit(settings.render_ms / 1000)

    sources, failed = live_sources(ctx, notes, tr)
    live_names = {module.name for module in registry.live_modules()}
    modules: dict[str, ModuleResult] = {}
    for tier_cache in (public, admin):  # admin entries replace the public ones
        if tier_cache is not None:
            modules.update(tier_cache.modules)
    newest = admin if admin is not None else public
    for name in sorted(modules, key=registry.order_key):
        section = registry.section_of(name)
        # the previous login comes from the reader's own file only, never from a tier file
        if name not in live_names and name != LOGIN_MODULE and section is not None:
            sources.append(view.Source(name, section, modules[name]))
    if login and uid is not None and trusted:
        previous = gather.previous_login(uid, now)
        if previous is not None:
            sources.append(view.Source(LOGIN_MODULE, LOGIN_SECTION, previous))

    cache_age: Optional[int] = None
    cached_failed = 0
    if newest is not None:
        cached_failed = newest.failed + newest.unreadable
        if now - newest.generated > STALE_PERIODS * timer_period:
            cache_age = now - newest.generated
    return view.RenderInput(
        sources=tuple(sources),
        now=now,
        hostname=_hostname(ctx, tr),
        layout=layout,
        language=language,
        rules=rules,
        package_manager=package_manager,
        failed=failed + cached_failed,
        config_ignored=admin.config_ignored if admin is not None else 0,
        cache_age=cache_age,
        admin=admin is not None,
        no_cache=newest is None,
        look=chosen_look,
    )


def terminal_width(env: Mapping[str, str]) -> int:
    """``COLUMNS``, else the size of the terminal on stdout, else 80."""
    try:
        columns = int(env.get("COLUMNS", ""))
        if columns > 0:
            return min(columns, MAX_WIDTH)
    except ValueError:
        pass
    try:
        columns = os.get_terminal_size(sys.__stdout__.fileno()).columns  # type: ignore[union-attr]
        if columns > 0:
            return min(columns, MAX_WIDTH)
    except (OSError, ValueError, AttributeError):
        pass
    return DEFAULT_WIDTH


def render_text(
    ctx: Context,
    *,
    cache_dir: str = DEFAULT_DIR,
    owner: Optional[int] = ROOT_UID,
    login: bool = False,
    uid: Optional[int] = None,
    env: Optional[Mapping[str, str]] = None,
    width: Optional[int] = None,
    isatty: bool = False,
    encoding: Optional[str] = None,
    notes: Optional[Notes] = None,
    public_only: bool = False,
) -> str:
    """The finished message for one reader, as one string."""
    env = os.environ if env is None else env
    inp = build_input(
        ctx,
        cache_dir=cache_dir,
        owner=owner,
        login=login,
        uid=uid,
        env=env,
        notes=Notes() if notes is None else notes,
        public_only=public_only,
    )
    if env.get("MOTP_PLAIN") == "1":
        # The reader's plain mode (final review, usability item 15): no header, no frame,
        # no dotted leaders. Presentation only; what is shown stays the same.
        plain_look = replace(inp.look, frame=False, label_style="colon")
        inp = replace(inp, layout=replace(inp.layout, header="off"), look=plain_look)
    layout = inp.layout
    chosen = theme.themed(
        theme.pick_charset(env, encoding, layout.charset, None),
        theme.pick_color(env, isatty, layout.color, None),
        inp.look,
    )
    return renderer.render(inp, width if width is not None else terminal_width(env), chosen)


def _write(text: str, out: TextIO) -> None:
    """One write of the finished message, as UTF-8 whatever the console's code page."""
    buffer = getattr(out, "buffer", None)
    out.flush()
    if buffer is None:
        out.write(text)
        out.flush()
        return
    buffer.write(text.encode(OUTPUT_ENCODING, ENCODE_ERRORS))
    buffer.flush()


def _stderr(text: str) -> None:
    try:
        sys.stderr.write(text + "\n")
        sys.stderr.flush()
    except (OSError, AttributeError):
        pass


def _print_notes(notes: Notes, env: Mapping[str, str]) -> None:
    tr = i18n.translator(i18n.language_from_env(env))
    for msg_id, texts in notes.lines:
        _stderr(tr.compose(msg_id, {k: sanitize(v, NOTE_CELLS) for k, v in texts.items()}))


def _report(exc: BaseException, env: Mapping[str, str], debug: bool) -> None:
    with contextlib.suppress(Exception):  # reporting must never raise a second error
        _report_unguarded(exc, env, debug)


def _report_unguarded(exc: BaseException, env: Mapping[str, str], debug: bool) -> None:
    tr = i18n.translator(i18n.language_from_env(env))
    _stderr(tr.message("show.error", {"error": type(exc).__name__}))
    if debug:
        import traceback

        _stderr("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).rstrip())


def main(
    login: bool = False,
    debug: bool = False,
    *,
    cache_dir: str = DEFAULT_DIR,
    owner: Optional[int] = ROOT_UID,
    context: Optional[Context] = None,
    uid: Optional[int] = None,
    env: Optional[Mapping[str, str]] = None,
    stream: Optional[TextIO] = None,
    width: Optional[int] = None,
) -> int:
    """Render and print the message; the exit code follows the rules in the module doc."""
    env = os.environ if env is None else env
    out = sys.stdout if stream is None else stream
    notes = Notes()
    try:
        if uid is None and hasattr(os, "getuid"):
            uid = os.getuid()
        ctx = context if context is not None else Context(now=int(time.time()))
        text = render_text(
            ctx,
            cache_dir=cache_dir,
            owner=owner,
            login=login,
            uid=uid,
            env=env,
            width=width,
            isatty=out.isatty(),
            encoding=getattr(out, "encoding", None),
            notes=notes,
        )
        _write(text, out)
    except BrokenPipeError:
        return 0  # the reader went away; nothing more to say
    except Exception as exc:
        if debug or not login:
            _report(exc, env, debug)
        return 0 if login else 1
    if debug:
        _print_notes(notes, env)
    return 0

"""Command line interface: ``version``, ``show``, ``collect``, ``modules``, ``config``,
``preview``, ``explain``, ``doctor``, ``install``, ``uninstall`` and ``shell-init``.

Every text printed here comes from the message catalogue (invariant 5). The usage and
error lines that ``argparse`` writes itself are the standard library's own.
"""

import argparse
import os
import pkgutil
import shutil
import stat
import sys
from typing import Optional

from motp import __version__
from motp import render as renderer
from motp.core import config, i18n, look, safepath
from motp.core.model import ContractError, MessageRef
from motp.core.sanitize import sanitize
from motp.install import hooks
from motp.render import demo, theme

PATH_CELLS = 200  # file paths in output lines
MIN_WIDTH = 10
MAX_WIDTH = 1000
OUTPUT_ENCODING = "utf-8"


def _for_argparse(text: str) -> str:
    """argparse %-formats help texts (not descriptions); a translated % must stay a %."""
    return text.replace("%", "%%")


# Each command's examples, shown under its help (final review, usability item 11): the
# command line, which is code and never translated, and the message that says what it does.
EXAMPLES: dict[str, tuple[tuple[str, str], ...]] = {
    "version": (("motp version", "cli.example.version"),),
    "show": (("motp", "cli.example.show"), ("motp show --debug", "cli.example.show_debug")),
    "collect": (
        ("sudo motp collect", "cli.example.collect"),
        ("sudo motp collect --no-sandbox", "cli.example.collect_direct"),
    ),
    "modules": (
        ("motp modules", "cli.example.modules"),
        ("motp modules --keys", "cli.example.modules_keys"),
    ),
    "doctor": (
        ("motp doctor", "cli.example.doctor"),
        ("sudo motp doctor", "cli.example.doctor_root"),
    ),
    "install": (
        ("sudo /usr/bin/python3 -I -S ./motp.pyz install --dry-run", "cli.example.dry_run"),
        ("sudo /usr/bin/python3 -I -S ./motp.pyz install", "cli.example.install"),
        ("sudo /usr/bin/python3 -I -S ./motp.pyz install --mode static", "cli.example.static"),
    ),
    "uninstall": (
        ("sudo motp uninstall --dry-run", "cli.example.dry_run"),
        ("sudo motp uninstall", "cli.example.uninstall"),
        ("sudo motp uninstall --purge", "cli.example.purge"),
    ),
    "shell-init": (("motp shell-init bash >> ~/.bashrc", "cli.example.shell_init"),),
    "config": (
        ("sudo motp config check", "cli.example.check"),
        ("motp config check ./draft.toml", "cli.example.check_file"),
        ("sudo motp config init", "cli.example.init"),
    ),
    "config check": (
        ("sudo motp config check", "cli.example.check"),
        ("motp config check ./draft.toml", "cli.example.check_file"),
    ),
    "config init": (
        ("sudo motp config init", "cli.example.init"),
        ("motp config init --path ./config.toml", "cli.example.init_path"),
    ),
    "explain": (
        ("motp explain", "cli.example.explain"),
        ("motp explain disks", "cli.example.explain_topic"),
        ('motp explain "Failed logins"', "cli.example.explain_label"),
    ),
    "preview": (
        ("motp preview", "cli.example.preview"),
        ("motp preview --width 60 --charset ascii", "cli.example.preview_narrow"),
        ("motp preview --preset classic --color always", "cli.example.preview_classic"),
    ),
}
# Lines after the examples of one command.
EXTRA = {"config check": ("cli.config.check.exit",)}
EXIT_CODES = (("0", "cli.exit.ok"), ("1", "cli.exit.failed"), ("2", "cli.exit.usage"))
HELP = {
    "version": "cli.version.help",
    "show": "cli.show.help",
    "collect": "cli.collect.help",
    "modules": "cli.modules.help",
    "doctor": "cli.doctor.help",
    "install": "cli.install.help",
    "uninstall": "cli.uninstall.help",
    "shell-init": "cli.shell_init.help",
    "config": "cli.config.help",
    "config check": "cli.config.check.help",
    "config init": "cli.config.init.help",
    "explain": "cli.explain.help",
    "preview": "cli.preview.help",
}


def _command(
    tr: i18n.Translator,
    sub: "argparse._SubParsersAction[argparse.ArgumentParser]",
    name: str,
    path: str = "",
    allow_abbrev: bool = True,
) -> argparse.ArgumentParser:
    """A sub-command with its help line, a description and an examples epilog."""
    key = f"{path} {name}".strip()
    text = tr.message(HELP[key])
    return sub.add_parser(
        name,
        help=_for_argparse(text),
        description=text[:1].upper() + text[1:],
        epilog=_examples(tr, key),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=allow_abbrev,
    )


def _examples(tr: i18n.Translator, key: str) -> str:
    examples = EXAMPLES[key]
    width = max(len(command) for command, _ in examples)
    lines = [tr.message("cli.examples")]
    for command, msg_id in examples:
        lines.append(f"  {command.ljust(width)}   {tr.message(msg_id)}")
    lines += [tr.message(msg_id) for msg_id in EXTRA.get(key, ())]
    return "\n".join(lines)


def _main_epilog(tr: i18n.Translator) -> str:
    lines = [tr.message("cli.exit.title")]
    lines += [f"  {code}  {tr.message(msg_id)}" for code, msg_id in EXIT_CODES]
    lines += [tr.message("cli.exit.login"), "", tr.message("cli.exit.debug")]
    lines.append(tr.message("cli.exit.explain"))
    return "\n".join(lines)


def build_parser(tr: i18n.Translator) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="motp",
        description=tr.message("cli.description"),
        epilog=_main_epilog(tr),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar=tr.message("cli.commands"))
    _command(tr, sub, "version")
    show = _command(tr, sub, "show", allow_abbrev=False)
    show.add_argument(
        "--login", action="store_true", help=_for_argparse(tr.message("cli.show.login_help"))
    )
    show.add_argument(
        "--debug", action="store_true", help=_for_argparse(tr.message("cli.show.debug_help"))
    )

    collect = _command(tr, sub, "collect")
    collect.add_argument(
        "--no-sandbox",
        action="store_true",
        help=_for_argparse(tr.message("cli.collect.no_sandbox_help")),
    )
    collect.add_argument("--in-unit", action="store_true", help=argparse.SUPPRESS)
    modules = _command(tr, sub, "modules")
    modules.add_argument(
        "--keys", action="store_true", help=_for_argparse(tr.message("cli.modules.keys_help"))
    )
    _command(tr, sub, "doctor")
    install = _command(tr, sub, "install")
    install.add_argument(
        "--dry-run", action="store_true", help=_for_argparse(tr.message("cli.dry_run_help"))
    )
    install.add_argument(
        "--no-start", action="store_true", help=_for_argparse(tr.message("cli.no_start_help"))
    )
    install.add_argument(
        "--mode",
        choices=config.MODES,
        help=_for_argparse(tr.message("cli.install.mode_help")),
    )
    uninstall = _command(tr, sub, "uninstall")
    uninstall.add_argument(
        "--dry-run", action="store_true", help=_for_argparse(tr.message("cli.dry_run_help"))
    )
    uninstall.add_argument(
        "--purge", action="store_true", help=_for_argparse(tr.message("cli.purge_help"))
    )

    shell_init = _command(tr, sub, "shell-init")
    shell_init.add_argument(
        "shell", choices=hooks.SHELLS, help=_for_argparse(tr.message("cli.shell_init.shell_help"))
    )

    conf = _command(tr, sub, "config")
    conf_sub = conf.add_subparsers(dest="config_command", metavar=tr.message("cli.commands"))
    check = _command(tr, conf_sub, "check", "config")
    check.add_argument(
        "path", nargs="?", help=_for_argparse(tr.message("cli.config.check.path_help"))
    )
    init = _command(tr, conf_sub, "init", "config")
    init.add_argument(
        "--path",
        default=os.path.join(config.DEFAULT_ROOT, config.MAIN_FILE),
        help=_for_argparse(tr.message("cli.config.init.path_help")),
    )

    explaining = _command(tr, sub, "explain")
    explaining.add_argument(
        "topic", nargs="?", help=_for_argparse(tr.message("cli.explain.topic_help"))
    )

    preview = _command(tr, sub, "preview")
    preview.add_argument(
        "--demo", action="store_true", help=_for_argparse(tr.message("cli.preview.demo_help"))
    )
    preview.add_argument(
        "--width", type=int, help=_for_argparse(tr.message("cli.preview.width_help"))
    )
    preview.add_argument(
        "--charset",
        choices=theme.CHARSET_MODES,
        default="auto",
        help=_for_argparse(tr.message("cli.preview.charset_help")),
    )
    preview.add_argument(
        "--color",
        choices=theme.MODES,
        default="auto",
        help=_for_argparse(tr.message("cli.preview.color_help")),
    )
    preview.add_argument(
        "--preset",
        choices=look.PRESETS,
        default="default",
        help=_for_argparse(tr.message("cli.preview.preset_help")),
    )
    parser.set_defaults(_parsers={"config": conf})
    return parser


def _path_text(path: str) -> str:
    return sanitize(path, PATH_CELLS)


def _problem_line(
    tr: i18n.Translator, file: str, reason: MessageRef, line: Optional[int] = None
) -> str:
    params = {"file": _path_text(file), "reason": tr.text(reason)}
    if line is not None:
        return tr.compose("config.check.problem_line", {**params, "line": str(line)})
    return tr.compose("config.check.problem", params)


def _warning_line(tr: i18n.Translator, warning: config.Problem) -> str:
    params = {"file": _path_text(warning.file), "reason": tr.text(warning.reason)}
    if warning.line is not None:
        return tr.compose("config.check.warning_line", {**params, "line": str(warning.line)})
    return tr.compose("config.check.warning", params)


def _print_warnings(tr: i18n.Translator, warnings: "list[config.Problem]") -> None:
    for warning in warnings:
        print(_warning_line(tr, warning))
    if warnings:
        print(tr.message("config.check.warnings", {"count": len(warnings)}))


FileId = tuple[int, int]  # device and inode


def _read_plain(path: str) -> tuple[bytes, FileId]:
    """Read a file named on the command line: regular file, bounded, never blocking.

    Raises ``ContractError`` with the reason when the file cannot be used.
    """
    flags = os.O_RDONLY
    for name in ("O_NONBLOCK", "O_CLOEXEC", "O_NOCTTY", "O_BINARY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ContractError(MessageRef("config.error.open")) from exc
    chunks: list[bytes] = []
    size = 0
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ContractError(MessageRef("config.error.not_regular"))
        while size <= config.MAX_FILE_BYTES:
            chunk = os.read(fd, config.MAX_FILE_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError as exc:
        raise ContractError(MessageRef("config.error.open")) from exc
    finally:
        os.close(fd)
    if size > config.MAX_FILE_BYTES:
        limit = (("max", config.MAX_FILE_BYTES),)
        raise ContractError(MessageRef("config.error.too_large", limit))
    return b"".join(chunks), (st.st_dev, st.st_ino)


def _tree_name(file_id: FileId, root: str) -> Optional[str]:
    """The name under which the collector would read this file, if it reads it at all."""
    for candidate in config.config_files(root)[0]:
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if (st.st_dev, st.st_ino) == file_id:
            return candidate
    return None


def _check_one(tr: i18n.Translator, path: str, root: str) -> int:
    """``motp config check <path>``.

    A file the collector reads (``config.toml`` or a drop-in under ``root``) is checked as
    the collector sees it: the whole tree is loaded and that file's problems are shown,
    ownership and the files loaded before it included. Any other file is checked on its
    own on top of the defaults, and whether MOTP would trust it where it lies is only
    noted, since an admin may check a draft before installing it.
    """
    shown = {"file": _path_text(path)}
    try:
        data, file_id = _read_plain(path)
    except ContractError as exc:
        print(_problem_line(tr, path, exc.message))
        return 1
    in_tree = _tree_name(file_id, root)
    if in_tree is not None:
        loaded = config.load(root)
        mine = [p for p in loaded.problems if p.file == in_tree]
        for problem in mine:
            print(_problem_line(tr, path, problem.reason, problem.line))
        if mine:
            return 1
        _print_warnings(tr, [w for w in loaded.warnings if w.file == in_tree])
        print(tr.compose("config.check.file_used", shown))
        return 0
    problems, warnings = config.content_report(data, path)
    for problem in problems:
        print(_problem_line(tr, path, problem.reason, problem.line))
    if problems:
        return 1
    _print_warnings(tr, warnings)
    print(tr.compose("config.check.file_valid", shown))
    # The walk resolves ".." physically, so the path is made absolute without normalising.
    full = path if path.startswith("/") else os.getcwd().rstrip("/") + "/" + path
    try:
        trusted = safepath.check_file(full)
        if (trusted.dev, trusted.ino) != file_id:
            raise ContractError(MessageRef("safepath.error.changed", (("path", full),)))
    except ContractError as exc:
        print(tr.compose("config.check.not_trusted", {**shown, "reason": tr.text(exc.message)}))
    return 0


def config_check(tr: i18n.Translator, path: Optional[str], root: str) -> int:
    """``motp config check [path]``: exit 0 when valid (warnings do not count), 1 when a
    problem was found or only root can read the config.

    Without a path, the configuration under ``root`` is loaded exactly as the collector
    loads it, ownership checks included. With a path, see ``_check_one``.
    """
    if path is not None:
        return _check_one(tr, path, root)
    loaded = config.load(root)
    if config.closed_to_user(root, loaded.problems):
        print(tr.message("config.check.root_only", {"root": _path_text(root)}))
        return 1
    for problem in loaded.problems:
        print(_problem_line(tr, problem.file, problem.reason, problem.line))
    if loaded.problems:
        print(tr.message("config.check.invalid"))
        return 1
    _print_warnings(tr, list(loaded.warnings))
    print(
        tr.message("config.check.valid", {"root": _path_text(root), "count": len(loaded.applied)})
    )
    return 0


def starter_text() -> bytes:
    data = pkgutil.get_data("motp", "data/starter-config.toml")
    return data if data is not None else b""


def config_init(tr: i18n.Translator, path: str) -> int:
    """``motp config init``: write the starter file; never overwrite or follow a link."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for name in ("O_NOFOLLOW", "O_CLOEXEC", "O_NOCTTY", "O_BINARY"):
        flags |= getattr(os, name, 0)
    shown = {"file": _path_text(path)}
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError:
        print(tr.compose("config.init.exists", shown), file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(tr.compose("config.init.no_directory", shown), file=sys.stderr)
        return 1
    except OSError:
        print(tr.compose("config.init.failed", shown), file=sys.stderr)
        return 1
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o644)  # whatever the umask, readable by all, writable by root
        data = starter_text()
        while data:
            data = data[os.write(fd, data) :]
    except OSError:
        print(tr.compose("config.init.failed", shown), file=sys.stderr)
        return 1
    finally:
        os.close(fd)
    print(tr.compose("config.init.written", shown))
    return 0


def _write(text: str) -> None:
    """One write of the finished message, as UTF-8 whatever the console's code page."""
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    sys.stdout.flush()
    data = text.encode(OUTPUT_ENCODING, "replace")
    buffer.write(data)
    buffer.flush()


def preview(tr: i18n.Translator, args: argparse.Namespace) -> int:
    """``motp preview``: the demo data, rendered as a login would render it.

    Only the demo can be previewed in this version, so it is the default (usability item
    10); ``--demo`` is still accepted and changes nothing.
    """
    width = args.width if args.width is not None else shutil.get_terminal_size().columns
    if not MIN_WIDTH <= width <= MAX_WIDTH:
        limits = {"min": MIN_WIDTH, "max": MAX_WIDTH}
        print(tr.message("cli.preview.bad_width", limits), file=sys.stderr)
        return 2
    env = os.environ
    isatty = sys.stdout.isatty()
    encoding = getattr(sys.stdout, "encoding", None)
    charset = theme.pick_charset(env, encoding, "auto", args.charset)
    color = theme.pick_color(env, isatty, "auto", args.color)
    inp = demo.demo_input(language=tr.language, preset=args.preset)
    _write(renderer.render(inp, width, theme.themed(charset, color, inp.look)))
    return 0


def explain(topic: Optional[str], cache_dir: Optional[str] = None, owner: Optional[int] = 0) -> int:
    """``motp explain [topic]``: exit 0, or 2 for a topic nobody knows.

    It speaks the language the message itself speaks: ``render.json``'s, when the config
    forces one, else the reader's locale. The same file names the package manager, so on an
    apt or dnf system only its commands are listed, and the threshold limits in force.
    Without a package manager (another system, not installed or not collected yet) every
    command is listed, marked with the one it is for.
    """
    from motp import explain as pages
    from motp import show
    from motp.core import cache
    from motp.modules import registry

    folder = show.DEFAULT_DIR if cache_dir is None else cache_dir
    try:
        settings = cache.read_render_file(os.path.join(folder, "render.json"), owner)
    except ContractError:
        settings = None
    language = i18n.language_from_env(os.environ)
    rules = {**registry.LIVE_RULES, **config.defaults().thresholds}
    package_manager, charset_mode = "", "auto"
    if settings is not None:
        if settings.language != "auto":
            language = settings.language
        rules.update(settings.thresholds)
        package_manager = settings.package_manager
        charset_mode = settings.layout.charset
    tr = i18n.translator(language)
    encoding = getattr(sys.stdout, "encoding", None)
    ascii_only = theme.pick_charset(os.environ, encoding, charset_mode, None).ascii_only
    width = shutil.get_terminal_size().columns - 1
    if topic is None:
        lines = pages.topic_list(tr, width, ascii_only)
    else:
        found = pages.page(
            tr,
            topic.lower(),
            rules=rules,
            package_manager=package_manager,
            width=width,
            ascii_only=ascii_only,
        )
        if found is None:
            print(tr.message("explain.unknown_topic", {"topic": topic}), file=sys.stderr)
            return 2
        lines = found
    _write("".join(f"{line}{chr(10)}" for line in lines))
    return 0


def isolated_without_site() -> bool:
    """``python3 -I -S`` (T2): no environment, no user site, no site directories. The two
    commands that change the system as root refuse to run without both, since ``site``
    reads ``.pth`` files of directories that are not always root's alone (blueprint 5.6,
    security review of phase 14). The installed wrapper always passes both."""
    return bool(sys.flags.isolated) and bool(sys.flags.no_site)


def main(argv: Optional[list[str]] = None) -> int:
    """Run one command; an unexpected error is one line on stderr and exit code 1.

    ``MOTP_DEBUG=1`` shows the traceback instead (usability item 15). ``motp show --login``
    never gets here with an error: ``entry`` catches everything there and exits 0.
    """
    tr = i18n.translator(i18n.language_from_env(os.environ))
    parser = build_parser(tr)
    args = parser.parse_args(argv)
    try:
        return _dispatch(tr, parser, args)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        if os.environ.get("MOTP_DEBUG") == "1":
            raise
        detail = sanitize(f"{type(exc).__name__}: {exc}", PATH_CELLS)
        print(tr.message("cli.unexpected", {"detail": detail}), file=sys.stderr)
        return 1


def _dispatch(
    tr: i18n.Translator, parser: argparse.ArgumentParser, args: argparse.Namespace
) -> int:
    if args.command in (None, "show"):  # `motp` alone shows the message (4.13)
        from motp import show

        return show.main(login=getattr(args, "login", False), debug=getattr(args, "debug", False))
    if args.command == "version":
        print(tr.message("cli.version.output", {"version": __version__}))
        return 0
    if args.command == "collect":
        from motp.collect import runner

        return runner.main(no_sandbox=args.no_sandbox, in_unit=args.in_unit)
    if args.command == "modules":
        from motp.collect import listing

        if args.keys:
            return listing.keys_main(sys.stdout)
        return listing.main(sys.stdout)
    if args.command == "doctor":
        from motp.install import doctor

        return doctor.main()
    if args.command in ("install", "uninstall") and not isolated_without_site():
        print(tr.message("install.error.flags"), file=sys.stderr)
        return 2
    if args.command == "install":
        from motp.install import installer

        return installer.install(dry_run=args.dry_run, no_start=args.no_start, mode=args.mode)
    if args.command == "uninstall":
        from motp.install import installer

        return installer.uninstall(purge=args.purge, dry_run=args.dry_run)
    if args.command == "config" and args.config_command == "check":
        return config_check(tr, args.path, config.DEFAULT_ROOT)
    if args.command == "config" and args.config_command == "init":
        return config_init(tr, args.path)
    if args.command == "config":  # no sub-command: its help, as a usage error
        args._parsers["config"].print_help(sys.stdout)
        return 2
    if args.command == "explain":
        return explain(args.topic)
    if args.command == "preview":
        return preview(tr, args)
    if args.command == "shell-init":
        _write(hooks.rc_snippet(args.shell))
        return 0
    parser.print_help(sys.stderr)
    return 2


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())

"""``motp explain <topic>``: what a row or a warning means, and what to do (blueprint D19).

The texts are catalogue messages, so they come in every language MOTP speaks and nothing
is read from outside the program. This module holds the table of topics: which messages
explain each one, which labels and row texts it covers (a test keeps that complete), and
which entries of the hint table belong to it. An alert that carries a command shows no hint
sentence, so the sentences are shown here, next to the same commands.

Only the command line imports this module; ``motp show`` never does.
"""

import textwrap
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional

from motp.core import hints
from motp.core.i18n import Translator, translator
from motp.core.sanitize import sanitize
from motp.core.thresholds import Rule

MAX_WIDTH = 78
MIN_WIDTH = 20
INDENT = "  "
HINT_INDENT = "      "
SELF = "motp explain "  # the hint that leads here is not repeated here
_ALL_CELLS = 4000


@dataclass(frozen=True)
class Topic:
    title: str
    what: str
    warn: str = ""
    todo: str = ""
    covers: tuple[str, ...] = ()  # the labels and screen texts this topic explains
    hints: tuple[str, ...] = ()  # ids of the hint table
    rules: tuple[str, ...] = ()  # threshold rules whose limits are shown


TOPICS: Mapping[str, Topic] = {
    "status": Topic(
        "explain.status.title",
        "explain.status.what",
        "explain.status.warn",
        "explain.status.todo",
        covers=(
            "status.ok",
            "status.warn",
            "status.crit",
            "status.unknown",
            "value.age",
            "value.ago",
            "value.yes",
            "value.no",
            "value.labelled",
            "section.attention",
            "section.tip",
        ),
    ),
    "hostname": Topic(
        "explain.hostname.title",
        "explain.hostname.what",
        covers=("label.hostname", "render.host_uptime", "section.host"),
    ),
    "os": Topic("explain.os.title", "explain.os.what", covers=("label.os",)),
    "kernel": Topic("explain.kernel.title", "explain.kernel.what", covers=("label.kernel",)),
    "address": Topic("explain.address.title", "explain.address.what", covers=("label.address",)),
    "dns": Topic("explain.dns.title", "explain.dns.what", covers=("label.dns",)),
    "uptime": Topic(
        "explain.uptime.title",
        "explain.uptime.what",
        covers=("label.uptime", "section.system"),
    ),
    "load": Topic(
        "explain.load.title",
        "explain.load.what",
        "explain.load.warn",
        "explain.load.todo",
        covers=("label.load", "load.summary"),
        rules=("load_per_core",),
    ),
    "memory": Topic(
        "explain.memory.title",
        "explain.memory.what",
        "explain.memory.warn",
        "explain.memory.todo",
        covers=("label.memory", "memory.summary"),
        rules=("memory_used_percent",),
    ),
    "swap": Topic(
        "explain.swap.title",
        "explain.swap.what",
        "explain.swap.warn",
        "explain.swap.todo",
        covers=("label.swap",),
        rules=("swap_used_percent",),
    ),
    "updates": Topic(
        "explain.updates.title",
        "explain.updates.what",
        "explain.updates.warn",
        "explain.updates.todo",
        covers=(
            "label.updates",
            "label.packages",
            "label.package_lists",
            "label.held_back",
            "updates.summary",
            "updates.plain",
            "updates.none",
            "updates.unsplit",
            "updates.held_only",
            "updates.no_lists",
        ),
        hints=("updates.install", "updates.security"),
    ),
    "reboot": Topic(
        "explain.reboot.title",
        "explain.reboot.what",
        "explain.reboot.warn",
        "explain.reboot.todo",
        covers=("label.reboot", "reboot.required", "reboot.not_required"),
        hints=("reboot.required",),
    ),
    "eol": Topic(
        "explain.eol.title",
        "explain.eol.what",
        "explain.eol.warn",
        "explain.eol.todo",
        covers=(
            "label.eol",
            "eol.supported",
            "eol.supported_table",
            "eol.ending",
            "eol.ending_table",
            "eol.ended",
            "eol.ended_table",
        ),
        hints=("os.eol",),
    ),
    "firewall": Topic(
        "explain.firewall.title",
        "explain.firewall.what",
        "explain.firewall.warn",
        "explain.firewall.todo",
        covers=(
            "label.firewall",
            "firewall.inactive",
            "firewall.active",
            "firewall.active_zone",
            "firewall.failed",
            "section.security",
        ),
        hints=("firewall.ufw", "firewall.firewalld", "firewall.nftables"),
    ),
    "autoupdates": Topic(
        "explain.autoupdates.title",
        "explain.autoupdates.what",
        "explain.autoupdates.warn",
        "explain.autoupdates.todo",
        covers=(
            "label.autoupdates",
            "autoupdates.on",
            "autoupdates.off",
            "autoupdates.not_installed",
            "autoupdates.download_only",
            "autoupdates.apply_off",
            "autoupdates.periodic_off",
        ),
        hints=(
            "autoupdates.install",
            "autoupdates.enable",
            "autoupdates.enable_dnf5",
            "autoupdates.apply_dnf5",
            "autoupdates.timer",
            "autoupdates.unmask",
            "autoupdates.unmask_dnf5",
            "autoupdates.periodic",
        ),
    ),
    "logins": Topic(
        "explain.logins.title",
        "explain.logins.what",
        todo="explain.logins.todo",
        covers=(
            "label.failed_logins",
            "label.login_sources",
            "logins.failed",
            "logins.failed_more",
            "records.not_recorded",
        ),
    ),
    "fail2ban": Topic(
        "explain.fail2ban.title",
        "explain.fail2ban.what",
        "explain.fail2ban.warn",
        "explain.fail2ban.todo",
        covers=(
            "label.fail2ban",
            "label.jail",
            "fail2ban.banned",
            "fail2ban.not_running",
            "fail2ban.not_checked",
        ),
        hints=("fail2ban.status", "import_path.check"),
    ),
    "login": Topic(
        "explain.login.title",
        "explain.login.what",
        todo="explain.login.todo",
        covers=("label.previous_login", "label.login_from", "label.login_tty", "section.login"),
    ),
    "sessions": Topic(
        "explain.sessions.title",
        "explain.sessions.what",
        covers=("label.sessions", "label.session_users", "sessions.count", "records.not_recorded"),
    ),
    "disks": Topic(
        "explain.disks.title",
        "explain.disks.what",
        "explain.disks.warn",
        "explain.disks.todo",
        covers=(
            "label.mount",
            "disk.usage",
            "disk.usage_full",
            "disk.usage_short",
            "disk.usage_free",
            "meter.percent",
            "section.disks",
        ),
        hints=("disk.space",),
        rules=("disk_used_percent",),
    ),
    "inodes": Topic(
        "explain.inodes.title",
        "explain.inodes.what",
        "explain.inodes.warn",
        "explain.inodes.todo",
        covers=(
            "label.mount_inodes",
            "disk.inode_usage",
            "disk.inode_full",
            "disk.inode_short",
            "disk.inode_free",
        ),
        hints=("disk.inodes",),
        rules=("inode_used_percent",),
    ),
    "units": Topic(
        "explain.units.title",
        "explain.units.what",
        "explain.units.warn",
        "explain.units.todo",
        covers=(
            "label.failed_units",
            "label.units",
            "units.none",
            "units.failed_count",
            "section.services",
        ),
        hints=("units.failed",),
    ),
    "services": Topic(
        "explain.services.title",
        "explain.services.what",
        "explain.services.warn",
        "explain.services.todo",
        covers=(
            "label.unit_row",
            "unit.state",
            "unit.state_sub",
            "unit.not_found",
            "unit.masked",
            "unit.unknown",
        ),
    ),
    "files": Topic(
        "explain.files.title",
        "explain.files.what",
        "explain.files.warn",
        "explain.files.todo",
        covers=("label.file_row", "file_age.missing", "file_age.unreadable"),
    ),
    "containers": Topic(
        "explain.containers.title",
        "explain.containers.what",
        "explain.containers.warn",
        "explain.containers.todo",
        covers=(
            "label.containers",
            "label.docker",
            "label.podman",
            "label.running",
            "label.unhealthy",
            "containers.summary",
            "containers.summary_problems",
            "containers.not_running",
            "containers.unreachable",
            "section.containers",
        ),
    ),
    "plugins": Topic(
        "explain.plugins.title",
        "explain.plugins.what",
        todo="explain.plugins.todo",
        covers=("plugin.prefix", "section.plugins"),
    ),
    "collector": Topic(
        "explain.collector.title",
        "explain.collector.what",
        "explain.collector.warn",
        "explain.collector.todo",
        covers=(
            "render.cache_old",
            "render.no_cache",
            "modules.failed",
            "config.ignored",
            "status.module_failed",
        ),
        hints=("cache.stale", "modules.failed", "config.check"),
    ),
}


def _commands(topic: Topic, package_manager: str) -> "list[tuple[str, str, str]]":
    """``(command, package manager it is for or "", hint message id)``, each once.

    With a known package manager only its commands are listed; otherwise all of them,
    those that differ marked with their package manager.
    """
    found: dict[tuple[str, str, str], None] = {}
    for hint_id in topic.hints:
        entry = hints.HINTS[hint_id]
        if package_manager:
            looked = hints.lookup(hint_id, package_manager)
            choices = [("", looked[1])] if looked and looked[1] else []
        else:
            choices = [("" if k == hints.ANY else k, v) for k, v in entry.commands.items()]
        for manager, command in choices:
            if not command.startswith(SELF):
                found[(command, manager, entry.message)] = None
    return list(found)


def _wrapped(text: str, width: int, indent: str, ascii_only: bool) -> list[str]:
    if ascii_only:
        text = sanitize(text, _ALL_CELLS, ascii_only=True)
    return textwrap.wrap(
        text,
        width,
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def topic_list(tr: Translator, width: int, ascii_only: bool) -> list[str]:
    """Every topic with its title."""
    width = max(MIN_WIDTH, min(width, MAX_WIDTH))
    column = max(len(name) for name in TOPICS) + 2
    lines = _wrapped(tr.message("explain.list.heading"), width, "", ascii_only)
    for name, topic in TOPICS.items():
        title = tr.message(topic.title)
        if ascii_only:
            title = sanitize(title, _ALL_CELLS, ascii_only=True)
        lines.append(f"{INDENT}{name:<{column}}{title}")
    return lines


def _key(text: str) -> str:
    return " ".join(text.casefold().replace("-", " ").replace("_", " ").split())


def find_topic(tr: Translator, name: str) -> Optional[str]:
    """The topic ``name`` asks for: its name, the name with or without a final "s"
    ("disk" for "disks"), or the label of a row it covers, in English or the reader's
    language ("Failed logins", "Fehlanmeldungen"; final review, usability item 15)."""
    want = _key(name)
    for candidate in (want, want + "s", want[:-1] if want.endswith("s") else want):
        name_ = candidate.replace(" ", "_")
        if name_ in TOPICS:
            return name_
    english = translator("en")
    for topic_name, topic in TOPICS.items():
        for msg_id in topic.covers:
            if not msg_id.startswith("label.") or not want:
                continue
            try:
                labels = {_key(english.message(msg_id)), _key(tr.message(msg_id))}
            except (KeyError, ValueError):
                continue  # a label with a parameter (a mount point) names no topic
            if want in labels:
                return topic_name
    return None


def page(
    tr: Translator,
    name: str,
    *,
    rules: Mapping[str, Rule],
    package_manager: str,
    width: int,
    ascii_only: bool,
) -> Optional[list[str]]:
    """The lines that explain ``name``; ``None`` for a topic nobody knows."""
    found = find_topic(tr, name)
    if found is None:
        return None
    topic = TOPICS[found]
    width = max(MIN_WIDTH, min(width, MAX_WIDTH))

    def paragraph(msg_id: str, indent: str = "") -> list[str]:
        return _wrapped(tr.message(msg_id), width, indent, ascii_only)

    lines = [*paragraph(topic.title), "", *paragraph(topic.what)]
    for heading, body in (
        ("explain.heading.warn", topic.warn),
        ("explain.heading.todo", topic.todo),
    ):
        if body:
            lines += ["", *paragraph(heading), *paragraph(body, INDENT)]
    limits = [rules[rule] for rule in topic.rules if rule in rules]
    for rule in limits:
        values = {"warn": f"{rule.warn:g}", "crit": f"{rule.crit:g}", "rule": rule.name}
        lines += ["", *_wrapped(tr.message("explain.limits", values), width, "", ascii_only)]
    commands = _commands(topic, package_manager)
    if commands:
        lines += ["", *paragraph("explain.heading.commands")]
        for command, manager, message in commands:
            lines.append(INDENT + command + (f"  ({manager})" if manager else ""))
            lines += paragraph(message, HINT_INDENT)
    return lines

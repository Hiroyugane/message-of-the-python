"""``app_containers``: running and unhealthy containers (blueprint 4.3, 5.4, D12, phase 11).

Runs as a cached module in a probe process **as root**: the runtimes' sockets belong to
root (Docker's group ``docker`` is root by another name, 5.6). It asks each runtime that
listens on its system socket one fixed, read-only question,

    GET /containers/json?all=1

through ``Context.unix_get`` (``collect.unixhttp``): a ``GET`` and nothing else, a target
fixed here, root's socket in root's directories, a root process behind it, the probe's
deadline and a cap on the answer. A runtime's API can start containers, and a container
can be root on the host, so the module has no other request and no way to build one from
anything it reads. It does not start the ``docker`` or ``podman`` programs: their
behaviour depends on config files and environment, and rootful Podman's program needs
write access the sandbox denies.

* Docker: ``/run/docker.sock``, only while ``docker.service`` is active: systemd keeps
  the socket open after ``systemctl stop docker`` and would start Docker (and its
  containers with a restart policy) on the probe's connection. A stopped Docker is an
  admin row instead. Without systemd the socket is asked directly.
* Podman: ``/run/podman/podman.sock``, which exists only where the admin enabled
  ``podman.socket``; Podman answers the same request in Docker's form there. Without it
  the module does not see Podman's containers (decision log, phase 11).

**What leaves the probe.** Counts by state, public (5.4). For admins, the names and
images of the running containers and of those that are unhealthy or restarting. Names,
images and states are the runtime's account of text that whoever starts a container
chooses, so each is sanitised and cut before it is joined into a list; the collector
sanitises again when it accepts the document.
"""

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from motp.core import strictjson
from motp.core.model import ContractError, Detail, Item, Status, Unit, Visibility, ref
from motp.core.sanitize import sanitize
from motp.modules import rows_unit, services
from motp.modules.base import CACHED, Context, Detection, context_error, parse_error

TARGET = "/containers/json?all=1"
# (key, socket, label id, service unit)
RUNTIMES = (
    ("docker", "/run/docker.sock", "label.docker", "docker.service"),
    ("podman", "/run/podman/podman.sock", "label.podman", "podman.service"),
)
# Services whose socket starts the whole daemon, and with it every container that has a
# restart policy: their socket is asked only while the service already runs, so a probe
# never brings back a Docker the admin stopped (security review of phase 11). Podman's
# socket starts ``podman system service``, which starts no container: that is the way
# Podman's API is meant to be used, so it is asked whenever the socket exists.
ACTIVATING_DAEMONS = ("docker.service",)
MAX_ANSWER = 8 * 1024 * 1024  # about 4,000 containers with their labels
MAX_DEPTH = 16
MAX_CONTAINERS = 4096
NAME_CELLS = 40
IMAGE_CELLS = 40
LIST_CHARS = 100
RUNNING = "running"
PROBLEM_STATES = ("restarting",)


def _text(value: object, cells: int) -> str:
    return sanitize(value, cells) if isinstance(value, str) else ""


def container_name(entry: Mapping[str, Any]) -> str:
    names = entry.get("Names")
    first = names[0] if isinstance(names, list) and names else ""
    name = first[1:] if isinstance(first, str) and first.startswith("/") else first
    return _text(name, NAME_CELLS)


def image_name(entry: Mapping[str, Any]) -> str:
    image = entry.get("Image")
    if isinstance(image, str) and image.startswith("sha256:"):
        image = image[:19]  # sha256: and 12 hex digits, as the runtimes print an id
    return _text(image, IMAGE_CELLS)


def is_unhealthy(entry: Mapping[str, Any]) -> bool:
    """Docker and Podman put ``(unhealthy)`` into the status text; newer Docker also
    sends a ``Health`` object."""
    health = entry.get("Health")
    if isinstance(health, dict) and health.get("Status") == "unhealthy":
        return True
    status = entry.get("Status")
    return isinstance(status, str) and "(unhealthy)" in status


def parse(body: bytes) -> "list[Mapping[str, Any]]":
    """The list of containers; an answer of another shape fails the module."""
    try:
        data = strictjson.loads(body, max_bytes=MAX_ANSWER, max_depth=MAX_DEPTH)
    except ContractError as exc:
        raise parse_error("app_containers") from exc
    if not isinstance(data, list) or len(data) > MAX_CONTAINERS:
        raise parse_error("app_containers")
    if any(
        not isinstance(entry, dict) or not isinstance(entry.get("State"), str) for entry in data
    ):
        raise parse_error("app_containers")
    return data


def name_list(entries: Sequence[Mapping[str, Any]]) -> str:
    """``web (nginx:1.27), db (postgres:16), +3``: as many as fit."""
    words = []
    for entry in sorted(entries, key=container_name):
        name, image = container_name(entry), image_name(entry)
        words.append(f"{name} ({image})" if image else name)
    shown: list[str] = []
    length = 0
    for word in words:
        length += len(word) + 2
        if shown and length > LIST_CHARS:
            break
        shown.append(word)
    if len(shown) < len(words):
        shown.append(f"+{len(words) - len(shown)}")
    return ", ".join(shown)


def runtime_item(key: str, label: str, containers: "list[Mapping[str, Any]]") -> Item:
    """Counts by state, which add up to the number of containers: running (of which some
    may be unhealthy), restarting, and stopped (every other state)."""
    running = [c for c in containers if c["State"] == RUNNING]
    restarting = [c for c in containers if c["State"] in PROBLEM_STATES]
    unhealthy = [c for c in running if is_unhealthy(c)]
    stopped = len(containers) - len(running) - len(restarting)
    problems = unhealthy + restarting
    detail: list[Detail] = []
    if problems:
        detail.append(
            Detail(
                f"app_containers.{key}_problems", name_list(problems), label=ref("label.unhealthy")
            )
        )
    if running:
        detail.append(
            Detail(f"app_containers.{key}_running", name_list(running), label=ref("label.running"))
        )
    if problems:
        text = ref(
            "containers.summary_problems",
            running=len(running),
            unhealthy=len(unhealthy),
            restarting=len(restarting),
            stopped=stopped,
        )
    else:
        text = ref("containers.summary", running=len(running), stopped=stopped)
    return Item(
        key=f"app_containers.{key}",
        value=len(running),
        unit=Unit.COUNT,
        label=ref(label),
        status=Status.WARN if problems else Status.OK,
        text=text,
        visibility=Visibility.PUBLIC,
        detail=tuple(detail),
    )


def stopped_item(key: str, label: str) -> Item:
    """The runtime's service is stopped: said to admins, and the socket is left alone."""
    return Item(
        key=f"app_containers.{key}",
        value=None,
        unit=Unit.COUNT,
        label=ref(label),
        status=Status.UNKNOWN,
        text=ref("containers.not_running"),
        visibility=Visibility.ADMIN,
    )


def unreachable_item(key: str, label: str) -> Item:
    return Item(
        key=f"app_containers.{key}",
        value=None,
        unit=Unit.COUNT,
        label=ref(label),
        status=Status.WARN,
        text=ref("containers.unreachable"),
        visibility=Visibility.ADMIN,
    )


def service_states(ctx: Context) -> "Optional[dict[str, str]]":
    """unit -> ActiveState of the runtimes' services; ``None`` without systemd."""
    if not ctx.exists(services.SYSTEMD_RUNNING):
        return None
    units = [unit for _key, _path, _label, unit in RUNTIMES]
    text = ctx.run(rows_unit.argv(units)).decode("utf-8", "replace")
    blocks = rows_unit.parse_show(text, len(units))
    states: dict[str, str] = {}
    for unit, values in zip(units, blocks):
        if values.get("Id") not in (unit, None):
            raise parse_error("app_containers")
        states[unit] = values.get("ActiveState", "")
    return states


class AppContainers:
    name = "app_containers"
    section = "containers"
    mode = CACHED
    needs_root = True
    interval = 300
    max_age = 1800
    timeout = 10.0
    binaries: tuple[str, ...] = (services.SYSTEMCTL,)
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(any(ctx.exists(path) for _key, path, _label, _unit in RUNTIMES))

    def collect(self, ctx: Context) -> list[Item]:
        """One item per runtime whose socket exists. A runtime that does not answer is
        an admin warning; the module fails only when no runtime answered."""
        present = [r for r in RUNTIMES if ctx.exists(r[1])]
        states = service_states(ctx) if present else None
        items: list[Item] = []
        answered = 0
        for key, path, label, unit in present:
            if states is not None and unit in ACTIVATING_DAEMONS and states.get(unit) != "active":
                items.append(stopped_item(key, label))  # connecting would start it
                continue
            try:
                containers = parse(ctx.unix_get(path, TARGET, MAX_ANSWER))
            except ValueError:
                items.append(unreachable_item(key, label))
                continue
            answered += 1
            items.append(runtime_item(key, label, containers))
        if present and not answered and not any(i.status is Status.UNKNOWN for i in items):
            raise context_error("context.error.socket")
        return items

"""A fake system for the tests of the package modules (phase 9).

The files below ``fixtures/packages`` are the real output of each tier-1 image, taken with
the modules' own command lines (``tools/capture_package_fixtures.py``). ``System`` holds
the files a module may ask about and answers the programs it may start.
"""

import contextlib
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Optional

from motp.collect import child
from motp.collect.context import ProbeContext
from motp.core import probe
from motp.core.i18n import translator
from motp.core.model import HintRef, Item, MessageRef, ModuleResult
from motp.modules import packages, registry
from motp.modules.base import context_error, parse_os_release
from motp.render import view
from motp.render.view import RenderInput, Source

from .support import FIXTURES, NOW

CAPTURES = FIXTURES / "packages"
APT_DISTROS = ("debian12", "ubuntu2204")
DNF_DISTROS = ("almalinux9", "fedora45")
ALL_DISTROS = APT_DISTROS + DNF_DISTROS
DAY = 86400


def captured(distro: str, name: str) -> str:
    return (CAPTURES / distro / name).read_text(encoding="utf-8")


class System(ProbeContext):
    """A fake system: files with their contents, modification times and program output."""

    def __init__(
        self,
        files: Optional[dict[str, str]] = None,
        *,
        outputs: Optional[Mapping[Any, str]] = None,
        mtimes: Optional[dict[str, int]] = None,
        os_release: Optional[dict[str, str]] = None,
        binaries: tuple[str, ...] = (),
        now: int = NOW,
    ) -> None:
        super().__init__(now=now, os_release=os_release or {}, binaries=binaries)
        object.__setattr__(self, "files", dict(files or {}))
        object.__setattr__(self, "outputs", dict(outputs or {}))
        object.__setattr__(self, "mtimes", dict(mtimes or {}))
        object.__setattr__(self, "calls", [])
        object.__setattr__(self, "scratch", [])

    SCRATCH = "/var/tmp/motp-scratch"  # noqa: S108  (a name in a fake system)
    files: dict[str, str]
    outputs: dict[tuple[str, ...], str]
    mtimes: dict[str, int]
    calls: list[tuple[str, ...]]
    scratch: list[str]

    @contextlib.contextmanager
    def scratch_dir(self) -> Iterator[str]:
        self.scratch.append("made")
        try:
            yield self.SCRATCH
        finally:
            self.scratch.append("removed")

    def _is_dir(self, path: str) -> bool:
        return any(name.startswith(path + "/") for name in self.files)

    def _exists(self, path: str) -> bool:
        return path in self.files or self._is_dir(path)

    def _read_bytes(self, path: str, max_bytes: int) -> bytes:
        if path not in self.files:
            raise context_error("context.error.read")
        return self.files[path].encode("utf-8")[:max_bytes]

    def _list_dir(self, path: str) -> list[str]:
        if not self._is_dir(path):
            raise context_error("context.error.read")
        prefix = path + "/"
        return sorted({n[len(prefix) :].split("/")[0] for n in self.files if n.startswith(prefix)})

    def _mtime(self, path: str) -> int:
        if path in self.mtimes:
            return self.mtimes[path]
        if not self._exists(path):
            raise context_error("context.error.read")
        return self.now - 3600

    def run(self, argv: Sequence[str], ok_codes: tuple[int, ...] = (0,)) -> bytes:
        args = tuple(argv)
        assert args[0] in self.binaries, f"{args[0]} is not in the module's binaries"
        self.calls.append(args)
        if args not in self.outputs:
            raise context_error("context.error.run_failed")
        return self.outputs[args].encode("utf-8")


def base_files(distro: str) -> dict[str, str]:
    """The programs and package lists each image has."""
    files = {"/etc/os-release": captured(distro, "os-release")}
    if distro in APT_DISTROS:
        files[packages.APT_GET] = ""
        for name in captured(distro, "lists.txt").split():
            files[f"/var/lib/apt/lists/{name}"] = ""
        return files
    dnf5 = distro == "fedora45"
    files[packages.RPM] = ""
    files[packages.DNF] = ""
    if dnf5:
        files[packages.DNF5_PROGRAM] = ""
    cache_dir = "/var/cache/libdnf5" if dnf5 else "/var/cache/dnf"
    for name in captured(distro, "lists.txt").split():
        files[f"{cache_dir}/{name}/repodata/repomd.xml"] = ""
        if not name.startswith(("extras", "fedora-")):  # as in the captured caches
            files[f"{cache_dir}/{name}/repodata/0a-updateinfo.xml.zck"] = ""
    return files


def system(
    distro: str,
    module: object,
    files: Optional[dict[str, str]] = None,
    outputs: Optional[Mapping[Any, str]] = None,
    **kwargs: object,
) -> System:
    release = parse_os_release(captured(distro, "os-release"))
    return System(
        {**base_files(distro), **(files or {})},
        outputs=outputs,
        os_release=release,
        binaries=tuple(module.binaries),  # type: ignore[attr-defined]
        **kwargs,  # type: ignore[arg-type]
    )


def only(items: "list[Item]") -> Item:
    assert len(items) == 1
    return items[0]


def through_the_contract(name: str, items: "list[Item]") -> "tuple[Item, ...]":
    """The items as the collector accepts them from the probe's document."""
    module = registry.cached_module(name)
    assert module is not None
    return probe.validate_builtin(
        child.document(name, items), name, module.default_visibility
    ).items


def text_of(item: Item) -> str:
    assert isinstance(item.text, MessageRef)
    return translator("en").text(item.text)


def hint_of(item: Item) -> str:
    assert isinstance(item.hint, HintRef)
    return item.hint.id


def detail_of(item: Item, key: str) -> str:
    return str(next(d.value for d in item.detail if d.key == key))


def render_for(name: str, items: "list[Item]", admin: bool, manager: str = "apt") -> view.View:
    module = registry.cached_module(name)
    assert module is not None
    result = ModuleResult(
        collected=NOW, interval=module.interval, max_age=module.max_age, items=tuple(items)
    )
    source = Source(name, module.section, result)
    return view.build(RenderInput((source,), NOW, "web01", package_manager=manager, admin=admin))


def alerts(shown: view.View) -> list[view.Alert]:
    return [alert for section in shown.sections for alert in section.alerts]


def everything(shown: view.View) -> str:
    return repr(shown)

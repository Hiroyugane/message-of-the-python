"""Helpers shared by the phase 5 tests: a fixture context and a cache-directory builder."""

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Optional

from motp.collect.context import ProbeContext
from motp.core import cache
from motp.core.cache import Layout, RenderSettings
from motp.core.model import ModuleResult
from motp.core.thresholds import Rule
from motp.modules.base import Context, FsUsage, context_error

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = 1795600000


class FixtureContext(Context):
    """A ``Context`` that serves ``/proc`` and ``/sys`` files from a fixture tree."""

    _root: Path

    def __init__(self, tree: str, now: int = NOW, root: Optional[Path] = None) -> None:
        super().__init__(now=now)
        object.__setattr__(self, "_root", (root or FIXTURES) / tree)

    def _file(self, path: str) -> Path:
        return self._root / path.lstrip("/").replace(":", "_")  # no ":" in Windows names

    def _read_bytes(self, path: str, max_bytes: int) -> bytes:
        try:
            return self._file(path).read_bytes()[:max_bytes]
        except OSError as exc:
            raise context_error("context.error.read") from exc

    def _exists(self, path: str) -> bool:
        return self._file(path).is_file()


class FixtureProbeContext(ProbeContext):
    """A probe ``ProbeContext`` serving a fixture tree and a table of file system usage."""

    _root: Path
    _usage: Mapping[str, FsUsage]

    def __init__(
        self,
        tree: str,
        now: int = NOW,
        usage: Optional[Mapping[str, FsUsage]] = None,
        os_release: Optional[Mapping[str, str]] = None,
        root: Optional[Path] = None,
    ) -> None:
        super().__init__(now=now, os_release=dict(os_release or {}))
        object.__setattr__(self, "_root", (root or FIXTURES) / tree)
        object.__setattr__(self, "_usage", dict(usage or {}))

    def _file(self, path: str) -> Path:
        return self._root / path.lstrip("/").replace(":", "_")  # no ":" in Windows names

    def _read_bytes(self, path: str, max_bytes: int) -> bytes:
        try:
            return self._file(path).read_bytes()[:max_bytes]
        except OSError as exc:
            raise context_error("context.error.read") from exc

    def _exists(self, path: str) -> bool:
        return self._file(path).exists()

    def _statvfs(self, path: str) -> FsUsage:
        try:
            return self._usage[path]
        except KeyError:
            raise context_error("context.error.statvfs") from None


GIB = 1024**3


def usage(size_gib: float, used_percent: float, inodes: int = 0, inodes_used: float = 0) -> FsUsage:
    """File system usage with no reserved blocks: ``used_percent`` of ``size_gib`` used."""
    size = int(size_gib * GIB)
    free = size - int(size * used_percent / 100)
    inodes_free = inodes - int(inodes * inodes_used / 100)
    return FsUsage(
        size=size,
        free=free,
        available=free,
        inodes=inodes,
        inodes_free=inodes_free,
        inodes_available=inodes_free,
        fsid=0,
    )


def write_cache(
    directory: Path,
    modules: Mapping[str, ModuleResult],
    *,
    admin: Optional[Mapping[str, ModuleResult]] = None,
    settings: Optional[RenderSettings] = None,
    generated: int = NOW,
    failed: int = 0,
) -> Path:
    """Write ``public.json``, optionally ``admin.json`` and ``render.json`` into a directory."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "public.json").write_bytes(
        cache.encode_tier_file(cache.PUBLIC, generated, modules, failed)
    )
    if admin is not None:
        (directory / "admin.json").write_bytes(
            cache.encode_tier_file(cache.ADMIN, generated, admin, failed)
        )
    if settings is not None:
        (directory / "render.json").write_bytes(cache.encode_render_file(settings))
    if os.name == "posix":
        for path in directory.iterdir():
            path.chmod(0o644)
    return directory


def render_settings(
    rules: Optional[Mapping[str, Rule]] = None,
    layout: Optional[Layout] = None,
    language: str = "auto",
    timer_period: int = 300,
    render_ms: int = 1000,
) -> RenderSettings:
    return RenderSettings(
        generated=NOW,
        layout=layout or Layout(),
        language=language,
        thresholds=dict(rules or {}),
        timer_period=timer_period,
        render_ms=render_ms,
        package_manager="apt",
    )

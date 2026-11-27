"""``hw_memory``: memory and swap from ``/proc/meminfo`` (blueprint 4.3).

Used memory is ``MemTotal - MemAvailable`` (kernel 3.14 and newer); on older kernels the
free, buffered and cached amounts stand in for ``MemAvailable``. The rows carry the used
share in percent, so the rules ``memory_used_percent`` and ``swap_used_percent`` judge them,
and a text such as ``5.9 GiB of 7.9 GiB``. Swap is left out when the system has none.
"""

from motp.core.model import Item, Unit, Visibility, ref
from motp.modules.base import LIVE, Context, Detection, format_bytes, parse_error

MEMINFO = "/proc/meminfo"
KIB = 1024
MAX_KIB = 1 << 50


def parse_meminfo(text: str) -> dict[str, int]:
    """Field name -> kibibytes, for the lines that look like ``Name:   123 kB``."""
    fields: dict[str, int] = {}
    for line in text.splitlines():
        name, colon, rest = line.partition(":")
        parts = rest.split()
        if colon and parts and parts[0].isdigit():
            number = int(parts[0])
            if number < MAX_KIB:
                fields[name] = number
    return fields


def _share(used: int, total: int) -> float:
    return round(100.0 * used / total, 1)


class HwMemory:
    name = "hw_memory"
    section = "system"
    mode = LIVE
    needs_root = False
    interval = 1
    max_age = 60
    timeout = 0.2
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(MEMINFO))

    def collect(self, ctx: Context) -> list[Item]:
        fields = parse_meminfo(ctx.read_text(MEMINFO))
        total = fields.get("MemTotal", 0)
        if total <= 0:
            raise parse_error(self.name)
        if "MemAvailable" in fields:
            available = fields["MemAvailable"]
        else:
            available = sum(fields.get(k, 0) for k in ("MemFree", "Buffers", "Cached"))
        used = min(max(total - available, 0), total)
        items = [
            Item(
                key="hw_memory.used",
                value=_share(used, total),
                unit=Unit.PERCENT,
                label=ref("label.memory"),
                rule="memory_used_percent",
                text=ref(
                    "memory.summary", used=format_bytes(used * KIB), total=format_bytes(total * KIB)
                ),
            )
        ]
        swap_total = fields.get("SwapTotal", 0)
        if swap_total > 0:
            swap_used = min(max(swap_total - fields.get("SwapFree", 0), 0), swap_total)
            items.append(
                Item(
                    key="hw_memory.swap",
                    value=_share(swap_used, swap_total),
                    unit=Unit.PERCENT,
                    label=ref("label.swap"),
                    rule="swap_used_percent",
                    text=ref(
                        "memory.summary",
                        used=format_bytes(swap_used * KIB),
                        total=format_bytes(swap_total * KIB),
                    ),
                )
            )
        return items

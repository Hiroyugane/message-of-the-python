"""``hw_load``: the load averages, judged per CPU core (blueprint 4.3, 4.5).

The rule ``load_per_core`` is applied to the 5-minute average divided by the number of
online CPUs: the 1-minute value jumps with every compile at login time, the 15-minute value
reacts too late. All three averages are shown in the text.
"""

from motp.core.model import Item, Unit, Visibility, ref
from motp.modules.base import LIVE, Context, Detection, parse_error

LOADAVG = "/proc/loadavg"
CPU_ONLINE = "/sys/devices/system/cpu/online"
CPUINFO = "/proc/cpuinfo"
MAX_CPUS = 1 << 16


def parse_cpu_list(text: str) -> int:
    """Count the CPUs in a kernel list such as ``0-3,6``; 0 for anything else."""
    total = 0
    for part in text.strip().split(","):
        low, dash, high = part.partition("-")
        if not low.isdigit() or (dash and not high.isdigit()):
            return 0
        first = int(low)
        last = int(high) if dash else first
        if last < first or last >= MAX_CPUS:
            return 0
        total += last - first + 1
    return total


def cpu_count(ctx: Context) -> int:
    """Online CPUs from ``/sys``, else the ``processor`` lines of ``/proc/cpuinfo``, else 1."""
    try:
        count = parse_cpu_list(ctx.read_text(CPU_ONLINE, 256))
    except ValueError:
        count = 0
    if count:
        return count
    try:
        text = ctx.read_text(CPUINFO)
    except ValueError:
        return 1
    count = sum(1 for line in text.splitlines() if line.startswith("processor"))
    return count or 1


def parse_loadavg(text: str) -> tuple[float, float, float]:
    fields = text.split()
    try:
        values = tuple(float(f) for f in fields[:3])
    except ValueError:
        values = ()
    if len(values) != 3 or any(not 0 <= v < 1e9 for v in values):  # NaN fails the range too
        raise parse_error("hw_load")
    return values[0], values[1], values[2]


class HwLoad:
    name = "hw_load"
    section = "system"
    mode = LIVE
    needs_root = False
    interval = 1
    max_age = 60
    timeout = 0.2
    binaries: tuple[str, ...] = ()
    default_visibility = Visibility.PUBLIC

    def detect(self, ctx: Context) -> Detection:
        return Detection(ctx.exists(LOADAVG))

    def collect(self, ctx: Context) -> list[Item]:
        one, five, fifteen = parse_loadavg(ctx.read_text(LOADAVG, 256))
        cores = cpu_count(ctx)
        return [
            Item(
                key="hw_load.per_core",
                value=round(five / cores, 3),
                unit=Unit.RATIO,
                label=ref("label.load"),
                rule="load_per_core",
                text=ref(
                    "load.summary", one=f"{one:.2f}", five=f"{five:.2f}", fifteen=f"{fifteen:.2f}"
                ),
            )
        ]

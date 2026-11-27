"""The wall-clock limit of the render path (blueprint 4.14, threat T4).

``motp show`` arms this first thing in ``__main__``. When the limit passes, the handler
calls ``os._exit(0)``: the process ends at once, silently, with exit code 0. Nothing in the
program can swallow that, because no exception is raised: ``except BaseException`` and
``finally`` blocks never see it, and a module stuck in ``time.sleep`` or a blocking read is
interrupted by the signal.

Limits, stated plainly (4.14): the timer takes effect between Python instructions and in
interruptible system calls. Interpreter start and the first imports happen before it is
armed, and a process blocked inside the kernel on the program's own files cannot be ended.
The limit can also fire while the single output write is blocked (a terminal paused with
Ctrl-S), which leaves a cut message on the screen; the timer stays armed during the write on
purpose, since a blocked terminal must not hang the login.

On systems without ``SIGALRM`` (a Windows development machine) a daemon timer thread does
the same job. ``signal`` is imported here and in ``core/proc.py`` only; a guard test keeps
every other module of the render path away from it, so no render code can replace the
handler.
"""

import os
import signal
import time

DEFAULT_SECONDS = 1.0
MIN_SECONDS = 0.001

_started = 0.0


def _expire(*_args: object) -> None:
    os._exit(0)


def _set_timer(seconds: float) -> None:
    seconds = max(seconds, MIN_SECONDS)
    setitimer = getattr(signal, "setitimer", None)
    if setitimer is not None and hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _expire)
        setitimer(signal.ITIMER_REAL, seconds)
        return
    import threading  # only where there is no SIGALRM

    timer = threading.Timer(seconds, _expire)
    timer.daemon = True
    timer.start()


def arm(seconds: float = DEFAULT_SECONDS) -> None:
    """Start the limit: ``seconds`` from now the process ends with exit code 0."""
    global _started
    _started = time.monotonic()
    _set_timer(seconds)


def limit(total: float) -> None:
    """Change the limit to ``total`` seconds counted from ``arm`` (``render_ms`` of the cache).

    Shortens or extends the running limit; if ``total`` has already passed, the process
    ends at once. On the thread fallback the earlier timer keeps running as well, so there
    the shorter of the two applies.
    A limit that was never armed stays off, so tests that call ``show`` in-process arm no
    timer.
    """
    if _started:
        _set_timer(total - (time.monotonic() - _started))


def disarm() -> None:
    """Cancel the limit (tests). ``limit`` stays off until the next ``arm``."""
    global _started
    _started = 0.0
    setitimer = getattr(signal, "setitimer", None)
    if setitimer is not None and hasattr(signal, "SIGALRM"):
        setitimer(signal.ITIMER_REAL, 0)

"""The local-socket client of phase 11 (``collect.unixhttp``) and ``ProbeContext.unix_get``:
one fixed ``GET``, a deadline for everything, a cap on the answer, no redirects, and as
root only a root socket served by a root process."""

import contextlib
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Callable, Optional

import pytest

from motp.collect import unixhttp
from motp.collect.context import ProbeContext
from motp.core.model import ContractError
from motp.modules.base import Context

linux = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="needs Unix sockets with SO_PEERCRED"
)
root_only = pytest.mark.skipif(
    not sys.platform.startswith("linux") or getattr(os, "geteuid", lambda: 1)() != 0,
    reason="needs Linux and root (runs inside the CI containers)",
)

OK = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]"


# --- the request and the answer --------------------------------------------------------


def test_the_request_is_one_fixed_get() -> None:
    assert unixhttp.request_bytes("/containers/json?all=1") == (
        b"GET /containers/json?all=1 HTTP/1.0\r\nHost: localhost\r\nUser-Agent: motp\r\n"
        b"Accept: application/json\r\nConnection: close\r\n\r\n"
    )


@pytest.mark.parametrize(
    "target",
    [
        "containers/json",
        "/containers/json\r\nX-Evil: 1",
        "/containers/json HTTP/1.1\r\n\r\nPOST /containers/create",
        "/a b",
        "/" + "a" * 300,
        "/containers/json?all=1#x",
        "http://example.com/",
        "",
    ],
)
def test_a_target_with_anything_but_plain_path_characters_is_refused(target: str) -> None:
    with pytest.raises(unixhttp.UnixHttpError):
        unixhttp.request_bytes(target)


def test_a_plain_answer() -> None:
    assert unixhttp.parse_response(OK, 100) == b"[]"
    assert unixhttp.parse_response(b"HTTP/1.0 200 OK\r\n\r\n[1]", 100) == b"[1]"


def test_a_chunked_answer() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"3\r\n[1,\r\n2;ext=1\r\n2]\r\n0\r\nTrailer: x\r\n\r\n"
    )
    assert unixhttp.parse_response(raw, 100) == b"[1,2]"


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: /elsewhere\r\n\r\n",
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n[]",  # cut short
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n[]",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n[]",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n[]\r\n",  # cut chunk
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        b"HTTP/1.1 200 OK\r\n X: folded\r\n\r\n[]",
        b"HTTP/1.1 200 OK\r\n\r",  # no end of the header
        b"SSH-2.0-OpenSSH\r\n\r\n",
        b"\x1b[31mHTTP/1.1 200\r\n\r\n[]",
        b"HTTP/1.1 200 OK\r\n" + b"X: y\r\n" * 100 + b"\r\n[]",
    ],
)
def test_anything_but_a_complete_200_answer_is_refused(raw: bytes) -> None:
    with pytest.raises(unixhttp.UnixHttpError):
        unixhttp.parse_response(raw, 1024)


def test_the_body_cap_holds_for_both_forms() -> None:
    with pytest.raises(unixhttp.UnixHttpError):
        unixhttp.parse_response(b"HTTP/1.0 200 OK\r\n\r\n" + b"x" * 101, 100)
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"40\r\n" + b"x" * 64
    chunked += b"\r\n40\r\n" + b"x" * 64 + b"\r\n0\r\n\r\n"
    with pytest.raises(unixhttp.UnixHttpError):
        unixhttp.parse_response(chunked, 100)


def test_an_error_never_carries_the_answer() -> None:
    try:
        unixhttp.parse_response(b"HTTP/1.1 302 \x1b]0;owned\x07\r\n\r\n", 100)
    except unixhttp.UnixHttpError as exc:
        assert str(exc) == "status"  # the word, never the reason text


def test_a_live_module_cannot_talk_to_a_socket() -> None:
    with pytest.raises(ContractError):
        Context().unix_get("/run/docker.sock", "/containers/json", 100)


@pytest.mark.parametrize(
    "path", ["/var/run/../tmp/docker.sock", "/home/docker.sock", "run/docker.sock", "/etc/x"]
)
def test_the_context_connects_below_run_only(path: str) -> None:
    with pytest.raises(ContractError):
        ProbeContext().unix_get(path, "/containers/json", 100)


def test_the_context_refuses_when_the_deadline_has_passed() -> None:
    ctx = ProbeContext(deadline=10.0, clock=lambda: 10.0)
    with pytest.raises(ContractError):
        ctx.unix_get("/run/docker.sock", "/containers/json", 100)


# --- a real socket (Linux) -------------------------------------------------------------


Handler = Callable[[socket.socket], None]


@pytest.fixture
def server() -> Iterator[Callable[[Handler], str]]:
    """Serve connections on a Unix socket with ``handler``; yields a starter."""
    made: list[tuple[socket.socket, threading.Thread, str]] = []

    def start(handler: Handler, parent: Optional[str] = None) -> str:
        directory = tempfile.mkdtemp(prefix="motp-sock-", dir=parent)
        path = os.path.join(directory, "api.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)

        def serve() -> None:  # every connection in turn, until the listener closes
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                with conn, contextlib.suppress(OSError):
                    handler(conn)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        made.append((listener, thread, directory))
        return path

    yield start
    for listener, thread, directory in made:
        listener.close()
        thread.join(timeout=5)
        shutil.rmtree(directory, ignore_errors=True)


def _answer(raw: bytes) -> Handler:
    def handler(conn: socket.socket) -> None:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request += chunk
        assert request == unixhttp.request_bytes("/containers/json?all=1")
        conn.sendall(raw)

    return handler


def _uid() -> int:
    return os.getuid()


@linux
def test_a_real_answer_over_a_unix_socket(server: Callable[[Handler], str]) -> None:
    path = server(_answer(OK))
    body = unixhttp.get(
        path, "/containers/json?all=1", timeout=5, max_bytes=100, expect_peer_uid=_uid()
    )
    assert body == b"[]"


@linux
def test_a_server_of_another_user_is_refused(server: Callable[[Handler], str]) -> None:
    path = server(_answer(OK))
    with pytest.raises(unixhttp.UnixHttpError, match="peer_uid"):
        unixhttp.get(
            path, "/containers/json?all=1", timeout=5, max_bytes=100, expect_peer_uid=_uid() + 1
        )


@linux
def test_a_server_that_never_answers_costs_the_deadline_only(
    server: Callable[[Handler], str],
) -> None:
    hold = threading.Event()

    def silent(conn: socket.socket) -> None:
        hold.wait(10)

    path = server(silent)
    started = time.monotonic()
    with pytest.raises(unixhttp.UnixHttpError, match=r"recv|deadline"):
        unixhttp.get(
            path, "/containers/json?all=1", timeout=0.5, max_bytes=100, expect_peer_uid=_uid()
        )
    assert time.monotonic() - started < 2
    hold.set()


@linux
def test_a_server_that_trickles_is_held_to_one_deadline(
    server: Callable[[Handler], str],
) -> None:
    def trickle(conn: socket.socket) -> None:
        conn.recv(4096)
        for _ in range(50):
            conn.sendall(b"H")
            time.sleep(0.1)

    path = server(trickle)
    started = time.monotonic()
    with pytest.raises(unixhttp.UnixHttpError):
        unixhttp.get(
            path, "/containers/json?all=1", timeout=0.6, max_bytes=100, expect_peer_uid=_uid()
        )
    assert time.monotonic() - started < 2


@linux
def test_an_endless_answer_is_cut_at_the_cap(server: Callable[[Handler], str]) -> None:
    def flood(conn: socket.socket) -> None:
        conn.recv(4096)
        conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
        block = b"x" * 65536
        for _ in range(200):
            conn.sendall(block)

    path = server(flood)
    with pytest.raises(unixhttp.UnixHttpError, match="too_large"):
        unixhttp.get(
            path, "/containers/json?all=1", timeout=5, max_bytes=1024, expect_peer_uid=_uid()
        )


@linux
def test_a_redirect_is_not_followed(server: Callable[[Handler], str]) -> None:
    path = server(_answer(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /x\r\n\r\n"))
    with pytest.raises(unixhttp.UnixHttpError, match="status"):
        unixhttp.get(
            path, "/containers/json?all=1", timeout=5, max_bytes=100, expect_peer_uid=_uid()
        )


@root_only
def test_root_talks_only_to_a_root_socket_in_a_root_chain(
    server: Callable[..., str],
) -> None:
    path = server(_answer(OK), "/run")
    ctx = ProbeContext()
    assert ctx.unix_get(path, "/containers/json?all=1", 100) == b"[]"
    os.chmod(path, 0o666)  # anyone may write to it: refused
    with pytest.raises(ContractError):
        ctx.unix_get(path, "/containers/json?all=1", 100)
    os.chmod(path, 0o660)  # the docker group may: fine (5.6)
    assert ctx.unix_get(path, "/containers/json?all=1", 100) == b"[]"
    os.chown(path, 1000, 1000)
    with pytest.raises(ContractError):
        ctx.unix_get(path, "/containers/json?all=1", 100)


@root_only
def test_root_refuses_a_socket_below_a_directory_others_can_write(
    server: Callable[..., str],
) -> None:
    path = server(_answer(OK), "/run")
    os.chmod(os.path.dirname(path), 0o777)
    with pytest.raises(ContractError):
        ProbeContext().unix_get(path, "/containers/json?all=1", 100)


@root_only
def test_root_refuses_a_file_that_is_not_a_socket() -> None:
    directory = Path(tempfile.mkdtemp(prefix="motp-sock-", dir="/run"))
    try:
        (directory / "api.sock").write_text("HTTP/1.0 200 OK\r\n\r\n[]")
        with pytest.raises(ContractError):
            ProbeContext().unix_get(str(directory / "api.sock"), "/containers/json", 100)
    finally:
        shutil.rmtree(directory)


def test_a_socket_that_cannot_be_made_is_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Code review of phase 11: an OSError here escaped as a module bug."""
    monkeypatch.setattr(socket, "AF_UNIX", 1, raising=False)

    def refuse(*_args: object, **_kw: object) -> socket.socket:
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(socket, "socket", refuse)
    with pytest.raises(unixhttp.UnixHttpError, match="socket"):
        unixhttp.get("/run/x.sock", "/containers/json", timeout=1, max_bytes=10)

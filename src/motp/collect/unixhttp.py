"""One read-only HTTP request over a local Unix socket (blueprint 4.11, 5.3 T13, phase 11).

``app_containers`` asks the Docker or Podman service which containers exist. Their socket
is the runtime's whole API, so whoever can write to it controls every container and, as
root, the host. This client is built so that the only thing it can ever say is one
``GET`` of a path the caller fixes in code:

* **Local only.** The socket is ``AF_UNIX``; the module never resolves a name and never
  creates any other kind of socket. It is the one file of the package that may import
  ``socket`` (the guard of invariant 2 checks that it names no other address family),
  and the collector unit allows only ``AF_UNIX`` and ``AF_NETLINK`` anyway.
* **A fixed request.** The method is ``GET`` and nothing else; the target must match
  ``TARGET`` (a path and a query of plain characters), so no header, line break or
  second request can be smuggled in. The request asks the server to close the connection
  afterwards (``HTTP/1.0``).
* **The right server.** As root, the socket must sit in a directory chain only root can
  change (``safepath``), be a socket owned by root that others cannot write, and the
  process listening on it must be root (``SO_PEERCRED``). A socket some user started,
  even under a name the module would ask for, is refused.
* **Bounded answer.** One deadline for connect, send and every read; the header at most
  ``MAX_HEADER`` bytes, the body at most ``max_bytes``. A server that never answers
  costs the probe its deadline and nothing more.
* **No redirects, no surprises.** Only status 200 is an answer. ``Content-Length`` must
  match what arrived; ``chunked`` transfer encoding is decoded with the same limits; any
  other transfer or content encoding is refused.

Errors are ``UnixHttpError`` with a fixed reason word for the probe's stderr log; no part
of the answer goes into an error.
"""

import os
import re
import socket
import stat
import struct
import time
from typing import Callable, Optional

TARGET = re.compile(r"/[A-Za-z0-9/_.-]{0,200}(\?[A-Za-z0-9_.=&-]{0,200})?\Z")
MAX_HEADER = 16 * 1024
MAX_HEADER_LINES = 64
RECV_SIZE = 65536
_STATUS = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?\Z")
_CHUNK_SIZE = re.compile(rb"([0-9A-Fa-f]{1,8})(?:;[^\r\n]*)?\Z")
_PEERCRED = struct.Struct("3i")  # struct ucred: pid, uid, gid


class UnixHttpError(Exception):
    """The request failed; ``args[0]`` is a fixed reason word, never server text."""


def _refused(reason: str) -> UnixHttpError:
    return UnixHttpError(reason)


def request_bytes(target: str) -> bytes:
    """The one request this client sends, for a target that passed ``TARGET``."""
    if type(target) is not str or not TARGET.match(target):
        raise _refused("target")
    return (
        f"GET {target} HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "User-Agent: motp\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")


def check_socket_file(st: os.stat_result) -> None:
    """A socket file root owns and others cannot write (its group may: ``docker``)."""
    if not stat.S_ISSOCK(st.st_mode):
        raise _refused("not_socket")
    if st.st_uid != 0:
        raise _refused("socket_owner")
    if st.st_mode & stat.S_IWOTH:
        raise _refused("socket_mode")


def peer_uid(sock: socket.socket) -> int:
    """The uid of the process at the other end (Linux ``SO_PEERCRED``)."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise _refused("peercred")
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, option, _PEERCRED.size)
    except OSError as exc:
        raise _refused("peercred") from exc
    _pid, uid, _gid = _PEERCRED.unpack(raw)
    return int(uid)


def get(
    path: str,
    target: str,
    *,
    timeout: float,
    max_bytes: int,
    expect_peer_uid: Optional[int] = 0,
    clock: Callable[[], float] = time.monotonic,
) -> bytes:
    """``GET target`` on the socket at ``path`` (a checked real path); the body.

    ``expect_peer_uid`` is the uid the listening process must have (root in the
    collector; ``None`` skips the check, for tests on systems without it).
    """
    request = request_bytes(target)
    family = getattr(socket, "AF_UNIX", None)
    if family is None or timeout <= 0:
        raise _refused("unsupported" if family is None else "deadline")
    deadline = clock() + timeout
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:  # no descriptors left, or the family refused
        raise _refused("socket") from exc
    try:
        sock.settimeout(timeout)
        try:
            sock.connect(path)
        except OSError as exc:
            raise _refused("connect") from exc
        if expect_peer_uid is not None and peer_uid(sock) != expect_peer_uid:
            raise _refused("peer_uid")
        _send_all(sock, request, deadline, clock)
        raw = _read_all(sock, MAX_HEADER + max_bytes + MAX_HEADER, deadline, clock)
    finally:
        sock.close()
    return parse_response(raw, max_bytes)


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    left = deadline - clock()
    if left <= 0:
        raise _refused("deadline")
    return left


def _send_all(
    sock: socket.socket, data: bytes, deadline: float, clock: Callable[[], float]
) -> None:
    sent = 0
    while sent < len(data):
        sock.settimeout(_remaining(deadline, clock))
        try:
            sent += sock.send(data[sent:])
        except OSError as exc:  # socket.timeout is an OSError
            raise _refused("send") from exc


def _read_all(sock: socket.socket, cap: int, deadline: float, clock: Callable[[], float]) -> bytes:
    """Everything until the server closes, or fail past ``cap`` bytes or the deadline."""
    chunks: list[bytes] = []
    size = 0
    while True:
        sock.settimeout(_remaining(deadline, clock))
        try:
            chunk = sock.recv(RECV_SIZE)
        except OSError as exc:
            raise _refused("recv") from exc
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > cap:
            raise _refused("too_large")
        chunks.append(chunk)


def parse_response(raw: bytes, max_bytes: int) -> bytes:
    """The body of a complete ``200`` answer; anything else raises."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep or len(head) > MAX_HEADER:
        raise _refused("header")
    lines = head.split(b"\r\n")
    if len(lines) > MAX_HEADER_LINES:
        raise _refused("header")
    status = _STATUS.match(lines[0])
    if status is None:
        raise _refused("status_line")
    if status.group(1) != b"200":
        raise _refused("status")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not name or name != name.strip() or b" " in name:
            raise _refused("header")
        key = name.lower()
        if key in headers:  # a repeated length or encoding header is a smuggling trick
            raise _refused("header")
        headers[key] = value.strip()
    if headers.get(b"content-encoding", b"identity").lower() != b"identity":
        raise _refused("encoding")
    transfer = headers.get(b"transfer-encoding")
    if transfer is not None:
        if transfer.lower() != b"chunked" or b"content-length" in headers:
            raise _refused("encoding")
        return _dechunk(body, max_bytes)
    if b"content-length" in headers:
        length = headers[b"content-length"]
        if not length.isdigit() or len(length) > 12 or int(length) != len(body):
            raise _refused("length")
    if len(body) > max_bytes:
        raise _refused("too_large")
    return body


def _dechunk(data: bytes, max_bytes: int) -> bytes:
    out: list[bytes] = []
    size = 0
    pos = 0
    while True:
        end = data.find(b"\r\n", pos)
        if end < 0:
            raise _refused("chunk")
        found = _CHUNK_SIZE.match(data[pos:end])
        if found is None:
            raise _refused("chunk")
        length = int(found.group(1), 16)
        pos = end + 2
        if length == 0:
            return b"".join(out)  # trailers after the last chunk are ignored
        size += length
        if size > max_bytes or pos + length + 2 > len(data):
            raise _refused("too_large" if size > max_bytes else "chunk")
        if data[pos + length : pos + length + 2] != b"\r\n":
            raise _refused("chunk")
        out.append(data[pos : pos + length])
        pos += length + 2

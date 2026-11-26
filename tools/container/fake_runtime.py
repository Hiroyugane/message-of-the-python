#!/usr/bin/env python3
"""A stand-in for a container runtime's API socket, for the phase 11 container tests.

Docker and Podman cannot run inside the unprivileged test containers, so the systemd and
login checks start this instead, as root, on ``/run/docker.sock`` (0660 root:root, as
Docker makes it):

    python3 -I fake_runtime.py answer <socket> <fixture.json>   # serve the fixture
    python3 -I fake_runtime.py hang <socket>                    # accept, never answer

In ``answer`` mode every connection gets the ``answer`` list of the fixture file (the
format of ``tests/fixtures/security/docker-api.json``) for ``GET /containers/json?all=1``
and 404 for anything else; each request line is appended to ``<socket>.log``, so a test
can see what the module asked. In ``hang`` mode it reads the request and keeps the
connection open without a word, the case where the module's deadline must hold.
"""

import json
import os
import socket
import sys
import threading

HOLD_SECONDS = 600


def serve(mode: str, path: str, fixture: str = "") -> None:
    body = b""
    if mode == "answer":
        with open(fixture, encoding="utf-8") as f:
            body = json.dumps(json.load(f)["answer"]).encode()
    if os.path.exists(path):
        os.unlink(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o660)
    listener.listen(16)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handle, args=(conn, mode, path, body), daemon=True).start()


def handle(conn: socket.socket, mode: str, path: str, body: bytes) -> None:
    with conn:
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request += chunk
        line = request.split(b"\r\n", 1)[0].decode("ascii", "replace")
        with open(path + ".log", "a", encoding="utf-8") as log:
            log.write(line + "\n")
        if mode == "hang":
            threading.Event().wait(HOLD_SECONDS)
            return
        if line == "GET /containers/json?all=1 HTTP/1.0":
            head = (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            )
            conn.sendall(head.encode() + body)
        else:
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")


if __name__ == "__main__":
    serve(*sys.argv[1:4])

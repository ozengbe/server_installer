"""Minimal FastCGI client (stdlib only).

Used to run probe scripts through a tenant's real PHP-FPM, so isolation is
tested from inside the actual sandbox rather than approximated.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

FCGI_VERSION = 1
BEGIN_REQUEST = 1
END_REQUEST = 3
PARAMS = 4
STDIN = 5
STDOUT = 6
STDERR = 7
RESPONDER = 1
_HEADER = struct.Struct("!BBHHBx")
_MAX_CONTENT = 65535


class FastCGIError(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    stderr: bytes = b""
    app_status: int = 0


def _record(rtype: int, content: bytes, request_id: int = 1) -> bytes:
    padding = (8 - len(content) % 8) % 8
    return (
        _HEADER.pack(FCGI_VERSION, rtype, request_id, len(content), padding)
        + content
        + (b"\x00" * padding)
    )


def _length(n: int) -> bytes:
    return bytes([n]) if n < 128 else struct.pack("!I", n | 0x80000000)


def encode_params(params: Mapping[str, str]) -> bytes:
    out = bytearray()
    for key, value in params.items():
        k, v = key.encode(), value.encode()
        out += _length(len(k)) + _length(len(v)) + k + v
    return bytes(out)


def _stream(rtype: int, data: bytes) -> bytes:
    chunks = [data[i : i + _MAX_CONTENT] for i in range(0, len(data), _MAX_CONTENT)]
    return b"".join(_record(rtype, c) for c in chunks) + _record(rtype, b"")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise FastCGIError("connection closed by FastCGI server")
        buf += chunk
    return bytes(buf)


def parse_response(stdout: bytes) -> tuple[int, dict[str, str], bytes]:
    head, sep, body = stdout.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = stdout.partition(b"\n\n")
    headers: dict[str, str] = {}
    for line in head.decode("latin-1").splitlines():
        name, colon, value = line.partition(":")
        if colon:
            headers[name.strip().lower()] = value.strip()
    status = 200
    if "status" in headers:
        status = int(headers["status"].split()[0])
    return status, headers, body


def request(
    socket_path: Path,
    params: Mapping[str, str],
    *,
    body: bytes = b"",
    timeout: float = 30.0,
) -> Response:
    begin = struct.pack("!HB5x", RESPONDER, 0)
    payload = (
        _record(BEGIN_REQUEST, begin)
        + _stream(PARAMS, encode_params(params))
        + _stream(STDIN, body)
    )
    stdout, stderr = bytearray(), bytearray()
    app_status = 0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path))
            sock.sendall(payload)
            app_status = _read_until_end(sock, stdout, stderr)
    except OSError as exc:
        raise FastCGIError(f"{socket_path}: {exc}") from None
    status, headers, resp_body = parse_response(bytes(stdout))
    return Response(status, headers, resp_body, bytes(stderr), app_status)


def _read_until_end(sock: socket.socket, stdout: bytearray, stderr: bytearray) -> int:
    """Collect STDOUT/STDERR records until END_REQUEST; return the app status."""
    while True:
        version, rtype, _rid, length, padding = _HEADER.unpack(_recv_exact(sock, 8))
        if version != FCGI_VERSION:
            raise FastCGIError(f"unexpected FastCGI version {version}")
        content = _recv_exact(sock, length) if length else b""
        if padding:
            _recv_exact(sock, padding)
        if rtype == STDOUT:
            stdout += content
        elif rtype == STDERR:
            stderr += content
        elif rtype == END_REQUEST:
            app_status: int = struct.unpack("!I", content[:4])[0]
            return app_status


def php_params(
    script: Path, *, query: str = "", extra: Mapping[str, str] | None = None
) -> dict[str, str]:
    params = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "REQUEST_METHOD": "GET",
        "SCRIPT_FILENAME": str(script),
        "SCRIPT_NAME": "/" + script.name,
        "REQUEST_URI": "/" + script.name + (f"?{query}" if query else ""),
        "QUERY_STRING": query,
        "SERVER_SOFTWARE": "ozenix-probe",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "REMOTE_ADDR": "127.0.0.1",
        "CONTENT_LENGTH": "0",
    }
    params.update(extra or {})
    return params

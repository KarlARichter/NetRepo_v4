"""
NetRepo Secure - Protocol utilities
Length-prefixed JSON messages over TCP/TLS.

Message format:
- 4-byte unsigned big-endian length (N)
- N bytes UTF-8 JSON payload

All commands and responses are JSON objects.
"""

from __future__ import annotations

import json
import socket
from typing import Any, Dict

MAX_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MB hard cap (prevents memory abuse)

class ProtocolError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes or raise ProtocolError on disconnect/timeout."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError as e:
            raise ProtocolError(str(e))
        if not chunk:
            raise ProtocolError("Connection closed while receiving data")
        buf.extend(chunk)
    return bytes(buf)


def send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"Message too large: {len(payload)} bytes")
    header = len(payload).to_bytes(4, "big", signed=False)
    sock.sendall(header + payload)


def recv_json(sock: socket.socket) -> Dict[str, Any]:
    header = _recv_exact(sock, 4)
    n = int.from_bytes(header, "big", signed=False)
    if n <= 0 or n > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"Invalid message length: {n}")
    payload = _recv_exact(sock, n)
    try:
        obj = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise ProtocolError(f"Invalid JSON payload: {e}")
    if not isinstance(obj, dict):
        raise ProtocolError("JSON message must be an object")
    return obj

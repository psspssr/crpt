"""Local IPC transport binding using uint32_be length-prefixed frames."""

from __future__ import annotations

import socket
import struct
from socketserver import BaseRequestHandler, ThreadingTCPServer
from typing import Any, Callable

from .codec import decode_bytes, encode_bytes
from .envelope import validate_envelope
from .policy import SecurityPolicy
from .replay import ReplayCache, ReplayCacheProtocol
from .transport_ws import process_ws_payload
from .versioning import RuntimeVersionPolicy


MessageHandler = Callable[[dict[str, Any]], dict[str, Any]]


class IPCTransportError(ValueError):
    """Raised on IPC framing/transport errors."""



def encode_ipc_frame(payload: bytes) -> bytes:
    """Encode bytes as a length-prefixed frame (uint32_be + payload)."""
    if not isinstance(payload, (bytes, bytearray)):
        raise IPCTransportError("payload must be bytes")
    size = len(payload)
    if size > 0xFFFFFFFF:
        raise IPCTransportError("payload too large")
    return struct.pack(">I", size) + bytes(payload)



def decode_ipc_frames(buffer: bytes) -> tuple[list[bytes], bytes]:
    """Decode as many frames as possible from a stream buffer."""
    frames: list[bytes] = []
    offset = 0
    length = len(buffer)

    while True:
        if length - offset < 4:
            break
        size = struct.unpack(">I", buffer[offset : offset + 4])[0]
        if length - offset - 4 < size:
            break
        start = offset + 4
        end = start + size
        frames.append(buffer[start:end])
        offset = end

    return frames, buffer[offset:]



def send_ipc(
    host: str,
    port: int,
    envelope: dict[str, Any],
    *,
    encoding: str = "json",
    timeout: float = 10.0,
    version_policy: RuntimeVersionPolicy | None = None,
) -> dict[str, Any]:
    validate_envelope(envelope, allow_schema_uri=False, version_policy=version_policy)
    payload = encode_bytes(envelope, encoding=encoding)

    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.sendall(encode_ipc_frame(payload))
        response_payload = _read_frame(conn, timeout=timeout)

    decoded = decode_bytes(response_payload, encoding=encoding)
    validate_envelope(decoded, allow_schema_uri=False, version_policy=version_policy)
    return decoded


class IPCServer:
    """Threaded TCP server for IPC framed A2A messages."""

    def __init__(
        self,
        host: str,
        port: int,
        handler: MessageHandler,
        *,
        encoding: str = "json",
        replay_cache: ReplayCacheProtocol | None = None,
        enforce_replay: bool = False,
        security_policy: SecurityPolicy | None = None,
        version_policy: RuntimeVersionPolicy | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.handler = handler
        self.encoding = encoding
        self.enforce_replay = enforce_replay
        self.security_policy = security_policy
        self.version_policy = version_policy

        needs_replay = enforce_replay or bool(security_policy and security_policy.require_replay)
        self.replay_cache = replay_cache or (ReplayCache() if needs_replay else None)
        self._server = self._build_server()

    def _build_server(self) -> ThreadingTCPServer:
        handler_fn = self.handler
        encoding = self.encoding
        enforce_replay = self.enforce_replay
        security_policy = self.security_policy
        replay_cache = self.replay_cache
        version_policy = self.version_policy

        class RequestHandler(BaseRequestHandler):
            def handle(self) -> None:
                buffer = b""
                while True:
                    try:
                        chunk = self.request.recv(4096)
                    except OSError:
                        break
                    if not chunk:
                        break

                    buffer += chunk
                    frames, remainder = decode_ipc_frames(buffer)
                    buffer = remainder
                    for frame in frames:
                        response = process_ws_payload(
                            frame,
                            encoding=encoding,
                            handler=handler_fn,
                            enforce_replay=enforce_replay,
                            replay_cache=replay_cache,
                            security_policy=security_policy,
                            version_policy=version_policy,
                        )
                        try:
                            self.request.sendall(encode_ipc_frame(response))
                        except OSError:
                            return

        class ReusableServer(ThreadingTCPServer):
            allow_reuse_address = True

        return ReusableServer((self.host, self.port), RequestHandler)

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()



def _read_exact(sock: socket.socket, size: int, *, timeout: float) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise IPCTransportError("connection closed while reading frame")
        data.extend(chunk)
    return bytes(data)



def _read_frame(sock: socket.socket, *, timeout: float) -> bytes:
    header = _read_exact(sock, 4, timeout=timeout)
    size = struct.unpack(">I", header)[0]
    if size == 0:
        return b""
    return _read_exact(sock, size, timeout=timeout)

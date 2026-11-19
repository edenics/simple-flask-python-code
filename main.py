"""Trojan-over-WebSocket relay for Clash.

This app accepts a Trojan handshake inside a WebSocket connection and relays
TCP traffic to the requested destination. It is intended for private use only:
a password is required and the WebSocket path is fixed.

Environment variables:
    TROJAN_PASSWORD   password used by Clash (change before deploying)
    PROXY_WS_PATH     WebSocket path, default /trojan
    PORT              listening port, default 8080

Build: pip install -r requirements.txt
Start: python main.py
"""

import asyncio
import os
import socket
import struct
from typing import Optional, Tuple

from aiohttp import WSMsgType, web

PASSWORD = os.environ.get("TROJAN_PASSWORD", "change-me-please-set-TROJAN_PASSWORD")
WS_PATH = os.environ.get("PROXY_WS_PATH", "/trojan")
PORT = int(os.environ.get("PORT", "8080"))
CONNECT_TIMEOUT = 10


def _parse_socks5(payload: bytes) -> Optional[Tuple[str, int, int]]:
    """Parse a SOCKS5 CONNECT request. Return (host, port, bytes_consumed)."""
    if len(payload) < 5:
        return None
    if payload[0] != 0x05 or payload[1] != 0x01 or payload[2] != 0x00:
        raise ValueError("unsupported SOCKS5 request (only CONNECT is supported)")

    atyp = payload[3]
    if atyp == 0x01:  # IPv4
        if len(payload) < 10:
            return None
        host = socket.inet_ntoa(payload[4:8])
        port = struct.unpack("!H", payload[8:10])[0]
        return host, port, 10
    if atyp == 0x03:  # domain name
        name_len = payload[4]
        if len(payload) < 5 + name_len + 2:
            return None
        host = payload[5 : 5 + name_len].decode("idna", "replace")
        port = struct.unpack("!H", payload[5 + name_len : 7 + name_len])[0]
        return host, port, 7 + name_len
    if atyp == 0x04:  # IPv6
        if len(payload) < 22:
            return None
        host = socket.inet_ntop(socket.AF_INET6, payload[4:20])
        port = struct.unpack("!H", payload[20:22])[0]
        return host, port, 22
    raise ValueError(f"unsupported SOCKS5 address type: {atyp}")


def parse_trojan_handshake(data: bytes) -> Optional[Tuple[str, str, int, int]]:
    """Parse 'password\\r\\n' + SOCKS5 CONNECT.

    Returns (password, host, port, total_consumed), or None when more bytes
    are needed. Raises ValueError on a malformed handshake.
    """
    idx = data.find(b"\r\n")
    if idx < 0:
        if len(data) > 4096:
            raise ValueError("password line too long")
        return None
    password = data[:idx].decode("utf-8", "replace")
    parsed = _parse_socks5(data[idx + 2 :])
    if parsed is None:
        return None
    host, port, consumed = parsed
    return password, host, port, idx + 2 + consumed


async def _pump_upstream(reader: asyncio.StreamReader, ws: web.WebSocketResponse) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            await ws.send_bytes(data)
    except (ConnectionError, RuntimeError):
        pass
    finally:
        await ws.close()


async def ws_relay(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=16 * 1024 * 1024)
    await ws.prepare(request)

    buffer = bytearray()
    writer: Optional[asyncio.StreamWriter] = None
    pump_task: Optional[asyncio.Task] = None

    try:
        async for msg in ws:
            if msg.type in (WSMsgType.BINARY, WSMsgType.TEXT):
                payload = msg.data.encode("utf-8") if isinstance(msg.data, str) else msg.data

                if writer is None:
                    buffer.extend(payload)
                    try:
                        handshake = parse_trojan_handshake(bytes(buffer))
                    except ValueError as exc:
                        print(f"[auth] malformed handshake: {exc}", flush=True)
                        break
                    if handshake is None:
                        continue

                    password, host, port, consumed = handshake
                    if password != PASSWORD:
                        print("[auth] wrong password", flush=True)
                        break

                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port), CONNECT_TIMEOUT
                        )
                    except (OSError, asyncio.TimeoutError) as exc:
                        print(f"[connect] failed {host}:{port}: {exc}", flush=True)
                        break

                    print(f"[connect] {host}:{port}", flush=True)
                    initial = bytes(buffer[consumed:])
                    if initial:
                        writer.write(initial)
                        await writer.drain()
                    pump_task = asyncio.create_task(_pump_upstream(reader, ws))
                elif payload:
                    writer.write(payload)
                    await writer.drain()
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR):
                break
    finally:
        if pump_task is not None:
            pump_task.cancel()
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
        if not ws.closed:
            await ws.close()
    return ws


async def index(_: web.Request) -> web.Response:
    return web.Response(
        text=f"Trojan-WS relay is running. WebSocket path: {WS_PATH}\n",
        content_type="text/plain",
    )


async def health(_: web.Request) -> web.Response:
    return web.Response(text="OK", content_type="text/plain")


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/health", health)
    app.router.add_get(WS_PATH, ws_relay)
    return app


if __name__ == "__main__":
    print(f"Starting Trojan-WS relay on 0.0.0.0:{PORT} (path {WS_PATH})", flush=True)
    web.run_app(build_app(), host="0.0.0.0", port=PORT, access_log=None)

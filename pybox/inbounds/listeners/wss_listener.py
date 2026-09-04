import asyncio
import ssl

import websockets

from ...connections.connection import Connection

from ...connections.ws import WsConnection
from ...utils.address import format_socket_address
from .listener import Listener


class WssListener(Listener):
    def __init__(
        self, host: str, port: int, path: str, certificate_path: str, key_path: str
    ) -> None:
        self.host = host
        self.port = port
        self.path = path
        self.certificate_path = certificate_path
        self.key_path = key_path
        self.server: websockets.Server | None = None
        self.queue: asyncio.Queue[WsConnection] = asyncio.Queue()

    async def start(self):
        ssl_context = ssl.create_default_context()
        ssl_context.load_cert_chain(
            certfile=self.certificate_path, keyfile=self.key_path
        )
        self.server = await websockets.serve(
            self._handle, self.host, self.port, ssl=ssl_context
        )
        for sock in self.server.sockets:
            print(f"[listen] wss://{format_socket_address(sock.getsockname())}")

    async def _handle(self, ws: websockets.ServerConnection):
        if not ws.request or ws.request.path != self.path:
            await ws.close()
        connection = WsConnection(ws)
        await self.queue.put(connection)
        await ws.wait_closed()

    async def accept(self) -> Connection:
        return await self.queue.get()

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

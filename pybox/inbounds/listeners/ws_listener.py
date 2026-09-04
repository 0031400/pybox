import asyncio

import websockets

from ...connections.connection import Connection

from ...connections.ws import WsConnection
from ...utils.address import format_socket_address
from .listener import Listener


class WsListener(Listener):
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.server: websockets.Server | None = None
        self.queue: asyncio.Queue[WsConnection] = asyncio.Queue()

    async def start(self):
        self.server = await websockets.serve(self._handle, self.host, self.port)
        for sock in self.server.sockets:
            print(f"[listen] ws://{format_socket_address(sock.getsockname())}")

    async def _handle(self, ws: websockets.ServerConnection):
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

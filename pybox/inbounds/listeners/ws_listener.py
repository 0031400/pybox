import asyncio

import websockets

from ...common.log import log
from ...connections.connection import Connection

from ...connections.ws import WsConnection
from ...utils.address import format_socket_address
from .listener import Listener


class WsListener(Listener):
    def __init__(self, host: str, port: int, path: str) -> None:
        self.host = host
        self.port = port
        self.path = path
        self.server: websockets.Server | None = None
        self.queue: asyncio.Queue[WsConnection] = asyncio.Queue()

    async def start(self):
        self.server = await websockets.serve(self._handle, self.host, self.port)
        for sock in self.server.sockets:
            log("listen",f"ws://{format_socket_address(sock.getsockname())}")

    async def _handle(self, ws: websockets.ServerConnection):
        if not ws.request or ws.request.path != self.path:
            await ws.close()
        connection = WsConnection(ws)
        await self.queue.put(connection)
        try:
            await ws.wait_closed()
        except Exception:
            pass

    async def accept(self) -> Connection:
        return await self.queue.get()

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

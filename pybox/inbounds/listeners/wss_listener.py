import asyncio
import ssl

import websockets

from pybox.connections.connection import Connection

from ...connections.ws import WsConnection
from .listener import Listener


class WssListener(Listener):
    def __init__(
        self, host: str, port: int, certificate_path: str, key_path: str
    ) -> None:
        self.host = host
        self.port = port
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

    async def _handle(self, ws: websockets.ServerConnection):
        connection = WsConnection(ws)
        await self.queue.put(connection)

    async def accept(self) -> Connection:
        return await self.queue.get()

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

import asyncio

from pybox.connections.connection import Connection

from ...connections.tcp import TcpConnection
from .listener import Listener


class TcpListener(Listener):
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.server: asyncio.Server | None = None
        self.queue: asyncio.Queue[TcpConnection] = asyncio.Queue()

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        connection = TcpConnection(reader, writer)
        await self.queue.put(connection)

    async def accept(self) -> Connection:
        return await self.queue.get()

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

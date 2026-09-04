import asyncio
import ssl

from ...connections.connection import Connection

from ...connections.tcp import TcpConnection
from ...utils.address import format_socket_address
from .listener import Listener


class TlsListener(Listener):
    def __init__(
        self, host: str, port: int, certificate_path: str, key_path: str
    ) -> None:
        self.host = host
        self.port = port
        self.certificate_path = certificate_path
        self.key_path = key_path
        self.server: asyncio.Server | None = None
        self.queue: asyncio.Queue[TcpConnection] = asyncio.Queue()

    async def start(self):
        ssl_context = ssl.create_default_context()
        ssl_context.load_cert_chain(
            certfile=self.certificate_path, keyfile=self.key_path
        )
        self.server = await asyncio.start_server(
            self._handle, self.host, self.port, ssl=ssl_context
        )        
        for sock in self.server.sockets:
            print(f"[listen] tls://{format_socket_address(sock.getsockname())}")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        connection = TcpConnection(reader, writer)
        await self.queue.put(connection)
        await writer.wait_closed()

    async def accept(self) -> Connection:
        return await self.queue.get()

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

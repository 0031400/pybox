import asyncio
from typing import Any

from .connection import Connection


class TcpConnection(Connection):
    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.reader = reader
        self.writer = writer

    async def read(self, n: int) -> bytes:
        return await self.reader.read(n)

    async def read_exactly(self, n: int) -> bytes:
        return await self.reader.readexactly(n)

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()

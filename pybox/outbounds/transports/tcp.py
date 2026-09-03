import asyncio

from pybox.connections.connection import Connection

from ...common.address import Destination
from ...connections.tcp import TcpConnection
from .transport import Transport


class TcpTransport(Transport):
    async def connect(self, destination: Destination) -> Connection:
        reader, writer = await asyncio.open_connection(
            destination.address, destination.port
        )
        return TcpConnection(reader, writer)

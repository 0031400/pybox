import asyncio

from ..common.address import Destination

from ..connections.connection import Connection
from ..connections.tcp import TcpConnection
from .outbound import Outbound


class DirectOutbound(Outbound):
    async def connect(self, destination: Destination, first_data: bytes) -> Connection:
        reader, writer = await asyncio.open_connection(
            destination.address, destination.port
        )
        connection = TcpConnection(reader, writer)
        await connection.write(first_data)
        return connection

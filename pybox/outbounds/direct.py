import asyncio
import time

from ..common.address import Destination

from ..common.network import open_connection
from ..connections.connection import Connection
from ..connections.tcp import TcpConnection
from .outbound import Outbound


class DirectOutbound(Outbound):
    async def connect(
        self, destination: Destination, initial_data: bytes
    ) -> Connection:
        reader, writer = await open_connection(destination.address, destination.port)
        connection = TcpConnection(reader, writer)
        await connection.write(initial_data)
        return connection

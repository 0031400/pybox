import asyncio

from ..common.address import Destination

from ..connections.connection import Connection
from ..connections.tcp_connection import TcpConnection
from .outbound import Outbound


class DirectOutbound(Outbound):
    async def connect(self, destination: Destination) -> Connection:
        reader, writer = await asyncio.open_connection(
            destination.address, destination.port
        )
        return TcpConnection(reader, writer)

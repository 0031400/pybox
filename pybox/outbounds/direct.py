from ..common.address import Address

from ..connections.connection import Connection
from .outbound import Outbound
from .transports.tcp import TcpTransport


class DirectOutbound(Outbound):
    async def connect(
        self, destination: Address, initial_data: bytes
    ) -> Connection:
        transport = TcpTransport()
        connection = await transport.connect(destination)
        await connection.write(initial_data)
        return connection

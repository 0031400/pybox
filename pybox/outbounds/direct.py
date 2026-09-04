from ..common.address import Destination

from ..common.network import open_connection
from ..connections.connection import Connection
from ..connections.tcp import TcpConnection
from .outbound import Outbound
from .transports.tcp import TcpTransport


class DirectOutbound(Outbound):
    async def connect(
        self, destination: Destination, initial_data: bytes
    ) -> Connection:
        transport = TcpTransport()
        connection = await transport.connect(destination)
        await connection.write(initial_data)
        return connection

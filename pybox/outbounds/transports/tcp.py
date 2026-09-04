from ...common.network import open_connection
from ...connections.connection import Connection

from ...common.address import Destination
from ...connections.tcp import TcpConnection
from .transport import Transport


class TcpTransport(Transport):
    async def connect(self, destination: Destination) -> Connection:
        reader, writer = await open_connection(
            destination.address, destination.port
        )
        return TcpConnection(reader, writer)

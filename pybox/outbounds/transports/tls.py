import asyncio
import ssl

from pybox.connections.connection import Connection

from ...common.address import Destination
from ...connections.tcp import TcpConnection
from .transport import Transport


class TlsTransport(Transport):
    def __init__(self, server_name: str, verify: bool) -> None:
        self.server_name = server_name
        self.verify = verify

    async def connect(self, destination: Destination) -> Connection:
        context = ssl.create_default_context()
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(
            destination.address,
            destination.port,
            ssl=context,
            server_hostname=self.server_name,
        )
        return TcpConnection(reader, writer)

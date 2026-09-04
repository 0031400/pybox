import asyncio
import ssl

from ...common.network import open_connection
from ...connections.connection import Connection

from ...common.address import Destination
from ...connections.tcp import TcpConnection
from .transport import Transport


class TlsTransport(Transport):
    def __init__(self, server_name: str, insecure: bool) -> None:
        self.server_name = server_name
        self.insecure = insecure

    async def connect(self, destination: Destination) -> Connection:
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        reader, writer = await open_connection(
            destination.address,
            destination.port,
            ssl=context,
            server_hostname=self.server_name,
        )
        return TcpConnection(reader, writer)

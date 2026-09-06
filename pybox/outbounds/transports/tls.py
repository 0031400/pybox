import asyncio
import ssl

from ...common.network import  open_tcp_sock
from ...connections.connection import Connection

from ...common.address import Address
from ...connections.tcp import TcpConnection
from .transport import Transport


class TlsTransport(Transport):
    def __init__(self, server_name: str, insecure: bool) -> None:
        self.server_name = server_name
        self.insecure = insecure

    async def connect(self, destination: Address) -> Connection:
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = await open_tcp_sock(destination)
        reader, writer = await asyncio.open_connection(
            sock=sock, ssl=context, server_hostname=self.server_name
        )
        return TcpConnection(reader, writer)

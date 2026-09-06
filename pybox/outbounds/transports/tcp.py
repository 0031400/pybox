import asyncio

from ...common.network import  open_tcp_sock
from ...connections.connection import Connection

from ...common.address import Address
from ...connections.tcp import TcpConnection
from .transport import Transport


class TcpTransport(Transport):
    async def connect(self, destination: Address) -> Connection:
        sock = await open_tcp_sock(destination)
        reader, writer = await asyncio.open_connection(sock=sock)
        return TcpConnection(reader, writer)

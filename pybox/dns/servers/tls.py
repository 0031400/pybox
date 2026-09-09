import asyncio
import ipaddress
import ssl

from ...common.network import connnect_ip
from .server import DnsServer


class TlsDnsServer(DnsServer):
    def __init__(
        self,
        server: ipaddress.IPv4Address | ipaddress.IPv6Address,
        server_port: int,
        server_hostname: str,
        insecure: bool,
    ) -> None:
        self.server = server
        self.server_port = server_port
        self.time_out = 3
        self.server_hostname = server_hostname
        self.insecure = insecure
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def query(self, request: bytes) -> bytes:
        if not self.reader or not self.writer:
            await self.build_connect()
        assert self.writer and self.reader
        self.writer.write(len(request).to_bytes(2, "big") + request)
        await self.writer.drain()
        try:
            length_bytes = await asyncio.wait_for(
                self.reader.readexactly(2), self.time_out
            )
            length = int.from_bytes(length_bytes, "big")
            data = await asyncio.wait_for(
                self.reader.readexactly(length), self.time_out
            )
        except asyncio.TimeoutError:
            raise RuntimeError("tls dns query timeout")
        return data

    async def build_connect(self):
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = await connnect_ip(self.server, self.server_port)
        self.reader, self.writer = await asyncio.open_connection(
            sock=sock, ssl=context, server_hostname=self.server_hostname
        )

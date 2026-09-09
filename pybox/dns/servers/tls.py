import asyncio
import ipaddress
import ssl

from ...common.address import (
    DOMAIN_Address,
    IPV4_Address,
    IPV6_Address,
    host_port_to_addr,
)
from ...common.network import connect_address, connnect_ip
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

    async def query(self, request: bytes) -> bytes:
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = await connnect_ip(self.server, self.server_port)
        reader, writer = await asyncio.open_connection(
            sock=sock, ssl=context, server_hostname=self.server_hostname
        )
        writer.write(len(request).to_bytes(2, "big") + request)
        await writer.drain()
        try:
            try:
                res = await asyncio.wait_for(reader.read(4096), self.time_out)
            except asyncio.TimeoutError:
                raise RuntimeError("tls dns query timeout")
            length = int.from_bytes(res[:2], "big")
            return res[2 : 2 + length]
        finally:
            writer.close()
            await writer.wait_closed()

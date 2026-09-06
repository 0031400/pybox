import asyncio
import ipaddress
import ssl

from ...common.address import (
    DOMAIN_Address,
    IPV4_Address,
    IPV6_Address,
    host_port_to_addr,
)
from ...common.network import open_tcp_sock
from .server import DnsServer


class TlsDnsServer(DnsServer):
    def __init__(
        self,
        server: str,
        server_port: int,
        server_hostname: str,
        insecure: bool,
        bootstrap_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
    ) -> None:
        self.time_out = 3
        self.server_hostname = server_hostname
        self.insecure = insecure
        self.destination = host_port_to_addr(server, server_port)
        if isinstance(self.destination, DOMAIN_Address):
            if not bootstrap_address:
                raise RuntimeError("need bootstrap_address")
            if isinstance(bootstrap_address, ipaddress.IPv4Address):
                self.destination = IPV4_Address(
                    bootstrap_address, self.destination.port
                )
            else:
                self.destination = IPV6_Address(
                    bootstrap_address, self.destination.port
                )

    async def query(self, request: bytes) -> bytes:
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = await open_tcp_sock(self.destination)
        reader, writer = await asyncio.open_connection(
            sock=sock, ssl=context, server_hostname=self.server_hostname
        )
        writer.write(len(request).to_bytes(2, "big") + request)
        await writer.drain()
        try:
            res = await reader.read(4096)
            length = int.from_bytes(res[:2], "big")
            return res[2 : 2 + length]
        finally:
            writer.close()
            await writer.wait_closed()

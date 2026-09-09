import asyncio
import ipaddress
from ...common import globals
from ...common.udp import UdpClient, UdpSession
from .server import DnsServer


class UdpDnsServer(DnsServer):
    def __init__(
        self,
        server: ipaddress.IPv4Address | ipaddress.IPv6Address,
        server_port: int,
    ) -> None:
        self.server = server
        self.server_port = server_port
        self.time_out = 3

    async def query(self, request: bytes) -> bytes:
        client = UdpClient()
        local_addr: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] | None = (
            None
        )
        if self.server.version == 4 and globals.LOCAL_IPV4:
            local_addr = (ipaddress.IPv4Address(globals.LOCAL_IPV4), 0)
        if self.server.version == 6 and globals.LOCAL_IPV6:
            local_addr = (ipaddress.IPv6Address(globals.LOCAL_IPV6), 0)
        await client.start(
            local_addr=local_addr, remote_addr=(self.server, self.server_port)
        )
        client.send(UdpSession(request, self.server, self.server_port))
        try:
            session = await asyncio.wait_for(client.sessions(), self.time_out)
        except asyncio.TimeoutError:
            raise RuntimeError("udp dns query timeout")
        return session.data

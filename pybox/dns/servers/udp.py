import asyncio
import ipaddress
import socket

from pybox.common import network

from ...common.address import (
    DOMAIN_Address,
    IPV4_Address,
    IPV6_Address,
    host_port_to_addr,
)
from .server import DnsServer


class UdpDnsServer(DnsServer):
    def __init__(
        self,
        server: str,
        server_port: int,
        bootstrap_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
    ) -> None:
        self.server = server
        self.server_port = server_port
        self.time_out = 3
        destination = host_port_to_addr(server, server_port)
        if isinstance(destination, DOMAIN_Address):
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
        else:
            self.destination: IPV4_Address | IPV6_Address = destination

    async def query(self, request: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        if isinstance(self.destination, IPV4_Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if network.LOCAL_IPV4:
                sock.bind((network.LOCAL_IPV4, 0))
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            if network.LOCAL_IPV6:
                sock.bind((network.LOCAL_IPV6, 0))
        sock.setblocking(False)
        sock.connect((str(self.destination.address), self.destination.port))
        sock.send(request)
        data = await asyncio.wait_for(
            loop.sock_recv(sock, 65535), timeout=self.time_out
        )
        return data

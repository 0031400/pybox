import asyncio
import ipaddress
import socket
from ...common import globals
from pybox.common import network

from ...common.address import (
    DOMAIN_Address,
    IPV4_Address,
    IPV6_Address,
    host_port_to_addr,
)
from .server import DnsServer


class UdpClient(asyncio.DatagramProtocol):
    def __init__(
        self, future: asyncio.Future, request: bytes, remote: tuple[str, int]
    ) -> None:
        self.future = future
        self.request = request
        self.remote = remote

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        self.transport.sendto(self.request, self.remote)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.future.set_result(data)


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
        # if isinstance(self.destination, IPV4_Address):
        #     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #     if network.LOCAL_IPV4:
        #         sock.bind((network.LOCAL_IPV4, 0))
        # else:
        #     sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        #     if network.LOCAL_IPV6:
        #         sock.bind((network.LOCAL_IPV6, 0))
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = asyncio.Future()
        if globals.LOCAL_IPV4:
            transport, protocol = await loop.create_datagram_endpoint(
                protocol_factory=lambda: UdpClient(future, request, (self.server, self.server_port)),
                remote_addr=(self.server, self.server_port),
                local_addr=(globals.LOCAL_IPV4, 0),
            )
        else:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UdpClient(future, request, (self.server, self.server_port)),
                remote_addr=(self.server, self.server_port),
            )
        return await future

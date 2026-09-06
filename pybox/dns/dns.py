import asyncio
from dataclasses import dataclass
import ipaddress
import socket
from typing import Any

from .servers.server import DnsServer


@dataclass
class DnsSession:
    request: bytes
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int


class DnsCenter:
    def __init__(
        self, listen: str | None, listen_port: int | None, servers: dict[str, DnsServer]
    ) -> None:
        self.servers = servers
        self.listen = listen
        self.listen_port = listen_port
        self.queue: asyncio.Queue[DnsSession] = asyncio.Queue()
        self.transport: asyncio.DatagramTransport | None = None

    async def start(self):
        if self.listen and self.listen_port:
            (
                self.transport,
                protocol,
            ) = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: DnsListener(self), local_addr=(self.listen, self.listen_port)
            )

    async def handle(self, data: bytes, addr: tuple[str | Any, int]):
        await self.queue.put(DnsSession(data, ipaddress.ip_address(addr[0]), addr[1]))

    async def query(self, tag: str, request: bytes):
        server = self.servers.get(tag)
        if not server:
            raise RuntimeError("fial to find dns server")
        return await server.query(request)

    async def sessions(self) -> DnsSession:
        return await self.queue.get()

    async def send(self, data: bytes, addr: tuple[str, int]):
        if not self.transport:
            return
        self.transport.sendto(data, addr)


class DnsListener(asyncio.DatagramProtocol):
    def __init__(self, center: DnsCenter) -> None:
        self.center = center

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple[str | Any, int]):
        await self.center.handle(data, addr)


async def resolve(domain: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    loop = asyncio.get_running_loop()
    results = await loop.getaddrinfo(domain, None, type=0, proto=0, flags=0)
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for family, _, _, _, sock_addr in results:
        if family == socket.AF_INET:
            ips.append(ipaddress.IPv4Address(sock_addr[0]))
        if family == socket.AF_INET6:
            ips.append(ipaddress.IPv6Address(sock_addr[0]))
    return ips

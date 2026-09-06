import asyncio
from dataclasses import dataclass
import ipaddress
from typing import Any
import dns.rdatatype

import dns
import dns.message
import dns.query
from ..common import globals

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

    async def start(self):
        if not self.listen or not self.listen_port:
            raise RuntimeError("dns need listen addr")
        loop = asyncio.get_running_loop()
        self.transport, protocol = await loop.create_datagram_endpoint(
            lambda: UdpClient(self), local_addr=(self.listen, self.listen_port)
        )

    async def query(self, tag: str, request: bytes):
        server = self.servers.get(tag)
        if not server:
            raise RuntimeError("fial to find dns server")
        return await server.query(request)

    async def sessions(self) -> DnsSession:
        return await self.queue.get()

    def send(self, data: bytes, addr: tuple[str, int]):
        self.transport.sendto(data, addr)


class UdpClient(asyncio.DatagramProtocol):
    def __init__(self, center: DnsCenter) -> None:
        self.center = center

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        asyncio.create_task(
            self.center.queue.put(
                DnsSession(data, ipaddress.ip_address(addr[0]), addr[1])
            )
        )


async def resolve(domain: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    # loop = asyncio.get_running_loop()
    # results = await loop.getaddrinfo(domain, None, type=0, proto=0, flags=0)
    # ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    # for family, _, _, _, sock_addr in results:
    #     if family == socket.AF_INET:
    #         ips.append(ipaddress.IPv4Address(sock_addr[0]))
    #     if family == socket.AF_INET6:
    #         ips.append(ipaddress.IPv6Address(sock_addr[0]))
    # return ips
    response = dns.query.udp(
        dns.message.make_query(domain, "A"), "119.29.29.29", source=globals.LOCAL_IPV4
    )
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for rrset in response.answer:
        for rr in rrset:
            if rrset.rdtype == dns.rdatatype.A or rrset.rdtype == dns.rdatatype.AAAA:
                ips.append(ipaddress.ip_address(rr.address))
    return ips

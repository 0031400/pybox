import asyncio
from dataclasses import dataclass
import ipaddress
import socket
from typing import Any
import dns.asyncquery
import dns.asyncresolver
import dns.rdatatype

import dns
from ..common.udp import UdpClient, UdpSession
import dns.message
import dns.query
from ..common import globals

from ..common.log import log
from .servers.server import DnsServer


class DnsCenter:
    def __init__(
        self, listen: str | None, listen_port: int | None, servers: dict[str, DnsServer]
    ) -> None:
        self.servers = servers
        self.listen = listen
        self.listen_port = listen_port
        self.queue: asyncio.Queue[UdpSession] = asyncio.Queue()
        self.client = UdpClient()

    async def start(self):
        if not self.listen or not self.listen_port:
            raise RuntimeError("dns need listen addr")
        await self.client.start(
            local_addr=(ipaddress.ip_address(self.listen), self.listen_port)
        )
        asyncio.create_task(self.server_work())

    async def server_work(self):
        try:
            while True:
                await self.queue.put(await self.client.queue.get())
        except Exception as e:
            log("error", f"dns center server work {e}")

    async def query(self, tag: str, request: bytes):
        server = self.servers.get(tag)
        if not server:
            raise RuntimeError("fial to find dns server")
        return await server.query(request)

    async def sessions(self) -> UdpSession:
        return await self.queue.get()

    def send(self, session: UdpSession):
        self.client.send(session)


async def resolve(domain: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    log("resolve", f"<- {domain}")
    if not globals.LOCAL_IPV4:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(domain, None, type=0, proto=0, flags=0)
        ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for family, _, _, _, sock_addr in results:
            if family == socket.AF_INET:
                ips.append(ipaddress.IPv4Address(sock_addr[0]))
            if family == socket.AF_INET6:
                ips.append(ipaddress.IPv6Address(sock_addr[0]))
        return ips
    if globals.LOCAL_IPV4:
        answers = (
            await dns.asyncquery.udp(
                dns.message.make_query(domain, "A"),
                "119.29.29.29",
                source=globals.LOCAL_IPV4,
            )
        ).answer
    else:
        answers = (
            await dns.asyncquery.udp(
                dns.message.make_query(domain, "A"),
                "119.29.29.29",
            )
        ).answer
        answers += (
            await dns.asyncquery.udp(
                dns.message.make_query(domain, "AAAA"),
                "119.29.29.29",
            )
        ).answer

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for rrset in answers:
        for rr in rrset:
            if rrset.rdtype == dns.rdatatype.A or rrset.rdtype == dns.rdatatype.AAAA:
                ips.append(ipaddress.ip_address(rr.address))
    log("resolve", f"{domain} -> {','.join([str(ip) for ip in ips])}")
    return ips

import asyncio
from dataclasses import dataclass
import ipaddress
from queue import Queue
import socket
import threading
from turtle import pu
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
        self.queue: Queue[DnsSession] = Queue()
        self.transport: asyncio.DatagramTransport | None = None

    async def start(self):
        threading.Thread(target=self.serve_worker, daemon=True).start()

    def serve_worker(self):
        if self.listen and self.listen_port:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.listen, self.listen_port))
            while True:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self.queue.put(DnsSession(data, ipaddress.ip_address(addr[0]), addr[1]))
                except Exception as e:
                    print(e)

    async def query(self, tag: str, request: bytes):
        server = self.servers.get(tag)
        if not server:
            raise RuntimeError("fial to find dns server")
        return await server.query(request)

    def sessions(self) -> DnsSession:
        return self.queue.get()

    def send(self, data: bytes, addr: tuple[str, int]):
        self.sock.sendto(data, addr)


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

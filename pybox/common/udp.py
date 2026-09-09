import asyncio
from dataclasses import dataclass
import ipaddress
from typing import Any


@dataclass
class UdpSession:
    data: bytes
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int


class UdpClient:
    class Client(asyncio.DatagramProtocol):
        def __init__(
            self,
            queue: asyncio.Queue[UdpSession],
        ) -> None:
            self.queue = queue

        def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
            asyncio.create_task(
                self.queue.put(UdpSession(data, ipaddress.ip_address(addr[0]), addr[1]))
            )

    def __init__(self) -> None:
        self.queue: asyncio.Queue[UdpSession] = asyncio.Queue()
        self.transport: asyncio.DatagramTransport | None = None

    async def start(
        self,
        local_addr: (
            tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] | None
        ) = None,
        remote_addr: (
            tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int] | None
        ) = None,
    ):
        loop = asyncio.get_running_loop()
        local_addr_out = (str(local_addr[0]), local_addr[1]) if local_addr else None
        remote_addr_out = (str(remote_addr[0]), remote_addr[1]) if remote_addr else None
        if not local_addr_out and not remote_addr_out:
            raise RuntimeError("local_addr or remote_addr must set one")
        self.transport, protocol = await loop.create_datagram_endpoint(
            lambda: self.Client(self.queue),
            local_addr=local_addr_out,
            remote_addr=remote_addr_out,
        )

    async def local_addr(
        self,
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
        if not self.transport:
            raise RuntimeError("udp socket has closed")
        sock_name = self.transport.get_extra_info("sockname")
        return (ipaddress.ip_address(sock_name[0]), sock_name[1])

    async def sessions(self):
        return await self.queue.get()

    def close(self):
        if self.transport:
            self.transport.close()
            self.transport = None

    def send(self, session: UdpSession):
        if not self.transport:
            raise RuntimeError("udp socket has closed")
        self.transport.sendto(session.data, (str(session.ip), session.port))

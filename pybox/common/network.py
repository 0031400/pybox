import asyncio
from ipaddress import IPv4Address, IPv6Address
import ipaddress
from typing import cast
import socket
import ssl

from ..dns.dns import resolve
from .address import AddressType, Address, DOMAIN_Address, IPV4_Address


async def open_sock(destination: Address):
    if isinstance(destination, DOMAIN_Address):
        ips = await resolve(destination.address)
    else:
        ips = [destination.address]

    async def connect(ip: IPv4Address | IPv6Address, port: int) -> socket.socket:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        # sock.bind(("10.137.1.37", 0))
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        await loop.sock_connect(sock, (str(ip), port))
        return sock

    tasks = [asyncio.create_task(connect(ip, destination.port)) for ip in ips]
    try:
        for future in asyncio.as_completed(tasks):
            try:
                sock = await future
                return sock
            except Exception:
                continue
        raise RuntimeError("fail to connect")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

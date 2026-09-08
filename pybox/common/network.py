import asyncio
from ipaddress import IPv4Address, IPv6Address
import ipaddress
import socket

from ..dns.dns import resolve
from .address import Address, DOMAIN_Address

from . import globals
from .log import log


def set_default_local_addr():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 53))
        globals.LOCAL_IPV4 = sock.getsockname()[0]
    finally:
        sock.close()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.connect(("2400:3200::1", 53))
        globals.LOCAL_IPV6 = sock.getsockname()[0]
    finally:
        sock.close()
    if not globals.LOCAL_IPV4:
        log("[ipv4]", globals.LOCAL_IPV4)
    if not globals.LOCAL_IPV6:
        log("[ipv6]", globals.LOCAL_IPV6)


async def open_tcp_sock(destination: Address) -> socket.socket:
    if isinstance(destination, DOMAIN_Address):
        ips: list[IPv4Address | IPv6Address] = await resolve(destination.address)
    else:
        ips = [destination.address]

    async def connect(ip: IPv4Address | IPv6Address, port: int) -> socket.socket:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

        if globals.LOCAL_IPV4:
            sock.bind((globals.LOCAL_IPV4, 0))
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

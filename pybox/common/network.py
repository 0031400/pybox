import asyncio
from ipaddress import IPv4Address, IPv6Address
import ipaddress
import struct
from typing import cast
import socket
import ssl

from ..dns.dns import resolve
from .address import Address, DOMAIN_Address

LOCAL_IPV4: str = ""
LOCAL_IPV6: str = ""


def set_default_local_addr():
    global LOCAL_IPV4, LOCAL_IPV6
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 53))
        LOCAL_IPV4 = sock.getsockname()[0]
    finally:
        sock.close()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.connect(("2400:3200::1", 53))
        LOCAL_IPV6 = sock.getsockname()[0]
    finally:
        sock.close()
    if not LOCAL_IPV4:
        print(f"[ipv4] {LOCAL_IPV4}")
    if not LOCAL_IPV6:
        print(f"[ipv6] {LOCAL_IPV6}")


async def open_tcp_sock(destination: Address) -> socket.socket:
    global LOCAL_IPV4, LOCAL_IPV6
    if isinstance(destination, DOMAIN_Address):
        ips = await resolve(destination.address)
    else:
        ips = [destination.address]

    async def connect(ip: IPv4Address | IPv6Address, port: int) -> socket.socket:
        if isinstance(ip, ipaddress.IPv4Address):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

        if LOCAL_IPV4:
            sock.bind((LOCAL_IPV4, 0))
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

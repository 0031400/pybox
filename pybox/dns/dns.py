import asyncio
import ipaddress
import socket


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

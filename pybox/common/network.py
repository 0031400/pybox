import asyncio
from math import e
import socket


async def open_connection(
    host: str, port: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)

    async def connect(addr) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        family, socktype, proto, _, sock_addr = addr
        return await asyncio.open_connection(sock_addr[0], sock_addr[1], family=family)

    tasks = [asyncio.create_task(connect(addr)) for addr in addresses]
    try:
        for future in asyncio.as_completed(tasks):
            try:
                reader, writer = await future
                return reader, writer
            except Exception:
                continue
        raise RuntimeError("fail to connect")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

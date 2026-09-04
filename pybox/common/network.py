import asyncio
from math import e
import socket
import ssl


async def open_connection(
    host: str,
    port: int,
    ssl: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)

    async def connect(
        addr: tuple[
            socket.AddressFamily,
            socket.SocketKind,
            int,
            str,
            tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
        ],
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        family, socktype, proto, _, sock_addr = addr
        if not isinstance(sock_addr[0], str) or not isinstance(sock_addr[1], int):
            raise RuntimeError("unsupport address")
        return await asyncio.open_connection(
            sock_addr[0],
            sock_addr[1],
            ssl=ssl,
            server_hostname=server_hostname,
        )

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

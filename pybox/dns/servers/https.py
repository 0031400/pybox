import asyncio
import ipaddress
import ssl

from ...common.network import connnect_ip
from .server import DnsServer


class HttpsDnsServer(DnsServer):
    def __init__(
        self,
        server: ipaddress.IPv4Address | ipaddress.IPv6Address,
        server_port: int,
        server_hostname: str,
        insecure: bool,
        path: str,
        host: str,
    ) -> None:
        self.server = server
        self.server_port = server_port
        self.time_out = 3
        self.server_hostname = server_hostname
        self.insecure = insecure
        self.path = path
        self.host = host

    async def query(self, request: bytes) -> bytes:
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = await connnect_ip(self.server, self.server_port)
        reader, writer = await asyncio.open_connection(
            sock=sock, ssl=context, server_hostname=self.server_hostname
        )
        https_request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/dns-message\r\n"
            f"Content-Length: {len(request)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        writer.write(https_request + request)
        await writer.drain()
        byte_array = bytearray()
        try:
            status_line = await asyncio.wait_for(
                reader.readuntil(b"\r\n"), self.time_out
            )
            if not status_line.startswith(b"HTTP/1.1 200"):
                raise RuntimeError("https dns reposonse error")
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                byte_array.extend(chunk)
        except asyncio.TimeoutError:
            raise RuntimeError("tls dns query timeout")
        data = bytes(byte_array.split(b"\r\n\r\n", 1)[1])
        writer.close()
        await writer.wait_closed()
        return data

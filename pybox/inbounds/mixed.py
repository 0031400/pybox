from collections.abc import AsyncIterator
from urllib.parse import urlsplit
from ..common.address import AddressType, Destination
from ..connections.connection import Connection
from ..common.session import Session
import ipaddress

from .inbound import Inbound
from .listeners.listener import Listener


class MixedInbound(Inbound):
    def __init__(self, listener: Listener) -> None:
        self.listener = listener

    async def start(self):
        await self.listener.start()

    async def sessions(self) -> AsyncIterator[Session]:
        while True:
            connection = await self.listener.accept()
            try:
                yield await self._handshake(connection)
            except Exception:
                await connection.close()

    async def _socks5_handshake(
        self, connection: Connection, first_byte: bytes
    ) -> Session:
        nmethods = (await connection.read_exactly(1))[0]
        auth_methods_bytes = await connection.read_exactly(nmethods)
        auth_ok = False
        for auth_method in auth_methods_bytes:
            if auth_method == 0:
                auth_ok = True
                break
        if not auth_ok:
            await connection.write(bytes([5, 255]))
            raise RuntimeError(f"error auth")
        await connection.write(bytes([5, 0]))
        version = (await connection.read_exactly(1))[0]
        if version != 5:
            raise RuntimeError("version error")
        cmd = (await connection.read_exactly(1))[0]
        if cmd != 1:
            raise RuntimeError("cmd error")
        rsv = (await connection.read_exactly(1))[0]
        if rsv != 0:
            raise RuntimeError("rsv error")
        atyp = (await connection.read_exactly(1))[0]
        address = ""
        address_type = AddressType.IPV4
        if atyp == 1:
            addr_bytes = await connection.read_exactly(4)
            address = str(ipaddress.IPv4Address(addr_bytes))
        elif atyp == 3:
            address_type = AddressType.DOMAIN
            domain_len = (await connection.read_exactly(1))[0]
            address = (await connection.read_exactly(domain_len)).decode()
        elif atyp == 4:
            address_type = AddressType.IPV6
            addr_bytes = await connection.read_exactly(16)
            address = str(ipaddress.IPv6Address(addr_bytes))
        else:
            raise RuntimeError("atyp error")
        port = int.from_bytes((await connection.read_exactly(2)), "big")
        await connection.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        initial_data = await connection.read(4096)
        destination = Destination(type=address_type, address=address, port=port)
        return Session(connection, destination, initial_data)

    async def _http_handshake(
        self, connection: Connection, first_byte: bytes
    ) -> Session:
        data = first_byte
        while b"\r\n\r\n" not in data:
            chunk = await connection.read(4096)
            if not chunk:
                raise RuntimeError("read http header fail")
            data += chunk
            if len(data) > 64 * 1024:
                raise RuntimeError("http header too big")
        parts = data.split(b"\r\n\r\n", 1)
        header = parts[0]
        remaining = parts[1]
        lines = header.split(b"\r\n")
        if not lines:
            raise RuntimeError("invalid http header")
        request_line = lines[0].decode("latin-1")
        parts = request_line.split(" ")
        if len(parts) != 3:
            raise RuntimeError("invalid http request line")
        method, target, version = parts
        if method.upper() == "CONNECT":
            destination = Destination.from_authority(target)
            await connection.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            initial_data = await connection.read(4096)
            return Session(connection, destination, initial_data)
        if not target.startswith(("http://", "https://")):
            raise RuntimeError("invalid http proxy target")
        uri = urlsplit(target)
        if not uri.hostname:
            raise RuntimeError("http proxy missing host")
        destination = Destination.from_host_port(uri.hostname, uri.port or 80)
        path = uri.path or "/"
        if uri.query:
            path += "?" + uri.query
        result = [f"{method} {path} {version}".encode("latin-1")]
        for line in lines[1:]:
            result.append(line)
        initial_data = b"\r\n".join(result) + b"\r\n\r\n" + remaining
        return Session(connection, destination, initial_data)

    async def _handshake(self, connection: Connection) -> Session:
        first_byte = await connection.read_exactly(1)
        if first_byte[0] == 5:
            return await self._socks5_handshake(connection, first_byte)
        else:
            return await self._http_handshake(connection, first_byte)

    async def close(self):
        return await self.listener.close()

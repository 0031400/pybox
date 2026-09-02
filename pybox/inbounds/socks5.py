import asyncio
from collections.abc import AsyncIterator
from ..common.address import AddressType, Destination
from ..connections.connection import Connection
from ..common.session import Session
from ..utils.address import host_port, get_ip_port
from ..utils.network import close_writer, relay
import ipaddress

from .inbound import Inbound
from .listeners.listener import Listener


class Socks5Inbound(Inbound):
    def __init__(self, listener: Listener, users: dict[str, str]) -> None:
        self.users = users
        self.listener = listener

    async def start(self):
        await self.listener.start()

    async def sessions(self) -> AsyncIterator[Session]:
        while True:
            connection = await self.listener.accept()
            try:
                destination = await self._handshake(connection)
                yield Session(connection=connection, destination=destination)
            except Exception:
                await connection.close()

    async def _handshake(self, connection: Connection) -> Destination:
        header = await connection.read_exactly(2)
        version = header[0]
        nmethods = header[1]
        if version != 5:
            raise RuntimeError(f"error socks5 version: {version}")
        auth_methods_bytes = await connection.read_exactly(nmethods)
        choosed_auth = -1
        if len(self.users) == 0:
            for auth_method in auth_methods_bytes:
                if auth_method == 0:
                    choosed_auth = 0
                    break
        else:
            for auth_method in auth_methods_bytes:
                if auth_method == 2:
                    choosed_auth = 2
                    break
        auth_ok = False
        if choosed_auth == 0:
            auth_ok = True
        elif choosed_auth == 2:
            await connection.write(bytes([5, 2]))
            version = (await connection.read_exactly(1))[0]
            if version != 1:
                raise RuntimeError(f"error auth version: {version}")
            username_len = (await connection.read_exactly(1))[0]
            username = (await connection.read_exactly(username_len)).decode()
            password_len = (await connection.read_exactly(1))[0]
            password = (await connection.read_exactly(password_len)).decode()
            if self.users.get(username) == password:
                auth_ok = True
        else:
            await connection.write(bytes([5, 255]))
            raise RuntimeError(f"error auth method")
        if auth_ok:
            await connection.write(bytes([5, 0]))
        else:
            await connection.write(bytes([5, 1]))
            raise RuntimeError(f"error auth")
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
        return Destination(type=address_type, address=address, port=port)
    async def close(self):
        return await self.listener.close()
import asyncio
from collections.abc import AsyncIterator
from ..common.address import AddressType, Destination
from ..common.session import Session
from ..connections.connection import Connection
import ipaddress
from .listeners.listener import Listener

from ..common.session import Session
from .inbound import Inbound


class VLessInbound(Inbound):
    def __init__(self, listener: Listener, uuids: list[str]) -> None:
        self.listener = listener
        self.uuids: list[bytes] = []
        self.queue: asyncio.Queue[Session] = asyncio.Queue()
        for uuid in uuids:
            uuid = uuid.replace("-", "")
            if len(uuid) != 32:
                raise RuntimeError("error uuid length")
            self.uuids.append(bytes.fromhex(uuid))
        if not len(self.uuids):
            raise RuntimeError("lack uuid")

    async def start(self):
        await self.listener.start()
        while True:
            connection = await self.listener.accept()
            asyncio.create_task(self._handshake(connection))

    async def sessions(self) -> Session:
        return await self.queue.get()

    async def _handshake(self, connection: Connection):
        version = (await connection.read_exactly(1))[0]
        if version != 0:
            raise RuntimeError("version error")
        uuid = await connection.read_exactly(16)
        if uuid not in self.uuids:
            raise RuntimeError("auth error")
        protobuf_len = (await connection.read_exactly(1))[0]
        if protobuf_len != 0:
            raise RuntimeError("protobuf unsupported")
        await connection.read_exactly(protobuf_len)
        cmd = (await connection.read_exactly(1))[0]
        if cmd != 1:
            raise RuntimeError("cmd unsupported")
        port = int.from_bytes((await connection.read_exactly(2)), "big")
        atyp = (await connection.read_exactly(1))[0]
        address = ""
        if atyp == 1:
            address_type = AddressType.IPV4
            addr_bytes = await connection.read_exactly(4)
            address = str(ipaddress.IPv4Address(addr_bytes))
        elif atyp == 2:
            address_type = AddressType.DOMAIN
            domain_len = (await connection.read_exactly(1))[0]
            address = (await connection.read_exactly(domain_len)).decode()
        elif atyp == 3:
            address_type = AddressType.IPV6
            addr_bytes = await connection.read_exactly(16)
            address = str(ipaddress.IPv6Address(addr_bytes))
        else:
            raise RuntimeError("atyp unsupported")
        initial_data = await connection.read(4096)
        await connection.write(bytes([0, 0]))
        destination = Destination(type=address_type, address=address, port=port)
        session = Session(connection, destination, initial_data)
        await self.queue.put(session)

    async def close(self):
        return await self.listener.close()

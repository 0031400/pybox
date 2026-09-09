import asyncio
from ..common.address import (
    DOMAIN_Address,
    IPV4_Address,
    IPV6_Address,
)
from ..common.session import Session
from ..connections.connection import Connection
import ipaddress
from .listeners.listener import Listener
from ..common.log import log

from ..common.session import Session
from .inbound import Inbound


class VLessInbound(Inbound):
    def __init__(self, listener: Listener, uuids: list[str]) -> None:
        self.listener = listener
        self.uuids: list[bytes] = []
        self.tasks: list[asyncio.Task] = []
        self.queue: asyncio.Queue[Session] = asyncio.Queue()
        for uuid in uuids:
            uuid = uuid.replace("-", "")
            if len(uuid) != 32:
                raise RuntimeError("error uuid length")
            self.uuids.append(bytes.fromhex(uuid))
        if not len(self.uuids):
            raise RuntimeError("lack uuid")

    async def start(self):
        try:
            await self.listener.start()
            while True:
                connection = await self.listener.accept()
                task = asyncio.create_task(self.handshake(connection))
                self.tasks.append(task)

        except Exception as e:
            log("error", f"vless inbound start {e}")

    async def sessions(self) -> Session:
        return await self.queue.get()

    async def handshake(self, connection: Connection):
        try:
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
            if atyp == 1:
                addr_bytes = await connection.read_exactly(4)
                destination = IPV4_Address(ipaddress.IPv4Address(addr_bytes), port)
            elif atyp == 2:
                domain_len = (await connection.read_exactly(1))[0]
                address = (await connection.read_exactly(domain_len)).decode()
                destination = DOMAIN_Address(address, port)
            elif atyp == 3:
                addr_bytes = await connection.read_exactly(16)
                destination = IPV6_Address(ipaddress.IPv6Address(addr_bytes), port)
            else:
                raise RuntimeError("atyp unsupported")
            initial_data = await connection.read(4096)
            await connection.write(bytes([0, 0]))
            session = Session(connection, destination, initial_data)
            await self.queue.put(session)
        except Exception as e:
            log("error", f"vless handshake {e}")

    async def close(self):
        return await self.listener.close()

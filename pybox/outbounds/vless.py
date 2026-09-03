import ipaddress

from pybox.connections.connection import Connection

from ..common.address import Destination, AddressType
from .outbound import Outbound
from .transports.transport import Transport


class VlessOutbound(Outbound):
    def __init__(self, server: Destination, uuid: str, transport: Transport) -> None:
        self.server = server
        self.uuid = uuid.replace("-", "")
        self.transport = transport

    async def connect(
        self, destination: Destination, initial_data: bytes
    ) -> Connection:
        connection = await self.transport.connect(self.server)
        match destination.type:
            case AddressType.IPV4:
                address_bytes = (
                    bytes([1]) + ipaddress.IPv4Address(destination.address).packed
                )
            case AddressType.IPV6:
                address_bytes = (
                    bytes([3]) + ipaddress.IPv6Address(destination.address).packed
                )
            case _:
                data = destination.address.encode()
                address_bytes = bytes([2, len(data)]) + data
        req_data = (
            bytes([0])
            + bytes.fromhex(self.uuid)
            + bytes([0, 1])
            + destination.port.to_bytes(2, "big")
            + address_bytes
            + initial_data
        )
        await connection.write(req_data)
        res_bytes = await connection.read_exactly(2)
        if res_bytes[0] != 0 or res_bytes[1] != 0:
            raise RuntimeError("error vless response")
        return connection

from ..common.address import Address
from ..connections.connection import Connection

from .outbound import Outbound


class BlockOutbound(Outbound):
    async def connect(self, destination: Address, initial_data: bytes) -> Connection:
        raise RuntimeError("block destination")

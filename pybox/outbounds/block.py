from ..common.address import Destination
from ..connections.connection import Connection

from .outbound import Outbound


class BlockOutbound(Outbound):
    async def connect(self, destination: Destination, initial_data: bytes) -> Connection:
        raise RuntimeError("block destination")

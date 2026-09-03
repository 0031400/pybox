from pybox.common.address import Destination
from pybox.connections.connection import Connection

from .outbound import Outbound


class BlockOutbound(Outbound):
    async def connect(self, destination: Destination, first_data: bytes) -> Connection:
        raise RuntimeError("block destination")

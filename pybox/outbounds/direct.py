from ..common.address import Destination
from ..transports.tcp import TcpTransport
from ..transports.transport import Transport


class DirectOutbound:
    async def connect(self, destination: Destination) -> "Transport":
        return await TcpTransport.connect(destination)

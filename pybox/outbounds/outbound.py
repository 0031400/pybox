from abc import ABC, abstractmethod

from ..common.address import Destination
from ..connections.connection import Connection


class Outbound(ABC):
    @abstractmethod
    async def connect(
        self, destination: Destination, initial_data: bytes
    ) -> Connection: ...

from abc import ABC, abstractmethod

from ..common.address import Address
from ..connections.connection import Connection


class Outbound(ABC):
    @abstractmethod
    async def connect(
        self, destination: Address, initial_data: bytes
    ) -> Connection: ...

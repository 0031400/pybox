from abc import ABC, abstractmethod

from ...common.address import Address
from ...connections.connection import Connection


class Transport(ABC):
    @abstractmethod
    async def connect(self, destination: Address) -> Connection: ...

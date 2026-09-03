from abc import ABC, abstractmethod

from ...common.address import Destination
from ...connections.connection import Connection


class Transport(ABC):
    @abstractmethod
    async def connect(self, destination: Destination) -> Connection: ...

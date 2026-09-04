from abc import ABC, abstractmethod
from ...connections.connection import Connection


class Listener(ABC):
    @abstractmethod
    async def start(self): ...
    @abstractmethod
    async def accept(self) -> Connection: ...
    @abstractmethod
    async def close(self): ...


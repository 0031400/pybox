from abc import ABC, abstractmethod
from ...connections.connection import Connection


class Listener(ABC):
    @abstractmethod
    async def start(self): ...
    async def accept(self) -> Connection: ...
    async def close(self): ...


from abc import ABC, abstractmethod
from ..common.session import Session


class Inbound(ABC):
    @abstractmethod
    async def start(self): ...
    @abstractmethod
    async def sessions(self) -> Session: ...
    @abstractmethod
    async def close(self): ...


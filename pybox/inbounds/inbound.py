from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from ..common.session import Session


class Inbound(ABC):
    @abstractmethod
    async def start(self): ...
    @abstractmethod
    def sessions(self) -> AsyncIterator[Session]: ...
    @abstractmethod
    async def close(self): ...


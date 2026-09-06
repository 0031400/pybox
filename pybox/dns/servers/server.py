from abc import ABC

class DnsServer(ABC):
    async def query(self, request: bytes) -> bytes: ...

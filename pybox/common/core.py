import asyncio

from ..inbounds.inbound import Inbound


class Core:
    def __init__(self, inbounds: list[Inbound]) -> None:
        self.inbounds = inbounds

    async def start(self):
        for inbound in self.inbounds:
            await inbound.start()

    async def run(self):
        tasks = [
            asyncio.create_task(self._consume(inbound)) for inbound in self.inbounds
        ]
        await asyncio.gather(*tasks)

    async def _consume(self, inbound: Inbound):
        async for session in inbound.sessions(): 
            print(f"session: {session.destination.address}")

import asyncio
from os import write
from turtle import width

from ..connections.connection import Connection
from ..inbounds.inbound import Inbound
from ..outbounds.outbound import Outbound
from .session import Session


class Core:
    def __init__(self, inbounds: list[Inbound], outbounds: dict[str, Outbound]) -> None:
        self.inbounds = inbounds
        self.outbounds = outbounds

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
            asyncio.create_task(self._handle_session(session))

    async def _handle_session(self, session: Session):
        first_data=await session.connection.read(4096)
        outbound = self.outbounds["final"]
        try:
            remote = await outbound.connect(session.destination,first_data)
            await relay(session.connection, remote)
        except Exception:
            await session.connection.close()


async def relay(left: Connection, right: Connection):
    async def forward(source: Connection, target: Connection):
        while True:
            data = await source.read(4096)
            if not data:
                break
            await target.write(data)

    task1 = asyncio.create_task(forward(left, right))
    task2 = asyncio.create_task(forward(right, left))
    done, pending = await asyncio.wait(
        [task1, task2], return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
    await asyncio.gather(*done, return_exceptions=True)
    await left.close()
    await right.close()

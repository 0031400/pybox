import websockets

from .connection import Connection


class WsConnection(Connection):
    def __init__(
        self, ws: websockets.ClientConnection | websockets.ServerConnection
    ) -> None:
        self.ws = ws
        self.buffer = bytearray()

    async def read(self, n: int) -> bytes:
        if self.buffer:
            data = bytes(self.buffer[:n])
            del self.buffer[:n]
            return data
        else:
            message = await self.ws.recv()
            if isinstance(message, str):
                raise RuntimeError("ws receive text message")
            return message

    async def read_exactly(self, n: int) -> bytes:
        while len(self.buffer) < n:
            message = await self.ws.recv()
            if isinstance(message, str):
                raise RuntimeError("ws receive text message")
            self.buffer.extend(message)
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    async def write(self, data: bytes) -> None:
        await self.ws.send(data)

    async def close(self) -> None:
        await self.ws.close()

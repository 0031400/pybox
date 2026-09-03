import websockets

from pybox.connections.connection import Connection

from ...common.address import Destination
from ...connections.ws import WsConnection
from .transport import Transport


class WsTransport(Transport):
    def __init__(self, path: str, headers: dict[str, str]) -> None:
        self.path = path
        self.headers = headers

    async def connect(self, destination: Destination) -> Connection:
        uri = f"ws://{destination.authority()}{self.path}"
        ws = await websockets.connect(uri, additional_headers=self.headers)
        return WsConnection(ws)

import ssl

import websockets

from pybox.connections.connection import Connection

from ...common.address import Destination
from ...connections.ws import WsConnection
from .transport import Transport


class WssTransport(Transport):
    def __init__(
        self, path: str, headers: dict[str, str], server_name: str, insecure: bool
    ) -> None:
        self.path = path
        self.headers = headers
        self.server_name = server_name
        self.insecure = insecure

    async def connect(self, destination: Destination) -> Connection:
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        uri = f"wss://{destination.authority()}{self.path}"
        ws = await websockets.connect(uri, additional_headers=self.headers, ssl=context)
        return WsConnection(ws)

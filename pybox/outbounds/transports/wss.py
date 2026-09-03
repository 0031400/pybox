import ssl

import websockets

from pybox.connections.connection import Connection

from ...common.address import AddressType, Destination
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
        key = next((k for k in self.headers if k.lower() == "host"), None)
        if destination.type != AddressType.DOMAIN and key:
            ip = destination.address
            destination.address = self.headers[key]
            del self.headers[key]
            uri = f"wss://{destination.authority()}{self.path}"
            ws = await websockets.connect(
                uri,
                additional_headers=self.headers,
                ssl=context,
                host=ip,
                port=destination.port,
                server_hostname=self.server_name,
                proxy=None,
            )
        else:
            uri = f"wss://{destination.authority()}{self.path}"
            ws = await websockets.connect(
                uri,
                additional_headers=self.headers,
                ssl=context,
                server_hostname=self.server_name,
                proxy=None,
            )
        return WsConnection(ws)

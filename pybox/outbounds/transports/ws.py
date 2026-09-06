import websockets

from ...common.network import open_sock
from ...connections.connection import Connection

from ...common.address import Address, host_port_to_addr
from ...connections.ws import WsConnection
from .transport import Transport


class WsTransport(Transport):
    def __init__(self, path: str, headers: dict[str, str]) -> None:
        self.path = path
        self.headers = headers

    async def connect(self, destination: Address) -> Connection:
        sock = await open_sock(destination)
        key = next((k for k in self.headers if k.lower() == "host"), None)
        if key:
            host_dst = host_port_to_addr(self.headers[key], destination.port)
        else:
            host_dst = destination
        uri = f"wss://{host_dst.authority()}{self.path}"
        ws = await websockets.connect(uri, additional_headers=self.headers, sock=sock)
        return WsConnection(ws)

import ssl

import websockets

from ...common.network import open_tcp_sock
from ...connections.connection import Connection

from ...common.address import AddressType, Address, DOMAIN_Address, host_port_to_addr
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

    async def connect(self, destination: Address) -> Connection:
        context = ssl.create_default_context()
        if self.insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        sock = await open_tcp_sock(destination)
        key = next((k for k in self.headers if k.lower() == "host"), None)
        if key:
            host_dst = host_port_to_addr(self.headers[key], destination.port)
        else:
            host_dst = destination
        uri = f"wss://{host_dst.authority()}{self.path}"
        ws = await websockets.connect(
            uri,
            additional_headers=self.headers,
            ssl=context,
            server_hostname=self.server_name,
            proxy=None,
            sock=sock,
        )
        return WsConnection(ws)

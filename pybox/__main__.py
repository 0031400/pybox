import argparse
import asyncio
import ipaddress

from pybox.inbounds import inbound

from .common.core import Core
from .inbounds.listeners.tcp_listener import TcpListener
from .inbounds.socks5 import Socks5Inbound
from .inbounds.vless import VLessInbound
from .outbounds.direct import DirectOutbound
from .outbounds.outbound import Outbound


class App:
    def __init__(self) -> None:
        pass

    async def run(self):
        listener = TcpListener("localhost", 3000)
        socks5 = Socks5Inbound(listener, {})
        core = Core([socks5], {"direct": DirectOutbound()})
        await core.start()
        await core.run()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--address", type=str, default="localhost", help="listen address"
    )
    parser.add_argument("--port", type=int, default=3000, help="listen port")
    args = parser.parse_args()
    app = App()
    asyncio.run(app.run())


if __name__ == "__main__":
    main()
